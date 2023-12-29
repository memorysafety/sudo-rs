use std::{
    fs::File,
    io::{self, Cursor, Read, Seek, Write},
    path::PathBuf,
};

use crate::log::{auth_info, auth_warn};

use super::{
    audit::secure_open_cookie_file,
    file::FileLock,
    interface::UserId,
    time::{Duration, SystemTime},
    Process, WithProcess,
};

/// Truncates or extends the underlying data
pub trait SetLength {
    /// After this is called, the underlying data will either be truncated
    /// up to new_len bytes, or it will have been extended by zero bytes up to
    /// new_len.
    fn set_len(&mut self, new_len: usize) -> io::Result<()>;
}

impl SetLength for File {
    fn set_len(&mut self, new_len: usize) -> io::Result<()> {
        File::set_len(self, new_len as u64)
    }
}

type BoolStorage = u8;

const SIZE_OF_TS: i64 = std::mem::size_of::<SystemTime>() as i64;
const SIZE_OF_BOOL: i64 = std::mem::size_of::<BoolStorage>() as i64;
const MOD_OFFSET: i64 = SIZE_OF_TS + SIZE_OF_BOOL;

#[derive(Debug)]
pub struct SessionRecordFile {
    file: File,
    timeout: Duration,
    for_user: UserId,
}

impl SessionRecordFile {
    const BASE_PATH: &'static str = "/var/run/sudo-rs/ts";

    pub fn open_for_user(user: UserId, timeout: Duration) -> io::Result<Self> {
        let mut path = PathBuf::from(Self::BASE_PATH);
        path.push(user.to_string());
        SessionRecordFile::new(user, secure_open_cookie_file(&path)?, timeout)
    }

    const FILE_VERSION: u16 = 1;
    const MAGIC_NUM: u16 = 0x50D0;
    const VERSION_OFFSET: u64 = Self::MAGIC_NUM.to_le_bytes().len() as u64;
    const FIRST_RECORD_OFFSET: u64 =
        Self::VERSION_OFFSET + Self::FILE_VERSION.to_le_bytes().len() as u64;

    /// Create a new SessionRecordFile from the given i/o stream.
    /// Timestamps in this file are considered valid if they were created or
    /// updated at most `timeout` time ago.
    pub fn new(for_user: UserId, io: File, timeout: Duration) -> io::Result<Self> {
        let mut session_records = SessionRecordFile {
            file: io,
            timeout,
            for_user,
        };

        // match the magic number, otherwise reset the file
        match session_records.read_magic()? {
            Some(magic) if magic == Self::MAGIC_NUM => (),
            x => {
                if let Some(_magic) = x {
                    auth_info!("Session records file for user '{for_user}' is invalid, resetting");
                }

                session_records.init(Self::VERSION_OFFSET)?;
            }
        }

        // match the file version
        match session_records.read_version()? {
            Some(v) if v == Self::FILE_VERSION => (),
            x => {
                if let Some(v) = x {
                    auth_info!("Session records file for user '{for_user}' has invalid version {v}, only file version {} is supported, resetting", Self::FILE_VERSION);
                } else {
                    auth_info!(
                        "Session records file did not contain file version information, resetting"
                    );
                }

                session_records.init(Self::FIRST_RECORD_OFFSET)?;
            }
        }

        // we are ready to read records
        Ok(session_records)
    }

    /// Read the magic number from the input stream
    fn read_magic(&mut self) -> io::Result<Option<u16>> {
        let mut magic_bytes = [0; std::mem::size_of::<u16>()];
        match self.file.read_exact(&mut magic_bytes) {
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
            Err(e) => Err(e),
            Ok(()) => Ok(Some(u16::from_le_bytes(magic_bytes))),
        }
    }

    /// Read the version number from the input stream
    fn read_version(&mut self) -> io::Result<Option<u16>> {
        let mut version_bytes = [0; std::mem::size_of::<u16>()];
        match self.file.read_exact(&mut version_bytes) {
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
            Err(e) => Err(e),
            Ok(()) => Ok(Some(u16::from_le_bytes(version_bytes))),
        }
    }

    /// Initialize a new empty stream. If the stream/file was already filled
    /// before it will be truncated.
    fn init(&mut self, offset: u64) -> io::Result<()> {
        // lock the file to indicate that we are currently writing to it
        let lock = FileLock::exclusive(&self.file, false)?;

        self.file.set_len(0)?;
        self.file.rewind()?;
        self.file.write_all(&Self::MAGIC_NUM.to_le_bytes())?;
        self.file.write_all(&Self::FILE_VERSION.to_le_bytes())?;
        self.file.seek(io::SeekFrom::Start(offset))?;

        lock.unlock()?;

        Ok(())
    }

    /// Read the next record and keep note of the start and end positions in the file of that record
    ///
    /// This method assumes that the file is already exclusively locked.
    fn next_record(&mut self) -> io::Result<Option<SessionRecord>> {
        // record the position at which this record starts (including size bytes)
        let mut record_length_bytes = [0; std::mem::size_of::<u16>()];

        let curr_pos = self.file.stream_position()?;

        // if eof occurs here we assume we reached the end of the file
        let record_length = match self.file.read_exact(&mut record_length_bytes) {
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
            Ok(()) => u16::from_le_bytes(record_length_bytes),
        };

        // special case when record_length is zero
        if record_length == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Found empty record",
            ));
        }

        let mut buf = vec![0; record_length as usize];
        match self.file.read_exact(&mut buf) {
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                // there was half a record here, we clear the rest of the file
                auth_info!("Found incomplete record in session records file for {}, clearing rest of the file", self.for_user);
                self.file.set_len(curr_pos)?;
                return Ok(None);
            }
            Err(e) => return Err(e),
            Ok(()) => (),
        }

        // we now try and decode the data read into a session record
        match SessionRecord::from_bytes(&buf) {
            Err(_) => {
                // any error assumes that this file is nonsense from this point
                // onwards, so we clear the file up to the start of this record
                auth_info!("Found invalid record in session records file for {}, clearing rest of the file", self.for_user);

                self.file.set_len(curr_pos)?;
                Ok(None)
            }
            Ok(record) => Ok(Some(record)),
        }
    }

    /// Try and find a record for the given scope and auth user id and update
    /// that record time to the current time. This will not create a new record
    /// when one is not found. A record will only be updated if it is still
    /// valid at this time.
    pub fn touch(&mut self, scope: RecordScope, auth_user: UserId) -> io::Result<TouchResult> {
        // lock the file to indicate that we are currently in a writing operation
        let lock = FileLock::exclusive(&self.file, false)?;
        self.seek_to_first_record()?;
        while let Some(record) = self.next_record()? {
            // only touch if record is enabled
            if record.enabled && record.matches(&scope, auth_user) {
                let now = SystemTime::now()?;
                if record.written_between(now - self.timeout, now) {
                    // move back to where the timestamp is and overwrite with the latest time
                    self.file.seek(io::SeekFrom::Current(-MOD_OFFSET))?;
                    let new_time = SystemTime::now()?;
                    new_time.encode(&mut self.file)?;

                    // make sure we can still go to the end of the record
                    self.file.seek(io::SeekFrom::Current(SIZE_OF_BOOL))?;

                    // writing is done, unlock and return
                    lock.unlock()?;
                    return Ok(TouchResult::Updated {
                        old_time: record.timestamp,
                        new_time,
                    });
                } else {
                    lock.unlock()?;
                    return Ok(TouchResult::Outdated {
                        time: record.timestamp,
                    });
                }
            }
        }

        lock.unlock()?;
        Ok(TouchResult::NotFound)
    }

    /// Disable all records that match the given scope. If an auth user id is
    /// given then only records with the given scope that are targetting that
    /// specific user will be disabled.
    pub fn disable(&mut self, scope: RecordScope, auth_user: Option<UserId>) -> io::Result<()> {
        let lock = FileLock::exclusive(&self.file, false)?;
        self.seek_to_first_record()?;
        while let Some(record) = self.next_record()? {
            let must_disable = auth_user
                .map(|tu| record.matches(&scope, tu))
                .unwrap_or_else(|| record.scope == scope);
            if must_disable {
                self.file.seek(io::SeekFrom::Current(-SIZE_OF_BOOL))?;
                write_bool(false, &mut self.file)?;
            }
        }
        lock.unlock()?;
        Ok(())
    }

    /// Create a new record for the given scope and auth user id.
    /// If there is an existing record that matches the scope and auth user,
    /// then that record will be updated.
    pub fn create(&mut self, scope: RecordScope, auth_user: UserId) -> io::Result<CreateResult> {
        // lock the file to indicate that we are currently writing to it
        let lock = FileLock::exclusive(&self.file, false)?;
        self.seek_to_first_record()?;
        while let Some(record) = self.next_record()? {
            if record.matches(&scope, auth_user) {
                self.file.seek(io::SeekFrom::Current(-MOD_OFFSET))?;
                let new_time = SystemTime::now()?;
                new_time.encode(&mut self.file)?;
                write_bool(true, &mut self.file)?;
                lock.unlock()?;
                return Ok(CreateResult::Updated {
                    old_time: record.timestamp,
                    new_time,
                });
            }
        }

        // record was not found in the list so far, create a new one
        let record = SessionRecord::new(scope, auth_user)?;

        // make sure we really are at the end of the file
        self.file.seek(io::SeekFrom::End(0))?;

        self.write_record(&record)?;
        lock.unlock()?;

        Ok(CreateResult::Created {
            time: record.timestamp,
        })
    }

    /// Completely resets the entire file and removes all records.
    pub fn reset(&mut self) -> io::Result<()> {
        self.init(0)
    }

    /// Write a new record at the current position in the file.
    fn write_record(&mut self, record: &SessionRecord) -> io::Result<()> {
        // convert the new record to byte representation and make sure that it fits
        let bytes = record.as_bytes()?;
        let record_length = bytes.len();
        if record_length > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "A record with an unexpectedly large size was created",
            ));
        }
        let record_length = record_length as u16; // store as u16

        // write the record
        self.file.write_all(&record_length.to_le_bytes())?;
        self.file.write_all(&bytes)?;

        Ok(())
    }

    /// Move to where the first record starts.
    fn seek_to_first_record(&mut self) -> io::Result<()> {
        self.file
            .seek(io::SeekFrom::Start(Self::FIRST_RECORD_OFFSET))?;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TouchResult {
    /// The record was found and within the timeout, and it was refreshed
    Updated {
        old_time: SystemTime,
        new_time: SystemTime,
    },
    /// A record was found, but it was no longer valid
    Outdated { time: SystemTime },
    /// A record was not found that matches the input
    NotFound,
}

pub enum CreateResult {
    /// The record was found and it was refreshed
    Updated {
        old_time: SystemTime,
        new_time: SystemTime,
    },
    /// A new record was created and was set to the time returned
    Created { time: SystemTime },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordScope {
    Tty {
        tty_device: libc::dev_t,
        session_pid: libc::pid_t,
        init_time: SystemTime,
    },
    Ppid {
        group_pid: libc::pid_t,
        init_time: SystemTime,
    },
}

impl RecordScope {
    fn encode(&self, target: &mut impl Write) -> std::io::Result<()> {
        match self {
            RecordScope::Tty {
                tty_device,
                session_pid,
                init_time,
            } => {
                target.write_all(&[1u8])?;
                let b = tty_device.to_le_bytes();
                target.write_all(&b)?;
                let b = session_pid.to_le_bytes();
                target.write_all(&b)?;
                init_time.encode(target)?;
            }
            RecordScope::Ppid {
                group_pid,
                init_time,
            } => {
                target.write_all(&[2u8])?;
                let b = group_pid.to_le_bytes();
                target.write_all(&b)?;
                init_time.encode(target)?;
            }
        }

        Ok(())
    }

    fn decode(from: &mut impl Read) -> std::io::Result<RecordScope> {
        let mut buf = [0; 1];
        from.read_exact(&mut buf)?;
        match buf[0] {
            1 => {
                let mut buf = [0; std::mem::size_of::<libc::dev_t>()];
                from.read_exact(&mut buf)?;
                let tty_device = libc::dev_t::from_le_bytes(buf);
                let mut buf = [0; std::mem::size_of::<libc::pid_t>()];
                from.read_exact(&mut buf)?;
                let session_pid = libc::pid_t::from_le_bytes(buf);
                let init_time = SystemTime::decode(from)?;
                Ok(RecordScope::Tty {
                    tty_device,
                    session_pid,
                    init_time,
                })
            }
            2 => {
                let mut buf = [0; std::mem::size_of::<libc::pid_t>()];
                from.read_exact(&mut buf)?;
                let group_pid = libc::pid_t::from_le_bytes(buf);
                let init_time = SystemTime::decode(from)?;
                Ok(RecordScope::Ppid {
                    group_pid,
                    init_time,
                })
            }
            x => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Unexpected scope variant discriminator: {x}"),
            )),
        }
    }

    /// Tries to determine a record match scope for the current context.
    /// This should never produce an error since any actual error should just be
    /// ignored and no session record file should be used in that case.
    pub fn for_process(process: &Process) -> Option<RecordScope> {
        let tty = Process::tty_device_id(WithProcess::Current);
        if let Ok(Some(tty_device)) = tty {
            if let Ok(init_time) = Process::starting_time(WithProcess::Other(process.session_id)) {
                Some(RecordScope::Tty {
                    tty_device: tty_device.id(),
                    session_pid: process.session_id.id(),
                    init_time,
                })
            } else {
                auth_warn!("Could not get terminal foreground process starting time");
                None
            }
        } else if let Some(parent_pid) = process.parent_pid {
            if let Ok(init_time) = Process::starting_time(WithProcess::Other(parent_pid)) {
                Some(RecordScope::Ppid {
                    group_pid: parent_pid.id(),
                    init_time,
                })
            } else {
                auth_warn!("Could not get parent process starting time");
                None
            }
        } else {
            None
        }
    }
}

fn write_bool(b: bool, target: &mut impl Write) -> io::Result<()> {
    let s: BoolStorage = if b { 0xFF } else { 0x00 };
    let bytes = s.to_le_bytes();
    target.write_all(&bytes)?;
    Ok(())
}

/// A record in the session record file
#[derive(Debug, PartialEq, Eq)]
pub struct SessionRecord {
    /// The scope for which the current record applies, i.e. what process group
    /// or which TTY for interactive sessions
    scope: RecordScope,
    /// The user that needs to be authenticated against
    auth_user: libc::uid_t,
    /// The timestamp at which the time was created. This must always be a time
    /// originating from a monotonic clock that continues counting during system
    /// sleep.
    timestamp: SystemTime,
    /// Disabled records act as if they do not exist, but their storage can
    /// be re-used when recreating for the same scope and auth user
    enabled: bool,
}

impl SessionRecord {
    /// Create a new record that is scoped to the specified scope and has `auth_user` as
    /// the target for authentication for the session.
    fn new(scope: RecordScope, auth_user: UserId) -> io::Result<SessionRecord> {
        Ok(Self::init(scope, auth_user, true, SystemTime::now()?))
    }

    /// Initialize a new record with the given parameters
    fn init(
        scope: RecordScope,
        auth_user: UserId,
        enabled: bool,
        timestamp: SystemTime,
    ) -> SessionRecord {
        SessionRecord {
            scope,
            auth_user: auth_user.id(),
            timestamp,
            enabled,
        }
    }

    /// Encode a record into the given stream
    fn encode(&self, target: &mut impl Write) -> std::io::Result<()> {
        self.scope.encode(target)?;

        // write user id
        let buf = self.auth_user.to_le_bytes();
        target.write_all(&buf)?;

        // write timestamp
        self.timestamp.encode(target)?;

        // write enabled boolean
        write_bool(self.enabled, target)?;

        Ok(())
    }

    /// Decode a record from the given stream
    fn decode(from: &mut impl Read) -> std::io::Result<SessionRecord> {
        let scope = RecordScope::decode(from)?;

        // auth user id
        let mut buf = [0; std::mem::size_of::<libc::uid_t>()];
        from.read_exact(&mut buf)?;
        let auth_user = libc::uid_t::from_le_bytes(buf);

        // timestamp
        let timestamp = SystemTime::decode(from)?;

        // enabled boolean
        let mut buf = [0; std::mem::size_of::<BoolStorage>()];
        from.read_exact(&mut buf)?;
        let enabled = match BoolStorage::from_le_bytes(buf) {
            0xFF => true,
            0x00 => false,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid boolean value detected in input stream",
                ))
            }
        };

        Ok(SessionRecord::init(
            scope,
            UserId(auth_user),
            enabled,
            timestamp,
        ))
    }

    /// Convert the record to a vector of bytes for storage.
    pub fn as_bytes(&self) -> std::io::Result<Vec<u8>> {
        let mut v = vec![];
        self.encode(&mut v)?;
        Ok(v)
    }

    /// Convert the given byte slice to a session record, the byte slice must
    /// be fully consumed for this conversion to be valid.
    pub fn from_bytes(data: &[u8]) -> std::io::Result<SessionRecord> {
        let mut cursor = Cursor::new(data);
        let record = SessionRecord::decode(&mut cursor)?;
        if cursor.position() != data.len() as u64 {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Record size and record length did not match",
            ))
        } else {
            Ok(record)
        }
    }

    /// Returns true if this record matches the specified scope and is for the
    /// specified target auth user.
    pub fn matches(&self, scope: &RecordScope, auth_user: UserId) -> bool {
        self.scope == *scope && self.auth_user == auth_user.id()
    }

    /// Returns true if this record was written somewhere in the time range
    /// between `early_time` (inclusive) and `later_time` (inclusive), where
    /// early timestamp may not be later than the later timestamp.
    pub fn written_between(&self, early_time: SystemTime, later_time: SystemTime) -> bool {
        early_time <= later_time && self.timestamp >= early_time && self.timestamp <= later_time
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::system::tests::tempfile;

    const TEST_USER_ID: UserId = UserId(1000);

    impl SetLength for Cursor<Vec<u8>> {
        fn set_len(&mut self, new_len: usize) -> io::Result<()> {
            self.get_mut().truncate(new_len);
            while self.get_mut().len() < new_len {
                self.get_mut().push(0);
            }
            Ok(())
        }
    }

    impl SetLength for Cursor<&mut Vec<u8>> {
        fn set_len(&mut self, new_len: usize) -> io::Result<()> {
            self.get_mut().truncate(new_len);
            while self.get_mut().len() < new_len {
                self.get_mut().push(0);
            }
            Ok(())
        }
    }

    #[test]
    fn can_encode_and_decode() {
        let tty_sample = SessionRecord::new(
            RecordScope::Tty {
                tty_device: 10,
                session_pid: 42,
                init_time: SystemTime::now().unwrap() - Duration::seconds(150),
            },
            UserId(999),
        )
        .unwrap();

        let mut bytes = tty_sample.as_bytes().unwrap();
        let decoded = SessionRecord::from_bytes(&bytes).unwrap();
        assert_eq!(tty_sample, decoded);

        // we provide some invalid input
        assert!(SessionRecord::from_bytes(&bytes[1..]).is_err());

        // we have remaining input after decoding
        bytes.push(0);
        assert!(SessionRecord::from_bytes(&bytes).is_err());

        let ppid_sample = SessionRecord::new(
            RecordScope::Ppid {
                group_pid: 42,
                init_time: SystemTime::now().unwrap(),
            },
            UserId(123),
        )
        .unwrap();
        let bytes = ppid_sample.as_bytes().unwrap();
        let decoded = SessionRecord::from_bytes(&bytes).unwrap();
        assert_eq!(ppid_sample, decoded);
    }

    #[test]
    fn timestamp_record_matches_works() {
        let init_time = SystemTime::now().unwrap();
        let scope = RecordScope::Tty {
            tty_device: 12,
            session_pid: 1234,
            init_time,
        };

        let tty_sample = SessionRecord::new(scope, UserId(675)).unwrap();

        assert!(tty_sample.matches(&scope, UserId(675)));
        assert!(!tty_sample.matches(&scope, UserId(789)));
        assert!(!tty_sample.matches(
            &RecordScope::Tty {
                tty_device: 20,
                session_pid: 1234,
                init_time
            },
            UserId(675)
        ));
        assert!(!tty_sample.matches(
            &RecordScope::Ppid {
                group_pid: 42,
                init_time
            },
            UserId(675)
        ));

        // make sure time is different
        std::thread::sleep(std::time::Duration::from_millis(1));
        assert!(!tty_sample.matches(
            &RecordScope::Tty {
                tty_device: 12,
                session_pid: 1234,
                init_time: SystemTime::now().unwrap()
            },
            UserId(675)
        ));
    }

    #[test]
    fn timestamp_record_written_between_works() {
        let some_time = SystemTime::now().unwrap() + Duration::minutes(100);
        let scope = RecordScope::Tty {
            tty_device: 12,
            session_pid: 1234,
            init_time: some_time,
        };
        let sample = SessionRecord::init(scope, UserId(1234), true, some_time);

        let dur = Duration::seconds(30);

        assert!(sample.written_between(some_time, some_time));
        assert!(sample.written_between(some_time, some_time + dur));
        assert!(sample.written_between(some_time - dur, some_time));
        assert!(!sample.written_between(some_time + dur, some_time - dur));
        assert!(!sample.written_between(some_time + dur, some_time + dur + dur));
        assert!(!sample.written_between(some_time - dur - dur, some_time - dur));
    }

    fn tempfile_with_data(data: &[u8]) -> io::Result<File> {
        let mut file = tempfile()?;
        file.write_all(data)?;
        file.rewind()?;
        Ok(file)
    }

    fn data_from_tempfile(mut f: File) -> io::Result<Vec<u8>> {
        let mut v = vec![];
        f.rewind()?;
        f.read_to_end(&mut v)?;
        Ok(v)
    }

    #[test]
    fn session_record_file_header_checks() {
        // valid header should remain valid
        let c = tempfile_with_data(&[0xD0, 0x50, 0x01, 0x00]).unwrap();
        let timeout = Duration::seconds(30);
        assert!(SessionRecordFile::new(TEST_USER_ID, c.try_clone().unwrap(), timeout).is_ok());
        let v = data_from_tempfile(c).unwrap();
        assert_eq!(&v[..], &[0xD0, 0x50, 0x01, 0x00]);

        // invalid headers should be corrected
        let c = tempfile_with_data(&[0xAB, 0xBA]).unwrap();
        assert!(SessionRecordFile::new(TEST_USER_ID, c.try_clone().unwrap(), timeout).is_ok());
        let v = data_from_tempfile(c).unwrap();
        assert_eq!(&v[..], &[0xD0, 0x50, 0x01, 0x00]);

        // empty header should be filled in
        let c = tempfile_with_data(&[]).unwrap();
        assert!(SessionRecordFile::new(TEST_USER_ID, c.try_clone().unwrap(), timeout).is_ok());
        let v = data_from_tempfile(c).unwrap();
        assert_eq!(&v[..], &[0xD0, 0x50, 0x01, 0x00]);

        // invalid version should reset file
        let c = tempfile_with_data(&[0xD0, 0x50, 0xAB, 0xBA, 0x0, 0x0]).unwrap();
        assert!(SessionRecordFile::new(TEST_USER_ID, c.try_clone().unwrap(), timeout).is_ok());
        let v = data_from_tempfile(c).unwrap();
        assert_eq!(&v[..], &[0xD0, 0x50, 0x01, 0x00]);
    }

    #[test]
    fn can_create_and_update_valid_file() {
        let timeout = Duration::seconds(30);
        let c = tempfile_with_data(&[]).unwrap();
        let mut srf =
            SessionRecordFile::new(TEST_USER_ID, c.try_clone().unwrap(), timeout).unwrap();
        let tty_scope = RecordScope::Tty {
            tty_device: 0,
            session_pid: 0,
            init_time: SystemTime::new(0, 0),
        };
        let auth_user = UserId(2424);
        let res = srf.create(tty_scope, auth_user).unwrap();
        let CreateResult::Created { time } = res else {
            panic!("Expected record to be created");
        };

        std::thread::sleep(std::time::Duration::from_millis(1));
        let second = srf.touch(tty_scope, auth_user).unwrap();
        let TouchResult::Updated { old_time, new_time } = second else {
            panic!("Expected record to be updated");
        };
        assert_eq!(time, old_time);
        assert_ne!(old_time, new_time);

        std::thread::sleep(std::time::Duration::from_millis(1));
        let res = srf.create(tty_scope, auth_user).unwrap();
        let CreateResult::Updated { .. } = res else {
            panic!("Expected record to be updated");
        };

        // reset the file
        assert!(srf.reset().is_ok());

        // after all this the data should be just an empty header
        let data = data_from_tempfile(c).unwrap();
        assert_eq!(&data, &[0xD0, 0x50, 0x01, 0x00]);
    }
}
