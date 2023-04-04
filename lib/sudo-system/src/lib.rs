use std::{
    ffi::{c_int, CString},
    fs::OpenOptions,
    mem::MaybeUninit,
    os::fd::AsRawFd,
    path::PathBuf,
};

use libc::pid_t;
pub use libc::PATH_MAX;
use sudo_cutils::*;

mod audit;
pub use audit::secure_open;

pub fn hostname() -> String {
    let max_hostname_size = sysconf(libc::_SC_HOST_NAME_MAX).unwrap_or(256);
    let mut buf = vec![0; max_hostname_size as usize];
    match cerr(unsafe { libc::gethostname(buf.as_mut_ptr(), buf.len() - 1) }) {
        Ok(_) => unsafe { string_from_ptr(buf.as_ptr()) },
        Err(_) => {
            // there aren't any known conditions under which the gethostname call should fail
            panic!("Unexpected error while retrieving hostname, this should not happen");
        }
    }
}

/// set target user and groups (uid, gid, additional groups) for a command
pub fn set_target_user(
    cmd: &mut std::process::Command,
    current_user: User,
    target_user: User,
    target_group: Group,
) {
    use std::os::unix::process::CommandExt;

    // means that we are using the default user because `-u` was not passed.
    let user_is_default = target_user.is_default;
    // means that we are going to change users
    let user_is_changed = current_user.uid != target_user.uid;
    // means that we are using the principal gid of the target user because `-g` was not passed or
    // was passed with the principal gid.
    let group_is_default = target_user.uid == target_group.gid;

    let mut groups = target_user.groups.unwrap_or_default();

    let (uid, gid) = if group_is_default {
        // no `-g`: We just set the uid, gid and groups using the target user.
        (target_user.uid, target_user.gid)
    } else if user_is_default {
        //  `-g` and no `-u`: The set uid must be the one of the current user and the set groups
        //  must be the ones of the current user extended with the target group gid.
        (current_user.uid, target_group.gid)
    } else {
        // `-g` and `-u`: The set uid must be the one of the target user and the set groups must be
        // the ones of the target group extended with the target group gid.
        (target_user.uid, target_group.gid)
    };

    // add the requested group (implied or supplied via `-g`) if it was not already present
    let group_is_changed = if !groups.contains(&target_group.gid) {
        groups.push(target_group.gid);
        true
    } else {
        false
    };

    // we need to do this in a `pre_exec` call since the `groups` method in `process::Command` is unstable
    // see https://github.com/rust-lang/rust/blob/a01b4cc9f375f1b95fa8195daeea938d3d9c4c34/library/std/src/sys/unix/process/process_unix.rs#L329-L352
    // for the std implementation of the libc calls to `setgroups`, `setgid` and `setuid`
    unsafe {
        cmd.pre_exec(move || {
            // if group_is_default is false, no supplementary groups need to be set;
            // this conditional enables sudo to run without needing superuser rights (when they are not otherwise needed)
            if user_is_changed || group_is_changed {
                cerr(libc::setgroups(groups.len(), groups.as_ptr()))?;
            }
            cerr(libc::setgid(gid))?;
            cerr(libc::setuid(uid))?;

            Ok(())
        });
    }
}

/// Send a signal to a process.
pub fn kill(pid: pid_t, signal: c_int) -> c_int {
    // SAFETY: This function cannot cause UB even if `pid` is not a valid process ID or if
    // `signal` is not a valid signal code.
    unsafe { libc::kill(pid, signal) }
}

/// Get a process group ID.
pub fn getpgid(pid: pid_t) -> pid_t {
    // SAFETY: This function cannot cause UB even if `pid` is not a valid process ID
    unsafe { libc::getpgid(pid) }
}

#[derive(Debug, Clone, PartialEq)]
pub struct User {
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
    pub name: String,
    pub gecos: String,
    pub home: String,
    pub shell: String,
    pub passwd: String,
    pub groups: Option<Vec<libc::gid_t>>,
    pub is_default: bool,
}

impl User {
    /// # Safety
    /// This function expects `pwd` to be a result from a succesful call to `getpwXXX_r`.
    /// (It can cause UB if any of `pwd`'s pointed-to strings does not have a null-terminator.)
    unsafe fn from_libc(pwd: &libc::passwd) -> User {
        User {
            uid: pwd.pw_uid,
            gid: pwd.pw_gid,
            name: string_from_ptr(pwd.pw_name),
            gecos: string_from_ptr(pwd.pw_gecos),
            home: string_from_ptr(pwd.pw_dir),
            shell: string_from_ptr(pwd.pw_shell),
            passwd: string_from_ptr(pwd.pw_passwd),
            groups: None,
            is_default: false,
        }
    }

    pub fn from_uid(uid: libc::uid_t) -> std::io::Result<Option<User>> {
        let max_pw_size = sysconf(libc::_SC_GETPW_R_SIZE_MAX).unwrap_or(16_384);
        let mut buf = vec![0; max_pw_size as usize];
        let mut pwd = MaybeUninit::uninit();
        let mut pwd_ptr = std::ptr::null_mut();
        cerr(unsafe {
            libc::getpwuid_r(
                uid,
                pwd.as_mut_ptr(),
                buf.as_mut_ptr(),
                buf.len(),
                &mut pwd_ptr,
            )
        })?;
        if pwd_ptr.is_null() {
            Ok(None)
        } else {
            let pwd = unsafe { pwd.assume_init() };
            Ok(Some(unsafe { Self::from_libc(&pwd) }))
        }
    }

    pub fn effective_uid() -> libc::uid_t {
        unsafe { libc::geteuid() }
    }

    pub fn effective() -> std::io::Result<Option<User>> {
        Self::from_uid(Self::effective_uid())
    }

    pub fn real_uid() -> libc::uid_t {
        unsafe { libc::getuid() }
    }

    pub fn real() -> std::io::Result<Option<User>> {
        Self::from_uid(Self::real_uid())
    }

    pub fn from_name(name: &str) -> std::io::Result<Option<User>> {
        let max_pw_size = sysconf(libc::_SC_GETPW_R_SIZE_MAX).unwrap_or(16_384);
        let mut buf = vec![0; max_pw_size as usize];
        let mut pwd = MaybeUninit::uninit();
        let mut pwd_ptr = std::ptr::null_mut();
        let name_c = CString::new(name).expect("String contained null bytes");
        cerr(unsafe {
            libc::getpwnam_r(
                name_c.as_ptr(),
                pwd.as_mut_ptr(),
                buf.as_mut_ptr(),
                buf.len(),
                &mut pwd_ptr,
            )
        })?;
        if pwd_ptr.is_null() {
            Ok(None)
        } else {
            let pwd = unsafe { pwd.assume_init() };
            Ok(Some(unsafe { Self::from_libc(&pwd) }))
        }
    }

    pub fn with_groups(mut self) -> User {
        let mut groups = vec![];
        let mut buf_len: libc::c_int = 32;
        let mut buffer: Vec<libc::gid_t>;

        while {
            let username = CString::new(self.name.as_str()).expect("String contained null bytes");

            buffer = vec![0; buf_len as usize];
            let result = unsafe {
                libc::getgrouplist(
                    username.as_ptr(),
                    self.gid,
                    buffer.as_mut_ptr(),
                    &mut buf_len,
                )
            };

            result == -1
        } {
            if buf_len >= 65536 {
                panic!("User has too many groups, this should not happen");
            }

            buf_len *= 2;
        }

        for i in 0..buf_len {
            groups.push(buffer[i as usize]);
        }

        self.groups = Some(groups);

        self
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Group {
    pub gid: libc::gid_t,
    pub name: String,
    pub passwd: String,
    pub members: Vec<String>,
}

impl Group {
    /// # Safety
    /// This function expects `grp` to be a result from a succesful call to `getgrXXX_r`.
    /// In particular the grp.gr_mem pointer is assumed to be non-null, and pointing to a
    /// null-terminated list; the pointed-to strings are expected to be null-terminated.
    unsafe fn from_libc(grp: &libc::group) -> Group {
        // find out how many members we have
        let mut mem_count = 0;
        while !(*grp.gr_mem.offset(mem_count)).is_null() {
            mem_count += 1;
        }

        // convert the members to a slice and then put them into a vec of strings
        let mut members = Vec::with_capacity(mem_count as usize);
        let mem_slice = std::slice::from_raw_parts(grp.gr_mem, mem_count as usize);
        for mem in mem_slice {
            members.push(string_from_ptr(*mem));
        }

        Group {
            gid: grp.gr_gid,
            name: string_from_ptr(grp.gr_name),
            passwd: string_from_ptr(grp.gr_passwd),
            members,
        }
    }

    pub fn effective_gid() -> libc::gid_t {
        unsafe { libc::getegid() }
    }

    pub fn effective() -> std::io::Result<Option<Group>> {
        Self::from_gid(Self::effective_gid())
    }

    pub fn real_gid() -> libc::uid_t {
        unsafe { libc::getgid() }
    }

    pub fn real() -> std::io::Result<Option<Group>> {
        Self::from_gid(Self::real_gid())
    }

    pub fn from_gid(gid: libc::gid_t) -> std::io::Result<Option<Group>> {
        let max_gr_size = sysconf(libc::_SC_GETGR_R_SIZE_MAX).unwrap_or(16_384);
        let mut buf = vec![0; max_gr_size as usize];
        let mut grp = MaybeUninit::uninit();
        let mut grp_ptr = std::ptr::null_mut();
        cerr(unsafe {
            libc::getgrgid_r(
                gid,
                grp.as_mut_ptr(),
                buf.as_mut_ptr(),
                buf.len(),
                &mut grp_ptr,
            )
        })?;
        if grp_ptr.is_null() {
            Ok(None)
        } else {
            let grp = unsafe { grp.assume_init() };
            Ok(Some(unsafe { Group::from_libc(&grp) }))
        }
    }

    pub fn from_name(name: &str) -> std::io::Result<Option<Group>> {
        let max_gr_size = sysconf(libc::_SC_GETGR_R_SIZE_MAX).unwrap_or(16_384);
        let mut buf = vec![0; max_gr_size as usize];
        let mut grp = MaybeUninit::uninit();
        let mut grp_ptr = std::ptr::null_mut();
        let name_c = CString::new(name).expect("String contained null bytes");
        cerr(unsafe {
            libc::getgrnam_r(
                name_c.as_ptr(),
                grp.as_mut_ptr(),
                buf.as_mut_ptr(),
                buf.len(),
                &mut grp_ptr,
            )
        })?;
        if grp_ptr.is_null() {
            Ok(None)
        } else {
            let grp = unsafe { grp.assume_init() };
            Ok(Some(unsafe { Group::from_libc(&grp) }))
        }
    }
}

// generalized traits for when we want to hide implementations
pub mod interface;

#[derive(Debug, Clone)]
pub struct Process {
    pub pid: libc::pid_t,
    pub parent_pid: libc::pid_t,
    pub group_id: libc::pid_t,
    pub session_id: libc::pid_t,
    pub term_foreground_group_id: libc::pid_t,
    pub name: PathBuf,
}

impl Default for Process {
    fn default() -> Self {
        Self::new()
    }
}

impl Process {
    pub fn new() -> Process {
        Process {
            pid: Self::process_id(),
            parent_pid: Self::parent_id(),
            group_id: Self::group_id(),
            session_id: Self::session_id(),
            term_foreground_group_id: Self::term_foreground_group_id(),
            name: Self::process_name().unwrap_or_else(|| PathBuf::from("sudo")),
        }
    }

    pub fn process_name() -> Option<PathBuf> {
        std::env::args().next().map(PathBuf::from)
    }

    /// Return the process identifier for the current process
    pub fn process_id() -> libc::pid_t {
        unsafe { libc::getpid() }
    }

    /// Return the parent process identifier for the current process
    pub fn parent_id() -> libc::pid_t {
        unsafe { libc::getppid() }
    }

    /// Return the process group id for the current process
    pub fn group_id() -> libc::pid_t {
        unsafe { libc::getpgid(0) }
    }

    /// Get the session id for the current process
    pub fn session_id() -> libc::pid_t {
        unsafe { libc::getsid(0) }
    }

    /// Get the process group id of the process group that is currently in
    /// the foreground of our terminal
    pub fn term_foreground_group_id() -> libc::pid_t {
        match OpenOptions::new().read(true).write(true).open("/dev/tty") {
            Ok(f) => {
                let res = unsafe { libc::tcgetpgrp(f.as_raw_fd()) };
                if res == -1 {
                    0
                } else {
                    res
                }
            }
            Err(_) => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::User;

    #[test]
    fn test_get_user() {
        let root = User::from_uid(0).unwrap().unwrap();

        assert_eq!(root.uid, 0);
        assert_eq!(root.name, "root");
    }

    #[test]
    fn test_group_impl() {
        use super::Group;
        use std::ffi::CString;

        fn test(name: &str, passwd: &str, gid: libc::gid_t, mem: &[&str]) {
            assert_eq!(
                {
                    let c_mem: Vec<CString> =
                        mem.iter().map(|&s| CString::new(s).unwrap()).collect();
                    let c_name = CString::new(name).unwrap();
                    let c_passwd = CString::new(passwd).unwrap();
                    unsafe {
                        Group::from_libc(&libc::group {
                            gr_name: c_name.as_ptr() as *mut _,
                            gr_passwd: c_passwd.as_ptr() as *mut _,
                            gr_gid: gid,
                            gr_mem: c_mem
                                .iter()
                                .map(|cs| cs.as_ptr() as *mut _)
                                .chain(std::iter::once(std::ptr::null_mut()))
                                .collect::<Vec<*mut libc::c_char>>()
                                .as_mut_ptr(),
                        })
                    }
                },
                Group {
                    name: name.to_string(),
                    passwd: passwd.to_string(),
                    gid,
                    members: mem.iter().map(|s| s.to_string()).collect(),
                }
            )
        }

        test("dr. bill", "fidelio", 1999, &["eyes", "wide", "shut"]);
        test("eris", "fnord", 5, &[]);
        test("abc", "password123", 42, &[""]);
    }
}
