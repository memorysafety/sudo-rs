use std::convert::From;
use std::ffi::CStr;
use std::fmt;
use std::str::FromStr;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GroupId(pub libc::gid_t);
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UserId(pub libc::uid_t);
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ProcessId(pub libc::pid_t);
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DeviceId(pub libc::dev_t);

pub(crate) const ROOT_ID: u32 = 0;
pub(crate) const ROOT: UserId = UserId(ROOT_ID);

impl UserId {
    pub fn id(&self) -> u32 {
        self.0
    }
}

impl ProcessId {
    pub fn id(&self) -> i32 {
        self.0
    }
}

impl GroupId {
    pub fn id(&self) -> u32 {
        self.0
    }
}

impl DeviceId {
    pub fn id(&self) -> u64 {
        self.0
    }
}

impl FromStr for UserId {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let uid = s.parse::<libc::uid_t>()?;
        Ok(UserId(uid))
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let uid_str = format!("{}", self.0);
        f.write_str(&uid_str)
    }
}

impl FromStr for ProcessId {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let pid = s.parse::<libc::pid_t>()?;
        Ok(ProcessId(pid))
    }
}

impl fmt::Display for ProcessId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pid_str = format!("{}", self.0);
        f.write_str(&pid_str)
    }
}

impl From<ProcessId> for i64 {
    fn from(value: ProcessId) -> Self {
        value.0.into()
    }
}

impl FromStr for GroupId {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let gid = s.parse::<libc::gid_t>()?;
        Ok(GroupId(gid))
    }
}

impl fmt::Display for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let gid_str = format!("{}", self.0);
        f.write_str(&gid_str)
    }
}

impl FromStr for DeviceId {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let did = s.parse::<libc::dev_t>()?;
        Ok(DeviceId(did))
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let did_str = format!("{}", self.0);
        f.write_str(&did_str)
    }
}

/// This trait/module is here to not make this crate independent (at the present time) in the idiosyncracies of user representation details
/// (which we may decide over time), as well as to make explicit what functionality a user-representation must have; this
/// interface is not set in stone and "easy" to change.
pub trait UnixUser {
    fn has_name(&self, _name: &str) -> bool {
        false
    }
    fn has_uid(&self, _uid: UserId) -> bool {
        false
    }
    fn is_root(&self) -> bool {
        false
    }
    fn in_group_by_name(&self, _name: &CStr) -> bool {
        false
    }
    fn in_group_by_gid(&self, _gid: GroupId) -> bool {
        false
    }
}

pub trait UnixGroup {
    fn as_gid(&self) -> GroupId;
    fn try_as_name(&self) -> Option<&str>;
}

impl UnixUser for super::User {
    fn has_name(&self, name: &str) -> bool {
        self.name == name
    }
    fn has_uid(&self, uid: UserId) -> bool {
        self.uid == uid
    }
    fn is_root(&self) -> bool {
        let root_id = UserId(ROOT_ID);
        self.has_uid(root_id)
    }
    fn in_group_by_name(&self, name_c: &CStr) -> bool {
        if let Ok(Some(group)) = super::Group::from_name(name_c) {
            self.in_group_by_gid(group.gid)
        } else {
            false
        }
    }
    fn in_group_by_gid(&self, gid: GroupId) -> bool {
        self.groups.contains(&gid)
    }
}

impl UnixGroup for super::Group {
    fn as_gid(&self) -> GroupId {
        self.gid
    }

    fn try_as_name(&self) -> Option<&str> {
        Some(&self.name)
    }
}

#[cfg(test)]
mod test {
    use crate::system::{Group, User};

    use super::*;

    #[test]
    fn test_user_id() {
        let uid = UserId(1000);
        assert_eq!(uid.id(), 1000u32);
        let parsed_uid: UserId = "1000".parse().unwrap();
        assert_eq!(parsed_uid, uid);
        assert_eq!(format!("{}", uid), "1000");
    }

    #[test]
    fn test_group_id() {
        let gid = GroupId(1000);
        assert_eq!(gid.id(), 1000u32);
        let parsed_gid: GroupId = "1000".parse().unwrap();
        assert_eq!(parsed_gid, gid);
        assert_eq!(format!("{}", gid), "1000");
    }

    #[test]
    fn test_process_id() {
        let pid = ProcessId(1000);
        assert_eq!(pid.id(), 1000i32);
        let parsed_pid: ProcessId = "1000".parse().unwrap();
        assert_eq!(parsed_pid, pid);
        assert_eq!(format!("{}", pid), "1000");
    }

    #[test]
    fn test_device_id() {
        let did = DeviceId(1000);
        assert_eq!(did.id(), 1000u64);
        let parsed_did: DeviceId = "1000".parse().unwrap();
        assert_eq!(parsed_did, did);
        assert_eq!(format!("{}", did), "1000");
    }

    fn test_user(user: impl UnixUser, name_c: &CStr, uid: UserId) {
        let name = name_c.to_str().unwrap();
        assert!(user.has_name(name));
        assert!(user.has_uid(uid));
        assert!(user.in_group_by_name(name_c));
        assert_eq!(user.is_root(), name == "root");
    }

    fn test_group(group: impl UnixGroup, name: &str, gid: GroupId) {
        assert_eq!(group.as_gid(), gid);
        assert_eq!(group.try_as_name(), Some(name));
    }

    #[test]
    fn test_unix_user() {
        let user = |name| User::from_name(name).unwrap().unwrap();
        test_user(user(cstr!("root")), cstr!("root"), UserId(ROOT_ID));
        test_user(user(cstr!("daemon")), cstr!("daemon"), UserId(1));
    }

    #[test]
    fn test_unix_group() {
        let group = |name| Group::from_name(name).unwrap().unwrap();
        test_group(group(cstr!("root")), "root", GroupId(ROOT_ID));
        test_group(group(cstr!("daemon")), "daemon", GroupId(1));
    }

    #[test]
    fn test_default() {
        impl UnixUser for () {}
        assert!(!().has_name("root"));
        assert!(!().has_uid(UserId(ROOT_ID)));
        assert!(!().is_root());
        assert!(!().in_group_by_name(cstr!("root")));
    }
}
