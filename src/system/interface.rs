use std::ffi::CStr;

pub type GroupId = libc::gid_t;
pub type UserId = libc::uid_t;
pub type ProcessId = libc::pid_t;
pub type DeviceId = libc::dev_t;

/// This trait/module is here to not make this crate independent (at the present time) in the idiosyncracies of user representation details
/// (which we may decide over time), as well as to make explicit what functionality a user-representation must have; this
/// interface is not set in stone and "easy" to change.
pub trait UnixUser {
    fn has_name(&self, _name: &str) -> bool {
        false
    }
    fn has_uid(&self, _uid: libc::uid_t) -> bool {
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
    fn has_uid(&self, uid: GroupId) -> bool {
        self.uid == uid
    }
    fn is_root(&self) -> bool {
        self.has_uid(0)
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

    fn test_user(user: impl UnixUser, name_c: &CStr, uid: libc::uid_t) {
        let name = name_c.to_str().unwrap();
        assert!(user.has_name(name));
        assert!(user.has_uid(uid));
        assert!(user.in_group_by_name(name_c));
        assert_eq!(user.is_root(), name == "root");
    }

    fn test_group(group: impl UnixGroup, name: &str, gid: libc::gid_t) {
        assert_eq!(group.as_gid(), gid);
        assert_eq!(group.try_as_name(), Some(name));
    }

    #[test]
    #[ignore = "ci"]
    fn test_unix_user() {
        let user = |name| User::from_name(name).unwrap().unwrap();
        test_user(user(cstr!("root")), cstr!("root"), 0);
        test_user(user(cstr!("daemon")), cstr!("daemon"), 1);
    }

    #[test]
    #[ignore = "ci"]
    fn test_unix_group() {
        let group = |name| Group::from_name(name).unwrap().unwrap();
        test_group(group(cstr!("root")), "root", 0);
        test_group(group(cstr!("daemon")), "daemon", 1);
    }

    #[test]
    fn test_default() {
        impl UnixUser for () {}
        assert!(!().has_name("root"));
        assert!(!().has_uid(0));
        assert!(!().is_root());
        assert!(!().in_group_by_name(cstr!("root")));
    }
}
