use std::{fs::File, io, os::fd::AsRawFd};

use crate::{
    cutils::cerr,
    system::interface::{GroupId, UserId},
};

pub(crate) trait Chown {
    fn chown(&self, uid: UserId, gid: GroupId) -> io::Result<()>;
}

impl Chown for File {
    fn chown(&self, owner: UserId, group: GroupId) -> io::Result<()> {
        let fd = self.as_raw_fd();

        cerr(unsafe { libc::fchown(fd, owner.id(), group.id()) }).map(|_| ())
    }
}
