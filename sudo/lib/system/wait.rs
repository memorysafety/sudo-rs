use std::io;

use libc::{
    c_int, WCONTINUED, WEXITSTATUS, WIFCONTINUED, WIFEXITED, WIFSIGNALED, WIFSTOPPED, WNOHANG,
    WSTOPSIG, WTERMSIG, WUNTRACED, __WALL,
};
use sudo_cutils::cerr;

use crate::{interface::ProcessId, signal::SignalNumber};

/// Wait for a process to change state.
///
/// Calling this function will block until a child specified by [`WaitPid`] has changed state. This
/// can be configured further using [`WaitOptions`].
pub fn waitpid<P: Into<WaitPid>>(
    pid: P,
    options: WaitOptions,
) -> Result<(ProcessId, WaitStatus), WaitError> {
    let pid = pid.into().into_pid();
    let mut status: c_int = 0;

    let pid =
        cerr(unsafe { libc::waitpid(pid, &mut status, options.flags) }).map_err(WaitError::Io)?;

    if pid == 0 && options.flags & WNOHANG != 0 {
        return Err(WaitError::NotReady);
    }

    Ok((pid, WaitStatus { status }))
}

/// Error values returned when [`waitpid`] fails.
#[derive(Debug)]
pub enum WaitError {
    // No children were in a waitable state.
    //
    // This is only returned if the [`WaitOptions::no_hang`] option is used.
    NotReady,
    // Regular I/O error.
    Io(io::Error),
}

/// Which child process to wait for.
pub enum WaitPid {
    /// Wait for any child process.
    Any,
    /// Wait for the child process with the given ID.
    One(ProcessId),
}

impl WaitPid {
    fn into_pid(self) -> ProcessId {
        match self {
            Self::Any => -1,
            Self::One(pid) => pid,
        }
    }
}

impl From<ProcessId> for WaitPid {
    fn from(pid: ProcessId) -> Self {
        debug_assert!(pid > 0);
        Self::One(pid)
    }
}

/// Options to configure how [`waitpid`] waits for children.
pub struct WaitOptions {
    flags: c_int,
}

impl WaitOptions {
    /// Only wait for terminated children.
    pub const fn new() -> Self {
        Self { flags: 0 }
    }

    /// Return immediately if no child has exited.
    pub const fn no_hang(mut self) -> Self {
        self.flags |= WNOHANG;
        self
    }

    /// Return immediately if a child has stopped.
    pub const fn untraced(mut self) -> Self {
        self.flags |= WUNTRACED;
        self
    }

    /// Return immediately if a child has been resumed by `SIGCONT`.
    pub const fn continued(mut self) -> Self {
        self.flags |= WCONTINUED;
        self
    }

    /// Wait for all children, regardless of being created using `clone` or not.
    pub const fn all(mut self) -> Self {
        self.flags |= __WALL;
        self
    }
}

/// The status of the waited child.
#[derive(Clone, Copy)]
pub struct WaitStatus {
    status: c_int,
}

impl WaitStatus {
    /// Return `true` if the child terminated normally, i.e., by calling `exit`.
    pub const fn did_exit(&self) -> bool {
        WIFEXITED(self.status)
    }

    /// Return the exit status of the child if the child terminated normally.
    pub const fn exit_status(&self) -> Option<c_int> {
        if self.did_exit() {
            Some(WEXITSTATUS(self.status))
        } else {
            None
        }
    }

    /// Return `true` if the child process was terminated by a signal.
    pub const fn was_signaled(&self) -> bool {
        WIFSIGNALED(self.status)
    }

    /// Return the signal number which caused the child to terminate if the child was terminated by
    /// a signal.
    pub const fn term_signal(&self) -> Option<SignalNumber> {
        if self.was_signaled() {
            Some(WTERMSIG(self.status))
        } else {
            None
        }
    }

    /// Return `true` if the child process was stopped by a signal.
    pub const fn was_stopped(&self) -> bool {
        WIFSTOPPED(self.status)
    }

    /// Return the signal number which caused the child to stop if the child was stopped by a
    /// signal.
    pub const fn stop_signal(&self) -> Option<SignalNumber> {
        if self.was_stopped() {
            Some(WSTOPSIG(self.status))
        } else {
            None
        }
    }

    /// Return `true` if the child process was resumed by receiving `SIGCONT`.
    pub const fn did_continue(&self) -> bool {
        WIFCONTINUED(self.status)
    }
}

#[cfg(test)]
mod tests {
    use libc::{SIGCONT, SIGKILL, SIGSTOP};

    use crate::{
        interface::ProcessId,
        kill,
        wait::{WaitError, WaitPid},
    };

    use super::{waitpid, WaitOptions};

    #[test]
    fn exit_status() {
        let command = std::process::Command::new("sh")
            .args(["-c", "exit 42"])
            .spawn()
            .unwrap();

        let command_pid = command.id() as ProcessId;

        let (pid, status) = waitpid(command_pid, WaitOptions::new()).unwrap();
        assert_eq!(command_pid, pid);
        assert_eq!(status.exit_status(), Some(42));
    }

    #[test]
    fn signals() {
        let command = std::process::Command::new("sh")
            .args(["-c", "sleep 1; exit 42"])
            .spawn()
            .unwrap();

        let command_pid = command.id() as ProcessId;

        kill(command_pid, SIGSTOP).unwrap();

        let (pid, status) = waitpid(command_pid, WaitOptions::new().untraced()).unwrap();
        assert_eq!(command_pid, pid);
        assert_eq!(status.stop_signal(), Some(SIGSTOP));

        kill(command_pid, SIGCONT).unwrap();

        let (pid, status) = waitpid(command_pid, WaitOptions::new().continued()).unwrap();
        assert_eq!(command_pid, pid);
        assert!(status.did_continue());

        kill(command_pid, SIGKILL).unwrap();

        let (pid, status) = waitpid(command_pid, WaitOptions::new()).unwrap();
        assert_eq!(command_pid, pid);
        assert_eq!(status.term_signal(), Some(SIGKILL));
    }

    #[test]
    fn no_hang() {
        let command = std::process::Command::new("sh")
            .args(["-c", "sleep 0.1; exit 42"])
            .spawn()
            .unwrap();

        let command_pid = command.id() as ProcessId;

        let mut count = 0;
        let (pid, status) = loop {
            match waitpid(command_pid, WaitOptions::new().no_hang()) {
                Ok(ok) => break ok,
                Err(WaitError::NotReady) => count += 1,
                Err(WaitError::Io(err)) => panic!("{err}"),
            }
        };

        assert_eq!(command_pid, pid);
        assert_eq!(status.exit_status(), Some(42));
        assert!(count > 0);
    }

    #[test]
    fn any() {
        let cmd1 = std::process::Command::new("sh")
            .args(["-c", "sleep 0.1; exit 42"])
            .spawn()
            .unwrap();

        let cmd2 = std::process::Command::new("sh")
            .args(["-c", "sleep 0.2; exit 43"])
            .spawn()
            .unwrap();

        let (pid, status) = waitpid(WaitPid::Any, WaitOptions::new()).unwrap();
        assert_eq!(cmd1.id() as ProcessId, pid);
        assert_eq!(status.exit_status(), Some(42));

        let (pid, status) = waitpid(WaitPid::Any, WaitOptions::new()).unwrap();
        assert_eq!(cmd2.id() as ProcessId, pid);
        assert_eq!(status.exit_status(), Some(43));
    }
}