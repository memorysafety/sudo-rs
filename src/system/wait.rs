use std::io;

use libc::{
    c_int, WEXITSTATUS, WIFCONTINUED, WIFEXITED, WIFSIGNALED, WIFSTOPPED, WNOHANG, WSTOPSIG,
    WTERMSIG, WUNTRACED, __WALL,
};

use crate::cutils::cerr;
use crate::system::signal::signal_name;
use crate::{system::interface::ProcessId, system::signal::SignalNumber};

mod sealed {
    pub(crate) trait Sealed {}

    impl Sealed for crate::system::interface::ProcessId {}
}

pub(crate) trait Wait: sealed::Sealed {
    /// Wait for a process to change state.
    ///
    /// Calling this function will block until a child specified by the given process ID has
    /// changed state. This can be configured further using [`WaitOptions`].
    fn wait(self, options: WaitOptions) -> Result<(ProcessId, WaitStatus), WaitError>;
}

impl Wait for ProcessId {
    fn wait(self, options: WaitOptions) -> Result<(ProcessId, WaitStatus), WaitError> {
        let mut status: c_int = 0;

        let pid = cerr(unsafe { libc::waitpid(self.id(), &mut status, options.flags) })
            .map_err(WaitError::Io)?;

        if pid == 0 && options.flags & WNOHANG != 0 {
            return Err(WaitError::NotReady);
        }

        Ok((ProcessId(pid), WaitStatus { status }))
    }
}

/// Error values returned when [`Wait::wait`] fails.
#[derive(Debug)]
pub enum WaitError {
    // No children were in a waitable state.
    //
    // This is only returned if the [`WaitOptions::no_hang`] option is used.
    NotReady,
    // Regular I/O error.
    Io(io::Error),
}

/// Options to configure how [`Wait::wait`] waits for children.
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

    /// Wait for all children, regardless of being created using `clone` or not.
    pub const fn all(mut self) -> Self {
        self.flags |= __WALL;
        self
    }
}

/// The status of the waited child.
pub struct WaitStatus {
    status: c_int,
}

impl std::fmt::Debug for WaitStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(exit_status) = self.exit_status() {
            write!(f, "ExitStatus({exit_status})")
        } else if let Some(signal) = self.term_signal() {
            write!(f, "TermSignal({})", signal_name(signal))
        } else if let Some(signal) = self.stop_signal() {
            write!(f, "StopSignal({})", signal_name(signal))
        } else if self.did_continue() {
            write!(f, "Continued")
        } else {
            write!(f, "Unknown")
        }
    }
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
    use libc::{SIGKILL, SIGSTOP};

    use crate::system::{
        interface::ProcessId,
        kill,
        wait::{Wait, WaitError, WaitOptions},
    };

    #[test]
    fn exit_status() {
        let command = std::process::Command::new("sh")
            .args(["-c", "sleep 0.1; exit 42"])
            .spawn()
            .unwrap();

        let command_pid = ProcessId(command.id() as i32);

        let (pid, status) = command_pid.wait(WaitOptions::new()).unwrap();
        assert_eq!(command_pid, pid);
        assert!(status.did_exit());
        assert_eq!(status.exit_status(), Some(42));

        assert!(!status.was_signaled());
        assert!(status.term_signal().is_none());
        assert!(!status.was_stopped());
        assert!(status.stop_signal().is_none());
        assert!(!status.did_continue());

        // Waiting when there are no children should fail.
        let WaitError::Io(err) = command_pid.wait(WaitOptions::new()).unwrap_err() else {
            panic!("`WaitError::NotReady` should not happens if `WaitOptions::no_hang` was not called.");
        };
        assert_eq!(err.raw_os_error(), Some(libc::ECHILD));
    }

    #[test]
    fn signals() {
        let command = std::process::Command::new("sh")
            .args(["-c", "sleep 1; exit 42"])
            .spawn()
            .unwrap();

        let command_pid = ProcessId(command.id() as i32);

        kill(command_pid, SIGSTOP).unwrap();

        let (pid, status) = command_pid.wait(WaitOptions::new().untraced()).unwrap();
        assert_eq!(command_pid, pid);
        assert_eq!(status.stop_signal(), Some(SIGSTOP));

        kill(command_pid, SIGKILL).unwrap();

        let (pid, status) = command_pid.wait(WaitOptions::new()).unwrap();
        assert_eq!(command_pid, pid);
        assert!(status.was_signaled());
        assert_eq!(status.term_signal(), Some(SIGKILL));

        assert!(!status.did_exit());
        assert!(status.exit_status().is_none());
        assert!(!status.was_stopped());
        assert!(status.stop_signal().is_none());
        assert!(!status.did_continue());
    }

    #[test]
    fn no_hang() {
        let command = std::process::Command::new("sh")
            .args(["-c", "sleep 0.1; exit 42"])
            .spawn()
            .unwrap();

        let command_pid = ProcessId(command.id() as i32);

        let mut count = 0;
        let (pid, status) = loop {
            match command_pid.wait(WaitOptions::new().no_hang()) {
                Ok(ok) => break ok,
                Err(WaitError::NotReady) => count += 1,
                Err(WaitError::Io(err)) => panic!("{err}"),
            }
        };

        assert_eq!(command_pid, pid);
        assert!(status.did_exit());
        assert_eq!(status.exit_status(), Some(42));
        assert!(count > 0);

        assert!(!status.was_signaled());
        assert!(status.term_signal().is_none());
        assert!(!status.was_stopped());
        assert!(status.stop_signal().is_none());
        assert!(!status.did_continue());
    }
}
