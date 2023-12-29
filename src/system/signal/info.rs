use crate::system::interface::ProcessId;

use super::SignalNumber;

/// Information related to the arrival of a signal.
#[repr(transparent)]
pub(crate) struct SignalInfo {
    info: libc::siginfo_t,
}

impl SignalInfo {
    pub(super) const SIZE: usize = std::mem::size_of::<Self>();

    /// Returns whether the signal was sent by the user or not.
    pub(crate) fn is_user_signaled(&self) -> bool {
        // FIXME: we should check if si_code is equal to SI_USER but for some reason the latter it
        // is not available in libc.
        self.info.si_code <= 0
    }

    /// Gets the PID that sent the signal.
    pub(crate) fn pid(&self) -> ProcessId {
        // FIXME: some signals don't set si_pid.
        unsafe { ProcessId(self.info.si_pid()) }
    }

    /// Gets the signal number.
    pub(crate) fn signal(&self) -> SignalNumber {
        self.info.si_signo
    }
}
