use std::{ffi::c_int, io, os::unix::process::CommandExt, process::Command};

use super::{
    event::PollEvent,
    event::{EventRegistry, Process, StopReason},
    io_util::was_interrupted,
    terminate_process, ExitReason, HandleSigchld, ProcessOutput,
};
use crate::{
    common::bin_serde::BinPipe,
    system::signal::{
        consts::*, register_handlers, SignalHandler, SignalHandlerBehavior, SignalNumber,
        SignalSet, SignalStream,
    },
};
use crate::{
    exec::{handle_sigchld, opt_fmt, signal_fmt},
    log::{dev_error, dev_info, dev_warn},
    system::{
        fork, getpgid, getpgrp,
        interface::ProcessId,
        kill, killpg,
        term::{Terminal, UserTerm},
        wait::WaitOptions,
        FileCloser, ForkResult,
    },
};

pub(super) fn exec_no_pty(sudo_pid: ProcessId, mut command: Command) -> io::Result<ProcessOutput> {
    // FIXME (ogsudo): Initialize the policy plugin's session here.

    // Block all the signals until we are done setting up the signal handlers so we don't miss
    // SIGCHLD.
    let original_set = match SignalSet::full().and_then(|set| set.block()) {
        Ok(original_set) => Some(original_set),
        Err(err) => {
            dev_warn!("cannot block signals: {err}");
            None
        }
    };

    let mut file_closer = FileCloser::new();

    // FIXME (ogsudo): Some extra config happens here if selinux is available.

    // Use a pipe to get the IO error if `exec` fails.
    let (mut errpipe_tx, errpipe_rx) = BinPipe::pair()?;

    // Don't close the error pipe as we need it to retrieve the error code if the command execution
    // fails.
    file_closer.except(&errpipe_tx);

    let ForkResult::Parent(command_pid) = fork().map_err(|err| {
        dev_warn!("unable to fork command process: {err}");
        err
    })?
    else {
        file_closer.close_the_universe()?;

        // Restore the signal mask now that the handlers have been setup.
        if let Some(set) = original_set {
            if let Err(err) = set.set_mask() {
                dev_warn!("cannot restore signal mask: {err}");
            }
        }

        let err = command.exec();

        dev_warn!("failed to execute command: {err}");
        // If `exec` returns, it means that executing the command failed. Send the error to the
        // monitor using the pipe.
        if let Some(error_code) = err.raw_os_error() {
            errpipe_tx.write(&error_code).ok();
        }

        return Ok(ProcessOutput::ChildExit);
    };

    dev_info!("executed command with pid {command_pid}");

    let mut registry = EventRegistry::new();

    let mut closure = ExecClosure::new(command_pid, sudo_pid, errpipe_rx, &mut registry)?;

    // Restore the signal mask now that the handlers have been setup.
    if let Some(set) = original_set {
        if let Err(err) = set.set_mask() {
            dev_warn!("cannot restore signal mask: {err}");
        }
    }

    let command_exit_reason = match registry.event_loop(&mut closure) {
        StopReason::Break(err) => return Err(err),
        StopReason::Exit(reason) => reason,
    };

    Ok(ProcessOutput::SudoExit {
        output: crate::exec::ExecOutput {
            command_exit_reason,
            restore_signal_handlers: Box::new(move || drop(closure.signal_handlers)),
        },
    })
}

struct ExecClosure {
    command_pid: Option<ProcessId>,
    sudo_pid: ProcessId,
    parent_pgrp: ProcessId,
    errpipe_rx: BinPipe<i32>,
    signal_stream: &'static SignalStream,
    signal_handlers: [SignalHandler; ExecClosure::SIGNALS.len()],
}

impl ExecClosure {
    const SIGNALS: [SignalNumber; 12] = [
        SIGINT, SIGQUIT, SIGTSTP, SIGTERM, SIGHUP, SIGALRM, SIGPIPE, SIGUSR1, SIGUSR2, SIGCHLD,
        SIGCONT, SIGWINCH,
    ];

    fn new(
        command_pid: ProcessId,
        sudo_pid: ProcessId,
        errpipe_rx: BinPipe<i32>,
        registry: &mut EventRegistry<Self>,
    ) -> io::Result<Self> {
        registry.register_event(&errpipe_rx, PollEvent::Readable, |_| ExecEvent::ErrPipe);

        let signal_stream = SignalStream::init()?;

        registry.register_event(signal_stream, PollEvent::Readable, |_| ExecEvent::Signal);

        let signal_handlers = register_handlers(Self::SIGNALS)?;

        Ok(Self {
            command_pid: Some(command_pid),
            errpipe_rx,
            sudo_pid,
            parent_pgrp: getpgrp(),
            signal_stream,
            signal_handlers,
        })
    }

    /// Decides if the signal sent by the process with `signaler_pid` PID is self-terminating.
    ///
    /// A signal is self-terminating if `signaler_pid`:
    /// - is the same PID of the command, or
    /// - is in the process group of the command and either sudo or the command is the leader.
    fn is_self_terminating(&self, signaler_pid: ProcessId) -> bool {
        if signaler_pid != ProcessId(0) {
            if Some(signaler_pid) == self.command_pid {
                return true;
            }

            if let Ok(signaler_pgrp) = getpgid(signaler_pid) {
                if Some(signaler_pgrp) == self.command_pid || signaler_pgrp == self.sudo_pid {
                    return true;
                }
            }
        }

        false
    }

    /// Suspend the main process.
    fn suspend_parent(&self, signal: SignalNumber) {
        let mut opt_tty = UserTerm::open().ok();
        let mut opt_pgrp = None;

        if let Some(tty) = opt_tty.as_ref() {
            if let Ok(saved_pgrp) = tty.tcgetpgrp() {
                // Save the terminal's foreground process group so we can restore it after resuming
                // if needed.
                opt_pgrp = Some(saved_pgrp);
            } else {
                opt_tty.take();
            }
        }

        if let Some(saved_pgrp) = opt_pgrp {
            // This means that the command was stopped trying to access the terminal. If the
            // terminal has a different foreground process group and we own the terminal, we give
            // it to the command and let it continue.
            if let SIGTTOU | SIGTTIN = signal {
                if saved_pgrp == self.parent_pgrp {
                    if let Some(command_pgrp) = self.command_pid.and_then(|pid| getpgid(pid).ok()) {
                        if command_pgrp != self.parent_pgrp
                            && opt_tty
                                .as_ref()
                                .is_some_and(|tty| tty.tcsetpgrp_nobg(command_pgrp).is_ok())
                        {
                            if let Err(err) = killpg(command_pgrp, SIGCONT) {
                                dev_warn!("cannot send SIGCONT to command ({command_pgrp}): {err}");
                            }

                            return;
                        }
                    }
                }
            }
        }

        let sigtstp_handler = if signal == SIGTSTP {
            SignalHandler::register(signal, SignalHandlerBehavior::Default)
                .map_err(|err| dev_warn!("cannot set handler for {}: {err}", signal_fmt(signal)))
                .ok()
        } else {
            None
        };

        if let Err(err) = kill(self.sudo_pid, signal) {
            dev_warn!(
                "cannot send {} to {} (sudo): {err}",
                signal_fmt(signal),
                self.sudo_pid
            );
        }

        drop(sigtstp_handler);

        if let Some(saved_pgrp) = opt_pgrp {
            // Restore the foreground process group after resuming.
            if saved_pgrp != self.parent_pgrp {
                if let Some(tty) = opt_tty {
                    tty.tcsetpgrp_nobg(saved_pgrp).ok();
                }
            }
        }
    }

    fn on_signal(&mut self, registry: &mut EventRegistry<Self>) {
        let info = match self.signal_stream.recv() {
            Ok(info) => info,
            Err(err) => {
                dev_error!("sudo could not receive signal: {err}");
                return;
            }
        };

        dev_info!(
            "received{} {} from {}",
            opt_fmt(info.is_user_signaled(), " user signaled"),
            info.signal(),
            info.pid()
        );

        let Some(command_pid) = self.command_pid else {
            dev_info!("command was terminated, ignoring signal");
            return;
        };

        match info.signal() {
            SIGCHLD => handle_sigchld(self, registry, "command", command_pid),
            signal => {
                // FIXME: we should handle SIGWINCH here if we want to support I/O plugins that
                // react on window change events.

                // Skip the signal if it was sent by the user and it is self-terminating.
                if info.is_user_signaled() && self.is_self_terminating(info.pid()) {
                    return;
                }

                if signal == SIGALRM {
                    terminate_process(command_pid, false);
                } else {
                    kill(command_pid, signal).ok();
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecEvent {
    Signal,
    ErrPipe,
}

impl Process for ExecClosure {
    type Event = ExecEvent;
    type Break = io::Error;
    type Exit = ExitReason;

    fn on_event(&mut self, event: Self::Event, registry: &mut EventRegistry<Self>) {
        match event {
            ExecEvent::Signal => self.on_signal(registry),
            ExecEvent::ErrPipe => {
                match self.errpipe_rx.read() {
                    Err(err) if was_interrupted(&err) => { /* Retry later */ }
                    Err(err) => registry.set_break(err),
                    Ok(error_code) => {
                        // Received error code from the command, forward it to the parent.
                        registry.set_break(io::Error::from_raw_os_error(error_code));
                    }
                }
            }
        }
    }
}

impl HandleSigchld for ExecClosure {
    const OPTIONS: WaitOptions = WaitOptions::new().all().untraced().no_hang();

    fn on_exit(&mut self, exit_code: c_int, registry: &mut EventRegistry<Self>) {
        registry.set_exit(ExitReason::Code(exit_code));
        self.command_pid = None;
    }

    fn on_term(&mut self, signal: SignalNumber, registry: &mut EventRegistry<Self>) {
        registry.set_exit(ExitReason::Signal(signal));
        self.command_pid = None;
    }

    fn on_stop(&mut self, signal: SignalNumber, _registry: &mut EventRegistry<Self>) {
        self.suspend_parent(signal);
    }
}
