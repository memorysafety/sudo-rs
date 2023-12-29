#![forbid(unsafe_code)]

use crate::common::{resolve::resolve_current_user, Context, Error};
use crate::log::dev_info;
use crate::system::interface::ROOT;
use crate::system::timestamp::RecordScope;
use crate::system::User;
use crate::system::{time::Duration, timestamp::SessionRecordFile, Process};
use cli::help;
#[cfg(test)]
pub use cli::SudoAction;
#[cfg(not(test))]
use cli::SudoAction;
use pam::PamAuthenticator;
use pipeline::{Pipeline, PolicyPlugin};
use std::path::Path;

mod cli;
mod diagnostic;
mod env;
mod pam;
mod pipeline;

const VERSION: &str = std::env!("CARGO_PKG_VERSION");

fn candidate_sudoers_file() -> &'static Path {
    let pb_rs: &'static Path = Path::new("/etc/sudoers-rs");
    if pb_rs.exists() {
        dev_info!("Running with /etc/sudoers-rs file");
        pb_rs
    } else {
        dev_info!("Running with /etc/sudoers file");
        Path::new("/etc/sudoers")
    }
}

#[derive(Default)]
pub(crate) struct SudoersPolicy {}

impl PolicyPlugin for SudoersPolicy {
    type PreJudgementPolicy = crate::sudoers::Sudoers;
    type Policy = crate::sudoers::Judgement;

    fn init(&mut self) -> Result<Self::PreJudgementPolicy, Error> {
        let sudoers_path = candidate_sudoers_file();

        let (sudoers, syntax_errors) = crate::sudoers::Sudoers::open(sudoers_path)
            .map_err(|e| Error::Configuration(format!("{e}")))?;

        for crate::sudoers::Error(pos, error) in syntax_errors {
            diagnostic::diagnostic!("{error}", sudoers_path @ pos);
        }

        Ok(sudoers)
    }

    fn judge(
        &mut self,
        pre: Self::PreJudgementPolicy,
        context: &Context,
    ) -> Result<Self::Policy, Error> {
        Ok(pre.check(
            &context.current_user,
            &context.hostname,
            crate::sudoers::Request {
                user: &context.target_user,
                group: &context.target_group,
                command: &context.command.command,
                arguments: &context.command.arguments,
            },
        ))
    }
}

fn sudo_process() -> Result<(), Error> {
    crate::log::SudoLogger::new("sudo: ").into_global_logger();

    dev_info!("development logs are enabled");

    self_check()?;

    let pipeline = Pipeline {
        policy: SudoersPolicy::default(),
        authenticator: PamAuthenticator::new_cli(),
    };

    // parse cli options
    match SudoAction::from_env() {
        Ok(action) => match action {
            SudoAction::Help(_) => {
                eprintln_ignore_io_error!("{}", help::long_help_message());
                std::process::exit(0);
            }
            SudoAction::Version(_) => {
                eprintln_ignore_io_error!("sudo-rs {VERSION}");
                std::process::exit(0);
            }
            SudoAction::RemoveTimestamp(_) => {
                let user = resolve_current_user()?;
                let mut record_file =
                    SessionRecordFile::open_for_user(user.uid, Duration::seconds(0))?;
                record_file.reset()?;
                Ok(())
            }
            SudoAction::ResetTimestamp(_) => {
                if let Some(scope) = RecordScope::for_process(&Process::new()) {
                    let user = resolve_current_user()?;
                    let mut record_file =
                        SessionRecordFile::open_for_user(user.uid, Duration::seconds(0))?;
                    record_file.disable(scope, None)?;
                }
                Ok(())
            }
            SudoAction::Validate(options) => pipeline.run_validate(options),
            SudoAction::Run(options) => {
                // special case for when no command is given
                if options.positional_args.is_empty() && !options.shell && !options.login {
                    eprintln_ignore_io_error!("{}", help::USAGE_MSG);
                    std::process::exit(1);
                } else {
                    pipeline.run(options)
                }
            }
            SudoAction::List(options) => pipeline.run_list(options),
            SudoAction::Edit(_) => {
                eprintln_ignore_io_error!("error: `--edit` flag has not yet been implemented");
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln_ignore_io_error!("{e}\n{}", help::USAGE_MSG);
            std::process::exit(1);
        }
    }
}

fn self_check() -> Result<(), Error> {
    let euid = User::effective_uid();
    if euid == ROOT {
        Ok(())
    } else {
        Err(Error::SelfCheck)
    }
}

pub fn main() {
    match sudo_process() {
        Ok(()) => (),
        Err(error) => {
            if !error.is_silent() {
                diagnostic::diagnostic!("{error}");
            }
            std::process::exit(1);
        }
    }
}
