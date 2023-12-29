use std::{borrow::Cow, ops::ControlFlow, path::Path};

use crate::{
    common::{Context, Error},
    pam::CLIConverser,
    sudo::{cli::SudoListOptions, pam::PamAuthenticator, SudoersPolicy},
    sudoers::{Authorization, ListRequest, Policy, Request, Sudoers},
    system::interface::ROOT,
    system::User,
};

use super::{Pipeline, PolicyPlugin};

impl Pipeline<SudoersPolicy, PamAuthenticator<CLIConverser>> {
    pub(in crate::sudo) fn run_list(mut self, cmd_opts: SudoListOptions) -> Result<(), Error> {
        let verbose_list_mode = cmd_opts.list.is_verbose();
        let other_user = cmd_opts
            .other_user
            .as_ref()
            .map(|username| {
                User::from_name(username.as_cstr())?
                    .ok_or_else(|| Error::UserNotFound(username.clone().into()))
            })
            .transpose()?;

        let original_command = cmd_opts.positional_args.first().cloned();

        let sudoers = self.policy.init()?;
        let context = super::build_context(cmd_opts.into(), &sudoers)?;

        if original_command.is_some() && !context.command.resolved {
            return Err(Error::CommandNotFound(context.command.command));
        }

        if self
            .auth_invoking_user(&context, &sudoers, &original_command, &other_user)?
            .is_break()
        {
            return Ok(());
        }

        if let Some(other_user) = &other_user {
            check_other_users_list_perms(other_user, &context, &sudoers, &original_command)?;
        }

        if let Some(original_command) = original_command {
            check_sudo_command_perms(&original_command, &context, &other_user, &sudoers)?;
        } else {
            let invoking_user = other_user.as_ref().unwrap_or(&context.current_user);
            println_ignore_io_error!(
                "User {} may run the following commands on {}:",
                invoking_user.name,
                context.hostname
            );

            let matching_entries = sudoers.matching_entries(invoking_user, &context.hostname);

            for entry in matching_entries {
                if verbose_list_mode {
                    let entry = entry.verbose();
                    println_ignore_io_error!("{entry}");
                } else {
                    println_ignore_io_error!("{entry}");
                }
            }
        }

        Ok(())
    }

    fn auth_invoking_user(
        &mut self,
        context: &Context,
        sudoers: &Sudoers,
        original_command: &Option<String>,
        other_user: &Option<User>,
    ) -> Result<ControlFlow<(), ()>, Error> {
        let list_request = ListRequest {
            target_user: &context.target_user,
            target_group: &context.target_group,
        };
        let judgement =
            sudoers.check_list_permission(&context.current_user, &context.hostname, list_request);
        match judgement.authorization() {
            Authorization::Allowed(auth) => {
                self.auth_and_update_record_file(context, auth)?;
                Ok(ControlFlow::Continue(()))
            }

            Authorization::Forbidden => {
                if context.current_user.uid == ROOT {
                    if original_command.is_some() {
                        return Err(Error::Silent);
                    }

                    println_ignore_io_error!(
                        "User {} is not allowed to run sudo on {}.",
                        other_user.as_ref().unwrap_or(&context.current_user).name,
                        context.hostname
                    );

                    // this branch does not result in exit code 1 but no further information should
                    // be printed in this case
                    Ok(ControlFlow::Break(()))
                } else {
                    let command = if other_user.is_none() {
                        "sudo".into()
                    } else {
                        format_list_command(original_command)
                    };

                    Err(Error::NotAllowed {
                        username: context.current_user.name.clone(),
                        command,
                        hostname: context.hostname.clone(),
                        other_user: other_user.as_ref().map(|user| &user.name).cloned(),
                    })
                }
            }
        }
    }
}

fn check_other_users_list_perms(
    other_user: &User,
    context: &Context,
    sudoers: &Sudoers,
    original_command: &Option<String>,
) -> Result<(), Error> {
    let list_request = ListRequest {
        target_user: &context.target_user,
        target_group: &context.target_group,
    };
    let judgement = sudoers.check_list_permission(other_user, &context.hostname, list_request);

    if let Authorization::Forbidden = judgement.authorization() {
        return Err(Error::NotAllowed {
            username: context.current_user.name.clone(),
            command: format_list_command(original_command),
            hostname: context.hostname.clone(),
            other_user: Some(other_user.name.clone()),
        });
    }

    Ok(())
}

fn check_sudo_command_perms(
    original_command: &str,
    context: &Context,
    other_user: &Option<User>,
    sudoers: &Sudoers,
) -> Result<(), Error> {
    let user = other_user.as_ref().unwrap_or(&context.current_user);

    let request = Request {
        user: &context.target_user,
        group: &context.target_group,
        command: &context.command.command,
        arguments: &context.command.arguments,
    };

    let judgement = sudoers.check(user, &context.hostname, request);

    if let Authorization::Forbidden = judgement.authorization() {
        return Err(Error::Silent);
    } else {
        let command_is_relative_path =
            original_command.contains('/') && !Path::new(&original_command).is_absolute();
        let command: Cow<_> = if command_is_relative_path {
            original_command.into()
        } else {
            let resolved_command = &context.command.command;
            resolved_command.display().to_string().into()
        };

        if context.command.arguments.is_empty() {
            println_ignore_io_error!("{command}");
        } else {
            println_ignore_io_error!("{command} {}", context.command.arguments.join(" "));
        }
    }

    Ok(())
}

fn format_list_command(original_command: &Option<String>) -> Cow<'static, str> {
    if let Some(original_command) = original_command {
        format!("list {original_command}").into()
    } else {
        "list".into()
    }
}
