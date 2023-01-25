use std::path::PathBuf;

use clap:: {
    Parser,
    Arg,
    Command,
    Args,
    error::Error,
    ArgMatches,
    FromArgMatches,
    ArgAction
};

#[clap(
    name = "sudo-rs",
    about = "sudo - execute a command as another user",
    version,
    // disable_version_flag = true,
    // disable_help_flag = true,
    override_usage = "usage: sudo -h | -K | -k | -V
    usage: sudo -v [-AknS] [-g group] [-h host] [-p prompt] [-u user]
    usage: sudo -l [-AknS] [-g group] [-h host] [-p prompt] [-U user] [-u user] [command]
    usage: sudo [-AbEHknPS] [-C num] [-D directory] [-g group] [-h host] [-p prompt] [-R directory] [-T timeout] [-u user] [VAR=value] [-i|-s] [<command>]
    usage: sudo -e [-AknS] [-C num] [-D directory] [-g group] [-h host] [-p prompt] [-R directory] [-T timeout] [-u user] file ...",
)]
#[derive(Debug, Parser, Clone)]
pub struct Cli {   
    #[arg(long, short = 'A', help = "use a helper program for password prompting", action)]  
    pub askpass: bool,
    #[arg(short = 'b', long, help = "run command in the background", action)]
    pub background: bool,
    #[arg(short = 'B', long, help = "ring bell when prompting", action)]
    pub bell: bool,
    #[arg(short = 'C', long = "close-from", help = "close all file descriptors >= num")]
    pub num: Option<i16>,
    #[arg(short = 'D', long = "chdir", help = "change the working directory before running command")]
    pub directory:  Option<PathBuf>,
    #[arg(long, value_delimiter=',', default_value = None, default_missing_value = "", require_equals = true, num_args = 0..)]
    pub preserve_env: Vec<String>,
    #[arg(short = 'E')]
    pub short_preserve_env: bool,
    #[arg(short = 'e', long, help = "edit files instead of running a command", action)]
    pub edit: bool,
    #[arg(short = 'g', long = "group", help = "run command as the specified group name or ID")]
    pub group: Option<String>,
    #[arg(short = 'H', long = "set-home", help = "set HOME variable to target user's home dir", action)]
    pub set_home: bool,
    // #[arg(long, help = "display help message and exit!", action = ArgAction::Help)] 
    // pub help: bool, // TO DO: help as well as host are supposed to have short 'h'???
    // #[arg(short = 'h', long = "host", help = "run command on host (if supported by plugin)")]
    // pub host: Option<String>,
    #[arg(short = 'i', long, help = "run login shell as the target user; a command may also be specified", action, conflicts_with("shell"))]
    pub login: bool,
    #[arg(short = 'K', long = "remove-timestamp", help = "remove timestamp file completely", action, conflicts_with("reset_timestamp"), conflicts_with("version"))]
    pub remove_timestamp: bool,
    #[arg(short = 'k', long = "reset-timestamp", help = "invalidate timestamp file", action, conflicts_with("remove_timestamp"), conflicts_with("version"))]
    pub reset_timestamp: bool,
    #[arg(short, long, help = "list user's privileges or check a specific command; use twice for longer format
    ", action)]
    pub list: bool,
    #[arg(short = 'n', long = "non-interactive", help = "non-interactive mode, no prompts are used", action)]
    pub non_interactive: bool,
    #[arg(short = 'P', long = "preserve-groups", help = "preserve group vector instead of setting to target's", action)]
    pub preserve_groups: bool,
    #[arg(short = 'p', long = "prompt", help = "use the specified password prompt")]
    pub prompt: Option<String>,
    #[arg(short = 'R', long = "chroot", help = "change the root directory before running command", value_name = "directory")]
    pub chroot: Option<PathBuf>,
    #[arg(short = 'S', long, help = "read password from standard input", action)]
    pub stdin: bool,
    #[arg(short = 's', long, help = "run shell as the target user; a command may also be specified", action)]
    pub shell: bool,
    #[arg(short = 'T', long = "command-timeout", help = "terminate command after the specified time limit", value_name = "timeout")]
    pub command_timeout: Option<String>,
    #[arg(short = 'U', long = "other-user", help = "in list mode, display privileges for user", value_name = "user")]
    pub other_user: Option<String>,
    #[arg(short = 'u', long = "user", help = "run command (or edit file) as specified user name or ID")]
    pub user: Option<String>,
    // #[arg(short = 'V', long = "version", help = "display version information and exit!", action = ArgAction::Version, conflicts_with("host"), conflicts_with("remove_timestamp"), conflicts_with("reset_timestamp"))] 
    // pub version: bool,
    #[arg(short = 'v', long, help = "update user's timestamp without running a command", action)]
    pub validate: bool,
    #[arg(long = " ", help = "stop processing command line arguments", action)] // long arg should be "--", not allowed. How to pass?
    pub stop_processing_args: bool,
    // To Do: in OGSudo there is an option   --    "stop processing command line arguments." hyphens are  not allowed in clap!

}


#[derive(Debug)]
pub struct SudoOptions {
    // This is what OGsudo calls `-E, --preserve-env`
    pub preserve_env: bool,
    // This is what OGsudo calls `--preserve-env=list`
    pub preserve_env_list: Vec<String>,
}

impl From<Cli> for SudoOptions {
    fn from(command: Cli) -> Self {
        // This lets us know if the user passed `--preserve-env` with no args
        let preserve_env_no_args = command.preserve_env.iter().any(String::is_empty);

        Self {
            preserve_env: command.short_preserve_env || preserve_env_no_args,
            preserve_env_list: {
                // Filter any empty item from the list as this means that the user passed
                // `--preserve-env` with no args which is not relevant for this list.
                command
                    .preserve_env
                    .into_iter()
                    .filter(|s| !s.is_empty())
                    .collect()
            },
        }
    }
}
