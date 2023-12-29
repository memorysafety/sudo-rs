use std::{
    fmt::Display,
    path::{Path, PathBuf},
};

use crate::system::escape_os_str_lossy;

use super::resolve::{canonicalize, resolve_path};

#[derive(Debug, Default)]
#[cfg_attr(test, derive(PartialEq))]
pub struct CommandAndArguments {
    pub(crate) command: PathBuf,
    pub(crate) arguments: Vec<String>,
    pub(crate) resolved: bool,
    pub(crate) arg0: Option<PathBuf>,
}

impl Display for CommandAndArguments {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cmd = escape_os_str_lossy(self.command.as_os_str());
        let args = self
            .arguments
            .iter()
            .map(|a| a.escape_default().collect::<String>())
            .collect::<Vec<_>>()
            .join(" ");
        write!(f, "{} {}", cmd, args)
    }
}

// when -i and -s are used, the arguments given to sudo are escaped "except for alphanumerics, underscores, hyphens, and dollar signs."
fn escaped(arguments: Vec<String>) -> String {
    arguments
        .into_iter()
        .map(|arg| {
            arg.chars()
                .map(|c| match c {
                    '_' | '-' | '$' => c.to_string(),
                    c if c.is_alphanumeric() => c.to_string(),
                    _ => ['\\', c].iter().collect(),
                })
                .collect()
        })
        .collect::<Vec<String>>()
        .join(" ")
}

//checks whether the Path is actually describing a qualified path (i.e. contains "/")
//or just specifying the name of a file (in which case we are going to resolve it via PATH)
fn is_qualified(path: impl AsRef<Path>) -> bool {
    path.as_ref().parent() != Some(Path::new(""))
}

impl CommandAndArguments {
    pub fn build_from_args(shell: Option<PathBuf>, mut arguments: Vec<String>, path: &str) -> Self {
        let mut resolved = true;
        let mut command;
        let mut arg0 = None;
        if let Some(chosen_shell) = shell {
            command = chosen_shell;
            if !arguments.is_empty() {
                arguments = vec!["-c".to_string(), escaped(arguments)]
            }
        } else {
            command = arguments.first().map(|s| s.into()).unwrap_or_default();
            arguments.remove(0);

            // remember the original binary name before resolving symlinks; this is not
            // to be used except for setting the `arg0`
            arg0 = Some(command.clone());

            // resolve the command, remembering errors (but not propagating them)
            if !is_qualified(&command) {
                match resolve_path(&command, path) {
                    Some(qualified_path) => command = qualified_path,
                    None => resolved = false,
                }
            }

            // resolve symlinks, even if the command was obtained through a PATH or SHELL
            // once again, failure to canonicalize should not stop the pipeline
            match canonicalize(&command) {
                Ok(canon_path) => command = canon_path,
                Err(_) => resolved = false,
            }
        }

        CommandAndArguments {
            command,
            arguments,
            resolved,
            arg0,
        }
    }
}

#[cfg(test)]
mod test {
    use super::{escaped, CommandAndArguments};

    #[test]
    fn test_escaped() {
        let test = |src: &[&str], target: &str| {
            assert_eq!(
                &escaped(src.iter().map(|s| s.to_string()).collect()),
                target
            );
        };
        test(&["a", "b", "c"], "a b c");
        test(&["a", "b c"], "a b\\ c");
        test(&["a", "b-c"], "a b-c");
        test(&["a", "b#c"], "a b\\#c");
        test(&["1 2 3"], "1\\ 2\\ 3");
        test(&["! @ $"], "\\!\\ \\@\\ $");
    }

    #[test]
    fn test_build_command_and_args() {
        assert_eq!(
            CommandAndArguments::build_from_args(
                None,
                vec!["/usr/bin/fmt".into(), "hello".into()],
                "/bin"
            ),
            CommandAndArguments {
                command: "/usr/bin/fmt".into(),
                arguments: vec!["hello".into()],
                resolved: true,
                arg0: Some("/usr/bin/fmt".into()),
            }
        );

        assert_eq!(
            CommandAndArguments::build_from_args(
                None,
                vec!["fmt".into(), "hello".into()],
                "/tmp:/usr/bin:/bin"
            ),
            CommandAndArguments {
                command: "/usr/bin/fmt".into(),
                arguments: vec!["hello".into()],
                resolved: true,
                arg0: Some("fmt".into()),
            }
        );

        assert_eq!(
            CommandAndArguments::build_from_args(
                None,
                vec!["thisdoesnotexist".into(), "hello".into()],
                ""
            ),
            CommandAndArguments {
                command: "thisdoesnotexist".into(),
                arguments: vec!["hello".into()],
                resolved: false,
                arg0: Some("thisdoesnotexist".into()),
            }
        );

        assert_eq!(
            CommandAndArguments::build_from_args(
                Some("shell".into()),
                vec!["ls".into(), "hello".into()],
                "/bin"
            ),
            CommandAndArguments {
                command: "shell".into(),
                arguments: vec!["-c".into(), "ls hello".into()],
                resolved: true,
                arg0: None,
            }
        );
    }

    #[test]
    fn qualified_paths() {
        use super::is_qualified;
        assert!(is_qualified("foo/bar"));
        assert!(is_qualified("a/b/bar"));
        assert!(is_qualified("a/b//bar"));
        assert!(is_qualified("/bar"));
        assert!(is_qualified("/bar/"));
        assert!(is_qualified("/bar/foo/"));
        assert!(is_qualified("/"));
        assert!(is_qualified("")); // don't try to resolve ""
        assert!(!is_qualified("bar"));
    }
}
