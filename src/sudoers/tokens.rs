//! Various tokens

use crate::common::{SudoPath, SudoString};

use super::basic_parser::{Many, Token};
use crate::common::{HARDENED_ENUM_VALUE_0, HARDENED_ENUM_VALUE_1, HARDENED_ENUM_VALUE_2};

#[cfg_attr(test, derive(Clone, PartialEq, Eq))]
pub struct Username(pub SudoString);

/// A username consists of alphanumeric characters as well as "." and "-", but does not start with an underscore.
impl Token for Username {
    fn construct(text: String) -> Result<Self, String> {
        SudoString::new(text)
            .map_err(|e| e.to_string())
            .map(Username)
    }

    fn accept(c: char) -> bool {
        c.is_ascii_alphanumeric() || ".-_".contains(c)
    }

    fn accept_1st(c: char) -> bool {
        c != '_' && Self::accept(c)
    }
}

impl Many for Username {}

pub struct Digits(pub u32);

impl Token for Digits {
    const MAX_LEN: usize = 9;

    fn construct(s: String) -> Result<Self, String> {
        Ok(Digits(s.parse().unwrap()))
    }

    fn accept(c: char) -> bool {
        c.is_ascii_digit()
    }
}

pub struct Numeric(pub String);

impl Token for Numeric {
    const MAX_LEN: usize = 18;

    fn construct(s: String) -> Result<Self, String> {
        Ok(Numeric(s))
    }

    fn accept(c: char) -> bool {
        c.is_ascii_hexdigit() || c == '.'
    }
}

/// A hostname consists of alphanumeric characters and ".", "-",  "_"
pub struct Hostname(pub String);

impl std::ops::Deref for Hostname {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Token for Hostname {
    fn construct(text: String) -> Result<Self, String> {
        Ok(Hostname(text))
    }

    fn accept(c: char) -> bool {
        c.is_ascii_alphanumeric() || ".-_".contains(c)
    }
}

impl Many for Hostname {}

/// This enum allows items to use the ALL wildcard or be specified with aliases, or directly.
/// (Maybe this is better defined not as a Token but simply directly as an implementation of [crate::sudoers::basic_parser::Parse])
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[repr(u32)]
pub enum Meta<T> {
    All = HARDENED_ENUM_VALUE_0,
    Only(T) = HARDENED_ENUM_VALUE_1,
    Alias(String) = HARDENED_ENUM_VALUE_2,
}

impl<T> Meta<T> {
    #[cfg(test)]
    pub fn is_alias(&self) -> bool {
        matches!(self, Self::Alias(..))
    }
}

impl<T: Token> Token for Meta<T> {
    fn construct(raw: String) -> Result<Self, String> {
        // `T` may accept whitespace resulting in `raw` having trailing whitespace which would make
        // the first two checks below fail. this `cooked` version has no trailing whitespace
        let cooked = raw.trim_end().to_string();

        Ok(if cooked == "ALL" {
            Meta::All
        } else if cooked.starts_with(AliasName::accept_1st)
            && cooked.chars().skip(1).all(AliasName::accept)
        {
            Meta::Alias(cooked)
        } else {
            Meta::Only(T::construct(raw)?)
        })
    }

    const MAX_LEN: usize = T::MAX_LEN;

    fn accept(c: char) -> bool {
        T::accept(c) || c.is_uppercase()
    }
    fn accept_1st(c: char) -> bool {
        T::accept_1st(c) || c.is_uppercase()
    }

    const ALLOW_ESCAPE: bool = T::ALLOW_ESCAPE;

    fn escaped(c: char) -> bool {
        T::escaped(c)
    }
}

impl<T: Many> Many for Meta<T> {
    const SEP: char = T::SEP;
    const LIMIT: usize = T::LIMIT;
}

/// An identifier that consits of only uppercase characters.
pub struct AliasName(pub String);

impl Token for AliasName {
    fn construct(s: String) -> Result<Self, String> {
        Ok(AliasName(s))
    }

    fn accept_1st(c: char) -> bool {
        c.is_ascii_uppercase() || c.is_ascii_digit()
    }

    fn accept(c: char) -> bool {
        Self::accept_1st(c) || c == '_'
    }
}

/// A struct that represents valid command strings; this can contain escape sequences and are
/// limited to 1024 characters.
pub type Command = (glob::Pattern, Option<Box<[String]>>);

impl Token for Command {
    const MAX_LEN: usize = 1024;

    fn construct(s: String) -> Result<Self, String> {
        let cvt_err = |pat: Result<_, glob::PatternError>| {
            pat.map_err(|err| format!("wildcard pattern error {err}"))
        };

        // the tokenizer should not give us a token that consists of only whitespace
        let mut cmd_iter = s.split_whitespace();
        let mut cmd = cmd_iter.next().unwrap().to_string();
        let mut args = cmd_iter.map(String::from).collect::<Vec<String>>();

        let argpat = if args.is_empty() {
            // if no arguments are mentioned, anything is allowed
            None
        } else {
            if args.last().map(|x| -> &str { x }) == Some("\"\"") {
                // if the magic "" appears, no (further) arguments are allowed
                args.pop();
            }
            if args.iter().any(|arg| arg.chars().any(|c| "?*".contains(c))) {
                return Err("wildcards are not allowed in command arguments".to_string());
            }
            Some(args.into_boxed_slice())
        };

        // record if the cmd ends in a slash and remove it if it does
        let is_dir = cmd.ends_with('/') && {
            cmd.pop();
            true
        };

        // canonicalize path (if possible)
        if let Ok(real_cmd) = crate::common::resolve::canonicalize(&cmd) {
            cmd = real_cmd
                .to_str()
                .ok_or("non-UTF8 characters in filesystem")?
                .to_string();
        }

        // if the cmd ends with a slash, any command in that directory is allowed
        if is_dir {
            cmd.push_str("/*");
        }

        Ok((cvt_err(glob::Pattern::new(&cmd))?, argpat))
    }

    // all commands start with "/" except "sudoedit"
    fn accept_1st(c: char) -> bool {
        c == '/' || c == 's'
    }

    fn accept(c: char) -> bool {
        !Self::escaped(c) && !c.is_control()
    }

    const ALLOW_ESCAPE: bool = true;
    fn escaped(c: char) -> bool {
        matches!(c, '\\' | ',' | ':' | '=' | '#')
    }
}

impl Many for Command {}

pub struct DefaultName(pub String);

impl Token for DefaultName {
    fn construct(text: String) -> Result<Self, String> {
        Ok(DefaultName(text))
    }

    fn accept(c: char) -> bool {
        c.is_ascii_alphanumeric() || c == '_'
    }
}

pub struct EnvVar(pub String);

impl Token for EnvVar {
    fn construct(text: String) -> Result<Self, String> {
        Ok(EnvVar(text))
    }

    fn accept(c: char) -> bool {
        !c.is_control() && !c.is_whitespace() && !Self::escaped(c)
    }

    const ALLOW_ESCAPE: bool = true;
    fn escaped(c: char) -> bool {
        matches!(c, '\\' | '=' | '#' | '"')
    }
}

pub struct QuotedText(pub String);

impl Token for QuotedText {
    const MAX_LEN: usize = 1024;

    fn construct(s: String) -> Result<Self, String> {
        Ok(QuotedText(s))
    }

    fn accept(c: char) -> bool {
        !Self::escaped(c)
    }

    const ALLOW_ESCAPE: bool = true;
    fn escaped(c: char) -> bool {
        matches!(c, '\\' | '"') || c.is_control()
    }
}

// `@include "some/path"`
//           ^^^^^^^^^^^
pub struct QuotedInclude(pub String);

impl Token for QuotedInclude {
    const MAX_LEN: usize = 1024;

    fn construct(s: String) -> Result<Self, String> {
        Ok(QuotedInclude(s))
    }

    fn accept(c: char) -> bool {
        !Self::escaped(c)
    }

    const ALLOW_ESCAPE: bool = true;
    fn escaped(c: char) -> bool {
        matches!(c, '"') || c.is_control()
    }
}

pub struct IncludePath(pub String);

impl Token for IncludePath {
    const MAX_LEN: usize = 1024;

    fn construct(s: String) -> Result<Self, String> {
        Ok(IncludePath(s))
    }

    fn accept(c: char) -> bool {
        !c.is_control() && !Self::escaped(c)
    }

    const ALLOW_ESCAPE: bool = true;
    fn escaped(c: char) -> bool {
        matches!(c, '\\' | '"' | ' ')
    }
}

// used for Defaults where quotes around some items are optional
pub struct StringParameter(pub String);

impl Token for StringParameter {
    const MAX_LEN: usize = QuotedText::MAX_LEN;

    fn construct(s: String) -> Result<Self, String> {
        Ok(StringParameter(s))
    }

    fn accept(c: char) -> bool {
        !c.is_control() && !Self::escaped(c)
    }

    const ALLOW_ESCAPE: bool = true;
    fn escaped(c: char) -> bool {
        matches!(c, '\\' | '"' | ' ' | '#' | ',')
    }
}

// a path used for in CWD and CHROOT specs
#[derive(Clone, PartialEq)]
#[cfg_attr(test, derive(Debug, Eq))]
pub enum ChDir {
    Path(SudoPath),
    Any,
}

impl Token for ChDir {
    const MAX_LEN: usize = 1024;

    fn construct(s: String) -> Result<Self, String> {
        if s == "*" {
            Ok(ChDir::Any)
        } else if s.contains('*') {
            Err("path cannot contain '*'".to_string())
        } else {
            Ok(ChDir::Path(
                SudoPath::try_from(s).map_err(|e| e.to_string())?,
            ))
        }
    }

    fn accept(c: char) -> bool {
        !c.is_control() && !Self::escaped(c)
    }

    fn accept_1st(c: char) -> bool {
        "~/*".contains(c)
    }

    const ALLOW_ESCAPE: bool = true;
    fn escaped(c: char) -> bool {
        matches!(c, '\\' | '"' | ' ')
    }
}
