// TODO: add "allowed:" restrictions on string parameters that are enum-like; and maybe also on
// integers that have a particular range restriction
//
// FUTURE IDEA: use a representation that allows for more Rust-type structure rather than passing
// strings around; some settings in sudoers file are more naturally represented like that, such as
// "verifypw" and "logfile"
#[derive(Debug)]
pub enum SudoDefault {
    Flag(bool),
    Integer(OptTuple<i128>),
    Text(OptTuple<&'static str>),
    List(&'static [&'static str]),
    Enum(OptTuple<StrEnum<'static>>),
}

#[derive(Debug)]
pub struct OptTuple<T> {
    pub default: T,
    pub negated: Option<T>,
}

mod strenum;
pub use strenum::StrEnum;

mod settings_dsl;
use settings_dsl::*;

defaults! {
    always_query_group_plugin = false
    always_set_home           = false
    env_reset                 = true
    mail_badpass              = true
    match_group_by_gid        = false
    use_pty                   = false
    visiblepw                 = false

    passwd_tries              = 3
    umask                     = 0o22 (!= 0o777)

    editor                    = "/usr/bin/editor"
    lecture_file              = ""
    secure_path               = "" (!= "")
    verifypw                  = "all" (!= "never") [all, always, any, never]

    env_keep                  = ["COLORS", "DISPLAY", "HOSTNAME", "KRB5CCNAME", "LS_COLORS", "PATH",
                                 "PS1", "PS2", "XAUTHORITY", "XAUTHORIZATION", "XDG_CURRENT_DESKTOP"]

    env_check                 = ["COLORTERM", "LANG", "LANGUAGE", "LC_*", "LINGUAS", "TERM", "TZ"]

    env_delete                = ["IFS", "CDPATH", "LOCALDOMAIN", "RES_OPTIONS", "HOSTALIASES",
                                "NLSPATH", "PATH_LOCALE", "LD_*", "_RLD*", "TERMINFO", "TERMINFO_DIRS",
                                "TERMPATH", "TERMCAP", "ENV", "BASH_ENV", "PS4", "GLOBIGNORE",
                                "BASHOPTS", "SHELLOPTS", "JAVA_TOOL_OPTIONS", "PERLIO_DEBUG",
                                "PERLLIB", "PERL5LIB", "PERL5OPT", "PERL5DB", "FPATH", "NULLCMD",
                                "READNULLCMD", "ZDOTDIR", "TMPPREFIX", "PYTHONHOME", "PYTHONPATH",
                                "PYTHONINSPECT", "PYTHONUSERBASE", "RUBYLIB", "RUBYOPT", "*=()*"]
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn check() {
        macro_rules! test {
            ($name:ident => $value:pat) => {
                let Some(foo@$value) = sudo_default(stringify!($name)) else { unreachable!() };
                if let SudoDefault::Enum(OptTuple { default, negated }) = foo {
                    assert!(default
                        .possible_values
                        .iter()
                        .any(|x| *x as *const str == default.get()));
                    negated.map(|neg| assert!(neg.possible_values.contains(&neg.get())));
                }
            };
        }
        assert!(sudo_default("bla").is_none());

        use SudoDefault::*;

        test! { always_query_group_plugin => Flag(false) };
        test! { always_set_home => Flag(false) };
        test! { env_reset => Flag(true) };
        test! { mail_badpass => Flag(true) };
        test! { match_group_by_gid => Flag(false) };
        test! { use_pty => Flag(false) };
        test! { visiblepw => Flag(false) };
        test! { passwd_tries => Integer(OptTuple { default: 3, negated: None }) };
        test! { umask => Integer(OptTuple { default: 18, negated: Some(511) }) };
        test! { editor => Text(OptTuple { default: "/usr/bin/editor", negated: None }) };
        test! { lecture_file => Text(_) };
        test! { secure_path => Text(OptTuple { default: "", negated: Some("") }) };
        test! { env_keep => List(_) };
        test! { env_check => List(["COLORTERM", "LANG", "LANGUAGE", "LC_*", "LINGUAS", "TERM", "TZ"]) };
        test! { env_delete => List(_) };
        test! { verifypw => Enum(OptTuple { default: StrEnum { value: "all", possible_values: [_, "always", "any", _] }, negated: Some(StrEnum { value: "never", .. }) }) };

        let myenum = StrEnum::new("hello", &["hello", "goodbye"]).unwrap();
        assert!(&myenum as &str == "hello");
    }
}
