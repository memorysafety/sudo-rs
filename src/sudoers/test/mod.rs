use std::ffi::CStr;

use super::ast;
use super::*;
use basic_parser::{parse_eval, parse_lines, parse_string};

#[derive(PartialEq)]
struct Named(&'static str);

fn dummy_cksum(name: &str) -> u32 {
    if name == "root" {
        0
    } else {
        1000 + name.chars().fold(0, |x, y| (x * 97 + y as u32) % 1361)
    }
}

impl UnixUser for Named {
    fn has_name(&self, name: &str) -> bool {
        self.0 == name
    }

    fn has_uid(&self, uid: UserId) -> bool {
        dummy_cksum(self.0) == uid.id()
    }

    fn in_group_by_name(&self, name: &CStr) -> bool {
        self.has_name(name.to_str().unwrap())
    }

    fn in_group_by_gid(&self, gid: GroupId) -> bool {
        dummy_cksum(self.0) == gid.id()
    }

    fn is_root(&self) -> bool {
        self.0 == "root"
    }
}

impl UnixGroup for Named {
    fn as_gid(&self) -> crate::system::interface::GroupId {
        GroupId(dummy_cksum(self.0))
    }
    fn try_as_name(&self) -> Option<&str> {
        Some(self.0)
    }
}

macro_rules! request {
    ($user:ident) => {
        (&Named(stringify!($user)), &Named(stringify!($user)))
    };
    ($user:ident, $group:ident) => {
        (&Named(stringify!($user)), &Named(stringify!($group)))
    };
}

macro_rules! sudoer {
    ($($e:expr),*) => {
        parse_lines(&mut [$($e),*, ""].join("\n").chars().peekable())
            .into_iter()
            .map(|x| Ok::<_,basic_parser::Status>(x.unwrap()))
    }
}

// alternative to parse_eval, but goes through sudoer! directly
#[must_use]
fn parse_line(s: &str) -> Sudo {
    sudoer![s].next().unwrap().unwrap()
}

/// Returns `None` if a syntax error is encountered
fn try_parse_line(s: &str) -> Option<Sudo> {
    parse_lines(&mut [s, ""].join("").chars().peekable())
        .into_iter()
        .next()?
        .ok()
}

#[test]
fn ambiguous_spec() {
    assert!(parse_eval::<ast::Sudo>("marc, User_Alias ALL = ALL").is_spec());
}

#[test]
fn permission_test() {
    let root = || (&Named("root"), &Named("root"));

    let realpath =
        |path: &Path| crate::common::resolve::canonicalize(path).unwrap_or(path.to_path_buf());

    macro_rules! FAIL {
        ([$($sudo:expr),*], $user:expr => $req:expr, $server:expr; $command:expr) => {
            let (Sudoers { rules,aliases,settings }, _) = analyze(Path::new("/etc/fakesudoers"), sudoer![$($sudo),*]);
            let cmdvec = $command.split_whitespace().map(String::from).collect::<Vec<_>>();
            let req = Request { user: $req.0, group: $req.1, command: &realpath(cmdvec[0].as_ref()), arguments: &cmdvec[1..].to_vec() };
            assert_eq!(Sudoers { rules, aliases, settings }.check(&Named($user), $server, req).flags, None);
        }
    }

    macro_rules! pass {
        ([$($sudo:expr),*], $user:expr => $req:expr, $server:expr; $command:expr $(=> [$($key:ident : $val:expr),*])?) => {
            let (Sudoers { rules,aliases,settings }, _) = analyze(Path::new("/etc/fakesudoers"), sudoer![$($sudo),*]);
            let cmdvec = $command.split_whitespace().map(String::from).collect::<Vec<_>>();
            let req = Request { user: $req.0, group: $req.1, command: &realpath(cmdvec[0].as_ref()), arguments: &cmdvec[1..].to_vec() };
            let result = Sudoers { rules, aliases, settings }.check(&Named($user), $server, req).flags;
            assert!(!result.is_none());
            $(
                let result = result.unwrap();
                $(assert_eq!(result.$key, $val);)*
            )?
        }
    }
    macro_rules! SYNTAX {
        ([$sudo:expr]) => {
            assert!(parse_string::<Sudo>($sudo).is_err())
        };
    }

    SYNTAX!(["ALL ALL = (;) ALL"]);
    FAIL!(["user ALL=(ALL:ALL) ALL"], "nobody"    => root(), "server"; "/bin/hello");
    pass!(["user ALL=(ALL:ALL) ALL"], "user"      => root(), "server"; "/bin/hello");
    pass!(["user ALL=(ALL:ALL) /bin/foo"], "user" => root(), "server"; "/bin/foo" => [authenticate: Authenticate::None]);
    FAIL!(["user ALL=(ALL:ALL) /bin/foo"], "user" => root(), "server"; "/bin/hello");
    pass!(["user ALL=(ALL:ALL) PASSWD: /bin/foo"], "user" => root(), "server"; "/bin/foo" => [authenticate: Authenticate::Passwd]);
    pass!(["user ALL=(ALL:ALL) NOPASSWD: PASSWD: /bin/foo"], "user" => root(), "server"; "/bin/foo" => [authenticate: Authenticate::Passwd]);
    pass!(["user ALL=(ALL:ALL) PASSWD: NOPASSWD: /bin/foo"], "user" => root(), "server"; "/bin/foo" => [authenticate: Authenticate::Nopasswd]);
    pass!(["user ALL=(ALL:ALL) /bin/foo, NOPASSWD: /bin/bar"], "user" => root(), "server"; "/bin/foo" => [authenticate: Authenticate::None]);
    pass!(["user ALL=(ALL:ALL) /bin/foo, NOPASSWD: /bin/bar"], "user" => root(), "server"; "/bin/bar" => [authenticate: Authenticate::Nopasswd]);
    pass!(["user ALL=(ALL:ALL) NOPASSWD: /bin/foo, /bin/bar"], "user" => root(), "server"; "/bin/bar" => [authenticate: Authenticate::Nopasswd]);
    pass!(["user ALL=(ALL:ALL) CWD=/ /bin/foo, /bin/bar"], "user" => root(), "server"; "/bin/bar" => [cwd: Some(ChDir::Path("/".into()))]);
    pass!(["user ALL=(ALL:ALL) CWD=/ /bin/foo, CWD=* /bin/bar"], "user" => root(), "server"; "/bin/bar" => [cwd: Some(ChDir::Any)]);
    pass!(["user ALL=(ALL:ALL) CWD=/bin CWD=* /bin/foo"], "user" => root(), "server"; "/bin/foo" => [cwd: Some(ChDir::Any)]);
    pass!(["user ALL=(ALL:ALL) CWD=/usr/bin NOPASSWD: /bin/foo"], "user" => root(), "server"; "/bin/foo" => [authenticate: Authenticate::Nopasswd, cwd: Some(ChDir::Path("/usr/bin".into()))]);
    //note: original sudo does not allow the below
    pass!(["user ALL=(ALL:ALL) NOPASSWD: CWD=/usr/bin /bin/foo"], "user" => root(), "server"; "/bin/foo" => [authenticate: Authenticate::Nopasswd, cwd: Some(ChDir::Path("/usr/bin".into()))]);

    pass!(["user ALL=/bin/e##o"], "user" => root(), "vm"; "/bin/e");
    SYNTAX!(["ALL ALL=(ALL) /bin/\n/echo"]);

    pass!(["user server=(ALL:ALL) ALL"], "user" => root(), "server"; "/bin/hello");
    FAIL!(["user laptop=(ALL:ALL) ALL"], "user" => root(), "server"; "/bin/hello");

    pass!(["user ALL=!/bin/hello", "user ALL=/bin/hello"], "user" => root(), "server"; "/bin/hello");
    FAIL!(["user ALL=/bin/hello", "user ALL=!/bin/hello"], "user" => root(), "server"; "/bin/hello");

    for alias in [
        "User_Alias GROUP=user1, user2",
        "User_Alias GROUP=ALL,!user3",
    ] {
        pass!([alias,"GROUP ALL=/bin/hello"], "user1" => root(), "server"; "/bin/hello");
        pass!([alias,"GROUP ALL=/bin/hello"], "user2" => root(), "server"; "/bin/hello");
        FAIL!([alias,"GROUP ALL=/bin/hello"], "user3" => root(), "server"; "/bin/hello");
    }
    pass!(["user ALL=/bin/hello arg"], "user" => root(), "server"; "/bin/hello arg");
    pass!(["user ALL=/bin/hello  arg"], "user" => root(), "server"; "/bin/hello arg");
    pass!(["user ALL=/bin/hello arg"], "user" => root(), "server"; "/bin/hello  arg");
    FAIL!(["user ALL=/bin/hello arg"], "user" => root(), "server"; "/bin/hello boo");
    // several test cases with globbing in the arguments are explicitly not supported by sudo-rs
    //pass!(["user ALL=/bin/hello a*g"], "user" => root(), "server"; "/bin/hello  aaaarg");
    //FAIL!(["user ALL=/bin/hello a*g"], "user" => root(), "server"; "/bin/hello boo");
    pass!(["user ALL=/bin/hello"], "user" => root(), "server"; "/bin/hello boo");
    FAIL!(["user ALL=/bin/hello \"\""], "user" => root(), "server"; "/bin/hello boo");
    pass!(["user ALL=/bin/hello \"\""], "user" => root(), "server"; "/bin/hello");
    pass!(["user ALL=/bin/hel*"], "user" => root(), "server"; "/bin/hello");
    pass!(["user ALL=/bin/hel*"], "user" => root(), "server"; "/bin/help");
    pass!(["user ALL=/bin/hel*"], "user" => root(), "server"; "/bin/help me");
    //pass!(["user ALL=/bin/hel* *"], "user" => root(), "server"; "/bin/help");
    FAIL!(["user ALL=/bin/hel* me"], "user" => root(), "server"; "/bin/help");
    pass!(["user ALL=/bin/hel* me"], "user" => root(), "server"; "/bin/help me");
    FAIL!(["user ALL=/bin/hel* me"], "user" => root(), "server"; "/bin/help me please");

    pass!(["user ALL=(ALL:ALL) /bin/foo"], "user" => root(), "server"; "/bin/foo" => [authenticate: Authenticate::None]);
    pass!(["root ALL=(ALL:ALL) /bin/foo"], "root" => root(), "server"; "/bin/foo" => [authenticate: Authenticate::Nopasswd]);
    pass!(["user ALL=(ALL:ALL) /bin/foo"], "user" => request! { user, user }, "server"; "/bin/foo" => [authenticate: Authenticate::Nopasswd]);
    pass!(["user ALL=(ALL:ALL) /bin/foo"], "user" => request! { user, root }, "server"; "/bin/foo" => [authenticate: Authenticate::None]);

    assert_eq!(Named("user").as_gid(), GroupId(1466));
    pass!(["#1466 server=(ALL:ALL) ALL"], "user" => root(), "server"; "/bin/hello");
    pass!(["%#1466 server=(ALL:ALL) ALL"], "user" => root(), "server"; "/bin/hello");
    FAIL!(["#1466 server=(ALL:ALL) ALL"], "root" => root(), "server"; "/bin/hello");
    FAIL!(["%#1466 server=(ALL:ALL) ALL"], "root" => root(), "server"; "/bin/hello");
    pass!(["#1466,#1234,foo server=(ALL:ALL) ALL"], "user" => root(), "server"; "/bin/hello");
    pass!(["#1234,foo,#1466 server=(ALL:ALL) ALL"], "user" => root(), "server"; "/bin/hello");
    pass!(["foo,#1234,#1466 server=(ALL:ALL) ALL"], "user" => root(), "server"; "/bin/hello");
    FAIL!(["foo,#1234,#1366 server=(ALL:ALL) ALL"], "user" => root(), "server"; "/bin/hello");
    FAIL!(["#1366,#1234,foo server=(ALL:ALL) ALL"], "user" => root(), "server"; "/bin/hello");
    pass!(["user ALL=(ALL:#1466) /bin/foo"], "user" => request! { root, root }, "server"; "/bin/foo");
    FAIL!(["user ALL=(ALL:#1466) /bin/foo"], "user" => request! { root, other }, "server"; "/bin/foo");
    pass!(["user ALL=(ALL:#1466) /bin/foo"], "user" => request! { root, user }, "server"; "/bin/foo");
    pass!(["user ALL=(root,user:ALL) /bin/foo"], "user" => request! { root, wheel }, "server"; "/bin/foo");
    pass!(["user ALL=(root,user:ALL) /bin/foo"], "user" => request! { user, wheel }, "server"; "/bin/foo");
    FAIL!(["user ALL=(root,user:ALL) /bin/foo"], "user" => request! { sudo, wheel }, "server"; "/bin/foo");
    FAIL!(["user ALL=(#0:wheel) /bin/foo"], "user" => request! { sudo, wheel }, "server"; "/bin/foo");
    pass!(["user ALL=(#0:wheel) /bin/foo"], "user" => request! { root, root }, "server"; "/bin/foo");
    FAIL!(["user ALL=(%#1466:wheel) /bin/foo"], "user" => request! { root, root }, "server"; "/bin/foo");
    pass!(["user ALL=(%#1466:wheel) /bin/foo"], "user" => request! { user, user }, "server"; "/bin/foo");

    // tests with a 'singular' runas spec
    FAIL!(["user ALL=(ALL) /bin/foo"], "user" => request! { sudo, wheel }, "server"; "/bin/foo");
    pass!(["user ALL=(ALL) /bin/foo"], "user" => request! { sudo, sudo }, "server"; "/bin/foo");

    // tests without a runas spec
    FAIL!(["user ALL=/bin/foo"], "user" => request! { sudo, sudo }, "server"; "/bin/foo");
    FAIL!(["user ALL=/bin/foo"], "user" => request! { sudo, root }, "server"; "/bin/foo");
    FAIL!(["user ALL=/bin/foo"], "user" => request! { root, sudo }, "server"; "/bin/foo");
    pass!(["user ALL=/bin/foo"], "user" => request! { root, root }, "server"; "/bin/foo");

    // slightly counterintuitive test which simulates only -g being passed
    pass!(["user ALL=(sudo:sudo) /bin/foo"], "user" => request! { user, sudo }, "server"; "/bin/foo");

    // tests with multiple runas specs
    pass!(["user ALL=(root) /bin/ls, (sudo) /bin/true"], "user" => request! { root }, "server"; "/bin/ls");
    pass!(["user ALL=(root) NOPASSWD: /bin/ls, (sudo) /bin/true"], "user" => request! { sudo }, "server"; "/bin/true" => [authenticate: Authenticate::Nopasswd]);
    FAIL!(["user ALL=(root) /bin/ls, (sudo) /bin/true"], "user" => request! { sudo }, "server"; "/bin/ls");
    FAIL!(["user ALL=(root) /bin/ls, (sudo) /bin/true"], "user" => request! { root }, "server"; "/bin/true");

    SYNTAX!(["User_Alias, marc ALL = ALL"]);

    pass!(["User_Alias FULLTIME=ALL,!marc","FULLTIME ALL=ALL"], "user" => root(), "server"; "/bin/bash");
    FAIL!(["User_Alias FULLTIME=ALL,!marc","FULLTIME ALL=ALL"], "marc" => root(), "server"; "/bin/bash");
    FAIL!(["User_Alias FULLTIME=ALL,!marc","ALL,!FULLTIME ALL=ALL"], "user" => root(), "server"; "/bin/bash");
    pass!(["User_Alias FULLTIME=ALL,!!!marc","ALL,!FULLTIME ALL=ALL"], "marc" => root(), "server"; "/bin/bash");
    pass!(["Host_Alias MACHINE=laptop,server","user MACHINE=ALL"], "user" => root(), "server"; "/bin/bash");
    pass!(["Host_Alias MACHINE=laptop,server","user MACHINE=ALL"], "user" => root(), "laptop"; "/bin/bash");
    FAIL!(["Host_Alias MACHINE=laptop,server","user MACHINE=ALL"], "user" => root(), "desktop"; "/bin/bash");
    pass!(["Cmnd_Alias WHAT=/bin/dd, /bin/rm","user ALL=WHAT"], "user" => root(), "server"; "/bin/rm");
    pass!(["Cmd_Alias WHAT=/bin/dd,/bin/rm","user ALL=WHAT"], "user" => root(), "laptop"; "/bin/dd");
    FAIL!(["Cmnd_Alias WHAT=/bin/dd,/bin/rm","user ALL=WHAT"], "user" => root(), "desktop"; "/bin/bash");

    pass!(["User_Alias A=B","User_Alias B=user","A ALL=ALL"], "user" => root(), "vm"; "/bin/ls");
    pass!(["Host_Alias A=B","Host_Alias B=vm","ALL A=ALL"], "user" => root(), "vm"; "/bin/ls");
    pass!(["Cmnd_Alias A=B","Cmnd_Alias B=/bin/ls","ALL ALL=A"], "user" => root(), "vm"; "/bin/ls");

    FAIL!(["Runas_Alias TIME=%wheel,!!sudo","user ALL=() ALL"], "user" => request!{ sudo, sudo }, "vm"; "/bin/ls");
    pass!(["Runas_Alias TIME=%wheel,!!sudo","user ALL=(TIME) ALL"], "user" => request! { sudo, sudo }, "vm"; "/bin/ls");
    FAIL!(["Runas_Alias TIME=%wheel,!!sudo","user ALL=(:TIME) ALL"], "user" => request! { sudo, sudo }, "vm"; "/bin/ls");
    pass!(["Runas_Alias TIME=%wheel,!!sudo","user ALL=(:TIME) ALL"], "user" => request! { user, sudo }, "vm"; "/bin/ls");
    pass!(["Runas_Alias TIME=%wheel,!!sudo","user ALL=(TIME) ALL"], "user" => request! { wheel, wheel }, "vm"; "/bin/ls");

    pass!(["Runas_Alias \\"," TIME=%wheel\\",",sudo # hallo","user ALL\\","=(TIME) ALL"], "user" => request! { wheel, wheel }, "vm"; "/bin/ls");

    // test the less-intuitive "substition-like" alias mechanism
    FAIL!(["User_Alias FOO=!user", "ALL, FOO ALL=ALL"], "user" => root(), "vm"; "/bin/ls");
    pass!(["User_Alias FOO=!user", "!FOO ALL=ALL"], "user" => root(), "vm"; "/bin/ls");
}

#[test]
fn default_bool_test() {
    let (Sudoers { settings, .. }, _) = analyze(
        Path::new("/etc/fakesudoers"),
        sudoer![
            "Defaults env_reset",
            "Defaults !use_pty",
            "Defaults !env_keep",
            "Defaults !secure_path",
            "Defaults !env_editor"
        ],
    );
    assert!(settings.flags.contains("env_reset"));
    assert!(!settings.flags.contains("use_pty"));
    assert!(settings.list["env_keep"].is_empty());
    assert_eq!(settings.str_value["secure_path"], None);
    assert!(!settings.flags.contains("env_editor"));
}

#[test]
fn default_set_test() {
    let (Sudoers { settings, .. }, _) = analyze(
        Path::new("/etc/fakesudoers"),
        sudoer![
            "Defaults env_keep = \"FOO HUK BAR\"",
            "Defaults env_keep -= HUK",
            "Defaults !env_check",
            "Defaults env_check += \"FOO\"",
            "Defaults env_check += \"XYZZY\"",
            "Defaults passwd_tries = 5",
            "Defaults secure_path = /etc"
        ],
    );
    assert_eq!(
        settings.list["env_keep"],
        ["FOO", "BAR"].into_iter().map(|x| x.to_string()).collect()
    );
    assert_eq!(
        settings.list["env_check"],
        ["FOO", "XYZZY"]
            .into_iter()
            .map(|x| x.to_string())
            .collect()
    );
    assert_eq!(settings.str_value["secure_path"].as_deref(), Some("/etc"));
    assert_eq!(settings.int_value["passwd_tries"], 5);

    assert!(parse_string::<Sudo>("Defaults verifypw = \"sometimes\"").is_err());
    assert!(parse_string::<Sudo>("Defaults verifypw = sometimes").is_err());
    assert!(parse_string::<Sudo>("Defaults verifypw = never").is_ok());
}

#[test]
fn default_multi_test() {
    let (Sudoers { settings, .. }, _) = analyze(
        Path::new("/etc/fakesudoers"),
        sudoer![
        "Defaults env_reset, !use_pty, secure_path=/etc, env_keep = \"FOO BAR\", env_keep -= BAR"
    ],
    );
    assert!(settings.flags.contains("env_reset"));
    assert!(!settings.flags.contains("use_pty"));
    assert_eq!(settings.str_value["secure_path"].as_deref(), Some("/etc"));
    assert_eq!(
        settings.list["env_keep"],
        ["FOO".to_string()].into_iter().collect()
    );
}

#[test]
#[should_panic]
fn invalid_directive() {
    parse_eval::<ast::Sudo>("User_Alias, user Alias = user1, user2");
}

#[test]
fn directive_test() {
    let y = parse_eval::<Spec<UserSpecifier>>;
    match parse_eval::<ast::Sudo>("User_Alias HENK = user1, user2") {
        Sudo::Decl(Directive::UserAlias(defs)) => {
            let [Def(name, list)] = &defs[..] else {
                panic!("incorrectly parsed")
            };
            assert_eq!(name, "HENK");
            assert_eq!(*list, vec![y("user1"), y("user2")]);
        }
        _ => panic!("incorrectly parsed"),
    }

    match parse_eval::<ast::Sudo>("Runas_Alias FOO = foo : BAR = bar") {
        Sudo::Decl(Directive::RunasAlias(defs)) => {
            let [Def(name1, list1), Def(name2, list2)] = &defs[..] else {
                panic!("incorrectly parsed")
            };
            assert_eq!(name1, "FOO");
            assert_eq!(*list1, vec![y("foo")]);
            assert_eq!(name2, "BAR");
            assert_eq!(*list2, vec![y("bar")]);
        }
        _ => panic!("incorrectly parsed"),
    }
}

#[test]
// the overloading of '#' causes a lot of issues
fn hashsign_test() {
    assert!(parse_line("#42 ALL=ALL").is_spec());
    assert!(parse_line("ALL ALL=(#42) ALL").is_spec());
    assert!(parse_line("ALL ALL=(%#42) ALL").is_spec());
    assert!(parse_line("ALL ALL=(:#42) ALL").is_spec());
    assert!(parse_line("User_Alias FOO=#42, %#0, #3").is_decl());
    assert!(parse_line("").is_line_comment());
    assert!(parse_line("#this is a comment").is_line_comment());
    assert!(parse_line("#include foo").is_include());
    assert!(parse_line("#includedir foo").is_include_dir());
    assert_eq!("foo bar", parse_line("#include \"foo bar\"").as_include());
    // this is fine
    assert!(parse_line("#inlcudedir foo").is_line_comment());
    assert!(parse_line("@include foo").is_include());
    assert!(parse_line("@includedir foo").is_include_dir());
    assert_eq!("foo bar", parse_line("@include \"foo bar\"").as_include());
}

#[test]
fn gh674_at_include_quoted_backslash() {
    assert!(parse_line(r#"@include "/etc/sudo\ers" "#).is_include());
    assert!(parse_line(r#"@includedir "/etc/sudo\ers.d" "#).is_include_dir());
}

#[test]
fn gh676_percent_h_escape_unsupported() {
    let (_, errs) = analyze(
        Path::new("/etc/fakesudoers"),
        sudoer!(r#"@includedir "/etc/%h" "#),
    );
    assert_eq!(errs.len(), 1);
    assert_eq!(
        errs[0].1,
        "cannot open sudoers file /etc/%h: percent escape %h in includedir is unsupported"
    )
}

#[test]
fn hashsign_error() {
    assert!(parse_line("#include foo bar").is_line_comment());
}

#[test]
fn include_regression() {
    assert!(try_parse_line("#4,#include foo").is_none());
}

#[test]
fn nullbyte_regression() {
    assert!(try_parse_line("ferris ALL=(ALL:ferris\0) ALL").is_none());
}

#[test]
fn alias_all_regression() {
    assert!(try_parse_line("User_Alias ALL = sudouser").is_none())
}

#[test]
fn defaults_regression() {
    assert!(try_parse_line("Defaults .mymachine=ALL").is_none())
}

#[test]
fn useralias_underscore_regression() {
    let sudo = parse_line("FOO_BAR ALL=ALL");
    let spec = sudo.as_spec().expect("`Sudo::Spec`");
    assert!(spec.users[0]
        .as_allow()
        .expect("`Qualified::Allow`")
        .is_alias());
}

fn test_topo_sort(n: usize) {
    let alias = |s: &str| Qualified::Allow(Meta::<UserSpecifier>::Alias(s.to_string()));
    let stop = || Qualified::Allow(Meta::<UserSpecifier>::All);
    type Elem = Spec<UserSpecifier>;
    let test_case = |x1: Elem, x2: Elem, x3: Elem| {
        let table = vec![
            Def("AAP".to_string(), vec![x1]),
            Def("NOOT".to_string(), vec![x2]),
            Def("MIES".to_string(), vec![x3]),
        ];
        let mut err = vec![];
        let order = sanitize_alias_table(&table, &mut err);
        assert!(err.is_empty());
        let mut seen = HashSet::new();
        for Def(id, defns) in order.iter().map(|&i| &table[i]) {
            if defns.iter().any(|spec| {
                let Qualified::Allow(Meta::Alias(id2)) = spec else {
                    return false;
                };
                !seen.contains(id2)
            }) {
                panic!("forward reference encountered after sorting");
            }
            seen.insert(id);
        }
    };
    match n {
        0 => test_case(alias("AAP"), alias("NOOT"), stop()),
        1 => test_case(alias("AAP"), stop(), alias("NOOT")),
        2 => test_case(alias("NOOT"), alias("AAP"), stop()),
        3 => test_case(alias("NOOT"), stop(), alias("AAP")),
        4 => test_case(stop(), alias("AAP"), alias("NOOT")),
        5 => test_case(stop(), alias("NOOT"), alias("AAP")),
        _ => panic!("error in test case"),
    }
}

#[test]
fn test_topo_positive() {
    test_topo_sort(3);
    test_topo_sort(4);
}

#[test]
#[should_panic]
fn test_topo_fail0() {
    test_topo_sort(0);
}
#[test]
#[should_panic]
fn test_topo_fail1() {
    test_topo_sort(1);
}
#[test]
#[should_panic]
fn test_topo_fail2() {
    test_topo_sort(2);
}
#[test]
#[should_panic]
fn test_topo_fail5() {
    test_topo_sort(5);
}

fn fuzz_topo_sort(siz: usize) {
    for mut n in 0..(1..siz).reduce(|x, y| x * y).unwrap() {
        let name = |s: u8| std::str::from_utf8(&[65 + s]).unwrap().to_string();
        let alias = |s: String| Qualified::Allow(Meta::<UserSpecifier>::Alias(s));
        let stop = || Qualified::Allow(Meta::<UserSpecifier>::All);

        let mut data = (0..siz - 1)
            .map(|i| alias(name(i as u8)))
            .collect::<Vec<_>>();
        data.push(stop());

        for i in (1..=siz).rev() {
            data.swap(i - 1, n % i);
            n /= i;
        }

        let table = data
            .into_iter()
            .enumerate()
            .map(|(i, x)| Def(name(i as u8), vec![x]))
            .collect();

        let mut err = vec![];
        let order = sanitize_alias_table(&table, &mut err);
        if !err.is_empty() {
            return;
        }

        let mut seen = HashSet::new();
        for Def(id, defns) in order.iter().map(|&i| &table[i]) {
            if defns.iter().any(|spec| {
                let Qualified::Allow(Meta::Alias(id2)) = spec else {
                    return false;
                };
                !seen.contains(id2)
            }) {
                panic!("forward reference encountered after sorting");
            }
            seen.insert(id);
        }
        assert!(seen.len() == siz);
    }
}

#[test]
fn fuzz_topo_sort7() {
    fuzz_topo_sort(7)
}
