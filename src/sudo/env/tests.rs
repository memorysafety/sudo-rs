use crate::common::{CommandAndArguments, Context, Environment};
use crate::sudo::{
    cli::{SudoAction, SudoRunOptions},
    env::environment::get_target_environment,
};
use crate::system::interface::{GroupId, UserId};
use crate::system::{Group, Process, User};
use std::collections::{HashMap, HashSet};

const TESTS: &str = "
> env
    FOO=BAR
    HOME=/home/test
    HOSTNAME=test-ubuntu
    LANG=en_US.UTF-8
    LANGUAGE=en_US.UTF-8
    LC_ALL=en_US.UTF-8
    LS_COLORS=cd=40;33;01:*.jpg=01;35:*.mp3=00;36:
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    PWD=/home/test
    SHLVL=0
    TERM=xterm
    _=/usr/bin/sudo
> sudo env
    HOSTNAME=test-ubuntu
    LANG=en_US.UTF-8
    LANGUAGE=en_US.UTF-8
    LC_ALL=en_US.UTF-8
    LS_COLORS=cd=40;33;01:*.jpg=01;35:*.mp3=00;36:
    MAIL=/var/mail/root
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    SHELL=/bin/bash
    SUDO_COMMAND=/usr/bin/env
    SUDO_GID=1000
    SUDO_UID=1000
    SUDO_USER=test
    HOME=/root
    LOGNAME=root
    USER=root
    TERM=xterm
> sudo -u test env
    HOSTNAME=test-ubuntu
    LANG=en_US.UTF-8
    LANGUAGE=en_US.UTF-8
    LC_ALL=en_US.UTF-8
    LS_COLORS=cd=40;33;01:*.jpg=01;35:*.mp3=00;36:
    MAIL=/var/mail/test
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    SHELL=/bin/sh
    SUDO_COMMAND=/usr/bin/env
    SUDO_GID=1000
    SUDO_UID=1000
    SUDO_USER=test
    HOME=/home/test
    LOGNAME=test
    USER=test
    TERM=xterm
";

fn parse_env_commands(input: &str) -> Vec<(&str, Environment)> {
    input
        .trim()
        .split("> ")
        .filter(|l| !l.is_empty())
        .map(|e| {
            let (cmd, vars) = e.split_once('\n').unwrap();

            let vars: Environment = vars
                .lines()
                .map(|line| line.trim().split_once('=').unwrap())
                .map(|(k, v)| (k.into(), v.into()))
                .collect();

            (cmd, vars)
        })
        .collect()
}

fn create_test_context(sudo_options: &SudoRunOptions) -> Context {
    let path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string();
    let command =
        CommandAndArguments::build_from_args(None, sudo_options.positional_args.clone(), &path);

    let current_user = User {
        uid: UserId(1000),
        gid: GroupId(1000),

        name: "test".into(),
        gecos: String::new(),
        home: "/home/test".into(),
        shell: "/bin/sh".into(),
        passwd: String::new(),
        groups: vec![],
    };

    let current_group = Group {
        gid: GroupId(1000),
        name: "test".to_string(),
        passwd: String::new(),
        members: Vec::new(),
    };

    let root_user = User {
        uid: UserId(0),
        gid: GroupId(0),
        name: "root".into(),
        gecos: String::new(),
        home: "/root".into(),
        shell: "/bin/bash".into(),
        passwd: String::new(),
        groups: vec![],
    };

    let root_group = Group {
        gid: GroupId(0),
        name: "root".to_string(),
        passwd: String::new(),
        members: Vec::new(),
    };

    Context {
        hostname: "test-ubuntu".to_string(),
        command,
        current_user: current_user.clone(),
        target_user: if sudo_options.user.as_deref() == Some("test") {
            current_user
        } else {
            root_user
        },
        target_group: if sudo_options.user.as_deref() == Some("test") {
            current_group
        } else {
            root_group
        },
        launch: crate::common::context::LaunchType::Direct,
        chdir: sudo_options.chdir.clone(),
        stdin: sudo_options.stdin,
        non_interactive: sudo_options.non_interactive,
        process: Process::new(),
        use_session_records: false,
        use_pty: true,
    }
}

fn environment_to_set(environment: Environment) -> HashSet<String> {
    HashSet::from_iter(
        environment
            .iter()
            .map(|(k, v)| format!("{}={}", k.to_str().unwrap(), v.to_str().unwrap())),
    )
}

#[test]
fn test_environment_variable_filtering() {
    let mut parts = parse_env_commands(TESTS);
    let initial_env = parts.remove(0).1;

    for (cmd, expected_env) in parts {
        let options = SudoAction::try_parse_from(cmd.split_whitespace())
            .unwrap()
            .try_into_run()
            .ok()
            .unwrap();
        let settings = crate::sudoers::Judgement::default();
        let context = create_test_context(&options);
        let resulting_env =
            get_target_environment(initial_env.clone(), HashMap::new(), &context, &settings);

        let resulting_env = environment_to_set(resulting_env);
        let expected_env = environment_to_set(expected_env);
        let mut diff = resulting_env
            .symmetric_difference(&expected_env)
            .collect::<Vec<_>>();

        diff.sort();

        assert!(
            diff.is_empty(),
            "\"{cmd}\" results in an environment mismatch:\n{diff:#?}",
        );
    }
}
