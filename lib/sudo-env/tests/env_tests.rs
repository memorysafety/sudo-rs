use std::collections::HashSet;
use sudo_cli::SudoOptions;
use sudo_common::context::{CommandAndArguments, Context, Environment};
use sudo_env::environment::get_target_environment;
use sudo_system::{Group, User};
use sudoers::Settings;

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
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();

            (cmd, vars)
        })
        .collect()
}

fn create_test_context<'a>(sudo_options: &'a SudoOptions) -> Context<'a> {
    let command = CommandAndArguments::try_from(sudo_options.external_args.as_slice()).unwrap();

    let current_user = User {
        uid: 1000,
        gid: 1000,
        name: "test".to_string(),
        gecos: String::new(),
        home: "/home/test".to_string(),
        shell: "/bin/sh".to_string(),
        passwd: String::new(),
        groups: None,
    };

    let current_group = Group {
        gid: 1000,
        name: "test".to_string(),
        passwd: String::new(),
        members: Vec::new(),
    };

    let root_user = User {
        uid: 0,
        gid: 0,
        name: "root".to_string(),
        gecos: String::new(),
        home: "/root".to_string(),
        shell: "/bin/bash".to_string(),
        passwd: String::new(),
        groups: None,
    };

    let root_group = Group {
        gid: 0,
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
        set_home: sudo_options.set_home,
        preserve_env_list: sudo_options.preserve_env_list.clone(),
        login: sudo_options.login,
        shell: sudo_options.shell,
        chdir: sudo_options.directory.clone(),
        pid: std::process::id() as i32,
    }
}

fn environment_to_set(environment: Environment) -> HashSet<String> {
    HashSet::from_iter(environment.iter().map(|(k, v)| format!("{}={}", k, v)))
}

#[test]
fn test_environment_variable_filtering() {
    let mut parts = parse_env_commands(TESTS);
    let initial_env = parts.remove(0).1;

    for (cmd, expected_env) in parts {
        let options = SudoOptions::try_parse_from(cmd.split_whitespace()).unwrap();
        let settings = Settings::default();
        let context = create_test_context(&options);
        let resulting_env = get_target_environment(initial_env.clone(), &context, &settings);

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
