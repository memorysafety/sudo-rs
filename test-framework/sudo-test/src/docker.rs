use core::str;
use std::{
    fs::{self, File},
    io::{Seek, SeekFrom, Write},
    path::PathBuf,
    process::{Command as StdCommand, Stdio},
};

use tempfile::NamedTempFile;

use crate::{Result, SudoUnderTest, BASE_IMAGE};

pub use self::command::{Command, Output};

mod command;

const DOCKER_RUN_COMMAND: &[&str] = &["sleep", "infinity"];

pub struct Container {
    id: String,
}

impl Container {
    pub fn new(image: &str) -> Result<Self> {
        let mut docker_run = StdCommand::new("docker");
        docker_run
            .args(["run", "-d", "--rm", image])
            .args(DOCKER_RUN_COMMAND);
        let id = run(&mut docker_run, None)?.stdout()?;
        validate_docker_id(&id, &docker_run)?;

        Ok(Container { id })
    }

    pub fn exec(&self, cmd: &Command) -> Result<Output> {
        let mut docker_exec = StdCommand::new("docker");
        docker_exec.arg("exec");
        if cmd.get_stdin().is_some() {
            docker_exec.arg("-i");
        }
        if let Some(user) = cmd.get_user() {
            docker_exec.arg("--user");
            docker_exec.arg(user);
        }
        docker_exec.arg(&self.id);
        docker_exec.args(cmd.get_args());

        run(&mut docker_exec, cmd.get_stdin())
    }

    pub fn cp(&self, path_in_container: &str, file_contents: &str) -> Result<()> {
        let mut temp_file = NamedTempFile::new()?;
        fs::write(&mut temp_file, file_contents)?;

        let src_path = temp_file.path().display().to_string();
        let dest_path = format!("{}:{path_in_container}", self.id);

        run(
            StdCommand::new("docker").args(["cp", &src_path, &dest_path]),
            None,
        )?
        .assert_success()?;

        Ok(())
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        // running this to completion would block the current thread for several seconds so just
        // fire and forget
        let _ = StdCommand::new("docker")
            .args(["stop", &self.id])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    }
}

pub fn build_base_image() -> Result<()> {
    let repo_root = repo_root();
    let mut cmd = StdCommand::new("docker");

    cmd.args(["build", "-t", BASE_IMAGE]);

    match SudoUnderTest::from_env()? {
        SudoUnderTest::Ours => {
            // needed for dockerfile-specific dockerignore (e.g. `Dockerfile.dockerignore`) support
            cmd.env("DOCKER_BUILDKIT", "1");

            cmd.current_dir(repo_root);
            cmd.args(["-f", "test-framework/sudo-test/src/ours.Dockerfile", "."]);
        }

        SudoUnderTest::Theirs => {
            // pass Dockerfile via stdin to not provide the repository as a build context
            let f = File::open(repo_root.join("test-framework/sudo-test/src/theirs.Dockerfile"))?;
            cmd.arg("-").stdin(Stdio::from(f));
        }
    }

    run(&mut cmd, None)?.assert_success()?;

    Ok(())
}

fn repo_root() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path
}

fn run(cmd: &mut StdCommand, stdin: Option<&str>) -> Result<Output> {
    let mut temp_file;
    if let Some(stdin) = stdin {
        temp_file = tempfile::tempfile()?;
        temp_file.write_all(stdin.as_bytes())?;
        temp_file.seek(SeekFrom::Start(0))?;
        cmd.stdin(Stdio::from(temp_file));
    }

    let output = cmd.output()?;

    let mut stderr = String::from_utf8(output.stderr)?;
    let mut stdout = String::from_utf8(output.stdout)?;

    // it's a common pitfall to forget to remove the trailing '\n' so remove it here
    if stderr.ends_with('\n') {
        stderr.pop();
    }

    if stdout.ends_with('\n') {
        stdout.pop();
    }

    Ok(Output {
        status: output.status,
        stderr,
        stdout,
    })
}

fn validate_docker_id(id: &str, cmd: &StdCommand) -> Result<()> {
    if id.chars().any(|c| !c.is_ascii_hexdigit()) {
        return Err(
            format!("`{cmd:?}` return what appears to be an invalid docker id: {id}").into(),
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{thread, time::Duration};

    use super::*;

    const IMAGE: &str = "ubuntu:22.04";

    #[test]
    #[ignore = "slow"]
    fn eventually_removes_container_on_drop() -> Result<()> {
        let mut check_cmd = StdCommand::new("docker");
        let docker = Container::new(IMAGE)?;
        check_cmd.args(["ps", "--all", "--quiet", "--filter"]);
        check_cmd.arg(format!("id={}", docker.id));

        let matches = run(&mut check_cmd, None)?.stdout()?;
        assert_eq!(1, matches.lines().count());
        drop(docker);

        // wait for a bit until `stop` and `--rm` have done their work
        thread::sleep(Duration::from_secs(15));

        let matches = run(&mut check_cmd, None)?.stdout()?;
        assert_eq!(0, matches.lines().count());

        Ok(())
    }

    #[test]
    fn exec_as_root_works() -> Result<()> {
        let docker = Container::new(IMAGE)?;

        docker.exec(&Command::new("true"))?.assert_success()?;

        let output = docker.exec(&Command::new("false"))?;
        assert_eq!(Some(1), output.status.code());

        Ok(())
    }

    #[test]
    fn exec_as_user_named_root_works() -> Result<()> {
        let docker = Container::new(IMAGE)?;

        docker
            .exec(Command::new("true").as_user("root"))?
            .assert_success()
    }

    #[test]
    fn exec_as_non_root_user_works() -> Result<()> {
        let username = "ferris";

        let docker = Container::new(IMAGE)?;

        docker
            .exec(Command::new("useradd").arg(username))?
            .assert_success()?;

        docker
            .exec(Command::new("true").as_user(username))?
            .assert_success()
    }

    #[test]
    fn cp_works() -> Result<()> {
        let path = "/tmp/file";
        let expected = "Hello, world!";

        let docker = Container::new(IMAGE)?;

        docker.cp(path, expected)?;

        let actual = docker.exec(Command::new("cat").arg(path))?.stdout()?;
        assert_eq!(expected, actual);

        Ok(())
    }

    #[test]
    fn stdin_works() -> Result<()> {
        let expected = "Hello, root!";
        let filename = "greeting";

        let docker = Container::new(IMAGE)?;

        docker
            .exec(Command::new("tee").arg(filename).stdin(expected))?
            .assert_success()?;

        let actual = docker.exec(Command::new("cat").arg(filename))?.stdout()?;
        assert_eq!(expected, actual);

        Ok(())
    }
}
