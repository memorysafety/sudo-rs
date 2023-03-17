//! sudo-rs test framework

#![deny(missing_docs)]
#![deny(unsafe_code)]

use std::{
    collections::{HashMap, HashSet},
    env,
    path::Path,
    sync::Once,
};

use docker::Container;

pub use docker::{Command, Output};

type Error = Box<dyn std::error::Error>;
type Result<T> = core::result::Result<T, Error>;

mod docker;

const BASE_IMAGE: &str = env!("CARGO_CRATE_NAME");

/// are we testing the original sudo?
pub fn is_original_sudo() -> bool {
    matches!(SudoUnderTest::from_env(), Ok(SudoUnderTest::Theirs))
}

enum SudoUnderTest {
    Ours,
    Theirs,
}

impl SudoUnderTest {
    fn from_env() -> Result<Self> {
        if let Ok(under_test) = env::var("SUDO_UNDER_TEST") {
            if under_test == "ours" {
                Ok(Self::Ours)
            } else if under_test == "theirs" {
                Ok(Self::Theirs)
            } else {
                Err("variable SUDO_UNDER_TEST must be set to one of: ours, theirs".into())
            }
        } else {
            Ok(Self::Theirs)
        }
    }
}

type AbsolutePath = String;
type Groupname = String;
type Username = String;

/// test environment        
pub struct Env {
    container: Container,
    users: HashSet<Username>,
}

/// creates a new test environment builder that contains the specified `/etc/sudoers` file
#[allow(non_snake_case)]
pub fn Env(sudoers: impl Into<TextFile>) -> EnvBuilder {
    let mut builder = EnvBuilder::default();
    let mut sudoers = sudoers.into();
    // HACK append newline to work around memorysafety/sudo-rs#102
    sudoers.contents.push('\n');
    builder.file("/etc/sudoers", sudoers);
    builder
}

impl Command {
    /// executes the command in the specified test environment
    pub fn exec(&self, env: &Env) -> Result<Output> {
        if let Some(username) = self.get_user() {
            assert!(
                env.users.contains(username),
                "tried to exec as non-existent user: {username}"
            );
        }

        env.container.exec(self)
    }
}

/// test environment builder
#[derive(Default)]
pub struct EnvBuilder {
    files: HashMap<AbsolutePath, TextFile>,
    groups: HashMap<Groupname, Group>,
    users: HashMap<Username, User>,
}

impl EnvBuilder {
    /// adds a `file` to the test environment at the specified `path`
    ///
    /// # Panics
    ///
    /// - if `path` is not an absolute path
    /// - if `path` has previously been declared
    pub fn file(&mut self, path: impl AsRef<str>, file: impl Into<TextFile>) -> &mut Self {
        let path = path.as_ref();
        assert!(Path::new(path).is_absolute(), "path must be absolute");
        assert!(
            !self.files.contains_key(path),
            "file at {path} has already been declared"
        );

        self.files.insert(path.to_string(), file.into());

        self
    }

    /// adds the specified `group` to the test environment
    ///
    /// # Panics
    ///
    /// - if the `group` has previously been declared
    pub fn group(&mut self, group: impl Into<Group>) -> &mut Self {
        let group = group.into();
        let groupname = &group.name;
        assert!(
            !self.groups.contains_key(groupname),
            "group {} has already been declared",
            groupname
        );
        self.groups.insert(groupname.to_string(), group);

        self
    }

    /// adds the specified `user` to the test environment
    ///
    /// # Panics
    ///
    /// - if the `user` has previously been declared
    pub fn user(&mut self, user: impl Into<User>) -> &mut Self {
        let user = user.into();
        let username = &user.name;
        assert!(
            !self.users.contains_key(username),
            "user {} has already been declared",
            username
        );
        self.users.insert(username.to_string(), user);

        self
    }

    /// builds the test environment
    ///
    /// # Panics
    ///
    /// - if any specified `user` already exists in the base image
    /// - if any specified `group` already exists in the base image
    /// - if any specified `user` tries to use a user ID that already exists in the base image
    /// - if any specified `group` tries to use a group ID that already exists in the base image
    pub fn build(&self) -> Result<Env> {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            docker::build_base_image().expect("fatal error: could not build the base Docker image")
        });

        let container = Container::new(BASE_IMAGE)?;

        let (mut usernames, user_ids) = getent_passwd(&container)?;

        for new_user in self.users.values() {
            assert!(
                !usernames.contains(&new_user.name),
                "user {} already exists in base image",
                new_user.name
            );

            if let Some(user_id) = new_user.id {
                assert!(
                    !user_ids.contains(&user_id),
                    "user ID {user_id} already exists in base image"
                );
            }
        }

        let (groupnames, group_ids) = getent_group(&container)?;

        for new_group in self.groups.values() {
            assert!(
                !groupnames.contains(&new_group.name),
                "group {} already exists in base image",
                new_group.name
            );

            if let Some(group_id) = new_group.id {
                assert!(
                    !group_ids.contains(&group_id),
                    "group ID {group_id} already exists in base image"
                );
            }
        }

        // create groups with known IDs first to avoid collisions ..
        for group in self.groups.values().filter(|group| group.id.is_some()) {
            group.create(&container)?;
        }

        // .. with groups that get assigned IDs dynamically
        for group in self.groups.values().filter(|group| group.id.is_none()) {
            group.create(&container)?;
        }

        // create users with known IDs first to avoid collisions ..
        for user in self.users.values().filter(|user| user.id.is_some()) {
            user.create(&container)?;
            usernames.insert(user.name.to_string());
        }

        // .. with users that get assigned IDs dynamically
        for user in self.users.values().filter(|user| user.id.is_none()) {
            user.create(&container)?;
            usernames.insert(user.name.to_string());
        }

        for (path, file) in &self.files {
            file.create(path, &container)?;
        }

        Ok(Env {
            container,
            users: usernames,
        })
    }
}

/// a user
pub struct User {
    name: Username,

    groups: HashSet<Groupname>,
    id: Option<u32>,
    password: Option<String>,
}

/// creates a new user with the specified `name`
#[allow(non_snake_case)]
pub fn User(name: impl AsRef<str>) -> User {
    name.as_ref().into()
}

impl User {
    /// assigns this user to the specified `group`
    pub fn group(mut self, group: impl AsRef<str>) -> Self {
        let groupname = group.as_ref();
        assert!(
            !self.groups.contains(groupname),
            "user {} has already been assigned to {groupname}",
            self.name
        );

        self.groups.insert(groupname.to_string());

        self
    }

    /// assigns this user to all the specified `groups`
    pub fn groups(mut self, groups: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        for group in groups {
            self = self.group(group);
        }
        self
    }

    /// assigns the specified user `id` to this user
    ///
    /// if not specified, the user will get an automatically allocated ID
    pub fn id(mut self, id: u32) -> Self {
        self.id = Some(id);
        self
    }

    /// assigns the specified `password` to this user
    ///
    /// if not specified, the user will have no password
    pub fn password(mut self, password: impl AsRef<str>) -> Self {
        self.password = Some(password.as_ref().to_string());
        self
    }

    fn create(&self, container: &Container) -> Result<()> {
        let mut useradd = Command::new("useradd");
        useradd.arg("--no-user-group");
        if let Some(id) = self.id {
            useradd.arg("--uid").arg(id.to_string());
        }
        if !self.groups.is_empty() {
            let group_list = self.groups.iter().cloned().collect::<Vec<_>>().join(",");
            useradd.arg("--groups").arg(group_list);
        }
        useradd.arg(&self.name);
        container.exec(&useradd)?.assert_success()?;

        if let Some(password) = &self.password {
            container
                .exec(Command::new("chpasswd").stdin(format!("{}:{password}", self.name)))?
                .assert_success()?;
        }

        Ok(())
    }
}

impl From<String> for User {
    fn from(name: String) -> Self {
        assert!(!name.is_empty(), "user name cannot be an empty string");

        Self {
            name,
            groups: HashSet::new(),
            id: None,
            password: None,
        }
    }
}

impl From<&'_ str> for User {
    fn from(name: &'_ str) -> Self {
        name.to_string().into()
    }
}

/// a group
pub struct Group {
    name: Groupname,

    id: Option<u32>,
}

/// creates a group with the specified `name`
#[allow(non_snake_case)]
pub fn Group(name: impl AsRef<str>) -> Group {
    name.as_ref().into()
}

impl Group {
    /// assigns the specified group `id` to this group
    ///
    /// if not specified, the group will get an automatically allocated ID
    pub fn id(mut self, id: u32) -> Self {
        self.id = Some(id);
        self
    }

    fn create(&self, container: &Container) -> Result<()> {
        let mut groupadd = Command::new("groupadd");
        if let Some(id) = self.id {
            groupadd.arg("--gid");
            groupadd.arg(id.to_string());
        }
        groupadd.arg(&self.name);
        container.exec(&groupadd)?.assert_success()
    }
}

impl From<String> for Group {
    fn from(name: String) -> Self {
        assert!(!name.is_empty(), "group name cannot be an empty string");

        Self { name, id: None }
    }
}

impl From<&'_ str> for Group {
    fn from(name: &'_ str) -> Self {
        name.to_string().into()
    }
}

/// a text file
pub struct TextFile {
    contents: String,

    chmod: String,
    chown: String,
}

/// creates a text file with the specified `contents`
#[allow(non_snake_case)]
pub fn TextFile(contents: impl AsRef<str>) -> TextFile {
    contents.as_ref().into()
}

impl TextFile {
    const DEFAULT_CHMOD: &str = "000";
    const DEFAULT_CHOWN: &str = "root:root";

    /// chmod string to apply to the file
    ///
    /// if not specified, the default is "000"
    pub fn chmod(mut self, chmod: impl AsRef<str>) -> Self {
        self.chmod = chmod.as_ref().to_string();
        self
    }

    /// chown string to apply to the file
    ///
    /// if not specified, the default is "root:root"
    pub fn chown(mut self, chown: impl AsRef<str>) -> Self {
        self.chown = chown.as_ref().to_string();
        self
    }

    fn create(&self, path: &str, container: &Container) -> Result<()> {
        container.cp(path, &self.contents)?;

        container
            .exec(Command::new("chown").args([&self.chown, path]))?
            .assert_success()?;
        container
            .exec(Command::new("chmod").args([&self.chmod, path]))?
            .assert_success()
    }
}

impl From<String> for TextFile {
    fn from(contents: String) -> Self {
        Self {
            contents,
            chmod: Self::DEFAULT_CHMOD.to_string(),
            chown: Self::DEFAULT_CHOWN.to_string(),
        }
    }
}

impl From<&'_ str> for TextFile {
    fn from(contents: &'_ str) -> Self {
        contents.to_string().into()
    }
}

fn getent_group(container: &Container) -> Result<(HashSet<Groupname>, HashSet<u32>)> {
    let stdout = container
        .exec(Command::new("getent").arg("group"))?
        .stdout()?;
    let mut groupnames = HashSet::new();
    let mut group_ids = HashSet::new();
    for line in stdout.lines() {
        let mut parts = line.split(':');
        match (parts.next(), parts.next(), parts.next()) {
            (Some(name), Some(_), Some(id)) => {
                groupnames.insert(name.to_string());
                group_ids.insert(id.parse()?);
            }
            _ => {
                return Err(format!("invalid `getent group` syntax: {line}").into());
            }
        }
    }

    Ok((groupnames, group_ids))
}

fn getent_passwd(container: &Container) -> Result<(HashSet<Username>, HashSet<u32>)> {
    let stdout = container
        .exec(Command::new("getent").arg("passwd"))?
        .stdout()?;
    let mut usernames = HashSet::new();
    let mut user_ids = HashSet::new();
    for line in stdout.lines() {
        let mut parts = line.split(':');
        match (parts.next(), parts.next(), parts.next()) {
            (Some(name), Some(_), Some(id)) => {
                usernames.insert(name.to_string());
                user_ids.insert(id.parse()?);
            }
            _ => {
                return Err(format!("invalid `getent passwd` syntax: {line}").into());
            }
        }
    }

    Ok((usernames, user_ids))
}

#[cfg(test)]
mod tests {
    use super::*;

    const USERNAME: &str = "ferris";
    const GROUPNAME: &str = "rustaceans";

    #[test]
    fn group_creation_works() -> Result<()> {
        let env = EnvBuilder::default().group(GROUPNAME).build()?;

        let groupnames = getent_group(&env.container)?.0;
        assert!(groupnames.contains(GROUPNAME));

        Ok(())
    }

    #[test]
    fn user_creation_works() -> Result<()> {
        let env = EnvBuilder::default().user(USERNAME).build()?;

        let usernames = getent_passwd(&env.container)?.0;
        assert!(usernames.contains(USERNAME));

        Ok(())
    }

    #[test]
    fn no_implicit_home_creation() -> Result<()> {
        let env = EnvBuilder::default().user(USERNAME).build()?;

        let output = Command::new("sh")
            .arg("-c")
            .arg(format!("[ -d /home/{USERNAME} ]"))
            .exec(&env)?;
        assert!(!output.status().success());
        Ok(())
    }

    #[test]
    fn no_implicit_user_group_creation() -> Result<()> {
        let env = EnvBuilder::default().user(USERNAME).build()?;

        let stdout = Command::new("groups")
            .as_user(USERNAME)
            .exec(&env)?
            .stdout()?;
        let groups = stdout.split(' ').collect::<HashSet<_>>();
        assert!(!groups.contains(USERNAME));

        Ok(())
    }

    #[test]
    fn no_password_by_default() -> Result<()> {
        let env = EnvBuilder::default().user(USERNAME).build()?;

        let stdout = Command::new("passwd")
            .args(["--status", USERNAME])
            .exec(&env)?
            .stdout()?;

        assert!(stdout.starts_with(&format!("{USERNAME} L")));

        Ok(())
    }

    #[test]
    fn password_assignment_works() -> Result<()> {
        let password = "strong-password";
        let env = Env("ALL ALL=(ALL:ALL) ALL")
            .user(User(USERNAME).password(password))
            .build()?;

        Command::new("sudo")
            .args(["-S", "true"])
            .as_user(USERNAME)
            .stdin(password)
            .exec(&env)?
            .assert_success()
    }

    #[test]
    fn creating_user_part_of_existing_group_works() -> Result<()> {
        let groupname = "users";
        let env = EnvBuilder::default()
            .user(User(USERNAME).group(groupname))
            .build()?;

        let stdout = Command::new("groups")
            .as_user(USERNAME)
            .exec(&env)?
            .stdout()?;
        let user_groups = stdout.split(' ').collect::<HashSet<_>>();
        assert!(user_groups.contains(groupname));

        Ok(())
    }

    #[test]
    fn sudoers_file_get_created_with_expected_contents() -> Result<()> {
        let expected = "Hello, root!";
        let env = Env(expected).build()?;

        let actual = Command::new("cat")
            .arg("/etc/sudoers")
            .exec(&env)?
            .stdout()?;
        assert_eq!(expected, actual);

        Ok(())
    }

    #[test]
    fn text_file_gets_created_with_right_perms() -> Result<()> {
        let chown = format!("{USERNAME}:{GROUPNAME}");
        let chmod = "600";
        let expected_contents = "hello";
        let path = "/root/file";
        let env = EnvBuilder::default()
            .user(USERNAME)
            .group(GROUPNAME)
            .file(path, TextFile(expected_contents).chown(chown).chmod(chmod))
            .build()?;

        let actual_contents = Command::new("cat").arg(path).exec(&env)?.stdout()?;
        assert_eq!(expected_contents, &actual_contents);

        let ls_l = Command::new("ls").args(["-l", path]).exec(&env)?.stdout()?;
        assert!(ls_l.starts_with("-rw-------"));
        assert!(ls_l.contains(&format!("{USERNAME} {GROUPNAME}")));

        Ok(())
    }

    #[test]
    #[should_panic = "user root already exists in base image"]
    fn cannot_create_user_that_already_exists_in_base_image() {
        EnvBuilder::default().user("root").build().unwrap();
    }

    #[test]
    #[should_panic = "user ID 0 already exists in base image"]
    fn cannot_assign_user_id_that_already_exists_in_base_image() {
        EnvBuilder::default()
            .user(User(USERNAME).id(0))
            .build()
            .unwrap();
    }

    #[test]
    #[should_panic = "group root already exists in base image"]
    fn cannot_create_group_that_already_exists_in_base_image() {
        EnvBuilder::default().group("root").build().unwrap();
    }

    #[test]
    #[should_panic = "group ID 0 already exists in base image"]
    fn cannot_assign_group_id_that_already_exists_in_base_image() {
        EnvBuilder::default()
            .group(Group(GROUPNAME).id(0))
            .build()
            .unwrap();
    }

    #[test]
    fn setting_user_id_works() -> Result<()> {
        let expected = 1023;
        let env = EnvBuilder::default()
            .user(User(USERNAME).id(expected))
            .build()?;

        let actual = Command::new("id")
            .args(["-u", USERNAME])
            .exec(&env)?
            .stdout()?
            .parse()?;
        assert_eq!(expected, actual);

        Ok(())
    }

    #[test]
    fn setting_group_id_works() -> Result<()> {
        let expected = 1023;
        let env = EnvBuilder::default()
            .group(Group(GROUPNAME).id(expected))
            .build()?;

        let stdout = Command::new("getent")
            .args(["group", GROUPNAME])
            .exec(&env)?
            .stdout()?;
        let actual = stdout.split(':').nth(2);
        assert_eq!(Some(expected.to_string().as_str()), actual);

        Ok(())
    }
}
