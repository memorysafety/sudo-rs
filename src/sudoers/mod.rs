#![forbid(unsafe_code)]

//! Code that checks (and in the future: lists) permissions in the sudoers file

mod ast;
mod ast_names;
mod basic_parser;
mod char_stream;
mod entry;
mod tokens;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::{io, mem};

use crate::common::resolve::resolve_path;
use crate::log::auth_warn;
use crate::system::can_execute;
use crate::system::interface::{GroupId, UnixGroup, UnixUser, UserId};
use ast::*;
use tokens::*;

/// How many nested include files do we allow?
const INCLUDE_LIMIT: u8 = 128;

/// Export some necessary symbols from modules
pub use ast::TextEnum;
pub struct Error(pub Option<basic_parser::Position>, pub String);

#[derive(Default)]
pub struct Sudoers {
    rules: Vec<PermissionSpec>,
    aliases: AliasTable,
    settings: Settings,
}

/// A structure that represents what the user wants to do
pub struct Request<'a, User: UnixUser, Group: UnixGroup> {
    pub user: &'a User,
    pub group: &'a Group,
    pub command: &'a Path,
    pub arguments: &'a [String],
}

pub struct ListRequest<'a, User: UnixUser, Group: UnixGroup> {
    pub target_user: &'a User,
    pub target_group: &'a Group,
}

#[derive(Default)]
pub struct Judgement {
    flags: Option<Tag>,
    settings: Settings,
}

mod policy;

pub use policy::{Authorization, AuthorizationAllowed, DirChange, Policy, PreJudgementPolicy};

pub use self::entry::Entry;

/// This function takes a file argument for a sudoers file and processes it.
impl Sudoers {
    pub fn open(path: impl AsRef<Path>) -> Result<(Sudoers, Vec<Error>), io::Error> {
        let sudoers = open_sudoers(path.as_ref())?;
        Ok(analyze(path.as_ref(), sudoers))
    }

    pub fn read<R: io::Read, P: AsRef<Path>>(
        reader: R,
        path: P,
    ) -> Result<(Sudoers, Vec<Error>), io::Error> {
        let sudoers = read_sudoers(reader)?;
        Ok(analyze(path.as_ref(), sudoers))
    }

    pub fn check<User: UnixUser + PartialEq<User>, Group: UnixGroup>(
        &self,
        am_user: &User,
        on_host: &str,
        request: Request<User, Group>,
    ) -> Judgement {
        // exception: if user is root or does not switch users, NOPASSWD is implied
        let skip_passwd =
            am_user.is_root() || (request.user == am_user && in_group(am_user, request.group));

        let mut flags = check_permission(self, am_user, on_host, request);
        if let Some(Tag { authenticate, .. }) = flags.as_mut() {
            if skip_passwd {
                *authenticate = Authenticate::Nopasswd;
            }
        }

        Judgement {
            flags,
            settings: self.settings.clone(), // this is wasteful, but in the future this will not be a simple clone and it avoids a lifetime
        }
    }

    pub fn check_list_permission<User: UnixUser + PartialEq<User>, Group: UnixGroup>(
        &self,
        invoking_user: &User,
        hostname: &str,
        request: ListRequest<User, Group>,
    ) -> Judgement {
        // exception: if user is root or does not switch users, NOPASSWD is implied
        let skip_passwd = invoking_user.is_root()
            || (request.target_user == invoking_user
                && in_group(invoking_user, request.target_group));

        let mut flags = self
            .matching_user_specs(invoking_user, hostname)
            .flatten()
            .fold(None::<Tag>, |outcome, (_, (tag, _))| {
                if let Some(outcome) = outcome {
                    let new_outcome = if outcome.needs_passwd() { tag } else { outcome };

                    Some(new_outcome)
                } else {
                    Some(tag)
                }
            });

        if let Some(Tag { authenticate, .. }) = flags.as_mut() {
            if skip_passwd {
                *authenticate = Authenticate::Nopasswd;
            }
        }

        Judgement {
            flags,
            settings: self.settings.clone(), // this is wasteful, but in the future this will not be a simple clone and it avoids a lifetime
        }
    }

    /// returns `User_Spec`s that match `invoking_user` and `hostname`
    ///
    /// it also distributes `Tag_Spec`s across the `Cmnd_Spec` list of each `User_Spec`
    ///
    /// the outer iterator are the `User_Spec`s; the inner iterator are the `Cmnd_Spec`s of
    /// said `User_Spec`s
    fn matching_user_specs<'a: 'b + 'c, 'b: 'c, 'c, User: UnixUser + PartialEq<User>>(
        &'a self,
        invoking_user: &'b User,
        hostname: &'c str,
    ) -> impl Iterator<Item = impl Iterator<Item = (Option<&'a RunAs>, (Tag, &'a Spec<Command>))> + 'b>
           + 'c {
        let Self { rules, aliases, .. } = self;
        let user_aliases = get_aliases(&aliases.user, &match_user(invoking_user));
        let host_aliases = get_aliases(&aliases.host, &match_token(hostname));

        rules
            .iter()
            .filter_map(move |sudo| {
                find_item(&sudo.users, &match_user(invoking_user), &user_aliases)?;
                Some(&sudo.permissions)
            })
            .flatten()
            .filter_map(move |(hosts, runas_cmds)| {
                find_item(hosts, &match_token(hostname), &host_aliases)?;
                Some(distribute_tags(runas_cmds))
            })
    }

    /// returns `User_Spec`s that match `invoking_user` and `hostname` in a print-able format
    pub fn matching_entries<'a, User: UnixUser + PartialEq<User>>(
        &'a self,
        invoking_user: &User,
        hostname: &str,
    ) -> Vec<Entry<'a>> {
        // NOTE this method MUST NOT perform any filtering that `Self::check` does not do to
        // ensure `sudo $command` and `sudo --list` use the same permission checking logic
        let user_specs = self.matching_user_specs(invoking_user, hostname);

        let cmnd_aliases = unfold_alias_table(&self.aliases.cmnd);
        let mut entries = vec![];
        for cmd_specs in user_specs {
            group_cmd_specs_per_runas(cmd_specs, &mut entries, &cmnd_aliases);
        }

        entries
    }

    pub(crate) fn solve_editor_path(&self) -> Option<PathBuf> {
        if self.settings.flags.contains("env_editor") {
            for key in ["SUDO_EDITOR", "VISUAL", "EDITOR"] {
                if let Some(var) = std::env::var_os(key) {
                    let path = Path::new(&var);
                    if can_execute(path) {
                        return Some(path.to_owned());
                    }
                    let path = resolve_path(
                        path,
                        &std::env::var("PATH").unwrap_or(env!("DEFAULT_PATH").to_string()),
                    );
                    if let Some(path) = path {
                        return Some(path);
                    }
                }
            }
        }

        None
    }
}

fn group_cmd_specs_per_runas<'a>(
    cmnd_specs: impl Iterator<Item = (Option<&'a RunAs>, (Tag, &'a Spec<Command>))>,
    entries: &mut Vec<Entry<'a>>,
    cmnd_aliases: &HashMap<&String, &'a Vec<Spec<Command>>>,
) {
    static EMPTY_RUNAS: RunAs = RunAs {
        users: Vec::new(),
        groups: Vec::new(),
    };

    let mut runas = None;
    let mut collected_specs = vec![];

    for (new_runas, (tag, spec)) in cmnd_specs {
        if let Some(new_runas) = new_runas {
            if !collected_specs.is_empty() {
                entries.push(Entry::new(
                    runas.take().unwrap_or(&EMPTY_RUNAS),
                    mem::take(&mut collected_specs),
                ));
            }

            runas = Some(new_runas);
        }

        let (negate, meta) = match spec {
            Qualified::Allow(meta) => (false, meta),
            Qualified::Forbid(meta) => (true, meta),
        };

        if let Meta::Alias(alias_name) = meta {
            if let Some(specs) = cmnd_aliases.get(alias_name) {
                // expand Cmnd_Alias
                for spec in specs.iter() {
                    let new_spec = if negate { spec.negate() } else { spec.as_ref() };

                    collected_specs.push((tag.clone(), new_spec))
                }
            }
        } else {
            collected_specs.push((tag, spec.as_ref()));
        }
    }

    if !collected_specs.is_empty() {
        entries.push(Entry::new(runas.unwrap_or(&EMPTY_RUNAS), collected_specs));
    }
}

fn read_sudoers<R: io::Read>(mut reader: R) -> io::Result<Vec<basic_parser::Parsed<Sudo>>> {
    // it's a bit frustrating that BufReader.chars() does not exist
    let mut buffer = String::new();
    reader.read_to_string(&mut buffer)?;

    use basic_parser::parse_lines;
    use char_stream::*;
    Ok(parse_lines(&mut PeekableWithPos::new(buffer.chars())))
}

fn open_sudoers(path: &Path) -> io::Result<Vec<basic_parser::Parsed<Sudo>>> {
    let source = crate::system::secure_open(path, false)?;
    read_sudoers(source)
}

fn open_subsudoers(path: &Path) -> io::Result<Vec<basic_parser::Parsed<Sudo>>> {
    let source = crate::system::secure_open(path, true)?;
    read_sudoers(source)
}

#[derive(Default)]
pub(super) struct AliasTable {
    user: VecOrd<Def<UserSpecifier>>,
    host: VecOrd<Def<Hostname>>,
    cmnd: VecOrd<Def<Command>>,
    runas: VecOrd<Def<UserSpecifier>>,
}

/// A vector with a list defining the order in which it needs to be processed

type VecOrd<T> = (Vec<usize>, Vec<T>);

fn elems<T>(vec: &VecOrd<T>) -> impl Iterator<Item = &T> {
    vec.0.iter().map(|&i| &vec.1[i])
}

/// Check if the user `am_user` is allowed to run `cmdline` on machine `on_host` as the requested
/// user/group. Not that in the sudoers file, later permissions override earlier restrictions.
/// The `cmdline` argument should already be ready to essentially feed to an exec() call; or be
/// a special command like 'sudoedit'.

// This code is structure to allow easily reading the 'happy path'; i.e. as soon as something
// doesn't match, we escape using the '?' mechanism.
fn check_permission<User: UnixUser + PartialEq<User>, Group: UnixGroup>(
    sudoers: &Sudoers,
    am_user: &User,
    on_host: &str,
    request: Request<User, Group>,
) -> Option<Tag> {
    let cmdline = (request.command, request.arguments);

    let aliases = &sudoers.aliases;
    let cmnd_aliases = get_aliases(&aliases.cmnd, &match_command(cmdline));
    let runas_user_aliases = get_aliases(&aliases.runas, &match_user(request.user));
    let runas_group_aliases = get_aliases(&aliases.runas, &match_group_alias(request.group));

    // NOTE to ensure `sudo $command` and `sudo --list` behave the same, both this function and
    // `Sudoers::matching_entries` must call this `matching_user_specs` method
    let matching_user_specs = sudoers.matching_user_specs(am_user, on_host).flatten();

    let allowed_commands = matching_user_specs.filter_map(|(runas, cmdspec)| {
        if let Some(RunAs { users, groups }) = runas {
            let stays_in_group = in_group(request.user, request.group);
            if request.user != am_user || (stays_in_group && !users.is_empty()) {
                find_item(users, &match_user(request.user), &runas_user_aliases)?
            }
            if !stays_in_group {
                find_item(groups, &match_group(request.group), &runas_group_aliases)?
            }
        } else if !(request.user.is_root() && in_group(request.user, request.group)) {
            None?;
        }

        Some(cmdspec)
    });

    find_item(allowed_commands, &match_command(cmdline), &cmnd_aliases)
}

/// Process a raw parsed AST bit of RunAs + Command specifications:
/// - RunAs specifications distribute over the commands that follow (until overridden)
/// - Tags accumulate over the entire line

fn distribute_tags(
    runas_cmds: &[(Option<RunAs>, CommandSpec)],
) -> impl Iterator<Item = (Option<&RunAs>, (Tag, &Spec<Command>))> {
    runas_cmds.iter().scan(
        (None, Default::default()),
        |(mut last_runas, tag), (runas, CommandSpec(mods, cmd))| {
            last_runas = runas.as_ref().or(last_runas);
            for f in mods {
                f(tag);
            }

            Some((last_runas, (tag.clone(), cmd)))
        },
    )
}

/// A type to represent positive or negative association with an alias; i.e. if a key maps to true,
/// the alias affirms membership, if a key maps to false, the alias denies membership; if a key
/// isn't present membership is affirmed nor denied
type FoundAliases = HashMap<String, bool>;

/// Find an item matching a certain predicate in an collection (optionally attributed) list of
/// identifiers; identifiers can be directly identifying, wildcards, and can either be positive or
/// negative (i.e. preceeded by an even number of exclamation marks in the sudoers file)

fn find_item<'a, Predicate, Iter, T: 'a>(
    items: Iter,
    matches: &Predicate,
    aliases: &FoundAliases,
) -> Option<<Iter::Item as WithInfo>::Info>
where
    Predicate: Fn(&T) -> bool,
    Iter: IntoIterator,
    Iter::Item: WithInfo<Item = &'a Spec<T>>,
{
    let mut result = None;
    for item in items {
        let (judgement, who) = match item.clone().to_inner() {
            Qualified::Forbid(x) => (false, x),
            Qualified::Allow(x) => (true, x),
        };
        let info = || item.to_info();
        match who {
            Meta::All => result = judgement.then(info),
            Meta::Only(ident) if matches(ident) => result = judgement.then(info),
            Meta::Alias(id) if aliases.contains_key(id) => {
                result = if aliases[id] {
                    judgement.then(info)
                } else {
                    // in this case, an explicit negation in the alias applies
                    (!judgement).then(info)
                }
            }
            _ => {}
        };
    }

    result
}

/// A interface to access optional "satellite data"
trait WithInfo: Clone {
    type Item;
    type Info;
    fn to_inner(self) -> Self::Item;
    fn to_info(self) -> Self::Info;
}

/// A specific interface for `Spec<T>` --- we can't make a generic one;
/// A `Spec<T>` does not contain any additional information.
impl<'a, T> WithInfo for &'a Spec<T> {
    type Item = &'a Spec<T>;
    type Info = ();
    fn to_inner(self) -> &'a Spec<T> {
        self
    }
    fn to_info(self) {}
}

/// A commandspec can be "tagged"
impl<'a> WithInfo for (Tag, &'a Spec<Command>) {
    type Item = &'a Spec<Command>;
    type Info = Tag;
    fn to_inner(self) -> &'a Spec<Command> {
        self.1
    }
    fn to_info(self) -> Tag {
        self.0
    }
}

/// Now follow a collection of functions used as closures for `find_item`
fn match_user(user: &impl UnixUser) -> impl Fn(&UserSpecifier) -> bool + '_ {
    move |spec| match spec {
        UserSpecifier::User(id) => match_identifier(user, id),
        UserSpecifier::Group(Identifier::Name(name)) => user.in_group_by_name(name.as_cstr()),
        UserSpecifier::Group(Identifier::ID(num)) => user.in_group_by_gid(GroupId(*num)),
        _ => todo!(), // nonunix-groups, netgroups, etc.
    }
}

fn in_group(user: &impl UnixUser, group: &impl UnixGroup) -> bool {
    user.in_group_by_gid(group.as_gid())
}

fn match_group(group: &impl UnixGroup) -> impl Fn(&Identifier) -> bool + '_ {
    move |id| match id {
        Identifier::ID(num) => group.as_gid() == GroupId(*num),
        Identifier::Name(name) => group.try_as_name().map_or(false, |s| name == s),
    }
}

fn match_group_alias(group: &impl UnixGroup) -> impl Fn(&UserSpecifier) -> bool + '_ {
    move |spec| match spec {
        UserSpecifier::User(ident) => match_group(group)(ident),
        /* the parser does not allow this, but can happen due to Runas_Alias,
         * see https://github.com/memorysafety/sudo-rs/issues/13 */
        _ => {
            auth_warn!("warning: ignoring %group syntax in runas_alias for checking sudo -g");
            false
        }
    }
}

fn match_token<T: basic_parser::Token + std::ops::Deref<Target = String>>(
    text: &str,
) -> (impl Fn(&T) -> bool + '_) {
    move |token| token.as_str() == text
}

fn match_command<'a>((cmd, args): (&'a Path, &'a [String])) -> (impl Fn(&Command) -> bool + 'a) {
    let opts = glob::MatchOptions {
        require_literal_separator: true,
        ..glob::MatchOptions::new()
    };
    move |(cmdpat, argpat)| {
        cmdpat.matches_path_with(cmd, opts)
            && argpat.as_ref().map_or(true, |vec| args == vec.as_ref())
    }
}

fn unfold_alias_table<T>(table: &VecOrd<Def<T>>) -> HashMap<&String, &Vec<Qualified<Meta<T>>>> {
    elems(table).map(|Def(id, list)| (id, list)).collect()
}

/// Find all the aliases that a object is a member of; this requires [sanitize_alias_table] to have run first;
/// I.e. this function should not be "pub".

fn get_aliases<Predicate, T>(table: &VecOrd<Def<T>>, pred: &Predicate) -> FoundAliases
where
    Predicate: Fn(&T) -> bool,
{
    use std::iter::once;
    let all = Qualified::Allow(Meta::All);

    let mut set = HashMap::new();
    for Def(id, list) in elems(table) {
        if find_item(list, &pred, &set).is_some() {
            set.insert(id.clone(), true);
        } else if find_item(once(&all).chain(list), &pred, &set).is_none() {
            // the item wasn't found even if we prepend ALL to the list of definitions; that means
            // it is explicitly excluded by the alias definition.
            set.insert(id.clone(), false);
        }
    }

    set
}

/// Code to map an ast::Identifier to the UnixUser trait

fn match_identifier(user: &impl UnixUser, ident: &ast::Identifier) -> bool {
    match ident {
        Identifier::Name(name) => user.has_name(name),
        Identifier::ID(num) => user.has_uid(UserId(*num)),
    }
}

#[derive(Clone)]
pub struct Settings {
    pub flags: HashSet<String>,
    pub str_value: HashMap<String, Option<Box<str>>>,
    pub enum_value: HashMap<String, TextEnum>,
    pub int_value: HashMap<String, i64>,
    pub list: HashMap<String, HashSet<String>>,
}

impl Default for Settings {
    fn default() -> Self {
        let mut this = Settings {
            flags: Default::default(),
            str_value: Default::default(),
            enum_value: Default::default(),
            int_value: Default::default(),
            list: Default::default(),
        };

        use crate::defaults::{sudo_default, OptTuple, SudoDefault};
        for key in crate::defaults::ALL_PARAMS.iter() {
            match sudo_default(key).expect("internal error") {
                SudoDefault::Flag(default) => {
                    if default {
                        this.flags.insert(key.to_string());
                    }
                }
                SudoDefault::Text(OptTuple { default, .. }) => {
                    this.str_value
                        .insert(key.to_string(), default.map(|x| x.into()));
                }
                SudoDefault::Enum(OptTuple { default, .. }) => {
                    this.enum_value.insert(key.to_string(), default);
                }
                SudoDefault::Integer(OptTuple { default, .. }, _) => {
                    this.int_value.insert(key.to_string(), default);
                }
                SudoDefault::List(default) => {
                    this.list.insert(
                        key.to_string(),
                        default.iter().map(|x| x.to_string()).collect(),
                    );
                }
            }
        }

        this
    }
}

/// Process a sudoers-parsing file into a workable AST
fn analyze(
    path: &Path,
    sudoers: impl IntoIterator<Item = basic_parser::Parsed<Sudo>>,
) -> (Sudoers, Vec<Error>) {
    use ConfigValue::*;
    use Directive::*;

    let mut result: Sudoers = Default::default();

    fn resolve_relative(base: &Path, path: impl AsRef<Path>) -> PathBuf {
        if path.as_ref().is_relative() {
            // there should always be a parent since we start with /etc/sudoers, and make every other path
            // absolute based on previous inputs; not having a parent is therefore a serious bug
            base.parent()
                .expect("invalid hardcoded path in sudo-rs")
                .join(path)
        } else {
            path.as_ref().into()
        }
    }

    impl Sudoers {
        fn include(&mut self, path: &Path, diagnostics: &mut Vec<Error>, count: &mut u8) {
            if *count >= INCLUDE_LIMIT {
                diagnostics.push(Error(
                    None,
                    format!("include file limit reached opening '{}'", path.display()),
                ))
            // FIXME: this will cause an error in `visudo` if we open a non-privileged sudoers file
            // that includes another non-privileged sudoer files.
            } else {
                match open_subsudoers(path) {
                    Ok(subsudoer) => {
                        *count += 1;
                        self.process(path, subsudoer, diagnostics, count)
                    }
                    Err(e) => {
                        let message = if e.kind() == io::ErrorKind::NotFound {
                            // improve the error message in this case
                            format!("cannot open sudoers file '{}'", path.display())
                        } else {
                            e.to_string()
                        };

                        diagnostics.push(Error(None, message))
                    }
                }
            }
        }

        fn process(
            &mut self,
            cur_path: &Path,
            sudoers: impl IntoIterator<Item = basic_parser::Parsed<Sudo>>,
            diagnostics: &mut Vec<Error>,
            safety_count: &mut u8,
        ) {
            for item in sudoers {
                match item {
                    Ok(line) => match line {
                        Sudo::LineComment => {}

                        Sudo::Spec(permission) => self.rules.push(permission),

                        Sudo::Decl(UserAlias(mut def)) => self.aliases.user.1.append(&mut def),
                        Sudo::Decl(HostAlias(mut def)) => self.aliases.host.1.append(&mut def),
                        Sudo::Decl(CmndAlias(mut def)) => self.aliases.cmnd.1.append(&mut def),
                        Sudo::Decl(RunasAlias(mut def)) => self.aliases.runas.1.append(&mut def),

                        Sudo::Decl(Defaults(params)) => {
                            for (name, value) in params {
                                self.set_default(name, value)
                            }
                        }

                        Sudo::Include(path) => self.include(
                            &resolve_relative(cur_path, path),
                            diagnostics,
                            safety_count,
                        ),

                        Sudo::IncludeDir(path) => {
                            if path.contains("%h") {
                                diagnostics.push(Error(
                                    None,
                                    format!("cannot open sudoers file {path}: percent escape %h in includedir is unsupported")));
                                continue;
                            }

                            let path = resolve_relative(cur_path, path);
                            let Ok(files) = std::fs::read_dir(&path) else {
                                diagnostics.push(Error(
                                    None,
                                    format!("cannot open sudoers file {}", path.display()),
                                ));
                                continue;
                            };
                            let mut safe_files = files
                                .filter_map(|direntry| {
                                    let path = direntry.ok()?.path();
                                    let text = path.file_name()?.to_str()?;
                                    if text.ends_with('~') || text.contains('.') {
                                        None
                                    } else {
                                        Some(path)
                                    }
                                })
                                .collect::<Vec<_>>();
                            safe_files.sort();
                            for file in safe_files {
                                self.include(file.as_ref(), diagnostics, safety_count)
                            }
                        }
                    },

                    Err(basic_parser::Status::Fatal(pos, error)) => {
                        diagnostics.push(Error(Some(pos), error))
                    }
                    Err(_) => panic!("internal parser error"),
                }
            }
        }

        fn set_default(&mut self, name: String, value: ConfigValue) {
            match value {
                Flag(value) => {
                    if value {
                        self.settings.flags.insert(name);
                    } else {
                        self.settings.flags.remove(&name);
                    }
                }
                List(mode, values) => {
                    let slot: &mut _ = self.settings.list.entry(name).or_default();
                    match mode {
                        Mode::Set => *slot = values.into_iter().collect(),
                        Mode::Add => slot.extend(values),
                        Mode::Del => {
                            for key in values {
                                slot.remove(&key);
                            }
                        }
                    }
                }
                Text(value) => {
                    self.settings.str_value.insert(name, value);
                }
                Enum(value) => {
                    self.settings.enum_value.insert(name, value);
                }
                Num(value) => {
                    self.settings.int_value.insert(name, value);
                }
            }
        }
    }

    let mut diagnostics = vec![];
    result.process(path, sudoers, &mut diagnostics, &mut 0);

    let alias = &mut result.aliases;
    alias.user.0 = sanitize_alias_table(&alias.user.1, &mut diagnostics);
    alias.host.0 = sanitize_alias_table(&alias.host.1, &mut diagnostics);
    alias.cmnd.0 = sanitize_alias_table(&alias.cmnd.1, &mut diagnostics);
    alias.runas.0 = sanitize_alias_table(&alias.runas.1, &mut diagnostics);

    (result, diagnostics)
}

/// Alias definition inin a Sudoers file can come in any order; and aliases can refer to other aliases, etc.
/// It is much easier if they are presented in a "definitional order" (i.e. aliases that use other aliases occur later)
/// At the same time, this is a good place to detect problems in the aliases, such as unknown aliases and cycles.

fn sanitize_alias_table<T>(table: &Vec<Def<T>>, diagnostics: &mut Vec<Error>) -> Vec<usize> {
    fn remqualify<U>(item: &Qualified<U>) -> &U {
        match item {
            Qualified::Allow(x) => x,
            Qualified::Forbid(x) => x,
        }
    }

    // perform a topological sort (hattip david@tweedegolf.com) to produce a derangement
    struct Visitor<'a, T> {
        seen: HashSet<usize>,
        table: &'a Vec<Def<T>>,
        order: Vec<usize>,
        diagnostics: &'a mut Vec<Error>,
    }

    impl<T> Visitor<'_, T> {
        fn complain(&mut self, text: String) {
            self.diagnostics.push(Error(None, text))
        }

        fn visit(&mut self, pos: usize) {
            if self.seen.insert(pos) {
                let Def(_, members) = &self.table[pos];
                for elem in members {
                    let Meta::Alias(name) = remqualify(elem) else {
                        break;
                    };
                    let Some(dependency) = self.table.iter().position(|Def(id, _)| id == name)
                    else {
                        self.complain(format!("undefined alias: '{name}'"));
                        continue;
                    };
                    self.visit(dependency);
                }
                self.order.push(pos);
            } else if !self.order.contains(&pos) {
                let Def(id, _) = &self.table[pos];
                self.complain(format!("recursive alias: '{id}'"));
            }
        }
    }

    let mut visitor = Visitor {
        seen: HashSet::new(),
        table,
        order: Vec::with_capacity(table.len()),
        diagnostics,
    };

    let mut dupe = HashSet::new();
    for (i, Def(name, _)) in table.iter().enumerate() {
        if !dupe.insert(name) {
            visitor.complain(format!("multiple occurrences of '{name}'"));
        } else {
            visitor.visit(i);
        }
    }

    visitor.order
}

#[cfg(test)]
mod test;
