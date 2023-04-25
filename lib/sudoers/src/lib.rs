#![forbid(unsafe_code)]

//! Code that checks (and in the future: lists) permissions in the sudoers file

mod ast;
mod ast_names;
mod basic_parser;
mod char_stream;
mod tokens;

use std::collections::{HashMap, HashSet};
use std::path::Path;

use ast::*;
use sudo_log::auth_warn;
use sudo_system::interface::{UnixGroup, UnixUser};
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
    pub arguments: &'a str,
}

#[derive(Debug, Default)]
pub struct Judgement {
    flags: Option<Tag>,
    settings: Settings,
}

mod policy;

pub use policy::{Authorization, DirChange, Policy, PreJudgementPolicy};

/// This function takes a file argument for a sudoers file and processes it.
impl Sudoers {
    pub fn new(path: impl AsRef<Path>) -> Result<(Sudoers, Vec<Error>), std::io::Error> {
        let sudoers = read_sudoers(path.as_ref())?;
        Ok(analyze(sudoers))
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
        if let Some(Tag { passwd, .. }) = flags.as_mut() {
            if skip_passwd {
                *passwd = false
            }
        }

        Judgement {
            flags,
            settings: self.settings.clone(), // this is wasteful, but in the future this will not be a simple clone and it avoids a lifetime
        }
    }
}

fn read_sudoers(path: &Path) -> Result<Vec<basic_parser::Parsed<Sudo>>, std::io::Error> {
    use std::io::Read;
    let mut source = sudo_system::secure_open(path)?;

    // it's a bit frustrating that BufReader.chars() does not exist
    let mut buffer = String::new();
    source.read_to_string(&mut buffer)?;

    use basic_parser::parse_lines;
    use char_stream::*;
    Ok(parse_lines(&mut PeekableWithPos::new(buffer.chars())))
}

#[derive(Default)]
pub(crate) struct AliasTable {
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

/// Process a raw parsed AST bit of RunAs + Command specifications:
/// - RunAs specifications distribute over the commands that follow (until overridden)
/// - Tags accumulate over the entire line

fn distribute_tags<'a>(
    runas_cmds: &'a Vec<(Option<RunAs>, CommandSpec)>,
) -> impl Iterator<Item = (Option<&'a RunAs>, (Tag, &'a Spec<Command>, &'a Sha2))> + DoubleEndedIterator
{
    let mut last_runas = None;
    let mut tag = Default::default();
    runas_cmds
        .iter()
        .map(move |(runas, CommandSpec(mods, cmd, digest))| {
            last_runas = runas.as_ref().or(last_runas);
            for f in mods {
                f(&mut tag);
            }
            (last_runas, (tag.clone(), cmd, digest))
        })
}

/// Check if the user `am_user` is allowed to run `cmdline` on machine `on_host` as the requested
/// user/group. Not that in the sudoers file, later permissions override earlier restrictions.
/// The `cmdline` argument should already be ready to essentially feed to an exec() call; or be
/// a special command like 'sudoedit'.

// This code is structure to allow easily reading the 'happy path'; i.e. as soon as something
// doesn't match, we escape using the '?' mechanism.
fn check_permission<User: UnixUser + PartialEq<User>, Group: UnixGroup>(
    Sudoers { rules, aliases, .. }: &Sudoers,
    am_user: &User,
    on_host: &str,
    request: Request<User, Group>,
) -> Option<Tag> {
    let cmdline = (request.command, request.arguments);

    let user_aliases = get_aliases(&aliases.user, &match_user(am_user));
    let host_aliases = get_aliases(&aliases.host, &match_token(on_host));
    let cmnd_aliases = get_aliases(&aliases.cmnd, &match_command(cmdline));
    let runas_user_aliases = get_aliases(&aliases.runas, &match_user(request.user));
    let runas_group_aliases = get_aliases(&aliases.runas, &match_group_alias(request.group));

    let mut sha2_eq = check_all_sha2(request.command);

    let allowed_commands = rules
        .iter()
        .filter_map(|sudo| {
            find_item(&sudo.users, &match_user(am_user), &user_aliases)?;
            Some(&sudo.permissions)
        })
        .flatten()
        .filter_map(|(hosts, runas_cmds)| {
            find_item(hosts, &match_token(on_host), &host_aliases)?;
            Some(distribute_tags(runas_cmds))
        })
        .flatten()
        .filter_map(|(runas, cmdspec)| {
            if let Some(RunAs { users, groups }) = runas {
                if !users.is_empty() || request.user != am_user {
                    find_item(users, &match_user(request.user), &runas_user_aliases)?
                }
                if !in_group(request.user, request.group) {
                    find_item(groups, &match_group(request.group), &runas_group_aliases)?
                }
            } else if !(request.user.is_root() && in_group(request.user, request.group)) {
                None?;
            }

            Some(cmdspec)
        })
        .filter(|(_, _, Sha2(hex))| hex.is_empty() || sha2_eq(hex));

    find_item(allowed_commands, &match_command(cmdline), &cmnd_aliases)
}

/// Find an item matching a certain predicate in an collection (optionally attributed) list of
/// identifiers; identifiers can be directly identifying, wildcards, and can either be positive or
/// negative (i.e. preceeded by an even number of exclamation marks in the sudoers file)

fn find_item<'a, Predicate, Iter, T: 'a>(
    items: Iter,
    matches: &Predicate,
    aliases: &HashSet<String>,
) -> Option<<Iter::Item as WithInfo>::Info>
where
    Predicate: Fn(&T) -> bool,
    Iter: IntoIterator,
    Iter::Item: WithInfo<Item = &'a Spec<T>>,
    Iter::IntoIter: DoubleEndedIterator,
{
    for item in items.into_iter().rev() {
        let (judgement, who) = match item.clone().as_item() {
            Qualified::Forbid(x) => (None, x),
            Qualified::Allow(x) => (Some(item.as_info()), x),
        };
        match who {
            Meta::All => return judgement,
            Meta::Only(ident) if matches(ident) => return judgement,
            Meta::Alias(id) if aliases.contains(id) => return judgement,
            _ => {}
        };
    }

    None
}

/// A interface to access optional "satellite data"
trait WithInfo: Clone {
    type Item;
    type Info;
    fn as_item(self) -> Self::Item;
    fn as_info(self) -> Self::Info;
}

/// A specific interface for `Spec<T>` --- we can't make a generic one;
/// A Spec<T> does not contain any additional information.
impl<'a, T> WithInfo for &'a Spec<T> {
    type Item = &'a Spec<T>;
    type Info = ();
    fn as_item(self) -> &'a Spec<T> {
        self
    }
    fn as_info(self) {}
}

/// A commandspec can be "tagged"
impl<'a, T> WithInfo for (Tag, &'a Spec<Command>, &'a T) {
    type Item = &'a Spec<Command>;
    type Info = Tag;
    fn as_item(self) -> &'a Spec<Command> {
        &self.1
    }
    fn as_info(self) -> Tag {
        self.0.clone()
    }
}

/// Now follow a collection of functions used as closures for `find_item`
fn match_user(user: &impl UnixUser) -> impl Fn(&UserSpecifier) -> bool + '_ {
    move |spec| match spec {
        UserSpecifier::User(id) => match_identifier(user, id),
        UserSpecifier::Group(Identifier::Name(name)) => user.in_group_by_name(name),
        UserSpecifier::Group(Identifier::ID(num)) => user.in_group_by_gid(*num),
        _ => todo!(), // nonunix-groups, netgroups, etc.
    }
}

fn in_group(user: &impl UnixUser, group: &impl UnixGroup) -> bool {
    user.in_group_by_gid(group.as_gid())
}

fn match_group(group: &impl UnixGroup) -> impl Fn(&Identifier) -> bool + '_ {
    move |id| match id {
        Identifier::ID(num) => group.as_gid() == *num,
        Identifier::Name(name) => group.try_as_name().map_or(false, |s| s == name),
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

fn match_command<'a>((cmd, args): (&'a Path, &'a str)) -> (impl Fn(&Command) -> bool + 'a) {
    move |(cmdpat, argpat)| cmdpat.matches_path(cmd) && argpat.matches(args)
}

/// Find all the aliases that a object is a member of; this requires [sanitize_alias_table] to have run first;
/// I.e. this function should not be "pub".

fn get_aliases<Predicate, T>(table: &VecOrd<Def<T>>, pred: &Predicate) -> HashSet<String>
where
    Predicate: Fn(&T) -> bool,
{
    let mut set = HashSet::new();
    for Def(id, list) in elems(table) {
        if find_item(list, &pred, &set).is_some() {
            set.insert(id.clone());
        }
    }

    set
}

/// Code to map an ast::Identifier to the UnixUser trait

fn match_identifier(user: &impl UnixUser, ident: &ast::Identifier) -> bool {
    match ident {
        Identifier::Name(name) => user.has_name(name),
        Identifier::ID(num) => user.has_uid(*num),
    }
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub flags: HashSet<String>,
    pub str_value: HashMap<String, Option<Box<str>>>,
    pub enum_value: HashMap<String, TextEnum>,
    pub int_value: HashMap<String, i128>,
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

        use sudo_defaults::{sudo_default, OptTuple, SudoDefault};
        for key in sudo_defaults::ALL_PARAMS.iter() {
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
fn analyze(sudoers: impl IntoIterator<Item = basic_parser::Parsed<Sudo>>) -> (Sudoers, Vec<Error>) {
    use ConfigValue::*;
    use Directive::*;

    let mut result: Sudoers = Default::default();

    impl Sudoers {
        fn include(&mut self, path: &Path, diagnostics: &mut Vec<Error>, count: &mut u8) {
            if *count >= INCLUDE_LIMIT {
                diagnostics.push(Error(
                    None,
                    format!("include file limit reached opening `{}'", path.display()),
                ))
            } else if let Ok(subsudoer) = read_sudoers(path) {
                *count += 1;
                self.process(subsudoer, diagnostics, count)
            } else {
                diagnostics.push(Error(
                    None,
                    format!("cannot open sudoers file `{}'", path.display()),
                ))
            }
        }

        fn process(
            &mut self,
            sudoers: impl IntoIterator<Item = basic_parser::Parsed<Sudo>>,
            diagnostics: &mut Vec<Error>,
            safety_count: &mut u8,
        ) {
            for item in sudoers {
                match item {
                    Ok(line) => match line {
                        Sudo::LineComment => {}

                        Sudo::Spec(permission) => self.rules.push(permission),

                        Sudo::Decl(UserAlias(def)) => self.aliases.user.1.push(def),
                        Sudo::Decl(HostAlias(def)) => self.aliases.host.1.push(def),
                        Sudo::Decl(CmndAlias(def)) => self.aliases.cmnd.1.push(def),
                        Sudo::Decl(RunasAlias(def)) => self.aliases.runas.1.push(def),

                        Sudo::Decl(Defaults(params)) => {
                            for (name, value) in params {
                                self.set_default(name, value)
                            }
                        }

                        Sudo::Include(path) => {
                            self.include(path.as_ref(), diagnostics, safety_count)
                        }

                        Sudo::IncludeDir(path) => {
                            let Ok(files) = std::fs::read_dir(&path) else {
                                diagnostics.push(Error(None, format!("cannot open sudoers file {path}")));
                                continue;
                            };
                            let mut safe_files = files
                                .filter_map(|direntry| {
                                    let path = direntry.ok()?.path();
                                    let text = path.to_str()?;
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
    result.process(sudoers, &mut diagnostics, &mut 0);

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
                    let Meta::Alias(name) = remqualify(elem) else { break };
                    let Some(dependency) = self.table.iter().position(|Def(id,_)| id==name) else {
                        self.complain(format!("undefined alias: `{name}'"));
                        continue;
                    };
                    self.visit(dependency);
                }
                self.order.push(pos);
            } else if !self.order.contains(&pos) {
                let Def(id, _) = &self.table[pos];
                self.complain(format!("recursive alias: `{id}'"));
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
            visitor.complain(format!("multiple occurences of `{name}'"));
        } else {
            visitor.visit(i);
        }
    }

    visitor.order
}

mod compute_hash;

fn check_all_sha2(binary: &Path) -> impl FnMut(&Box<[u8]>) -> bool + '_ {
    use compute_hash::sha2;

    let mut memo = std::collections::HashMap::new(); // pun not intended

    move |bytes| {
        let bits = 8 * bytes.len() as u16;
        memo.entry(bits).or_insert_with(|| sha2(bits, binary)) == bytes
    }
}

#[cfg(test)]
mod test;
