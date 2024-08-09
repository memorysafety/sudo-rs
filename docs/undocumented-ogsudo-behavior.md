This internal document describes ogsudo behavior that's not documented in its man pages.

Where possible, this document is formatted as a list of "diffs" on top of version 1.9.5 of the man pages.

# [`man sudo`](https://www.sudo.ws/docs/man/1.9.5/sudo.man/)

## [`-D` *directory*, `--chdir` *directory*](https://www.sudo.ws/docs/man/1.9.5/sudo.man/#D)

The `--chdir` flag is ignored if its value matches the current working directory.
This applies regardless of what the `CWD` policy in the sudoers file specifies for the invoking user.
That is, `sudo --chdir=$(pwd) true` is equivalent to `sudo true`.

## [Environment](https://www.sudo.ws/docs/man/1.9.5/sudo.man/#ENVIRONMENT)

### [`SUDO_PS1`](https://www.sudo.ws/docs/man/1.9.5/sudo.man/#SUDO_PS1)

The `SUDO_PS1` mechanism has precedence over the `env_keep` and `env_check` mechanisms.
If `PS1` is in either of those lists and `PS1` and `SUDO_PS1` are both set in the invoking sure environment,
then `PS1` will be set to the value of `SUDO_PS1`.
In other words: given `Defaults env_keep = PS1`, `env PS1=a SUDO_PS1=b sudo printenv PS1` prints `b`.

## Miscellaneous

This section contains information that can't be placed in any of the existing man page sections.

### Command-Line Interface

In the case of short flags that accept a value, the space between the flag and the value is not required.
That is, `sudo -u root true` and `sudo -uroot true` are equivalent.

# [`man sudoers`](https://www.sudo.ws/docs/man/1.9.5/sudoers.man/)

## [Sudoers file format](https://www.sudo.ws/docs/man/1.9.5/sudoers.man/#SUDOERS_FILE_FORMAT)

### [Aliases](https://www.sudo.ws/docs/man/1.9.5/sudoers.man/#Aliases)

The manual states that the allowed syntax for aliases is:

> `NAME ::= A-Z*`

but that is incorrect; the allowed syntax is actually: `NAME ::= [A-Z]([A-Z][0-9]_)*`.
That is, aliases can contain digits and underscores but must start with an uppercase letter.

## [Command environment](https://www.sudo.ws/docs/man/1.9.5/sudoers.man/#Command_environment)

### `VARIABLE=value` matching

The manual says:

> By default, environment variables are matched by name. However, if the pattern includes an equal
> sign (`=`), both the variables name and value must match  

but does not mention that the equal sign can only be used when surrounded by double quotes.
That is, `Defaults env_check = "VARIABLE=value"` is correct syntax.
Whereas, `Defaults env_check = VARIABLE=value` is invalid syntax.

### `SUDO_PS1`

The manual says:

> Environment variables with a value beginning with `()` are removed unless both the name and value
> parts are matched by `env_keep` or `env_check`, as they may be interpreted as functions by the
> bash shell 

This does not affect the operation of the `SUDO_PS1` environment variable.
That is, `SUDO_PS1="() abc" sudo printenv PS1` prints `() abc`

## [Sudoers options](https://www.sudo.ws/docs/man/1.9.5/sudoers.man/#SUDOERS_OPTIONS)

### `env_keep`

The `env_keep` list is not empty by default and contains the following environment variables by name: 

- `DISPLAY`
- `PATH`

These variables can be removed from the list using either the override (`=`) or remove (`-=`) operators.

### `env_check`

The `env_check` list is not empty by default and contains the following environment variables by name:

- `TERM`
- `TZ`

These variables can be removed from the list using either the override (`=`) or remove (`-=`) operators.

### Applies to both `env_keep` and `env_checek`

#### `!` clears the list

The manual says that the `!` operator "disables" the list but it would be more accurate to say that it *clears* the list.
After clearing the list with `Defaults !env_keep` (`Defaults !env_check`), it's possible to override its contents and/or add items to it.

#### Error handling

The manual says that the `env_keep` (`env_check`) accepts a list of space-separated variables but does not mention how errors within the list are handled.
sudo skips / ignores malformed items and updates the list using only the well-formed items.
That is, given `Defaults env_keep += "A.* VARIABLE"` sudo adds `VARIABLE` to the `env_keep` list.

#### `SUDO_` variables

This is not explicit in the manual: it's not possible to preserve the following variables from the invoking user's environment as they'll be set by sudo.

- `SUDO_COMMAND`
- `SUDO_GID`
- `SUDO_UID`
- `SUDO_USER`
