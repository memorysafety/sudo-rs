# sudo-rs

A safety oriented and memory safe implementation of sudo and su written in Rust.

## Status of this project

Sudo-rs is being developed further; features you might expect from original sudo
may still be unimplemented or not planned. If there is an important one you need,
please request it using the issue tracker. If you encounter any usability bugs,
also please report them on the [issue tracker](https://github.com/memorysafety/sudo-rs/issues).
Suspected vulnerabilities can be reported on our [security page](https://github.com/memorysafety/sudo-rs/security).

An [audit of sudo-rs version 0.2.0](docs/audit/audit-report-sudo-rs.pdf) has been performed in August 2023.
The findings from that audit are addressed in the current version.

Sudo-rs currently is targeted for Linux-based operating systems only; Linux kernel 5.9
or newer is necessary to run sudo-rs.

## Installing sudo-rs

The recommended way to start using `sudo-rs` is via the package manager of your Linux distribution.

### Arch Linux

```sh
yay -Syu sudo-rs
```

### Debian/Ubuntu
If you are running Debian 13 (trixie) or later, or Ubuntu 24.04 (Noble Numbat) or later, you can use:
```sh
sudo apt-get install sudo-rs
```
This will offer the functionality using the commands `su-rs` and `sudo-rs`. If you want to invoke sudo-rs
via the usual commands `sudo` and `su` instead, prepend `/usr/lib/cargo/bin` to your current `$PATH` variable.

### Fedora

For Fedora, we expect sudo-rs to be available via its package manager soon.

### Installing our pre-compiled x86-64 binaries

You can also switch to sudo-rs manually by using our pre-compiled tarballs.
We currently only offer these for x86-64 systems.

We recommend installing sudo-rs and su-s in your `/usr/local` hierarchy using the commands:
```sh
sudo tar -C /usr/local -xvf sudo-VERSION.tar.gz
```
and for su-rs:
```sh
sudo tar -C /usr/local -xvf su-VERSION.tar.gz
```
This will install sudo-rs and su-rs in `/usr/local/bin` using the usual commands `sudo` and `su`.

### Building from source

Sudo-rs is written in Rust. The minimum required Rust version is 1.70. If your
Linux distribution does not package that version (or a later one), you can always
install the most recent version through [rustup]. You also need the C development
files for PAM (`libpam0g-dev` on Debian, `pam-devel` on Fedora).

On Ubuntu or Debian-based systems, use the following command to install the PAM development library:
```
sudo apt-get install libpam0g-dev
```

On Fedora, CentOS and other Red Hat-based systems, you can use the following command:
```
sudo yum install pam-devel
```

With dependencies installed, building sudo-rs is a simple matter of:
```
cargo build --release
```

This produces a binary `target/release/sudo`. However, this binary must have
the setuid flag set and must be owned by the root user in order to provide any
useful functionality. Consult your operating system manual for details.

Sudo-rs needs the sudoers configuration file. The sudoers configuration file
will be loaded from `/etc/sudoers-rs` if that file exists, otherwise the
original `/etc/sudoers` location will be used. You must make sure that a valid
sudoers configuration exists at that location. For an explanation of the
sudoers syntax you can look at the
[original sudo man page](https://www.sudo.ws/docs/man/sudoers.man/).

[rustup]: https://rustup.rs/

## Differences from original sudo

sudo-rs supports less functionality than sudo. Some of this is by design. In
most cases you will get a clear error if you try something that is not
supported (e.g. use a configuration flag or command line option that is not
implemented).

Exceptions to the above, with respect to your `/etc/sudoers` configuration:

* `use_pty` is enabled by default, but can be disabled.
* `env_reset` is ignored --- this is always enabled.
* `visiblepw` is ignored --- this is always disabled.
* `verifypw` is currently ignored; a password is always necessary for `sudo -v`.
* `mail_badpass`, `always_set_home`, `always_query_group_plugin` and
  `match_group_by_gid` are not applicable to our implementation, but ignored for
  compatibility reasons.

Some other notable restrictions to be aware of:

* Some functionality is not yet supported; in particular `sudoedit` and preventing shell
  escapes using `NOEXEC` and `NOINTERCEPT`.
* Per-user, per-command, per-host `Defaults` sudoers entries for finer-grained control
  are not (yet) supported.
* Sudo-rs always uses PAM for authentication at this time, your system must be
  set up for PAM. Sudo-rs will use the `sudo` service configuration. This also means
  that resource limits, umasks, etc have to be configured via PAM and not through
  the sudoers file.
* sudo-rs will not include the sendmail support of original sudo.
* The sudoers file must be valid UTF-8.
* To prevent a common configuration mistake in the sudoers file, wildcards
  are not supported in *argument positions* for a command.
  E.g., `%sudoers ALL = /sbin/fsck*` will allow `sudo fsck` and `sudo fsck_exfat` as expected,
  but `%sudoers ALL = /bin/rm *.txt` will not allow an operator to run `sudo rm README.txt`,
  nor `sudo rm -rf /home .txt`, as with original sudo.

If you find a common use case for original sudo missing, please create a feature
request for it in our issue tracker.

## Aim of the project

Our current target is to build a drop-in replacement for all common use cases of
sudo. For the sudoers config syntax this means that we support the default
configuration files of common Linux distributions. Our implementation should support
all commonly used command line options from the original sudo implementation.

Some parts of the original sudo are explicitly not in scope. Sudo has a large
and rich history and some of the features available in the original sudo
implementation are largely unused or only available for legacy platforms. In
order to determine which features make it we both consider whether the feature
is relevant for modern systems, and whether it will receive at very least
decent usage. Finally, of course, a feature should not compromise the safety of
the whole program.

Our `su` implementation is made using the building blocks we created for our
sudo implementation.  It will be suitable replacement for the `su` distributed
by [util-linux].

[util-linux]: https://github.com/util-linux/util-linux

## Future work

While our initial target is a drop-in replacement for most basic use cases of
sudo, our work may evolve beyond that target. We are also looking into
alternative ways to configure sudo without the sudoers config file syntax and to
extract parts of our work in usable crates for other people.

## Sponsors

The development of sudo-rs is an initiative of the [Prossimo project by ISRG](https://www.memorysafety.org/).
An independent security audit of sudo-rs was made possible by the [NLNet Foundation](https://nlnet.nl/).
