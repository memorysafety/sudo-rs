use std::fs::{DirBuilder, File, Metadata, OpenOptions};
use std::io::{self, Error, ErrorKind};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::prelude::OpenOptionsExt;
use std::path::Path;

// of course we can also write "file & 0o040 != 0", but this makes the intent explicit
enum Op {
    Read = 4,
    Write = 2,
    Exec = 1,
}
enum Category {
    Owner = 2,
    Group = 1,
    World = 0,
}

fn mode(who: Category, what: Op) -> u32 {
    (what as u32) << (3 * who as u32)
}

pub fn secure_open(path: impl AsRef<Path>, check_parent_dir: bool) -> io::Result<File> {
    let mut open_options = OpenOptions::new();
    open_options.read(true);
    secure_open_impl(path.as_ref(), &mut open_options, check_parent_dir, false)
}

pub fn secure_open_cookie_file(path: impl AsRef<Path>) -> io::Result<File> {
    let mut open_options = OpenOptions::new();
    open_options
        .read(true)
        .write(true)
        .create(true)
        .mode(mode(Category::Owner, Op::Write) | mode(Category::Owner, Op::Read));
    secure_open_impl(path.as_ref(), &mut open_options, true, true)
}

fn checks(path: &Path, meta: Metadata) -> io::Result<()> {
    let error = |msg| Error::new(ErrorKind::PermissionDenied, msg);

    let path_mode = meta.permissions().mode();
    if meta.uid() != 0 {
        Err(error(format!("{} must be owned by root", path.display())))
    } else if meta.gid() != 0 && (path_mode & mode(Category::Group, Op::Write) != 0) {
        Err(error(format!(
            "{} cannot be group-writable",
            path.display()
        )))
    } else if path_mode & mode(Category::World, Op::Write) != 0 {
        Err(error(format!(
            "{} cannot be world-writable",
            path.display()
        )))
    } else {
        Ok(())
    }
}

// Open `path` with options `open_options`, provided that it is "secure".
// "Secure" means that it passes the `checks` function above.
// If `check_parent_dir` is set, also check that the parent directory is "secure" also.
// If `create_parent_dirs` is set, create the path to the file if it does not already exist.
fn secure_open_impl(
    path: &Path,
    open_options: &mut OpenOptions,
    check_parent_dir: bool,
    create_parent_dirs: bool,
) -> io::Result<File> {
    let error = |msg| Error::new(ErrorKind::PermissionDenied, msg);
    if check_parent_dir || create_parent_dirs {
        if let Some(parent_dir) = path.parent() {
            // if we should create parent dirs and it does not yet exist, create it
            if create_parent_dirs && !parent_dir.exists() {
                DirBuilder::new()
                    .recursive(true)
                    .mode(
                        mode(Category::Owner, Op::Write)
                            | mode(Category::Owner, Op::Read)
                            | mode(Category::Owner, Op::Exec)
                            | mode(Category::Group, Op::Exec)
                            | mode(Category::World, Op::Exec),
                    )
                    .create(parent_dir)?;
            }

            if check_parent_dir {
                let parent_meta = std::fs::metadata(parent_dir)?;
                checks(parent_dir, parent_meta)?;
            }
        } else {
            return Err(error(format!(
                "{} has no valid parent directory",
                path.display()
            )));
        }
    }

    let file = open_options.open(path)?;
    let meta = file.metadata()?;
    checks(path, meta)?;

    Ok(file)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[ignore = "ci"]
    fn secure_open_is_predictable() {
        // /etc/hosts should be readable and "secure" (if this test fails, you have been compromised)
        assert!(std::fs::File::open("/etc/hosts").is_ok());
        assert!(secure_open("/etc/hosts", false).is_ok());
        // /var/log/utmp should be readable, but not secure (writeable by group other than root)
        assert!(std::fs::File::open("/var/log/wtmp").is_ok());
        assert!(secure_open("/var/log/wtmp", false).is_err());
        // /etc/shadow should not be readable
        assert!(std::fs::File::open("/etc/shadow").is_err());
        assert!(secure_open("/etc/shadow", false).is_err());
    }

    #[test]
    #[ignore = "ci"]
    fn test_secure_open_cookie_file() {
        assert!(secure_open_cookie_file("/etc/hosts").is_err());
    }
}
