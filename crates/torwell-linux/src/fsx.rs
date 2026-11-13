//! Symlink-safe, ownership-checked filesystem helpers built on `openat(2)`.
//!
//! Every directory component is opened with `O_NOFOLLOW|O_DIRECTORY` and checked with
//! `fstat`, so a symlink or attacker-writable directory anywhere in the chain is refused.
//! `owner` is 0 in production; tests pass their own uid.

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Component, Path, PathBuf};

use crate::error::Error;

pub struct SecureDir {
    fd: OwnedFd,
    pub path: PathBuf,
    owner: u32,
}

fn cstr(s: &str) -> Result<CString, Error> {
    CString::new(s).map_err(|_| Error::UnsafePath(format!("NUL in name {s:?}")))
}

fn last_err() -> io::Error {
    io::Error::last_os_error()
}

fn fstat(fd: RawFd) -> io::Result<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(last_err());
    }
    Ok(st)
}

fn check_leaf_name(name: &str) -> Result<(), Error> {
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err(Error::UnsafePath(format!("bad file name {name:?}")));
    }
    Ok(())
}

/// Opens `path` (absolute, no `..`) as a trusted directory. Ancestors must be owned by
/// root or `owner`, and not group/other-writable unless sticky. The final directory must be
/// owned by `owner` and not group/other-writable. With `create`, a missing final component
/// is made with mode 0755.
pub fn open_secure_dir(path: &Path, owner: u32, create: bool) -> Result<SecureDir, Error> {
    if !path.is_absolute() {
        return Err(Error::UnsafePath(format!(
            "{} is not absolute",
            path.display()
        )));
    }
    let root = cstr("/")?;
    let raw = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_RDONLY,
        )
    };
    if raw < 0 {
        return Err(last_err().into());
    }
    let mut cur = unsafe { OwnedFd::from_raw_fd(raw) };
    let comps: Vec<&std::ffi::OsStr> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(Ok(n)),
            Component::RootDir => None,
            _ => Some(Err(())),
        })
        .collect::<Result<_, _>>()
        .map_err(|_| Error::UnsafePath(format!("{} has . or .. components", path.display())))?;
    for (i, comp) in comps.iter().enumerate() {
        let last = i + 1 == comps.len();
        let name = comp
            .to_str()
            .ok_or_else(|| Error::UnsafePath("non-UTF-8 path".into()))?;
        let c = cstr(name)?;
        let flags = libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_RDONLY;
        let mut fd = unsafe { libc::openat(cur.as_raw_fd(), c.as_ptr(), flags) };
        if fd < 0 && last && create && last_err().raw_os_error() == Some(libc::ENOENT) {
            if unsafe { libc::mkdirat(cur.as_raw_fd(), c.as_ptr(), 0o755) } != 0 {
                return Err(last_err().into());
            }
            fd = unsafe { libc::openat(cur.as_raw_fd(), c.as_ptr(), flags) };
            if fd >= 0 && unsafe { libc::fchown(fd, owner, u32::MAX) } != 0 {
                return Err(last_err().into());
            }
        }
        if fd < 0 {
            let e = last_err();
            return Err(match e.raw_os_error() {
                Some(libc::ELOOP) | Some(libc::ENOTDIR) => Error::UnsafePath(format!(
                    "{name} in {} is a symlink or not a directory",
                    path.display()
                )),
                _ => e.into(),
            });
        }
        let next = unsafe { OwnedFd::from_raw_fd(fd) };
        let st = fstat(next.as_raw_fd())?;
        let writable = st.st_mode & 0o022 != 0;
        if last {
            if st.st_uid != owner || writable {
                return Err(Error::UnsafePath(format!(
                    "{} must be owned by uid {owner} and not group/other-writable",
                    path.display()
                )));
            }
        } else if (st.st_uid != 0 && st.st_uid != owner) || (writable && st.st_mode & 0o1000 == 0) {
            return Err(Error::UnsafePath(format!(
                "ancestor {name} of {} is not trusted",
                path.display()
            )));
        }
        cur = next;
    }
    Ok(SecureDir {
        fd: cur,
        path: path.to_path_buf(),
        owner,
    })
}

impl SecureDir {
    fn open_file(&self, name: &str, flags: i32, mode: u32) -> Result<File, Error> {
        self.open_raw(name, flags, mode).map_err(|e| match e {
            Error::Io(_) => e,
            other => other,
        })
    }

    fn open_raw(&self, name: &str, flags: i32, mode: u32) -> Result<File, Error> {
        check_leaf_name(name)?;
        let c = cstr(name)?;
        let fd = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                c.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode,
            )
        };
        if fd < 0 {
            let e = last_err();
            return Err(if e.raw_os_error() == Some(libc::ELOOP) {
                Error::UnsafePath(format!("{name} is a symlink"))
            } else {
                e.into()
            });
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn check_regular(&self, f: &File, name: &str) -> Result<libc::stat, Error> {
        let st = fstat(f.as_raw_fd())?;
        if st.st_mode & libc::S_IFMT != libc::S_IFREG || st.st_nlink != 1 || st.st_uid != self.owner
        {
            return Err(Error::UnsafePath(format!(
                "{name} must be a single-link regular file owned by uid {}",
                self.owner
            )));
        }
        if st.st_mode & 0o022 != 0 {
            return Err(Error::UnsafePath(format!("{name} is group/other-writable")));
        }
        Ok(st)
    }

    /// `Ok(None)` when absent. Refuses symlinks, hardlinks, non-regular files, foreign owners.
    pub fn read_file(&self, name: &str, max: u64) -> Result<Option<Vec<u8>>, Error> {
        use std::io::Read;
        check_leaf_name(name)?;
        let c = cstr(name)?;
        let flags = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        let fd = unsafe { libc::openat(self.fd.as_raw_fd(), c.as_ptr(), flags) };
        if fd < 0 {
            let e = last_err();
            return match e.raw_os_error() {
                Some(libc::ENOENT) => Ok(None),
                Some(libc::ELOOP) => Err(Error::UnsafePath(format!("{name} is a symlink"))),
                _ => Err(e.into()),
            };
        }
        let f = unsafe { File::from_raw_fd(fd) };
        let st = self.check_regular(&f, name)?;
        if st.st_size as u64 > max {
            return Err(Error::UnsafePath(format!("{name} is too large")));
        }
        let mut buf = Vec::new();
        f.take(max).read_to_end(&mut buf)?;
        Ok(Some(buf))
    }

    /// Atomic replace: temp file (`O_EXCL`), fsync, rename over target, fsync directory.
    /// Refuses to replace a target that is not a regular owned file.
    pub fn write_file_atomic(&self, name: &str, data: &[u8], mode: u32) -> Result<(), Error> {
        use std::io::Write;
        check_leaf_name(name)?;
        // Validate any existing target before replacing it.
        let _existing = self.read_file(name, 16 << 20)?;
        let tmp = format!(".{name}.tmp{}", std::process::id());
        let tmp_c = cstr(&tmp)?;
        let _ = unsafe { libc::unlinkat(self.fd.as_raw_fd(), tmp_c.as_ptr(), 0) };
        let mut f = self.open_file(&tmp, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, mode)?;
        let res = (|| -> Result<(), Error> {
            if unsafe { libc::fchown(f.as_raw_fd(), self.owner, u32::MAX) } != 0 {
                return Err(last_err().into());
            }
            if unsafe { libc::fchmod(f.as_raw_fd(), mode) } != 0 {
                return Err(last_err().into());
            }
            f.write_all(data)?;
            f.sync_all()?;
            let name_c = cstr(name)?;
            if unsafe {
                libc::renameat(
                    self.fd.as_raw_fd(),
                    tmp_c.as_ptr(),
                    self.fd.as_raw_fd(),
                    name_c.as_ptr(),
                )
            } != 0
            {
                return Err(last_err().into());
            }
            Ok(())
        })();
        if res.is_err() {
            let _ = unsafe { libc::unlinkat(self.fd.as_raw_fd(), tmp_c.as_ptr(), 0) };
            return res;
        }
        if unsafe { libc::fsync(self.fd.as_raw_fd()) } != 0 {
            return Err(last_err().into());
        }
        Ok(())
    }

    /// Removes a regular owned file. Absent is fine.
    pub fn remove_file(&self, name: &str) -> Result<(), Error> {
        if self.read_file(name, 16 << 20)?.is_none() {
            return Ok(());
        }
        let c = cstr(name)?;
        if unsafe { libc::unlinkat(self.fd.as_raw_fd(), c.as_ptr(), 0) } != 0 {
            return Err(last_err().into());
        }
        if unsafe { libc::fsync(self.fd.as_raw_fd()) } != 0 {
            return Err(last_err().into());
        }
        Ok(())
    }

    /// Opens (creating, mode 0600) and exclusively `flock`s a lock file without blocking.
    pub fn lock(&self, name: &str) -> Result<LockGuard, Error> {
        let f = self.open_file(name, libc::O_RDWR | libc::O_CREAT, 0o600)?;
        let st = self.check_regular(&f, name)?;
        if st.st_mode & 0o077 != 0 {
            return Err(Error::UnsafePath(format!("{name} must be mode 0600")));
        }
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let e = last_err();
            return Err(if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
                Error::Locked
            } else {
                e.into()
            });
        }
        Ok(LockGuard { _file: f })
    }
}

/// Lock released when dropped (or when the process dies).
pub struct LockGuard {
    _file: File,
}

/// Checks that `path` is a trusted executable: absolute, no symlink anywhere (equal to its
/// canonical form), a regular file owned by `owner`, not group/other-writable, executable.
pub fn check_trusted_exec(path: &Path, owner: u32) -> Result<(), Error> {
    use std::os::unix::fs::MetadataExt;
    if !path.is_absolute() {
        return Err(Error::UnsafePath(format!(
            "{} is not absolute",
            path.display()
        )));
    }
    let canon = std::fs::canonicalize(path)?;
    if canon != path {
        return Err(Error::UnsafePath(format!(
            "{} resolves to {} (symlink)",
            path.display(),
            canon.display()
        )));
    }
    let md = std::fs::symlink_metadata(path)?;
    if !md.is_file() || md.uid() != owner || md.mode() & 0o022 != 0 || md.mode() & 0o111 == 0 {
        return Err(Error::UnsafePath(format!(
            "{} must be an executable regular file owned by uid {owner}, not group/other-writable",
            path.display()
        )));
    }
    let mut dir = path.parent();
    while let Some(d) = dir {
        let dm = std::fs::symlink_metadata(d)?;
        if (dm.uid() != owner && dm.uid() != 0)
            || (dm.mode() & 0o022 != 0 && dm.mode() & 0o1000 == 0)
        {
            return Err(Error::UnsafePath(format!(
                "directory {} is not trusted",
                d.display()
            )));
        }
        dir = d.parent();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("torwell-fsx-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }
    fn me() -> u32 {
        unsafe { libc::geteuid() }
    }

    #[test]
    fn atomic_write_replaces_and_leaves_no_temp_files() {
        let p = tmp("atomic");
        let d = open_secure_dir(&p, me(), false).unwrap();
        d.write_file_atomic("a", b"one", 0o644).unwrap();
        d.write_file_atomic("a", b"two", 0o644).unwrap();
        assert_eq!(d.read_file("a", 100).unwrap().unwrap(), b"two");
        assert_eq!(std::fs::read_dir(&p).unwrap().count(), 1);
        d.remove_file("a").unwrap();
        assert!(d.read_file("a", 100).unwrap().is_none());
        std::fs::remove_dir_all(&p).unwrap();
    }

    #[test]
    fn refuses_symlink_hardlink_and_non_regular_targets() {
        let p = tmp("targets");
        let d = open_secure_dir(&p, me(), false).unwrap();
        std::fs::write(p.join("real"), "x").unwrap();
        std::os::unix::fs::symlink(p.join("real"), p.join("sym")).unwrap();
        assert!(matches!(d.read_file("sym", 10), Err(Error::UnsafePath(_))));
        assert!(matches!(
            d.write_file_atomic("sym", b"y", 0o644),
            Err(Error::UnsafePath(_))
        ));
        std::fs::hard_link(p.join("real"), p.join("hard")).unwrap();
        assert!(matches!(d.read_file("hard", 10), Err(Error::UnsafePath(_))));
        std::fs::create_dir(p.join("sub")).unwrap();
        assert!(matches!(d.read_file("sub", 10), Err(Error::UnsafePath(_))));
        assert!(d.read_file("../x", 10).is_err());
        assert_eq!(std::fs::read_to_string(p.join("real")).unwrap(), "x");
        std::fs::remove_dir_all(&p).unwrap();
    }

    #[test]
    fn rejects_foreign_owner_and_world_writable_directories() {
        let p = tmp("owner");
        assert!(matches!(
            open_secure_dir(&p, me().wrapping_add(1), false),
            Err(Error::UnsafePath(_))
        ));
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o757)).unwrap();
        assert!(matches!(
            open_secure_dir(&p, me(), false),
            Err(Error::UnsafePath(_))
        ));
        assert!(open_secure_dir(Path::new("relative"), me(), false).is_err());
        assert!(open_secure_dir(&p.join("../x"), me(), false).is_err());
        std::fs::remove_dir_all(&p).unwrap();
    }

    #[test]
    fn lock_is_exclusive_and_released_on_drop() {
        let p = tmp("lock");
        let d = open_secure_dir(&p, me(), false).unwrap();
        let g = d.lock("l").unwrap();
        assert!(matches!(d.lock("l"), Err(Error::Locked)));
        drop(g);
        assert!(d.lock("l").is_ok());
        std::fs::remove_dir_all(&p).unwrap();
    }

    #[test]
    fn cookie_reader_rejects_loose_mode_symlink_and_wrong_size() {
        use crate::env::{Env, SystemEnv};
        let p = tmp("cookie");
        let f = p.join("c");
        std::fs::write(&f, [1u8; 32]).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut env = SystemEnv::new();
        assert!(env.read_cookie(&f, me()).is_err());
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(env.read_cookie(&f, me()).unwrap(), [1u8; 32]);
        assert!(env.read_cookie(&f, me().wrapping_add(1)).is_err());
        std::os::unix::fs::symlink(&f, p.join("s")).unwrap();
        assert!(env.read_cookie(&p.join("s"), me()).is_err());
        std::fs::write(p.join("short"), [1u8; 8]).unwrap();
        std::fs::set_permissions(p.join("short"), std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(env.read_cookie(&p.join("short"), me()).is_err());
        std::fs::remove_dir_all(&p).unwrap();
    }
}
