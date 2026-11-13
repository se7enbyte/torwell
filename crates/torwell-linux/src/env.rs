//! Non-command host seams: euid, user lookup, randomness, clock, Tor control transport.

use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::error::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserInfo {
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
}

pub trait Env {
    fn euid(&self) -> u32;
    /// Looks the user up by exact name; `None` when it does not exist.
    fn lookup_user(&self, name: &str) -> Result<Option<UserInfo>, Error>;
    /// Cryptographically secure random bytes (OS CSPRNG).
    fn random_bytes(&mut self, out: &mut [u8]) -> Result<(), Error>;
    /// Monotonic time since an arbitrary origin.
    fn now(&self) -> Duration;
    fn sleep(&mut self, d: Duration);
    /// Reads the 32-byte Tor control cookie, refusing symlinks, wrong owner or loose mode.
    fn read_cookie(&mut self, path: &Path, owner: u32) -> Result<[u8; 32], Error>;
    /// Connects to the unix control socket (owner-checked), writes `request`, reads until EOF
    /// or `timeout`, and returns everything read.
    fn control_exchange(
        &mut self,
        socket: &Path,
        owner: u32,
        request: &[u8],
        timeout: Duration,
    ) -> Result<String, Error>;
    /// Real, effective, saved and fs uids of a process.
    fn process_uids(&self, pid: u32) -> Result<[u32; 4], Error>;
}

pub struct SystemEnv {
    origin: Instant,
}

impl SystemEnv {
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemEnv {
    fn default() -> Self {
        Self::new()
    }
}

/// Parses one `/etc/passwd` line for `name`. Pure, for tests.
pub fn parse_passwd_line(line: &str, name: &str) -> Option<UserInfo> {
    let f: Vec<&str> = line.split(':').collect();
    if f.len() != 7 || f[0] != name {
        return None;
    }
    Some(UserInfo {
        uid: f[2].parse().ok()?,
        gid: f[3].parse().ok()?,
        home: f[5].to_string(),
        shell: f[6].to_string(),
    })
}

pub fn parse_proc_status_uids(status: &str) -> Option<[u32; 4]> {
    let line = status.lines().find(|l| l.starts_with("Uid:"))?;
    let v: Vec<u32> = line[4..]
        .split_whitespace()
        .filter_map(|x| x.parse().ok())
        .collect();
    <[u32; 4]>::try_from(v).ok()
}

impl Env for SystemEnv {
    fn euid(&self) -> u32 {
        unsafe { libc::geteuid() }
    }

    fn lookup_user(&self, name: &str) -> Result<Option<UserInfo>, Error> {
        let text = std::fs::read_to_string("/etc/passwd")?;
        Ok(text.lines().find_map(|l| parse_passwd_line(l, name)))
    }

    fn random_bytes(&mut self, out: &mut [u8]) -> Result<(), Error> {
        let mut filled = 0;
        while filled < out.len() {
            let n = unsafe {
                libc::getrandom(out[filled..].as_mut_ptr().cast(), out.len() - filled, 0)
            };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e.into());
            }
            filled += n as usize;
        }
        Ok(())
    }

    fn now(&self) -> Duration {
        self.origin.elapsed()
    }

    fn sleep(&mut self, d: Duration) {
        std::thread::sleep(d);
    }

    fn read_cookie(&mut self, path: &Path, owner: u32) -> Result<[u8; 32], Error> {
        let md = std::fs::symlink_metadata(path)?;
        if !md.is_file()
            || md.uid() != owner
            || md.mode() & 0o077 != 0
            || md.len() != 32
            || md.nlink() != 1
        {
            return Err(Error::UnsafePath(format!(
                "control cookie {} must be a 32-byte single-link file owned by uid {owner} with mode 0600",
                path.display()
            )));
        }
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags_nofollow()
            .open(path)?;
        let mut buf = [0u8; 32];
        f.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn control_exchange(
        &mut self,
        socket: &Path,
        owner: u32,
        request: &[u8],
        timeout: Duration,
    ) -> Result<String, Error> {
        let md = std::fs::symlink_metadata(socket)?;
        if !md.file_type().is_socket() || md.uid() != owner || md.mode() & 0o077 != 0 {
            return Err(Error::UnsafePath(format!(
                "control socket {} must be a unix socket owned by uid {owner} with mode 0600",
                socket.display()
            )));
        }
        let deadline = Instant::now() + timeout;
        let mut s = UnixStream::connect(socket)?;
        s.set_write_timeout(Some(timeout))?;
        s.write_all(request)?;
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Error::Tor("control connection timed out".into()));
            }
            s.set_read_timeout(Some(left))?;
            match s.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    out.extend_from_slice(&buf[..n]);
                    if out.len() > 64 * 1024 {
                        return Err(Error::Tor("control reply too large".into()));
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(Error::Tor("control connection timed out".into()))
                }
                Err(e) => return Err(e.into()),
            }
        }
        String::from_utf8(out).map_err(|_| Error::Tor("control reply is not UTF-8".into()))
    }

    fn process_uids(&self, pid: u32) -> Result<[u32; 4], Error> {
        let text = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
        parse_proc_status_uids(&text).ok_or_else(|| Error::Tor("cannot parse /proc status".into()))
    }
}

trait NoFollow {
    fn custom_flags_nofollow(&mut self) -> &mut Self;
}

impl NoFollow for std::fs::OpenOptions {
    fn custom_flags_nofollow(&mut self) -> &mut Self {
        use std::os::unix::fs::OpenOptionsExt;
        self.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwd_parsing_is_exact_and_strict() {
        let l = "torwell-tor:x:970:970:Torwell:/var/lib/torwell-tor:/usr/bin/nologin";
        let u = parse_passwd_line(l, "torwell-tor").unwrap();
        assert_eq!(
            (u.uid, u.gid, u.shell.as_str()),
            (970, 970, "/usr/bin/nologin")
        );
        assert!(parse_passwd_line(l, "torwell").is_none());
        assert!(parse_passwd_line("torwell-tor:x:abc:1:g:/h:/s", "torwell-tor").is_none());
        assert!(parse_passwd_line("torwell-tor:x:1:1", "torwell-tor").is_none());
    }

    #[test]
    fn proc_status_uid_parsing() {
        assert_eq!(
            parse_proc_status_uids("Name:\ttor\nUid:\t970\t970\t970\t970\nGid:\t1\t1\t1\t1\n"),
            Some([970; 4])
        );
        assert_eq!(
            parse_proc_status_uids("Uid:\t970\t0\t970\t970\n"),
            Some([970, 0, 970, 970])
        );
        assert_eq!(parse_proc_status_uids("Name:\ttor\n"), None);
    }
}
