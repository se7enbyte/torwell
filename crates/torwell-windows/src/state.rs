//! Durable Torwell-owned state, written ahead of every mutation so recovery knows what may exist.
//! The directory must be Administrators/SYSTEM-only; state is a single JSON file replaced
//! atomically, guarded by a lock file whose owner PID is checked for liveness.

use std::any::Any;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use torwell_core::mac::{MacAddress, MacRestore};

use crate::error::{Error, Result};
use crate::verify::PathGuard;

pub const STATE_VERSION: u32 = 1;
const MAX_STATE_BYTES: u64 = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcRecord {
    pub pid: u32,
    /// Verified image path; a PID is only terminated if its live image still matches.
    pub image: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacRecord {
    pub restore: MacRestore,
    pub candidate: MacAddress,
    /// Set before the change is attempted, so an interrupted change is still restored.
    pub change_attempted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum Phase {
    Starting,
    Active,
    Blocked { reason: String },
    Stopping,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnedState {
    pub version: u32,
    pub session: String,
    pub phase: Phase,
    /// True once base WFP installation has been *attempted* (may exist).
    pub wfp_base: bool,
    pub wfp_tunnel_luid: Option<u64>,
    pub tunnel_name: String,
    pub tor_exe: PathBuf,
    pub tor: Option<ProcRecord>,
    pub bridge: Option<ProcRecord>,
    pub mac: Option<MacRecord>,
}

impl OwnedState {
    pub fn new(session: String, tunnel_name: String, tor_exe: PathBuf) -> Self {
        Self {
            version: STATE_VERSION,
            session,
            phase: Phase::Starting,
            wfp_base: false,
            wfp_tunnel_luid: None,
            tunnel_name,
            tor_exe,
            tor: None,
            bridge: None,
            mac: None,
        }
    }
}

pub trait StateStore {
    fn load(&self) -> Result<Option<OwnedState>>;
    fn save(&self, state: &OwnedState) -> Result<()>;
    fn clear(&self) -> Result<()>;
    /// Exclusive lock for the lifetime of the returned guard.
    fn lock(&self) -> Result<Box<dyn Any>>;
}

pub struct FileStateStore<G: PathGuard> {
    dir: PathBuf,
    guard: G,
    is_alive: Box<dyn Fn(u32) -> bool>,
}

struct LockFile(PathBuf);
impl Drop for LockFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

impl<G: PathGuard> FileStateStore<G> {
    pub fn new(dir: PathBuf, guard: G, is_alive: Box<dyn Fn(u32) -> bool>) -> Self {
        Self {
            dir,
            guard,
            is_alive,
        }
    }

    fn file(&self) -> PathBuf {
        self.dir.join("state.json")
    }
    fn lock_path(&self) -> PathBuf {
        self.dir.join("state.lock")
    }

    fn check_dir(&self) -> Result<()> {
        self.guard
            .verify_admin_only(&self.dir)
            .map_err(|e| Error::State(format!("state directory unsafe: {e}")))
    }

    fn reject_link(p: &Path) -> Result<bool> {
        match fs::symlink_metadata(p) {
            Ok(m) if m.file_type().is_symlink() || !m.is_file() => Err(Error::State(format!(
                "{} is not a regular file",
                p.display()
            ))),
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(Error::State(e.to_string())),
        }
    }
}

impl<G: PathGuard> StateStore for FileStateStore<G> {
    fn load(&self) -> Result<Option<OwnedState>> {
        self.guard.ensure_secure_dir(&self.dir)?;
        self.check_dir()?;
        let p = self.file();
        if !Self::reject_link(&p)? {
            return Ok(None);
        }
        let meta = fs::metadata(&p).map_err(|e| Error::State(e.to_string()))?;
        if meta.len() > MAX_STATE_BYTES {
            return Err(Error::State("state file too large".into()));
        }
        let text = fs::read_to_string(&p).map_err(|e| Error::State(e.to_string()))?;
        let st: OwnedState =
            serde_json::from_str(&text).map_err(|e| Error::State(format!("corrupt state: {e}")))?;
        if st.version != STATE_VERSION {
            return Err(Error::State(format!(
                "unsupported state version {}",
                st.version
            )));
        }
        Ok(Some(st))
    }

    fn save(&self, state: &OwnedState) -> Result<()> {
        self.guard.ensure_secure_dir(&self.dir)?;
        self.check_dir()?;
        let target = self.file();
        Self::reject_link(&target)?;
        let tmp = self.dir.join("state.json.tmp");
        Self::reject_link(&tmp)?;
        let json = serde_json::to_vec_pretty(state).map_err(|e| Error::State(e.to_string()))?;
        let io = |e: std::io::Error| Error::State(e.to_string());
        let mut f = fs::File::create(&tmp).map_err(io)?;
        f.write_all(&json).map_err(io)?;
        f.sync_all().map_err(io)?;
        drop(f);
        fs::rename(&tmp, &target).map_err(io)
    }

    fn clear(&self) -> Result<()> {
        self.check_dir()?;
        match fs::remove_file(self.file()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::State(e.to_string())),
        }
    }

    fn lock(&self) -> Result<Box<dyn Any>> {
        self.guard.ensure_secure_dir(&self.dir)?;
        self.check_dir()?;
        let p = self.lock_path();
        for _ in 0..2 {
            match fs::OpenOptions::new().write(true).create_new(true).open(&p) {
                Ok(mut f) => {
                    let _ = write!(f, "{}", std::process::id());
                    return Ok(Box::new(LockFile(p)));
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    Self::reject_link(&p)?;
                    let pid: Option<u32> = fs::read_to_string(&p)
                        .ok()
                        .and_then(|s| s.trim().parse().ok());
                    match pid {
                        Some(pid) if (self.is_alive)(pid) => {
                            return Err(Error::State(format!(
                                "another Torwell helper (pid {pid}) holds the lock"
                            )))
                        }
                        _ => {
                            // Owner is gone (or unreadable): the lock is stale.
                            fs::remove_file(&p).map_err(|e| Error::State(e.to_string()))?;
                        }
                    }
                }
                Err(e) => return Err(Error::State(e.to_string())),
            }
        }
        Err(Error::State("could not acquire state lock".into()))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::testutil::{temp_dir, FakeGuard};

    fn store(name: &str, alive: bool) -> (FileStateStore<FakeGuard>, PathBuf) {
        let d = temp_dir(name);
        (
            FileStateStore::new(d.clone(), FakeGuard::default(), Box::new(move |_| alive)),
            d,
        )
    }

    fn sample() -> OwnedState {
        OwnedState::new(
            "s1".into(),
            "torwell0".into(),
            PathBuf::from(r"C:\Tor\tor.exe"),
        )
    }

    #[test]
    fn round_trip_and_clear() {
        let (s, _) = store("st-rt", false);
        assert_eq!(s.load().unwrap(), None);
        let mut st = sample();
        st.wfp_base = true;
        s.save(&st).unwrap();
        assert_eq!(s.load().unwrap(), Some(st));
        s.clear().unwrap();
        assert_eq!(s.load().unwrap(), None);
        s.clear().unwrap();
    }

    #[test]
    fn unsafe_directory_blocks_every_operation() {
        let d = temp_dir("st-unsafe");
        let s = FileStateStore::new(
            d,
            FakeGuard {
                insecure_state: true,
                ..Default::default()
            },
            Box::new(|_| false),
        );
        assert!(s.load().is_err());
        assert!(s.save(&sample()).is_err());
        assert!(s.lock().is_err());
    }

    #[test]
    fn symlinked_state_file_is_refused() {
        let (s, d) = store("st-link", false);
        let victim = d.join("victim");
        fs::write(&victim, b"{}").unwrap();
        std::os::unix::fs::symlink(&victim, d.join("state.json")).unwrap();
        assert!(s.load().is_err());
        assert!(s.save(&sample()).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"{}");
    }

    #[test]
    fn corrupt_and_wrong_version_are_errors_not_empty() {
        let (s, d) = store("st-bad", false);
        fs::write(d.join("state.json"), b"not json").unwrap();
        assert!(s.load().is_err());
        let mut st = sample();
        st.version = 99;
        fs::write(d.join("state.json"), serde_json::to_vec(&st).unwrap()).unwrap();
        assert!(s.load().is_err());
    }

    #[test]
    fn lock_is_exclusive_and_stale_lock_is_reclaimed() {
        let (live, d) = store("st-lock", true);
        let g = live.lock().unwrap();
        assert!(live.lock().is_err());
        drop(g);
        let g = live.lock().unwrap();
        drop(g);
        // Stale: lock file exists but its owner is dead.
        fs::write(d.join("state.lock"), "4242").unwrap();
        let dead = FileStateStore::new(d.clone(), FakeGuard::default(), Box::new(|_| false));
        assert!(dead.lock().is_ok());
    }
}
