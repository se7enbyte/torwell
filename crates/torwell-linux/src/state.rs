//! Root-owned durable state. Written (atomically) *before* each class of mutation.

use serde::{Deserialize, Serialize};
use torwell_core::{Config, MacAddress, MacRestore};

use crate::error::Error;
use crate::fsx::{LockGuard, SecureDir};

pub const STATE_FILE: &str = "state.json";
pub const LOCK_FILE: &str = "lock";
const VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum Phase {
    /// Intent recorded; mutations may be in flight or have been interrupted.
    Starting,
    /// Tor bootstrap and enforcement verified.
    Active,
    /// Enforcement verified blocking, Tor not usable.
    Blocked {
        reason: String,
    },
    RecoveryRequired {
        reason: String,
    },
    Stopping,
}

/// Whether the owned nft table may exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NftMark {
    /// Not attempted.
    None,
    /// Apply attempted; the table may or may not exist.
    Pending,
    Installed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacProgress {
    /// Modify attempted; the profile may or may not hold the candidate.
    Pending,
    Applied,
}

/// A DHCP "send hostname" property of the profile, with the raw value read before the change
/// (`yes`/`no` on older NetworkManager, `-1`/`0`/`1` on 1.52+). Restored on stop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostnamePrior {
    pub property: String,
    pub prior: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacRecord {
    pub connection_uuid: String,
    /// `802-3-ethernet` or `802-11-wireless`.
    pub setting: String,
    pub restore: MacRestore,
    pub candidate: MacAddress,
    pub progress: MacProgress,
    /// Hostname-sending properties disabled together with the MAC change. Absent in state
    /// files written before this existed.
    #[serde(default)]
    pub hostname: Vec<HostnamePrior>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Durable {
    pub version: u32,
    /// Random ownership token; embedded in every owned nft rule comment.
    pub token: String,
    pub phase: Phase,
    pub config: Config,
    pub tor_uid: u32,
    pub nft: NftMark,
    pub tor_started: bool,
    /// Rule listing (handles stripped) captured right after install; used for tamper checks.
    pub fingerprint: Option<String>,
    pub mac: Option<MacRecord>,
}

impl Durable {
    pub fn new(token: String, config: Config, tor_uid: u32) -> Self {
        Self {
            version: VERSION,
            token,
            phase: Phase::Starting,
            config,
            tor_uid,
            nft: NftMark::None,
            tor_started: false,
            fingerprint: None,
            mac: None,
        }
    }
}

pub struct Store {
    dir: SecureDir,
}

impl Store {
    pub fn new(dir: SecureDir) -> Self {
        Self { dir }
    }

    pub fn load(&self) -> Result<Option<Durable>, Error> {
        match self.dir.read_file(STATE_FILE, 1 << 20)? {
            None => Ok(None),
            Some(b) => {
                let d: Durable = serde_json::from_slice(&b)
                    .map_err(|e| Error::State(format!("corrupt state: {e}")))?;
                if d.version != VERSION {
                    return Err(Error::State(format!(
                        "unsupported state version {}",
                        d.version
                    )));
                }
                Ok(Some(d))
            }
        }
    }

    /// Readable by unprivileged status callers (0644); contains no secrets.
    pub fn save(&self, d: &Durable) -> Result<(), Error> {
        let b = serde_json::to_vec_pretty(d).map_err(|e| Error::State(e.to_string()))?;
        self.dir.write_file_atomic(STATE_FILE, &b, 0o644)
    }

    pub fn clear(&self) -> Result<(), Error> {
        self.dir.remove_file(STATE_FILE)
    }

    pub fn lock(&self) -> Result<LockGuard, Error> {
        self.dir.lock(LOCK_FILE)
    }

    pub fn dir(&self) -> &SecureDir {
        &self.dir
    }
}
