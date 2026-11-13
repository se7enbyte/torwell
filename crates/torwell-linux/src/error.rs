//! Error and failure types. A failed mutating operation reports the resulting core
//! `State`, so callers can tell "nothing changed" from "still blocking" from "recover".

use std::fmt;

use torwell_core::State;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Mutations need effective uid 0.
    NotRoot,
    /// Dependency preflight failed; the strings are the failing items.
    Preflight(Vec<String>),
    /// Invalid caller options or configuration.
    Config(String),
    /// Another torwell operation holds the lock.
    Locked,
    /// A path failed ownership, mode, symlink or file-type checks.
    UnsafePath(String),
    /// An nft table named `torwell` exists that this state does not own.
    ForeignTable,
    /// A file or table is not recorded as torwell-owned; it was left untouched.
    NotOwned(String),
    /// The operation is not allowed in the current persisted state.
    WrongState(String),
    /// An external command failed, timed out, or printed something unexpected.
    Command {
        what: String,
        detail: String,
    },
    /// Tor did not meet a verification (bootstrap, listeners, control reply...).
    Tor(String),
    /// Enforcement verification failed.
    Enforcement(String),
    /// MAC change failed. `rolled_back` tells whether the prior policy was verified restored.
    Mac {
        detail: String,
        rolled_back: bool,
    },
    Io(String),
    State(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotRoot => f.write_str("root (euid 0) is required"),
            Error::Preflight(items) => write!(f, "preflight failed: {}", items.join("; ")),
            Error::Config(m) => write!(f, "invalid options: {m}"),
            Error::Locked => f.write_str("another torwell operation holds the lock"),
            Error::UnsafePath(m) => write!(f, "unsafe path: {m}"),
            Error::ForeignTable => {
                f.write_str("nft table `inet torwell` exists but is not owned by this state")
            }
            Error::NotOwned(m) => write!(f, "refusing to touch non-owned object: {m}"),
            Error::WrongState(m) => write!(f, "wrong state: {m}"),
            Error::Command { what, detail } => write!(f, "{what} failed: {detail}"),
            Error::Tor(m) => write!(f, "tor: {m}"),
            Error::Enforcement(m) => write!(f, "enforcement: {m}"),
            Error::Mac {
                detail,
                rolled_back,
            } => {
                write!(f, "mac: {detail} (rolled back: {rolled_back})")
            }
            Error::Io(m) => write!(f, "io: {m}"),
            Error::State(m) => write!(f, "state: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

/// A failed mutating operation plus the state it left behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpFailure {
    pub error: Error,
    /// `Idle` means nothing was changed. `Blocked` means verified blocking enforcement
    /// remains. `RecoveryRequired` means unverified owned state remains.
    pub state: State,
}

impl fmt::Display for OpFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (state: {:?})", self.error, self.state)
    }
}

impl std::error::Error for OpFailure {}
