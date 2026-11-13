use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Not a Windows host (or the Windows implementation is not compiled in).
    Unsupported(String),
    /// A prerequisite is missing or unverified. Nothing was changed.
    Preflight(Vec<String>),
    /// Torwell-owned state already exists; only stop/recover may proceed.
    StateExists,
    Lifecycle(String),
    Config(String),
    State(String),
    Wfp(String),
    Mac(String),
    Process(String),
    Bridge(String),
    /// Tor bootstrap did not complete; enforcement remains in place.
    Bootstrap(String),
    /// Evidence for `Connected` failed.
    Evidence(String),
    /// Torwell enforcement is active but the operation failed.
    Blocked(String),
    /// Torwell-owned state may be partly applied. Run stop/recover.
    RecoveryRequired(String),
    /// A foreign object sits where Torwell-owned state was expected; refused to touch it.
    Foreign(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Preflight(items) => write!(f, "preflight failed: {}", items.join("; ")),
            Error::StateExists => f.write_str("Torwell state exists; run stop or recover first"),
            Error::Unsupported(s)
            | Error::Lifecycle(s)
            | Error::Config(s)
            | Error::State(s)
            | Error::Wfp(s)
            | Error::Mac(s)
            | Error::Process(s)
            | Error::Bridge(s)
            | Error::Bootstrap(s)
            | Error::Evidence(s)
            | Error::Blocked(s)
            | Error::RecoveryRequired(s)
            | Error::Foreign(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
