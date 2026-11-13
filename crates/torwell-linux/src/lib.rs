//! Linux backend for torwell: nftables transparent-proxy enforcement around a dedicated,
//! systemd-managed Tor service, with root-owned durable state and an optional
//! NetworkManager MAC change.
//!
//! Mutating entry points (`Backend::start/stop/recover/switch_identity`) require euid 0.
//! All commands go through the injectable [`Runner`]; nothing here uses a shell.
//! See `docs/LINUX.md`.

pub mod env;
pub mod error;
pub mod exec;
pub mod fsx;
pub mod mac;
pub mod rules;
pub mod runner;
pub mod state;
pub mod tor;

pub use env::{Env, SystemEnv, UserInfo};
pub use error::{Error, OpFailure};
pub use exec::{
    Backend, Binaries, BootRestore, LiveStatus, MacApplied, Paths, PreflightItem, PreflightReport,
    RebootProtection, StartOptions, StartOutcome, Status, StopOptions, StopOutcome, SwitchOutcome,
    RESTORE_UNIT,
};
pub use runner::{Cmd, Output, Runner, SystemRunner};

impl Backend<SystemRunner, SystemEnv> {
    /// Production wiring: real processes, real host, default system paths.
    pub fn system() -> Self {
        Backend::new(SystemRunner, SystemEnv::new(), Paths::default())
    }
}
