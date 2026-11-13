//! The seam between the dispatcher and the platform backend. `LinuxOps` wires it to
//! `torwell_linux::Backend`; tests supply fakes.

use torwell_linux::{
    BootRestore, Error, LiveStatus, OpFailure, RebootProtection, StartOptions, StartOutcome,
    Status, StopOutcome, SwitchOutcome,
};
use torwell_protocol::{AdapterInfo, Capability};

/// Read-only host facts for `inspect`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Host {
    pub capabilities: Vec<Capability>,
    pub adapters: Vec<AdapterInfo>,
}

pub trait Ops {
    /// Effective uid of this process.
    fn euid(&self) -> u32;
    /// Non-mutating capability and adapter discovery.
    fn host(&mut self) -> Host;
    /// Persisted state only.
    fn status(&mut self) -> Result<Status, Error>;
    /// Root-only live evidence (enforcement read-back, Tor bootstrap).
    fn inspect_live(&mut self) -> Result<LiveStatus, Error>;
    fn reboot_protection(&self) -> RebootProtection;
    fn start(&mut self, options: &StartOptions) -> Result<StartOutcome, OpFailure>;
    fn stop(&mut self) -> Result<StopOutcome, OpFailure>;
    fn recover(&mut self) -> Result<StopOutcome, OpFailure>;
    fn switch_identity(&mut self) -> Result<SwitchOutcome, OpFailure>;
    fn restore_at_boot(&mut self) -> Result<BootRestore, Error>;
}
