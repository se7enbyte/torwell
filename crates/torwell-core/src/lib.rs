//! Platform-neutral core for torwell: typed configuration, explicit capability states,
//! MAC validation and restore metadata, a lifecycle state machine, and inert plans.
//!
//! This crate changes no firewall, DNS, routing or MAC state, starts no process and runs
//! no command. Plans describe intended operations for a later privileged executor.

pub mod capability;
pub mod config;
pub mod host;
pub mod lifecycle;
pub mod mac;
pub mod plan;

pub use capability::{Capability, Os, Report, Support};
pub use config::{Config, MacMode};
pub use host::{detect, detect_host};
pub use lifecycle::{Check, Evidence, Fault, Lifecycle, State, TransitionError};
pub use mac::{MacAddress, MacError, MacRestore, ProfileMac};
pub use plan::{LinuxOptions, Plan, PlanError, Platform, Step, WindowsOptions};
