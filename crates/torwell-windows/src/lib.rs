//! Windows backend for torwell.
//!
//! Everything except [`win`] is portable and driven through injectable traits
//! ([`wfp::WfpApi`], [`exec::CommandRunner`], [`proc::ProcessLauncher`], [`state::StateStore`],
//! ...) so ordering, ownership and recovery are tested on any host. [`win`] holds the only
//! raw Win32 calls and exists only on `cfg(windows)`. On other targets
//! [`backend::WindowsBackend::system`] returns [`error::Error::Unsupported`].
//!
//! No Windows runtime support is claimed: the Windows-only code type-checks for
//! `x86_64-pc-windows-gnu` (`cargo check --target`) but has never run on Windows.

pub mod adapter;
pub mod backend;
pub mod bridge;
pub mod clock;
pub mod error;
pub mod exec;
pub mod ids;
pub mod mac;
pub mod policy;
pub mod preflight;
pub mod proc;
pub mod sddl;
pub mod sha256;
pub mod state;
pub mod tor;
pub mod verify;
pub mod wfp;

#[cfg(windows)]
pub mod win;

#[cfg(test)]
mod backend_tests;
#[cfg(test)]
mod testutil;

pub use backend::{RecoverMode, StartRequest, StatusReport, WindowsBackend};
pub use error::Error;
