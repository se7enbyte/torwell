//! `Ops` backed by the real Linux backend.

use std::path::Path;
use std::time::{Duration, Instant};

use torwell_core::Support;
use torwell_linux::mac::check_interface;
use torwell_linux::{
    Backend, BootRestore, Env, Error, LiveStatus, OpFailure, RebootProtection, Runner,
    StartOptions, StartOutcome, Status, StopOptions, StopOutcome, SwitchOutcome, SystemEnv,
    SystemRunner,
};
use torwell_protocol::{AdapterInfo, Capability, MAX_LIST_ITEMS};

use crate::ops::{Host, Ops};
use crate::reply::clean;

const CMD_TIMEOUT: Duration = Duration::from_secs(30);
const INSPECT_CMD_TIMEOUT: Duration = Duration::from_secs(4);
/// `inspect` must answer inside the UI's 10 s limit; stop probing adapters after this.
const INSPECT_BUDGET: Duration = Duration::from_secs(5);

pub struct LinuxOps<R: Runner, E: Env> {
    backend: Backend<R, E>,
    net_dir: std::path::PathBuf,
}

impl LinuxOps<SystemRunner, SystemEnv> {
    pub fn system() -> Self {
        Self::new(Backend::system())
    }
}

impl<R: Runner, E: Env> LinuxOps<R, E> {
    pub fn new(backend: Backend<R, E>) -> Self {
        Self {
            backend,
            net_dir: "/sys/class/net".into(),
        }
    }

    pub fn with_net_dir(mut self, dir: impl Into<std::path::PathBuf>) -> Self {
        self.net_dir = dir.into();
        self
    }
}

/// Interface names from `net_dir`, sorted, without loopback or names the backend refuses.
pub fn list_interfaces(net_dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(net_dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| n != "lo" && check_interface(n).is_ok())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

fn capability(name: String, support: Support, detail: &str) -> Capability {
    Capability {
        name: clean(&name, 64),
        support,
        detail: clean(detail, 200),
    }
}

impl<R: Runner, E: Env> Ops for LinuxOps<R, E> {
    fn euid(&self) -> u32 {
        unsafe { libc::geteuid() }
    }

    fn host(&mut self) -> Host {
        let started = Instant::now();
        let mut capabilities: Vec<Capability> = torwell_core::detect_host()
            .capabilities
            .into_iter()
            .map(|c| capability(c.name, c.support, &c.detail))
            .collect();
        let report = self.backend.preflight(false);
        for item in report.items {
            let name = format!("linux.preflight.{}", item.name.replace(' ', "_"));
            let support = if item.ok {
                Support::Supported
            } else {
                Support::Unsupported
            };
            capabilities.push(capability(name, support, &item.detail));
        }
        let mut adapters = Vec::new();
        for name in list_interfaces(&self.net_dir)
            .into_iter()
            .take(MAX_LIST_ITEMS)
        {
            let mac_change = if started.elapsed() > INSPECT_BUDGET {
                Support::Unknown
            } else {
                // Read-only NetworkManager discovery. The backend never reports `Supported`
                // from discovery alone.
                self.backend
                    .mac_capability(&name, INSPECT_CMD_TIMEOUT)
                    .support
            };
            adapters.push(AdapterInfo { name, mac_change });
        }
        Host {
            capabilities,
            adapters,
        }
    }

    fn status(&mut self) -> Result<Status, Error> {
        self.backend.status()
    }

    fn inspect_live(&mut self) -> Result<LiveStatus, Error> {
        self.backend.inspect_live(CMD_TIMEOUT)
    }

    fn reboot_protection(&self) -> RebootProtection {
        self.backend.reboot_protection()
    }

    fn start(&mut self, options: &StartOptions) -> Result<StartOutcome, OpFailure> {
        self.backend.start(options)
    }

    fn stop(&mut self) -> Result<StopOutcome, OpFailure> {
        self.backend.stop(&StopOptions::default())
    }

    fn recover(&mut self) -> Result<StopOutcome, OpFailure> {
        self.backend.recover(&StopOptions::default())
    }

    fn switch_identity(&mut self) -> Result<SwitchOutcome, OpFailure> {
        self.backend.switch_identity(CMD_TIMEOUT)
    }

    fn restore_at_boot(&mut self) -> Result<BootRestore, Error> {
        self.backend.restore_at_boot(CMD_TIMEOUT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_listing_skips_loopback_and_bad_names_and_is_sorted() {
        let dir = std::env::temp_dir().join(format!("torwell-engine-net-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for n in ["wlan0", "lo", "eth0", "bad name", "-x"] {
            std::fs::write(dir.join(n), b"").unwrap();
        }
        assert_eq!(list_interfaces(&dir), vec!["eth0", "wlan0"]);
        assert!(list_interfaces(&dir.join("missing")).is_empty());
    }
}
