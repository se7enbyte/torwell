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
/// Total time for one adapter's read-only NetworkManager probe (three `nmcli` calls, each
/// limited to a third of this).
const INSPECT_CMD_TIMEOUT: Duration = Duration::from_secs(3);
/// `inspect` must answer inside the UI's 10 s limit; stop probing adapters after this, so
/// the worst case is this plus one adapter probe, well under the limit.
const INSPECT_BUDGET: Duration = Duration::from_secs(5);

pub struct LinuxOps<R: Runner, E: Env> {
    backend: Backend<R, E>,
    net_dir: std::path::PathBuf,
    route_file: std::path::PathBuf,
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
            route_file: "/proc/net/route".into(),
        }
    }

    pub fn with_route_file(mut self, file: impl Into<std::path::PathBuf>) -> Self {
        self.route_file = file.into();
        self
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

/// The interface carrying the IPv4 default route (lowest metric), from `/proc/net/route`.
pub fn default_route_interface(route_file: &Path) -> Option<String> {
    let text = std::fs::read_to_string(route_file).ok()?;
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            // Iface Destination Gateway Flags RefCnt Use Metric Mask ...
            let flags = u32::from_str_radix(f.get(3)?, 16).ok()?;
            let metric: u32 = f.get(6)?.parse().ok()?;
            let is_default = *f.get(1)? == "00000000" && *f.get(7)? == "00000000";
            // RTF_UP (1) and RTF_GATEWAY (2).
            (is_default && flags & 3 == 3).then(|| (metric, f[0].to_string()))
        })
        .min()
        .map(|(_, iface)| iface)
}

/// Why `name` is a virtual device according to sysfs (its link resolves under
/// `devices/virtual`), if it is.
fn sysfs_virtual(net_dir: &Path, name: &str) -> bool {
    std::fs::canonicalize(net_dir.join(name))
        .map(|p| p.components().any(|c| c.as_os_str() == "virtual"))
        .unwrap_or(false)
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
        // The default-route adapter first: the UI offers the first supported adapter.
        let mut names = list_interfaces(&self.net_dir);
        if let Some(i) = default_route_interface(&self.route_file)
            .and_then(|d| names.iter().position(|n| *n == d))
        {
            let d = names.remove(i);
            names.insert(0, d);
        }
        let mut adapters = Vec::new();
        for name in names.into_iter().take(MAX_LIST_ITEMS) {
            let cap = if started.elapsed() > INSPECT_BUDGET {
                torwell_core::Capability {
                    name: String::new(),
                    support: Support::Unknown,
                    detail: "not probed: inspect time budget used up".into(),
                }
            } else if sysfs_virtual(&self.net_dir, &name) {
                torwell_core::Capability {
                    name: String::new(),
                    support: Support::Unsupported,
                    detail: format!("{name} is a virtual device; only physical ethernet and wifi adapters are supported"),
                }
            } else {
                // Read-only NetworkManager discovery (managed, ethernet/wifi, active
                // profile). The post-apply read-back is still the real proof.
                self.backend.mac_capability(&name, INSPECT_CMD_TIMEOUT)
            };
            // The reason is reported next to the verdict, e.g. why an adapter is unsupported.
            capabilities.push(capability(
                format!("linux.mac.{name}"),
                cap.support,
                &cap.detail,
            ));
            adapters.push(AdapterInfo {
                name,
                mac_change: cap.support,
            });
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
    fn default_route_is_the_lowest_metric_default_gateway_entry() {
        let f = std::env::temp_dir().join(format!("torwell-route-{}", std::process::id()));
        std::fs::write(
            &f,
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
             wlan0\t00000000\t0100A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
             enp1\t00000000\t0107A8C0\t0003\t0\t0\t20100\t00000000\t0\t0\t0\n\
             eth9\t0007A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n",
        )
        .unwrap();
        assert_eq!(default_route_interface(&f).as_deref(), Some("wlan0"));
        std::fs::write(&f, "Iface\tDestination\n").unwrap();
        assert_eq!(default_route_interface(&f), None);
        assert_eq!(default_route_interface(&f.with_extension("missing")), None);
    }

    #[test]
    fn virtual_devices_are_recognised_from_the_sysfs_link() {
        let root = std::env::temp_dir().join(format!("torwell-sysfs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let net = root.join("class/net");
        std::fs::create_dir_all(&net).unwrap();
        std::fs::create_dir_all(root.join("devices/virtual/net/virbr0")).unwrap();
        std::fs::create_dir_all(root.join("devices/pci0000:00/net/enp1")).unwrap();
        std::os::unix::fs::symlink("../../devices/virtual/net/virbr0", net.join("virbr0")).unwrap();
        std::os::unix::fs::symlink("../../devices/pci0000:00/net/enp1", net.join("enp1")).unwrap();
        assert!(sysfs_virtual(&net, "virbr0"));
        assert!(!sysfs_virtual(&net, "enp1"));
        assert!(!sysfs_virtual(&net, "missing"));
    }

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
