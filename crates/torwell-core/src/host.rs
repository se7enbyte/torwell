//! Host-safe detection: OS and dependency presence only.
//!
//! Detection runs no commands, performs no network lookups (no outbound IP checks),
//! reads no secrets and changes no system state. It only checks whether a file exists
//! on the search path.

use std::path::PathBuf;

use crate::capability::{Capability, Os, Report, Support};

pub fn current_os() -> Os {
    if cfg!(target_os = "linux") {
        Os::Linux
    } else if cfg!(target_os = "windows") {
        Os::Windows
    } else {
        Os::Other
    }
}

/// True when `name` exists as a file in a PATH directory or a standard sbin directory.
/// The file is not executed.
pub fn command_on_path(name: &str) -> bool {
    let mut dirs = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect::<Vec<PathBuf>>())
        .unwrap_or_default();
    dirs.push(PathBuf::from("/usr/sbin"));
    dirs.push(PathBuf::from("/sbin"));
    dirs.iter().any(|dir| dir.join(name).is_file())
}

/// Detects the current host using the real filesystem presence check.
pub fn detect_host() -> Report {
    detect(current_os(), command_on_path)
}

/// Builds a capability report from an OS and a presence probe. Tests supply a fake probe.
pub fn detect(os: Os, has_command: impl Fn(&str) -> bool) -> Report {
    let capabilities = match os {
        Os::Linux => vec![
            presence("linux.nftables", has_command("nft"), "nft"),
            presence("linux.tor", has_command("tor"), "tor"),
            presence("linux.iproute2", has_command("ip"), "ip"),
            unknown(
                "linux.mac_adapter_change",
                "needs a per-adapter probe and explicit opt-in; not attempted by detection",
            ),
        ],
        Os::Windows => vec![
            unknown(
                "windows.runtime",
                "Windows runtime not tested; availability is not assumed",
            ),
            unknown(
                "windows.wintun",
                "signed Wintun presence is not probed by this foundation",
            ),
            unknown("windows.wfp", "WFP filter behaviour is untested"),
            unknown(
                "windows.mac_adapter_change",
                "override behaviour is driver-dependent and untested",
            ),
        ],
        Os::Other => vec![cap(
            "platform",
            Support::Unsupported,
            "outside the Linux and Windows scope",
        )],
    };
    Report { os, capabilities }
}

fn presence(name: &str, found: bool, binary: &str) -> Capability {
    if found {
        cap(
            name,
            Support::Supported,
            &format!("`{binary}` found; functionality not tested"),
        )
    } else {
        cap(name, Support::Unsupported, &format!("`{binary}` not found"))
    }
}

fn unknown(name: &str, detail: &str) -> Capability {
    cap(name, Support::Unknown, detail)
}

fn cap(name: &str, support: Support, detail: &str) -> Capability {
    Capability {
        name: name.to_string(),
        support,
        detail: detail.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_reports_presence_without_claiming_function() {
        let report = detect(Os::Linux, |cmd| cmd == "nft");

        let nft = report.get("linux.nftables").unwrap();
        assert_eq!(nft.support, Support::Supported);
        assert!(nft.detail.contains("not tested"));

        assert_eq!(
            report.get("linux.tor").unwrap().support,
            Support::Unsupported
        );
        assert_eq!(
            report.get("linux.mac_adapter_change").unwrap().support,
            Support::Unknown
        );
    }

    #[test]
    fn windows_runtime_is_unknown_not_assumed() {
        let report = detect(Os::Windows, |_| true);
        assert_eq!(
            report.get("windows.runtime").unwrap().support,
            Support::Unknown
        );
        assert_eq!(
            report.get("windows.wintun").unwrap().support,
            Support::Unknown
        );
        assert_eq!(report.get("windows.wfp").unwrap().support, Support::Unknown);
    }

    #[test]
    fn other_platforms_are_unsupported() {
        let report = detect(Os::Other, |_| true);
        assert_eq!(report.capabilities.len(), 1);
        assert_eq!(report.capabilities[0].support, Support::Unsupported);
    }
}
