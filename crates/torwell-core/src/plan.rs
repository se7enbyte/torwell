//! Inert, serializable operation plans.
//!
//! Nothing here executes. A plan describes the intended operations for a later
//! privileged executor. Steps are typed data: no shell strings, no flush-style
//! operations, and deletes only for Torwell-owned objects. Teardown only removes the
//! `torwell` table and never touches other rules.
//!
//! Ordering: record prior state, install fail-closed rules, apply MAC change (optional),
//! then start Tor, then verify. Rules exist before Tor starts, so there is no direct window.

use serde::{Deserialize, Serialize};

use crate::config::{check_name, Config, ConfigError, MacMode, NameError};
use crate::mac::{MacAddress, MacRestore, ProfileMac};

/// The only nftables table Torwell may create or delete.
pub const OWNED_TABLE: &str = "torwell";

/// Linux interface names are at most 15 bytes.
const LINUX_IFNAME_MAX: usize = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    LinuxNftables,
    WindowsWintunWfp,
}

/// Every plan produced by this crate is inert. No executor exists yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanStatus {
    PlanOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    pub platform: Platform,
    pub status: PlanStatus,
    pub caveats: Vec<String>,
    pub steps: Vec<Step>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Step {
    /// Snapshot prior Torwell-owned and profile state before any mutation.
    RecordPriorState,

    /// Set a locally administered candidate. Driver-dependent; read-back must follow.
    MacSetCandidate {
        interface: String,
        candidate: MacAddress,
    },
    VerifyMacReadback {
        interface: String,
        expected: MacAddress,
    },

    /// Create the Torwell-owned `inet` table (covers IPv4 and IPv6).
    NftCreateOwnedTable {
        table: String,
    },
    /// Accept output from the Tor process so it can reach the network directly.
    NftAcceptTorUid {
        table: String,
        uid: u32,
    },
    NftAcceptLoopback {
        table: String,
    },
    /// Redirect non-loopback TCP to Tor's TransPort (IPv4).
    NftRedirectTcp {
        table: String,
        to_port: u16,
    },
    /// Redirect UDP port 53 to Tor's DNSPort.
    NftRedirectUdpDns {
        table: String,
        to_port: u16,
    },
    /// Reject all remaining output: other UDP, ICMP and IPv6. Must come last.
    NftRejectRest {
        table: String,
    },

    /// Create the signed Wintun tunnel adapter.
    WintunCreateAdapter {
        name: String,
    },
    WintunDefaultRoute {
        name: String,
    },
    /// Userspace TCP-to-SOCKS bridge from the tunnel to Tor's SOCKS port.
    TcpSocksBridgeStart {
        socks_port: u16,
    },
    /// WFP: permit the Tor image so it can reach the real uplink.
    WfpPermitTorImage {
        image: String,
    },
    WfpPermitAdapter {
        name: String,
    },
    /// WFP: persistently block other outbound traffic; retain enforcement if the helper exits.
    WfpBlockOthers,
    /// Remove only the persistent WFP provider/sublayer/filters recorded as Torwell-owned.
    WfpDeleteOwnedPolicy,

    StartTor {
        socks_port: u16,
        dns_port: u16,
        trans_port: Option<u16>,
        run_as_uid: Option<u32>,
    },

    VerifyTorBootstrap,
    VerifyLinuxRedirects,
    VerifyLinuxDirectRejected,
    VerifyWindowsBridge,
    VerifyWindowsBlock,

    StopTor,
    StopTcpSocksBridge,
    NftDeleteOwnedTable {
        table: String,
    },
    WintunDestroyAdapter {
        name: String,
    },
    /// Restore the prior profile policy, not the effective address.
    MacRestoreProfile {
        interface: String,
        profile: ProfileMac,
    },
    VerifyMacRestore {
        interface: String,
        prior_effective: Option<MacAddress>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    Config(ConfigError),
    Name(NameError),
    /// Exempting uid 0 would let every root process bypass the policy.
    RootTorUid,
    /// MAC mode is on but the interface or candidate is missing.
    MacOptionsMissing,
    /// Candidates must be locally administered; a universal OUI is not allowed here.
    NotLocallyAdministered,
}

impl From<ConfigError> for PlanError {
    fn from(err: ConfigError) -> Self {
        PlanError::Config(err)
    }
}

impl From<NameError> for PlanError {
    fn from(err: NameError) -> Self {
        PlanError::Name(err)
    }
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlanError::Config(err) => write!(f, "invalid configuration: {err}"),
            PlanError::Name(err) => write!(f, "invalid name: {err}"),
            PlanError::RootTorUid => f.write_str("the Tor uid must not be root"),
            PlanError::MacOptionsMissing => {
                f.write_str("MAC mode needs an interface and a candidate address")
            }
            PlanError::NotLocallyAdministered => {
                f.write_str("MAC candidate must be locally administered")
            }
        }
    }
}

impl std::error::Error for PlanError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxOptions {
    /// User the Tor process runs as. Its traffic is exempted. Must not be 0.
    pub tor_uid: u32,
    /// Interface for the optional MAC change. Required when MAC mode is on.
    pub interface: Option<String>,
    /// Candidate from a caller-supplied CSPRNG. Required when MAC mode is on.
    pub mac_candidate: Option<MacAddress>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsOptions {
    /// Physical adapter for the optional MAC change. Required when MAC mode is on.
    pub physical_adapter: Option<String>,
    /// Candidate from a caller-supplied CSPRNG. Required when MAC mode is on.
    pub mac_candidate: Option<MacAddress>,
    /// Tor image path that WFP permits to reach the real uplink.
    pub tor_image: String,
    /// Name of the Wintun tunnel adapter Torwell creates.
    pub tunnel_name: String,
}

/// Linux nftables + Tor. Rule order: exemptions, then redirects, then reject.
pub fn linux_nftables_plan(config: &Config, opts: &LinuxOptions) -> Result<Plan, PlanError> {
    config.validate()?;
    if opts.tor_uid == 0 {
        return Err(PlanError::RootTorUid);
    }
    if let Some(name) = &opts.interface {
        check_name(name)?;
        if name.len() > LINUX_IFNAME_MAX {
            return Err(PlanError::Name(NameError));
        }
    }

    let table = OWNED_TABLE.to_string();
    let mut steps = vec![Step::RecordPriorState];
    steps.extend([
        Step::NftCreateOwnedTable {
            table: table.clone(),
        },
        Step::NftAcceptTorUid {
            table: table.clone(),
            uid: opts.tor_uid,
        },
        Step::NftAcceptLoopback {
            table: table.clone(),
        },
        Step::NftRedirectTcp {
            table: table.clone(),
            to_port: config.trans_port,
        },
        Step::NftRedirectUdpDns {
            table: table.clone(),
            to_port: config.dns_port,
        },
        Step::NftRejectRest { table },
    ]);
    steps.extend(mac_steps(
        config,
        opts.interface.as_deref(),
        opts.mac_candidate,
    )?);
    steps.extend([
        Step::StartTor {
            socks_port: config.socks_port,
            dns_port: config.dns_port,
            trans_port: Some(config.trans_port),
            run_as_uid: Some(opts.tor_uid),
        },
        Step::VerifyTorBootstrap,
        Step::VerifyLinuxRedirects,
        Step::VerifyLinuxDirectRejected,
    ]);

    Ok(plan(
        Platform::LinuxNftables,
        &[
            "Plan only: nothing is executed by this crate.",
            "Existing connections are not grandfathered; they must be tested.",
            "Coexistence with NetworkManager, firewalld and container rules is untested.",
            "IPv6 is rejected by policy, not because Tor cannot carry it.",
        ],
        steps,
    ))
}

/// Teardown for the Linux plan. Deletes only the Torwell-owned table.
pub fn linux_teardown_plan(restore: Option<&MacRestore>) -> Plan {
    let mut steps = restore_steps(restore);
    steps.extend([
        Step::StopTor,
        Step::NftDeleteOwnedTable {
            table: OWNED_TABLE.to_string(),
        },
    ]);
    plan(
        Platform::LinuxNftables,
        &["Deletes only the Torwell-owned table; unrelated rules are left untouched."],
        steps,
    )
}

/// Windows Wintun + TCP-SOCKS bridge + WFP. Runtime behaviour is untested.
pub fn windows_wintun_plan(config: &Config, opts: &WindowsOptions) -> Result<Plan, PlanError> {
    config.validate()?;
    check_name(&opts.tunnel_name)?;
    check_name(&opts.tor_image)?;

    let mut steps = vec![Step::RecordPriorState];
    steps.extend([
        Step::WfpPermitTorImage {
            image: opts.tor_image.clone(),
        },
        Step::WfpPermitAdapter {
            name: opts.tunnel_name.clone(),
        },
        Step::WfpBlockOthers,
    ]);
    steps.extend(mac_steps(
        config,
        opts.physical_adapter.as_deref(),
        opts.mac_candidate,
    )?);
    steps.extend([
        Step::WintunCreateAdapter {
            name: opts.tunnel_name.clone(),
        },
        Step::WintunDefaultRoute {
            name: opts.tunnel_name.clone(),
        },
        Step::TcpSocksBridgeStart {
            socks_port: config.socks_port,
        },
        Step::StartTor {
            socks_port: config.socks_port,
            dns_port: config.dns_port,
            trans_port: None,
            run_as_uid: None,
        },
        Step::VerifyTorBootstrap,
        Step::VerifyWindowsBridge,
        Step::VerifyWindowsBlock,
    ]);

    let mut caveats = vec![
        "Plan only: nothing is executed by this crate.".to_string(),
        "Windows runtime not tested; no support is claimed.".to_string(),
        "Wintun is layer 3 only; DNS handling comes from the bridge and Tor.".to_string(),
        "Executor must install persistent owned WFP policy; dynamic-session-only enforcement is insufficient."
            .to_string(),
    ];
    if config.mac == MacMode::RandomOnApply {
        caveats
            .push("Adapter MAC override is driver-dependent; read-back is required.".to_string());
    }
    Ok(Plan {
        platform: Platform::WindowsWintunWfp,
        status: PlanStatus::PlanOnly,
        caveats,
        steps,
    })
}

/// Teardown for the Windows plan. Removes only the Torwell tunnel adapter.
pub fn windows_teardown_plan(
    tunnel_name: &str,
    restore: Option<&MacRestore>,
) -> Result<Plan, PlanError> {
    check_name(tunnel_name)?;
    let mut steps = vec![
        Step::StopTor,
        Step::StopTcpSocksBridge,
        Step::WintunDestroyAdapter {
            name: tunnel_name.to_string(),
        },
    ];
    steps.extend(restore_steps(restore));
    steps.push(Step::WfpDeleteOwnedPolicy);
    Ok(plan(
        Platform::WindowsWintunWfp,
        &["Keep persistent WFP blocking until bridge, adapter and MAC teardown succeeds; then remove only owned policy."],
        steps,
    ))
}

fn mac_steps(
    config: &Config,
    interface: Option<&str>,
    candidate: Option<MacAddress>,
) -> Result<Vec<Step>, PlanError> {
    match config.mac {
        MacMode::Off => Ok(Vec::new()),
        MacMode::RandomOnApply => {
            let (Some(interface), Some(candidate)) = (interface, candidate) else {
                return Err(PlanError::MacOptionsMissing);
            };
            check_name(interface)?;
            if !candidate.is_locally_administered() {
                return Err(PlanError::NotLocallyAdministered);
            }
            Ok(vec![
                Step::MacSetCandidate {
                    interface: interface.to_string(),
                    candidate,
                },
                Step::VerifyMacReadback {
                    interface: interface.to_string(),
                    expected: candidate,
                },
            ])
        }
    }
}

fn restore_steps(restore: Option<&MacRestore>) -> Vec<Step> {
    match restore {
        None => Vec::new(),
        Some(r) => vec![
            Step::MacRestoreProfile {
                interface: r.interface().to_string(),
                profile: r.restore_profile().clone(),
            },
            Step::VerifyMacRestore {
                interface: r.interface().to_string(),
                prior_effective: r.prior_effective(),
            },
        ],
    }
}

fn plan(platform: Platform, caveats: &[&str], steps: Vec<Step>) -> Plan {
    Plan {
        platform,
        status: PlanStatus::PlanOnly,
        caveats: caveats.iter().map(|c| c.to_string()).collect(),
        steps,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate() -> MacAddress {
        MacAddress::from_candidate_bytes([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc])
    }

    fn linux_opts() -> LinuxOptions {
        LinuxOptions {
            tor_uid: 972,
            interface: None,
            mac_candidate: None,
        }
    }

    fn mac_config() -> Config {
        Config {
            mac: MacMode::RandomOnApply,
            ..Config::default()
        }
    }

    /// Table named by an nftables step, if any.
    fn table_of(step: &Step) -> Option<&str> {
        match step {
            Step::NftCreateOwnedTable { table }
            | Step::NftAcceptTorUid { table, .. }
            | Step::NftAcceptLoopback { table }
            | Step::NftRedirectTcp { table, .. }
            | Step::NftRedirectUdpDns { table, .. }
            | Step::NftRejectRest { table }
            | Step::NftDeleteOwnedTable { table } => Some(table.as_str()),
            _ => None,
        }
    }

    #[test]
    fn linux_plan_never_flushes_and_only_touches_owned_table() {
        let plan = linux_nftables_plan(&Config::default(), &linux_opts()).unwrap();
        let json = serde_json::to_string(&plan).unwrap().to_lowercase();
        assert!(!json.contains("flush"));

        let teardown = linux_teardown_plan(None);
        let json = serde_json::to_string(&teardown).unwrap().to_lowercase();
        assert!(!json.contains("flush"));

        for step in plan.steps.iter().chain(teardown.steps.iter()) {
            if let Some(table) = table_of(step) {
                assert_eq!(table, OWNED_TABLE);
            }
        }
    }

    #[test]
    fn linux_plan_records_state_first_and_rules_before_tor_start() {
        let plan = linux_nftables_plan(&Config::default(), &linux_opts()).unwrap();
        assert_eq!(plan.steps.first(), Some(&Step::RecordPriorState));

        let position = |pred: fn(&Step) -> bool| plan.steps.iter().position(pred).unwrap();
        let reject = position(|s| matches!(s, Step::NftRejectRest { .. }));
        let start = position(|s| matches!(s, Step::StartTor { .. }));
        assert!(reject < start);
        assert_eq!(plan.status, PlanStatus::PlanOnly);
    }

    #[test]
    fn linux_plan_rejects_root_tor_uid() {
        let opts = LinuxOptions {
            tor_uid: 0,
            ..linux_opts()
        };
        assert_eq!(
            linux_nftables_plan(&Config::default(), &opts),
            Err(PlanError::RootTorUid)
        );
    }

    #[test]
    fn mac_plan_needs_interface_and_candidate() {
        assert_eq!(
            linux_nftables_plan(&mac_config(), &linux_opts()),
            Err(PlanError::MacOptionsMissing)
        );

        let opts = LinuxOptions {
            interface: Some("wlan0".to_string()),
            mac_candidate: Some(candidate()),
            ..linux_opts()
        };
        let plan = linux_nftables_plan(&mac_config(), &opts).unwrap();
        assert!(plan
            .steps
            .iter()
            .any(|s| matches!(s, Step::MacSetCandidate { .. })));
        assert!(plan
            .steps
            .iter()
            .any(|s| matches!(s, Step::VerifyMacReadback { .. })));
    }

    #[test]
    fn mac_plan_rejects_universally_administered_candidate() {
        let universal = MacAddress::parse("00:1b:63:84:45:e6").unwrap();
        let opts = LinuxOptions {
            interface: Some("wlan0".to_string()),
            mac_candidate: Some(universal),
            ..linux_opts()
        };
        assert_eq!(
            linux_nftables_plan(&mac_config(), &opts),
            Err(PlanError::NotLocallyAdministered)
        );
    }

    #[test]
    fn mac_off_plan_has_no_mac_steps() {
        let opts = LinuxOptions {
            interface: Some("wlan0".to_string()),
            mac_candidate: Some(candidate()),
            ..linux_opts()
        };
        let plan = linux_nftables_plan(&Config::default(), &opts).unwrap();
        assert!(!plan
            .steps
            .iter()
            .any(|s| matches!(s, Step::MacSetCandidate { .. })));
    }

    #[test]
    fn teardown_restores_profile_not_effective_address() {
        let original = MacAddress::parse("00:11:22:33:44:55").unwrap();
        let restore = MacRestore::new("wlan0", ProfileMac::Preserve, Some(original)).unwrap();
        let plan = linux_teardown_plan(Some(&restore));

        assert!(plan.steps.contains(&Step::MacRestoreProfile {
            interface: "wlan0".to_string(),
            profile: ProfileMac::Preserve,
        }));
        assert!(plan.steps.contains(&Step::VerifyMacRestore {
            interface: "wlan0".to_string(),
            prior_effective: Some(original),
        }));
    }

    #[test]
    fn windows_plan_is_serializable_caveated_and_round_trips() {
        let opts = WindowsOptions {
            physical_adapter: None,
            mac_candidate: None,
            tor_image: r"C:\Tor\tor.exe".to_string(),
            tunnel_name: "torwell0".to_string(),
        };
        let plan = windows_wintun_plan(&Config::default(), &opts).unwrap();

        assert!(plan.caveats.iter().any(|c| c.contains("not tested")));
        assert!(plan.steps.contains(&Step::WfpBlockOthers));
        assert!(plan.steps.contains(&Step::WintunCreateAdapter {
            name: "torwell0".to_string()
        }));

        let json = serde_json::to_string(&plan).unwrap();
        assert!(json.contains("\"op\":\"wintun_create_adapter\""));
        assert!(!json.to_lowercase().contains("flush"));
        let back: Plan = serde_json::from_str(&json).unwrap();
        assert_eq!(back, plan);
    }

    #[test]
    fn windows_teardown_removes_only_named_tunnel() {
        let plan = windows_teardown_plan("torwell0", None).unwrap();
        let destroys: Vec<&Step> = plan
            .steps
            .iter()
            .filter(|s| matches!(s, Step::WintunDestroyAdapter { .. }))
            .collect();
        assert_eq!(
            destroys,
            vec![&Step::WintunDestroyAdapter {
                name: "torwell0".to_string()
            }]
        );
    }
    #[test]
    fn windows_stop_removes_persistent_policy_last() {
        let plan = windows_teardown_plan("Torwell", None).unwrap();
        assert!(matches!(
            plan.steps.last(),
            Some(Step::WfpDeleteOwnedPolicy)
        ));
        let adapter_index = plan
            .steps
            .iter()
            .position(|step| matches!(step, Step::WintunDestroyAdapter { .. }))
            .unwrap();
        assert!(adapter_index < plan.steps.len() - 1);
    }
    #[test]
    fn mac_change_follows_blocking_in_both_platform_plans() {
        let config = Config {
            mac: MacMode::RandomOnApply,
            ..Config::default()
        };
        let candidate = MacAddress::from_candidate_bytes([4, 5, 6, 7, 8, 9]);
        let linux = linux_nftables_plan(
            &config,
            &LinuxOptions {
                tor_uid: 999,
                interface: Some("eth0".into()),
                mac_candidate: Some(candidate),
            },
        )
        .unwrap();
        let windows = windows_wintun_plan(
            &config,
            &WindowsOptions {
                physical_adapter: Some("Ethernet".into()),
                mac_candidate: Some(candidate),
                tor_image: "C:\\Tor\\tor.exe".into(),
                tunnel_name: "Torwell".into(),
            },
        )
        .unwrap();
        for p in [linux, windows] {
            let block = p
                .steps
                .iter()
                .position(|s| matches!(s, Step::NftRejectRest { .. } | Step::WfpBlockOthers))
                .unwrap();
            let mac = p
                .steps
                .iter()
                .position(|s| matches!(s, Step::MacSetCandidate { .. }))
                .unwrap();
            assert!(block < mac);
        }
    }
}
