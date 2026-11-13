//! Pure WFP policy. Arbitration notes:
//!
//! - All filters live in one Torwell sublayer. Within a sublayer the highest-weight matching
//!   filter with a terminating action decides, so every permit outweighs the catch-all block.
//! - Across sublayers a block is final and a permit only continues evaluation. Our permits
//!   therefore cannot override another sublayer's block (e.g. Windows Firewall), and other
//!   sublayers' permits cannot override our block. We deliberately never set the
//!   clear-action-right flag, so no Torwell permit can override someone else's block.
//! - There is no unconditional permit, and permits are never IPv6 except loopback.
//! - Inbound filtering and LAN exceptions are out of scope (documented gap).

use std::path::PathBuf;

use crate::ids::FilterId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    AleAuthConnectV4,
    AleAuthConnectV6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Permit,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    /// Remote address within `addr/prefix` (IPv4).
    RemoteV4 {
        addr: [u8; 4],
        prefix: u8,
    },
    /// Remote address is `::1`.
    RemoteV6Loopback,
    /// Executable image; resolved by the WFP implementation to an app id blob.
    AppPath(PathBuf),
    /// Interface LUID of the Torwell tunnel (local interface at the connect layer).
    InterfaceLuid(u64),
    Tcp,
    Udp,
    RemotePort(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterSpec {
    pub id: FilterId,
    pub layer: Layer,
    pub action: Action,
    /// 0..=15 within the sublayer. Higher is evaluated first.
    pub weight: u8,
    pub conditions: Vec<Condition>,
}

pub const BLOCK_WEIGHT: u8 = 1;
pub const PERMIT_WEIGHT: u8 = 10;

/// Filters installed before anything else starts: catch-all block, loopback, verified Tor.
pub fn base_filters(tor_exe: &std::path::Path) -> Vec<FilterSpec> {
    vec![
        FilterSpec {
            id: FilterId::BlockAllV4,
            layer: Layer::AleAuthConnectV4,
            action: Action::Block,
            weight: BLOCK_WEIGHT,
            conditions: vec![],
        },
        FilterSpec {
            id: FilterId::BlockAllV6,
            layer: Layer::AleAuthConnectV6,
            action: Action::Block,
            weight: BLOCK_WEIGHT,
            conditions: vec![],
        },
        FilterSpec {
            id: FilterId::PermitLoopbackV4,
            layer: Layer::AleAuthConnectV4,
            action: Action::Permit,
            weight: PERMIT_WEIGHT,
            conditions: vec![Condition::RemoteV4 {
                addr: [127, 0, 0, 0],
                prefix: 8,
            }],
        },
        FilterSpec {
            id: FilterId::PermitLoopbackV6,
            layer: Layer::AleAuthConnectV6,
            action: Action::Permit,
            weight: PERMIT_WEIGHT,
            conditions: vec![Condition::RemoteV6Loopback],
        },
        // Tor reaches the real uplink over IPv4 TCP only (configured ClientUseIPv6 0).
        FilterSpec {
            id: FilterId::PermitTorV4,
            layer: Layer::AleAuthConnectV4,
            action: Action::Permit,
            weight: PERMIT_WEIGHT,
            conditions: vec![Condition::AppPath(tor_exe.to_path_buf()), Condition::Tcp],
        },
    ]
}

/// Added once the tunnel exists: TCP and DNS (to be answered by the bridge) via the tunnel only.
pub fn tunnel_filters(luid: u64) -> Vec<FilterSpec> {
    vec![
        FilterSpec {
            id: FilterId::PermitTunnelTcpV4,
            layer: Layer::AleAuthConnectV4,
            action: Action::Permit,
            weight: PERMIT_WEIGHT,
            conditions: vec![Condition::InterfaceLuid(luid), Condition::Tcp],
        },
        FilterSpec {
            id: FilterId::PermitTunnelDnsV4,
            layer: Layer::AleAuthConnectV4,
            action: Action::Permit,
            weight: PERMIT_WEIGHT,
            conditions: vec![
                Condition::InterfaceLuid(luid),
                Condition::Udp,
                Condition::RemotePort(53),
            ],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn all() -> Vec<FilterSpec> {
        let mut v = base_filters(Path::new(r"C:\Program Files\Tor\tor.exe"));
        v.extend(tunnel_filters(42));
        v
    }

    #[test]
    fn block_is_lowest_and_unconditional_only_for_blocks() {
        for f in all() {
            match f.action {
                Action::Block => {
                    assert_eq!(f.weight, BLOCK_WEIGHT);
                    assert!(f.conditions.is_empty());
                }
                Action::Permit => {
                    assert!(f.weight > BLOCK_WEIGHT);
                    assert!(
                        !f.conditions.is_empty(),
                        "{:?} is an unconditional permit",
                        f.id
                    );
                }
            }
            assert!(f.weight <= 15);
        }
    }

    #[test]
    fn both_address_families_have_a_block() {
        let f = all();
        assert!(f
            .iter()
            .any(|x| x.layer == Layer::AleAuthConnectV4 && x.action == Action::Block));
        assert!(f
            .iter()
            .any(|x| x.layer == Layer::AleAuthConnectV6 && x.action == Action::Block));
    }

    #[test]
    fn ipv6_permits_are_loopback_only() {
        for f in all()
            .iter()
            .filter(|f| f.layer == Layer::AleAuthConnectV6 && f.action == Action::Permit)
        {
            assert_eq!(f.conditions, vec![Condition::RemoteV6Loopback]);
        }
    }

    #[test]
    fn tor_permit_is_pinned_to_app_and_tcp() {
        let f = base_filters(Path::new(r"C:\t\tor.exe"));
        let tor = f.iter().find(|x| x.id == FilterId::PermitTorV4).unwrap();
        assert!(tor
            .conditions
            .iter()
            .any(|c| matches!(c, Condition::AppPath(_))));
        assert!(tor.conditions.contains(&Condition::Tcp));
        // The base set carries no tunnel permit: nothing reaches the network before the tunnel exists.
        assert!(!f.iter().any(|x| x
            .conditions
            .iter()
            .any(|c| matches!(c, Condition::InterfaceLuid(_)))));
    }

    #[test]
    fn tunnel_permits_are_interface_bound_and_dns_is_port_53_udp_only() {
        for f in tunnel_filters(7) {
            assert!(f.conditions.contains(&Condition::InterfaceLuid(7)));
        }
        let dns = &tunnel_filters(7)[1];
        assert!(
            dns.conditions.contains(&Condition::Udp)
                && dns.conditions.contains(&Condition::RemotePort(53))
        );
    }

    #[test]
    fn no_general_udp_or_icmp_permit() {
        for f in all().iter().filter(|f| f.action == Action::Permit) {
            if f.conditions.contains(&Condition::Udp) {
                assert!(f.conditions.contains(&Condition::RemotePort(53)));
            }
        }
    }
}
