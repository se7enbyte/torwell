//! Stable Torwell-owned WFP identities. Objects are found and removed by these keys, never by
//! enumerating and guessing, so recovery after a crash touches only what Torwell created.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    pub const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        Self {
            data1,
            data2,
            data3,
            data4,
        }
    }
}

impl std::fmt::Display for Guid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let d = self.data4;
        write!(
            f,
            "{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
            self.data1, self.data2, self.data3, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
        )
    }
}

pub const PROVIDER_KEY: Guid = Guid::new(
    0x7e3b_a1c0,
    0x4d2f,
    0x4e8a,
    [0x9b, 0x61, 0x5c, 0x0a, 0x77, 0x31, 0xd4, 0x01],
);
pub const SUBLAYER_KEY: Guid = Guid::new(
    0x7e3b_a1c0,
    0x4d2f,
    0x4e8a,
    [0x9b, 0x61, 0x5c, 0x0a, 0x77, 0x31, 0xd4, 0x02],
);
pub const PROVIDER_NAME: &str = "Torwell provider";
pub const SUBLAYER_NAME: &str = "Torwell sublayer";
/// Highest-precedence sublayer weight so other sublayers' permits cannot override our block
/// (a block in any sublayer wins over permits elsewhere; ours is also evaluated first).
pub const SUBLAYER_WEIGHT: u16 = 0xFFFF;

/// Every filter Torwell may create. Numbers are part of the persisted identity: never reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum FilterId {
    BlockAllV4 = 1,
    BlockAllV6 = 2,
    PermitLoopbackV4 = 3,
    PermitLoopbackV6 = 4,
    PermitTorV4 = 5,
    PermitTunnelTcpV4 = 6,
    PermitTunnelDnsV4 = 7,
}

pub const ALL_FILTERS: [FilterId; 7] = [
    FilterId::BlockAllV4,
    FilterId::BlockAllV6,
    FilterId::PermitLoopbackV4,
    FilterId::PermitLoopbackV6,
    FilterId::PermitTorV4,
    FilterId::PermitTunnelTcpV4,
    FilterId::PermitTunnelDnsV4,
];

impl FilterId {
    pub fn key(self) -> Guid {
        Guid::new(
            0x7e3b_a1c0,
            0x4d2f,
            0x4e8a,
            [0x9b, 0x61, 0x5c, 0x0a, 0x77, 0x31, 0xd5, self as u8],
        )
    }
    pub fn from_key(key: &Guid) -> Option<FilterId> {
        ALL_FILTERS.iter().copied().find(|f| f.key() == *key)
    }
    pub fn name(self) -> String {
        format!("Torwell filter {}", self as u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_unique_and_round_trip() {
        let mut keys: Vec<Guid> = ALL_FILTERS.iter().map(|f| f.key()).collect();
        keys.push(PROVIDER_KEY);
        keys.push(SUBLAYER_KEY);
        let n = keys.len();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), n);
        for f in ALL_FILTERS {
            assert_eq!(FilterId::from_key(&f.key()), Some(f));
        }
        assert_eq!(FilterId::from_key(&PROVIDER_KEY), None);
    }

    #[test]
    fn guid_display() {
        assert_eq!(
            PROVIDER_KEY.to_string(),
            "{7e3ba1c0-4d2f-4e8a-9b61-5c0a7731d401}"
        );
    }
}
