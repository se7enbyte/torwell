//! MAC address validation, candidate construction and restore metadata.
//!
//! This module never generates randomness. Candidates are built from bytes the caller
//! supplies, which must come from a cryptographically secure source (for example the
//! OS CSPRNG). Nothing here reads or changes an interface.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::config::{check_name, NameError};

/// A validated 48-bit unicast, non-zero MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct MacAddress([u8; 6]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacError {
    /// Not six octets in `aa:bb:..`, `aa-bb-..` or bare 12-hex-digit form.
    Format,
    Zero,
    /// Multicast bit set. Broadcast `ff:ff:ff:ff:ff:ff` is rejected here too.
    Multicast,
}

impl fmt::Display for MacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            MacError::Format => "expected 12 hex digits, optionally separated by ':' or '-'",
            MacError::Zero => "all-zero MAC address is not valid",
            MacError::Multicast => "multicast and broadcast MAC addresses are not valid",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for MacError {}

impl MacAddress {
    /// Validates raw octets: rejects all-zero and multicast (I/G bit set).
    pub fn new(octets: [u8; 6]) -> Result<Self, MacError> {
        if octets == [0; 6] {
            return Err(MacError::Zero);
        }
        if (octets[0] & 0x01) != 0 {
            return Err(MacError::Multicast);
        }
        Ok(Self(octets))
    }

    /// Parses `aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff` or `aabbccddeeff`.
    pub fn parse(text: &str) -> Result<Self, MacError> {
        if !text.is_ascii() {
            return Err(MacError::Format);
        }
        let bytes = text.as_bytes();
        let mut octets = [0u8; 6];
        match bytes.len() {
            17 => {
                for (i, octet) in octets.iter_mut().enumerate() {
                    let start = i * 3;
                    if i < 5 && !matches!(bytes[start + 2], b':' | b'-') {
                        return Err(MacError::Format);
                    }
                    *octet = hex_pair(&bytes[start..start + 2])?;
                }
            }
            12 => {
                for (i, octet) in octets.iter_mut().enumerate() {
                    *octet = hex_pair(&bytes[i * 2..i * 2 + 2])?;
                }
            }
            _ => return Err(MacError::Format),
        }
        Self::new(octets)
    }

    /// Builds a locally administered unicast candidate from six caller-supplied bytes.
    ///
    /// Sets the U/L bit and clears the I/G bit. The result is never zero or multicast.
    /// The input must be secure random bytes; this function does not make a weak source
    /// secure, and the candidate is not a secret.
    pub fn from_candidate_bytes(mut random: [u8; 6]) -> Self {
        random[0] = (random[0] | 0x02) & 0xFE;
        Self(random)
    }

    pub fn octets(&self) -> [u8; 6] {
        self.0
    }

    pub fn is_locally_administered(&self) -> bool {
        (self.0[0] & 0x02) != 0
    }
}

fn hex_pair(pair: &[u8]) -> Result<u8, MacError> {
    Ok((hex_val(pair[0])? << 4) | hex_val(pair[1])?)
}

fn hex_val(c: u8) -> Result<u8, MacError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(MacError::Format),
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let o = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            o[0], o[1], o[2], o[3], o[4], o[5]
        )
    }
}

impl TryFrom<String> for MacAddress {
    type Error = MacError;

    fn try_from(text: String) -> Result<Self, MacError> {
        Self::parse(&text)
    }
}

impl From<MacAddress> for String {
    fn from(mac: MacAddress) -> String {
        mac.to_string()
    }
}

/// The MAC policy configured on the connection profile, distinct from the address
/// currently in effect. `Absent` means no override field existed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileMac {
    Absent,
    Preserve,
    Permanent,
    Random,
    Stable,
    Explicit(MacAddress),
}

/// Metadata captured before any MAC change so the prior policy can be restored.
///
/// Restoration uses `restore_profile`, the prior profile policy. It never uses the
/// effective address, which may be a Torwell-applied candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacRestore {
    interface: String,
    prior_profile: ProfileMac,
    prior_effective: Option<MacAddress>,
}

impl MacRestore {
    pub fn new(
        interface: &str,
        prior_profile: ProfileMac,
        prior_effective: Option<MacAddress>,
    ) -> Result<Self, NameError> {
        check_name(interface)?;
        Ok(Self {
            interface: interface.to_string(),
            prior_profile,
            prior_effective,
        })
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }

    pub fn restore_profile(&self) -> &ProfileMac {
        &self.prior_profile
    }

    /// Address observed before the change, if it could be read. Used for read-back only.
    pub fn prior_effective(&self) -> Option<MacAddress> {
        self.prior_effective
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_colon_dash_and_bare_forms() {
        let expected = MacAddress::new([0x02, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]).unwrap();
        assert_eq!(MacAddress::parse("02:1a:2b:3c:4d:5e"), Ok(expected));
        assert_eq!(MacAddress::parse("02-1A-2B-3C-4D-5E"), Ok(expected));
        assert_eq!(MacAddress::parse("021a2b3c4d5e"), Ok(expected));
        assert_eq!(expected.to_string(), "02:1a:2b:3c:4d:5e");
    }

    #[test]
    fn rejects_zero_address() {
        assert_eq!(MacAddress::parse("00:00:00:00:00:00"), Err(MacError::Zero));
        assert_eq!(MacAddress::new([0; 6]), Err(MacError::Zero));
    }

    #[test]
    fn rejects_multicast_and_broadcast() {
        assert_eq!(
            MacAddress::parse("01:00:5e:00:00:01"),
            Err(MacError::Multicast)
        );
        assert_eq!(
            MacAddress::parse("ff:ff:ff:ff:ff:ff"),
            Err(MacError::Multicast)
        );
        assert_eq!(
            MacAddress::new([0x03, 0, 0, 0, 0, 1]),
            Err(MacError::Multicast)
        );
    }

    #[test]
    fn rejects_malformed_input() {
        assert_eq!(MacAddress::parse(""), Err(MacError::Format));
        assert_eq!(
            MacAddress::parse("zz:11:22:33:44:55"),
            Err(MacError::Format)
        );
        assert_eq!(MacAddress::parse("aa:bb:cc"), Err(MacError::Format));
        assert_eq!(
            MacAddress::parse("aa:bb:cc:dd:ee:ff:00"),
            Err(MacError::Format)
        );
        assert_eq!(
            MacAddress::parse("aa;bb:cc:dd:ee:ff"),
            Err(MacError::Format)
        );
        assert_eq!(
            MacAddress::parse("aa:bb:cc:dd:ee:f\u{e9}"),
            Err(MacError::Format)
        );
    }

    #[test]
    fn candidate_is_locally_administered_unicast() {
        let high = MacAddress::from_candidate_bytes([0xff; 6]);
        assert_eq!(high.octets()[0], 0xfe);
        assert!(high.is_locally_administered());

        let low = MacAddress::from_candidate_bytes([0; 6]);
        assert_eq!(low.to_string(), "02:00:00:00:00:00");
        assert!(MacAddress::new(low.octets()).is_ok());
    }

    #[test]
    fn serializes_as_string_and_round_trips() {
        let mac = MacAddress::from_candidate_bytes([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]);
        let json = serde_json::to_string(&mac).unwrap();
        // 0x12 already has the U/L bit set and the I/G bit clear, so it is unchanged.
        assert_eq!(json, "\"12:34:56:78:9a:bc\"");
        assert_eq!(serde_json::from_str::<MacAddress>(&json).unwrap(), mac);
        assert!(serde_json::from_str::<MacAddress>("\"01:00:5e:00:00:01\"").is_err());
    }

    #[test]
    fn restore_keeps_prior_profile_not_effective_address() {
        let original = MacAddress::parse("00:11:22:33:44:55").unwrap();
        let restore =
            MacRestore::new("wlan0", ProfileMac::Explicit(original), Some(original)).unwrap();

        // A candidate becomes the effective address; the recorded profile must not change.
        let candidate = MacAddress::from_candidate_bytes([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]);
        assert_ne!(candidate, original);
        assert_eq!(restore.restore_profile(), &ProfileMac::Explicit(original));
        assert_eq!(restore.prior_effective(), Some(original));
    }

    #[test]
    fn absent_profile_is_restored_as_absent() {
        let observed = MacAddress::parse("00:11:22:33:44:55").unwrap();
        let restore = MacRestore::new("eth0", ProfileMac::Absent, Some(observed)).unwrap();
        assert_eq!(restore.restore_profile(), &ProfileMac::Absent);
    }

    #[test]
    fn restore_rejects_invalid_interface_name() {
        assert!(MacRestore::new("", ProfileMac::Preserve, None).is_err());
    }
}
