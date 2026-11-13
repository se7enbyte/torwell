//! Shared typed configuration. The traffic policy itself is fixed, not configurable:
//! UDP other than DNS, ICMP and IPv6 are always rejected by plans.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Whether a MAC change is requested. Defaults to `Off`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacMode {
    /// Leave the MAC address alone.
    #[default]
    Off,
    /// Opt-in: apply a locally administered unicast candidate and verify read-back.
    RandomOnApply,
}

/// Loopback ports Tor listens on. All three must be non-zero and distinct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub mac: MacMode,
    pub socks_port: u16,
    pub trans_port: u16,
    pub dns_port: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mac: MacMode::Off,
            socks_port: 9050,
            trans_port: 9040,
            dns_port: 5353,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<(), ConfigError> {
        let ports = [self.socks_port, self.trans_port, self.dns_port];
        if ports.contains(&0) {
            return Err(ConfigError::ZeroPort);
        }
        for (i, port) in ports.iter().enumerate() {
            if ports[i + 1..].contains(port) {
                return Err(ConfigError::DuplicatePort);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    ZeroPort,
    DuplicatePort,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::ZeroPort => f.write_str("port 0 is not allowed"),
            ConfigError::DuplicatePort => f.write_str("Tor ports must be distinct"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// A name (interface or adapter) that may appear in a typed plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NameError;

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("name must be 1-64 characters without control characters")
    }
}

impl std::error::Error for NameError {}

/// Rejects empty, overlong or control-character names. This is a sanity check on
/// typed data, not shell escaping: plans never reach a shell.
pub fn check_name(name: &str) -> Result<(), NameError> {
    let ok = !name.is_empty() && name.chars().count() <= 64 && !name.chars().any(char::is_control);
    if ok {
        Ok(())
    } else {
        Err(NameError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid_and_mac_off() {
        let config = Config::default();
        assert_eq!(config.validate(), Ok(()));
        assert_eq!(config.mac, MacMode::Off);
    }

    #[test]
    fn zero_and_duplicate_ports_are_rejected() {
        let zero = Config {
            socks_port: 0,
            ..Config::default()
        };
        assert_eq!(zero.validate(), Err(ConfigError::ZeroPort));

        let dup = Config {
            dns_port: 9050,
            ..Config::default()
        };
        assert_eq!(dup.validate(), Err(ConfigError::DuplicatePort));
    }

    #[test]
    fn config_round_trips_through_json() {
        let config = Config {
            mac: MacMode::RandomOnApply,
            ..Config::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"random_on_apply\""));
        let back: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn names_reject_empty_control_and_overlong() {
        assert!(check_name("wlan0").is_ok());
        assert!(check_name("Wi-Fi").is_ok());
        assert_eq!(check_name(""), Err(NameError));
        assert_eq!(check_name("eth\n0"), Err(NameError));
        assert_eq!(check_name(&"a".repeat(65)), Err(NameError));
    }
}
