//! TCP-to-SOCKS bridge: the upstream tun2proxy binary (MIT, Rust, documented Windows support via
//! Wintun) supervised as a child process. Torwell implements no packet bridge itself. Flags are
//! version-dependent across tun2proxy releases, so preflight requires the exact flag set in
//! the pinned binary's `--help`.

use std::ffi::OsString;
use std::path::PathBuf;

pub const REQUIRED_FLAGS: [&str; 4] = ["--setup", "--proxy", "--tun", "--dns"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeSpec {
    pub exe: PathBuf,
    pub tunnel_name: String,
    pub socks_port: u16,
}

/// `--dns virtual` answers DNS inside the tunnel and maps names to virtual addresses resolved
/// by Tor at connect time, so no DNS query leaves via a resolver. `--setup` lets tun2proxy
/// install its routes; the tunnel (and thus Wintun) is created by the bridge process.
pub fn bridge_args(s: &BridgeSpec) -> Vec<OsString> {
    [
        "--setup",
        "--proxy",
        &format!("socks5://127.0.0.1:{}", s.socks_port),
        "--tun",
        &s.tunnel_name,
        "--dns",
        "virtual",
    ]
    .iter()
    .map(OsString::from)
    .collect()
}

/// Names of required flags absent from `--help` output.
pub fn missing_flags(help: &str) -> Vec<&'static str> {
    REQUIRED_FLAGS
        .iter()
        .copied()
        .filter(|f| !help.contains(f))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_are_a_vector_with_loopback_socks() {
        let a = bridge_args(&BridgeSpec {
            exe: "x".into(),
            tunnel_name: "Torwell Tun".into(),
            socks_port: 9050,
        });
        assert_eq!(a[2], OsString::from("socks5://127.0.0.1:9050"));
        assert!(a.contains(&OsString::from("Torwell Tun")));
        assert!(a.contains(&OsString::from("virtual")));
    }

    #[test]
    fn missing_flags_reported() {
        assert!(missing_flags("--setup --proxy --tun --dns").is_empty());
        assert_eq!(missing_flags("--proxy --tun"), vec!["--setup", "--dns"]);
    }
}
