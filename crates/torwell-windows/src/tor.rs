//! Tor argument construction and bootstrap evidence. Bootstrap is observed from Tor's own log
//! (`Bootstrapped 100%`), never assumed from the process merely running.

use std::ffi::OsString;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

use crate::clock::Clock;
use crate::error::{Error, Result};
use crate::proc::{LineEvent, ManagedProcess};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorSpec {
    pub exe: PathBuf,
    pub data_dir: PathBuf,
    pub socks_port: u16,
    /// Physical uplink address Tor binds outbound sockets to (route-loop avoidance, see docs).
    pub bind_addr: Ipv4Addr,
}

/// Command-line options only: no torrc is read (`--ignore-missing-torrc`), so no ambient config
/// can widen listeners. SOCKS listens on loopback only; IPv6 is disabled by policy.
pub fn tor_args(s: &TorSpec) -> Vec<OsString> {
    let mut a: Vec<OsString> = Vec::new();
    let mut opt = |k: &str, v: String| {
        a.push(format!("--{k}").into());
        a.push(v.into());
    };
    opt("SocksPort", format!("127.0.0.1:{}", s.socks_port));
    opt("DataDirectory", s.data_dir.display().to_string());
    opt("OutboundBindAddress", s.bind_addr.to_string());
    opt("ClientUseIPv6", "0".into());
    opt("ClientOnly", "1".into());
    opt("SafeLogging", "1".into());
    opt("Log", "notice stdout".into());
    opt("RunAsDaemon", "0".into());
    a.push("--ignore-missing-torrc".into());
    a
}

/// Extracts the percentage from a Tor `Bootstrapped N%` notice.
pub fn parse_bootstrap(line: &str) -> Option<u8> {
    let i = line.find("Bootstrapped ")? + "Bootstrapped ".len();
    let rest = &line[i..];
    let end = rest.find('%')?;
    rest[..end].trim().parse().ok().filter(|p| *p <= 100)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapEvidence {
    pub percent: u8,
}

pub fn wait_bootstrap(
    p: &mut dyn ManagedProcess,
    clock: &dyn Clock,
    timeout: Duration,
) -> Result<BootstrapEvidence> {
    let start = clock.now();
    let mut best = 0u8;
    loop {
        let elapsed = clock.now().saturating_sub(start);
        if elapsed >= timeout {
            return Err(Error::Bootstrap(format!(
                "timed out after {timeout:?} at {best}%"
            )));
        }
        if let Some(code) = p.try_wait() {
            return Err(Error::Bootstrap(format!(
                "tor exited with code {code} at {best}%"
            )));
        }
        let wait = (timeout - elapsed).min(Duration::from_secs(1));
        match p.recv_line(wait) {
            LineEvent::Line(l) => {
                if let Some(pc) = parse_bootstrap(&l) {
                    best = best.max(pc);
                    if pc == 100 {
                        return Ok(BootstrapEvidence { percent: 100 });
                    }
                }
            }
            LineEvent::Idle => {}
            LineEvent::Closed => {
                return Err(Error::Bootstrap(format!("tor output closed at {best}%")))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{FakeClock, FakeProc};

    #[test]
    fn parses_bootstrap_lines() {
        assert_eq!(
            parse_bootstrap("Nov 13 [notice] Bootstrapped 100% (done): Done"),
            Some(100)
        );
        assert_eq!(
            parse_bootstrap("[notice] Bootstrapped 45% (loading_descriptors): x"),
            Some(45)
        );
        assert_eq!(parse_bootstrap("Bootstrapped 250%"), None);
        assert_eq!(parse_bootstrap("Bootstrap complete"), None);
    }

    #[test]
    fn args_pin_loopback_socks_no_ipv6_and_bind_address() {
        let s = TorSpec {
            exe: "tor.exe".into(),
            data_dir: r"C:\ProgramData\Torwell\tor".into(),
            socks_port: 9050,
            bind_addr: "192.168.1.5".parse().unwrap(),
        };
        let a: Vec<String> = tor_args(&s)
            .iter()
            .map(|x| x.to_string_lossy().into_owned())
            .collect();
        let joined = a.join(" ");
        assert!(joined.contains("--SocksPort 127.0.0.1:9050"));
        assert!(joined.contains("--ClientUseIPv6 0"));
        assert!(joined.contains("--OutboundBindAddress 192.168.1.5"));
        assert!(joined.contains("--ignore-missing-torrc"));
        assert!(!joined.contains("0.0.0.0"));
    }

    #[test]
    fn bootstrap_succeeds_only_on_100_percent() {
        let clock = FakeClock::default();
        let mut p = FakeProc::new(
            &clock,
            &[
                "Bootstrapped 5%",
                "Bootstrapped 80% (x)",
                "Bootstrapped 100% (done)",
            ],
        );
        assert_eq!(
            wait_bootstrap(&mut p, &clock, Duration::from_secs(60))
                .unwrap()
                .percent,
            100
        );
    }

    #[test]
    fn bootstrap_times_out_without_evidence() {
        let clock = FakeClock::default();
        let mut p = FakeProc::new(&clock, &["Bootstrapped 80% (x)"]);
        let e = wait_bootstrap(&mut p, &clock, Duration::from_secs(30)).unwrap_err();
        assert!(matches!(&e, Error::Bootstrap(m) if m.contains("timed out") && m.contains("80%")));
    }

    #[test]
    fn process_exit_is_reported_not_treated_as_success() {
        let clock = FakeClock::default();
        let mut p = FakeProc::new(&clock, &["Bootstrapped 10%"]);
        p.exit_after_lines = Some(3);
        assert!(
            matches!(wait_bootstrap(&mut p, &clock, Duration::from_secs(30)), Err(Error::Bootstrap(m)) if m.contains("exited"))
        );
    }
}
