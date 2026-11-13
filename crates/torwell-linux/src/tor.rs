//! Tor config rendering and control-protocol parsing. No I/O here.

use std::path::Path;

use torwell_core::Config;

use crate::error::Error;

pub const MARKER: &str = "# Managed by torwell-linux";
const TORRC: &str = include_str!("../assets/torrc.template");
const UNIT: &str = include_str!("../assets/torwell-tor.service");
pub const SYSUSERS: &str = include_str!("../assets/torwell-tor.sysusers.conf");
pub const SERVICE_USER: &str = "torwell-tor";
pub const UNIT_NAME: &str = "torwell-tor.service";

pub fn render_torrc(c: &Config, runtime_dir: &Path) -> String {
    TORRC
        .replace("@SOCKS_PORT@", &c.socks_port.to_string())
        .replace("@TRANS_PORT@", &c.trans_port.to_string())
        .replace("@DNS_PORT@", &c.dns_port.to_string())
        .replace("@RUNTIME_DIR@", &runtime_dir.display().to_string())
}

pub fn render_unit(tor: &Path, torrc: &Path) -> String {
    UNIT.replace("@TOR@", &tor.display().to_string())
        .replace("@TORRC@", &torrc.display().to_string())
}

/// A service identity is acceptable only if it is a system account: not root, below the
/// human UID range, with no login shell.
pub fn check_service_identity(uid: u32, shell: &str) -> Result<(), Error> {
    if uid == 0 || uid >= 1000 {
        return Err(Error::Config(format!(
            "{SERVICE_USER} has uid {uid}; need a system uid in 1..=999"
        )));
    }
    if !(shell.ends_with("/nologin") || shell.ends_with("/false")) {
        return Err(Error::Config(format!(
            "{SERVICE_USER} has login shell {shell}"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub code: u16,
    pub lines: Vec<String>,
}

/// Parses control replies: `250 text`, `250-text` (continued), `250+text` (data block
/// terminated by a lone `.`). Rejects malformed lines.
pub fn parse_replies(text: &str) -> Result<Vec<Reply>, Error> {
    let bad = |m: &str| Error::Tor(format!("malformed control reply: {m}"));
    let mut out = Vec::new();
    let mut cur: Option<Reply> = None;
    let mut in_data = false;
    for raw in text.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if line.is_empty() {
            continue;
        }
        if in_data {
            if line == "." {
                in_data = false;
            } else if let Some(r) = cur.as_mut() {
                r.lines
                    .push(line.strip_prefix('.').unwrap_or(line).to_string());
            }
            continue;
        }
        if line.len() < 4 || !line.is_char_boundary(3) || !line.is_char_boundary(4) {
            return Err(bad(line));
        }
        let code: u16 = line[..3].parse().map_err(|_| bad(line))?;
        let sep = line.as_bytes()[3];
        let body = line[4..].to_string();
        let r = cur.get_or_insert(Reply {
            code,
            lines: Vec::new(),
        });
        if r.code != code {
            return Err(bad("status code changed inside one reply"));
        }
        r.lines.push(body);
        match sep {
            b' ' => out.push(cur.take().unwrap()),
            b'-' => {}
            b'+' => in_data = true,
            _ => return Err(bad(line)),
        }
    }
    if cur.is_some() || in_data {
        return Err(bad("truncated reply"));
    }
    Ok(out)
}

pub fn authenticate_command(cookie: &[u8; 32]) -> String {
    let mut s = String::from("AUTHENTICATE ");
    for b in cookie {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Builds one pipelined request: AUTHENTICATE, the commands, QUIT.
pub fn build_request(cookie: &[u8; 32], commands: &[&str]) -> String {
    let mut s = authenticate_command(cookie);
    s.push_str("\r\n");
    for c in commands {
        s.push_str(c);
        s.push_str("\r\n");
    }
    s.push_str("QUIT\r\n");
    s
}

/// Checks replies for a pipelined request and returns the replies to `commands`.
/// Authentication failure or any non-250 reply is an error that never contains the cookie.
pub fn check_replies(replies: &[Reply], commands: usize) -> Result<&[Reply], Error> {
    let auth = replies
        .first()
        .ok_or_else(|| Error::Tor("no reply to AUTHENTICATE".into()))?;
    if auth.code != 250 {
        return Err(Error::Tor(format!(
            "control authentication rejected ({})",
            auth.code
        )));
    }
    let rest = replies.get(1..).unwrap_or(&[]);
    if rest.len() < commands {
        return Err(Error::Tor("missing control replies".into()));
    }
    for r in &rest[..commands] {
        if r.code != 250 {
            return Err(Error::Tor(format!(
                "control command failed: {} {}",
                r.code,
                r.lines.join(" ")
            )));
        }
    }
    Ok(&rest[..commands])
}

/// Value of `key=` in a GETINFO reply.
pub fn getinfo_value(reply: &Reply, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    reply
        .lines
        .iter()
        .find_map(|l| l.strip_prefix(&prefix))
        .map(str::to_string)
}

/// `NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"` -> (100, "done").
pub fn parse_bootstrap(value: &str) -> Result<(u8, String), Error> {
    let field = |name: &str| value.split_whitespace().find_map(|t| t.strip_prefix(name));
    let progress: u8 = field("PROGRESS=")
        .and_then(|p| p.parse().ok())
        .ok_or_else(|| Error::Tor(format!("no PROGRESS in bootstrap phase {value:?}")))?;
    let tag = field("TAG=").unwrap_or("").to_string();
    Ok((progress, tag))
}

pub fn bootstrap_done(value: &str) -> Result<bool, Error> {
    let (p, tag) = parse_bootstrap(value)?;
    Ok(p == 100 && tag == "done")
}

/// `net/listeners/*` value: space-separated quoted addresses. True only for exactly one
/// listener equal to `127.0.0.1:port`.
pub fn sole_loopback_listener(value: &str, port: u16) -> bool {
    let v: Vec<&str> = value.split_whitespace().collect();
    v.len() == 1 && v[0].trim_matches('"') == format!("127.0.0.1:{port}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: the unit once had `Requires=torwell-restore.service`, so every start failed
    /// with "Unit torwell-restore.service not found" unless boot protection was enabled.
    #[test]
    fn tor_unit_does_not_require_the_optional_restore_unit() {
        let u = render_unit(Path::new("/usr/bin/tor"), Path::new("/etc/torwell/torrc"));
        assert!(!u.contains("Requires="), "{u}");
        assert!(!u.contains("BindsTo=") && !u.contains("Requisite="), "{u}");
        assert!(u.contains("User=torwell-tor") && !u.contains('@'), "{u}");
    }

    #[test]
    fn torrc_binds_loopback_only_with_cookie_control_socket() {
        let c = Config::default();
        let t = render_torrc(&c, Path::new("/run/torwell-tor"));
        assert!(t.contains("SocksPort 127.0.0.1:9050"));
        assert!(t.contains("TransPort 127.0.0.1:9040"));
        assert!(t.contains("DNSPort 127.0.0.1:5353"));
        assert!(t.contains("ControlSocket /run/torwell-tor/control"));
        assert!(t.contains("CookieAuthentication 1"));
        assert!(!t.contains("ControlPort") && !t.contains("0.0.0.0") && !t.contains('@'));
        assert!(t.starts_with(MARKER));
    }

    #[test]
    fn unit_runs_as_dedicated_user_never_root_and_is_not_installed_enabled() {
        let u = render_unit(Path::new("/usr/bin/tor"), Path::new("/etc/torwell/torrc"));
        assert!(u.contains("User=torwell-tor") && !u.contains("User=root"));
        assert!(u.contains("ExecStart=/usr/bin/tor --quiet -f /etc/torwell/torrc"));
        assert!(!u.contains("[Install]") && !u.contains("WantedBy"));
        assert!(u.contains("NoNewPrivileges=yes") && !u.contains('@'));
        assert!(u.starts_with(MARKER));
        assert!(SYSUSERS.starts_with(MARKER));
    }

    #[test]
    fn identity_rejects_root_human_uid_and_login_shell() {
        assert!(check_service_identity(0, "/usr/bin/nologin").is_err());
        assert!(check_service_identity(1000, "/usr/bin/nologin").is_err());
        assert!(check_service_identity(970, "/bin/bash").is_err());
        assert!(check_service_identity(970, "/usr/bin/nologin").is_ok());
    }

    #[test]
    fn parses_multiline_and_data_replies() {
        let text = "250 OK\r\n250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n250 OK\r\n250+x=\r\nline\r\n..dot\r\n.\r\n250 OK\r\n250 closing connection\r\n";
        let r = parse_replies(text).unwrap();
        assert_eq!(r.len(), 4);
        assert_eq!(r[1].lines.len(), 2);
        assert_eq!(r[2].lines, vec!["x=", "line", ".dot", "OK"]);
        let v = getinfo_value(&r[1], "status/bootstrap-phase").unwrap();
        assert_eq!(parse_bootstrap(&v).unwrap(), (100, "done".to_string()));
        assert_eq!(bootstrap_done(&v), Ok(true));
    }

    #[test]
    fn rejects_malformed_and_truncated_replies() {
        assert!(parse_replies("25").is_err());
        assert!(parse_replies("abc OK\r\n").is_err());
        assert!(parse_replies("250-only continuation\r\n").is_err());
        assert!(parse_replies("250-a\r\n251 b\r\n").is_err());
        assert!(parse_replies("250+x=\r\nno terminator\r\n").is_err());
        assert!(parse_replies("250?x\r\n").is_err());
        assert!(parse_replies("250 é\u{e9}\r\n").is_ok());
    }

    #[test]
    fn partial_bootstrap_is_not_done() {
        assert_eq!(
            bootstrap_done("NOTICE BOOTSTRAP PROGRESS=80 TAG=ap_conn SUMMARY=\"x\""),
            Ok(false)
        );
        assert_eq!(
            bootstrap_done("NOTICE BOOTSTRAP PROGRESS=100 TAG=odd"),
            Ok(false)
        );
        assert!(bootstrap_done("garbage").is_err());
    }

    #[test]
    fn auth_failure_is_an_error_without_cookie_material() {
        let cookie = [0xabu8; 32];
        let req = build_request(&cookie, &["SIGNAL NEWNYM"]);
        assert!(req.starts_with("AUTHENTICATE abab") && req.ends_with("QUIT\r\n"));
        let replies = parse_replies("515 Authentication failed\r\n").unwrap();
        let e = check_replies(&replies, 1).unwrap_err().to_string();
        assert!(e.contains("515") && !e.contains("abab"));
        let ok = parse_replies("250 OK\r\n552 Unrecognized signal\r\n").unwrap();
        assert!(check_replies(&ok, 1).is_err());
        let ok = parse_replies("250 OK\r\n250 OK\r\n250 closing\r\n").unwrap();
        assert_eq!(check_replies(&ok, 1).unwrap().len(), 1);
        assert!(check_replies(&parse_replies("250 OK\r\n").unwrap(), 1).is_err());
    }

    #[test]
    fn listener_must_be_the_single_loopback_address() {
        assert!(sole_loopback_listener("\"127.0.0.1:9040\"", 9040));
        assert!(!sole_loopback_listener("\"0.0.0.0:9040\"", 9040));
        assert!(!sole_loopback_listener(
            "\"127.0.0.1:9040\" \"192.168.0.2:9040\"",
            9040
        ));
        assert!(!sole_loopback_listener("", 9040));
        assert!(!sole_loopback_listener("\"127.0.0.1:9041\"", 9040));
    }
}
