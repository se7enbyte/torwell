//! End-to-end tests against the built binary. Only non-mutating paths run: status, inspect,
//! refusals, and a mutating request that must be refused *before* anything is launched
//! (the test binary is not a root-owned install, so elevation is refused). These tests are
//! skipped for the mutating-request case if run as root.

use std::io::Write;
use std::process::{Command, Stdio};

use torwell_protocol::{decode_response, ErrorKind, Phase, Response, MAX_MESSAGE_BYTES};

const BIN: &str = env!("CARGO_BIN_EXE_torwell-engine");

fn euid() -> u32 {
    // /proc/self/status line "Uid:\treal\teffective\t..."
    let s = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = s.lines().find(|l| l.starts_with("Uid:")).unwrap();
    line.split_whitespace().nth(2).unwrap().parse().unwrap()
}

fn run(args: &[&str], stdin: &[u8]) -> (std::process::Output, Option<Response>) {
    let mut child = Command::new(BIN)
        .args(args)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut sin = child.stdin.take().unwrap();
    let data = stdin.to_vec();
    let w = std::thread::spawn(move || {
        let _ = sin.write_all(&data);
    });
    let out = child.wait_with_output().unwrap();
    let _ = w.join();
    let resp = decode_response(&out.stdout).ok();
    (out, resp)
}

#[test]
fn status_returns_one_valid_non_mutating_response() {
    let (out, resp) = run(&[], br#"{"version":1,"command":"status"}"#);
    let resp = resp
        .unwrap_or_else(|| panic!("invalid stdout: {:?}", String::from_utf8_lossy(&out.stdout)));
    match resp.result {
        Ok(state) => {
            assert_eq!(out.status.code(), Some(0));
            if euid() != 0 {
                // Unprivileged callers cannot verify anything live.
                assert!(
                    !matches!(state.phase, Phase::Connected | Phase::Blocked),
                    "{:?}",
                    state.phase
                );
            }
            assert_eq!(state.plan, None);
        }
        Err(e) => {
            assert_eq!(out.status.code(), Some(1));
            assert!(e.is_bounded());
        }
    }
}

#[test]
fn inspect_reports_reboot_capability_and_bounded_lists() {
    let (out, resp) = run(&[], br#"{"version":1,"command":"inspect"}"#);
    let state = resp
        .unwrap_or_else(|| panic!("invalid stdout: {:?}", String::from_utf8_lossy(&out.stdout)))
        .result
        .expect("inspect should succeed on a readable host");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(state.capabilities[0].name, "linux.reboot_protection");
    assert!(state
        .capabilities
        .iter()
        .any(|c| c.name == "linux.nftables"));
    assert!(state.adapters.iter().all(|a| a.name != "lo"));
    // Discovery alone never claims a working MAC change.
    assert!(state
        .adapters
        .iter()
        .all(|a| a.mac_change != torwell_protocol::Support::Supported));
}

#[test]
fn plan_is_inert_text() {
    let (_, resp) = run(
        &[],
        br#"{"version":1,"command":"plan","config":{"mac":"off","socks_port":9050,"trans_port":9040,"dns_port":5353},"adapter":null}"#,
    );
    let state = resp.unwrap().result.unwrap();
    let plan = state.plan.unwrap();
    assert!(plan[0].starts_with("Plan only"));
    assert!(!matches!(state.phase, Phase::Connected | Phase::Blocked));
}

#[test]
fn bad_requests_are_refused_with_error_responses() {
    let big = vec![b' '; MAX_MESSAGE_BYTES + 1];
    let cases: Vec<(&[u8], ErrorKind)> = vec![
        (b"", ErrorKind::InvalidRequest),
        (b"garbage", ErrorKind::InvalidRequest),
        (
            br#"{"version":1,"command":"rm"}"#,
            ErrorKind::InvalidRequest,
        ),
        (
            br#"{"version":1,"command":"status","argv":["/bin/sh"]}"#,
            ErrorKind::InvalidRequest,
        ),
        (
            br#"{"version":9,"command":"status"}"#,
            ErrorKind::UnsupportedVersion,
        ),
        (&big, ErrorKind::MessageTooLarge),
    ];
    for (input, kind) in cases {
        let (out, resp) = run(&[], input);
        assert_eq!(out.status.code(), Some(1));
        assert_eq!(resp.unwrap().result.unwrap_err().kind, kind);
    }
}

#[test]
fn mutating_request_from_an_untrusted_binary_is_refused_without_launching_pkexec() {
    use std::os::unix::fs::MetadataExt;
    let owner = std::fs::metadata(BIN).unwrap().uid();
    if euid() == 0 || owner == 0 {
        eprintln!("skipped: running as root or the binary is root-owned");
        return;
    }
    for cmd in [
        &br#"{"version":1,"command":"stop"}"#[..],
        br#"{"version":1,"command":"recover"}"#,
        br#"{"version":1,"command":"start","config":{"mac":"off","socks_port":9050,"trans_port":9040,"dns_port":5353},"adapter":null}"#,
    ] {
        let (out, resp) = run(&[], cmd);
        assert_eq!(out.status.code(), Some(1));
        let e = resp.unwrap().result.unwrap_err();
        assert_eq!(e.kind, ErrorKind::PermissionDenied);
        assert!(e.message.contains("Install torwell-engine"), "{}", e.message);
    }
}

#[test]
fn no_escalate_child_refuses_when_not_root() {
    if euid() == 0 {
        return;
    }
    let (out, resp) = run(&["--no-escalate"], br#"{"version":1,"command":"stop"}"#);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        resp.unwrap().result.unwrap_err().kind,
        ErrorKind::PermissionDenied
    );
}

#[test]
fn subcommands_are_root_only_and_unknown_args_are_usage_errors() {
    let (out, _) = run(&["frobnicate"], b"");
    assert_eq!(out.status.code(), Some(2));
    if euid() != 0 {
        let (out, _) = run(&["restore-at-boot"], b"");
        assert_eq!(out.status.code(), Some(2));
        let (out, _) = run(&["boot-protection", "enable"], b"");
        assert_eq!(out.status.code(), Some(2));
        let (out, _) = run(&["boot-protection", "disable"], b"");
        assert_eq!(out.status.code(), Some(2));
    }
    let (out, _) = run(&["boot-protection", "status"], b"");
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("reboot-protection: "));
}
