//! Packet-level kernel policy test. Runs `tests/netns/kernel_policy.py` inside a disposable
//! `unshare -Urn` user+network namespace; the script refuses to run in the host namespace.
//! Skips (passes with a note) when unprivileged namespaces, python3, nft or ip are missing.
//! No Tor runs here: this proves what the kernel does with the ruleset, not anonymity.

use std::path::Path;
use std::process::Command;

use torwell_linux::rules::{ruleset, RuleParams};

const UNMAPPED_TOR_UID: u32 = 12345; // nothing in the namespace runs as this uid

fn tools_ok() -> bool {
    let ok = |prog: &str, args: &[&str]| {
        Command::new(prog)
            .args(args)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    };
    ok("unshare", &["-Urn", "true"]) && ok("python3", &["-V"]) && ok("nft", &["-v"])
}

fn run(script: &str) -> (bool, String) {
    let dir = std::env::temp_dir().join(format!("torwell-kp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join(format!("rules-{}.nft", script.len()));
    std::fs::write(&file, script).unwrap();
    let host_ns = std::fs::read_link("/proc/self/ns/net").unwrap();
    let py = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/netns/kernel_policy.py");
    let out = Command::new("unshare")
        .args(["-Urn", "python3", "-I"])
        .arg(&py)
        .arg(&host_ns)
        .arg(&file)
        .args(["9040", "5353"])
        .output()
        .unwrap();
    let _ = std::fs::remove_file(&file);
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn params() -> RuleParams<'static> {
    RuleParams {
        token: "00112233445566778899aabbccddeeff",
        tor_uid: UNMAPPED_TOR_UID,
        trans_port: 9040,
        dns_port: 5353,
    }
}

#[test]
fn ruleset_redirects_tcp_and_dns_and_blocks_everything_else_with_real_packets() {
    if !tools_ok() {
        eprintln!("SKIPPED: unshare -Urn, python3 or nft unavailable");
        return;
    }
    let (ok, out) = run(&ruleset(&params()));
    println!("{out}");
    assert!(ok, "kernel policy checks failed:\n{out}");
    for check in [
        "\"tcp_redirected_to_transport\": true",
        "\"tcp_original_dst_seen_by_listener\": true",
        "\"udp53_redirected_to_dnsport\": true",
        "\"arbitrary_udp_v4_blocked\": true",
        "\"ipv6_tcp_udp_dns_blocked\": true",
        "\"preexisting_flow_blocked_after_enforcement\": true",
        "\"vm_traffic_was_forwarded_before_enforcement\": true",
        "\"vm_traffic_blocked_after_enforcement\": true",
    ] {
        assert!(out.contains(check), "missing {check}:\n{out}");
    }
}

/// Negative control: without the redirected-flow accepts the filter chain rejects every
/// redirected connection, because the output hook keeps the pre-NAT oif. The harness must
/// notice that, or its passing result above would mean nothing.
#[test]
fn harness_detects_a_ruleset_that_rejects_redirected_flows() {
    if !tools_ok() {
        eprintln!("SKIPPED: unshare -Urn, python3 or nft unavailable");
        return;
    }
    let broken: String = ruleset(&params())
        .lines()
        .filter(|l| !l.contains(":f-trans\"") && !l.contains(":f-dns\""))
        .map(|l| format!("{l}\n"))
        .collect();
    let (ok, out) = run(&broken);
    assert!(!ok, "harness passed a broken ruleset:\n{out}");
}

/// Negative control for the forward chain: the output-only ruleset (before the VM/container
/// fix) must fail the harness, proving the VM check can see a real bypass.
#[test]
fn harness_detects_vm_traffic_bypassing_an_output_only_ruleset() {
    if !tools_ok() {
        eprintln!("SKIPPED: unshare -Urn, python3 or nft unavailable");
        return;
    }
    let output_only: String = ruleset(&params())
        .lines()
        .filter(|l| !l.contains("filter_forward"))
        .map(|l| format!("{l}\n"))
        .collect();
    let (ok, out) = run(&output_only);
    assert!(!ok, "harness passed an output-only ruleset:\n{out}");
    assert!(
        out.contains("\"vm_traffic_blocked_after_enforcement\": false"),
        "{out}"
    );
}
