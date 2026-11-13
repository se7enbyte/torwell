//! Executor tests against a simulated host. Nothing here touches the real firewall,
//! services, network or MAC: commands go to a fake runner, the filesystem part uses a
//! private temp directory owned by the test user.

use std::cell::RefCell;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

use torwell_core::{Check, Config, MacMode, State};
use torwell_linux::*;

// ---------- simulated host ----------

#[derive(Default)]
struct Sim {
    log: Vec<String>,
    stdin_log: Vec<String>,
    /// Simulated `inet torwell` table: the token of its rules (None = absent).
    table_token: Option<String>,
    foreign_table: bool,
    tamper_policy: bool,
    unit_active: bool,
    fail: Vec<(&'static str, i32)>,
    bootstrap: u8,
    listeners_ok: bool,
    newnym_reply: &'static str,
    control_calls: Vec<String>,
    // NetworkManager
    nm_type: &'static str,
    nm_profile: String,
    nm_effective: String,
    nm_break_readback: bool,
    nm_fail_restore: bool,
}

type Shared = Rc<RefCell<Sim>>;

struct FakeRunner(Shared);
struct FakeEnv {
    sim: Shared,
    euid: u32,
    clock: Duration,
}

fn ok(stdout: &str) -> io::Result<Output> {
    Ok(Output {
        code: Some(0),
        stdout: stdout.into(),
        stderr: String::new(),
    })
}
fn exit(code: i32, stdout: &str, stderr: &str) -> io::Result<Output> {
    Ok(Output {
        code: Some(code),
        stdout: stdout.into(),
        stderr: stderr.into(),
    })
}

/// The real `nft -j list table inet torwell` output captured from nftables 1.1.7 in a
/// disposable `unshare -Urn` namespace, re-keyed to this test's token and Tor uid.
fn listing(token: &str, tamper: bool) -> String {
    const REAL: &str = include_str!("fixtures/nft-1.1.7-list-table.json");
    assert_eq!(REAL.matches("\"right\": 987").count(), 2, "fixture uid");
    let s = REAL
        .replace("00112233445566778899aabbccddeeff", token)
        .replace("\"right\": 987", "\"right\": 970");
    if tamper {
        s.replace("\"policy\": \"drop\"", "\"policy\": \"accept\"")
    } else {
        s
    }
}

impl Runner for FakeRunner {
    fn run(&mut self, cmd: &Cmd) -> io::Result<Output> {
        assert!(
            cmd.program.is_absolute(),
            "relative program {:?}",
            cmd.program
        );
        let mut s = self.0.borrow_mut();
        let name = cmd
            .program
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let args = cmd.args.join(" ");
        let line = format!("{name} {args}");
        s.log.push(line.clone());
        if let Some(i) = &cmd.stdin {
            s.stdin_log.push(String::from_utf8_lossy(i).into_owned());
        }
        let failing = s
            .fail
            .iter()
            .find(|(k, _)| line.contains(k))
            .map(|(_, c)| *c);
        if let Some(code) = failing {
            return exit(code, "", "simulated failure");
        }
        match (name.as_str(), args.as_str()) {
            ("nft", "--version") => ok("nftables v1.1.7 (Commodore Bullmoose #8)\n"),
            ("tor", "--version") => ok("Tor version 0.4.8.12.\nTor is running on Linux.\n"),
            ("nft", "-j list tables") => {
                let mut v = vec![serde_json::json!({"metainfo": {}})];
                if s.table_token.is_some() || s.foreign_table {
                    v.push(
                        serde_json::json!({"table": {"family":"inet","name":"torwell","handle":9}}),
                    );
                }
                ok(&serde_json::json!({"nftables": v}).to_string())
            }
            ("nft", "-c -f -") => ok(""),
            ("nft", "-f -") => {
                let script = cmd
                    .stdin
                    .clone()
                    .map(|b| String::from_utf8(b).unwrap())
                    .unwrap_or_default();
                if script.starts_with("delete table inet torwell") {
                    s.table_token = None;
                } else {
                    let t = script
                        .split("torwell:")
                        .nth(1)
                        .unwrap()
                        .split(':')
                        .next()
                        .unwrap()
                        .to_string();
                    s.table_token = Some(t);
                }
                ok("")
            }
            ("nft", "-j list table inet torwell") => match s.table_token.clone() {
                Some(t) => ok(&listing(&t, s.tamper_policy)),
                None => exit(1, "", "No such file or directory"),
            },
            ("systemd-sysusers", _) | ("systemctl", "daemon-reload") => ok(""),
            ("systemctl", "start torwell-tor.service") => {
                s.unit_active = true;
                ok("")
            }
            ("systemctl", "stop torwell-tor.service") => {
                s.unit_active = false;
                ok("")
            }
            ("systemctl", "is-active torwell-tor.service") => {
                if s.unit_active {
                    ok("active\n")
                } else {
                    exit(3, "inactive\n", "")
                }
            }
            ("nmcli", a) => nm(&mut s, a),
            other => panic!("unexpected command {other:?}"),
        }
    }
}

fn nm(s: &mut Sim, a: &str) -> io::Result<Output> {
    if a == "-t -g RUNNING general" {
        return ok("running\n");
    }
    if a.starts_with("-t -g GENERAL.TYPE,GENERAL.STATE,GENERAL.CON-UUID device show") {
        return ok(&format!(
            "{}\n100 (connected)\n11111111-2222-3333-4444-555555555555\n",
            s.nm_type
        ));
    }
    if a.starts_with("-t -g 802-3-ethernet.cloned-mac-address connection show") {
        return ok(&format!("{}\n", s.nm_profile.replace(':', "\\:")));
    }
    if a.starts_with("-t -g GENERAL.HWADDR device show") {
        return ok(&format!("{}\n", s.nm_effective.replace(':', "\\:")));
    }
    if let Some(rest) = a.strip_prefix("connection modify --temporary uuid 11111111-2222-3333-4444-555555555555 802-3-ethernet.cloned-mac-address") {
        let v = rest.strip_prefix(' ').unwrap_or("").to_string();
        if s.nm_fail_restore && v != s.nm_profile && !v.contains(':') {
            return exit(1, "", "restore refused");
        }
        s.nm_profile = v;
        return ok("");
    }
    if a.starts_with("connection up uuid 11111111-2222-3333-4444-555555555555 ifname") {
        if !s.nm_break_readback && s.nm_profile.contains(':') {
            s.nm_effective = s.nm_profile.clone();
        }
        return ok("");
    }
    panic!("unexpected nmcli {a}")
}

impl Env for FakeEnv {
    fn euid(&self) -> u32 {
        self.euid
    }
    fn lookup_user(&self, name: &str) -> Result<Option<UserInfo>, Error> {
        Ok((name == "torwell-tor").then(|| UserInfo {
            uid: 970,
            gid: 970,
            home: "/var/lib/torwell-tor".into(),
            shell: "/usr/bin/nologin".into(),
        }))
    }
    fn random_bytes(&mut self, out: &mut [u8]) -> Result<(), Error> {
        for (i, b) in out.iter_mut().enumerate() {
            *b = 0x10 + i as u8;
        }
        Ok(())
    }
    fn now(&self) -> Duration {
        self.clock
    }
    fn sleep(&mut self, d: Duration) {
        self.clock += d;
    }
    fn read_cookie(&mut self, _p: &Path, owner: u32) -> Result<[u8; 32], Error> {
        assert_eq!(owner, 970, "cookie must be owned by the tor identity");
        Ok([7u8; 32])
    }
    fn control_exchange(
        &mut self,
        socket: &Path,
        owner: u32,
        request: &[u8],
        _t: Duration,
    ) -> Result<String, Error> {
        assert_eq!(owner, 970);
        assert!(socket.ends_with("control"));
        let req = String::from_utf8(request.to_vec()).unwrap();
        let mut s = self.sim.borrow_mut();
        let cmds: Vec<&str> = req.split("\r\n").filter(|l| !l.is_empty()).collect();
        assert!(cmds[0].starts_with("AUTHENTICATE "));
        assert_eq!(*cmds.last().unwrap(), "QUIT");
        let mut out = String::from("250 OK\r\n");
        for c in &cmds[1..cmds.len() - 1] {
            s.control_calls.push(c.to_string());
            match *c {
                "GETINFO status/bootstrap-phase" => out += &format!("250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS={} TAG={} SUMMARY=\"x\"\r\n250 OK\r\n", s.bootstrap, if s.bootstrap == 100 { "done" } else { "loading" }),
                "GETINFO net/listeners/socks" => out += "250-net/listeners/socks=\"127.0.0.1:9050\"\r\n250 OK\r\n",
                "GETINFO net/listeners/trans" => out += &format!("250-net/listeners/trans=\"{}:9040\"\r\n250 OK\r\n", if s.listeners_ok { "127.0.0.1" } else { "0.0.0.0" }),
                "GETINFO net/listeners/dns" => out += "250-net/listeners/dns=\"127.0.0.1:5353\"\r\n250 OK\r\n",
                "GETINFO process/pid" => out += "250-process/pid=4242\r\n250 OK\r\n",
                "SIGNAL NEWNYM" => out += &format!("{}\r\n", s.newnym_reply),
                other => panic!("unexpected control command {other}"),
            }
        }
        out += "250 closing connection\r\n";
        Ok(out)
    }
    fn process_uids(&self, pid: u32) -> Result<[u32; 4], Error> {
        assert_eq!(pid, 4242);
        Ok([970; 4])
    }
}

// ---------- fixture ----------

struct Fx {
    sim: Shared,
    root: PathBuf,
    paths: Paths,
}

fn uid() -> u32 {
    unsafe { libc::geteuid() }
}

fn fixture(name: &str) -> Fx {
    let root =
        std::env::temp_dir().join(format!("torwell-linux-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
    let bin = root.join("bin");
    std::fs::create_dir(&bin).unwrap();
    let mut b = Binaries::default();
    for (slot, n) in [
        (&mut b.nft, "nft"),
        (&mut b.tor, "tor"),
        (&mut b.systemctl, "systemctl"),
        (&mut b.sysusers, "systemd-sysusers"),
        (&mut b.nmcli, "nmcli"),
    ] {
        let p = bin.join(n);
        std::fs::write(&p, "#!/bin/false\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        *slot = p;
    }
    let marker = root.join("systemd");
    std::fs::create_dir(&marker).unwrap();
    let paths = Paths {
        state_dir: root.join("state"),
        config_dir: root.join("etc-torwell"),
        unit_dir: root.join("units"),
        sysusers_dir: root.join("sysusers"),
        runtime_dir: root.join("run"),
        systemd_marker: marker,
        binaries: b,
        trusted_owner: uid(),
    };
    let sim = Rc::new(RefCell::new(Sim {
        bootstrap: 100,
        listeners_ok: true,
        newnym_reply: "250 OK",
        nm_type: "ethernet",
        nm_effective: "00:11:22:33:44:55".into(),
        ..Sim::default()
    }));
    Fx { sim, root, paths }
}

impl Fx {
    fn backend(&self) -> Backend<FakeRunner, FakeEnv> {
        self.backend_as(0)
    }
    fn backend_as(&self, euid: u32) -> Backend<FakeRunner, FakeEnv> {
        Backend::new(
            FakeRunner(self.sim.clone()),
            FakeEnv {
                sim: self.sim.clone(),
                euid,
                clock: Duration::ZERO,
            },
            self.paths.clone(),
        )
    }
    fn log(&self) -> Vec<String> {
        self.sim.borrow().log.clone()
    }
    fn pos(&self, needle: &str) -> usize {
        self.log()
            .iter()
            .position(|l| l.contains(needle))
            .unwrap_or_else(|| panic!("{needle} not run; log: {:#?}", self.log()))
    }
    fn ran(&self, needle: &str) -> bool {
        self.log().iter().any(|l| l.contains(needle))
    }
    fn state_file(&self) -> PathBuf {
        self.paths.state_dir.join("state.json")
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn opts() -> StartOptions {
    let mut o = StartOptions::new(Config::default());
    o.bootstrap_timeout = Duration::from_secs(5);
    o
}

fn mac_opts() -> StartOptions {
    let mut o = opts();
    o.config.mac = MacMode::RandomOnApply;
    o.mac_interface = Some("eth0".into());
    o
}

// ---------- tests ----------

#[test]
fn start_orders_mutations_and_reports_connected_only_with_evidence() {
    let fx = fixture("happy");
    let out = fx.backend().start(&opts()).unwrap();
    assert_eq!(out.state, State::Connected);
    assert_eq!(out.evidence.tor_bootstrap, Check::Passed);
    assert_eq!(out.evidence.enforcement, Check::Passed);
    assert_eq!(out.evidence.mac_readback, Check::NotRun);
    assert_eq!(out.tor_uid, 970);
    // Blocking table is applied before Tor starts; check precedes apply.
    assert!(fx.pos("systemd-sysusers") < fx.pos("nft -c -f -"));
    assert!(fx.pos("nft -c -f -") < fx.pos("nft -f -"));
    assert!(fx.pos("nft -f -") < fx.pos("systemctl start"));
    assert!(!fx.ran("nmcli"), "MAC off must not touch NetworkManager");
    for s in &fx.sim.borrow().stdin_log {
        assert!(!s.contains("flush") && !s.contains("delete"), "{s}");
    }
    assert_eq!(fx.backend().status().unwrap().state, State::Starting);
    // Rendered assets exist and are marked as managed.
    let torrc = std::fs::read_to_string(fx.paths.config_dir.join("torrc")).unwrap();
    assert!(
        torrc.starts_with("# Managed by torwell-linux")
            && torrc.contains("TransPort 127.0.0.1:9040")
    );
}

#[test]
fn every_mutating_entry_point_refuses_non_root_without_running_anything() {
    let fx = fixture("nonroot");
    let mut b = fx.backend_as(1000);
    assert_eq!(b.start(&opts()).unwrap_err().error, Error::NotRoot);
    assert_eq!(
        b.stop(&StopOptions::default()).unwrap_err().error,
        Error::NotRoot
    );
    assert_eq!(
        b.recover(&StopOptions::default()).unwrap_err().error,
        Error::NotRoot
    );
    assert_eq!(
        b.switch_identity(Duration::from_secs(1)).unwrap_err().error,
        Error::NotRoot
    );
    assert!(fx.log().is_empty());
    assert!(!fx.paths.state_dir.exists());
}

#[test]
fn foreign_table_collision_is_refused_before_any_mutation() {
    let fx = fixture("foreign");
    fx.sim.borrow_mut().foreign_table = true;
    let f = fx.backend().start(&opts()).unwrap_err();
    assert_eq!(f.error, Error::ForeignTable);
    assert_eq!(f.state, State::Idle);
    assert!(!fx.ran("nft -f -") && !fx.ran("sysusers") && !fx.ran("systemctl"));
    assert!(!fx.state_file().exists());
}

#[test]
fn preflight_failure_is_reported_before_state_or_commands() {
    let fx = fixture("preflight");
    std::fs::remove_file(&fx.paths.binaries.tor).unwrap();
    let f = fx.backend().start(&opts()).unwrap_err();
    assert!(
        matches!(&f.error, Error::Preflight(items) if items.iter().any(|i| i.contains("binary tor")))
    );
    assert!(!fx.ran("nft -f -") && !fx.state_file().exists());
}

#[test]
fn symlinked_binary_is_not_trusted() {
    let fx = fixture("symlinkbin");
    let real = fx.root.join("bin/nft");
    let link = fx.root.join("bin/nft-link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let mut paths = fx.paths.clone();
    paths.binaries.nft = link;
    let mut b = Backend::new(
        FakeRunner(fx.sim.clone()),
        FakeEnv {
            sim: fx.sim.clone(),
            euid: 0,
            clock: Duration::ZERO,
        },
        paths,
    );
    assert!(!b.preflight(false).ok());
}

#[test]
fn nft_apply_failure_with_no_table_leaves_idle_and_never_starts_tor() {
    let fx = fixture("applyfail");
    fx.sim.borrow_mut().fail.push(("nft -f -", 1));
    let f = fx.backend().start(&opts()).unwrap_err();
    assert!(matches!(f.error, Error::Command { .. }));
    assert_eq!(f.state, State::Idle);
    assert!(!fx.ran("systemctl start"));
    assert!(!fx.state_file().exists());
}

#[test]
fn nft_syntax_check_failure_stops_before_apply() {
    let fx = fixture("checkfail");
    fx.sim.borrow_mut().fail.push(("nft -c -f -", 1));
    let f = fx.backend().start(&opts()).unwrap_err();
    assert_eq!(f.state, State::Idle);
    assert!(!fx.ran("nft -f -"));
}

#[test]
fn bootstrap_timeout_retains_verified_block_and_never_opens_traffic() {
    let fx = fixture("timeout");
    fx.sim.borrow_mut().bootstrap = 40;
    let f = fx.backend().start(&opts()).unwrap_err();
    assert!(matches!(f.error, Error::Tor(ref m) if m.contains("timed out")));
    assert!(matches!(f.state, State::Blocked { .. }));
    assert!(fx.sim.borrow().table_token.is_some(), "table must remain");
    assert!(
        !fx.log().iter().any(|l| l.contains("delete")),
        "no automatic teardown"
    );
    assert!(fx
        .sim
        .borrow()
        .stdin_log
        .iter()
        .all(|s| !s.contains("delete")));
    // Persisted, and a new start is refused until explicit stop.
    assert!(matches!(
        fx.backend().status().unwrap().state,
        State::Blocked { .. }
    ));
    let again = fx.backend().start(&opts()).unwrap_err();
    assert!(matches!(again.error, Error::WrongState(_)));
    // Explicit stop is allowed from Blocked and removes only the owned table.
    fx.backend().stop(&StopOptions::default()).unwrap();
    assert!(fx.sim.borrow().table_token.is_none());
    assert_eq!(fx.backend().status().unwrap().state, State::Idle);
    assert!(!fx.state_file().exists());
}

#[test]
fn wrong_tor_listener_is_not_connected() {
    let fx = fixture("listener");
    fx.sim.borrow_mut().listeners_ok = false;
    let f = fx.backend().start(&opts()).unwrap_err();
    assert!(matches!(f.error, Error::Tor(ref m) if m.contains("net/listeners/trans")));
    assert!(matches!(f.state, State::Blocked { .. }));
}

#[test]
fn unverifiable_enforcement_is_recovery_required_never_protection_verified() {
    let fx = fixture("tamper");
    fx.sim.borrow_mut().tamper_policy = true;
    let f = fx.backend().start(&opts()).unwrap_err();
    assert!(matches!(f.error, Error::Enforcement(_)));
    assert!(
        matches!(f.state, State::RecoveryRequired { .. }),
        "{:?}",
        f.state
    );
    assert!(
        !fx.ran("systemctl start"),
        "Tor must not start without verified enforcement"
    );
    // stop refuses this state; recover removes only the owned table.
    let e = fx.backend().stop(&StopOptions::default()).unwrap_err();
    assert!(matches!(e.error, Error::WrongState(_)));
    fx.backend().recover(&StopOptions::default()).unwrap();
    assert!(fx.sim.borrow().table_token.is_none());
}

#[test]
fn stop_order_is_tor_then_owned_table_then_state_and_deletes_only_owned_table() {
    let fx = fixture("stop");
    fx.backend().start(&opts()).unwrap();
    let before = fx.log().len();
    let out = fx.backend().stop(&StopOptions::default()).unwrap();
    assert!(out.table_removed && out.tor_stopped && !out.mac_restored);
    let log = &fx.log()[before..];
    let stop = log
        .iter()
        .position(|l| l.contains("systemctl stop"))
        .unwrap();
    let del = log.iter().position(|l| l.contains("nft -f -")).unwrap();
    assert!(stop < del);
    let deletes: Vec<String> = fx
        .sim
        .borrow()
        .stdin_log
        .iter()
        .filter(|s| s.contains("delete"))
        .cloned()
        .collect();
    assert_eq!(deletes.len(), 1);
    assert_eq!(deletes[0].trim(), "delete table inet torwell");
    assert!(!fx.state_file().exists());
    assert!(!fx.paths.config_dir.join("torrc").exists());
    // Stopping when idle is refused.
    assert!(matches!(
        fx.backend()
            .stop(&StopOptions::default())
            .unwrap_err()
            .error,
        Error::WrongState(_)
    ));
}

#[test]
fn stop_refuses_to_delete_a_table_without_our_token() {
    let fx = fixture("ownership");
    fx.backend().start(&opts()).unwrap();
    fx.sim.borrow_mut().table_token = Some("someone-elses-token".into());
    let f = fx.backend().stop(&StopOptions::default()).unwrap_err();
    assert!(matches!(f.error, Error::NotOwned(_)));
    assert!(matches!(f.state, State::RecoveryRequired { .. }));
    assert!(fx
        .sim
        .borrow()
        .stdin_log
        .iter()
        .all(|s| !s.contains("delete")));
    assert!(fx.sim.borrow().table_token.is_some());
    assert!(fx.state_file().exists(), "state is retained for recovery");
}

#[test]
fn failed_tor_stop_keeps_the_block_and_state() {
    let fx = fixture("stopfail");
    fx.backend().start(&opts()).unwrap();
    fx.sim.borrow_mut().fail.push(("systemctl stop", 1));
    let f = fx.backend().stop(&StopOptions::default()).unwrap_err();
    assert!(matches!(f.state, State::RecoveryRequired { .. }));
    assert!(fx.sim.borrow().table_token.is_some());
    assert!(fx
        .sim
        .borrow()
        .stdin_log
        .iter()
        .all(|s| !s.contains("delete")));
    assert!(fx.state_file().exists());
}

#[test]
fn switch_sends_authenticated_newnym_and_checks_the_reply() {
    let fx = fixture("switch");
    fx.backend().start(&opts()).unwrap();
    fx.sim.borrow_mut().control_calls.clear();
    assert!(
        fx.backend()
            .switch_identity(Duration::from_secs(5))
            .unwrap()
            .signal_accepted
    );
    assert_eq!(fx.sim.borrow().control_calls, vec!["SIGNAL NEWNYM"]);
    fx.sim.borrow_mut().newnym_reply = "552 Unrecognized signal";
    let f = fx
        .backend()
        .switch_identity(Duration::from_secs(5))
        .unwrap_err();
    assert!(matches!(f.error, Error::Tor(_)));
    assert_eq!(f.state, State::Connected);
}

#[test]
fn switch_requires_connected_and_intact_enforcement() {
    let fx = fixture("switchstate");
    assert!(matches!(
        fx.backend()
            .switch_identity(Duration::from_secs(1))
            .unwrap_err()
            .error,
        Error::WrongState(_)
    ));
    fx.backend().start(&opts()).unwrap();
    fx.sim.borrow_mut().tamper_policy = true;
    fx.sim.borrow_mut().control_calls.clear();
    let f = fx
        .backend()
        .switch_identity(Duration::from_secs(1))
        .unwrap_err();
    assert!(matches!(f.state, State::RecoveryRequired { .. }));
    assert!(
        fx.sim.borrow().control_calls.is_empty(),
        "no NEWNYM on broken enforcement"
    );
}

#[test]
fn concurrent_operation_is_refused_by_the_lock() {
    let fx = fixture("lock");
    let dir = torwell_linux::fsx::open_secure_dir(&fx.paths.state_dir, uid(), true).unwrap();
    let _held = dir.lock("lock").unwrap();
    let f = fx.backend().start(&opts()).unwrap_err();
    assert_eq!(f.error, Error::Locked);
    assert!(!fx.ran("nft -f -"));
}

#[test]
fn symlinked_state_directory_is_rejected() {
    let fx = fixture("symdir");
    let real = fx.root.join("realstate");
    std::fs::create_dir(&real).unwrap();
    std::os::unix::fs::symlink(&real, fx.root.join("state")).unwrap();
    let f = fx.backend().start(&opts()).unwrap_err();
    assert!(matches!(f.error, Error::UnsafePath(_)), "{:?}", f.error);
    assert!(!fx.ran("nft -f -"));
}

#[test]
fn group_writable_state_directory_is_rejected() {
    let fx = fixture("modedir");
    std::fs::create_dir(&fx.paths.state_dir).unwrap();
    std::fs::set_permissions(&fx.paths.state_dir, std::fs::Permissions::from_mode(0o775)).unwrap();
    let f = fx.backend().start(&opts()).unwrap_err();
    assert!(matches!(f.error, Error::UnsafePath(_)));
}

#[test]
fn symlinked_state_file_is_rejected_and_not_followed() {
    let fx = fixture("symfile");
    std::fs::create_dir(&fx.paths.state_dir).unwrap();
    let victim = fx.root.join("victim");
    std::fs::write(&victim, "keep").unwrap();
    std::os::unix::fs::symlink(&victim, fx.state_file()).unwrap();
    assert!(matches!(
        fx.backend().status().unwrap_err(),
        Error::UnsafePath(_)
    ));
    assert!(matches!(
        fx.backend().start(&opts()).unwrap_err().error,
        Error::UnsafePath(_)
    ));
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
}

#[test]
fn unmanaged_existing_config_file_is_not_overwritten() {
    let fx = fixture("assetowner");
    std::fs::create_dir(&fx.paths.config_dir).unwrap();
    std::fs::write(fx.paths.config_dir.join("torrc"), "user data\n").unwrap();
    let f = fx.backend().start(&opts()).unwrap_err();
    assert!(matches!(f.error, Error::NotOwned(_)));
    assert!(!fx.ran("nft -f -"));
    assert_eq!(
        std::fs::read_to_string(fx.paths.config_dir.join("torrc")).unwrap(),
        "user data\n"
    );
}

// ---------- MAC ----------

#[test]
fn unsupported_adapter_fails_before_any_mutation() {
    let fx = fixture("macbridge");
    fx.sim.borrow_mut().nm_type = "bridge";
    let f = fx.backend().start(&mac_opts()).unwrap_err();
    assert!(matches!(
        f.error,
        Error::Mac {
            rolled_back: true,
            ..
        }
    ));
    assert_eq!(f.state, State::Idle);
    assert!(
        !fx.ran("nft -f -")
            && !fx.ran("sysusers")
            && !fx.ran("modify")
            && !fx.state_file().exists()
    );
}

#[test]
fn mac_options_must_match_mode() {
    let fx = fixture("macopts");
    let mut o = opts();
    o.mac_interface = Some("eth0".into());
    assert!(matches!(
        fx.backend().start(&o).unwrap_err().error,
        Error::Config(_)
    ));
    let mut o = mac_opts();
    o.mac_interface = None;
    assert!(matches!(
        fx.backend().start(&o).unwrap_err().error,
        Error::Config(_)
    ));
    let mut o = mac_opts();
    o.mac_interface = Some("--evil".into());
    assert!(matches!(
        fx.backend().start(&o).unwrap_err().error,
        Error::Config(_)
    ));
    assert!(fx.log().is_empty());
}

#[test]
fn mac_applies_after_block_verifies_readback_and_restore_returns_absent_policy() {
    let fx = fixture("macok");
    let out = fx.backend().start(&mac_opts()).unwrap();
    assert_eq!(out.evidence.mac_readback, Check::Passed);
    let applied = out.mac.unwrap();
    assert!(applied.address.is_locally_administered());
    assert_eq!(fx.sim.borrow().nm_effective, applied.address.to_string());
    assert!(
        fx.pos("nft -f -") < fx.pos("connection modify"),
        "block before MAC change"
    );
    assert!(fx.pos("connection modify") < fx.pos("connection up"));
    assert!(fx.pos("connection up") < fx.pos("systemctl start"));
    assert!(fx.log().iter().any(|l| l.contains("--temporary")));
    // Stop restores the *prior profile policy* (absent => empty value), then Tor, then table.
    let out = fx.backend().stop(&StopOptions::default()).unwrap();
    assert!(out.mac_restored);
    assert_eq!(
        fx.sim.borrow().nm_profile,
        "",
        "absent policy restored as absent"
    );
    let log = fx.log();
    let restore = log
        .iter()
        .rposition(|l| l.contains("connection modify"))
        .unwrap();
    let stop = log
        .iter()
        .position(|l| l.contains("systemctl stop"))
        .unwrap();
    assert!(restore < stop);
}

#[test]
fn mac_readback_mismatch_rolls_back_and_keeps_block() {
    let fx = fixture("macmismatch");
    fx.sim.borrow_mut().nm_profile = "permanent".into();
    fx.sim.borrow_mut().nm_break_readback = true;
    let f = fx.backend().start(&mac_opts()).unwrap_err();
    assert!(
        matches!(
            f.error,
            Error::Mac {
                rolled_back: true,
                ..
            }
        ),
        "{:?}",
        f.error
    );
    assert!(matches!(f.state, State::Blocked { .. }));
    assert_eq!(
        fx.sim.borrow().nm_profile,
        "permanent",
        "prior policy restored"
    );
    assert!(!fx.ran("systemctl start"));
    assert!(fx.sim.borrow().table_token.is_some());
}

#[test]
fn failed_mac_rollback_is_recovery_required() {
    let fx = fixture("macrollback");
    fx.sim.borrow_mut().nm_profile = "permanent".into();
    fx.sim.borrow_mut().nm_break_readback = true;
    fx.sim.borrow_mut().nm_fail_restore = true;
    let f = fx.backend().start(&mac_opts()).unwrap_err();
    assert!(matches!(
        f.error,
        Error::Mac {
            rolled_back: false,
            ..
        }
    ));
    assert!(matches!(f.state, State::RecoveryRequired { .. }));
    // Intent was recorded with the prior policy before modification.
    let text = std::fs::read_to_string(fx.state_file()).unwrap();
    assert!(text.contains("permanent"));
}

#[test]
fn mac_capability_is_unsupported_for_unknown_adapters_and_never_claims_supported() {
    let fx = fixture("maccap");
    fx.sim.borrow_mut().nm_type = "wireguard";
    let c = fx.backend().mac_capability("wg0", Duration::from_secs(1));
    assert_eq!(c.support, torwell_core::Support::Unsupported);
    fx.sim.borrow_mut().nm_type = "ethernet";
    let c = fx.backend().mac_capability("eth0", Duration::from_secs(1));
    assert_eq!(c.support, torwell_core::Support::Unknown);
    assert!(
        !fx.ran("modify") && !fx.ran("connection up"),
        "discovery is read-only"
    );
}

// ---------- boot restore ----------

/// What a reboot does to the simulated host: nft tables are gone, the Tor unit is down.
fn reboot(fx: &Fx) {
    let mut s = fx.sim.borrow_mut();
    s.table_token = None;
    s.unit_active = false;
    s.log.clear();
    s.stdin_log.clear();
}

#[test]
fn boot_restore_with_no_state_does_nothing() {
    let fx = fixture("boot-none");
    assert_eq!(
        fx.backend().restore_at_boot(Duration::from_secs(1)),
        Ok(BootRestore::NothingToRestore)
    );
    assert!(fx.log().is_empty());
}

#[test]
fn boot_restore_reapplies_the_same_block_and_never_starts_tor() {
    let fx = fixture("boot-reapply");
    fx.backend().start(&opts()).unwrap();
    let token = fx.sim.borrow().table_token.clone().unwrap();
    reboot(&fx);

    let out = fx.backend().restore_at_boot(Duration::from_secs(1));
    assert_eq!(out, Ok(BootRestore::Reapplied));
    assert_eq!(fx.sim.borrow().table_token.as_deref(), Some(token.as_str()));
    assert!(fx.pos("nft -c -f -") < fx.pos("nft -f -"));
    assert!(
        !fx.ran("systemctl start"),
        "boot restore must not start Tor"
    );
    assert!(
        !fx.ran("nmcli"),
        "boot restore must not touch NetworkManager"
    );
    for s in &fx.sim.borrow().stdin_log {
        assert!(!s.contains("flush") && !s.contains("delete"), "{s}");
    }
    assert!(matches!(
        fx.backend().status().unwrap().state,
        State::Blocked { .. }
    ));

    // A second run (e.g. unit restarted) sees the verified table and changes nothing.
    fx.sim.borrow_mut().log.clear();
    assert_eq!(
        fx.backend().restore_at_boot(Duration::from_secs(1)),
        Ok(BootRestore::AlreadyEnforced)
    );
    assert!(!fx.ran("nft -f -"));

    // The restored Blocked state is left only through an explicit stop.
    fx.backend().stop(&StopOptions::default()).unwrap();
    assert!(fx.sim.borrow().table_token.is_none());
}

#[test]
fn boot_restore_refuses_a_tampered_existing_table_without_deleting_it() {
    let fx = fixture("boot-tamper");
    fx.backend().start(&opts()).unwrap();
    fx.sim.borrow_mut().tamper_policy = true;
    fx.sim.borrow_mut().log.clear();
    let err = fx
        .backend()
        .restore_at_boot(Duration::from_secs(1))
        .unwrap_err();
    assert!(matches!(err, Error::Enforcement(_)), "{err:?}");
    assert!(!fx.ran("nft -f -"), "nothing may be applied or deleted");
    assert!(matches!(
        fx.backend().status().unwrap().state,
        State::RecoveryRequired { .. }
    ));
}

#[test]
fn boot_restore_refuses_non_root() {
    let fx = fixture("boot-nonroot");
    assert_eq!(
        fx.backend_as(1000).restore_at_boot(Duration::from_secs(1)),
        Err(Error::NotRoot)
    );
}

#[test]
fn reboot_protection_needs_an_enabled_restore_unit() {
    let fx = fixture("boot-unit");
    let b = fx.backend();
    assert_eq!(b.reboot_protection(), RebootProtection::NotInstalled);
    std::fs::create_dir_all(fx.paths.unit_dir.join("multi-user.target.wants")).unwrap();
    std::fs::write(fx.paths.unit_dir.join(RESTORE_UNIT), "x").unwrap();
    assert_eq!(b.reboot_protection(), RebootProtection::InstalledNotEnabled);
    std::fs::write(
        fx.paths
            .unit_dir
            .join("multi-user.target.wants")
            .join(RESTORE_UNIT),
        "x",
    )
    .unwrap();
    assert_eq!(b.reboot_protection(), RebootProtection::Enabled);
}
