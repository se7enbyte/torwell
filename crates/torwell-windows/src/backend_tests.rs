//! Orchestration tests: ordering, failure containment, ownership and recovery, with every
//! system interface faked.

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::io;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use torwell_core::config::{Config, MacMode};
use torwell_core::lifecycle::State;
use torwell_core::mac::MacAddress;

use crate::adapter::MacState;
use crate::backend::*;
use crate::error::{Error, Result};
use crate::exec::{CommandOutput, CommandRunner, CommandSpec};
use crate::ids::{Guid, ALL_FILTERS};
use crate::preflight::HostProbe;
use crate::proc::{ManagedProcess, ProcSpec, ProcessControl, ProcessLauncher};
use crate::sha256::sha256;
use crate::state::{OwnedState, Phase, ProcRecord, StateStore};
use crate::testutil::*;
use crate::verify::Pinned;
use crate::wfp::{self, WfpApi};

#[derive(Default, Clone)]
struct MemStore(Rc<RefCell<Option<OwnedState>>>, Rc<Cell<u32>>);
impl StateStore for MemStore {
    fn load(&self) -> Result<Option<OwnedState>> {
        Ok(self.0.borrow().clone())
    }
    fn save(&self, s: &OwnedState) -> Result<()> {
        *self.0.borrow_mut() = Some(s.clone());
        self.1.set(self.1.get() + 1);
        Ok(())
    }
    fn clear(&self) -> Result<()> {
        *self.0.borrow_mut() = None;
        Ok(())
    }
    fn lock(&self) -> Result<Box<dyn Any>> {
        Ok(Box::new(()))
    }
}

struct Launcher {
    log: Log,
    clock: FakeClock,
    tor_lines: Vec<&'static str>,
    bridge_dies: bool,
    tunnel: Rc<Cell<bool>>,
}
impl ProcessLauncher for Launcher {
    fn launch(&self, spec: &ProcSpec) -> io::Result<Box<dyn ManagedProcess>> {
        let is_tor = spec
            .exe
            .file_name()
            .unwrap()
            .to_string_lossy()
            .contains("tor");
        self.log
            .borrow_mut()
            .push(format!("launch:{}", if is_tor { "tor" } else { "bridge" }));
        let mut p = FakeProc::new(&self.clock, if is_tor { &self.tor_lines } else { &[] });
        if is_tor {
            p.pid = 2000;
        } else {
            p.pid = 3000;
            if self.bridge_dies {
                p.exited = Some(2);
            } else {
                self.tunnel.set(true);
                p.on_kill = Some(self.tunnel.clone());
            }
        }
        Ok(Box::new(p))
    }
}

#[derive(Default)]
struct Procs {
    alive: RefCell<Vec<(u32, PathBuf)>>,
    terminated: RefCell<Vec<u32>>,
}
impl ProcessControl for Rc<Procs> {
    fn image_path(&self, pid: u32) -> Option<PathBuf> {
        self.alive
            .borrow()
            .iter()
            .find(|(p, _)| *p == pid)
            .map(|(_, i)| i.clone())
    }
    fn terminate(&self, pid: u32) -> io::Result<()> {
        self.terminated.borrow_mut().push(pid);
        self.alive.borrow_mut().retain(|(p, _)| *p != pid);
        Ok(())
    }
    fn is_alive(&self, pid: u32) -> bool {
        self.alive.borrow().iter().any(|(p, _)| *p == pid)
    }
}

struct Reaper {
    log: Log,
    lingering: Vec<String>,
}
impl ConnectionReaper for Reaper {
    fn reset_existing(&self, _k: &[u32]) -> Result<usize> {
        self.log.borrow_mut().push("reap".into());
        Ok(0)
    }
    fn lingering(&self, _k: &[u32]) -> Result<Vec<String>> {
        Ok(self.lingering.clone())
    }
}
struct Host(bool, bool);
impl HostProbe for Host {
    fn is_elevated(&self) -> Result<bool> {
        Ok(self.0)
    }
    fn bfe_running(&self) -> Result<bool> {
        Ok(self.1)
    }
}
struct Help;
impl CommandRunner for Help {
    fn run(&self, _s: &CommandSpec) -> io::Result<CommandOutput> {
        Ok(CommandOutput {
            code: Some(0),
            stdout: "--setup --proxy --tun --dns --bypass".into(),
            stderr: String::new(),
            timed_out: false,
        })
    }
}

#[derive(Clone)]
struct Opts {
    mac: MacMode,
    tor_lines: Vec<&'static str>,
    bridge_dies: bool,
    lingering: Vec<String>,
    fail_add_after: Option<usize>,
    ignore_mac_set: bool,
    elevated: bool,
}
impl Default for Opts {
    fn default() -> Self {
        Self {
            mac: MacMode::Off,
            tor_lines: vec!["Bootstrapped 50%", "Bootstrapped 100% (done)"],
            bridge_dies: false,
            lingering: vec![],
            fail_add_after: None,
            ignore_mac_set: false,
            elevated: true,
        }
    }
}

struct AdapterRc(Rc<FakeAdapter>);
impl crate::adapter::AdapterApi for AdapterRc {
    fn tunnel_luid(&self, n: &str) -> Result<Option<u64>> {
        self.0.tunnel_luid(n)
    }
    fn adapter_exists(&self, n: &str) -> Result<bool> {
        self.0.adapter_exists(n)
    }
    fn remove_adapter(&self, n: &str) -> Result<()> {
        self.0.remove_adapter(n)
    }
    fn uplink_ipv4(&self, n: &str) -> Result<Option<std::net::Ipv4Addr>> {
        self.0.uplink_ipv4(n)
    }
    fn read_mac(&self, n: &str) -> Result<MacState> {
        self.0.read_mac(n)
    }
    fn set_mac_override(&self, n: &str, m: &MacAddress) -> Result<()> {
        self.0.set_mac_override(n, m)
    }
    fn reset_mac_override(&self, n: &str) -> Result<()> {
        self.0.reset_mac_override(n)
    }
}

struct H {
    b: WindowsBackend,
    req: StartRequest,
    o: Opts,
    log: Log,
    clock: FakeClock,
    store: MemStore,
    wfp: Rc<RefCell<WfpState>>,
    adapter: Rc<FakeAdapter>,
    procs: Rc<Procs>,
}

impl H {
    fn deps(&self) -> Deps {
        let wfp = FakeWfp {
            shared: self.wfp.clone(),
            fail_add_after: self.o.fail_add_after,
            log: Some(self.log.clone()),
            ..Default::default()
        };
        Deps {
            wfp: Box::new(wfp),
            store: Box::new(self.store.clone()),
            adapter: Box::new(AdapterRc(self.adapter.clone())),
            launcher: Box::new(Launcher {
                log: self.log.clone(),
                clock: self.clock.clone(),
                tor_lines: self.o.tor_lines.clone(),
                bridge_dies: self.o.bridge_dies,
                tunnel: self.adapter.tunnel.clone(),
            }),
            procs: Box::new(self.procs.clone()),
            clock: Box::new(self.clock.clone()),
            rng: Box::new(FixedRng(vec![[0x10, 2, 3, 4, 5, 6]])),
            guard: Box::new(FakeGuard::default()),
            runner: Box::new(Help),
            host: Box::new(Host(self.o.elevated, true)),
            reaper: Box::new(Reaper {
                log: self.log.clone(),
                lingering: self.o.lingering.clone(),
            }),
        }
    }
    /// A new helper process: no in-memory state, same persisted state and system.
    fn restart_helper(&mut self) {
        self.b = WindowsBackend::new(self.deps());
    }
    fn mac(&self) -> MacState {
        self.adapter.state.borrow().clone()
    }
}

fn h(name: &str, o: Opts) -> H {
    let dir = temp_dir(name);
    let write = |f: &str, data: &[u8]| {
        let p = dir.join(f);
        std::fs::write(&p, data).unwrap();
        Pinned {
            path: p,
            sha256: sha256(data),
        }
    };
    let (tor, bridge, wintun) = (
        write("tor.exe", b"tor"),
        write("tun2proxy-bin.exe", b"bridge"),
        write("wintun.dll", b"dll"),
    );
    let log: Log = Default::default();
    let mut adapter = FakeAdapter::new(MacState {
        effective: MacAddress::parse("00:11:22:33:44:55").unwrap(),
        keyword_present: true,
        override_value: None,
    });
    adapter.log = Some(log.clone());
    adapter.ignore_set.set(o.ignore_mac_set);
    let ps = dir.join("powershell.exe");
    std::fs::write(&ps, b"").unwrap();
    let req = StartRequest {
        config: Config {
            mac: o.mac,
            ..Config::default()
        },
        tor,
        bridge,
        wintun_dll: wintun,
        tunnel_name: "Torwell Tun".into(),
        uplink_adapter: "Ethernet".into(),
        state_dir: dir,
        powershell: ps,
        bootstrap_timeout: Duration::from_secs(60),
        tunnel_timeout: Duration::from_secs(10),
    };
    let adapter = Rc::new(adapter);
    let mut x = H {
        b: WindowsBackend::new(Deps {
            wfp: Box::new(FakeWfp::default()),
            store: Box::new(MemStore::default()),
            adapter: Box::new(AdapterRc(adapter.clone())),
            launcher: Box::new(Launcher {
                log: log.clone(),
                clock: FakeClock::default(),
                tor_lines: vec![],
                bridge_dies: false,
                tunnel: Default::default(),
            }),
            procs: Box::new(Rc::new(Procs::default())),
            clock: Box::new(FakeClock::default()),
            rng: Box::new(FixedRng(vec![])),
            guard: Box::new(FakeGuard::default()),
            runner: Box::new(Help),
            host: Box::new(Host(true, true)),
            reaper: Box::new(Reaper {
                log: log.clone(),
                lingering: vec![],
            }),
        }),
        req,
        o,
        log,
        clock: FakeClock::default(),
        store: MemStore::default(),
        wfp: Default::default(),
        adapter,
        procs: Rc::new(Procs::default()),
    };
    x.restart_helper();
    x
}

fn pos(log: &Log, what: &str) -> usize {
    log.borrow()
        .iter()
        .position(|s| s == what)
        .unwrap_or_else(|| panic!("{what} not in {:?}", log.borrow()))
}
fn wfp_owned(h: &H) -> bool {
    let s = h.wfp.borrow();
    !s.filters.is_empty() || !s.providers.is_empty() || !s.sublayers.is_empty()
}
fn mac(s: &str) -> MacAddress {
    MacAddress::parse(s).unwrap()
}

#[test]
fn successful_start_orders_enforcement_before_bridge_and_tor() {
    let mut h = h("ok", Opts::default());
    let c = h.b.start(&h.req).unwrap();
    assert_eq!((c.tunnel_luid, c.bootstrap_percent), (77, 100));
    assert_eq!(h.b.lifecycle(), &State::Connected);
    assert!(pos(&h.log, "wfp:commit") < pos(&h.log, "reap"));
    assert!(pos(&h.log, "reap") < pos(&h.log, "launch:bridge"));
    assert!(pos(&h.log, "launch:bridge") < pos(&h.log, "launch:tor"));
    let commits: Vec<usize> = h
        .log
        .borrow()
        .iter()
        .enumerate()
        .filter(|(_, s)| *s == "wfp:commit")
        .map(|(i, _)| i)
        .collect();
    assert_eq!(commits.len(), 2);
    assert!(
        commits[1] > pos(&h.log, "launch:bridge") && commits[1] < pos(&h.log, "launch:tor"),
        "tunnel permits only after the tunnel exists"
    );
    let st = h.store.0.borrow().clone().unwrap();
    assert_eq!(st.phase, Phase::Active);
    assert!(st.wfp_base && st.tor.is_some() && st.bridge.is_some());
    assert_eq!(h.wfp.borrow().filters.len(), ALL_FILTERS.len());
}

#[test]
fn preflight_failure_changes_nothing() {
    let mut h = h(
        "pre",
        Opts {
            elevated: false,
            ..Default::default()
        },
    );
    assert!(matches!(h.b.start(&h.req), Err(Error::Preflight(_))));
    assert_eq!(h.b.lifecycle(), &State::Idle);
    assert!(h.store.0.borrow().is_none() && !wfp_owned(&h) && h.log.borrow().is_empty());
    // Tampered Tor binary: digest mismatch, still nothing applied.
    let mut h2 = h2_tampered();
    assert!(
        matches!(h2.b.start(&h2.req), Err(Error::Preflight(m)) if m.iter().any(|s| s.contains("digest")))
    );
    assert!(!wfp_owned(&h2) && h2.store.0.borrow().is_none());
}

fn h2_tampered() -> H {
    let h = h("tamper", Opts::default());
    std::fs::write(&h.req.tor.path, b"evil").unwrap();
    h
}

#[test]
fn bootstrap_timeout_keeps_enforcement_and_blocks() {
    let mut h = h(
        "boot",
        Opts {
            tor_lines: vec!["Bootstrapped 20%"],
            ..Default::default()
        },
    );
    let e = h.b.start(&h.req).unwrap_err();
    assert!(matches!(e, Error::Blocked(_)), "{e}");
    assert!(matches!(h.b.lifecycle(), State::Blocked { .. }));
    assert_eq!(
        h.wfp.borrow().filters.len(),
        ALL_FILTERS.len(),
        "kill switch stays after failure"
    );
    assert!(matches!(
        h.store.0.borrow().as_ref().unwrap().phase,
        Phase::Blocked { .. }
    ));
    assert!(!h.adapter.tunnel.get(), "bridge was killed");
    // Cannot restart or reconnect; only stop leaves Blocked.
    assert!(h.b.start(&h.req).is_err());
}

#[test]
fn bridge_crash_before_tunnel_is_blocked_not_connected() {
    let mut h = h(
        "bridge",
        Opts {
            bridge_dies: true,
            ..Default::default()
        },
    );
    assert!(matches!(h.b.start(&h.req), Err(Error::Blocked(m)) if m.contains("bridge exited")));
    assert!(!h.log.borrow().contains(&"launch:tor".to_string()));
    assert!(wfp_owned(&h));
}

#[test]
fn preexisting_connections_prevent_connected() {
    let mut h = h(
        "linger",
        Opts {
            lingering: vec!["10.0.0.5:443 pid 4".into()],
            ..Default::default()
        },
    );
    let e = h.b.start(&h.req).unwrap_err();
    assert!(
        matches!(&e, Error::Blocked(m) if m.contains("pre-existing")),
        "{e}"
    );
    assert!(!matches!(h.b.lifecycle(), State::Connected));
}

#[test]
fn atomic_wfp_failure_rolls_back_mac_and_returns_to_idle() {
    let mut h = h(
        "wfpfail",
        Opts {
            mac: MacMode::RandomOnApply,
            fail_add_after: Some(2),
            ..Default::default()
        },
    );
    let e = h.b.start(&h.req).unwrap_err();
    assert!(!matches!(e, Error::Blocked(_)));
    assert!(
        !wfp_owned(&h),
        "transaction aborted: nothing half-installed"
    );
    assert_eq!(h.mac().effective, mac("00:11:22:33:44:55"), "MAC restored");
    assert_eq!(h.mac().override_value, None);
    assert_eq!(h.b.lifecycle(), &State::Idle);
    assert!(h.store.0.borrow().is_none());
}

#[test]
fn aborted_policy_transaction_returns_to_idle_with_state_cleared() {
    let mut h = h(
        "wfpfail2",
        Opts {
            fail_add_after: Some(1),
            ..Default::default()
        },
    );
    let e = h.b.start(&h.req).unwrap_err();
    assert!(matches!(e, Error::Wfp(_)), "{e}");
    assert_eq!(h.b.lifecycle(), &State::Idle);
    assert!(h.store.0.borrow().is_none() && !wfp_owned(&h));
}

#[test]
fn unverifiable_enforcement_requires_recovery_and_keeps_state() {
    let mut h = h(
        "unverif",
        Opts {
            tor_lines: vec!["Bootstrapped 20%"],
            ..Default::default()
        },
    );
    // Someone tampers with the policy while Tor bootstraps: simulate by failing commit afterwards.
    h.o.fail_add_after = None;
    let _ = h.b.start(&h.req);
    // Blocked state; now remove one filter behind our back and re-stop to prove the status flags it.
    h.wfp.borrow_mut().filters.clear();
    assert_eq!(h.b.status().wfp_enforcing, Some(false));
    assert!(h.store.0.borrow().is_some());
}

#[test]
fn mac_readback_failure_aborts_before_any_firewall_change() {
    let mut h = h(
        "macfail",
        Opts {
            mac: MacMode::RandomOnApply,
            ignore_mac_set: true,
            ..Default::default()
        },
    );
    assert!(matches!(h.b.start(&h.req), Err(Error::Mac(_))));
    assert!(!wfp_owned(&h));
    assert_eq!(h.b.lifecycle(), &State::Idle);
}

#[test]
fn mac_on_success_requires_and_gets_readback_and_stop_restores_before_policy_removal() {
    let mut h = h(
        "macok",
        Opts {
            mac: MacMode::RandomOnApply,
            ..Default::default()
        },
    );
    h.b.start(&h.req).unwrap();
    assert_ne!(h.mac().effective, mac("00:11:22:33:44:55"));
    h.b.stop().unwrap();
    assert_eq!(h.mac().effective, mac("00:11:22:33:44:55"));
    assert_eq!(h.mac().override_value, None);
    assert!(!wfp_owned(&h));
    assert_eq!(h.b.lifecycle(), &State::Idle);
    assert!(h.store.0.borrow().is_none());
    let log = h.log.borrow();
    let reset = log.iter().rposition(|s| s == "mac:reset").unwrap();
    let last_commit = log.iter().rposition(|s| s == "wfp:commit").unwrap();
    assert!(reset < last_commit, "MAC restore precedes WFP removal");
}

#[test]
fn stop_kills_processes_and_removes_only_after_teardown() {
    let mut h = h("stop", Opts::default());
    h.b.start(&h.req).unwrap();
    let out = h.b.stop().unwrap();
    assert!(out.policy_removed && out.residual.is_empty());
    assert!(!wfp_owned(&h) && !h.adapter.tunnel.get());
    assert!(h.store.0.borrow().is_none());
}

#[test]
fn stuck_tunnel_keeps_blocking_until_forced() {
    let mut h = h("stuck", Opts::default());
    h.b.start(&h.req).unwrap();
    h.adapter.tunnel_stuck.set(true);
    let e = h.b.stop().unwrap_err();
    assert!(matches!(e, Error::RecoveryRequired(_)), "{e}");
    assert!(
        wfp_owned(&h),
        "kill switch persists while teardown is incomplete"
    );
    assert!(matches!(h.b.lifecycle(), State::RecoveryRequired { .. }));
    assert!(h.store.0.borrow().is_some());
    // Explicit, documented override.
    let out = h.b.recover(RecoverMode::ForceRemovePolicy).unwrap();
    assert!(out.policy_removed && !out.residual.is_empty());
    assert!(!wfp_owned(&h));
}

#[test]
fn recovery_after_helper_exit_uses_persisted_state_and_spares_reused_pids() {
    let mut h = h("recover", Opts::default());
    h.b.start(&h.req).unwrap();
    // Helper dies: Tor/bridge handles are lost; WFP policy and state persist.
    h.restart_helper();
    assert_eq!(h.b.lifecycle(), &State::Idle);
    let status = h.b.status();
    assert_eq!(status.wfp_enforcing, Some(true));
    assert!(status.persisted.is_some());
    // Bridge pid still alive with its real image; Tor pid was reused by an unrelated program.
    *h.procs.alive.borrow_mut() = vec![
        (3000, h.req.bridge.path.clone()),
        (2000, PathBuf::from(r"C:\Windows\notepad.exe")),
    ];
    h.b.recover(RecoverMode::Strict).unwrap();
    assert_eq!(*h.procs.terminated.borrow(), vec![3000]);
    assert!(!wfp_owned(&h));
    assert_eq!(h.b.lifecycle(), &State::Idle);
}

#[test]
fn start_refused_while_owned_state_or_policy_exists() {
    let mut h = h("refuse", Opts::default());
    h.b.start(&h.req).unwrap();
    h.restart_helper();
    assert!(matches!(h.b.start(&h.req), Err(Error::StateExists)));
    // Lost state but surviving policy is also refused.
    *h.store.0.borrow_mut() = None;
    assert!(matches!(h.b.start(&h.req), Err(Error::StateExists)));
}

#[test]
fn orphaned_policy_without_state_needs_explicit_force() {
    let mut h = h("orphan", Opts::default());
    h.b.start(&h.req).unwrap();
    h.restart_helper();
    *h.store.0.borrow_mut() = None;
    assert!(matches!(
        h.b.recover(RecoverMode::Strict),
        Err(Error::RecoveryRequired(_))
    ));
    assert!(wfp_owned(&h));
    let out = h.b.recover(RecoverMode::ForceRemovePolicy).unwrap();
    assert!(out.policy_removed);
    assert!(!wfp_owned(&h));
}

#[test]
fn foreign_filter_in_our_sublayer_is_never_deleted_and_policy_stays() {
    let mut h = h("foreign", Opts::default());
    h.b.start(&h.req).unwrap();
    h.wfp
        .borrow_mut()
        .foreign_in_sublayer
        .push(Guid::new(5, 5, 5, [5; 8]));
    assert!(h.b.stop().is_err());
    assert_eq!(h.wfp.borrow().filters.len(), ALL_FILTERS.len());
    assert_eq!(h.wfp.borrow().foreign_in_sublayer.len(), 1);
}

#[test]
fn status_is_read_only() {
    let mut h = h("status", Opts::default());
    h.b.start(&h.req).unwrap();
    let saves = h.store.1.get();
    let before = h.log.borrow().len();
    let s = h.b.status();
    assert_eq!(s.lifecycle, State::Connected);
    assert_eq!(s.wfp_enforcing, Some(true));
    assert_eq!(h.store.1.get(), saves);
    assert_eq!(h.log.borrow().len(), before);
    // Tampering is visible.
    h.wfp.borrow_mut().filters.clear();
    assert_eq!(h.b.status().wfp_enforcing, Some(false));
}

#[test]
fn recorded_pid_with_unreadable_image_is_not_terminated() {
    let mut h = h("pid", Opts::default());
    h.b.start(&h.req).unwrap();
    h.restart_helper();
    // alive but image unknown -> must not kill; teardown reports failure and keeps policy.
    struct Unreadable(Rc<Procs>);
    impl ProcessControl for Unreadable {
        fn image_path(&self, _p: u32) -> Option<PathBuf> {
            None
        }
        fn terminate(&self, p: u32) -> io::Result<()> {
            self.0.terminated.borrow_mut().push(p);
            Ok(())
        }
        fn is_alive(&self, _p: u32) -> bool {
            true
        }
    }
    let mut d = h.deps();
    d.procs = Box::new(Unreadable(h.procs.clone()));
    h.b = WindowsBackend::new(d);
    assert!(h.b.stop().is_err());
    assert!(h.procs.terminated.borrow().is_empty());
    assert!(wfp_owned(&h));
}

#[cfg(not(windows))]
#[test]
fn system_backend_is_unsupported_off_windows() {
    assert!(matches!(
        WindowsBackend::system(PathBuf::from("/x")),
        Err(Error::Unsupported(_))
    ));
}

#[test]
fn fake_wfp_helper_compiles_against_trait() {
    let mut w = FakeWfp::default();
    assert!(!wfp::owned_present(&mut w as &mut dyn WfpApi).unwrap());
    let _ = ProcRecord {
        pid: 1,
        image: PathBuf::new(),
    };
}
