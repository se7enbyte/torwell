//! Fakes shared by unit tests. Nothing here touches the host system except temp files.

use std::cell::{Cell, RefCell, RefMut};
use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

use torwell_core::mac::MacAddress;

use crate::adapter::{AdapterApi, MacState};
use crate::clock::Clock;
use crate::error::{Error, Result};
use crate::ids::Guid;
use crate::mac::Csprng;
use crate::policy::FilterSpec;
use crate::proc::{LineEvent, ManagedProcess};
use crate::verify::PathGuard;
use crate::wfp::{FilterReadback, SublayerReadback, WfpApi};

pub type Log = Rc<RefCell<Vec<String>>>;

pub fn temp_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("torwell-win-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::canonicalize(&d).unwrap()
}

#[derive(Clone, Default)]
pub struct FakeClock(pub Rc<Cell<Duration>>);
impl Clock for FakeClock {
    fn now(&self) -> Duration {
        self.0.get()
    }
    fn sleep(&self, d: Duration) {
        self.0.set(self.0.get() + d);
    }
}

#[derive(Default)]
pub struct FakeGuard {
    pub insecure_state: bool,
    pub writable: bool,
}
impl PathGuard for FakeGuard {
    fn ensure_secure_dir(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir).map_err(|e| Error::State(e.to_string()))
    }
    fn verify_admin_only(&self, _p: &Path) -> Result<()> {
        if self.insecure_state {
            Err(Error::State("users can write".into()))
        } else {
            Ok(())
        }
    }
    fn verify_not_user_writable(&self, _d: &Path) -> Result<()> {
        if self.writable {
            Err(Error::State("users can write".into()))
        } else {
            Ok(())
        }
    }
}

pub struct FixedRng(pub Vec<[u8; 6]>);
impl Csprng for FixedRng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
        let next = if self.0.len() > 1 {
            self.0.remove(0)
        } else {
            self.0.first().copied().unwrap_or([7; 6])
        };
        for (i, b) in buf.iter_mut().enumerate() {
            *b = next[i % 6].wrapping_add((i / 6) as u8);
        }
        Ok(())
    }
}

// ---- WFP ----

#[derive(Clone, Default)]
pub struct WfpState {
    pub providers: BTreeMap<Guid, bool>,
    pub sublayers: BTreeMap<Guid, SublayerReadback>,
    pub filters: BTreeMap<Guid, FilterReadback>,
    /// Unrelated filters in other sublayers (must survive).
    pub other_filters: Vec<Guid>,
    /// Filters in Torwell's sublayer not created by Torwell.
    pub foreign_in_sublayer: Vec<Guid>,
}

#[derive(Default)]
pub struct FakeWfp {
    pub shared: Rc<RefCell<WfpState>>,
    pub snapshot: Option<WfpState>,
    pub fail_add_after: Option<usize>,
    pub fail_commit: bool,
    pub adds: usize,
    pub log: Option<Log>,
}

impl FakeWfp {
    pub fn st(&self) -> RefMut<'_, WfpState> {
        self.shared.borrow_mut()
    }
    fn say(&self, s: &str) {
        if let Some(l) = &self.log {
            l.borrow_mut().push(s.to_string());
        }
    }
}

impl WfpApi for FakeWfp {
    fn begin(&mut self) -> Result<()> {
        self.snapshot = Some(self.shared.borrow().clone());
        Ok(())
    }
    fn commit(&mut self) -> Result<()> {
        if self.fail_commit {
            return Err(Error::Wfp("commit failed".into()));
        }
        self.say("wfp:commit");
        self.snapshot = None;
        Ok(())
    }
    fn abort(&mut self) {
        if let Some(s) = self.snapshot.take() {
            *self.shared.borrow_mut() = s;
        }
        self.say("wfp:abort");
    }
    fn get_provider(&mut self, key: &Guid) -> Result<Option<bool>> {
        Ok(self.shared.borrow().providers.get(key).copied())
    }
    fn add_provider(&mut self, key: &Guid, _n: &str) -> Result<()> {
        self.shared.borrow_mut().providers.insert(*key, true);
        Ok(())
    }
    fn get_sublayer(&mut self, key: &Guid) -> Result<Option<SublayerReadback>> {
        Ok(self.shared.borrow().sublayers.get(key).cloned())
    }
    fn add_sublayer(&mut self, key: &Guid, _n: &str, provider: &Guid, weight: u16) -> Result<()> {
        self.shared.borrow_mut().sublayers.insert(
            *key,
            SublayerReadback {
                persistent: true,
                provider: Some(*provider),
                weight,
            },
        );
        Ok(())
    }
    fn add_filter(&mut self, spec: &FilterSpec, provider: &Guid, sublayer: &Guid) -> Result<()> {
        if let Some(n) = self.fail_add_after {
            if self.adds >= n {
                return Err(Error::Wfp("add_filter failed".into()));
            }
        }
        self.adds += 1;
        self.shared.borrow_mut().filters.insert(
            spec.id.key(),
            FilterReadback {
                layer: spec.layer,
                action: spec.action,
                weight: spec.weight,
                persistent: true,
                provider: Some(*provider),
                sublayer: *sublayer,
                condition_count: spec.conditions.len(),
            },
        );
        Ok(())
    }
    fn get_filter(&mut self, key: &Guid) -> Result<Option<FilterReadback>> {
        Ok(self.shared.borrow().filters.get(key).cloned())
    }
    fn filters_in_sublayer(&mut self, _s: &Guid) -> Result<Vec<Guid>> {
        let s = self.shared.borrow();
        let mut v: Vec<Guid> = s.filters.keys().copied().collect();
        v.extend(s.foreign_in_sublayer.iter().copied());
        Ok(v)
    }
    fn delete_filter(&mut self, key: &Guid) -> Result<bool> {
        Ok(self.shared.borrow_mut().filters.remove(key).is_some())
    }
    fn delete_sublayer(&mut self, key: &Guid) -> Result<bool> {
        Ok(self.shared.borrow_mut().sublayers.remove(key).is_some())
    }
    fn delete_provider(&mut self, key: &Guid) -> Result<bool> {
        Ok(self.shared.borrow_mut().providers.remove(key).is_some())
    }
}

// ---- processes ----

pub struct FakeProc {
    clock: FakeClock,
    lines: VecDeque<String>,
    pub exit_after_lines: Option<usize>,
    recvs: usize,
    pub exited: Option<i32>,
    pub pid: u32,
    pub killed: Rc<Cell<bool>>,
    pub on_kill: Option<Rc<Cell<bool>>>,
}

impl FakeProc {
    pub fn new(clock: &FakeClock, lines: &[&str]) -> Self {
        Self {
            clock: clock.clone(),
            lines: lines.iter().map(|s| s.to_string()).collect(),
            exit_after_lines: None,
            recvs: 0,
            exited: None,
            pid: 1000,
            killed: Rc::new(Cell::new(false)),
            on_kill: None,
        }
    }
}

impl ManagedProcess for FakeProc {
    fn pid(&self) -> u32 {
        self.pid
    }
    fn try_wait(&mut self) -> Option<i32> {
        if self.killed.get() {
            return Some(-1);
        }
        if let Some(n) = self.exit_after_lines {
            if self.recvs >= n {
                return Some(1);
            }
        }
        self.exited
    }
    fn kill(&mut self) {
        self.killed.set(true);
        if let Some(c) = &self.on_kill {
            c.set(false);
        }
    }
    fn recv_line(&mut self, timeout: Duration) -> LineEvent {
        self.recvs += 1;
        match self.lines.pop_front() {
            Some(l) => LineEvent::Line(l),
            None => {
                self.clock.sleep(timeout);
                LineEvent::Idle
            }
        }
    }
}

// ---- adapter ----

pub struct FakeAdapter {
    pub state: RefCell<MacState>,
    base_effective: MacAddress,
    pub calls: RefCell<Vec<String>>,
    pub ignore_set: Cell<bool>,
    pub tunnel: Rc<Cell<bool>>,
    pub tunnel_stuck: Cell<bool>,
    pub log: Option<Log>,
}

impl FakeAdapter {
    pub fn new(s: MacState) -> Self {
        Self {
            base_effective: s.effective,
            state: RefCell::new(s),
            calls: RefCell::new(vec![]),
            ignore_set: Cell::new(false),
            tunnel: Rc::new(Cell::new(false)),
            tunnel_stuck: Cell::new(false),
            log: None,
        }
    }
    fn call(&self, s: &str) {
        self.calls.borrow_mut().push(s.to_string());
        if s != "read" {
            if let Some(l) = &self.log {
                l.borrow_mut().push(format!("mac:{s}"));
            }
        }
    }
}

impl AdapterApi for FakeAdapter {
    fn tunnel_luid(&self, _n: &str) -> Result<Option<u64>> {
        Ok(self.tunnel.get().then_some(77))
    }
    fn adapter_exists(&self, _n: &str) -> Result<bool> {
        Ok(self.tunnel.get() || self.tunnel_stuck.get())
    }
    fn remove_adapter(&self, _n: &str) -> Result<()> {
        if !self.tunnel_stuck.get() {
            self.tunnel.set(false);
        }
        Ok(())
    }
    fn uplink_ipv4(&self, _n: &str) -> Result<Option<std::net::Ipv4Addr>> {
        Ok(Some("192.168.1.20".parse().unwrap()))
    }
    fn read_mac(&self, _n: &str) -> Result<MacState> {
        self.call("read");
        Ok(self.state.borrow().clone())
    }
    fn set_mac_override(&self, _n: &str, mac: &MacAddress) -> Result<()> {
        self.call("set");
        if !self.ignore_set.get() {
            let mut s = self.state.borrow_mut();
            s.effective = *mac;
            s.override_value = Some(*mac);
        }
        Ok(())
    }
    fn reset_mac_override(&self, _n: &str) -> Result<()> {
        self.call("reset");
        let mut s = self.state.borrow_mut();
        s.override_value = None;
        s.effective = self.base_effective;
        Ok(())
    }
}

#[allow(dead_code)]
pub fn io_err() -> io::Error {
    io::Error::other("fake")
}
