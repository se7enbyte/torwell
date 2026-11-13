//! Start / stop / status / recover orchestration over injected dependencies.
//!
//! Ordering (every mutation is preceded by a durable state write):
//! preflight (no mutation) -> optional MAC -> persistent WFP base policy (fail-closed, verified)
//! -> reset pre-existing connections -> bridge (creates the tunnel) -> tunnel WFP permits ->
//! Tor -> bootstrap evidence -> enforcement re-verification -> `Connected`.
//! Failure after enforcement exists keeps enforcement (`Blocked`); only an explicit stop or
//! recover removes it, and only Torwell-owned objects.

use std::path::PathBuf;
use std::time::Duration;

use torwell_core::config::{Config, MacMode};
use torwell_core::lifecycle::{Check, Evidence, Fault, Lifecycle, State};

use crate::adapter::{validate_adapter_name, AdapterApi};
use crate::bridge::{self, BridgeSpec};
use crate::clock::Clock;
use crate::error::{Error, Result};
use crate::exec::CommandRunner;
use crate::mac::{self, Csprng};
use crate::policy::{self, FilterSpec};
use crate::preflight::{self, HostProbe};
use crate::proc::{same_image, ManagedProcess, ProcSpec, ProcessControl, ProcessLauncher};
use crate::state::{OwnedState, Phase, ProcRecord, StateStore};
use crate::tor::{self, TorSpec};
use crate::verify::{PathGuard, Pinned};
use crate::wfp::{self, WfpApi};

/// Closes TCP connections that predate enforcement (ALE connect filters never see them).
pub trait ConnectionReaper {
    /// Resets established non-loopback TCP connections not owned by `keep_pids`. Returns count.
    fn reset_existing(&self, keep_pids: &[u32]) -> Result<usize>;
    /// Descriptions of non-loopback established connections still present (excluding `keep_pids`).
    fn lingering(&self, keep_pids: &[u32]) -> Result<Vec<String>>;
}

pub struct Deps {
    pub wfp: Box<dyn WfpApi>,
    pub store: Box<dyn StateStore>,
    pub adapter: Box<dyn AdapterApi>,
    pub launcher: Box<dyn ProcessLauncher>,
    pub procs: Box<dyn ProcessControl>,
    pub clock: Box<dyn Clock>,
    pub rng: Box<dyn Csprng>,
    pub guard: Box<dyn PathGuard>,
    pub runner: Box<dyn CommandRunner>,
    pub host: Box<dyn HostProbe>,
    pub reaper: Box<dyn ConnectionReaper>,
}

#[derive(Debug, Clone)]
pub struct StartRequest {
    pub config: Config,
    pub tor: Pinned,
    pub bridge: Pinned,
    pub wintun_dll: Pinned,
    /// Name given to the Wintun adapter created by the bridge.
    pub tunnel_name: String,
    /// Physical adapter whose IPv4 address Tor binds to, and whose MAC may be changed.
    pub uplink_adapter: String,
    pub state_dir: PathBuf,
    pub powershell: PathBuf,
    pub bootstrap_timeout: Duration,
    pub tunnel_timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connected {
    pub tunnel_luid: u64,
    pub bootstrap_percent: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoverMode {
    /// Remove WFP policy only after processes, tunnel and MAC teardown all verified.
    Strict,
    /// Explicit user choice: remove Torwell's WFP policy even if other teardown failed,
    /// reporting residue. Restores direct (unprotected) networking.
    ForceRemovePolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopOutcome {
    pub policy_removed: bool,
    /// Non-empty if teardown left something behind (only possible with `ForceRemovePolicy`).
    pub residual: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusReport {
    pub lifecycle: State,
    pub persisted: Option<OwnedState>,
    /// Live read-back of the expected WFP policy. `None` if no state to compare with.
    pub wfp_enforcing: Option<bool>,
    pub problems: Vec<String>,
}

pub struct WindowsBackend {
    d: Deps,
    lifecycle: Lifecycle,
    tor: Option<Box<dyn ManagedProcess>>,
    bridge: Option<Box<dyn ManagedProcess>>,
}

impl WindowsBackend {
    pub fn new(deps: Deps) -> Self {
        Self {
            d: deps,
            lifecycle: Lifecycle::new(MacMode::Off),
            tor: None,
            bridge: None,
        }
    }

    #[cfg(windows)]
    pub fn system(state_dir: PathBuf) -> Result<Self> {
        crate::win::system_deps(state_dir).map(Self::new)
    }

    #[cfg(not(windows))]
    pub fn system(_state_dir: PathBuf) -> Result<Self> {
        Err(Error::Unsupported(
            "the Windows backend only runs on Windows".into(),
        ))
    }

    pub fn lifecycle(&self) -> &State {
        self.lifecycle.state()
    }

    pub fn start(&mut self, req: &StartRequest) -> Result<Connected> {
        if *self.lifecycle.state() != State::Idle {
            return Err(Error::Lifecycle(format!(
                "cannot start in state {:?}",
                self.lifecycle.state()
            )));
        }
        req.config
            .validate()
            .map_err(|e| Error::Config(e.to_string()))?;
        validate_adapter_name(&req.tunnel_name)?;
        validate_adapter_name(&req.uplink_adapter)?;
        let _lock = self.d.store.lock()?;
        if self.d.store.load()?.is_some() || wfp::owned_present(&mut *self.d.wfp)? {
            return Err(Error::StateExists);
        }
        preflight::run(
            &preflight::Inputs {
                tor: &req.tor,
                bridge: &req.bridge,
                wintun_dll: &req.wintun_dll,
                powershell: &req.powershell,
                state_dir: &req.state_dir,
            },
            &*self.d.guard,
            &*self.d.runner,
            &*self.d.host,
        )?;
        let uplink_ip = self
            .d
            .adapter
            .uplink_ipv4(&req.uplink_adapter)?
            .ok_or_else(|| {
                Error::Preflight(vec![format!(
                    "{:?} has no usable IPv4 address",
                    req.uplink_adapter
                )])
            })?;

        self.lifecycle = Lifecycle::new(req.config.mac);
        self.lifecycle.begin_plan().map_err(lc)?;
        self.lifecycle.begin_start().map_err(lc)?;
        let mut sid = [0u8; 8];
        self.d.rng.fill(&mut sid)?;
        let session: String = sid.iter().map(|b| format!("{b:02x}")).collect();
        let mut st = OwnedState::new(session, req.tunnel_name.clone(), req.tor.path.clone());
        if let Err(e) = self.d.store.save(&st) {
            // Nothing applied yet.
            let _ = self.lifecycle.request_stop();
            let _ = self.lifecycle.finish_stop(Ok(()));
            return Err(e);
        }
        match self.start_inner(req, &mut st, uplink_ip) {
            Ok(c) => Ok(c),
            Err(e) => Err(self.fail_start(&mut st, e)),
        }
    }

    fn expected(st: &OwnedState) -> Vec<FilterSpec> {
        let mut v = policy::base_filters(&st.tor_exe);
        if let Some(l) = st.wfp_tunnel_luid {
            v.extend(policy::tunnel_filters(l));
        }
        v
    }

    fn start_inner(
        &mut self,
        req: &StartRequest,
        st: &mut OwnedState,
        uplink_ip: std::net::Ipv4Addr,
    ) -> Result<Connected> {
        let mut mac_check = Check::NotRun;
        if req.config.mac == MacMode::RandomOnApply {
            let mut rec = mac::prepare(&*self.d.adapter, &mut *self.d.rng, &req.uplink_adapter)?;
            rec.change_attempted = true;
            st.mac = Some(rec.clone());
            self.d.store.save(st)?; // write-ahead: restore data exists before the change
            mac::apply(&*self.d.adapter, &*self.d.clock, &rec)?;
            mac_check = Check::Passed;
        }

        st.wfp_base = true;
        self.d.store.save(st)?;
        wfp::install_base(&mut *self.d.wfp, &req.tor.path)?;
        wfp::verify(&mut *self.d.wfp, &Self::expected(st))?;

        self.d.reaper.reset_existing(&[])?;

        let mut bridge = self
            .d
            .launcher
            .launch(&ProcSpec {
                exe: req.bridge.path.clone(),
                args: bridge::bridge_args(&BridgeSpec {
                    exe: req.bridge.path.clone(),
                    tunnel_name: req.tunnel_name.clone(),
                    socks_port: req.config.socks_port,
                }),
                cwd: req.bridge.path.parent().map(|p| p.to_path_buf()),
            })
            .map_err(|e| Error::Bridge(format!("cannot start bridge: {e}")))?;
        st.bridge = Some(ProcRecord {
            pid: bridge.pid(),
            image: req.bridge.path.clone(),
        });
        self.d.store.save(st)?;
        let start = self.d.clock.now();
        let luid = loop {
            if let Some(code) = bridge.try_wait() {
                self.bridge = None;
                return Err(Error::Bridge(format!(
                    "bridge exited with code {code} before the tunnel appeared"
                )));
            }
            if let Some(l) = self.d.adapter.tunnel_luid(&req.tunnel_name)? {
                break l;
            }
            if self.d.clock.now().saturating_sub(start) >= req.tunnel_timeout {
                self.bridge = Some(bridge);
                return Err(Error::Bridge(
                    "tunnel adapter did not appear in time".into(),
                ));
            }
            self.d.clock.sleep(Duration::from_millis(500));
        };
        self.bridge = Some(bridge);

        st.wfp_tunnel_luid = Some(luid);
        self.d.store.save(st)?;
        wfp::install_tunnel(&mut *self.d.wfp, luid)?;
        wfp::verify(&mut *self.d.wfp, &Self::expected(st))?;

        let data_dir = req.state_dir.join("tor");
        self.d.guard.ensure_secure_dir(&data_dir)?;
        let mut tor = self
            .d
            .launcher
            .launch(&ProcSpec {
                exe: req.tor.path.clone(),
                args: tor::tor_args(&TorSpec {
                    exe: req.tor.path.clone(),
                    data_dir,
                    socks_port: req.config.socks_port,
                    bind_addr: uplink_ip,
                }),
                cwd: None,
            })
            .map_err(|e| Error::Process(format!("cannot start tor: {e}")))?;
        st.tor = Some(ProcRecord {
            pid: tor.pid(),
            image: req.tor.path.clone(),
        });
        self.d.store.save(st)?;
        let boot = tor::wait_bootstrap(&mut *tor, &*self.d.clock, req.bootstrap_timeout);
        self.tor = Some(tor);
        let boot = boot?;

        // Independent enforcement checks, not just "install returned Ok".
        let mut enforcement = Check::Passed;
        let mut why = Vec::new();
        if let Err(e) = wfp::verify(&mut *self.d.wfp, &Self::expected(st)) {
            enforcement = Check::Failed;
            why.push(e.to_string());
        }
        let keep: Vec<u32> = [&self.tor, &self.bridge]
            .iter()
            .filter_map(|p| p.as_ref().map(|p| p.pid()))
            .collect();
        if self.tor.as_mut().and_then(|p| p.try_wait()).is_some()
            || self.bridge.as_mut().and_then(|p| p.try_wait()).is_some()
        {
            enforcement = Check::Failed;
            why.push("tor or bridge exited after bootstrap".into());
        }
        if self.d.adapter.tunnel_luid(&req.tunnel_name)? != Some(luid) {
            enforcement = Check::Failed;
            why.push("tunnel adapter changed or vanished".into());
        }
        let lingering = self.d.reaper.lingering(&keep)?;
        if !lingering.is_empty() {
            enforcement = Check::Failed;
            why.push(format!(
                "pre-existing direct connections remain: {}",
                lingering.join(", ")
            ));
        }
        let ev = Evidence {
            tor_bootstrap: Check::Passed,
            enforcement,
            mac_readback: mac_check,
        };
        self.lifecycle.verify_connected(&ev).map_err(|e| {
            Error::Evidence(format!(
                "{e}{}",
                if why.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", why.join("; "))
                }
            ))
        })?;
        st.phase = Phase::Active;
        self.d.store.save(st)?;
        Ok(Connected {
            tunnel_luid: luid,
            bootstrap_percent: boot.percent,
        })
    }

    fn fail_start(&mut self, st: &mut OwnedState, err: Error) -> Error {
        for p in [&mut self.tor, &mut self.bridge] {
            if let Some(mut p) = p.take() {
                p.kill();
            }
        }
        let reason = err.to_string();
        // If the base-policy transaction aborted, nothing Torwell-owned exists: no enforcement to keep.
        if st.wfp_base && matches!(wfp::owned_present(&mut *self.d.wfp), Ok(false)) {
            st.wfp_base = false;
            st.wfp_tunnel_luid = None;
        }
        if st.wfp_base {
            return match wfp::verify(&mut *self.d.wfp, &Self::expected(st)) {
                Ok(()) => {
                    st.phase = Phase::Blocked {
                        reason: reason.clone(),
                    };
                    let _ = self.d.store.save(st);
                    let _ = self
                        .lifecycle
                        .fail(reason.clone(), Fault::ProtectionVerified);
                    Error::Blocked(format!(
                        "{reason}; Torwell WFP policy stays in force (run stop to release)"
                    ))
                }
                Err(v) => {
                    let _ = self.d.store.save(st);
                    let msg = format!("{reason}; enforcement could not be verified: {v}");
                    let _ = self.lifecycle.fail(msg.clone(), Fault::Partial);
                    Error::RecoveryRequired(msg)
                }
            };
        }
        // No enforcement applied: roll back the only possible mutation (MAC) and verify.
        let mut rollback_err = None;
        if let Some(m) = &st.mac {
            if let Err(e) = mac::restore(&*self.d.adapter, &*self.d.clock, m) {
                rollback_err = Some(e.to_string());
            }
        }
        match rollback_err {
            None => {
                let _ = self.d.store.clear();
                let _ = self.lifecycle.request_stop();
                let _ = self.lifecycle.finish_stop(Ok(()));
                err
            }
            Some(re) => {
                let _ = self.d.store.save(st);
                let msg = format!("{reason}; MAC rollback failed: {re}");
                let _ = self.lifecycle.fail(msg.clone(), Fault::Partial);
                Error::RecoveryRequired(msg)
            }
        }
    }

    /// Explicit clean stop of a connection this helper (or an earlier one) started.
    pub fn stop(&mut self) -> Result<StopOutcome> {
        self.teardown(RecoverMode::Strict)
    }

    /// Recovery from persisted state (helper restart, crash, failed stop).
    pub fn recover(&mut self, mode: RecoverMode) -> Result<StopOutcome> {
        self.teardown(mode)
    }

    fn teardown(&mut self, mode: RecoverMode) -> Result<StopOutcome> {
        let _lock = self.d.store.lock()?;
        let loaded = self.d.store.load()?;
        let Some(mut st) = loaded else {
            if wfp::owned_present(&mut *self.d.wfp)? {
                if mode == RecoverMode::ForceRemovePolicy {
                    wfp::remove_owned(&mut *self.d.wfp)?;
                    return Ok(StopOutcome {
                        policy_removed: true,
                        residual: vec![
                            "no state file; MAC and processes could not be checked".into()
                        ],
                    });
                }
                return Err(Error::RecoveryRequired("Torwell WFP policy exists without state; recover with ForceRemovePolicy to remove it".into()));
            }
            return Ok(StopOutcome {
                policy_removed: false,
                residual: vec![],
            });
        };
        // A fresh helper process has no in-memory lifecycle: reflect that state honestly first.
        if *self.lifecycle.state() == State::Idle {
            self.lifecycle = Lifecycle::new(
                st.mac
                    .as_ref()
                    .map_or(MacMode::Off, |_| MacMode::RandomOnApply),
            );
            self.lifecycle.begin_plan().map_err(lc)?;
            self.lifecycle
                .fail("recovering persisted state", Fault::Partial)
                .map_err(lc)?;
        }
        self.lifecycle.request_stop().map_err(lc)?;
        st.phase = Phase::Stopping;
        self.d.store.save(&st)?;

        let mut failures: Vec<String> = Vec::new();
        for p in [&mut self.tor, &mut self.bridge] {
            if let Some(mut p) = p.take() {
                p.kill();
            }
        }
        for rec in [st.tor.take(), st.bridge.take()].into_iter().flatten() {
            if self.d.procs.is_alive(rec.pid) {
                match self.d.procs.image_path(rec.pid) {
                    Some(img) if same_image(&img, &rec.image) => {
                        if let Err(e) = self.d.procs.terminate(rec.pid) {
                            failures.push(format!("cannot terminate pid {}: {e}", rec.pid));
                            if rec.image == st.tor_exe {
                                st.tor = Some(rec.clone());
                            } else {
                                st.bridge = Some(rec.clone());
                            }
                        }
                    }
                    // PID reused by an unrelated process, or unreadable: never kill it.
                    Some(_) => {}
                    None => failures.push(format!(
                        "pid {} liveness known but image unreadable; not terminating",
                        rec.pid
                    )),
                }
            }
        }
        match self.d.adapter.adapter_exists(&st.tunnel_name) {
            Ok(true) => {
                self.d.clock.sleep(Duration::from_secs(2));
                let gone = !self
                    .d
                    .adapter
                    .adapter_exists(&st.tunnel_name)
                    .unwrap_or(true)
                    || (self.d.adapter.remove_adapter(&st.tunnel_name).is_ok()
                        && !self
                            .d
                            .adapter
                            .adapter_exists(&st.tunnel_name)
                            .unwrap_or(true));
                if !gone {
                    failures.push(format!("tunnel adapter {:?} still present", st.tunnel_name));
                }
            }
            Ok(false) => {}
            Err(e) => failures.push(format!("cannot query tunnel adapter: {e}")),
        }
        let mut mac_failed = false;
        if let Some(m) = &st.mac {
            if let Err(e) = mac::restore(&*self.d.adapter, &*self.d.clock, m) {
                failures.push(e.to_string());
                mac_failed = true;
            }
        }

        let mut policy_removed = false;
        if failures.is_empty() || mode == RecoverMode::ForceRemovePolicy {
            match wfp::remove_owned(&mut *self.d.wfp) {
                Ok(()) => policy_removed = true,
                Err(e) => failures.push(format!("WFP removal: {e}")),
            }
        } else {
            failures
                .push("WFP policy kept (still blocking) because earlier teardown failed".into());
        }

        if failures.is_empty() {
            self.d.store.clear()?;
            self.lifecycle.finish_stop(Ok(())).map_err(lc)?;
            return Ok(StopOutcome {
                policy_removed,
                residual: vec![],
            });
        }
        if !mac_failed {
            st.mac = None;
        }
        st.wfp_base = !policy_removed;
        if policy_removed {
            st.wfp_tunnel_luid = None;
        }
        let _ = self.d.store.save(&st);
        let msg = failures.join("; ");
        self.lifecycle.finish_stop(Err(msg.clone())).map_err(lc)?;
        if policy_removed {
            Ok(StopOutcome {
                policy_removed,
                residual: failures,
            })
        } else {
            Err(Error::RecoveryRequired(msg))
        }
    }

    /// Non-mutating inspection (reads persisted state and live WFP objects).
    pub fn status(&mut self) -> StatusReport {
        let mut problems = Vec::new();
        let persisted = match self.d.store.load() {
            Ok(s) => s,
            Err(e) => {
                problems.push(e.to_string());
                None
            }
        };
        let wfp_enforcing = persisted.as_ref().map(|st| {
            if !st.wfp_base {
                return false;
            }
            match wfp::verify(&mut *self.d.wfp, &Self::expected(st)) {
                Ok(()) => true,
                Err(e) => {
                    problems.push(e.to_string());
                    false
                }
            }
        });
        StatusReport {
            lifecycle: self.lifecycle.state().clone(),
            persisted,
            wfp_enforcing,
            problems,
        }
    }
}

fn lc(e: torwell_core::lifecycle::TransitionError) -> Error {
    Error::Lifecycle(e.to_string())
}
