//! The executor. Ordering (differs from the advisory core plan on purpose, see docs/LINUX.md):
//! intent -> assets/identity -> nft blocking table (verified) -> optional MAC -> start Tor ->
//! bootstrap/listener/uid verification -> enforcement re-verification -> Active.
//! Blocking is installed before any other traffic-affecting step, so there is no direct window.

use std::path::{Path, PathBuf};
use std::time::Duration;

use torwell_core::{Check, Config, Evidence, Fault, Lifecycle, MacAddress, MacMode, State};

use crate::env::Env;
use crate::error::{Error, OpFailure};
use crate::fsx::{check_trusted_exec, open_secure_dir};
use crate::mac::{self, Nm};
use crate::rules::{self, RuleParams};
use crate::runner::{Cmd, Runner};
use crate::state::{Durable, MacProgress, NftMark, Phase, Store};
use crate::tor;

#[derive(Debug, Clone)]
pub struct Binaries {
    pub nft: PathBuf,
    pub tor: PathBuf,
    pub systemctl: PathBuf,
    pub sysusers: PathBuf,
    pub nmcli: PathBuf,
}

impl Default for Binaries {
    fn default() -> Self {
        Self {
            nft: "/usr/bin/nft".into(),
            tor: "/usr/bin/tor".into(),
            systemctl: "/usr/bin/systemctl".into(),
            sysusers: "/usr/bin/systemd-sysusers".into(),
            nmcli: "/usr/bin/nmcli".into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Paths {
    /// Root-owned durable state and lock.
    pub state_dir: PathBuf,
    pub config_dir: PathBuf,
    pub unit_dir: PathBuf,
    pub sysusers_dir: PathBuf,
    /// Must match `RuntimeDirectory=torwell-tor` in the unit.
    pub runtime_dir: PathBuf,
    /// Exists only while systemd is the running init.
    pub systemd_marker: PathBuf,
    pub binaries: Binaries,
    /// Uid that must own state, config and trusted executables. 0 in production.
    pub trusted_owner: u32,
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            state_dir: "/var/lib/torwell".into(),
            config_dir: "/etc/torwell".into(),
            unit_dir: "/etc/systemd/system".into(),
            sysusers_dir: "/etc/sysusers.d".into(),
            runtime_dir: "/run/torwell-tor".into(),
            systemd_marker: "/run/systemd/system".into(),
            binaries: Binaries::default(),
            trusted_owner: 0,
        }
    }
}

const TORRC_FILE: &str = "torrc";
const SYSUSERS_FILE: &str = "torwell-tor.conf";

#[derive(Debug, Clone)]
pub struct StartOptions {
    pub config: Config,
    /// Required exactly when `config.mac == RandomOnApply`.
    pub mac_interface: Option<String>,
    pub bootstrap_timeout: Duration,
    pub command_timeout: Duration,
}

impl StartOptions {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            mac_interface: None,
            bootstrap_timeout: Duration::from_secs(180),
            command_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone)]
pub struct StopOptions {
    pub command_timeout: Duration,
}

impl Default for StopOptions {
    fn default() -> Self {
        Self {
            command_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacApplied {
    pub interface: String,
    pub address: MacAddress,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartOutcome {
    pub state: State,
    pub evidence: Evidence,
    pub tor_uid: u32,
    pub mac: Option<MacApplied>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopOutcome {
    pub mac_restored: bool,
    pub tor_stopped: bool,
    pub table_removed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchOutcome {
    /// Tor answered `250 OK` to `SIGNAL NEWNYM`. Tor may still rate-limit the effect.
    pub signal_accepted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub state: State,
    pub tor_uid: Option<u32>,
    pub mac: Option<MacApplied>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveStatus {
    pub enforcement: Check,
    pub tor_bootstrap: Check,
    pub detail: Vec<String>,
}

/// Name of the boot restore unit (asset `assets/torwell-restore.service`).
pub const RESTORE_UNIT: &str = "torwell-restore.service";

/// Result of [`Backend::restore_at_boot`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootRestore {
    /// No durable state: nothing was protected; nothing done.
    NothingToRestore,
    /// The owned table was already present and semantically verified.
    AlreadyEnforced,
    /// Blocking table re-applied and verified; state is `Blocked`, Tor not started.
    Reapplied,
}

/// See [`Backend::reboot_protection`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebootProtection {
    NotInstalled,
    InstalledNotEnabled,
    Enabled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightItem {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightReport {
    pub items: Vec<PreflightItem>,
}

impl PreflightReport {
    pub fn ok(&self) -> bool {
        self.items.iter().all(|i| i.ok)
    }
    fn failures(&self) -> Vec<String> {
        self.items
            .iter()
            .filter(|i| !i.ok)
            .map(|i| format!("{}: {}", i.name, i.detail))
            .collect()
    }
}

pub struct Backend<R: Runner, E: Env> {
    runner: R,
    env: E,
    paths: Paths,
}

fn state_of(phase: &Phase) -> State {
    match phase {
        Phase::Starting => State::Starting,
        Phase::Active => State::Connected,
        Phase::Blocked { reason } => State::Blocked {
            reason: reason.clone(),
        },
        Phase::RecoveryRequired { reason } => State::RecoveryRequired {
            reason: reason.clone(),
        },
        Phase::Stopping => State::Stopping,
    }
}

fn lifecycle_for(d: &Durable) -> Lifecycle {
    let mut lc = Lifecycle::new(d.config.mac);
    let _ = lc.begin_plan();
    let _ = lc.begin_start();
    match &d.phase {
        Phase::Starting => {}
        Phase::Active => {
            let _ = lc.verify_connected(&Evidence {
                tor_bootstrap: Check::Passed,
                enforcement: Check::Passed,
                mac_readback: Check::Passed,
            });
        }
        Phase::Blocked { reason } => {
            let _ = lc.fail(reason.clone(), Fault::ProtectionVerified);
        }
        Phase::RecoveryRequired { reason } => {
            let _ = lc.fail(reason.clone(), Fault::Partial);
        }
        Phase::Stopping => {
            let _ = lc.request_stop();
        }
    }
    lc
}

fn parse_version(text: &str) -> Option<Vec<u32>> {
    let tok = text.split_whitespace().find_map(|t| {
        let t = t.trim_start_matches('v').trim_end_matches('.');
        t.chars().next().filter(char::is_ascii_digit).map(|_| t)
    })?;
    tok.split('.')
        .map(|p| {
            p.split(|c: char| !c.is_ascii_digit())
                .next()
                .and_then(|n| n.parse().ok())
        })
        .collect()
}

fn at_least(found: &[u32], min: &[u32]) -> bool {
    found
        .iter()
        .chain(std::iter::repeat(&0))
        .take(min.len())
        .cmp(min.iter())
        != std::cmp::Ordering::Less
}

impl<R: Runner, E: Env> Backend<R, E> {
    pub fn new(runner: R, env: E, paths: Paths) -> Self {
        Self { runner, env, paths }
    }

    /// Escape hatch for tests to inspect recorded fakes.
    pub fn into_parts(self) -> (R, E) {
        (self.runner, self.env)
    }

    // ---------- helpers ----------

    fn require_root(&self) -> Result<(), Error> {
        if self.env.euid() == 0 {
            Ok(())
        } else {
            Err(Error::NotRoot)
        }
    }

    fn run(
        &mut self,
        program: &Path,
        what: &str,
        args: &[&str],
        stdin: Option<&str>,
        timeout: Duration,
    ) -> Result<crate::runner::Output, Error> {
        let mut cmd = Cmd::new(program, args, timeout);
        if let Some(s) = stdin {
            cmd = cmd.with_stdin(s.as_bytes().to_vec());
        }
        self.runner.run(&cmd).map_err(|e| Error::Command {
            what: what.into(),
            detail: e.to_string(),
        })
    }

    fn run_ok(
        &mut self,
        program: &Path,
        what: &str,
        args: &[&str],
        stdin: Option<&str>,
        timeout: Duration,
    ) -> Result<String, Error> {
        let out = self.run(program, what, args, stdin, timeout)?;
        if out.ok() {
            Ok(out.stdout)
        } else {
            Err(Error::Command {
                what: what.into(),
                detail: format!("exit {:?}: {}", out.code, out.stderr.trim()),
            })
        }
    }

    fn nft(
        &mut self,
        what: &str,
        args: &[&str],
        stdin: Option<&str>,
        t: Duration,
    ) -> Result<String, Error> {
        let p = self.paths.binaries.nft.clone();
        self.run_ok(&p, what, args, stdin, t)
    }

    fn table_exists(&mut self, t: Duration) -> Result<bool, Error> {
        let out = self.nft("nft list tables", &["-j", "list", "tables"], None, t)?;
        rules::table_exists(&out).map_err(|e| Error::Command {
            what: "nft list tables".into(),
            detail: e,
        })
    }

    fn store(&self, create: bool) -> Result<Store, Error> {
        if !create && std::fs::symlink_metadata(&self.paths.state_dir).is_err() {
            return Err(Error::WrongState(
                "nothing is running (no state directory)".into(),
            ));
        }
        Ok(Store::new(open_secure_dir(
            &self.paths.state_dir,
            self.paths.trusted_owner,
            create,
        )?))
    }

    fn params<'a>(d: &'a Durable) -> RuleParams<'a> {
        RuleParams {
            token: &d.token,
            tor_uid: d.tor_uid,
            trans_port: d.config.trans_port,
            dns_port: d.config.dns_port,
        }
    }

    /// Lists the owned table and checks its structure and (if recorded) fingerprint.
    fn verify_enforcement(&mut self, d: &Durable, t: Duration) -> Result<String, Error> {
        if d.nft != NftMark::Installed {
            return Err(Error::Enforcement(
                "owned table is not recorded as installed".into(),
            ));
        }
        let json = self.nft(
            "nft list table",
            &["-j", "list", "table", "inet", rules::TABLE],
            None,
            t,
        )?;
        rules::verify_listing(&json, &Self::params(d), d.fingerprint.as_deref())
            .map_err(Error::Enforcement)
    }

    fn systemctl(
        &mut self,
        what: &str,
        args: &[&str],
        t: Duration,
    ) -> Result<crate::runner::Output, Error> {
        let p = self.paths.binaries.systemctl.clone();
        self.run(&p, what, args, None, t)
    }

    fn unit_inactive(&mut self, t: Duration) -> Result<bool, Error> {
        let out = self.systemctl("systemctl is-active", &["is-active", tor::UNIT_NAME], t)?;
        Ok(matches!(out.stdout.trim(), "inactive" | "failed"))
    }

    fn control(
        &mut self,
        tor_uid: u32,
        cmds: &[&str],
        t: Duration,
    ) -> Result<Vec<tor::Reply>, Error> {
        let cookie = self
            .env
            .read_cookie(&self.paths.runtime_dir.join("control.authcookie"), tor_uid)?;
        let req = tor::build_request(&cookie, cmds);
        let text = self.env.control_exchange(
            &self.paths.runtime_dir.join("control"),
            tor_uid,
            req.as_bytes(),
            t,
        )?;
        let replies = tor::parse_replies(&text)?;
        Ok(tor::check_replies(&replies, cmds.len())?.to_vec())
    }

    fn nm<'a>(runner: &'a mut R, env: &'a mut E, nmcli: &'a Path, t: Duration) -> Nm<'a> {
        Nm {
            runner,
            env,
            nmcli,
            timeout: t,
        }
    }

    fn install_asset(&self, dir: &Path, name: &str, content: &str) -> Result<(), Error> {
        let d = open_secure_dir(dir, self.paths.trusted_owner, true)?;
        if let Some(existing) = d.read_file(name, 1 << 20)? {
            if !existing.starts_with(tor::MARKER.as_bytes()) {
                return Err(Error::NotOwned(format!(
                    "{} exists and is not managed by torwell",
                    dir.join(name).display()
                )));
            }
        }
        d.write_file_atomic(name, content.as_bytes(), 0o644)
    }

    // ---------- public: read-only ----------

    /// Non-mutating dependency check. Runs only `nft --version` and `tor --version`.
    pub fn preflight(&mut self, want_mac: bool) -> PreflightReport {
        let t = Duration::from_secs(10);
        let b = self.paths.binaries.clone();
        let owner = self.paths.trusted_owner;
        let mut items = Vec::new();
        let mut push = |name: &str, r: Result<String, Error>| {
            items.push(match r {
                Ok(detail) => PreflightItem {
                    name: name.into(),
                    ok: true,
                    detail,
                },
                Err(e) => PreflightItem {
                    name: name.into(),
                    ok: false,
                    detail: e.to_string(),
                },
            })
        };
        let mut bins = vec![
            ("nft", &b.nft),
            ("tor", &b.tor),
            ("systemctl", &b.systemctl),
            ("systemd-sysusers", &b.sysusers),
        ];
        if want_mac {
            bins.push(("nmcli", &b.nmcli));
        }
        let trusted: Vec<(&str, bool)> = bins
            .iter()
            .map(|(n, p)| {
                let r = check_trusted_exec(p, owner).map(|_| format!("{} trusted", p.display()));
                let ok = r.is_ok();
                push(&format!("binary {n}"), r);
                (*n, ok)
            })
            .collect();
        let ok_of = |n: &str| trusted.iter().any(|(m, ok)| *m == n && *ok);
        if ok_of("nft") {
            let r = self
                .run_ok(&b.nft, "nft --version", &["--version"], None, t)
                .and_then(|o| {
                    let v = parse_version(&o).ok_or_else(|| Error::Command {
                        what: "nft".into(),
                        detail: format!("unparsable version {o:?}"),
                    })?;
                    if at_least(&v, &[1, 0, 0]) {
                        Ok(o.trim().to_string())
                    } else {
                        Err(Error::Config(format!("nft {v:?} older than 1.0.0")))
                    }
                });
            push("nft version", r);
        }
        if ok_of("tor") {
            let r = self
                .run_ok(&b.tor, "tor --version", &["--version"], None, t)
                .and_then(|o| {
                    let v = parse_version(o.lines().next().unwrap_or("")).ok_or_else(|| {
                        Error::Command {
                            what: "tor".into(),
                            detail: format!("unparsable version {o:?}"),
                        }
                    })?;
                    if at_least(&v, &[0, 4, 5]) {
                        Ok(o.lines().next().unwrap_or("").to_string())
                    } else {
                        Err(Error::Config(format!("tor {v:?} older than 0.4.5")))
                    }
                });
            push("tor version", r);
        }
        let systemd = self.paths.systemd_marker.is_dir();
        push(
            "systemd running",
            if systemd {
                Ok("systemd marker present".into())
            } else {
                Err(Error::Config("systemd is not the running init".into()))
            },
        );
        let user = self.env.lookup_user(tor::SERVICE_USER);
        push(
            "service identity",
            match user {
                Ok(Some(u)) => tor::check_service_identity(u.uid, &u.shell)
                    .map(|_| format!("{} uid {}", tor::SERVICE_USER, u.uid)),
                Ok(None) => Ok(format!(
                    "{} absent; will be created by systemd-sysusers",
                    tor::SERVICE_USER
                )),
                Err(e) => Err(e),
            },
        );
        PreflightReport { items }
    }

    /// Persisted state only. Needs no privilege beyond read access to the state directory.
    pub fn status(&self) -> Result<Status, Error> {
        if std::fs::symlink_metadata(&self.paths.state_dir).is_err() {
            return Ok(Status {
                state: State::Idle,
                tor_uid: None,
                mac: None,
            });
        }
        let dir = open_secure_dir(&self.paths.state_dir, self.paths.trusted_owner, false)?;
        match Store::new(dir).load()? {
            None => Ok(Status {
                state: State::Idle,
                tor_uid: None,
                mac: None,
            }),
            Some(d) => Ok(Status {
                // Persisted Active is historical evidence, not evidence that nft or Tor
                // survived a reboot or are still running. Call inspect_live for proof.
                state: if d.phase == Phase::Active {
                    State::Starting
                } else {
                    state_of(&d.phase)
                },
                tor_uid: (d.tor_uid != 0).then_some(d.tor_uid),
                mac: d
                    .mac
                    .as_ref()
                    .filter(|m| m.progress == MacProgress::Applied)
                    .map(|m| MacApplied {
                        interface: m.restore.interface().to_string(),
                        address: m.candidate,
                    }),
            }),
        }
    }

    /// Root-only, non-mutating live checks of enforcement and Tor bootstrap.
    pub fn inspect_live(&mut self, command_timeout: Duration) -> Result<LiveStatus, Error> {
        self.require_root()?;
        let store = self.store(false)?;
        let d = store
            .load()?
            .ok_or_else(|| Error::WrongState("nothing is running".into()))?;
        let mut detail = Vec::new();
        let enforcement = match self.verify_enforcement(&d, command_timeout) {
            Ok(_) => Check::Passed,
            Err(e) => {
                detail.push(e.to_string());
                Check::Failed
            }
        };
        let tor_bootstrap = match self
            .control(
                d.tor_uid,
                &["GETINFO status/bootstrap-phase"],
                command_timeout,
            )
            .and_then(|r| {
                tor::getinfo_value(&r[0], "status/bootstrap-phase")
                    .ok_or_else(|| Error::Tor("no bootstrap value".into()))
            })
            .and_then(|v| tor::bootstrap_done(&v))
        {
            Ok(true) => Check::Passed,
            Ok(false) => {
                detail.push("bootstrap not complete".into());
                Check::Failed
            }
            Err(e) => {
                detail.push(e.to_string());
                Check::Failed
            }
        };
        Ok(LiveStatus {
            enforcement,
            tor_bootstrap,
            detail,
        })
    }

    /// Root-only boot entry point for `torwell-restore.service`. If durable state says
    /// protection was wanted when the machine went down, re-applies and verifies the
    /// blocking table (same token, Tor uid and ports) and records `Blocked`. It never starts
    /// Tor, never opens traffic and never deletes anything; the user leaves this state with
    /// `start` after `stop`, or with `recover`.
    pub fn restore_at_boot(&mut self, t: Duration) -> Result<BootRestore, Error> {
        self.require_root()?;
        if std::fs::symlink_metadata(&self.paths.state_dir).is_err() {
            return Ok(BootRestore::NothingToRestore);
        }
        let store = self.store(false)?;
        let _lock = store.lock()?;
        let Some(mut d) = store.load()? else {
            return Ok(BootRestore::NothingToRestore);
        };
        if d.tor_uid == 0 {
            // The uid exemption would cover root. Refuse rather than install a weaker block.
            let reason = "state has no Tor identity; boot restore refused, run recover".to_string();
            d.phase = Phase::RecoveryRequired {
                reason: reason.clone(),
            };
            store.save(&d)?;
            return Err(Error::WrongState(reason));
        }
        let params = Self::params(&d);
        if self.table_exists(t)? {
            let json = self.nft(
                "nft list table",
                &["-j", "list", "table", "inet", rules::TABLE],
                None,
                t,
            )?;
            return match rules::verify_listing(&json, &params, None) {
                Ok(_) => Ok(BootRestore::AlreadyEnforced),
                Err(e) => {
                    d.phase = Phase::RecoveryRequired {
                        reason: format!("boot restore: existing table failed verification: {e}"),
                    };
                    store.save(&d)?;
                    Err(Error::Enforcement(e))
                }
            };
        }
        let script = rules::ruleset(&params);
        self.nft("nft -c", &["-c", "-f", "-"], Some(&script), t)?;
        d.nft = NftMark::Pending;
        store.save(&d)?;
        self.nft("nft apply", &["-f", "-"], Some(&script), t)?;
        d.nft = NftMark::Installed;
        // The nft binary may have changed since the last fingerprint; re-verify semantically
        // and record a fresh fingerprint for later tamper checks.
        d.fingerprint = None;
        let fp = self.verify_enforcement(&d, t)?;
        d.fingerprint = Some(fp);
        d.phase = Phase::Blocked {
            reason: "restored at boot; Tor not started, traffic stays blocked".into(),
        };
        store.save(&d)?;
        Ok(BootRestore::Reapplied)
    }

    /// Whether the boot restore unit is installed and enabled. `start` alone never makes
    /// protection survive a reboot; only an enabled `torwell-restore.service` does.
    pub fn reboot_protection(&self) -> RebootProtection {
        let unit = self.paths.unit_dir.join(RESTORE_UNIT);
        let wanted = self
            .paths
            .unit_dir
            .join("multi-user.target.wants")
            .join(RESTORE_UNIT);
        match (unit.exists(), wanted.exists()) {
            (true, true) => RebootProtection::Enabled,
            (true, false) => RebootProtection::InstalledNotEnabled,
            _ => RebootProtection::NotInstalled,
        }
    }

    /// Non-mutating MAC capability for an interface.
    pub fn mac_capability(
        &mut self,
        interface: &str,
        command_timeout: Duration,
    ) -> torwell_core::Capability {
        let nmcli = self.paths.binaries.nmcli.clone();
        if let Err(e) = check_trusted_exec(&nmcli, self.paths.trusted_owner) {
            return torwell_core::Capability {
                name: "linux_mac_networkmanager".into(),
                support: torwell_core::Support::Unsupported,
                detail: e.to_string(),
            };
        }
        let mut nm = Self::nm(&mut self.runner, &mut self.env, &nmcli, command_timeout);
        mac::capability(&mut nm, interface)
    }

    // ---------- public: mutating ----------

    pub fn start(&mut self, o: &StartOptions) -> Result<StartOutcome, OpFailure> {
        let idle = |error: Error| OpFailure {
            error,
            state: State::Idle,
        };
        o.config
            .validate()
            .map_err(|e| idle(Error::Config(e.to_string())))?;
        match (&o.config.mac, &o.mac_interface) {
            (MacMode::RandomOnApply, None) => {
                return Err(idle(Error::Config("MAC mode needs mac_interface".into())))
            }
            (MacMode::Off, Some(_)) => {
                return Err(idle(Error::Config(
                    "mac_interface given but MAC mode is Off".into(),
                )))
            }
            (MacMode::RandomOnApply, Some(i)) => mac::check_interface(i).map_err(idle)?,
            _ => {}
        }
        self.require_root().map_err(idle)?;
        let t = o.command_timeout;
        let report = self.preflight(o.config.mac == MacMode::RandomOnApply);
        if !report.ok() {
            return Err(idle(Error::Preflight(report.failures())));
        }
        let store = self.store(true).map_err(idle)?;
        let _lock = store.lock().map_err(idle)?;
        if let Some(existing) = store.load().map_err(idle)? {
            return Err(OpFailure {
                error: Error::WrongState("state already exists; stop or recover first".into()),
                state: state_of(&existing.phase),
            });
        }
        if self.table_exists(t).map_err(idle)? {
            return Err(idle(Error::ForeignTable));
        }
        // Read-only MAC discovery and candidate generation: unsupported adapters fail here.
        let mac_plan = match &o.mac_interface {
            None => None,
            Some(iface) => {
                let nmcli = self.paths.binaries.nmcli.clone();
                let target = Self::nm(&mut self.runner, &mut self.env, &nmcli, t)
                    .discover(iface)
                    .map_err(idle)?;
                let mut b = [0u8; 6];
                self.env.random_bytes(&mut b).map_err(idle)?;
                Some((target, MacAddress::from_candidate_bytes(b)))
            }
        };
        let mut tok = [0u8; 16];
        self.env.random_bytes(&mut tok).map_err(idle)?;
        let token: String = tok.iter().map(|b| format!("{b:02x}")).collect();

        // Intent is durable before the first mutation.
        let mut d = Durable::new(token, o.config.clone(), 0);
        store.save(&d).map_err(idle)?;
        let mut lc = Lifecycle::new(o.config.mac);
        let _ = lc.begin_plan();
        let _ = lc.begin_start();

        match self.start_inner(&store, &mut d, mac_plan, o) {
            Ok(outcome) => {
                lc.verify_connected(&outcome.evidence)
                    .map_err(|e| OpFailure {
                        error: Error::Enforcement(e.to_string()),
                        state: State::Starting,
                    })?;
                Ok(StartOutcome {
                    state: lc.state().clone(),
                    ..outcome
                })
            }
            Err(e) => Err(self.settle(&store, &mut d, &mut lc, e, t)),
        }
    }

    fn start_inner(
        &mut self,
        store: &Store,
        d: &mut Durable,
        mac_plan: Option<(mac::MacTarget, MacAddress)>,
        o: &StartOptions,
    ) -> Result<StartOutcome, Error> {
        let t = o.command_timeout;
        let b = self.paths.binaries.clone();

        // Assets and the dedicated identity (no network effect).
        let torrc_path = self.paths.config_dir.join(TORRC_FILE);
        self.install_asset(
            &self.paths.config_dir,
            TORRC_FILE,
            &tor::render_torrc(&o.config, &self.paths.runtime_dir),
        )?;
        self.install_asset(
            &self.paths.unit_dir,
            tor::UNIT_NAME,
            &tor::render_unit(&b.tor, &torrc_path),
        )?;
        self.install_asset(&self.paths.sysusers_dir, SYSUSERS_FILE, tor::SYSUSERS)?;
        let sysusers_file = self.paths.sysusers_dir.join(SYSUSERS_FILE);
        self.run_ok(
            &b.sysusers,
            "systemd-sysusers",
            &[&sysusers_file.display().to_string()],
            None,
            t,
        )?;
        self.run_ok(
            &b.systemctl.clone(),
            "systemctl daemon-reload",
            &["daemon-reload"],
            None,
            t,
        )?;
        let user = self
            .env
            .lookup_user(tor::SERVICE_USER)?
            .ok_or_else(|| Error::Config(format!("{} was not created", tor::SERVICE_USER)))?;
        tor::check_service_identity(user.uid, &user.shell)?;
        d.tor_uid = user.uid;
        store.save(d)?;

        // Blocking table: syntax check, record Pending, apply atomically, verify.
        let script = rules::ruleset(&Self::params(d));
        self.nft("nft -c", &["-c", "-f", "-"], Some(&script), t)?;
        d.nft = NftMark::Pending;
        store.save(d)?;
        if let Err(e) = self.nft("nft apply", &["-f", "-"], Some(&script), t) {
            // The transaction is atomic; confirm whether anything exists before deciding.
            return match self.table_exists(t) {
                Ok(false) => {
                    d.nft = NftMark::None;
                    store.save(d)?;
                    Err(e)
                }
                _ => {
                    d.nft = NftMark::Installed;
                    store.save(d)?;
                    Err(e)
                }
            };
        }
        d.nft = NftMark::Installed;
        store.save(d)?;
        let fp = self.verify_enforcement(d, t)?;
        d.fingerprint = Some(fp);
        store.save(d)?;

        // Optional MAC, while the block is already in force.
        let mut mac_applied = None;
        let mut mac_check = Check::NotRun;
        if let Some((target, candidate)) = mac_plan {
            let nmcli = b.nmcli.clone();
            check_trusted_exec(&nmcli, self.paths.trusted_owner)?;
            let mut persist = |rec: &crate::state::MacRecord| -> Result<(), Error> {
                d.mac = Some(rec.clone());
                store.save(d)
            };
            let rec = Self::nm(&mut self.runner, &mut self.env, &nmcli, t).apply(
                &target,
                candidate,
                &mut persist,
            )?;
            mac_applied = Some(MacApplied {
                interface: rec.restore.interface().to_string(),
                address: rec.candidate,
            });
            mac_check = Check::Passed;
        }

        // Tor.
        d.tor_started = true;
        store.save(d)?;
        self.run_ok(
            &b.systemctl.clone(),
            "systemctl start",
            &["start", tor::UNIT_NAME],
            None,
            t,
        )?;
        self.wait_bootstrap(d.tor_uid, o)?;
        self.verify_tor(d, t)?;
        self.verify_enforcement(d, t)?;

        d.phase = Phase::Active;
        store.save(d)?;
        Ok(StartOutcome {
            state: State::Starting,
            evidence: Evidence {
                tor_bootstrap: Check::Passed,
                enforcement: Check::Passed,
                mac_readback: mac_check,
            },
            tor_uid: d.tor_uid,
            mac: mac_applied,
        })
    }

    fn wait_bootstrap(&mut self, tor_uid: u32, o: &StartOptions) -> Result<(), Error> {
        let start = self.env.now();
        let mut last = String::from("no control reply yet");
        loop {
            if self.unit_inactive(o.command_timeout)? {
                return Err(Error::Tor("tor service stopped during bootstrap".into()));
            }
            let left = o
                .bootstrap_timeout
                .saturating_sub(self.env.now().saturating_sub(start));
            if left.is_zero() {
                return Err(Error::Tor(format!("bootstrap timed out: {last}")));
            }
            let step = left.min(Duration::from_secs(10));
            match self.control(tor_uid, &["GETINFO status/bootstrap-phase"], step) {
                Ok(r) => match tor::getinfo_value(&r[0], "status/bootstrap-phase") {
                    Some(v) => match tor::bootstrap_done(&v) {
                        Ok(true) => return Ok(()),
                        Ok(false) => last = v,
                        Err(e) => last = e.to_string(),
                    },
                    None => last = "reply lacked bootstrap value".into(),
                },
                Err(e) => last = e.to_string(),
            }
            self.env.sleep(Duration::from_secs(1));
        }
    }

    /// Listener ports and process uid prove it is *our* Tor with the expected interfaces.
    fn verify_tor(&mut self, d: &Durable, t: Duration) -> Result<(), Error> {
        let r = self.control(
            d.tor_uid,
            &[
                "GETINFO net/listeners/socks",
                "GETINFO net/listeners/trans",
                "GETINFO net/listeners/dns",
                "GETINFO process/pid",
            ],
            t,
        )?;
        for (i, (key, port)) in [
            ("net/listeners/socks", d.config.socks_port),
            ("net/listeners/trans", d.config.trans_port),
            ("net/listeners/dns", d.config.dns_port),
        ]
        .iter()
        .enumerate()
        {
            let v = tor::getinfo_value(&r[i], key)
                .ok_or_else(|| Error::Tor(format!("no {key} value")))?;
            if !tor::sole_loopback_listener(&v, *port) {
                return Err(Error::Tor(format!(
                    "{key} is {v:?}, expected only 127.0.0.1:{port}"
                )));
            }
        }
        let pid: u32 = tor::getinfo_value(&r[3], "process/pid")
            .and_then(|v| v.trim().parse().ok())
            .ok_or_else(|| Error::Tor("no process/pid".into()))?;
        let uids = self.env.process_uids(pid)?;
        if uids.iter().any(|u| *u != d.tor_uid) {
            return Err(Error::Tor(format!(
                "tor pid {pid} runs with uids {uids:?}, expected only {}",
                d.tor_uid
            )));
        }
        Ok(())
    }

    /// Chooses the post-failure state. `ProtectionVerified` is used only when the owned
    /// table was just re-verified; otherwise the state is RecoveryRequired.
    fn settle(
        &mut self,
        store: &Store,
        d: &mut Durable,
        lc: &mut Lifecycle,
        err: Error,
        t: Duration,
    ) -> OpFailure {
        if d.nft == NftMark::None && !d.tor_started && d.mac.is_none() {
            return match store.clear() {
                Ok(()) => OpFailure {
                    error: err,
                    state: State::Idle,
                },
                Err(e) => OpFailure {
                    error: Error::State(format!("{err}; clearing intent failed: {e}")),
                    state: State::Starting,
                },
            };
        }
        let rollback_failed = matches!(
            err,
            Error::Mac {
                rolled_back: false,
                ..
            }
        );
        let reason = err.to_string();
        let verified = !rollback_failed && self.verify_enforcement(d, t).is_ok();
        if verified {
            let _ = lc.fail(reason.clone(), Fault::ProtectionVerified);
            d.phase = Phase::Blocked { reason };
        } else {
            let _ = lc.fail(reason.clone(), Fault::Partial);
            d.phase = Phase::RecoveryRequired { reason };
        }
        let _ = store.save(d);
        OpFailure {
            error: err,
            state: lc.state().clone(),
        }
    }

    /// Stops Tor, removes only the owned table, restores MAC. Refuses when Idle.
    pub fn stop(&mut self, o: &StopOptions) -> Result<StopOutcome, OpFailure> {
        self.teardown(o, false)
    }

    /// Same safe teardown for any non-idle state, including `Starting` left by a crash.
    pub fn recover(&mut self, o: &StopOptions) -> Result<StopOutcome, OpFailure> {
        self.teardown(o, true)
    }

    fn teardown(&mut self, o: &StopOptions, allow_broken: bool) -> Result<StopOutcome, OpFailure> {
        let idle = |error: Error| OpFailure {
            error,
            state: State::Idle,
        };
        self.require_root().map_err(idle)?;
        let t = o.command_timeout;
        let store = self.store(false).map_err(idle)?;
        let _lock = store.lock().map_err(idle)?;
        let mut d = match store.load().map_err(idle)? {
            Some(d) => d,
            None => return Err(idle(Error::WrongState("nothing to stop".into()))),
        };
        if !allow_broken && !matches!(d.phase, Phase::Active | Phase::Blocked { .. }) {
            return Err(OpFailure {
                error: Error::WrongState("use recover for this state".into()),
                state: state_of(&d.phase),
            });
        }
        let mut lc = lifecycle_for(&d);
        let _ = lc.request_stop();
        d.phase = Phase::Stopping;
        store.save(&d).map_err(|e| OpFailure {
            error: e,
            state: state_of(&Phase::Stopping),
        })?;

        match self.teardown_inner(&store, &mut d, t) {
            Ok(out) => {
                let _ = lc.finish_stop(Ok(()));
                Ok(out)
            }
            Err(e) => {
                let reason = e.to_string();
                let _ = lc.finish_stop(Err(reason.clone()));
                d.phase = Phase::RecoveryRequired { reason };
                let _ = store.save(&d);
                Err(OpFailure {
                    error: e,
                    state: lc.state().clone(),
                })
            }
        }
    }

    fn teardown_inner(
        &mut self,
        store: &Store,
        d: &mut Durable,
        t: Duration,
    ) -> Result<StopOutcome, Error> {
        let b = self.paths.binaries.clone();
        // 1. MAC first, while blocking is still in force.
        let mut mac_restored = false;
        if let Some(rec) = d.mac.clone() {
            check_trusted_exec(&b.nmcli, self.paths.trusted_owner)?;
            Self::nm(&mut self.runner, &mut self.env, &b.nmcli, t).restore(&rec)?;
            d.mac = None;
            store.save(d)?;
            mac_restored = true;
        }
        // 2. Tor.
        if !self.unit_inactive(t)? {
            self.run_ok(
                &b.systemctl,
                "systemctl stop",
                &["stop", tor::UNIT_NAME],
                None,
                t,
            )?;
            if !self.unit_inactive(t)? {
                return Err(Error::Tor("tor service still active after stop".into()));
            }
        }
        d.tor_started = false;
        store.save(d)?;
        // 3. Owned table only, after proving ownership.
        let mut table_removed = false;
        if self.table_exists(t)? {
            let json = self.nft(
                "nft list table",
                &["-j", "list", "table", "inet", rules::TABLE],
                None,
                t,
            )?;
            if !rules::owned_by(&json, &d.token) {
                return Err(Error::NotOwned(
                    "table inet torwell does not carry this state's ownership token; left in place"
                        .into(),
                ));
            }
            self.nft(
                "nft delete table",
                &["-f", "-"],
                Some(&format!("delete table inet {}\n", rules::TABLE)),
                t,
            )?;
            if self.table_exists(t)? {
                return Err(Error::Enforcement(
                    "table still present after delete".into(),
                ));
            }
            table_removed = true;
        }
        d.nft = NftMark::None;
        // 4. Generated config, then state last.
        let cfg = open_secure_dir(&self.paths.config_dir, self.paths.trusted_owner, false);
        if let Ok(dir) = cfg {
            if let Some(b) = dir.read_file(TORRC_FILE, 1 << 20)? {
                if b.starts_with(tor::MARKER.as_bytes()) {
                    dir.remove_file(TORRC_FILE)?;
                }
            }
        }
        store.clear()?;
        Ok(StopOutcome {
            mac_restored,
            tor_stopped: true,
            table_removed,
        })
    }

    /// NEWNYM, verified by Tor's `250 OK`. Only valid in `Connected`, and only after the
    /// enforcement fingerprint still matches.
    pub fn switch_identity(
        &mut self,
        command_timeout: Duration,
    ) -> Result<SwitchOutcome, OpFailure> {
        let idle = |error: Error| OpFailure {
            error,
            state: State::Idle,
        };
        self.require_root().map_err(idle)?;
        let store = self.store(false).map_err(idle)?;
        let _lock = store.lock().map_err(idle)?;
        let mut d = store
            .load()
            .map_err(idle)?
            .ok_or_else(|| idle(Error::WrongState("not running".into())))?;
        if d.phase != Phase::Active {
            return Err(OpFailure {
                error: Error::WrongState("switch needs the Connected state".into()),
                state: state_of(&d.phase),
            });
        }
        let mut lc = lifecycle_for(&d);
        if let Err(e) = self.verify_enforcement(&d, command_timeout) {
            let reason = e.to_string();
            let _ = lc.fail(reason.clone(), Fault::Partial);
            d.phase = Phase::RecoveryRequired { reason };
            let _ = store.save(&d);
            return Err(OpFailure {
                error: e,
                state: lc.state().clone(),
            });
        }
        let keep = |error: Error| OpFailure {
            error,
            state: State::Connected,
        };
        let r = self
            .control(d.tor_uid, &["SIGNAL NEWNYM"], command_timeout)
            .map_err(keep)?;
        Ok(SwitchOutcome {
            signal_accepted: r[0].code == 250,
        })
    }
}
