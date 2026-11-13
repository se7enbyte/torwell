//! Dependency preflight. Runs before any mutation and reports every problem at once.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::bridge;
use crate::error::{Error, Result};
use crate::exec::{CommandRunner, CommandSpec};
use crate::verify::{verify_executable, PathGuard, Pinned};

pub trait HostProbe {
    fn is_elevated(&self) -> Result<bool>;
    /// Base Filtering Engine service running (WFP is unusable without it).
    fn bfe_running(&self) -> Result<bool>;
}

pub struct Inputs<'a> {
    pub tor: &'a Pinned,
    pub bridge: &'a Pinned,
    /// Must live beside the bridge executable (loaded from the application directory).
    pub wintun_dll: &'a Pinned,
    pub powershell: &'a Path,
    pub state_dir: &'a PathBuf,
}

fn note(problems: &mut Vec<String>, r: Result<()>) {
    if let Err(e) = r {
        match e {
            Error::Preflight(v) => problems.extend(v),
            other => problems.push(other.to_string()),
        }
    }
}

pub fn run(
    i: &Inputs,
    guard: &dyn PathGuard,
    runner: &dyn CommandRunner,
    host: &dyn HostProbe,
) -> Result<()> {
    let mut problems: Vec<String> = Vec::new();
    match host.is_elevated() {
        Ok(true) => {}
        Ok(false) => problems.push("not running elevated (Administrator required)".into()),
        Err(e) => problems.push(format!("cannot determine elevation: {e}")),
    }
    match host.bfe_running() {
        Ok(true) => {}
        Ok(false) => problems.push("Base Filtering Engine (BFE) service is not running".into()),
        Err(e) => problems.push(format!("cannot query BFE: {e}")),
    }
    if !i.powershell.is_file() {
        problems.push(format!("{} not found", i.powershell.display()));
    }
    let tor_ok = verify_executable(i.tor, guard);
    let bridge_ok = verify_executable(i.bridge, guard);
    let wintun_ok = verify_executable(i.wintun_dll, guard);
    let bridge_verified = bridge_ok.is_ok();
    note(&mut problems, tor_ok);
    note(&mut problems, bridge_ok);
    note(&mut problems, wintun_ok);
    if i.wintun_dll.path.parent() != i.bridge.path.parent()
        || i.wintun_dll
            .path
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            != Some("wintun.dll".into())
    {
        problems.push(
            "wintun.dll must be named wintun.dll and sit beside the bridge executable".into(),
        );
    }
    if bridge_verified {
        let spec = CommandSpec {
            program: i.bridge.path.clone(),
            args: vec!["--help".into()],
            env: vec![],
            timeout: Duration::from_secs(10),
        };
        match runner.run(&spec) {
            Ok(o) => {
                let missing = bridge::missing_flags(&format!("{}{}", o.stdout, o.stderr));
                if !missing.is_empty() {
                    problems.push(format!("bridge binary lacks required flags {missing:?}"));
                }
            }
            Err(e) => problems.push(format!("cannot run bridge --help: {e}")),
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(Error::Preflight(problems))
    }
}
