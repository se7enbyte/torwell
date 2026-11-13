//! The only raw-Win32 layer. Compiled only on Windows and not yet compiled/run there.

pub mod random;
pub mod sys;
pub mod wfp;

use std::path::{Path, PathBuf};
use std::time::Duration;

use windows::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;

use crate::adapter::PsAdapter;
use crate::backend::Deps;
use crate::clock::SystemClock;
use crate::error::{Error, Result};
use crate::exec::{CommandRunner, CommandSpec, StdRunner};
use crate::mac::OsRng;
use crate::proc::StdLauncher;
use crate::sddl;
use crate::state::FileStateStore;
use crate::verify::PathGuard;

fn system_dir() -> Result<PathBuf> {
    let mut buf = vec![0u16; 260];
    // SAFETY: buffer is valid for its stated length.
    let n = unsafe { GetSystemWindowsDirectoryW(Some(&mut buf)) } as usize;
    if n == 0 || n > buf.len() {
        return Err(Error::Preflight(vec![
            "cannot resolve the Windows directory".into(),
        ]));
    }
    Ok(PathBuf::from(String::from_utf16_lossy(&buf[..n])))
}

/// ACL checks via fixed PowerShell text (path in an env var) and SDDL parsing; creation via icacls
/// with well-known SIDs (locale independent). An existing directory is verified, never "repaired".
pub struct AclGuard {
    pub powershell: PathBuf,
    pub icacls: PathBuf,
}

impl AclGuard {
    fn sddl_of(&self, p: &Path) -> Result<String> {
        const SCRIPT: &str = "$ErrorActionPreference='Stop';$p=$env:TORWELL_PATH;$i=Get-Item -LiteralPath $p -Force;if($i.Attributes -band [IO.FileAttributes]::ReparsePoint){'REPARSE'}else{(Get-Acl -LiteralPath $p).Sddl}";
        let out = StdRunner
            .run(&CommandSpec {
                program: self.powershell.clone(),
                args: [
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Restricted",
                    "-Command",
                    SCRIPT,
                ]
                .iter()
                .map(Into::into)
                .collect(),
                env: vec![("TORWELL_PATH".into(), p.display().to_string())],
                timeout: Duration::from_secs(30),
            })
            .map_err(|e| Error::State(e.to_string()))?;
        let s = out.stdout.trim().to_string();
        if !out.success() || s.is_empty() || s == "REPARSE" {
            return Err(Error::State(format!(
                "cannot read a plain ACL for {} (reparse point or error: {})",
                p.display(),
                out.stderr.trim()
            )));
        }
        Ok(s)
    }
}

impl PathGuard for AclGuard {
    fn ensure_secure_dir(&self, dir: &Path) -> Result<()> {
        if dir.exists() {
            return self.verify_admin_only(dir);
        }
        std::fs::create_dir_all(dir).map_err(|e| Error::State(e.to_string()))?;
        let run = |args: &[&str]| -> Result<()> {
            let mut a: Vec<std::ffi::OsString> = vec![dir.as_os_str().to_owned()];
            a.extend(args.iter().map(Into::into));
            let o = StdRunner
                .run(&CommandSpec {
                    program: self.icacls.clone(),
                    args: a,
                    env: vec![],
                    timeout: Duration::from_secs(30),
                })
                .map_err(|e| Error::State(e.to_string()))?;
            if o.success() {
                Ok(())
            } else {
                Err(Error::State(format!("icacls failed: {}", o.stdout.trim())))
            }
        };
        run(&["/inheritance:r"])?;
        run(&["/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"])?;
        run(&["/setowner", "*S-1-5-32-544"])?;
        self.verify_admin_only(dir)
    }
    fn verify_admin_only(&self, p: &Path) -> Result<()> {
        sddl::is_admin_only(&self.sddl_of(p)?)
            .map_err(|e| Error::State(format!("{}: {e}", p.display())))
    }
    fn verify_not_user_writable(&self, d: &Path) -> Result<()> {
        sddl::no_untrusted_write(&self.sddl_of(d)?)
            .map_err(|e| Error::State(format!("{}: {e}", d.display())))
    }
}

/// Builds all production dependencies. `state_dir` is typically `%ProgramData%\Torwell`.
pub fn system_deps(state_dir: PathBuf) -> Result<Deps> {
    let sys = system_dir()?.join("System32");
    let ps = sys.join(r"WindowsPowerShell\v1.0\powershell.exe");
    let guard = || AclGuard {
        powershell: ps.clone(),
        icacls: sys.join("icacls.exe"),
    };
    let store = FileStateStore::new(
        state_dir,
        guard(),
        Box::new(|pid| crate::proc::ProcessControl::is_alive(&sys::SystemProcs, pid)),
    );
    Ok(Deps {
        wfp: Box::new(wfp::SystemWfp::open()?),
        store: Box::new(store),
        adapter: Box::new(PsAdapter::new(StdRunner, ps.clone())),
        launcher: Box::new(StdLauncher),
        procs: Box::new(sys::SystemProcs),
        clock: Box::new(SystemClock::new()),
        rng: Box::new(OsRng),
        guard: Box::new(guard()),
        runner: Box::new(StdRunner),
        host: Box::new(sys::SystemHost {
            sc_exe: sys.join("sc.exe"),
        }),
        reaper: Box::new(sys::SystemReaper),
    })
}
