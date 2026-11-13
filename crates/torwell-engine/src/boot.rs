//! Boot protection: installs and enables `torwell-restore.service`, and `restore-at-boot`.
//!
//! `Backend::reboot_protection` looks for the unit and its `multi-user.target.wants` link in
//! `/etc/systemd/system`, so `enable` installs the rendered unit there (a packaged copy under
//! `/usr/lib/systemd/system` is overridden by it) and runs `systemctl enable` — never
//! `--now`. Everything uses absolute program paths and argument arrays; no shell.

use std::path::{Path, PathBuf};
use std::time::Duration;

use torwell_linux::fsx::{check_trusted_exec, open_secure_dir};
use torwell_linux::tor::MARKER;
use torwell_linux::{Cmd, Error, RebootProtection, Runner, RESTORE_UNIT};

const TEMPLATE: &str = include_str!("../../torwell-linux/assets/torwell-restore.service");
const PLACEHOLDER: &str = "@TORWELL_ENGINE@";
const TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct BootPaths {
    /// `/etc/systemd/system`.
    pub unit_dir: PathBuf,
    pub systemctl: PathBuf,
    /// Uid that must own the unit directory and systemctl. 0 in production.
    pub trusted_owner: u32,
}

impl Default for BootPaths {
    fn default() -> Self {
        Self {
            unit_dir: "/etc/systemd/system".into(),
            systemctl: "/usr/bin/systemctl".into(),
            trusted_owner: 0,
        }
    }
}

/// Same rule as `Backend::reboot_protection`, computed from files only.
pub fn protection(unit_dir: &Path) -> RebootProtection {
    let unit = unit_dir.join(RESTORE_UNIT).exists();
    let wanted = unit_dir
        .join("multi-user.target.wants")
        .join(RESTORE_UNIT)
        .exists();
    match (unit, wanted) {
        (true, true) => RebootProtection::Enabled,
        (true, false) => RebootProtection::InstalledNotEnabled,
        _ => RebootProtection::NotInstalled,
    }
}

pub fn describe(p: RebootProtection) -> &'static str {
    match p {
        RebootProtection::Enabled => "enabled",
        RebootProtection::InstalledNotEnabled => "installed-not-enabled",
        RebootProtection::NotInstalled => "not-installed",
    }
}

/// Renders the unit for `engine`, marked as torwell-managed. The path must be plain: it is
/// substituted into an `ExecStart=` line.
pub fn render_unit(engine: &Path) -> Result<String, Error> {
    let s = engine
        .to_str()
        .filter(|s| {
            s.starts_with('/')
                && !s.contains("..")
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | '+'))
        })
        .ok_or_else(|| {
            Error::Config(format!(
                "engine path {engine:?} is not a plain absolute path"
            ))
        })?;
    if !TEMPLATE.contains(PLACEHOLDER) {
        return Err(Error::State(
            "restore unit template lost its placeholder".into(),
        ));
    }
    Ok(format!("{MARKER}\n{}", TEMPLATE.replace(PLACEHOLDER, s)))
}

fn systemctl<R: Runner>(r: &mut R, p: &BootPaths, args: &[&str]) -> Result<(), Error> {
    let out = r
        .run(&Cmd::new(&p.systemctl, args, TIMEOUT))
        .map_err(|e| Error::Command {
            what: format!("systemctl {}", args.join(" ")),
            detail: e.to_string(),
        })?;
    if out.ok() {
        Ok(())
    } else {
        Err(Error::Command {
            what: format!("systemctl {}", args.join(" ")),
            detail: format!("exit {:?}: {}", out.code, out.stderr.trim()),
        })
    }
}

/// Installs the rendered unit and enables it. Refuses to replace a unit it did not write.
pub fn enable<R: Runner>(
    r: &mut R,
    p: &BootPaths,
    engine: &Path,
) -> Result<RebootProtection, Error> {
    check_trusted_exec(&p.systemctl, p.trusted_owner)?;
    let content = render_unit(engine)?;
    let dir = open_secure_dir(&p.unit_dir, p.trusted_owner, false)?;
    if let Some(existing) = dir.read_file(RESTORE_UNIT, 1 << 20)? {
        if !existing.starts_with(MARKER.as_bytes()) && existing != content.as_bytes() {
            return Err(Error::NotOwned(format!(
                "{} exists and is not managed by torwell",
                p.unit_dir.join(RESTORE_UNIT).display()
            )));
        }
    }
    dir.write_file_atomic(RESTORE_UNIT, content.as_bytes(), 0o644)?;
    systemctl(r, p, &["daemon-reload"])?;
    systemctl(r, p, &["enable", RESTORE_UNIT])?;
    let now = protection(&p.unit_dir);
    if now != RebootProtection::Enabled {
        return Err(Error::Command {
            what: "systemctl enable".into(),
            detail: format!("unit is {} after enable", describe(now)),
        });
    }
    Ok(now)
}

/// Disables the unit and removes the unit file only if torwell wrote it.
pub fn disable<R: Runner>(r: &mut R, p: &BootPaths) -> Result<RebootProtection, Error> {
    check_trusted_exec(&p.systemctl, p.trusted_owner)?;
    if protection(&p.unit_dir) == RebootProtection::NotInstalled {
        return Ok(RebootProtection::NotInstalled);
    }
    systemctl(r, p, &["disable", RESTORE_UNIT])?;
    let dir = open_secure_dir(&p.unit_dir, p.trusted_owner, false)?;
    if let Some(existing) = dir.read_file(RESTORE_UNIT, 1 << 20)? {
        if existing.starts_with(MARKER.as_bytes()) {
            dir.remove_file(RESTORE_UNIT)?;
            systemctl(r, p, &["daemon-reload"])?;
        }
    }
    let now = protection(&p.unit_dir);
    if now == RebootProtection::Enabled {
        return Err(Error::Command {
            what: "systemctl disable".into(),
            detail: "unit is still enabled".into(),
        });
    }
    Ok(now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use torwell_linux::Output;

    struct Fake {
        calls: Vec<String>,
        unit_dir: PathBuf,
        /// What a successful `enable` does to the filesystem (systemd's job).
        link_on_enable: bool,
        fail: Option<&'static str>,
    }

    impl Runner for Fake {
        fn run(&mut self, cmd: &Cmd) -> std::io::Result<Output> {
            self.calls.push(cmd.display());
            let verb = cmd.args[0].as_str();
            if self.fail == Some(verb) {
                return Ok(Output {
                    code: Some(1),
                    stdout: String::new(),
                    stderr: "boom\n".into(),
                });
            }
            let wants = self.unit_dir.join("multi-user.target.wants");
            match verb {
                "enable" if self.link_on_enable => {
                    std::fs::create_dir_all(&wants).unwrap();
                    std::fs::write(wants.join(RESTORE_UNIT), b"").unwrap();
                }
                "disable" => {
                    let _ = std::fs::remove_file(wants.join(RESTORE_UNIT));
                }
                _ => {}
            }
            Ok(Output {
                code: Some(0),
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }

    fn setup(name: &str) -> (BootPaths, PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("torwell-engine-boot-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("units")).unwrap();
        for d in [&dir, &dir.join("units")] {
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let ctl = dir.join("systemctl");
        std::fs::write(&ctl, b"x").unwrap();
        std::fs::set_permissions(&ctl, std::fs::Permissions::from_mode(0o755)).unwrap();
        let me = unsafe { libc::geteuid() };
        (
            BootPaths {
                unit_dir: dir.join("units"),
                systemctl: ctl,
                trusted_owner: me,
            },
            dir,
        )
    }

    fn fake(p: &BootPaths) -> Fake {
        Fake {
            calls: vec![],
            unit_dir: p.unit_dir.clone(),
            link_on_enable: true,
            fail: None,
        }
    }

    #[test]
    fn rendered_unit_has_marker_exec_line_and_no_placeholder() {
        let u = render_unit(Path::new("/usr/bin/torwell-engine")).unwrap();
        assert!(u.starts_with(MARKER));
        assert!(u.contains("ExecStart=/usr/bin/torwell-engine restore-at-boot"));
        assert!(!u.contains('@'));
        for bad in [
            "relative/engine",
            "/usr/bin/a b",
            "/usr/bin/a%b",
            "/usr/../bin/x",
            "/x\ny",
            "/x$y",
        ] {
            assert!(render_unit(Path::new(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn enable_installs_unit_runs_exact_commands_and_reports_enabled() {
        let (p, _d) = setup("enable");
        let mut r = fake(&p);
        let got = enable(&mut r, &p, Path::new("/usr/bin/torwell-engine")).unwrap();
        assert_eq!(got, RebootProtection::Enabled);
        let sc = p.systemctl.display();
        assert_eq!(
            r.calls,
            vec![
                format!("{sc} daemon-reload"),
                format!("{sc} enable torwell-restore.service")
            ]
        );
        let text = std::fs::read_to_string(p.unit_dir.join(RESTORE_UNIT)).unwrap();
        assert!(text.contains("ExecStart=/usr/bin/torwell-engine restore-at-boot"));
        assert!(!r
            .calls
            .iter()
            .any(|c| c.contains("--now") || c.contains("start")));
    }

    #[test]
    fn backend_and_local_protection_agree() {
        use torwell_linux::{Backend, Paths, SystemEnv, SystemRunner};
        let (p, _d) = setup("agree");
        let paths = Paths {
            unit_dir: p.unit_dir.clone(),
            ..Paths::default()
        };
        let backend = Backend::new(SystemRunner, SystemEnv::new(), paths);
        assert_eq!(backend.reboot_protection(), protection(&p.unit_dir));
        std::fs::write(p.unit_dir.join(RESTORE_UNIT), b"x").unwrap();
        assert_eq!(
            backend.reboot_protection(),
            RebootProtection::InstalledNotEnabled
        );
        assert_eq!(
            protection(&p.unit_dir),
            RebootProtection::InstalledNotEnabled
        );
        std::fs::create_dir_all(p.unit_dir.join("multi-user.target.wants")).unwrap();
        std::fs::write(
            p.unit_dir
                .join("multi-user.target.wants")
                .join(RESTORE_UNIT),
            b"",
        )
        .unwrap();
        assert_eq!(backend.reboot_protection(), RebootProtection::Enabled);
        assert_eq!(protection(&p.unit_dir), RebootProtection::Enabled);
    }

    #[test]
    fn enable_refuses_a_foreign_unit_and_reports_enable_without_link_as_failure() {
        let (p, _d) = setup("foreign");
        std::fs::write(
            p.unit_dir.join(RESTORE_UNIT),
            b"[Unit]\nDescription=someone else\n",
        )
        .unwrap();
        let mut r = fake(&p);
        assert!(matches!(
            enable(&mut r, &p, Path::new("/usr/bin/torwell-engine")),
            Err(Error::NotOwned(_))
        ));
        assert!(r.calls.is_empty());

        let (p, _d) = setup("nolink");
        let mut r = fake(&p);
        r.link_on_enable = false;
        let e = enable(&mut r, &p, Path::new("/usr/bin/torwell-engine")).unwrap_err();
        assert!(e.to_string().contains("installed-not-enabled"), "{e}");
    }

    #[test]
    fn systemctl_failure_is_an_error() {
        let (p, _d) = setup("fail");
        let mut r = fake(&p);
        r.fail = Some("enable");
        assert!(enable(&mut r, &p, Path::new("/usr/bin/torwell-engine")).is_err());
    }

    #[test]
    fn disable_removes_only_a_torwell_unit() {
        let (p, _d) = setup("disable");
        let mut r = fake(&p);
        enable(&mut r, &p, Path::new("/usr/bin/torwell-engine")).unwrap();
        let mut r = fake(&p);
        assert_eq!(disable(&mut r, &p).unwrap(), RebootProtection::NotInstalled);
        assert!(!p.unit_dir.join(RESTORE_UNIT).exists());

        // already absent: no systemctl call at all
        let mut r = fake(&p);
        assert_eq!(disable(&mut r, &p).unwrap(), RebootProtection::NotInstalled);
        assert!(r.calls.is_empty());

        // a foreign unit stays on disk
        std::fs::write(p.unit_dir.join(RESTORE_UNIT), b"[Unit]\n").unwrap();
        let mut r = fake(&p);
        disable(&mut r, &p).unwrap();
        assert!(p.unit_dir.join(RESTORE_UNIT).exists());
    }

    #[test]
    fn untrusted_systemctl_is_refused() {
        let (mut p, _d) = setup("untrusted");
        p.trusted_owner += 1;
        let mut r = fake(&p);
        assert!(enable(&mut r, &p, Path::new("/usr/bin/torwell-engine")).is_err());
        assert!(r.calls.is_empty());
    }
}
