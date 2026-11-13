//! Privilege escalation for mutating commands.
//!
//! The engine re-executes *itself* through `/usr/bin/pkexec`:
//! - the program is the absolute pkexec path, never looked up on `PATH`;
//! - the engine path comes from `/proc/self/exe`, never from `argv[0]` or the environment,
//!   and is refused unless it is root-owned, a regular file, not group/other-writable and
//!   reached through root-owned, non-writable directories (no symlinks);
//! - arguments are an array (no shell): `pkexec <engine> --no-escalate`;
//! - the child gets a cleared environment; the request bytes are forwarded on stdin;
//! - the reply is decoded and re-validated, never relayed blindly; the child's stderr is
//!   relayed bounded to our stderr.
//!
//! `--no-escalate` makes the elevated child refuse (instead of looping) if it somehow is not root.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use torwell_linux::fsx::check_trusted_exec;
use torwell_protocol::{decode_response, ErrorKind, ProtocolError, MAX_MESSAGE_BYTES};

use crate::reply::{clean, error, finalize, Reply, EXIT_ERROR};

/// The only program used for elevation.
pub const PKEXEC: &str = "/usr/bin/pkexec";
/// Marks the elevated child; see the module docs.
pub const NO_ESCALATE: &str = "--no-escalate";
/// How much of the child's stderr is kept and relayed.
pub const MAX_STDERR_BYTES: usize = 4096;
/// Upper bound for one elevated command (Tor bootstrap can take minutes).
pub const ELEVATED_TIMEOUT: Duration = Duration::from_secs(15 * 60);

pub trait Escalator {
    /// Runs the same request as root and returns the (re-validated) reply.
    fn escalate(&self, request: &[u8]) -> Result<Reply, ProtocolError>;
}

/// The exact argument vector passed to pkexec after the pkexec program itself.
pub fn pkexec_args(engine: &Path) -> Vec<OsString> {
    vec![
        engine.as_os_str().to_os_string(),
        OsString::from(NO_ESCALATE),
    ]
}

/// The complete argv, program first. Built here so tests can assert it exactly.
pub fn pkexec_argv(pkexec: &Path, engine: &Path) -> Vec<OsString> {
    let mut v = vec![pkexec.as_os_str().to_os_string()];
    v.extend(pkexec_args(engine));
    v
}

/// Resolves this executable through `proc_exe` (normally `/proc/self/exe`) and requires it
/// to be a trusted, installed copy. Shared by elevation and boot-protection.
pub fn trusted_self(proc_exe: &Path, owner: u32) -> Result<PathBuf, ProtocolError> {
    let exe = std::fs::read_link(proc_exe).map_err(|e| {
        error(
            ErrorKind::EngineUnavailable,
            &format!("engine unavailable: cannot resolve its own path: {e}"),
        )
    })?;
    check_trusted_exec(&exe, owner).map_err(|e| {
        error(
            ErrorKind::PermissionDenied,
            &format!(
                "elevation refused: {} is not a trusted installed engine ({e}). Install torwell-engine root-owned and not writable by others (for example /usr/bin/torwell-engine).",
                exe.display()
            ),
        )
    })?;
    Ok(exe)
}

#[derive(Debug, Clone)]
pub struct PkexecEscalator {
    pub pkexec: PathBuf,
    pub proc_exe: PathBuf,
    /// Uid that must own the engine and pkexec. 0 in production.
    pub trusted_owner: u32,
    pub timeout: Duration,
}

impl PkexecEscalator {
    pub fn system() -> Self {
        Self {
            pkexec: PathBuf::from(PKEXEC),
            proc_exe: PathBuf::from("/proc/self/exe"),
            trusted_owner: 0,
            timeout: ELEVATED_TIMEOUT,
        }
    }
}

impl Escalator for PkexecEscalator {
    fn escalate(&self, request: &[u8]) -> Result<Reply, ProtocolError> {
        let engine = trusted_self(&self.proc_exe, self.trusted_owner)?;
        check_trusted_exec(&self.pkexec, self.trusted_owner).map_err(|e| {
            error(
                ErrorKind::EngineUnavailable,
                &format!(
                    "engine unavailable: polkit's {} is missing or untrusted ({e}); install polkit",
                    self.pkexec.display()
                ),
            )
        })?;
        let relayed = relay(&self.pkexec, &pkexec_args(&engine), request, self.timeout)?;
        Ok(interpret(&relayed))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relayed {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub code: Option<i32>,
}

fn spawn(program: &Path, args: &[OsString]) -> std::io::Result<std::process::Child> {
    // `Text file busy` can happen when the program was just written by this process tree
    // (tests); retrying is harmless in production.
    let mut attempts = 0;
    loop {
        let r = Command::new(program)
            .args(args)
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();
        match r {
            Err(e) if e.raw_os_error() == Some(26) && attempts < 20 => {
                attempts += 1;
                std::thread::sleep(Duration::from_millis(25));
            }
            other => return other,
        }
    }
}

/// Runs `program args` with `stdin` forwarded, stdout bounded to the protocol limit and
/// stderr bounded to [`MAX_STDERR_BYTES`] (the rest is drained and dropped).
pub fn relay(
    program: &Path,
    args: &[OsString],
    stdin: &[u8],
    timeout: Duration,
) -> Result<Relayed, ProtocolError> {
    let mut child = spawn(program, args).map_err(|e| {
        let kind = if e.kind() == std::io::ErrorKind::PermissionDenied {
            ErrorKind::PermissionDenied
        } else {
            ErrorKind::EngineUnavailable
        };
        error(kind, &format!("cannot start {}: {e}", program.display()))
    })?;
    let input = stdin.to_vec();
    let mut child_stdin = child.stdin.take();
    let writer = std::thread::spawn(move || {
        if let Some(mut s) = child_stdin.take() {
            let _ = s.write_all(&input);
        }
    });
    let mut out = child.stdout.take();
    let out_t = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(o) = out.take() {
            let _ = o.take(MAX_MESSAGE_BYTES as u64 + 1).read_to_end(&mut buf);
        }
        buf
    });
    let mut err = child.stderr.take();
    let err_t = std::thread::spawn(move || {
        let mut kept = Vec::new();
        if let Some(mut e) = err.take() {
            let mut chunk = [0u8; 1024];
            while let Ok(n) = e.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                let room = MAX_STDERR_BYTES.saturating_sub(kept.len());
                kept.extend_from_slice(&chunk[..n.min(room)]);
            }
        }
        kept
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) => {}
            Err(e) => {
                let _ = child.kill();
                return Err(error(ErrorKind::Internal, &format!("waiting failed: {e}")));
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error(
                ErrorKind::Timeout,
                &format!(
                    "elevated engine did not finish within {} s",
                    timeout.as_secs()
                ),
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let _ = writer.join();
    let stdout = out_t.join().unwrap_or_default();
    let stderr = err_t.join().unwrap_or_default();
    if stdout.len() > MAX_MESSAGE_BYTES {
        return Err(error(
            ErrorKind::MessageTooLarge,
            "elevated engine output exceeds the protocol limit",
        ));
    }
    Ok(Relayed {
        stdout,
        stderr,
        code: status.code(),
    })
}

/// Turns the elevated child's result into this process's reply. A response is accepted only
/// if it decodes and validates; a success response additionally needs exit code 0.
pub fn interpret(r: &Relayed) -> Reply {
    let stderr_line = String::from_utf8_lossy(&r.stderr);
    if !stderr_line.trim().is_empty() {
        eprintln!(
            "torwell-engine (elevated): {}",
            clean(stderr_line.trim(), MAX_STDERR_BYTES)
        );
    }
    if let Ok(resp) = decode_response(&r.stdout) {
        return match (&resp.result, r.code) {
            (Err(_), _) | (Ok(_), Some(0)) => finalize(resp),
            (Ok(_), code) => finalize(torwell_protocol::Response::err(error(
                ErrorKind::InvalidResponse,
                &format!("elevated engine exited with {code:?} after a success response"),
            ))),
        };
    }
    let first = stderr_line.lines().next().unwrap_or("").trim();
    let note = if first.is_empty() {
        String::new()
    } else {
        format!(": {first}")
    };
    let (kind, msg) = match r.code {
        Some(126) => (
            ErrorKind::PermissionDenied,
            format!("authorization was dismissed or denied (pkexec exit 126){note}"),
        ),
        Some(127) => (
            ErrorKind::PermissionDenied,
            format!("polkit could not authorize or run the engine (pkexec exit 127); is org.torwell.engine.policy installed?{note}"),
        ),
        Some(c) => (
            ErrorKind::Internal,
            format!("elevated engine exited with status {c} without a valid response{note}"),
        ),
        None => (
            ErrorKind::Internal,
            "elevated engine was terminated by a signal".to_string(),
        ),
    };
    let mut reply = finalize(torwell_protocol::Response::err(error(kind, &msg)));
    reply.exit_code = EXIT_ERROR;
    reply
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use torwell_protocol::{encode_response, EngineState, Response};

    #[test]
    fn argv_is_exact_and_shell_free() {
        let argv = pkexec_argv(
            Path::new("/usr/bin/pkexec"),
            Path::new("/usr/bin/torwell-engine"),
        );
        let argv: Vec<&str> = argv.iter().map(|s| s.to_str().unwrap()).collect();
        assert_eq!(
            argv,
            [
                "/usr/bin/pkexec",
                "/usr/bin/torwell-engine",
                "--no-escalate"
            ]
        );
    }

    #[test]
    fn production_constants_are_fixed_absolute_paths() {
        let e = PkexecEscalator::system();
        assert_eq!(e.pkexec, Path::new("/usr/bin/pkexec"));
        assert_eq!(e.proc_exe, Path::new("/proc/self/exe"));
        assert_eq!(e.trusted_owner, 0);
    }

    fn tmpdir(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("torwell-engine-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    fn me() -> u32 {
        unsafe { libc::geteuid() }
    }

    #[test]
    fn untrusted_engine_is_refused_before_any_spawn() {
        // The test binary lives in a user-owned target dir: not root-owned.
        if me() == 0 {
            return;
        }
        let e = PkexecEscalator::system();
        let err = e.escalate(b"{}").unwrap_err();
        assert_eq!(err.kind, ErrorKind::PermissionDenied);
        assert!(
            err.message.contains("Install torwell-engine"),
            "{}",
            err.message
        );
    }

    #[test]
    fn writable_engine_is_refused_even_when_owner_matches() {
        let dir = tmpdir("writable");
        let exe = dir.join("engine");
        std::fs::write(&exe, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o775)).unwrap();
        let link = dir.join("self");
        std::os::unix::fs::symlink(&exe, &link).unwrap();
        let err = trusted_self(&link, me()).unwrap_err();
        assert_eq!(err.kind, ErrorKind::PermissionDenied);
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            trusted_self(&link, me()).unwrap(),
            exe.canonicalize().unwrap()
        );
        // other owner expected -> refused
        assert!(trusted_self(&link, me() + 1).is_err());
    }

    #[test]
    fn missing_pkexec_is_engine_unavailable() {
        let dir = tmpdir("nopkexec");
        let exe = dir.join("engine");
        std::fs::write(&exe, b"x").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = dir.join("self");
        std::os::unix::fs::symlink(&exe, &link).unwrap();
        let esc = PkexecEscalator {
            pkexec: dir.join("pkexec-missing"),
            proc_exe: link,
            trusted_owner: me(),
            timeout: Duration::from_secs(5),
        };
        assert_eq!(
            esc.escalate(b"{}").unwrap_err().kind,
            ErrorKind::EngineUnavailable
        );
    }

    /// A stand-in for pkexec: a script that records its argv and stdin and prints a reply.
    fn fake_pkexec(dir: &Path, body: &str) -> PathBuf {
        let p = dir.join("pkexec");
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    fn escalator_with(dir: &Path, pkexec: PathBuf) -> PkexecEscalator {
        let exe = dir.join("engine");
        std::fs::write(&exe, b"x").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = dir.join("self");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&exe, &link).unwrap();
        PkexecEscalator {
            pkexec,
            proc_exe: link,
            trusted_owner: me(),
            timeout: Duration::from_secs(10),
        }
    }

    #[test]
    fn relay_forwards_stdin_argv_and_validates_the_reply() {
        let dir = tmpdir("relay");
        let log = dir.join("log");
        let ok = String::from_utf8(encode_response(&Response::ok(EngineState::unknown())).unwrap())
            .unwrap();
        let body = format!(
            "echo \"$@\" > {log}\ncat >> {log}\nprintf '%s' '{ok}'",
            log = log.display(),
        );
        let esc = escalator_with(&dir, fake_pkexec(&dir, &body));
        let reply = esc.escalate(br#"{"version":1,"command":"stop"}"#).unwrap();
        assert_eq!(reply.exit_code, 0);
        let recorded = std::fs::read_to_string(&log).unwrap();
        let engine = dir.join("engine").canonicalize().unwrap();
        assert!(
            recorded.starts_with(&format!("{} --no-escalate\n", engine.display())),
            "{recorded}"
        );
        assert!(recorded.contains(r#"{"version":1,"command":"stop"}"#));
    }

    #[test]
    fn pkexec_dismissal_and_garbage_become_protocol_errors() {
        let dir = tmpdir("relay-err");
        let esc = escalator_with(
            &dir,
            fake_pkexec(
                &dir,
                "cat >/dev/null; echo 'Error: dismissed' >&2; exit 126",
            ),
        );
        let reply = esc.escalate(b"{}").unwrap();
        assert_eq!(reply.exit_code, EXIT_ERROR);
        let e = decode_response(&reply.stdout).unwrap().result.unwrap_err();
        assert_eq!(e.kind, ErrorKind::PermissionDenied);

        let esc = escalator_with(
            &dir,
            fake_pkexec(&dir, "cat >/dev/null; printf 'not json'; exit 0"),
        );
        let e = decode_response(&esc.escalate(b"{}").unwrap().stdout)
            .unwrap()
            .result
            .unwrap_err();
        assert_eq!(e.kind, ErrorKind::Internal);
    }

    #[test]
    fn a_success_response_from_a_failing_child_is_refused() {
        let dir = tmpdir("relay-code");
        let ok = String::from_utf8(encode_response(&Response::ok(EngineState::unknown())).unwrap())
            .unwrap();
        let esc = escalator_with(
            &dir,
            fake_pkexec(&dir, &format!("cat >/dev/null; printf '%s' '{ok}'; exit 3")),
        );
        let e = decode_response(&esc.escalate(b"{}").unwrap().stdout)
            .unwrap()
            .result
            .unwrap_err();
        assert_eq!(e.kind, ErrorKind::InvalidResponse);
    }

    #[test]
    fn an_unevidenced_connected_from_the_child_cannot_pass_through() {
        let dir = tmpdir("relay-lie");
        let lie = r#"{"version":1,"status":"ok","state":{"phase":"connected","bootstrap_percent":null,"verification":{"tor_bootstrap":"unknown","enforcement":"unknown","mac_readback":"not_run"},"mac_mode":"off","capabilities":[],"adapters":[],"plan":null,"diagnostic":null}}"#;
        let esc = escalator_with(
            &dir,
            fake_pkexec(&dir, &format!("cat >/dev/null; printf '%s' '{lie}'")),
        );
        let reply = esc.escalate(b"{}").unwrap();
        let text = String::from_utf8(reply.stdout).unwrap();
        assert!(!text.contains(r#""phase":"connected""#), "{text}");
    }

    #[test]
    fn oversized_child_output_is_cut_off() {
        let dir = tmpdir("relay-big");
        let esc = escalator_with(&dir, fake_pkexec(&dir, "cat >/dev/null; yes"));
        assert_eq!(
            esc.escalate(b"{}").unwrap_err().kind,
            ErrorKind::MessageTooLarge
        );
    }

    #[test]
    fn a_hung_child_times_out() {
        let dir = tmpdir("relay-hang");
        let mut esc = escalator_with(&dir, fake_pkexec(&dir, "exec sleep 30"));
        esc.timeout = Duration::from_millis(200);
        assert_eq!(esc.escalate(b"{}").unwrap_err().kind, ErrorKind::Timeout);
    }
}
