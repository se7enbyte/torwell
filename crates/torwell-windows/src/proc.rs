//! Managed long-running child processes (Tor, bridge) and PID ownership checks.

use std::ffi::OsString;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcSpec {
    pub exe: PathBuf,
    pub args: Vec<OsString>,
    pub cwd: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineEvent {
    Line(String),
    /// Nothing arrived within the wait.
    Idle,
    /// Output closed (process most likely exited).
    Closed,
}

pub trait ManagedProcess {
    fn pid(&self) -> u32;
    /// `Some(code)` once exited (`-1` if killed by signal).
    fn try_wait(&mut self) -> Option<i32>;
    fn kill(&mut self);
    /// Waits up to `timeout` for the next stdout/stderr line.
    fn recv_line(&mut self, timeout: Duration) -> LineEvent;
}

pub trait ProcessLauncher {
    fn launch(&self, spec: &ProcSpec) -> io::Result<Box<dyn ManagedProcess>>;
}

/// Identity of arbitrary PIDs, used so recovery only terminates processes whose image is the
/// recorded verified executable (PIDs are reused).
pub trait ProcessControl {
    fn image_path(&self, pid: u32) -> Option<PathBuf>;
    fn terminate(&self, pid: u32) -> io::Result<()>;
    fn is_alive(&self, pid: u32) -> bool;
}

pub struct StdLauncher;

struct StdProcess {
    child: Child,
    rx: Receiver<String>,
}

impl ProcessLauncher for StdLauncher {
    fn launch(&self, spec: &ProcSpec) -> io::Result<Box<dyn ManagedProcess>> {
        if !spec.exe.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "executable path must be absolute",
            ));
        }
        let mut cmd = Command::new(&spec.exe);
        cmd.args(&spec.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(cwd) = &spec.cwd {
            cmd.current_dir(cwd);
        }
        let mut child = cmd.spawn()?;
        let (tx, rx) = mpsc::channel();
        for stream in [
            child
                .stdout
                .take()
                .map(|s| Box::new(s) as Box<dyn io::Read + Send>),
            child
                .stderr
                .take()
                .map(|s| Box::new(s) as Box<dyn io::Read + Send>),
        ]
        .into_iter()
        .flatten()
        {
            let tx = tx.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(stream).lines().map_while(Result::ok) {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            });
        }
        Ok(Box::new(StdProcess { child, rx }))
    }
}

impl ManagedProcess for StdProcess {
    fn pid(&self) -> u32 {
        self.child.id()
    }
    fn try_wait(&mut self) -> Option<i32> {
        self.child
            .try_wait()
            .ok()
            .flatten()
            .map(|s| s.code().unwrap_or(-1))
    }
    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
    fn recv_line(&mut self, timeout: Duration) -> LineEvent {
        match self.rx.recv_timeout(timeout) {
            Ok(l) => LineEvent::Line(l),
            Err(RecvTimeoutError::Timeout) => LineEvent::Idle,
            Err(RecvTimeoutError::Disconnected) => LineEvent::Closed,
        }
    }
}

/// Windows paths compare case-insensitively; this helper is used for recorded-image checks.
pub fn same_image(a: &Path, b: &Path) -> bool {
    a.to_string_lossy()
        .eq_ignore_ascii_case(&b.to_string_lossy())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn launches_and_reads_lines() {
        let spec = ProcSpec {
            exe: "/bin/sh".into(),
            args: vec!["-c".into(), "echo one; echo two".into()],
            cwd: None,
        };
        let mut p = StdLauncher.launch(&spec).unwrap();
        assert_eq!(
            p.recv_line(Duration::from_secs(5)),
            LineEvent::Line("one".into())
        );
        assert_eq!(
            p.recv_line(Duration::from_secs(5)),
            LineEvent::Line("two".into())
        );
        p.kill();
    }

    #[test]
    fn relative_executable_rejected() {
        let spec = ProcSpec {
            exe: "sh".into(),
            args: vec![],
            cwd: None,
        };
        assert!(StdLauncher.launch(&spec).is_err());
    }

    #[test]
    fn image_compare_is_case_insensitive() {
        assert!(same_image(
            Path::new(r"C:\Tor\TOR.EXE"),
            Path::new(r"c:\tor\tor.exe")
        ));
    }
}
