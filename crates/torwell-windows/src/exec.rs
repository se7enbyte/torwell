//! Typed external command execution. Programs are absolute paths, arguments are a vector (never a
//! shell string), data crosses into PowerShell only through environment variables that fixed
//! script text reads as values, and every call has a timeout.

use std::ffi::OsString;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub env: Vec<(String, String)>,
    pub timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

impl CommandOutput {
    pub fn success(&self) -> bool {
        self.code == Some(0) && !self.timed_out
    }
}

pub trait CommandRunner {
    fn run(&self, spec: &CommandSpec) -> io::Result<CommandOutput>;
}

pub struct StdRunner;

impl CommandRunner for StdRunner {
    fn run(&self, spec: &CommandSpec) -> io::Result<CommandOutput> {
        if !spec.program.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "program path must be absolute",
            ));
        }
        let mut cmd = Command::new(&spec.program);
        cmd.args(&spec.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in &spec.env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn()?;
        let mut out = child.stdout.take().unwrap();
        let mut err = child.stderr.take().unwrap();
        let t_out = std::thread::spawn(move || {
            let mut b = Vec::new();
            let _ = out.by_ref().take(1 << 20).read_to_end(&mut b);
            b
        });
        let t_err = std::thread::spawn(move || {
            let mut b = Vec::new();
            let _ = err.by_ref().take(1 << 20).read_to_end(&mut b);
            b
        });
        let start = Instant::now();
        let (code, timed_out) = loop {
            if let Some(st) = child.try_wait()? {
                break (st.code(), false);
            }
            if start.elapsed() >= spec.timeout {
                let _ = child.kill();
                let _ = child.wait();
                break (None, true);
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        Ok(CommandOutput {
            code,
            stdout: String::from_utf8_lossy(&t_out.join().unwrap_or_default()).into_owned(),
            stderr: String::from_utf8_lossy(&t_err.join().unwrap_or_default()).into_owned(),
            timed_out,
        })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn spec(program: &str, args: &[&str], timeout: Duration) -> CommandSpec {
        CommandSpec {
            program: PathBuf::from(program),
            args: args.iter().map(OsString::from).collect(),
            env: vec![("TORWELL_X".into(), "a b; rm -rf /".into())],
            timeout,
        }
    }

    #[test]
    fn args_and_env_are_not_interpreted_by_a_shell() {
        let o = StdRunner
            .run(&spec(
                "/bin/sh",
                &["-c", "printf '%s|%s' \"$TORWELL_X\" \"$1\"", "sh", "$(id)"],
                Duration::from_secs(5),
            ))
            .unwrap();
        assert!(o.success());
        assert_eq!(o.stdout, "a b; rm -rf /|$(id)");
    }

    #[test]
    fn relative_program_is_rejected_and_timeout_kills() {
        assert!(StdRunner
            .run(&spec("sh", &[], Duration::from_secs(1)))
            .is_err());
        let o = StdRunner
            .run(&spec("/bin/sleep", &["5"], Duration::from_millis(100)))
            .unwrap();
        assert!(o.timed_out && !o.success());
    }
}
