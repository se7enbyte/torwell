//! Command execution seam. Only absolute programs and argument arrays; no shell.

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cmd {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub stdin: Option<Vec<u8>>,
    pub timeout: Duration,
}

impl Cmd {
    pub fn new(program: &std::path::Path, args: &[&str], timeout: Duration) -> Self {
        Self {
            program: program.to_path_buf(),
            args: args.iter().map(|s| s.to_string()).collect(),
            stdin: None,
            timeout,
        }
    }

    pub fn with_stdin(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.stdin = Some(data.into());
        self
    }

    /// Display form for logs and tests only; never executed.
    pub fn display(&self) -> String {
        let mut s = self.program.display().to_string();
        for a in &self.args {
            s.push(' ');
            s.push_str(a);
        }
        s
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    /// `None` when terminated by a signal.
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn ok(&self) -> bool {
        self.code == Some(0)
    }
}

pub trait Runner {
    /// A timeout must return `io::ErrorKind::TimedOut` after killing the child.
    fn run(&mut self, cmd: &Cmd) -> io::Result<Output>;
}

/// Spawns real processes with a cleared environment (fixed `LC_ALL=C`).
pub struct SystemRunner;

const MAX_CAPTURE: u64 = 1 << 20;

impl Runner for SystemRunner {
    fn run(&mut self, cmd: &Cmd) -> io::Result<Output> {
        if !cmd.program.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "program must be absolute",
            ));
        }
        if cmd.args.iter().any(|a| a.contains('\0')) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "NUL in argument",
            ));
        }
        let mut child = Command::new(&cmd.program)
            .args(&cmd.args)
            .env_clear()
            .env("LC_ALL", "C")
            .env("PATH", "/usr/bin")
            .stdin(if cmd.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let (Some(data), Some(mut stdin)) = (cmd.stdin.clone(), child.stdin.take()) {
            std::thread::spawn(move || {
                let _ = stdin.write_all(&data);
            });
        }
        let mut out = child.stdout.take().expect("piped");
        let mut err = child.stderr.take().expect("piped");
        let t_out = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = (&mut out).take(MAX_CAPTURE).read_to_string(&mut s);
            s
        });
        let t_err = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = (&mut err).take(MAX_CAPTURE).read_to_string(&mut s);
            s
        });
        let deadline = Instant::now() + cmd.timeout;
        let status = loop {
            if let Some(st) = child.try_wait()? {
                break st;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(io::ErrorKind::TimedOut, "command timed out"));
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        Ok(Output {
            code: status.code(),
            stdout: t_out.join().unwrap_or_default(),
            stderr: t_err.join().unwrap_or_default(),
        })
    }
}
