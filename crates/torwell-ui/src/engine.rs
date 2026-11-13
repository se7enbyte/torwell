//! The engine transport. The UI never runs privileged work itself: it starts the fixed
//! sibling `torwell-engine` binary once per request, writes one JSON request to stdin,
//! reads one JSON response from stdout and keeps a bounded stderr diagnostic.
//!
//! No shell, no PATH lookup, no inherited environment, a timeout, and bounded output.
//! Blocking I/O runs on the caller's worker thread, never on the UI thread.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use torwell_protocol::{
    decode_response, encode_request, EngineState, ErrorKind, ProtocolError, Request, Response,
    MAX_MESSAGE_BYTES,
};

/// File name of the engine beside the UI executable.
pub const ENGINE_FILE_NAME: &str = if cfg!(windows) {
    "torwell-engine.exe"
} else {
    "torwell-engine"
};
/// Default wall-clock limit for one read-only request.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
/// Limit for start/stop/switch/recover: covers the polkit password prompt and Tor bootstrap,
/// and outlasts the engine's own 15 minute elevated limit so the engine, not the UI, decides.
/// Killing a start midway would leave the block applied with Tor not ready.
pub const MUTATING_TIMEOUT: Duration = Duration::from_secs(16 * 60);

fn limit_for(request: &[u8], read_only: Duration) -> Duration {
    match torwell_protocol::decode_request(request).map(|r| r.command) {
        Ok(
            torwell_protocol::Command::Start(_)
            | torwell_protocol::Command::Stop
            | torwell_protocol::Command::Switch(_)
            | torwell_protocol::Command::Recover,
        ) => MUTATING_TIMEOUT.max(read_only),
        _ => read_only,
    }
}
/// Stderr is a diagnostic only and is read up to this many bytes.
pub const MAX_STDERR_BYTES: u64 = 4096;

/// Raw result of one child exchange, before the protocol is checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawReply {
    pub stdout: Vec<u8>,
    pub stderr: String,
    pub exit_code: Option<i32>,
}

/// One request/response exchange. Implemented by [`ChildEngine`]; tests supply fakes.
pub trait Transport: Send + Sync {
    /// Sends one encoded request. `Err` means the engine could not be reached or misbehaved
    /// at the transport level: `EngineUnavailable`, `PermissionDenied`, `Timeout` or
    /// `MessageTooLarge`.
    fn exchange(&self, request: &[u8]) -> Result<RawReply, ProtocolError>;
}

/// Runs a fixed program per request. The program path is absolute and never searched.
#[derive(Debug, Clone)]
pub struct ChildEngine {
    program: PathBuf,
    args: Vec<OsString>,
    timeout: Duration,
}

impl ChildEngine {
    /// The `torwell-engine` binary next to the running `torwell-ui` executable.
    pub fn sibling(timeout: Duration) -> Self {
        let program = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|dir| dir.join(ENGINE_FILE_NAME)))
            .unwrap_or_else(|| PathBuf::from(ENGINE_FILE_NAME));
        Self::with_program(program, Vec::new(), timeout)
    }

    /// An explicit program and arguments. Used by tests with harmless commands.
    pub fn with_program(
        program: impl Into<PathBuf>,
        args: Vec<OsString>,
        timeout: Duration,
    ) -> Self {
        Self {
            program: program.into(),
            args,
            timeout,
        }
    }

    pub fn program(&self) -> &std::path::Path {
        &self.program
    }
}

fn engine_error(kind: ErrorKind, message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(kind, message)
}

impl Transport for ChildEngine {
    fn exchange(&self, request: &[u8]) -> Result<RawReply, ProtocolError> {
        if request.len() > MAX_MESSAGE_BYTES {
            return Err(engine_error(
                ErrorKind::MessageTooLarge,
                format!("engine request exceeds {MAX_MESSAGE_BYTES} bytes"),
            ));
        }
        if !self.program.is_file() {
            return Err(engine_error(
                ErrorKind::EngineUnavailable,
                format!(
                    "engine unavailable: {} is not installed beside torwell-ui",
                    ENGINE_FILE_NAME
                ),
            ));
        }
        let mut child = Command::new(&self.program)
            .args(&self.args)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::PermissionDenied => engine_error(
                    ErrorKind::PermissionDenied,
                    "permission denied starting the engine; elevation is not wired yet",
                ),
                _ => engine_error(
                    ErrorKind::EngineUnavailable,
                    format!("engine unavailable: {e}"),
                ),
            })?;

        // The request is small (<= 64 KiB) but the engine may not read it; write on a helper
        // thread so a stalled engine is caught by the timeout below instead of blocking here.
        let stdin = child.stdin.take();
        let payload = request.to_vec();
        let writer = thread::spawn(move || {
            if let Some(mut stdin) = stdin {
                let _ = stdin.write_all(&payload);
            }
        });

        let overflow = Arc::new(AtomicBool::new(false));
        let stdout = child.stdout.take();
        let flag = Arc::clone(&overflow);
        let out_reader = thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(out) = stdout {
                // One byte past the limit is enough to detect overflow without buffering more.
                let _ = out.take(MAX_MESSAGE_BYTES as u64 + 1).read_to_end(&mut buf);
            }
            if buf.len() > MAX_MESSAGE_BYTES {
                flag.store(true, Ordering::SeqCst);
            }
            buf
        });
        let stderr = child.stderr.take();
        let err_reader = thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(err) = stderr {
                let mut reader = err;
                let mut chunk = [0; 1024];
                loop {
                    match reader.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(count) => {
                            let remaining = MAX_STDERR_BYTES.saturating_sub(buf.len() as u64);
                            let retained = count.min(remaining as usize);
                            buf.extend_from_slice(&chunk[..retained]);
                        }
                    }
                }
            }
            String::from_utf8_lossy(&buf).into_owned()
        });

        let limit = limit_for(request, self.timeout);
        let deadline = Instant::now() + limit;
        let status = loop {
            if let Some(status) = child.try_wait().map_err(|e| {
                engine_error(
                    ErrorKind::Internal,
                    format!("waiting for engine failed: {e}"),
                )
            })? {
                break Some(status);
            }
            if overflow.load(Ordering::SeqCst) {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                let _ = writer.join();
                let _ = out_reader.join();
                let _ = err_reader.join();
                return Err(engine_error(
                    ErrorKind::Timeout,
                    format!("engine did not answer within {} ms", limit.as_millis()),
                ));
            }
            thread::sleep(Duration::from_millis(5));
        };
        let _ = writer.join();
        let stdout = out_reader.join().unwrap_or_default();
        let stderr = err_reader.join().unwrap_or_default();
        if overflow.load(Ordering::SeqCst) || status.is_none() {
            return Err(engine_error(
                ErrorKind::MessageTooLarge,
                format!("engine output exceeds {MAX_MESSAGE_BYTES} bytes"),
            ));
        }
        Ok(RawReply {
            stdout,
            stderr,
            exit_code: status.and_then(|s| s.code()),
        })
    }
}

/// Turns a raw exchange into the engine's state. An engine error response is passed
/// through. A success response from a non-zero exit is refused: the engine's own claim is
/// not trusted when the process reports failure.
pub fn interpret(reply: &RawReply) -> Result<EngineState, ProtocolError> {
    let response: Response = decode_response(&reply.stdout)?;
    match response.result {
        Err(error) => Err(error),
        Ok(state) if reply.exit_code == Some(0) => Ok(state),
        Ok(_) => Err(engine_error(
            ErrorKind::InvalidResponse,
            format!(
                "engine exited with status {:?} after a success response",
                reply.exit_code
            ),
        )),
    }
}

/// Encodes one request, performs the exchange and returns the engine state or the error,
/// plus the first stderr line. Runs on a worker thread, never on the UI thread.
pub fn send(
    transport: &dyn Transport,
    request: &Request,
) -> (Result<EngineState, ProtocolError>, String) {
    let bytes = match encode_request(request) {
        Ok(bytes) => bytes,
        Err(error) => return (Err(error), String::new()),
    };
    match transport.exchange(&bytes) {
        Err(error) => (Err(error), String::new()),
        Ok(raw) => {
            let stderr = raw.stderr.lines().next().unwrap_or_default().to_string();
            (interpret(&raw), stderr)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A harmless system program with fixed arguments; no shell is involved.
    fn plain_program(program: &str, args: &[&str]) -> ChildEngine {
        ChildEngine::with_program(
            program,
            args.iter().map(OsString::from).collect(),
            Duration::from_secs(5),
        )
    }

    #[test]
    fn missing_engine_is_unavailable_not_disconnected() {
        let engine = plain_program("/nonexistent/torwell-engine", &[]);
        let err = engine.exchange(b"{}").unwrap_err();
        assert_eq!(err.kind, ErrorKind::EngineUnavailable);
        assert!(err.message.starts_with("engine unavailable"));
    }

    #[test]
    fn echo_program_returns_bytes_that_fail_protocol_decode() {
        // `cat` echoes the request, which is a request, not a response: it must not decode as one.
        let engine = plain_program("/bin/cat", &[]);
        let raw = engine
            .exchange(br#"{"version":1,"command":"status"}"#)
            .unwrap();
        assert_eq!(raw.exit_code, Some(0));
        assert_eq!(
            interpret(&raw).unwrap_err().kind,
            ErrorKind::InvalidResponse
        );
    }

    #[test]
    fn timeout_kills_a_silent_engine() {
        let engine = ChildEngine::with_program(
            "/bin/sleep",
            vec![OsString::from("30")],
            Duration::from_millis(150),
        );
        let started = Instant::now();
        let err = engine.exchange(b"{}").unwrap_err();
        assert_eq!(err.kind, ErrorKind::Timeout);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn unbounded_output_is_cut_off_at_the_limit() {
        // `yes` writes forever; output must stop at the protocol limit, not grow.
        let engine = plain_program("/usr/bin/yes", &[]);
        let err = engine.exchange(b"{}").unwrap_err();
        assert_eq!(err.kind, ErrorKind::MessageTooLarge);
    }

    #[test]
    fn oversized_request_is_rejected_before_child_start() {
        let engine = plain_program("/nonexistent/torwell-engine", &[]);
        let err = engine
            .exchange(&vec![0; MAX_MESSAGE_BYTES + 1])
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::MessageTooLarge);
    }

    #[test]
    fn stderr_is_drained_but_retained_only_to_its_bound() {
        let engine = ChildEngine::with_program(
            "/usr/bin/python3",
            vec![
                OsString::from("-c"),
                OsString::from(
                    "import sys; sys.stderr.write('x' * 100000); sys.stdout.write('{}')",
                ),
            ],
            Duration::from_secs(5),
        );
        let reply = engine.exchange(b"{}").unwrap();
        assert_eq!(reply.stdout, b"{}");
        assert_eq!(reply.stderr.len(), MAX_STDERR_BYTES as usize);
    }

    #[test]
    fn success_response_from_failed_process_is_refused() {
        let raw = RawReply {
            stdout: br#"{"version":1,"status":"ok","state":{"phase":"unconfigured","bootstrap_percent":null,"verification":{"tor_bootstrap":"unknown","enforcement":"unknown","mac_readback":"unknown"},"mac_mode":"off","capabilities":[],"adapters":[],"plan":null,"diagnostic":null}}"#.to_vec(),
            stderr: String::new(),
            exit_code: Some(3),
        };
        assert_eq!(
            interpret(&raw).unwrap_err().kind,
            ErrorKind::InvalidResponse
        );
    }

    #[test]
    fn mutating_requests_get_the_long_limit_and_reads_keep_the_short_one() {
        use torwell_protocol::{encode_request, Command, Request};
        let short = Duration::from_millis(150);
        let enc = |c| encode_request(&Request::new(c)).unwrap();
        assert_eq!(limit_for(&enc(Command::Status), short), short);
        assert_eq!(limit_for(&enc(Command::Inspect), short), short);
        assert_eq!(limit_for(&enc(Command::Stop), short), MUTATING_TIMEOUT);
        assert_eq!(limit_for(&enc(Command::Recover), short), MUTATING_TIMEOUT);
        assert_eq!(limit_for(b"garbage", short), short);
    }
}
