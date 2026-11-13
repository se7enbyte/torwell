//! One finished reply: the bytes for stdout and the process exit code.
//!
//! Every response leaves through [`finalize`], which runs the protocol's own validation
//! (`encode_response`). A state that claims more than its evidence shows can therefore never
//! reach stdout: it is replaced by an `internal` error.

use torwell_protocol::{encode_response, ErrorKind, ProtocolError, Response, MAX_DIAGNOSTIC_CHARS};

/// Exit code for a success response.
pub const EXIT_OK: i32 = 0;
/// Exit code for an error response (the JSON error is still on stdout).
pub const EXIT_ERROR: i32 = 1;
/// Exit code for command-line misuse and non-protocol subcommand failures.
pub const EXIT_USAGE: i32 = 2;
/// Exit code when stdout could not be written.
pub const EXIT_IO: i32 = 3;

const FALLBACK: &[u8] = br#"{"version":1,"status":"error","error":{"kind":"internal","message":"engine failed to encode a response"}}"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub stdout: Vec<u8>,
    pub exit_code: i32,
}

/// Replaces control characters and cuts to `max` characters (the last one is an ellipsis).
pub fn clean(text: &str, max: usize) -> String {
    let mut out: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if out.chars().count() > max {
        out = out.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
    }
    out
}

/// Joins `main` and an optional `suffix` into one diagnostic of at most
/// [`MAX_DIAGNOSTIC_CHARS`]. The suffix is kept whole; `main` is cut when needed.
pub fn diagnostic(main: &str, suffix: Option<&str>) -> String {
    match suffix {
        None => clean(main, MAX_DIAGNOSTIC_CHARS),
        Some(s) => {
            let s = clean(s, MAX_DIAGNOSTIC_CHARS / 2);
            let room = MAX_DIAGNOSTIC_CHARS - s.chars().count() - 1;
            format!("{} {}", clean(main, room), s)
        }
    }
}

pub fn error(kind: ErrorKind, message: &str) -> ProtocolError {
    ProtocolError::new(kind, clean(message, MAX_DIAGNOSTIC_CHARS))
}

pub fn error_reply(kind: ErrorKind, message: &str) -> Reply {
    finalize(Response::err(error(kind, message)))
}

/// Encodes a response, falling back to an `internal` error if the protocol refuses it.
pub fn finalize(response: Response) -> Reply {
    let code = if response.result.is_ok() {
        EXIT_OK
    } else {
        EXIT_ERROR
    };
    match encode_response(&response) {
        Ok(stdout) => Reply {
            stdout,
            exit_code: code,
        },
        Err(e) => {
            let fallback = Response::err(error(
                ErrorKind::Internal,
                &format!(
                    "engine produced a response the protocol refuses: {}",
                    e.message
                ),
            ));
            Reply {
                stdout: encode_response(&fallback).unwrap_or_else(|_| FALLBACK.to_vec()),
                exit_code: EXIT_ERROR,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use torwell_protocol::{EngineState, Phase};

    #[test]
    fn clean_strips_controls_and_bounds() {
        assert_eq!(clean("a\nb\u{0}c", 10), "a b c");
        let long = "x".repeat(900);
        let c = clean(&long, 512);
        assert_eq!(c.chars().count(), 512);
        assert!(c.ends_with('…'));
    }

    #[test]
    fn diagnostic_keeps_suffix_and_bound() {
        let d = diagnostic(&"m".repeat(900), Some("SUFFIX"));
        assert!(d.chars().count() <= MAX_DIAGNOSTIC_CHARS);
        assert!(d.ends_with("SUFFIX"));
    }

    #[test]
    fn unevidenced_connected_never_reaches_stdout() {
        let mut state = EngineState::unknown();
        state.phase = Phase::Connected;
        let reply = finalize(Response::ok(state));
        assert_eq!(reply.exit_code, EXIT_ERROR);
        let text = String::from_utf8(reply.stdout).unwrap();
        assert!(text.contains(r#""status":"error""#), "{text}");
        assert!(!text.contains(r#""phase":"connected""#));
    }
}
