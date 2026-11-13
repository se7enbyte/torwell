//! Typed, versioned contract between the unprivileged `torwell-ui` process and the
//! `torwell-engine` child process.
//!
//! One request is written to the engine's stdin as one JSON object; the engine writes one
//! JSON response object to stdout and diagnostics to stderr. Both directions are bounded by
//! [`MAX_MESSAGE_BYTES`]. Unknown fields, unknown commands and any version other than
//! [`PROTOCOL_VERSION`] are refused. The full wire schema is documented in `docs/UI.md`.
//!
//! This crate performs no I/O beyond encoding and decoding bytes.

mod request;
mod response;

use serde::{Deserialize, Serialize};

pub use request::{Adapter, Command, Request, Selection};
pub use response::{
    AdapterInfo, Capability, EngineState, Phase, Response, Verification, VerifyState,
};
pub use torwell_core::{Config, MacMode, Support};

/// The only protocol version this build speaks.
pub const PROTOCOL_VERSION: u32 = 1;
/// Upper bound for one request or one response, in bytes.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;
/// Upper bound for free-text diagnostics, in characters.
pub const MAX_DIAGNOSTIC_CHARS: usize = 512;
/// Upper bound for list fields (capabilities, adapters, plan steps).
pub const MAX_LIST_ITEMS: usize = 32;

/// Machine-readable error category. Engines may return the first eight; the UI also uses
/// the last four for failures of the transport itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    InvalidRequest,
    UnsupportedVersion,
    PermissionDenied,
    Unsupported,
    PreconditionFailed,
    AdapterUnavailable,
    Busy,
    Internal,
    EngineUnavailable,
    Timeout,
    MessageTooLarge,
    InvalidResponse,
}

/// An error that is shown to the user. `message` is bounded to [`MAX_DIAGNOSTIC_CHARS`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolError {
    pub kind: ErrorKind,
    pub message: String,
}

impl ProtocolError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// Whether the message respects [`MAX_DIAGNOSTIC_CHARS`] and has no control characters.
    pub fn is_bounded(&self) -> bool {
        bounded_text(&self.message, MAX_DIAGNOSTIC_CHARS)
    }
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for ProtocolError {}

/// Serializes a request, refusing anything over [`MAX_MESSAGE_BYTES`].
pub fn encode_request(request: &Request) -> Result<Vec<u8>, ProtocolError> {
    request.validate()?;
    encode(request, ErrorKind::MessageTooLarge)
}

/// Parses a request. Refuses oversized input, unknown versions, unknown fields and
/// commands, and invalid configuration or adapter names.
pub fn decode_request(bytes: &[u8]) -> Result<Request, ProtocolError> {
    decode(bytes, ErrorKind::InvalidRequest)
}

/// Serializes a response, refusing anything over [`MAX_MESSAGE_BYTES`] and states that
/// break [`EngineState::validate`].
pub fn encode_response(response: &Response) -> Result<Vec<u8>, ProtocolError> {
    if let Ok(state) = &response.result {
        state.validate()?;
    }
    encode(response, ErrorKind::MessageTooLarge)
}

/// Parses a response. Any invalid or unsupported response becomes
/// [`ErrorKind::InvalidResponse`] (or [`ErrorKind::UnsupportedVersion`] for other versions),
/// so a broken engine can never report a state the protocol forbids.
pub fn decode_response(bytes: &[u8]) -> Result<Response, ProtocolError> {
    decode(bytes, ErrorKind::InvalidResponse)
}

fn encode<T: Serialize>(value: &T, too_large: ErrorKind) -> Result<Vec<u8>, ProtocolError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|e| ProtocolError::new(ErrorKind::Internal, format!("encode failed: {e}")))?;
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::new(
            too_large,
            format!(
                "message is {} bytes; limit is {MAX_MESSAGE_BYTES}",
                bytes.len()
            ),
        ));
    }
    Ok(bytes)
}

/// Checks size and version before strict parsing, so a future version is reported as such
/// rather than as an unknown field.
fn decode<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    bad: ErrorKind,
) -> Result<T, ProtocolError> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::new(
            ErrorKind::MessageTooLarge,
            format!(
                "message is {} bytes; limit is {MAX_MESSAGE_BYTES}",
                bytes.len()
            ),
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| ProtocolError::new(bad, format!("malformed JSON: {e}")))?;
    match value.get("version").and_then(serde_json::Value::as_u64) {
        Some(v) if v == u64::from(PROTOCOL_VERSION) => {}
        Some(v) => {
            return Err(ProtocolError::new(
                ErrorKind::UnsupportedVersion,
                format!(
                    "protocol version {v} is not supported; this build speaks {PROTOCOL_VERSION}"
                ),
            ));
        }
        None => return Err(ProtocolError::new(bad, "missing or non-integer `version`")),
    }
    serde_json::from_value(value)
        .map_err(|e| ProtocolError::new(bad, format!("invalid message: {e}")))
}

/// True when `text` has at most `max` characters and no control characters.
pub(crate) fn bounded_text(text: &str, max: usize) -> bool {
    text.chars().count() <= max && !text.chars().any(char::is_control)
}
