//! Responses. Wire form: `{"version":1,"status":"ok","state":{..}}` or
//! `{"version":1,"status":"error","error":{"kind":"..","message":".."}}`.
//!
//! [`EngineState::validate`] is part of decoding. It refuses `connected` unless Tor
//! bootstrap and enforcement both passed, and `blocked` unless enforcement passed. An engine
//! cannot report protection that its own evidence does not show.

use serde::{Deserialize, Serialize};
use torwell_core::capability::Support;
use torwell_core::config::{check_name, MacMode};

use crate::{
    bounded_text, ErrorKind, ProtocolError, MAX_DIAGNOSTIC_CHARS, MAX_LIST_ITEMS, PROTOCOL_VERSION,
};

/// Maximum length of a plan step, in characters.
pub const MAX_PLAN_STEP_CHARS: usize = 200;

/// A response to exactly one request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ResponseWire", into = "ResponseWire")]
pub struct Response {
    pub version: u32,
    pub result: Result<EngineState, ProtocolError>,
}

impl Response {
    pub fn ok(state: EngineState) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            result: Ok(state),
        }
    }

    pub fn err(error: ProtocolError) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            result: Err(error),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum StatusWire {
    Ok,
    Error,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResponseWire {
    version: u32,
    status: StatusWire,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    state: Option<EngineState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<ProtocolError>,
}

impl TryFrom<ResponseWire> for Response {
    type Error = ProtocolError;

    fn try_from(wire: ResponseWire) -> Result<Self, Self::Error> {
        if wire.version != PROTOCOL_VERSION {
            return Err(ProtocolError::new(
                ErrorKind::UnsupportedVersion,
                format!("response version {} is not supported", wire.version),
            ));
        }
        let invalid = |m: &str| ProtocolError::new(ErrorKind::InvalidResponse, m);
        let result = match (wire.status, wire.state, wire.error) {
            (StatusWire::Ok, Some(state), None) => {
                state.validate()?;
                Ok(state)
            }
            (StatusWire::Error, None, Some(error)) => {
                if !error.is_bounded() {
                    return Err(invalid(
                        "error message is too long or has control characters",
                    ));
                }
                Err(error)
            }
            _ => {
                return Err(invalid(
                    "`status` must match exactly one of `state` or `error`",
                ))
            }
        };
        Ok(Response {
            version: PROTOCOL_VERSION,
            result,
        })
    }
}

impl From<Response> for ResponseWire {
    fn from(response: Response) -> Self {
        let (status, state, error) = match response.result {
            Ok(state) => (StatusWire::Ok, Some(state), None),
            Err(error) => (StatusWire::Error, None, Some(error)),
        };
        ResponseWire {
            version: response.version,
            status,
            state,
            error,
        }
    }
}

/// Lifecycle phase as the engine reports it. Each value is a distinct, verified claim:
///
/// - `unconfigured`: nothing has been applied and no selection exists.
/// - `disconnected`: nothing is applied; a previous session ended cleanly.
/// - `starting`: enforcement may be in place while Tor bootstraps. `bootstrap_percent` is set.
/// - `connected`: Tor bootstrap and enforcement checks both passed (see [`EngineState::validate`]).
/// - `blocked`: fail-closed. Enforcement is verified active, Tor is not connected.
/// - `recovery_required`: a partial failure. Nothing may start until `recover` or `stop` succeeds.
/// - `unsupported`: this host or backend cannot provide the requested function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Unconfigured,
    Disconnected,
    Starting,
    Connected,
    Blocked,
    RecoveryRequired,
    Unsupported,
}

/// Outcome of one verification check. `not_run` and `unknown` are never treated as passing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyState {
    /// The check was not attempted.
    NotRun,
    Passed,
    Failed,
    /// The check could not be performed, so its result is unknown.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verification {
    /// Tor reached bootstrap completion through the configured SOCKS port.
    pub tor_bootstrap: VerifyState,
    /// Read-back of the active blocking policy shows Torwell-owned enforcement.
    pub enforcement: VerifyState,
    /// Read-back of the requested MAC address. `not_run` when MAC mode is off.
    pub mac_readback: VerifyState,
}

impl Verification {
    pub const UNKNOWN: Verification = Verification {
        tor_bootstrap: VerifyState::Unknown,
        enforcement: VerifyState::Unknown,
        mac_readback: VerifyState::Unknown,
    };
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capability {
    /// Stable identifier such as `linux.nftables`, as in `torwell_core::capability`.
    pub name: String,
    pub support: Support,
    /// Short human-readable note. It must not claim function that was not tested.
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterInfo {
    pub name: String,
    /// `supported` only when the engine validated a MAC read-back path for this adapter.
    pub mac_change: Support,
}

/// The engine's state for one command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineState {
    pub phase: Phase,
    /// Tor bootstrap percentage, 0 to 100. Present only in `starting`.
    pub bootstrap_percent: Option<u8>,
    pub verification: Verification,
    /// The MAC mode the engine holds for this session. `off` unless the user opted in.
    pub mac_mode: MacMode,
    pub capabilities: Vec<Capability>,
    pub adapters: Vec<AdapterInfo>,
    /// Inert plan steps, present only for `plan`. Never implies that anything was applied.
    pub plan: Option<Vec<String>>,
    /// Concise diagnostic for the user, at most [`MAX_DIAGNOSTIC_CHARS`] characters.
    pub diagnostic: Option<String>,
}

impl EngineState {
    /// An engine state that claims nothing: unconfigured, all verification unknown.
    pub fn unknown() -> Self {
        Self {
            phase: Phase::Unconfigured,
            bootstrap_percent: None,
            verification: Verification::UNKNOWN,
            mac_mode: MacMode::Off,
            capabilities: Vec::new(),
            adapters: Vec::new(),
            plan: None,
            diagnostic: None,
        }
    }

    /// Checks the protocol invariants that tie phases to evidence, plus bounds.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        let bad = |m: String| ProtocolError::new(ErrorKind::InvalidResponse, m);
        let v = self.verification;
        match self.phase {
            Phase::Connected => {
                let mac_ok = self.mac_mode == MacMode::Off || v.mac_readback == VerifyState::Passed;
                if v.tor_bootstrap != VerifyState::Passed
                    || v.enforcement != VerifyState::Passed
                    || !mac_ok
                {
                    return Err(bad(
                        "phase `connected` requires passed tor_bootstrap and enforcement (and mac_readback when MAC is on)"
                            .into(),
                    ));
                }
            }
            Phase::Blocked if v.enforcement != VerifyState::Passed => {
                return Err(bad(
                    "phase `blocked` requires passed enforcement evidence".into()
                ));
            }
            _ => {}
        }
        match (self.phase, self.bootstrap_percent) {
            (Phase::Starting, Some(p)) if p <= 100 => {}
            (Phase::Starting, None) => {}
            (Phase::Starting, Some(_)) => {
                return Err(bad("bootstrap_percent must be 0 to 100".into()))
            }
            (_, None) => {}
            (_, Some(_)) => {
                return Err(bad(
                    "bootstrap_percent is only allowed in phase `starting`".into()
                ))
            }
        }
        if self.capabilities.len() > MAX_LIST_ITEMS || self.adapters.len() > MAX_LIST_ITEMS {
            return Err(bad(format!(
                "capabilities and adapters are limited to {MAX_LIST_ITEMS} items"
            )));
        }
        for c in &self.capabilities {
            if !bounded_text(&c.name, 64) || !bounded_text(&c.detail, 200) {
                return Err(bad(
                    "capability name or detail is too long or has control characters".into(),
                ));
            }
        }
        for a in &self.adapters {
            if check_name(&a.name).is_err() {
                return Err(bad("adapter name is invalid".into()));
            }
        }
        if let Some(steps) = &self.plan {
            if steps.len() > MAX_LIST_ITEMS
                || steps.iter().any(|s| !bounded_text(s, MAX_PLAN_STEP_CHARS))
            {
                return Err(bad("plan steps exceed the list or length bounds".into()));
            }
        }
        if let Some(d) = &self.diagnostic {
            if !bounded_text(d, MAX_DIAGNOSTIC_CHARS) {
                return Err(bad(format!(
                    "diagnostic exceeds {MAX_DIAGNOSTIC_CHARS} characters"
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decode_response, encode_response};

    fn state(phase: Phase, v: Verification) -> EngineState {
        EngineState {
            phase,
            verification: v,
            ..EngineState::unknown()
        }
    }

    const ALL_PASSED: Verification = Verification {
        tor_bootstrap: VerifyState::Passed,
        enforcement: VerifyState::Passed,
        mac_readback: VerifyState::NotRun,
    };

    #[test]
    fn connected_requires_tor_and_enforcement_evidence() {
        assert!(state(Phase::Connected, ALL_PASSED).validate().is_ok());
        let no_tor = Verification {
            tor_bootstrap: VerifyState::Unknown,
            ..ALL_PASSED
        };
        assert_eq!(
            state(Phase::Connected, no_tor).validate().unwrap_err().kind,
            ErrorKind::InvalidResponse
        );
        let no_enf = Verification {
            enforcement: VerifyState::Failed,
            ..ALL_PASSED
        };
        assert!(state(Phase::Connected, no_enf).validate().is_err());
    }

    #[test]
    fn connected_with_mac_on_requires_mac_readback() {
        let mut s = state(Phase::Connected, ALL_PASSED);
        s.mac_mode = MacMode::RandomOnApply;
        assert!(s.validate().is_err());
        s.verification.mac_readback = VerifyState::Passed;
        assert!(s.validate().is_ok());
    }

    #[test]
    fn blocked_requires_verified_enforcement_not_just_intent() {
        let unknown = Verification::UNKNOWN;
        assert!(state(Phase::Blocked, unknown).validate().is_err());
        let enforced = Verification {
            enforcement: VerifyState::Passed,
            ..Verification::UNKNOWN
        };
        assert!(state(Phase::Blocked, enforced).validate().is_ok());
    }

    #[test]
    fn starting_may_carry_bootstrap_percent_other_phases_may_not() {
        let mut s = state(Phase::Starting, Verification::UNKNOWN);
        s.bootstrap_percent = Some(42);
        assert!(s.validate().is_ok());
        s.bootstrap_percent = Some(101);
        assert!(s.validate().is_err());
        let mut d = state(Phase::Disconnected, Verification::UNKNOWN);
        d.bootstrap_percent = Some(10);
        assert!(d.validate().is_err());
    }

    #[test]
    fn unknown_state_claims_nothing() {
        let s = EngineState::unknown();
        assert_eq!(s.phase, Phase::Unconfigured);
        assert_eq!(s.verification, Verification::UNKNOWN);
        assert!(s.validate().is_ok());
    }

    #[test]
    fn list_and_text_bounds_are_enforced() {
        let mut s = EngineState::unknown();
        s.plan = Some(vec!["x".repeat(MAX_PLAN_STEP_CHARS + 1)]);
        assert!(s.validate().is_err());
        s.plan = Some(vec!["ok".into(); MAX_LIST_ITEMS + 1]);
        assert!(s.validate().is_err());
        s.plan = None;
        s.diagnostic = Some("d".repeat(MAX_DIAGNOSTIC_CHARS + 1));
        assert!(s.validate().is_err());
        s.diagnostic = Some("bell\u{7}".into());
        assert!(s.validate().is_err());
    }

    #[test]
    fn ok_response_round_trips() {
        let response = Response::ok(state(Phase::Disconnected, Verification::UNKNOWN));
        let bytes = encode_response(&response).unwrap();
        assert_eq!(decode_response(&bytes).unwrap(), response);
    }

    #[test]
    fn error_response_round_trips() {
        let response = Response::err(ProtocolError::new(
            ErrorKind::PermissionDenied,
            "engine needs elevation",
        ));
        let bytes = encode_response(&response).unwrap();
        assert!(String::from_utf8_lossy(&bytes).contains("\"status\":\"error\""));
        assert_eq!(decode_response(&bytes).unwrap(), response);
    }

    #[test]
    fn forged_connected_response_is_refused_on_decode() {
        let json = br#"{"version":1,"status":"ok","state":{"phase":"connected","bootstrap_percent":null,
            "verification":{"tor_bootstrap":"unknown","enforcement":"unknown","mac_readback":"not_run"},
            "mac_mode":"off","capabilities":[],"adapters":[],"plan":null,"diagnostic":null}}"#;
        assert_eq!(
            decode_response(json).unwrap_err().kind,
            ErrorKind::InvalidResponse
        );
    }

    #[test]
    fn unknown_response_fields_and_versions_are_refused() {
        let extra = br#"{"version":1,"status":"error","error":{"kind":"internal","message":"x"},"stdout":"y"}"#;
        assert_eq!(
            decode_response(extra).unwrap_err().kind,
            ErrorKind::InvalidResponse
        );
        let newer = br#"{"version":2,"status":"error","error":{"kind":"internal","message":"x"}}"#;
        assert_eq!(
            decode_response(newer).unwrap_err().kind,
            ErrorKind::UnsupportedVersion
        );
        let both = br#"{"version":1,"status":"ok","state":null,"error":{"kind":"internal","message":"x"}}"#;
        assert_eq!(
            decode_response(both).unwrap_err().kind,
            ErrorKind::InvalidResponse
        );
    }

    #[test]
    fn encode_refuses_states_that_violate_invariants() {
        let forged = Response::ok(state(Phase::Connected, Verification::UNKNOWN));
        assert_eq!(
            encode_response(&forged).unwrap_err().kind,
            ErrorKind::InvalidResponse
        );
    }

    #[test]
    fn oversized_response_is_refused() {
        let big = vec![b'{'; crate::MAX_MESSAGE_BYTES + 1];
        assert_eq!(
            decode_response(&big).unwrap_err().kind,
            ErrorKind::MessageTooLarge
        );
    }
}
