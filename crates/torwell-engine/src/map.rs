//! Pure mapping from backend results to protocol states and errors.
//!
//! Rules that keep the output honest:
//! - `connected` only from live evidence (both checks passed) or a successful `start` whose
//!   own evidence passed; anything else degrades, never upgrades.
//! - `blocked` only where the backend verified enforcement (live check, or the backend's own
//!   post-failure re-verification during `start`).
//! - persisted state alone is "unknown" evidence: it never yields `connected` or `blocked`.
//! - the reboot-protection capability is always listed; a diagnostic claims reboot protection
//!   only when the restore unit is installed and enabled.

use torwell_core::{Check, Config, MacMode, State, Support};
use torwell_linux::{
    Error, LiveStatus, OpFailure, RebootProtection, StartOutcome, Status, StopOutcome,
};
use torwell_protocol::{
    Capability, EngineState, ErrorKind, Phase, ProtocolError, Response, Verification, VerifyState,
};

use crate::reply::{diagnostic, error};

pub const REBOOT_CAPABILITY: &str = "linux.reboot_protection";

pub fn error_kind(e: &Error) -> ErrorKind {
    match e {
        Error::NotRoot => ErrorKind::PermissionDenied,
        Error::Config(_) => ErrorKind::InvalidRequest,
        Error::Locked => ErrorKind::Busy,
        Error::Preflight(_)
        | Error::UnsafePath(_)
        | Error::ForeignTable
        | Error::NotOwned(_)
        | Error::WrongState(_) => ErrorKind::PreconditionFailed,
        Error::Mac { .. } => ErrorKind::AdapterUnavailable,
        Error::Command { .. }
        | Error::Tor(_)
        | Error::Enforcement(_)
        | Error::Io(_)
        | Error::State(_) => ErrorKind::Internal,
    }
}

pub fn protocol_error(e: &Error) -> ProtocolError {
    error(error_kind(e), &e.to_string())
}

fn verify(c: Check) -> VerifyState {
    match c {
        Check::NotRun => VerifyState::NotRun,
        Check::Passed => VerifyState::Passed,
        Check::Failed => VerifyState::Failed,
    }
}

pub fn reboot_capability(rp: RebootProtection) -> Capability {
    let (support, detail) = match rp {
        RebootProtection::Enabled => (
            Support::Supported,
            "restore unit installed and enabled (file presence only; a reboot was not tested)",
        ),
        RebootProtection::InstalledNotEnabled => (
            Support::Unsupported,
            "restore unit installed but not enabled: traffic is NOT blocked after a reboot",
        ),
        RebootProtection::NotInstalled => (
            Support::Unsupported,
            "restore unit not installed: traffic is NOT blocked after a reboot",
        ),
    };
    Capability {
        name: REBOOT_CAPABILITY.into(),
        support,
        detail: detail.into(),
    }
}

fn reboot_suffix(rp: RebootProtection) -> &'static str {
    match rp {
        RebootProtection::Enabled => "Reboot protection: restore unit enabled (not boot-tested).",
        _ => "Reboot protection: NOT enabled; traffic is not blocked after a reboot (torwell-engine boot-protection enable).",
    }
}

fn base(phase: Phase, v: Verification, mac_mode: MacMode, rp: RebootProtection) -> EngineState {
    EngineState {
        phase,
        bootstrap_percent: None,
        verification: v,
        mac_mode,
        capabilities: vec![reboot_capability(rp)],
        adapters: Vec::new(),
        plan: None,
        diagnostic: None,
    }
}

const NONE_RUN: Verification = Verification {
    tor_bootstrap: VerifyState::NotRun,
    enforcement: VerifyState::NotRun,
    mac_readback: VerifyState::NotRun,
};

fn unknown_for(mac_mode: MacMode) -> Verification {
    Verification {
        tor_bootstrap: VerifyState::Unknown,
        enforcement: VerifyState::Unknown,
        mac_readback: if mac_mode == MacMode::Off {
            VerifyState::NotRun
        } else {
            VerifyState::Unknown
        },
    }
}

fn with_diag(mut s: EngineState, main: &str, protecting: Option<RebootProtection>) -> EngineState {
    s.diagnostic = Some(diagnostic(main, protecting.map(reboot_suffix)));
    s
}

/// State derived from persisted state, plus live evidence when the caller is root and ran
/// `inspect_live`. `live == None` means "not verifiable here".
pub fn persisted_state(
    st: &Status,
    live: Option<&LiveStatus>,
    rp: RebootProtection,
) -> EngineState {
    let mac_mode = if st.mac.is_some() {
        MacMode::RandomOnApply
    } else {
        MacMode::Off
    };
    let unknown = unknown_for(mac_mode);
    match &st.state {
        State::Idle => with_diag(
            base(Phase::Disconnected, NONE_RUN, MacMode::Off, rp),
            "No Torwell state on disk: nothing is applied.",
            None,
        ),
        State::Starting | State::Connected => match live {
            None => with_diag(
                base(Phase::Starting, unknown, mac_mode, rp),
                "Persisted state says active or starting; live verification needs root, so connected is not claimed.",
                Some(rp),
            ),
            Some(l) => live_state(st, l, mac_mode, rp, false),
        },
        State::Blocked { reason } => match live {
            None => with_diag(
                base(Phase::RecoveryRequired, unknown, mac_mode, rp),
                &format!(
                    "State records blocked ({reason}); enforcement is not verifiable without root. Use stop or recover."
                ),
                Some(rp),
            ),
            Some(l) => live_state(st, l, mac_mode, rp, true),
        },
        State::RecoveryRequired { reason } => with_diag(
            base(Phase::RecoveryRequired, unknown, mac_mode, rp),
            &format!("Recovery required: {reason}"),
            Some(rp),
        ),
        State::Stopping | State::Planning => with_diag(
            base(Phase::RecoveryRequired, unknown, mac_mode, rp),
            "An earlier operation was interrupted; run recover.",
            Some(rp),
        ),
    }
}

fn live_state(
    st: &Status,
    l: &LiveStatus,
    mac_mode: MacMode,
    rp: RebootProtection,
    was_blocked: bool,
) -> EngineState {
    let detail = if l.detail.is_empty() {
        String::new()
    } else {
        format!(" ({})", l.detail.join("; "))
    };
    let (tor, enf) = (l.tor_bootstrap, l.enforcement);
    if enf != Check::Passed {
        let v = Verification {
            tor_bootstrap: verify(tor),
            enforcement: verify(enf),
            mac_readback: unknown_for(mac_mode).mac_readback,
        };
        return with_diag(
            base(Phase::RecoveryRequired, v, mac_mode, rp),
            &format!("Live check: enforcement is not verified{detail}. Run recover."),
            Some(rp),
        );
    }
    if tor == Check::Passed && !was_blocked {
        let (mac_v, note) = if st.mac.is_some() {
            (
                VerifyState::Passed,
                " MAC read-back is from apply time (no live MAC check).",
            )
        } else {
            (VerifyState::NotRun, "")
        };
        let v = Verification {
            tor_bootstrap: VerifyState::Passed,
            enforcement: VerifyState::Passed,
            mac_readback: mac_v,
        };
        return with_diag(
            base(Phase::Connected, v, mac_mode, rp),
            &format!("Live as root: enforcement read-back and Tor bootstrap passed.{note}"),
            Some(rp),
        );
    }
    let v = Verification {
        tor_bootstrap: verify(tor),
        enforcement: VerifyState::Passed,
        mac_readback: unknown_for(mac_mode).mac_readback,
    };
    with_diag(
        base(Phase::Blocked, v, mac_mode, rp),
        &format!("Fail-closed: enforcement verified live, Tor is not connected{detail}."),
        Some(rp),
    )
}

/// A successful `start`. The backend's own lifecycle already demanded evidence; it is
/// checked again here so this layer cannot be the one that over-claims.
pub fn start_success(out: &StartOutcome, config: &Config, rp: RebootProtection) -> EngineState {
    let mac_on = config.mac == MacMode::RandomOnApply;
    let ev = out.evidence;
    let v = Verification {
        tor_bootstrap: verify(ev.tor_bootstrap),
        enforcement: verify(ev.enforcement),
        mac_readback: if mac_on {
            verify(ev.mac_readback)
        } else {
            VerifyState::NotRun
        },
    };
    let proven = out.state == State::Connected
        && v.tor_bootstrap == VerifyState::Passed
        && v.enforcement == VerifyState::Passed
        && (!mac_on || v.mac_readback == VerifyState::Passed);
    if proven {
        with_diag(
            base(Phase::Connected, v, config.mac, rp),
            "Tor bootstrap and nftables enforcement read-back passed.",
            Some(rp),
        )
    } else {
        with_diag(
            base(Phase::RecoveryRequired, v, config.mac, rp),
            "Start finished without complete evidence; run recover.",
            Some(rp),
        )
    }
}

/// How a failed mutating command is reported.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Start,
    Stop,
    Recover,
    Switch,
}

impl Verb {
    fn word(self) -> &'static str {
        match self {
            Verb::Start => "start",
            Verb::Stop => "stop",
            Verb::Recover => "recover",
            Verb::Switch => "switch",
        }
    }
}

/// Maps a backend failure. Errors that mean "refused, nothing changed" (wrong state,
/// busy, not root, bad options, preflight, foreign table) are protocol errors. Otherwise the
/// state the backend left behind is reported faithfully: verified `Blocked` after a failed
/// `start` (the backend re-verified enforcement), `RecoveryRequired` for anything unverified.
pub fn failure(f: &OpFailure, verb: Verb, mac_mode: MacMode, rp: RebootProtection) -> Response {
    let refused = matches!(
        f.error,
        Error::WrongState(_)
            | Error::Locked
            | Error::NotRoot
            | Error::Config(_)
            | Error::Preflight(_)
            | Error::ForeignTable
    );
    if refused {
        return Response::err(protocol_error(&f.error));
    }
    let word = verb.word();
    let msg = format!("{word} failed: {}", f.error);
    match &f.state {
        State::Idle | State::Connected => Response::err(error(error_kind(&f.error), &msg)),
        State::Blocked { .. } if verb == Verb::Start => {
            let v = Verification {
                tor_bootstrap: VerifyState::Unknown,
                enforcement: VerifyState::Passed,
                mac_readback: unknown_for(mac_mode).mac_readback,
            };
            Response::ok(with_diag(
                base(Phase::Blocked, v, mac_mode, rp),
                &format!("{msg}. Enforcement re-verified: traffic stays blocked (fail-closed). Use stop or recover."),
                Some(rp),
            ))
        }
        State::Blocked { .. }
        | State::RecoveryRequired { .. }
        | State::Starting
        | State::Stopping
        | State::Planning => Response::ok(with_diag(
            base(Phase::RecoveryRequired, unknown_for(mac_mode), mac_mode, rp),
            &format!("{msg}. Torwell-owned state remains; run recover."),
            Some(rp),
        )),
    }
}

/// A successful `stop` or `recover`.
pub fn stopped(out: &StopOutcome, verb: Verb, rp: RebootProtection) -> EngineState {
    let text = format!(
        "{} complete: Tor stopped, owned nftables table {}, MAC {}.",
        verb.word(),
        if out.table_removed {
            "removed"
        } else {
            "was already absent"
        },
        if out.mac_restored {
            "restored"
        } else {
            "unchanged"
        },
    );
    with_diag(
        base(Phase::Disconnected, NONE_RUN, MacMode::Off, rp),
        &format!("{text} Traffic is no longer filtered by Torwell."),
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use torwell_core::Evidence;

    fn status(state: State) -> Status {
        Status {
            state,
            tor_uid: Some(970),
            mac: None,
        }
    }

    fn live(enf: Check, tor: Check) -> LiveStatus {
        LiveStatus {
            enforcement: enf,
            tor_bootstrap: tor,
            detail: vec![],
        }
    }

    const RP: RebootProtection = RebootProtection::NotInstalled;

    #[test]
    fn persisted_active_without_live_is_never_connected_or_blocked() {
        for s in [
            State::Starting,
            State::Connected,
            State::Blocked { reason: "x".into() },
        ] {
            let st = persisted_state(&status(s), None, RP);
            assert!(
                !matches!(st.phase, Phase::Connected | Phase::Blocked),
                "{:?}",
                st.phase
            );
            assert!(st.validate().is_ok());
            assert_ne!(st.verification.enforcement, VerifyState::Passed);
        }
    }

    #[test]
    fn connected_needs_both_live_checks() {
        let st = status(State::Starting);
        let ok = persisted_state(&st, Some(&live(Check::Passed, Check::Passed)), RP);
        assert_eq!(ok.phase, Phase::Connected);
        let no_tor = persisted_state(&st, Some(&live(Check::Passed, Check::Failed)), RP);
        assert_eq!(no_tor.phase, Phase::Blocked);
        assert_eq!(no_tor.verification.enforcement, VerifyState::Passed);
        let no_enf = persisted_state(&st, Some(&live(Check::Failed, Check::Passed)), RP);
        assert_eq!(no_enf.phase, Phase::RecoveryRequired);
        let not_run = persisted_state(&st, Some(&live(Check::NotRun, Check::Passed)), RP);
        assert_eq!(not_run.phase, Phase::RecoveryRequired);
        for s in [&ok, &no_tor, &no_enf, &not_run] {
            assert!(s.validate().is_ok());
        }
    }

    #[test]
    fn persisted_blocked_is_not_upgraded_to_connected_by_live_tor() {
        let st = status(State::Blocked { reason: "r".into() });
        let s = persisted_state(&st, Some(&live(Check::Passed, Check::Passed)), RP);
        assert_eq!(s.phase, Phase::Blocked);
    }

    #[test]
    fn mac_mode_follows_applied_mac_and_connected_has_readback() {
        let mut st = status(State::Starting);
        st.mac = Some(torwell_linux::MacApplied {
            interface: "wlan0".into(),
            address: torwell_core::MacAddress::from_candidate_bytes([1, 2, 3, 4, 5, 6]),
        });
        let s = persisted_state(&st, Some(&live(Check::Passed, Check::Passed)), RP);
        assert_eq!(s.phase, Phase::Connected);
        assert_eq!(s.mac_mode, MacMode::RandomOnApply);
        assert_eq!(s.verification.mac_readback, VerifyState::Passed);
        assert!(s.validate().is_ok());
    }

    #[test]
    fn idle_is_disconnected() {
        let s = persisted_state(&status(State::Idle), None, RP);
        assert_eq!(s.phase, Phase::Disconnected);
        assert!(s.validate().is_ok());
    }

    fn outcome(state: State, tor: Check, enf: Check) -> StartOutcome {
        StartOutcome {
            state,
            evidence: Evidence {
                tor_bootstrap: tor,
                enforcement: enf,
                mac_readback: Check::NotRun,
            },
            tor_uid: 970,
            mac: None,
        }
    }

    #[test]
    fn start_success_is_connected_only_with_state_and_evidence() {
        let cfg = Config::default();
        let ok = start_success(
            &outcome(State::Connected, Check::Passed, Check::Passed),
            &cfg,
            RP,
        );
        assert_eq!(ok.phase, Phase::Connected);
        for bad in [
            outcome(State::Starting, Check::Passed, Check::Passed),
            outcome(State::Connected, Check::NotRun, Check::Passed),
            outcome(State::Connected, Check::Passed, Check::Failed),
        ] {
            let s = start_success(&bad, &cfg, RP);
            assert_eq!(s.phase, Phase::RecoveryRequired);
            assert!(s.validate().is_ok());
        }
    }

    #[test]
    fn start_success_with_mac_requires_mac_readback() {
        let cfg = Config {
            mac: MacMode::RandomOnApply,
            ..Config::default()
        };
        let s = start_success(
            &outcome(State::Connected, Check::Passed, Check::Passed),
            &cfg,
            RP,
        );
        assert_eq!(s.phase, Phase::RecoveryRequired);
    }

    fn fail(error: Error, state: State) -> OpFailure {
        OpFailure { error, state }
    }

    #[test]
    fn refusals_are_errors_even_when_persisted_state_says_connected() {
        let r = failure(
            &fail(Error::WrongState("exists".into()), State::Connected),
            Verb::Start,
            MacMode::Off,
            RP,
        );
        assert_eq!(r.result.unwrap_err().kind, ErrorKind::PreconditionFailed);
    }

    #[test]
    fn failed_start_states_map_faithfully() {
        let blocked = failure(
            &fail(
                Error::Tor("boom".into()),
                State::Blocked { reason: "r".into() },
            ),
            Verb::Start,
            MacMode::Off,
            RP,
        );
        let s = blocked.result.unwrap();
        assert_eq!(s.phase, Phase::Blocked);
        assert_eq!(s.verification.enforcement, VerifyState::Passed);
        assert!(s.validate().is_ok());

        let rec = failure(
            &fail(
                Error::Enforcement("x".into()),
                State::RecoveryRequired { reason: "r".into() },
            ),
            Verb::Start,
            MacMode::Off,
            RP,
        );
        assert_eq!(rec.result.unwrap().phase, Phase::RecoveryRequired);

        let idle = failure(
            &fail(
                Error::Command {
                    what: "nft".into(),
                    detail: "d".into(),
                },
                State::Idle,
            ),
            Verb::Start,
            MacMode::Off,
            RP,
        );
        assert_eq!(idle.result.unwrap_err().kind, ErrorKind::Internal);
    }

    #[test]
    fn blocked_from_a_failed_stop_is_not_taken_at_face_value() {
        let r = failure(
            &fail(Error::Io("x".into()), State::Blocked { reason: "r".into() }),
            Verb::Stop,
            MacMode::Off,
            RP,
        );
        assert_eq!(r.result.unwrap().phase, Phase::RecoveryRequired);
    }

    #[test]
    fn error_kinds() {
        assert_eq!(error_kind(&Error::NotRoot), ErrorKind::PermissionDenied);
        assert_eq!(error_kind(&Error::Locked), ErrorKind::Busy);
        assert_eq!(
            error_kind(&Error::Mac {
                detail: "d".into(),
                rolled_back: true
            }),
            ErrorKind::AdapterUnavailable
        );
    }

    #[test]
    fn reboot_claims_follow_the_backend() {
        let on = persisted_state(&status(State::Starting), None, RebootProtection::Enabled);
        assert!(on.diagnostic.unwrap().contains("restore unit enabled"));
        let off = persisted_state(&status(State::Starting), None, RP);
        assert!(off.diagnostic.as_ref().unwrap().contains("NOT enabled"));
        assert_eq!(off.capabilities[0].support, Support::Unsupported);
        let installed = reboot_capability(RebootProtection::InstalledNotEnabled);
        assert_eq!(installed.support, Support::Unsupported);
        assert_eq!(
            reboot_capability(RebootProtection::Enabled).support,
            Support::Supported
        );
    }

    #[test]
    fn stopped_is_disconnected() {
        let s = stopped(
            &StopOutcome {
                mac_restored: true,
                tor_stopped: true,
                table_removed: true,
            },
            Verb::Stop,
            RP,
        );
        assert_eq!(s.phase, Phase::Disconnected);
        assert!(s.validate().is_ok());
    }
}
