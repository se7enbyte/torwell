//! Lifecycle state machine. `Connected` is reachable only from `Starting`, and only
//! with explicit passing evidence. Failures never silently return to `Idle`.
//!
//! Transition summary:
//! - `Idle -> Planning -> Starting -> Connected` (requires `Evidence`)
//! - `Planning | Starting | Connected -> Blocked` on a failure with verified active enforcement
//! - `Planning | Starting | Connected -> RecoveryRequired` on a partial failure
//! - `Planning | Starting | Connected | Blocked | RecoveryRequired -> Stopping`
//! - `Stopping -> Idle` on complete teardown, otherwise `Stopping -> RecoveryRequired`

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::config::MacMode;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum State {
    Idle,
    Planning,
    /// Enforcement and Tor are being started. Not connected.
    Starting,
    /// Only reachable through `Lifecycle::verify_connected`.
    Connected,
    /// A failure with blocking enforcement verified by the executor. No connected
    /// claim, and only an explicit stop leaves this state.
    Blocked {
        reason: String,
    },
    /// Partial or unverifiable Torwell-owned state. Starting is refused; only stop/recovery.
    RecoveryRequired {
        reason: String,
    },
    /// Teardown or recovery in progress.
    Stopping,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Check {
    NotRun,
    Passed,
    Failed,
}

/// Verification results required before `Connected`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Tor reported bootstrap complete (observed, not assumed).
    pub tor_bootstrap: Check,
    /// Redirect and reject enforcement checks passed.
    pub enforcement: Check,
    /// MAC read-back matched the candidate. Required only when MAC mode is on.
    pub mac_readback: Check,
}

/// How a failure relates to Torwell-owned changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// The executor has verified that blocking enforcement is still active.
    /// Accounting for mutations alone is insufficient. Enter `Blocked`.
    ProtectionVerified,
    /// A change may be applied, or its rollback is unverified. Enter `RecoveryRequired`.
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionError {
    /// The action is not allowed in the current state.
    Invalid { action: &'static str, state: State },
    /// `Connected` needs this evidence check to have passed.
    Unverified { check: &'static str },
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransitionError::Invalid { action, state } => {
                write!(f, "cannot {action} while in state {state:?}")
            }
            TransitionError::Unverified { check } => {
                write!(f, "cannot mark connected: `{check}` not verified")
            }
        }
    }
}

impl std::error::Error for TransitionError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lifecycle {
    state: State,
    mac: MacMode,
}

impl Lifecycle {
    /// The MAC mode determines whether `Connected` also requires MAC read-back evidence.
    pub fn new(mac: MacMode) -> Self {
        Self {
            state: State::Idle,
            mac,
        }
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    pub fn is_connected(&self) -> bool {
        self.state == State::Connected
    }

    pub fn begin_plan(&mut self) -> Result<(), TransitionError> {
        match self.state {
            State::Idle => {
                self.state = State::Planning;
                Ok(())
            }
            _ => Err(self.invalid("begin planning")),
        }
    }

    /// Enforcement and Tor start may only begin after a plan exists.
    pub fn begin_start(&mut self) -> Result<(), TransitionError> {
        match self.state {
            State::Planning => {
                self.state = State::Starting;
                Ok(())
            }
            _ => Err(self.invalid("begin starting")),
        }
    }

    /// Moves to `Connected` only when Tor bootstrap and enforcement have passed, and MAC
    /// read-back has passed if MAC mode is on. On failure the state stays `Starting`.
    pub fn verify_connected(&mut self, evidence: &Evidence) -> Result<(), TransitionError> {
        if self.state != State::Starting {
            return Err(self.invalid("mark connected"));
        }
        require(evidence.tor_bootstrap, "tor_bootstrap")?;
        require(evidence.enforcement, "enforcement")?;
        if self.mac == MacMode::RandomOnApply {
            require(evidence.mac_readback, "mac_readback")?;
        }
        self.state = State::Connected;
        Ok(())
    }

    pub fn fail(&mut self, reason: impl Into<String>, fault: Fault) -> Result<(), TransitionError> {
        match self.state {
            State::Planning | State::Starting | State::Connected => {
                let reason: String = reason.into();
                self.state = match fault {
                    Fault::ProtectionVerified => State::Blocked { reason },
                    Fault::Partial => State::RecoveryRequired { reason },
                };
                Ok(())
            }
            _ => Err(self.invalid("record a failure")),
        }
    }

    /// Stop is also the only recovery path out of `Blocked` and `RecoveryRequired`.
    pub fn request_stop(&mut self) -> Result<(), TransitionError> {
        match self.state {
            State::Planning
            | State::Starting
            | State::Connected
            | State::Blocked { .. }
            | State::RecoveryRequired { .. } => {
                self.state = State::Stopping;
                Ok(())
            }
            _ => Err(self.invalid("stop")),
        }
    }

    /// `Ok(())` means teardown completed and verified. `Err(reason)` means it did not,
    /// and the state becomes `RecoveryRequired`.
    pub fn finish_stop(&mut self, outcome: Result<(), String>) -> Result<(), TransitionError> {
        match self.state {
            State::Stopping => {
                self.state = match outcome {
                    Ok(()) => State::Idle,
                    Err(reason) => State::RecoveryRequired { reason },
                };
                Ok(())
            }
            _ => Err(self.invalid("finish stopping")),
        }
    }

    fn invalid(&self, action: &'static str) -> TransitionError {
        TransitionError::Invalid {
            action,
            state: self.state.clone(),
        }
    }
}

fn require(check: Check, name: &'static str) -> Result<(), TransitionError> {
    if check == Check::Passed {
        Ok(())
    } else {
        Err(TransitionError::Unverified { check: name })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passed() -> Evidence {
        Evidence {
            tor_bootstrap: Check::Passed,
            enforcement: Check::Passed,
            mac_readback: Check::NotRun,
        }
    }

    fn starting(mac: MacMode) -> Lifecycle {
        let mut lc = Lifecycle::new(mac);
        lc.begin_plan().unwrap();
        lc.begin_start().unwrap();
        lc
    }

    #[test]
    fn happy_path_connects_only_after_evidence() {
        let mut lc = starting(MacMode::Off);
        lc.verify_connected(&passed()).unwrap();
        assert_eq!(lc.state(), &State::Connected);
        assert!(lc.is_connected());
    }

    #[test]
    fn connected_needs_tor_bootstrap_evidence() {
        let mut lc = starting(MacMode::Off);
        let ev = Evidence {
            tor_bootstrap: Check::NotRun,
            ..passed()
        };
        assert_eq!(
            lc.verify_connected(&ev),
            Err(TransitionError::Unverified {
                check: "tor_bootstrap"
            })
        );
        assert_eq!(lc.state(), &State::Starting);
    }

    #[test]
    fn failed_enforcement_evidence_does_not_connect() {
        let mut lc = starting(MacMode::Off);
        let ev = Evidence {
            enforcement: Check::Failed,
            ..passed()
        };
        assert_eq!(
            lc.verify_connected(&ev),
            Err(TransitionError::Unverified {
                check: "enforcement"
            })
        );
        assert!(!lc.is_connected());
    }

    #[test]
    fn mac_readback_is_required_only_when_mac_mode_is_on() {
        let mut off = starting(MacMode::Off);
        assert!(off.verify_connected(&passed()).is_ok());

        let mut on = starting(MacMode::RandomOnApply);
        assert_eq!(
            on.verify_connected(&passed()),
            Err(TransitionError::Unverified {
                check: "mac_readback"
            })
        );
        let with_readback = Evidence {
            mac_readback: Check::Passed,
            ..passed()
        };
        assert!(on.verify_connected(&with_readback).is_ok());
    }

    #[test]
    fn connected_is_unreachable_from_idle_or_planning() {
        let mut idle = Lifecycle::new(MacMode::Off);
        assert!(matches!(
            idle.verify_connected(&passed()),
            Err(TransitionError::Invalid { .. })
        ));

        let mut planning = Lifecycle::new(MacMode::Off);
        planning.begin_plan().unwrap();
        assert!(matches!(
            planning.verify_connected(&passed()),
            Err(TransitionError::Invalid { .. })
        ));
        assert_eq!(planning.state(), &State::Planning);
    }

    #[test]
    fn verified_protection_failure_while_connected_blocks_fail_closed() {
        let mut lc = starting(MacMode::Off);
        lc.verify_connected(&passed()).unwrap();
        lc.fail("tor process exited", Fault::ProtectionVerified)
            .unwrap();

        assert_eq!(
            lc.state(),
            &State::Blocked {
                reason: "tor process exited".to_string()
            }
        );
        assert!(!lc.is_connected());
        assert!(matches!(
            lc.verify_connected(&passed()),
            Err(TransitionError::Invalid { .. })
        ));
        assert!(matches!(
            lc.begin_plan(),
            Err(TransitionError::Invalid { .. })
        ));
        assert!(matches!(
            lc.begin_start(),
            Err(TransitionError::Invalid { .. })
        ));
    }

    #[test]
    fn partial_failure_retains_recovery_required() {
        let mut lc = starting(MacMode::Off);
        lc.fail("redirect applied, reject rule failed", Fault::Partial)
            .unwrap();

        assert!(matches!(lc.state(), State::RecoveryRequired { .. }));
        assert!(matches!(
            lc.begin_plan(),
            Err(TransitionError::Invalid { .. })
        ));
        assert!(matches!(
            lc.begin_start(),
            Err(TransitionError::Invalid { .. })
        ));
        assert!(matches!(
            lc.verify_connected(&passed()),
            Err(TransitionError::Invalid { .. })
        ));
    }

    #[test]
    fn recovery_failure_stays_recovery_required_and_success_returns_idle() {
        let mut lc = starting(MacMode::Off);
        lc.fail("partial enforcement", Fault::Partial).unwrap();

        lc.request_stop().unwrap();
        lc.finish_stop(Err("nft table delete failed".to_string()))
            .unwrap();
        assert_eq!(
            lc.state(),
            &State::RecoveryRequired {
                reason: "nft table delete failed".to_string()
            }
        );

        lc.request_stop().unwrap();
        lc.finish_stop(Ok(())).unwrap();
        assert_eq!(lc.state(), &State::Idle);
    }

    #[test]
    fn blocked_state_leaves_only_through_stop() {
        let mut lc = starting(MacMode::Off);
        lc.fail("bootstrap timeout", Fault::ProtectionVerified)
            .unwrap();
        assert!(matches!(lc.state(), State::Blocked { .. }));
        lc.request_stop().unwrap();
        assert_eq!(lc.state(), &State::Stopping);
    }

    #[test]
    fn stop_from_idle_is_invalid_and_clean_stop_returns_idle() {
        let mut lc = Lifecycle::new(MacMode::Off);
        assert!(matches!(
            lc.request_stop(),
            Err(TransitionError::Invalid { .. })
        ));

        let mut lc = starting(MacMode::Off);
        lc.request_stop().unwrap();
        lc.finish_stop(Ok(())).unwrap();
        assert_eq!(lc.state(), &State::Idle);
    }
}
