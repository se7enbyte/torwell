//! Dashboard state and its text. No OpenTUI types here, so the rules can be unit-tested.
//!
//! Invariant: the network is shown as connected, bootstrapping, blocked or protected only
//! when the last successful engine response says so and its evidence passed. Without an
//! engine, every network claim reads "unknown".

use std::collections::VecDeque;

use torwell_core::capability::{Os, Report, Support};
use torwell_core::config::{Config, MacMode};
use torwell_protocol::{
    Adapter, Command, EngineState, ErrorKind, Phase, ProtocolError, Selection, VerifyState,
};

/// How many recent messages are kept and shown.
pub const MESSAGE_LINES: usize = 3;
const MAX_MESSAGE_CHARS: usize = 160;

/// Menu actions, in display order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Inspect,
    Status,
    Plan,
    Start,
    Switch,
    Stop,
    Recover,
    ToggleMac,
}

impl Action {
    pub const ALL: [Action; 8] = [
        Action::Inspect,
        Action::Status,
        Action::Plan,
        Action::Start,
        Action::Switch,
        Action::Stop,
        Action::Recover,
        Action::ToggleMac,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Action::Inspect => "Inspect (read-only)",
            Action::Status => "Status (read-only)",
            Action::Plan => "Plan (no changes)",
            Action::Start => "Start",
            Action::Switch => "Switch",
            Action::Stop => "Stop",
            Action::Recover => "Recover",
            Action::ToggleMac => "MAC mode: toggle (opt-in)",
        }
    }

    /// Changes network or interface state, so it needs a second Enter to confirm.
    pub fn is_mutating(self) -> bool {
        matches!(
            self,
            Action::Start | Action::Switch | Action::Stop | Action::Recover
        )
    }

    fn short(self) -> &'static str {
        match self {
            Action::Inspect => "inspect",
            Action::Status => "status",
            Action::Plan => "plan",
            Action::Start => "start",
            Action::Switch => "switch",
            Action::Stop => "stop",
            Action::Recover => "recover",
            Action::ToggleMac => "MAC toggle",
        }
    }
}

/// What the last engine exchange established about the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Link {
    /// No engine response yet. Network state is unknown.
    NotQueried,
    /// The last command failed. Network state is unknown, not "disconnected".
    Failed(ProtocolError),
    /// The engine reported this state and it passed protocol validation.
    Reported(EngineState),
}

/// A finished engine exchange, sent from the worker thread to the UI thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineReply {
    pub action: Action,
    pub result: Result<EngineState, ProtocolError>,
    /// Sanitized stderr from the engine process; empty when none.
    pub stderr: String,
}

/// The visual weight of a status line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Good,
    Busy,
    Warn,
    Bad,
    Muted,
}

/// What the animation is allowed to show. Derived only from real engine evidence, never
/// from hope: `Connected` requires a reported `connected` phase *and* passed Tor bootstrap
/// and enforcement read-back (and MAC read-back when MAC mode is on).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mood {
    /// No engine answer yet, or the last command failed. State is unknown.
    Unknown,
    /// Reported not configured / disconnected: nothing applied.
    Idle,
    /// Reported bootstrapping, with the engine's percentage when it gave one.
    Starting(Option<u8>),
    /// Reported connected with all evidence passed.
    Connected,
    /// Reported fail-closed block.
    Blocked,
    /// Reported recovery required.
    Recovery,
    /// Reported unsupported on this host.
    Unsupported,
}

/// Text for each status line, in display order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lines {
    pub connection: (String, Tone),
    pub protection: (String, Tone),
    pub bootstrap: String,
    pub mac: String,
    pub linux: String,
    pub windows: String,
    pub messages: Vec<String>,
}

/// What the UI must do after an action was chosen.
#[derive(Debug, PartialEq, Eq)]
pub enum Next {
    /// Handled locally (message, toggle, or refusal).
    Done,
    /// Send this command to the engine; the action is busy until the reply arrives.
    Send(Action, Command),
}

#[derive(Debug)]
pub struct Model {
    pub host: Report,
    pub config: Config,
    pub adapter: Option<String>,
    pub link: Link,
    pub busy: Option<Action>,
    pub pending: Option<Action>,
    messages: VecDeque<String>,
}

impl Model {
    /// Starts with the host's presence-only capability report and no engine contact.
    pub fn new(host: Report) -> Self {
        let mut model = Self {
            host,
            config: Config::default(),
            adapter: None,
            link: Link::NotQueried,
            busy: None,
            pending: None,
            messages: VecDeque::new(),
        };
        model.message("Engine not queried. Network state is unknown until torwell-engine answers.");
        model
    }

    pub fn messages(&self) -> impl Iterator<Item = &str> {
        self.messages.iter().map(String::as_str)
    }

    fn message(&mut self, text: impl AsRef<str>) {
        let clean: String = text
            .as_ref()
            .chars()
            .filter(|c| !c.is_control())
            .take(MAX_MESSAGE_CHARS)
            .collect();
        self.messages.push_back(clean);
        while self.messages.len() > MESSAGE_LINES {
            self.messages.pop_front();
        }
    }

    /// The first validated adapter (the engine reports `mac_change: supported` only after
    /// read-back works). `None` otherwise, so MAC mode cannot be enabled on a guess.
    pub fn validated_adapter(&self) -> Option<String> {
        match &self.link {
            Link::Reported(state) => state
                .adapters
                .iter()
                .find(|a| a.mac_change == Support::Supported)
                .map(|a| a.name.clone()),
            _ => None,
        }
    }

    /// Handles a menu choice. Mutating actions need a second activation of the same action.
    pub fn activate(&mut self, action: Action) -> Next {
        if action == Action::ToggleMac {
            self.pending = None;
            return self.toggle_mac();
        }
        if let Some(busy) = self.busy {
            self.message(format!(
                "Busy: waiting for engine reply to {}.",
                busy.short()
            ));
            return Next::Done;
        }
        if action.is_mutating() && self.pending != Some(action) {
            self.pending = Some(action);
            self.message(format!(
                "Press Enter again to confirm {}. Any other choice cancels.",
                action.short()
            ));
            return Next::Done;
        }
        self.pending = None;
        let command = match action {
            Action::Inspect => Command::Inspect,
            Action::Status => Command::Status,
            Action::Stop => Command::Stop,
            Action::Recover => Command::Recover,
            Action::Plan | Action::Start | Action::Switch => {
                // The adapter is only meaningful when MAC mode is on; it is validated by the protocol.
                let adapter = match self.config.mac {
                    MacMode::Off => None,
                    MacMode::RandomOnApply => self.adapter.clone(),
                };
                let selection = adapter
                    .map(Adapter::new)
                    .transpose()
                    .and_then(|adapter| Selection::new(self.config.clone(), adapter));
                match selection {
                    Ok(selection) => match action {
                        Action::Plan => Command::Plan(selection),
                        Action::Start => Command::Start(selection),
                        _ => Command::Switch(selection),
                    },
                    Err(e) => {
                        self.message(format!("Not sent: {}", e.message));
                        return Next::Done;
                    }
                }
            }
            Action::ToggleMac => unreachable!("handled above"),
        };
        self.busy = Some(action);
        Next::Send(action, command)
    }

    fn toggle_mac(&mut self) -> Next {
        match self.config.mac {
            MacMode::RandomOnApply => {
                self.config.mac = MacMode::Off;
                self.adapter = None;
                self.message("MAC mode off (default). No adapter is changed.");
            }
            MacMode::Off => match self.validated_adapter() {
                Some(name) => {
                    self.config.mac = MacMode::RandomOnApply;
                    self.adapter = Some(name.clone());
                    self.message(format!(
                        "MAC random-on-apply selected for {name}. Applies on the next start or switch."
                    ));
                }
                None => self.message(
                    "MAC change unavailable: no adapter is validated by the engine (engine unavailable or no read-back support).",
                ),
            },
        }
        Next::Done
    }

    /// Applies an engine reply. Errors make the network state unknown.
    pub fn apply(&mut self, reply: &EngineReply) {
        self.busy = None;
        if !reply.stderr.trim().is_empty() {
            let first = reply.stderr.lines().next().unwrap_or_default();
            self.message(format!("engine stderr: {first}"));
        }
        match &reply.result {
            Ok(state) => {
                let text = state.diagnostic.clone().unwrap_or_else(|| {
                    format!("{}: {}", reply.action.short(), phase_label(state.phase))
                });
                self.message(text);
                self.link = Link::Reported(state.clone());
            }
            Err(error) => {
                self.message(format!(
                    "{} failed ({}): {}",
                    reply.action.short(),
                    kind_label(error.kind),
                    error.message
                ));
                self.link = Link::Failed(error.clone());
            }
        }
    }

    /// The animation mood for the current state. See [`Mood`].
    pub fn mood(&self) -> Mood {
        let Link::Reported(state) = &self.link else {
            return Mood::Unknown;
        };
        match state.phase {
            Phase::Unconfigured | Phase::Disconnected => Mood::Idle,
            Phase::Starting => Mood::Starting(state.bootstrap_percent.map(|p| p.min(100))),
            Phase::Connected => {
                let v = &state.verification;
                let mac_ok =
                    state.mac_mode == MacMode::Off || v.mac_readback == VerifyState::Passed;
                if v.tor_bootstrap == VerifyState::Passed
                    && v.enforcement == VerifyState::Passed
                    && mac_ok
                {
                    Mood::Connected
                } else {
                    Mood::Unknown
                }
            }
            Phase::Blocked => Mood::Blocked,
            Phase::RecoveryRequired => Mood::Recovery,
            Phase::Unsupported => Mood::Unsupported,
        }
    }

    /// Builds the status text for the current state.
    pub fn lines(&self) -> Lines {
        let (connection, protection, bootstrap) = match &self.link {
            Link::NotQueried => (
                ("Unknown: engine not queried".to_string(), Tone::Warn),
                ("Unknown".to_string(), Tone::Warn),
                "-".to_string(),
            ),
            Link::Failed(e) => {
                let text = match e.kind {
                    ErrorKind::EngineUnavailable => "Unknown: engine unavailable".to_string(),
                    _ => format!("Unknown: last command failed ({})", kind_label(e.kind)),
                };
                (
                    (text, Tone::Bad),
                    ("Unknown".to_string(), Tone::Warn),
                    "-".to_string(),
                )
            }
            Link::Reported(state) => {
                let (text, tone) = connection_text(state);
                let (protect, ptone) = protection_text(state);
                let bootstrap = match (state.phase, state.bootstrap_percent) {
                    (Phase::Starting, Some(p)) => format!("{p}%"),
                    (Phase::Starting, None) => "in progress (no percentage)".to_string(),
                    _ => "-".to_string(),
                };
                ((text, tone), (protect, ptone), bootstrap)
            }
        };
        let mac = match self.config.mac {
            MacMode::Off => "Off (default)".to_string(),
            MacMode::RandomOnApply => format!(
                "Random on apply, adapter {}",
                self.adapter.as_deref().unwrap_or("none")
            ),
        };
        Lines {
            connection,
            protection,
            bootstrap,
            mac,
            linux: platform_line(&self.host, Os::Linux, "Linux"),
            windows: platform_line(&self.host, Os::Windows, "Windows"),
            messages: self.messages.iter().cloned().collect(),
        }
    }
}

fn connection_text(state: &EngineState) -> (String, Tone) {
    match state.phase {
        Phase::Unconfigured => ("Not configured: nothing applied".into(), Tone::Muted),
        Phase::Disconnected => ("Disconnected: nothing applied".into(), Tone::Muted),
        Phase::Starting => match state.bootstrap_percent {
            Some(p) => (
                format!("Bootstrapping Tor ({p}%): not connected yet"),
                Tone::Busy,
            ),
            None => ("Bootstrapping Tor: not connected yet".into(), Tone::Busy),
        },
        Phase::Connected => (
            "Connected: Tor bootstrap and enforcement verified".into(),
            Tone::Good,
        ),
        Phase::Blocked => ("Blocked: fail-closed, Tor not connected".into(), Tone::Bad),
        Phase::RecoveryRequired => (
            "Recovery required: nothing starts until recovered".into(),
            Tone::Bad,
        ),
        Phase::Unsupported => ("Unsupported on this host".into(), Tone::Warn),
    }
}

fn protection_text(state: &EngineState) -> (String, Tone) {
    match state.verification.enforcement {
        VerifyState::Passed => ("Enforced (read-back verified)".into(), Tone::Good),
        VerifyState::Failed => ("Enforcement check failed".into(), Tone::Bad),
        VerifyState::NotRun => ("Not active (not checked)".into(), Tone::Muted),
        VerifyState::Unknown => ("Unknown (could not check)".into(), Tone::Warn),
    }
}

/// Dependency lines use presence only. The host's own OS is probed; the other platform is
/// reported as not probed rather than guessed.
fn platform_line(host: &Report, os: Os, name: &str) -> String {
    if host.os != os {
        return match os {
            Os::Windows => format!("{name}: not probed here; runtime untested (Wintun, WFP)"),
            _ => format!("{name}: not probed on this host"),
        };
    }
    let parts: Vec<String> = host
        .capabilities
        .iter()
        .map(|c| {
            let short = c.name.split('.').nth(1).unwrap_or(&c.name);
            let state = match c.support {
                Support::Supported => "found",
                Support::Unsupported => "missing",
                Support::Unknown => "unknown",
            };
            format!("{short} {state}")
        })
        .collect();
    format!("{name}: {} (presence only)", parts.join(", "))
}

pub fn phase_label(phase: Phase) -> &'static str {
    match phase {
        Phase::Unconfigured => "unconfigured",
        Phase::Disconnected => "disconnected",
        Phase::Starting => "starting",
        Phase::Connected => "connected",
        Phase::Blocked => "blocked",
        Phase::RecoveryRequired => "recovery required",
        Phase::Unsupported => "unsupported",
    }
}

pub fn kind_label(kind: ErrorKind) -> &'static str {
    match kind {
        ErrorKind::InvalidRequest => "invalid request",
        ErrorKind::UnsupportedVersion => "unsupported version",
        ErrorKind::PermissionDenied => "permission denied",
        ErrorKind::Unsupported => "unsupported",
        ErrorKind::PreconditionFailed => "precondition failed",
        ErrorKind::AdapterUnavailable => "adapter unavailable",
        ErrorKind::Busy => "engine busy",
        ErrorKind::Internal => "internal error",
        ErrorKind::EngineUnavailable => "engine unavailable",
        ErrorKind::Timeout => "timeout",
        ErrorKind::MessageTooLarge => "message too large",
        ErrorKind::InvalidResponse => "invalid response",
    }
}

#[cfg(test)]
mod mood_tests {
    use super::*;
    use torwell_core::host::detect;
    use torwell_protocol::Verification;

    fn model_with(state: EngineState) -> Model {
        let mut m = Model::new(detect(Os::Linux, |_| false));
        m.link = Link::Reported(state);
        m
    }

    fn connected(tor: VerifyState, enf: VerifyState) -> EngineState {
        EngineState {
            phase: Phase::Connected,
            verification: Verification {
                tor_bootstrap: tor,
                enforcement: enf,
                mac_readback: VerifyState::NotRun,
            },
            ..EngineState::unknown()
        }
    }

    #[test]
    fn connected_mood_needs_all_evidence() {
        let m = Model::new(detect(Os::Linux, |_| false));
        assert_eq!(m.mood(), Mood::Unknown);
        let ok = model_with(connected(VerifyState::Passed, VerifyState::Passed));
        assert_eq!(ok.mood(), Mood::Connected);
        for (t, e) in [
            (VerifyState::Passed, VerifyState::Unknown),
            (VerifyState::Unknown, VerifyState::Passed),
            (VerifyState::Failed, VerifyState::Passed),
            (VerifyState::NotRun, VerifyState::NotRun),
        ] {
            assert_eq!(model_with(connected(t, e)).mood(), Mood::Unknown);
        }
    }

    #[test]
    fn failed_link_is_unknown_not_idle() {
        let mut m = Model::new(detect(Os::Linux, |_| false));
        m.link = Link::Failed(ProtocolError::new(ErrorKind::EngineUnavailable, "x"));
        assert_eq!(m.mood(), Mood::Unknown);
    }
}
