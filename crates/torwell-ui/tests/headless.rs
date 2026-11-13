//! Headless OpenTUI tests: real frames from `TestApp`, key presses, and fake engine transports.
//! No test starts `torwell-engine`, touches host networking, or runs a mutating command.

use std::ffi::OsString;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use opentui::testing::TestApp;
use torwell_core::capability::Os;
use torwell_core::host::detect;
use torwell_protocol::{
    decode_request, encode_response, AdapterInfo, Capability, Command, EngineState, ErrorKind,
    MacMode, Phase, ProtocolError, Response, Support, Verification, VerifyState,
};
use torwell_ui::dashboard::{self, Dashboard};
use torwell_ui::engine::{ChildEngine, RawReply, Transport};

const TIMEOUT: Duration = Duration::from_secs(5);

type Answer = dyn Fn(&[u8]) -> Result<RawReply, ProtocolError> + Send + Sync;

/// A fake engine: records every request and answers with a closure.
struct Fake {
    calls: Arc<Mutex<Vec<Vec<u8>>>>,
    answer: Box<Answer>,
    delay: Duration,
}

impl Transport for Fake {
    fn exchange(&self, request: &[u8]) -> Result<RawReply, ProtocolError> {
        self.calls.lock().unwrap().push(request.to_vec());
        std::thread::sleep(self.delay);
        (self.answer)(request)
    }
}

fn fake(
    answer: impl Fn(&[u8]) -> Result<RawReply, ProtocolError> + Send + Sync + 'static,
) -> (Arc<dyn Transport>, Calls) {
    let calls: Calls = Arc::new(Mutex::new(Vec::new()));
    let transport = Fake {
        calls: Arc::clone(&calls),
        answer: Box::new(answer),
        delay: Duration::from_millis(0),
    };
    (Arc::new(transport), calls)
}

type Calls = Arc<Mutex<Vec<Vec<u8>>>>;

fn raw(stdout: Vec<u8>, exit: Option<i32>) -> RawReply {
    RawReply {
        stdout,
        stderr: String::new(),
        exit_code: exit,
    }
}

fn reply_with(state: EngineState) -> RawReply {
    raw(encode_response(&Response::ok(state)).unwrap(), Some(0))
}

fn error_reply(kind: ErrorKind, message: &str) -> RawReply {
    raw(
        encode_response(&Response::err(ProtocolError::new(kind, message))).unwrap(),
        Some(0),
    )
}

fn host() -> torwell_core::capability::Report {
    detect(Os::Linux, |name| name == "nft" || name == "ip")
}

fn state(phase: Phase) -> EngineState {
    EngineState {
        phase,
        ..EngineState::unknown()
    }
}

fn build(app: &TestApp, transport: Arc<dyn Transport>) -> Dashboard {
    dashboard::build(app.app(), transport, host())
}

/// Moves the menu cursor to the item at `index`.
fn select(app: &TestApp, index: usize) {
    for _ in 0..index {
        app.press("down");
    }
}

fn wait_idle(app: &TestApp, dash: &Dashboard) {
    assert!(
        app.wait_until(TIMEOUT, || !dash.is_busy()),
        "engine reply never arrived:\n{}",
        app.text()
    );
    app.render();
}

const START: usize = 3;
const STATUS: usize = 1;
const MAC: usize = 7;

#[test]
fn first_frame_without_engine_reports_unknown_network() {
    let app = TestApp::new(80, 24);
    let (transport, calls) = fake(|_| panic!("no request must be sent before a choice"));
    let _dash = build(&app, transport);
    let text = app.text();
    println!("{text}");

    assert!(text.contains("Torwell"), "title missing");
    assert!(text.contains("Tor routing for Linux and Windows. macOS out of scope."));
    assert!(
        text.contains("Connection  Unknown: engine not queried"),
        "{text}"
    );
    assert!(text.contains("Protection  Unknown"), "{text}");
    assert!(text.contains("Bootstrap   -"), "{text}");
    assert!(text.contains("MAC mode    Off (default)"), "{text}");
    assert!(
        text.contains("Linux: nftables found, tor missing, iproute2 found"),
        "{text}"
    );
    assert!(
        text.contains("Windows: not probed here; runtime untested"),
        "{text}"
    );
    for action in torwell_ui::model::Action::ALL {
        assert!(
            text.contains(action.label()),
            "menu missing {}",
            action.label()
        );
    }
    assert!(text.contains("Up/Down move"));
    assert!(
        !text.contains("Connected"),
        "no connected claim without an engine"
    );
    assert!(
        !text.contains("Enforced"),
        "no protection claim without an engine"
    );
    assert!(calls.lock().unwrap().is_empty());
}

#[test]
fn start_needs_a_second_enter_and_reports_missing_engine_explicitly() {
    let app = TestApp::new(80, 24);
    let dash = build(
        &app,
        Arc::new(ChildEngine::with_program(
            "/nonexistent/torwell-engine",
            Vec::new(),
            TIMEOUT,
        )),
    );
    select(&app, START);
    app.press("enter");
    let text = app.text();
    assert!(
        text.contains("Press Enter again to confirm start"),
        "{text}"
    );
    assert!(!dash.is_busy(), "first Enter must not send anything");

    app.press("enter");
    wait_idle(&app, &dash);
    let text = app.text();
    println!("{text}");
    assert!(
        text.contains("Connection  Unknown: engine unavailable"),
        "{text}"
    );
    assert!(text.contains("start failed (engine unavailable)"), "{text}");
    assert!(!text.contains("Connected"));
}

#[test]
fn confirmation_is_cancelled_by_another_choice() {
    let app = TestApp::new(80, 24);
    // Anything other than Inspect reaching the engine would be a cancelled start leaking out.
    let (transport, calls) = fake(|req| {
        assert!(
            matches!(decode_request(req).unwrap().command, Command::Inspect),
            "only Inspect may be sent"
        );
        Ok(reply_with(state(Phase::Disconnected)))
    });
    let dash = build(&app, transport);
    select(&app, START);
    app.press("enter");
    for _ in 0..START {
        app.press("up"); // back to Inspect, which cancels the pending start
    }
    app.press("enter");
    // Inspect is read-only and goes out; the cancelled start does not.
    wait_idle(&app, &dash);
    let sent = calls.lock().unwrap();
    assert_eq!(sent.len(), 1);
    assert!(matches!(
        decode_request(&sent[0]).unwrap().command,
        Command::Inspect
    ));
}

#[test]
fn status_reply_drives_bootstrap_and_connection_lines() {
    let app = TestApp::new(80, 24);
    let (transport, calls) = fake(|_| {
        let mut s = state(Phase::Starting);
        s.bootstrap_percent = Some(42);
        s.verification = Verification {
            tor_bootstrap: VerifyState::NotRun,
            enforcement: VerifyState::Passed,
            mac_readback: VerifyState::NotRun,
        };
        Ok(reply_with(s))
    });
    let dash = build(&app, transport);
    select(&app, STATUS);
    app.press("enter");
    wait_idle(&app, &dash);
    let text = app.text();
    println!("{text}");
    assert!(
        text.contains("Connection  Bootstrapping Tor (42%): not connected yet"),
        "{text}"
    );
    assert!(text.contains("Bootstrap   42%"), "{text}");
    assert!(
        text.contains("Protection  Enforced (read-back verified)"),
        "{text}"
    );
    assert!(!text.contains("Connected:"));
    assert_eq!(calls.lock().unwrap().len(), 1);
}

#[test]
fn connected_frame_requires_passed_evidence() {
    let app = TestApp::new(80, 24);
    let (transport, _calls) = fake(|_| {
        let mut s = state(Phase::Connected);
        s.verification = Verification {
            tor_bootstrap: VerifyState::Passed,
            enforcement: VerifyState::Passed,
            mac_readback: VerifyState::NotRun,
        };
        Ok(reply_with(s))
    });
    let dash = build(&app, transport);
    select(&app, STATUS);
    app.press("enter");
    wait_idle(&app, &dash);
    assert!(app
        .text()
        .contains("Connection  Connected: Tor bootstrap and enforcement verified"));
}

#[test]
fn forged_connected_reply_is_refused_and_shown_as_unknown() {
    let app = TestApp::new(80, 24);
    // Connected with no evidence: the protocol must refuse it, so the UI shows unknown.
    // The encoder refuses this state, so forge the bytes the way a broken engine would.
    let (transport, _calls) = fake(|_| {
        let honest = encode_response(&Response::ok(state(Phase::Disconnected))).unwrap();
        let forged = String::from_utf8(honest)
            .unwrap()
            .replace("\"disconnected\"", "\"connected\"");
        assert!(forged.contains("\"connected\""));
        Ok(raw(forged.into_bytes(), Some(0)))
    });
    let dash = build(&app, transport);
    select(&app, STATUS);
    app.press("enter");
    wait_idle(&app, &dash);
    let text = app.text();
    println!("{text}");
    assert!(
        text.contains("Connection  Unknown: last command failed (invalid response)"),
        "{text}"
    );
    assert!(!text.contains("Connected"), "{text}");
    assert!(text.contains("Protection  Unknown"), "{text}");
}

#[test]
fn future_version_and_unknown_fields_in_replies_are_refused() {
    let app = TestApp::new(80, 24);
    let (transport, _calls) = fake(|req| {
        let v2 = br#"{"version":2,"status":"ok","state":null}"#.to_vec();
        let extra = br#"{"version":1,"status":"error","error":{"kind":"internal","message":"x"},"shell":"sh"}"#.to_vec();
        Ok(raw(
            if req.windows(6).any(|w| w == b"status") {
                v2
            } else {
                extra
            },
            Some(0),
        ))
    });
    let dash = build(&app, transport);
    select(&app, STATUS);
    app.press("enter");
    wait_idle(&app, &dash);
    assert!(
        app.text().contains("status failed (unsupported version)"),
        "{}",
        app.text()
    );
}

#[test]
fn success_from_a_failed_process_is_refused() {
    let app = TestApp::new(80, 24);
    let (transport, _calls) = fake(|_| Ok(reply_with(state(Phase::Disconnected)).with_exit(3)));
    let dash = build(&app, transport);
    select(&app, STATUS);
    app.press("enter");
    wait_idle(&app, &dash);
    assert!(
        app.text().contains("status failed (invalid response)"),
        "{}",
        app.text()
    );
}

trait WithExit {
    fn with_exit(self, code: i32) -> Self;
}

impl WithExit for RawReply {
    fn with_exit(mut self, code: i32) -> Self {
        self.exit_code = Some(code);
        self
    }
}

#[test]
fn permission_denied_from_engine_is_explicit() {
    let app = TestApp::new(80, 24);
    let (transport, _calls) = fake(|_| {
        Ok(error_reply(
            ErrorKind::PermissionDenied,
            "elevation required",
        ))
    });
    let dash = build(&app, transport);
    select(&app, START);
    app.press("enter");
    app.press("enter");
    wait_idle(&app, &dash);
    let text = app.text();
    assert!(
        text.contains("start failed (permission denied): elevation required"),
        "{text}"
    );
    assert!(
        text.contains("Connection  Unknown: last command failed (permission denied)"),
        "{text}"
    );
}

#[test]
fn busy_engine_blocks_a_second_request_until_reply() {
    let app = TestApp::new(80, 24);
    let calls: Calls = Arc::new(Mutex::new(Vec::new()));
    let transport: Arc<dyn Transport> = Arc::new(Fake {
        calls: Arc::clone(&calls),
        answer: Box::new(|_| Ok(reply_with(state(Phase::Disconnected)))),
        delay: Duration::from_millis(200),
    });
    let dash = build(&app, transport);
    select(&app, STATUS);
    app.press("enter");
    select(&app, 0);
    app.press("up");
    app.press("enter");
    assert!(
        app.text()
            .contains("Busy: waiting for engine reply to status."),
        "{}",
        app.text()
    );
    wait_idle(&app, &dash);
    assert_eq!(
        calls.lock().unwrap().len(),
        1,
        "the busy choice must not send"
    );
}

#[test]
fn plan_is_sent_read_only_and_never_claims_connection() {
    let app = TestApp::new(80, 24);
    let (transport, calls) = fake(|_| {
        let mut s = state(Phase::Unconfigured);
        s.plan = Some(vec![
            "record prior state".into(),
            "install reject rule".into(),
        ]);
        Ok(reply_with(s))
    });
    let dash = build(&app, transport);
    select(&app, 2);
    app.press("enter");
    wait_idle(&app, &dash);
    let sent = calls.lock().unwrap();
    assert!(matches!(
        decode_request(&sent[0]).unwrap().command,
        Command::Plan(_)
    ));
    let text = app.text();
    assert!(
        text.contains("Connection  Not configured: nothing applied"),
        "{text}"
    );
}

#[test]
fn mac_toggle_inspects_first_then_refuses_with_the_engine_reason() {
    let app = TestApp::new(100, 24);
    let (transport, calls) = fake(|req| {
        assert!(
            matches!(decode_request(req).unwrap().command, Command::Inspect),
            "the toggle may only send the read-only inspect"
        );
        let mut s = state(Phase::Disconnected);
        s.adapters = vec![AdapterInfo {
            name: "virbr0".into(),
            mac_change: Support::Unsupported,
        }];
        s.capabilities = vec![Capability {
            name: "linux.mac.virbr0".into(),
            support: Support::Unsupported,
            detail: "virbr0 is a virtual device".into(),
        }];
        Ok(reply_with(s))
    });
    let dash = build(&app, transport);
    select(&app, MAC);
    app.press("enter");
    wait_idle(&app, &dash);
    assert_eq!(calls.lock().unwrap().len(), 1);
    let text = app.text();
    assert!(
        text.contains("MAC change unavailable: no adapter is validated by the engine"),
        "{text}"
    );
    assert!(text.contains("virbr0: virbr0 is a virtual"), "{text}");
    assert!(text.contains("MAC mode    Off (default)"), "{text}");
}

#[test]
fn mac_toggle_inspects_first_then_selects_the_supported_adapter() {
    let app = TestApp::new(100, 24);
    let (transport, calls) = fake(|_| {
        let mut s = state(Phase::Disconnected);
        s.adapters = vec![
            AdapterInfo {
                name: "enp37s0".into(),
                mac_change: Support::Supported,
            },
            AdapterInfo {
                name: "virbr0".into(),
                mac_change: Support::Unsupported,
            },
        ];
        Ok(reply_with(s))
    });
    let dash = build(&app, transport);
    select(&app, MAC);
    app.press("enter");
    wait_idle(&app, &dash);
    assert_eq!(calls.lock().unwrap().len(), 1, "one inspect, nothing else");
    let text = app.text();
    assert!(text.contains("MAC on enp37s0 (1/1)"), "{text}");
    assert!(
        text.contains("MAC mode    Random on apply, adapter enp37s0"),
        "{text}"
    );
    // A second toggle is local (no new request) and turns MAC off again.
    app.press("enter");
    assert_eq!(calls.lock().unwrap().len(), 1);
    assert!(app.text().contains("MAC mode    Off (default)"));
}

#[test]
fn mac_toggle_with_validated_adapter_then_start_sends_explicit_selection() {
    let app = TestApp::new(100, 24);
    let (transport, calls) = fake(|req| {
        if decode_request(req)
            .map(|r| matches!(r.command, Command::Start(_)))
            .unwrap_or(false)
        {
            return Ok(error_reply(
                ErrorKind::PermissionDenied,
                "elevation required",
            ));
        }
        let mut s = state(Phase::Disconnected);
        s.adapters = vec![AdapterInfo {
            name: "eth0".into(),
            mac_change: Support::Supported,
        }];
        s.capabilities = vec![Capability {
            name: "linux.mac_adapter_change".into(),
            support: Support::Supported,
            detail: "read-back ok".into(),
        }];
        Ok(reply_with(s))
    });
    let dash = build(&app, transport);
    select(&app, STATUS);
    app.press("enter");
    wait_idle(&app, &dash);
    select(&app, MAC);
    app.press("enter");
    let text = app.text();
    assert!(
        text.contains("MAC mode    Random on apply, adapter eth0"),
        "{text}"
    );
    assert!(
        text.contains("MAC on eth0 (1/1): random on next Start"),
        "{text}"
    );

    // Cursor is on the MAC item (7); Start is item 3, four steps up. Start needs two Enters.
    for _ in 0..(MAC - START) {
        app.press("up");
    }
    app.press("enter");
    app.press("enter");
    wait_idle(&app, &dash);
    let sent = calls.lock().unwrap();
    let start = sent
        .iter()
        .map(|b| decode_request(b).unwrap())
        .find(|r| matches!(r.command, Command::Start(_)))
        .expect("start was sent after confirmation");
    match start.command {
        Command::Start(selection) => {
            assert_eq!(selection.config.mac, MacMode::RandomOnApply);
            assert_eq!(selection.adapter.unwrap().name, "eth0");
        }
        _ => unreachable!(),
    }
}

#[test]
fn messages_show_the_three_most_recent_lines() {
    let app = TestApp::new(80, 24);
    let (transport, _calls) = fake(|_| Ok(reply_with(state(Phase::Disconnected))));
    let dash = build(&app, transport);
    for _ in 0..3 {
        select(&app, STATUS);
        app.press("enter");
        wait_idle(&app, &dash);
        select(&app, 0);
        app.press("up");
    }
    let text = app.text();
    assert!(
        !text.contains("Engine not queried"),
        "oldest message should have scrolled out:\n{text}"
    );
}

#[test]
fn q_quits_and_timeout_is_reported() {
    let app = TestApp::new(80, 24);
    let dash = build(
        &app,
        Arc::new(ChildEngine::with_program(
            "/bin/sleep",
            vec![OsString::from("30")],
            Duration::from_millis(150),
        )),
    );
    // Inspect keeps the short read-only limit (status may wait for a polkit prompt).
    app.press("enter");
    wait_idle(&app, &dash);
    assert!(
        app.text().contains("inspect failed (timeout)"),
        "{}",
        app.text()
    );
    app.press("q");
    assert!(app.is_quitting(), "q must quit");
}

// ---- layout and animation ----

use torwell_ui::art::LayoutMode;
use torwell_ui::model::Mood;

#[test]
fn art_is_hidden_at_80x24_and_shown_at_100x30() {
    let (transport, _calls) = fake(|_| panic!("no request"));
    let small = TestApp::new(80, 24);
    let d = build(&small, Arc::clone(&transport));
    let text = small.text();
    println!("{text}");
    assert_eq!(d.layout(), LayoutMode::Compact);
    assert!(!text.contains("█████"), "big logo must be hidden:\n{text}");
    // Every panel and the menu still fit.
    for needle in ["Status", "Host", "Actions", "Log", "Up/Down move"] {
        assert!(text.contains(needle), "{needle} missing:\n{text}");
    }
    for action in torwell_ui::model::Action::ALL {
        assert!(text.contains(action.label()), "{}:\n{text}", action.label());
    }

    let big = TestApp::new(100, 30);
    let d = build(&big, transport);
    let text = big.text();
    println!("{text}");
    assert_eq!(d.layout(), LayoutMode::Wide);
    assert!(text.contains("█████"), "big logo missing:\n{text}");
    for action in torwell_ui::model::Action::ALL {
        assert!(text.contains(action.label()), "{}:\n{text}", action.label());
    }
    big.resize(80, 24);
    big.render();
    assert_eq!(d.layout(), LayoutMode::Compact);
    assert!(!big.text().contains("█████"));
}

#[test]
fn animation_advances_but_unknown_state_stays_dim_and_never_connected() {
    let app = TestApp::new(100, 30);
    let (transport, _calls) = fake(|_| panic!("no request"));
    let dash = build(&app, transport);
    assert_eq!(dash.mood(), Mood::Unknown);
    let before = app.text();
    app.advance(Duration::from_secs(2));
    app.render();
    let after = app.text();
    // Relay path pulses, text must keep the safe claims regardless of frame.
    for t in [&before, &after] {
        assert!(!t.contains("Connected") && !t.contains("Enforced") && !t.contains("VERIFIED"));
        assert!(t.contains("UNKNOWN"));
    }
}

#[test]
fn verified_connection_gets_connected_mood_and_starting_shows_progress_bar() {
    let app = TestApp::new(100, 30);
    let mut ok = state(Phase::Connected);
    ok.verification = Verification {
        tor_bootstrap: VerifyState::Passed,
        enforcement: VerifyState::Passed,
        mac_readback: VerifyState::NotRun,
    };
    let bytes = encode_response(&Response::ok(ok)).unwrap();
    let (transport, _calls) = fake(move |_| Ok(raw(bytes.clone(), Some(0))));
    let dash = build(&app, transport);
    select(&app, STATUS);
    app.press("enter");
    wait_idle(&app, &dash);
    assert_eq!(dash.mood(), Mood::Connected);
    assert!(app.text().contains("VERIFIED"));

    let app = TestApp::new(100, 30);
    let mut st = state(Phase::Starting);
    st.bootstrap_percent = Some(50);
    let bytes = encode_response(&Response::ok(st)).unwrap();
    let (transport, _calls) = fake(move |_| Ok(raw(bytes.clone(), Some(0))));
    let dash = build(&app, transport);
    select(&app, STATUS);
    app.press("enter");
    wait_idle(&app, &dash);
    assert_eq!(dash.mood(), Mood::Starting(Some(50)));
    let text = app.text();
    println!("{text}");
    assert!(text.contains("Bootstrap   50%"));
    assert!(text.contains("██████████░░░░░░░░░░"), "{text}");
    assert!(!text.contains("VERIFIED"));
}

#[test]
fn number_hotkey_selects_and_mutating_still_needs_confirmation() {
    let app = TestApp::new(80, 24);
    let (transport, calls) = fake(|_| panic!("a single start press must send nothing"));
    let dash = build(&app, transport);
    app.press("4");
    app.render();
    assert!(app.text().contains("Press Enter again to confirm start"));
    assert!(!dash.is_busy());
    assert!(calls.lock().unwrap().is_empty());
}
