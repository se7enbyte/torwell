//! Request routing: decode, decide whether elevation is needed, dispatch, finalize.

use torwell_core::{MacMode, State};
use torwell_linux::StartOptions;
use torwell_protocol::{
    decode_request, Command, EngineState, ErrorKind, Request, Response, Selection, MAX_LIST_ITEMS,
};

use crate::map::{self, Verb};
use crate::ops::Ops;
use crate::privilege::Escalator;
use crate::reply::{clean, error, error_reply, finalize, Reply};

/// Commands that change host state. Only these may ever be elevated.
pub fn is_mutating(command: &Command) -> bool {
    matches!(
        command,
        Command::Start(_) | Command::Stop | Command::Switch(_) | Command::Recover
    )
}

/// Handles one raw request. `allow_escalate` is false for the elevated child, so a
/// non-root child refuses instead of re-launching itself.
pub fn handle_bytes(
    input: &[u8],
    ops: &mut dyn Ops,
    escalator: &dyn Escalator,
    allow_escalate: bool,
) -> Reply {
    let request = match decode_request(input) {
        Ok(r) => r,
        Err(e) => return finalize(Response::err(e)),
    };
    if is_mutating(&request.command) && ops.euid() != 0 {
        if !allow_escalate {
            return error_reply(
                ErrorKind::PermissionDenied,
                "the engine is not running as root and elevation is disabled for this process",
            );
        }
        return match escalator.escalate(input) {
            Ok(reply) => reply,
            Err(e) => finalize(Response::err(e)),
        };
    }
    finalize(handle(ops, &request))
}

/// Dispatches a decoded request. Mutating commands are refused here unless root, so this
/// is safe to call directly.
pub fn handle(ops: &mut dyn Ops, request: &Request) -> Response {
    if is_mutating(&request.command) && ops.euid() != 0 {
        return Response::err(error(
            ErrorKind::PermissionDenied,
            "root is required for this command",
        ));
    }
    match &request.command {
        Command::Inspect => inspect(ops),
        Command::Status => observe(ops, true),
        Command::Plan(sel) => plan(ops, sel),
        Command::Start(sel) => start(ops, sel),
        Command::Stop => stop(ops, Verb::Stop),
        Command::Recover => stop(ops, Verb::Recover),
        Command::Switch(sel) => switch(ops, sel),
    }
}

/// Persisted state, plus live evidence only when root and a live check can apply.
fn observe(ops: &mut dyn Ops, want_live: bool) -> Response {
    let rp = ops.reboot_protection();
    let status = match ops.status() {
        Ok(s) => s,
        Err(e) => return Response::err(map::protocol_error(&e)),
    };
    let live_applies = matches!(
        status.state,
        State::Starting | State::Connected | State::Blocked { .. }
    );
    let live = if want_live && ops.euid() == 0 && live_applies {
        match ops.inspect_live() {
            Ok(l) => Some(l),
            Err(e) => return Response::err(map::protocol_error(&e)),
        }
    } else {
        None
    };
    Response::ok(map::persisted_state(&status, live.as_ref(), rp))
}

fn inspect(ops: &mut dyn Ops) -> Response {
    let mut state = match observe(ops, false).result {
        Ok(s) => s,
        Err(e) => return Response::err(e),
    };
    let host = ops.host();
    // Keep the reboot capability first, then host capabilities up to the protocol cap.
    state.capabilities.extend(host.capabilities);
    state.capabilities.truncate(MAX_LIST_ITEMS);
    state.adapters = host.adapters;
    state.adapters.truncate(MAX_LIST_ITEMS);
    Response::ok(state)
}

fn plan(ops: &mut dyn Ops, sel: &Selection) -> Response {
    let mut state = match observe(ops, false).result {
        Ok(s) => s,
        Err(e) => return Response::err(e),
    };
    state.plan = Some(plan_steps(sel));
    let current = state.diagnostic.take().unwrap_or_default();
    state.diagnostic = Some(crate::reply::diagnostic(
        "Plan only: nothing was applied.",
        Some(&current),
    ));
    Response::ok(state)
}

/// Inert plan text. It mirrors the order `Backend::start` uses (blocking before Tor and
/// before any MAC change) and applies nothing.
pub fn plan_steps(sel: &Selection) -> Vec<String> {
    let c = &sel.config;
    let mac = match (c.mac, &sel.adapter) {
        (MacMode::RandomOnApply, Some(a)) => format!(
            "5. Change the MAC of adapter {} through NetworkManager (temporary), read it back, roll back on mismatch.",
            a.name
        ),
        _ => "5. MAC address: unchanged (mode off).".to_string(),
    };
    [
        "Plan only: nothing below has been applied or will be applied by this command.".to_string(),
        "Start needs root; Torwell asks polkit (pkexec) to run the installed engine.".to_string(),
        "1. Record intent in root-owned state (/var/lib/torwell/state.json).".to_string(),
        format!(
            "2. Install the managed Tor unit and torrc and the torwell-tor user (SOCKS {}, TransPort {}, DNSPort {} on 127.0.0.1).",
            c.socks_port, c.trans_port, c.dns_port
        ),
        format!(
            "3. Install nft table `inet torwell`: IPv4 TCP to {}, UDP/53 to {}, all other traffic (IPv6 too) rejected, Tor user exempt.",
            c.trans_port, c.dns_port
        ),
        "4. Read the installed rules back and verify every expression before going on.".to_string(),
        mac,
        "6. Start the dedicated Tor service and wait for bootstrap.".to_string(),
        "7. Verify Tor listeners, the Tor process owner and enforcement again; only then report connected.".to_string(),
        "A failure after step 3 keeps traffic blocked (fail-closed); use recover or stop.".to_string(),
        "Stop: restore MAC, stop Tor, delete only the owned table, remove the managed torrc, clear state.".to_string(),
        "Not covered: forwarded/container traffic, LAN access, and reboot protection unless torwell-restore.service is enabled.".to_string(),
    ]
    .into_iter()
    .map(|s| clean(&s, 200))
    .collect()
}

fn start(ops: &mut dyn Ops, sel: &Selection) -> Response {
    let rp = ops.reboot_protection();
    let mut options = StartOptions::new(sel.config.clone());
    // The adapter only matters when MAC change is requested; the backend refuses an adapter
    // with MAC off, and an unused selection must not turn into an error.
    if sel.config.mac == MacMode::RandomOnApply {
        options.mac_interface = sel.adapter.as_ref().map(|a| a.name.clone());
    }
    match ops.start(&options) {
        Ok(out) => Response::ok(map::start_success(&out, &sel.config, rp)),
        Err(f) => map::failure(&f, Verb::Start, sel.config.mac, rp),
    }
}

fn stop(ops: &mut dyn Ops, verb: Verb) -> Response {
    let rp = ops.reboot_protection();
    let result = if verb == Verb::Stop {
        ops.stop()
    } else {
        ops.recover()
    };
    match result {
        Ok(out) => Response::ok(map::stopped(&out, verb, rp)),
        Err(f) => map::failure(&f, verb, MacMode::Off, rp),
    }
}

/// `switch` requests a new Tor identity (NEWNYM). The selection is validated by the
/// protocol but is not re-applied: changing ports or MAC needs `stop` then `start`. The
/// result state comes from a fresh live check, not from the signal being accepted.
fn switch(ops: &mut dyn Ops, sel: &Selection) -> Response {
    let rp = ops.reboot_protection();
    match ops.switch_identity() {
        Err(f) => map::failure(&f, Verb::Switch, sel.config.mac, rp),
        Ok(out) if !out.signal_accepted => Response::err(error(
            ErrorKind::Internal,
            "Tor did not accept the new-identity signal",
        )),
        Ok(_) => match observe(ops, true).result {
            Ok(state) => Response::ok(with_switch_note(state)),
            Err(e) => Response::err(e),
        },
    }
}

fn with_switch_note(mut state: EngineState) -> EngineState {
    let current = state.diagnostic.take().unwrap_or_default();
    state.diagnostic = Some(crate::reply::diagnostic(
        "New Tor identity requested (NEWNYM accepted; Tor may rate-limit it). The selection was not re-applied.",
        Some(&current),
    ));
    state
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::ops::Host;
    use crate::reply::{EXIT_ERROR, EXIT_OK};
    use std::cell::RefCell;
    use torwell_core::{Check, Config, Evidence};
    use torwell_linux::{
        BootRestore, Error, LiveStatus, OpFailure, RebootProtection, StartOutcome, Status,
        StopOutcome, SwitchOutcome,
    };
    use torwell_protocol::{
        decode_response, encode_request, Adapter, Phase, ProtocolError, VerifyState,
    };

    pub struct Fake {
        pub euid: u32,
        pub status: Result<Status, Error>,
        pub live: Result<LiveStatus, Error>,
        pub start: Result<StartOutcome, OpFailure>,
        pub stop: Result<StopOutcome, OpFailure>,
        pub switch: Result<SwitchOutcome, OpFailure>,
        pub rp: RebootProtection,
        pub calls: Vec<&'static str>,
        pub start_options: Option<StartOptions>,
    }

    impl Fake {
        pub fn new(euid: u32) -> Self {
            Fake {
                euid,
                status: Ok(Status {
                    state: State::Idle,
                    tor_uid: None,
                    mac: None,
                }),
                live: Ok(LiveStatus {
                    enforcement: Check::Passed,
                    tor_bootstrap: Check::Passed,
                    detail: vec![],
                }),
                start: Ok(StartOutcome {
                    state: State::Connected,
                    evidence: Evidence {
                        tor_bootstrap: Check::Passed,
                        enforcement: Check::Passed,
                        mac_readback: Check::NotRun,
                    },
                    tor_uid: 970,
                    mac: None,
                }),
                stop: Ok(StopOutcome {
                    mac_restored: false,
                    tor_stopped: true,
                    table_removed: true,
                }),
                switch: Ok(SwitchOutcome {
                    signal_accepted: true,
                }),
                rp: RebootProtection::NotInstalled,
                calls: vec![],
                start_options: None,
            }
        }
    }

    impl Ops for Fake {
        fn euid(&self) -> u32 {
            self.euid
        }
        fn host(&mut self) -> Host {
            self.calls.push("host");
            Host::default()
        }
        fn status(&mut self) -> Result<Status, Error> {
            self.calls.push("status");
            self.status.clone()
        }
        fn inspect_live(&mut self) -> Result<LiveStatus, Error> {
            self.calls.push("inspect_live");
            self.live.clone()
        }
        fn reboot_protection(&self) -> RebootProtection {
            self.rp
        }
        fn start(&mut self, o: &StartOptions) -> Result<StartOutcome, OpFailure> {
            self.calls.push("start");
            self.start_options = Some(o.clone());
            self.start.clone()
        }
        fn stop(&mut self) -> Result<StopOutcome, OpFailure> {
            self.calls.push("stop");
            self.stop.clone()
        }
        fn recover(&mut self) -> Result<StopOutcome, OpFailure> {
            self.calls.push("recover");
            self.stop.clone()
        }
        fn switch_identity(&mut self) -> Result<SwitchOutcome, OpFailure> {
            self.calls.push("switch");
            self.switch.clone()
        }
        fn restore_at_boot(&mut self) -> Result<BootRestore, Error> {
            self.calls.push("restore");
            Ok(BootRestore::NothingToRestore)
        }
    }

    /// Records calls instead of executing anything.
    #[derive(Default)]
    pub struct SpyEscalator {
        pub seen: RefCell<Vec<Vec<u8>>>,
        pub answer: Option<Reply>,
    }

    impl Escalator for SpyEscalator {
        fn escalate(&self, request: &[u8]) -> Result<Reply, ProtocolError> {
            self.seen.borrow_mut().push(request.to_vec());
            self.answer
                .clone()
                .ok_or_else(|| ProtocolError::new(ErrorKind::PermissionDenied, "spy: no answer"))
        }
    }

    fn sel(mac: MacMode, adapter: Option<&str>) -> Selection {
        Selection::new(
            Config {
                mac,
                ..Config::default()
            },
            adapter.map(|a| Adapter::new(a).unwrap()),
        )
        .unwrap()
    }

    fn bytes(c: Command) -> Vec<u8> {
        encode_request(&Request::new(c)).unwrap()
    }

    fn run(c: Command, fake: &mut Fake, esc: &SpyEscalator) -> (Response, i32) {
        let reply = handle_bytes(&bytes(c), fake, esc, true);
        (decode_response(&reply.stdout).unwrap(), reply.exit_code)
    }

    #[test]
    fn read_only_commands_never_escalate_or_mutate() {
        let esc = SpyEscalator::default();
        for c in [
            Command::Inspect,
            Command::Status,
            Command::Plan(sel(MacMode::Off, None)),
        ] {
            let mut fake = Fake::new(1000);
            let (resp, code) = run(c, &mut fake, &esc);
            assert!(resp.result.is_ok());
            assert_eq!(code, EXIT_OK);
            assert!(
                fake.calls.iter().all(|c| ["status", "host"].contains(c)),
                "{:?}",
                fake.calls
            );
        }
        assert!(esc.seen.borrow().is_empty());
    }

    #[test]
    fn mutating_commands_escalate_when_not_root_with_the_original_bytes() {
        let esc = SpyEscalator {
            answer: Some(error_reply(ErrorKind::Busy, "from elevated child")),
            ..Default::default()
        };
        for c in [
            Command::Start(sel(MacMode::Off, None)),
            Command::Stop,
            Command::Recover,
            Command::Switch(sel(MacMode::Off, None)),
        ] {
            let input = bytes(c);
            let mut fake = Fake::new(1000);
            let reply = handle_bytes(&input, &mut fake, &esc, true);
            assert_eq!(esc.seen.borrow().last().unwrap(), &input);
            assert!(
                fake.calls.is_empty(),
                "no local backend call: {:?}",
                fake.calls
            );
            let resp = decode_response(&reply.stdout).unwrap();
            assert_eq!(resp.result.unwrap_err().kind, ErrorKind::Busy);
        }
        assert_eq!(esc.seen.borrow().len(), 4);
    }

    #[test]
    fn elevated_child_never_re_escalates() {
        let esc = SpyEscalator::default();
        let mut fake = Fake::new(1000);
        let reply = handle_bytes(&bytes(Command::Stop), &mut fake, &esc, false);
        let resp = decode_response(&reply.stdout).unwrap();
        assert_eq!(resp.result.unwrap_err().kind, ErrorKind::PermissionDenied);
        assert!(esc.seen.borrow().is_empty() && fake.calls.is_empty());
    }

    #[test]
    fn handle_refuses_mutations_without_root_even_if_called_directly() {
        let mut fake = Fake::new(1000);
        let r = handle(&mut fake, &Request::new(Command::Stop));
        assert_eq!(r.result.unwrap_err().kind, ErrorKind::PermissionDenied);
        assert!(fake.calls.is_empty());
    }

    #[test]
    fn invalid_oversized_and_unknown_requests_are_refused_before_anything_runs() {
        let esc = SpyEscalator::default();
        let cases: Vec<(Vec<u8>, ErrorKind)> = vec![
            (b"not json".to_vec(), ErrorKind::InvalidRequest),
            (br#"{"version":1,"command":"format-disk"}"#.to_vec(), ErrorKind::InvalidRequest),
            (br#"{"version":1,"command":"stop","exec":"/bin/sh"}"#.to_vec(), ErrorKind::InvalidRequest),
            (br#"{"version":2,"command":"status"}"#.to_vec(), ErrorKind::UnsupportedVersion),
            (br#"{"version":1,"command":"start"}"#.to_vec(), ErrorKind::InvalidRequest),
            (
                br#"{"version":1,"command":"start","config":{"mac":"off","socks_port":1,"trans_port":1,"dns_port":2}}"#.to_vec(),
                ErrorKind::InvalidRequest,
            ),
            (vec![b' '; torwell_protocol::MAX_MESSAGE_BYTES + 1], ErrorKind::MessageTooLarge),
            (Vec::new(), ErrorKind::InvalidRequest),
        ];
        for (input, kind) in cases {
            let mut fake = Fake::new(0);
            let reply = handle_bytes(&input, &mut fake, &esc, true);
            assert_eq!(reply.exit_code, EXIT_ERROR);
            let resp = decode_response(&reply.stdout).unwrap();
            assert_eq!(resp.result.unwrap_err().kind, kind);
            assert!(fake.calls.is_empty());
        }
        assert!(esc.seen.borrow().is_empty());
    }

    #[test]
    fn status_as_root_reports_connected_only_with_live_evidence() {
        let esc = SpyEscalator::default();
        let mut fake = Fake::new(0);
        fake.status = Ok(Status {
            state: State::Starting,
            tor_uid: Some(970),
            mac: None,
        });
        let (resp, _) = run(Command::Status, &mut fake, &esc);
        let s = resp.result.unwrap();
        assert_eq!(s.phase, Phase::Connected);
        assert_eq!(s.verification.tor_bootstrap, VerifyState::Passed);
        assert!(fake.calls.contains(&"inspect_live"));

        for (enf, tor, want) in [
            (Check::Passed, Check::Failed, Phase::Blocked),
            (Check::Failed, Check::Passed, Phase::RecoveryRequired),
            (Check::NotRun, Check::NotRun, Phase::RecoveryRequired),
        ] {
            let mut fake = Fake::new(0);
            fake.status = Ok(Status {
                state: State::Connected,
                tor_uid: Some(970),
                mac: None,
            });
            fake.live = Ok(LiveStatus {
                enforcement: enf,
                tor_bootstrap: tor,
                detail: vec![],
            });
            let (resp, _) = run(Command::Status, &mut fake, &esc);
            assert_eq!(resp.result.unwrap().phase, want);
        }
    }

    #[test]
    fn status_unprivileged_never_says_connected() {
        let esc = SpyEscalator::default();
        let mut fake = Fake::new(1000);
        fake.status = Ok(Status {
            state: State::Connected,
            tor_uid: Some(970),
            mac: None,
        });
        let (resp, _) = run(Command::Status, &mut fake, &esc);
        let s = resp.result.unwrap();
        assert_eq!(s.phase, Phase::Starting);
        assert!(!fake.calls.contains(&"inspect_live"));
    }

    #[test]
    fn status_backend_error_is_a_protocol_error_not_disconnected() {
        let esc = SpyEscalator::default();
        let mut fake = Fake::new(1000);
        fake.status = Err(Error::State("corrupt state".into()));
        let (resp, code) = run(Command::Status, &mut fake, &esc);
        assert_eq!(resp.result.unwrap_err().kind, ErrorKind::Internal);
        assert_eq!(code, EXIT_ERROR);
    }

    #[test]
    fn inspect_carries_host_facts_and_reboot_capability_first() {
        struct H(Fake);
        impl Ops for H {
            fn euid(&self) -> u32 {
                self.0.euid()
            }
            fn host(&mut self) -> Host {
                Host {
                    capabilities: vec![torwell_protocol::Capability {
                        name: "linux.nftables".into(),
                        support: torwell_core::Support::Supported,
                        detail: "found".into(),
                    }],
                    adapters: vec![torwell_protocol::AdapterInfo {
                        name: "wlan0".into(),
                        mac_change: torwell_core::Support::Unknown,
                    }],
                }
            }
            fn status(&mut self) -> Result<Status, Error> {
                self.0.status()
            }
            fn inspect_live(&mut self) -> Result<LiveStatus, Error> {
                self.0.inspect_live()
            }
            fn reboot_protection(&self) -> RebootProtection {
                self.0.rp
            }
            fn start(&mut self, o: &StartOptions) -> Result<StartOutcome, OpFailure> {
                self.0.start(o)
            }
            fn stop(&mut self) -> Result<StopOutcome, OpFailure> {
                self.0.stop()
            }
            fn recover(&mut self) -> Result<StopOutcome, OpFailure> {
                self.0.recover()
            }
            fn switch_identity(&mut self) -> Result<SwitchOutcome, OpFailure> {
                self.0.switch_identity()
            }
            fn restore_at_boot(&mut self) -> Result<BootRestore, Error> {
                self.0.restore_at_boot()
            }
        }
        let mut ops = H(Fake::new(1000));
        let r = handle(&mut ops, &Request::new(Command::Inspect));
        let s = r.result.unwrap();
        assert_eq!(s.capabilities[0].name, map::REBOOT_CAPABILITY);
        assert_eq!(s.capabilities[1].name, "linux.nftables");
        assert_eq!(s.adapters[0].name, "wlan0");
        assert_eq!(s.phase, Phase::Disconnected);
    }

    #[test]
    fn plan_is_inert_bounded_text() {
        let mut fake = Fake::new(1000);
        let r = handle(
            &mut fake,
            &Request::new(Command::Plan(sel(MacMode::RandomOnApply, Some("wlan0")))),
        );
        let s = r.result.unwrap();
        let steps = s.plan.unwrap();
        assert!(steps.len() <= MAX_LIST_ITEMS);
        assert!(steps.iter().any(|l| l.contains("wlan0")));
        assert!(steps[0].starts_with("Plan only"));
        assert!(s.diagnostic.unwrap().starts_with("Plan only"));
        assert_eq!(fake.calls, vec!["status"]);
    }

    #[test]
    fn start_as_root_reports_connected_with_evidence_and_passes_mac_interface() {
        let mut fake = Fake::new(0);
        let r = handle(
            &mut fake,
            &Request::new(Command::Start(sel(MacMode::Off, Some("wlan0")))),
        );
        let s = r.result.unwrap();
        assert_eq!(s.phase, Phase::Connected);
        assert_eq!(s.verification.mac_readback, VerifyState::NotRun);
        // adapter ignored when MAC is off: the backend would refuse it.
        assert_eq!(fake.start_options.unwrap().mac_interface, None);

        let mut fake = Fake::new(0);
        let _ = handle(
            &mut fake,
            &Request::new(Command::Start(sel(MacMode::RandomOnApply, Some("wlan0")))),
        );
        assert_eq!(
            fake.start_options.unwrap().mac_interface.as_deref(),
            Some("wlan0")
        );
    }

    #[test]
    fn start_without_evidence_is_not_connected() {
        let mut fake = Fake::new(0);
        fake.start = Ok(StartOutcome {
            state: State::Connected,
            evidence: Evidence {
                tor_bootstrap: Check::NotRun,
                enforcement: Check::Passed,
                mac_readback: Check::NotRun,
            },
            tor_uid: 970,
            mac: None,
        });
        let r = handle(
            &mut fake,
            &Request::new(Command::Start(sel(MacMode::Off, None))),
        );
        assert_ne!(r.result.unwrap().phase, Phase::Connected);
    }

    #[test]
    fn start_failure_states_pass_through() {
        let mut fake = Fake::new(0);
        fake.start = Err(OpFailure {
            error: Error::Tor("bootstrap timed out".into()),
            state: State::Blocked { reason: "x".into() },
        });
        let s = handle(
            &mut fake,
            &Request::new(Command::Start(sel(MacMode::Off, None))),
        )
        .result
        .unwrap();
        assert_eq!(s.phase, Phase::Blocked);
        assert!(s.diagnostic.unwrap().contains("bootstrap timed out"));

        let mut fake = Fake::new(0);
        fake.start = Err(OpFailure {
            error: Error::Preflight(vec!["nft: missing".into()]),
            state: State::Idle,
        });
        let e = handle(
            &mut fake,
            &Request::new(Command::Start(sel(MacMode::Off, None))),
        )
        .result
        .unwrap_err();
        assert_eq!(e.kind, ErrorKind::PreconditionFailed);
    }

    #[test]
    fn stop_and_recover_map_to_disconnected_or_recovery() {
        let mut fake = Fake::new(0);
        let s = handle(&mut fake, &Request::new(Command::Stop))
            .result
            .unwrap();
        assert_eq!(s.phase, Phase::Disconnected);
        assert_eq!(fake.calls, vec!["stop"]);
        let mut fake = Fake::new(0);
        let _ = handle(&mut fake, &Request::new(Command::Recover));
        assert_eq!(fake.calls, vec!["recover"]);

        let mut fake = Fake::new(0);
        fake.stop = Err(OpFailure {
            error: Error::NotOwned("foreign".into()),
            state: State::RecoveryRequired { reason: "r".into() },
        });
        let s = handle(&mut fake, &Request::new(Command::Stop))
            .result
            .unwrap();
        assert_eq!(s.phase, Phase::RecoveryRequired);
    }

    #[test]
    fn switch_reports_state_from_live_evidence() {
        let mut fake = Fake::new(0);
        fake.status = Ok(Status {
            state: State::Connected,
            tor_uid: Some(970),
            mac: None,
        });
        let s = handle(
            &mut fake,
            &Request::new(Command::Switch(sel(MacMode::Off, None))),
        )
        .result
        .unwrap();
        assert_eq!(s.phase, Phase::Connected);
        assert!(s.diagnostic.unwrap().contains("NEWNYM"));
        assert_eq!(fake.calls, vec!["switch", "status", "inspect_live"]);

        let mut fake = Fake::new(0);
        fake.status = Ok(Status {
            state: State::Connected,
            tor_uid: Some(970),
            mac: None,
        });
        fake.live = Ok(LiveStatus {
            enforcement: Check::Passed,
            tor_bootstrap: Check::Failed,
            detail: vec![],
        });
        let s = handle(
            &mut fake,
            &Request::new(Command::Switch(sel(MacMode::Off, None))),
        )
        .result
        .unwrap();
        assert_ne!(s.phase, Phase::Connected);

        let mut fake = Fake::new(0);
        fake.switch = Ok(SwitchOutcome {
            signal_accepted: false,
        });
        let e = handle(
            &mut fake,
            &Request::new(Command::Switch(sel(MacMode::Off, None))),
        )
        .result
        .unwrap_err();
        assert_eq!(e.kind, ErrorKind::Internal);
    }

    #[test]
    fn backend_text_is_cleaned_in_error_messages() {
        let mut fake = Fake::new(0);
        fake.stop = Err(OpFailure {
            error: Error::Command {
                what: "nft".into(),
                detail: format!("bad\n\u{7}{}", "x".repeat(2000)),
            },
            state: State::Idle,
        });
        let reply = finalize(handle(&mut fake, &Request::new(Command::Stop)));
        let resp = decode_response(&reply.stdout).unwrap();
        let e = resp.result.unwrap_err();
        assert!(e.is_bounded());
    }
}
