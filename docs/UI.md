# UI and engine protocol

`torwell-ui` is an unprivileged OpenTUI process. It performs read-only host capability
inspection locally through `torwell-core`; inspection does not apply firewall, DNS,
routing, or MAC changes. All engine actions run in a separate fixed sibling executable
(`torwell-engine` or `torwell-engine.exe`). The UI never invokes a shell or accepts a
command/path from the request. Until the engine and its privilege-separated platform
backends are integrated, its absence or inability to elevate is reported explicitly; the
UI never substitutes simulated success.

## Dashboard layout and animation

Panels: Status (Connection/Protection badges, bootstrap bar, MAC mode), Actions (menu),
Host (presence-only capabilities) and Log (last three messages). Keys: Up/Down, Enter,
`1`-`8` jump to an action (mutating actions still need a second press), `q` quits.

- Wide (at least 96x28): block-letter TORWELL logo, onion art and a relay path, two columns.
- Compact (80x24 and anything smaller): the big art is hidden; a one-line animated relay
  strip and stacked panels remain. The mode follows terminal resizes.

The animation is a pure function `(frame, mood, size)` in `src/art.rs`, ticked at 10 fps on
the UI thread (it never touches the engine worker; unchanged frames are not repainted).
`Mood` comes from `Model::mood()` and reflects only engine evidence: unknown/idle is a dim
slow pulse; starting is progress-driven by the reported bootstrap percentage; blocked is
red, recovery/unsupported amber. The green steady-flow look appears only for `Connected`,
which requires the connected phase plus passed Tor bootstrap and enforcement (and MAC
read-back when MAC mode is on). Otherwise the state is shown as unknown.

## Transport

Each request starts one child. The UI writes one UTF-8 JSON object to stdin and closes it;
the child writes exactly one UTF-8 JSON object to stdout and exits. Stderr is diagnostic
only. No newline is required. Requests and responses are each limited to 65,536 bytes;
the child has a 10-second default wall-clock timeout. Oversized stdout terminates the
child. Stderr is drained to avoid pipe deadlock, while only its first 4,096 bytes are
retained. A success response is accepted only with exit code zero. Unknown fields,
commands, enum values, and protocol versions are rejected. There is no network listener.

## Request schema (version 1)

All objects deny unknown fields. `version` is exactly `1`. Selection commands contain
the validated core config and an optional adapter. `config.mac` defaults to `off` in the
core; the wire form must state it explicitly. Ports are nonzero, distinct `u16` values.
`random_on_apply` requires an adapter.

```json
{"version":1,"command":"inspect"}
{"version":1,"command":"status"}
{"version":1,"command":"plan","config":{"mac":"off","socks_port":9050,"trans_port":9040,"dns_port":5353},"adapter":null}
{"version":1,"command":"start","config":{"mac":"off","socks_port":9050,"trans_port":9040,"dns_port":5353},"adapter":null}
{"version":1,"command":"stop"}
{"version":1,"command":"switch","config":{"mac":"off","socks_port":9050,"trans_port":9040,"dns_port":5353},"adapter":null}
{"version":1,"command":"recover"}
```

`adapter`, when selected, is `{"name":"..."}`; names are 1–64 characters without
control characters or surrounding whitespace. Commands are `inspect`, `status`, `plan`,
`start`, `stop`, `switch`, and `recover`. Only `plan`, `start`, and `switch` accept
`config` and `adapter`. A plan is inert and read-only.

## Response schema (version 1)

Exactly one of `state` or `error` accompanies status `ok` or `error` respectively:

```json
{"version":1,"status":"ok","state":{"phase":"disconnected","bootstrap_percent":null,"verification":{"tor_bootstrap":"unknown","enforcement":"unknown","mac_readback":"not_run"},"mac_mode":"off","capabilities":[],"adapters":[],"plan":null,"diagnostic":null}}
{"version":1,"status":"error","error":{"kind":"unsupported","message":"backend unavailable"}}
```

`phase` is `unconfigured`, `disconnected`, `starting`, `connected`, `blocked`,
`recovery_required`, or `unsupported`. `bootstrap_percent` is null except optionally in
`starting` (0–100). Verification values are `not_run`, `passed`, `failed`, and `unknown`.
Connected requires passed Tor bootstrap and enforcement evidence; if MAC is enabled,
MAC read-back must also pass. Blocked requires verified active enforcement. Capability
items are `{name, support, detail}` and adapter items are `{name, mac_change}`;
`support` is `supported`, `unsupported`, or `unknown`. `plan` is null or up to 32 inert
steps. Lists are capped at 32, adapter/capability text at 64/200 characters, plan steps
at 200 characters, and diagnostics at 512 characters. Error `kind` is one of
`invalid_request`, `unsupported_version`, `permission_denied`, `unsupported`,
`precondition_failed`, `adapter_unavailable`, `busy`, `internal`, `engine_unavailable`,
`timeout`, `message_too_large`, or `invalid_response`.

## Integration boundary

The child must perform non-mutating capability inspection without changing MAC state.
Only explicit typed selection and lifecycle commands may change state. The platform engine
and elevated transport are not yet integrated; Linux and Windows are targets, while
macOS is out of scope. A future engine must preserve recoverability, modify only
Torwell-owned state, reject bypass paths, and report connected only after Tor bootstrap
and enforcement read-back succeed. No real mutating engine is invoked by UI tests.
