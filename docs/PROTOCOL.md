# Initial UI/engine boundary

The OpenTUI process stays unprivileged. Network operations belong to a separate engine. The initial transport is one bounded JSON request on engine stdin and one JSON response on stdout; diagnostics use stderr. This protocol is local only, not a network listener. The integration phase will provide platform-specific privileged launch/service handling. Until then permission failures must be explicit.

The UI agent owns `crates/torwell-protocol/` and `crates/torwell-ui/`. Define shared Rust request/response types in the protocol crate and document final field names. Commands: inspect, status, plan, start, stop, switch, recover. Start/plan carry validated core Config and adapter selection; MAC is off by default. No arbitrary executable, shell command or file-operation field.

Responses distinguish unconfigured/disconnected, starting, connected (verified), blocked (verified active enforcement), recovery_required, and unsupported. Include capability details, optional bootstrap percentage, MAC mode/status, and a concise diagnostic. No fake connected state, fabricated public IP or synthetic Tor circuit in production. A missing engine must read "engine unavailable", not "disconnected and protected".

One request per child process; 64 KiB request/response limit; timeout; no inherited sensitive environment in elevated execution; no untrusted shell interpolation. The actual engine and elevated transport are integrated after the platform backends are ready. UI tests may use clearly isolated test handlers; default runtime must never silently fall back to simulated success.
