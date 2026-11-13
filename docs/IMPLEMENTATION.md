# Torwell implementation scope

User decision, 2026-11-13: target Linux and Windows; macOS is out of scope. First Linux distribution: Arch/CachyOS. Rust application code and OpenTUI frontend are required. Optional MAC changes depend on adapter support and default off.

## Work sequence

1. Resolve the matching native OpenTUI/Rust build from pinned upstream source; compile and run a minimal real frontend. Source builds are now in scope, unlike the earlier limited artifact check.
2. Implement a platform-neutral Rust policy/state core, explicit capabilities, non-mutating inspection and plans. A generated plan is not an applied connection.
3. Add actual platform executors, privilege separation and the OpenTUI dashboard. Linux candidate: nftables + Tor. Windows candidate: signed Wintun + TCP-to-SOCKS bridge + WFP. These are implementation candidates until tested.
4. Verify in isolated environments. No changes to this host's firewall, DNS, routing or MAC during development. No platform support claims based solely on compiling.

## Invariants

- Only manipulate Torwell-owned firewall state; never flush unrelated rules.
- Reject direct bypass including existing connections, uncontrolled UDP and unhandled IPv6. Keep explicit minimal exceptions needed for local networking and Tor itself.
- Record intended state before mutations and preserve recoverability across partial failures. Do not report connected until Tor bootstrap and the relevant enforcement checks succeed.
- A crash must not silently switch to unrestricted direct access. Explicit stop/recover has a separate, documented policy.
- MAC opt-in includes disruption information. Preserve original policy as well as the effective address, verify read-back, never mutate interfaces during automatic capability discovery.
- Keep privileged operations behind narrow typed requests. Never execute untrusted strings through a shell. Read-only UI must not require admin.
- Surface missing dependencies, untested adapters and unsupported backends honestly.

## Current parallel tasks

- OpenTUI source-build proof owns `spikes/opentui-smoke/`, `.tooling/`, `scripts/bootstrap-opentui.*` and its research report.
- Core foundation owns standalone `crates/torwell-core/` and `docs/CORE.md`. No other agent changes that crate until handoff.

Root workspace and integration are established after the native frontend proof and core API exist. No GitHub publication until the visibility choice is resolved.
