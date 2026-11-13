# torwell-windows

Standalone crate `crates/torwell-windows/` (depends on `../torwell-core`). Windows backend for the later engine. **Never run on Windows; no Windows support is claimed.**

## Status

* 73 portable tests pass on Linux (fake WFP, process launcher, runner, state store).
* `cargo check` and `cargo clippy -D warnings` pass for `x86_64-pc-windows-gnu`, so the Win32 code in `src/win/` type-checks. It has not executed.
* On non-Windows targets `WindowsBackend::system` returns `Error::Unsupported`.

## API

```rust
WindowsBackend::new(Deps) / WindowsBackend::system(state_dir)
b.start(&StartRequest) -> Result<Connected>
b.stop() -> Result<StopOutcome>
b.recover(RecoverMode) -> Result<StopOutcome>
b.status() -> StatusReport        // includes WFP read-back (`wfp_enforcing`)
b.lifecycle() -> &State
```

## Design (from the code)

* Kill switch: persistent WFP provider, sublayer and filters (no dynamic session, so it survives helper exit and BFE restart), added in one transaction, verified by read-back, removed only by Torwell's own keys. ALE auth-connect v4/v6 only.
* Arbitration (`src/policy.rs`): one Torwell sublayer; permits outweigh the catch-all block inside it; the clear-action-right flag is never set, so Torwell cannot override another sublayer's block. No unconditional permit; IPv6 permits only for loopback.
* Routing: Wintun tunnel created by the upstream **tun2proxy** binary (`--setup --proxy socks5://127.0.0.1:<socks> --tun <name> --dns virtual`), supervised as a child. Torwell implements no packet bridge. Preflight requires those flags in the pinned binary's `--help`.
* Tor bootstrap evidence, SDDL/ACL checks on durable state, optional MAC via adapter override with read-back and restore.

## Release gates

* Run on a real Windows VM: WFP objects, persistence across reboot, tun2proxy + Tor end to end, DNS/IPv6/existing-connection leak tests.
* Pin and verify a tun2proxy release and its licence/distribution.
* Inbound filtering and LAN exceptions are out of scope.
* `torwell-engine` integration (not written).
