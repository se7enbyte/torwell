# torwell-core

Standalone Rust crate at `crates/torwell-core/`. It is the platform-neutral foundation for the next phase. It changes no firewall, DNS, routing or MAC state, starts no process, runs no command, and makes no network request. Its plans are inert data.

No root workspace exists yet. The crate has its own `Cargo.toml` and `Cargo.lock`.

## API summary

| Module | Purpose |
|---|---|
| `config` | `Config { mac, socks_port, trans_port, dns_port }`, `MacMode::{Off, RandomOnApply}` (default `Off`), `validate()` (non-zero, distinct ports), `check_name()`. |
| `capability` | `Support::{Supported, Unsupported, Unknown}`, `Os`, `Capability`, `Report::get(name)`. |
| `host` | `detect_host()` / `detect(os, probe)`. Only OS and file-presence checks (`nft`, `tor`, `ip`). Windows runtime is always `Unknown`. |
| `mac` | `MacAddress::parse` / `new` (rejects zero, multicast, broadcast, malformed), `from_candidate_bytes` (sets U/L, clears I/G from caller bytes), `ProfileMac`, `MacRestore`. |
| `lifecycle` | `Lifecycle` state machine, `Evidence { tor_bootstrap, enforcement, mac_readback }` with `Check`, `Fault`. |
| `plan` | `linux_nftables_plan`, `linux_teardown_plan`, `windows_wintun_plan`, `windows_teardown_plan`. Serializable typed `Step`s with `PlanStatus::PlanOnly`. |

## Invariants and where they are tested

- **Invalid MAC input is rejected.** Zero, multicast and broadcast values, and malformed text. (`mac::tests`)
- **Candidates are locally administered unicast.** They come from caller-supplied bytes, and the crate does not generate randomness. (`mac::tests`)
- **Restore uses the prior profile policy, not the effective address.** `MacRestore::restore_profile()` returns the profile, and the effective address is for read-back only. An absent override is restored as `Absent`. (`mac::tests`, `plan::tests::teardown_restores_profile_not_effective_address`)
- **`Connected` requires evidence.** It is reachable only from `Starting`, and it requires `tor_bootstrap` and `enforcement` to be `Passed`. `mac_readback` is also required when MAC mode is on. A failed check leaves the state at `Starting`. (`lifecycle::tests`)
- **Failures retain protective state.** Only an executor-verified active blocking policy may use `Fault::ProtectionVerified` to enter `Blocked`; accounting for mutations is not enough. This model does not itself enforce networking. A partial failure enters `RecoveryRequired`. Neither can restart or connect. Only `request_stop` leaves them, and a failed teardown stays in `RecoveryRequired`. (`lifecycle::tests`)
- **No flush, no foreign deletes.** Generated plans contain no flush operation. The only delete is `NftDeleteOwnedTable { table: "torwell" }`. (`plan::tests::linux_plan_never_flushes_and_only_touches_owned_table`)
- **Rules before Tor.** Linux plans record prior state first, install the reject rule before `StartTor`, and reject root's Tor uid (`0`). (`plan::tests`)
- **Windows runtime is not assumed.** Detection and plan caveats say "not tested". (`host::tests`, `plan::tests`)

## Lifecycle

```
Idle -> Planning -> Starting -> Connected          (verify_connected needs Evidence)
Planning|Starting|Connected --fail(ProtectionVerified)--> Blocked            (fail-closed)
Planning|Starting|Connected --fail(Partial)----> RecoveryRequired
Planning|Starting|Connected|Blocked|RecoveryRequired --request_stop--> Stopping
Stopping --finish_stop(Ok)--> Idle ; finish_stop(Err(reason)) --> RecoveryRequired
```

## Not included yet

- No executor. Nothing applies a plan, runs `nft`, starts Tor, creates Wintun or installs WFP.
- No persistence of `MacRestore` or lifecycle state across crashes.
- No LAN or local-network exception rules. The plan has none yet.
- No IPv6 or UDP tests. The plan rejects them by policy. Leak tests are needed.
- No Windows or macOS runtime evidence. Windows plans are inert and untested. macOS is out of scope.
- The plan Windows MAC step is driver-dependent and has no verified adapter API behaviour.

## Build and test

```sh
export RUSTUP_HOME=/home/se7enbyte/torwell/.tooling/rustup \
       CARGO_HOME=/home/se7enbyte/torwell/.tooling/cargo \
       RUSTUP_TOOLCHAIN=1.99.1-x86_64-unknown-linux-gnu
/home/se7enbyte/torwell/.tooling/cargo/bin/cargo test --manifest-path /home/se7enbyte/torwell/crates/torwell-core/Cargo.toml
```

Dependencies: `serde` (derive) at runtime and `serde_json` as a dev-dependency only. Clippy and rustfmt are not installed in the `.tooling` toolchain, so they were not run.
