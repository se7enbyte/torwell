# torwell-linux

Standalone crate `crates/torwell-linux/` (depends on `../torwell-core`, no workspace). Privileged library for the later engine: nftables enforcement around a dedicated systemd-managed Tor, root-owned durable state, optional NetworkManager MAC change. **Nothing here has been run on a host**: development used a fake runner/env, plus one `nft -c` syntax check inside `unshare -Urn`. No real Tor, nft apply, systemd, NetworkManager or leak test has happened.

## API (`torwell_linux`)

```rust
let mut b = Backend::system();                    // or Backend::new(runner, env, Paths)
b.preflight(want_mac) -> PreflightReport          // read-only; runs `nft --version`, `tor --version`
b.status() -> Result<Status, Error>               // persisted state; Active reported Starting (live state unknown)
b.inspect_live(timeout) -> Result<LiveStatus, Error>   // root, non-mutating re-check
b.mac_capability(iface, timeout) -> Capability    // read-only NM probe (3 nmcli calls); Supported = eligible
b.start(&StartOptions) -> Result<StartOutcome, OpFailure>
b.stop(&StopOptions)    -> Result<StopOutcome, OpFailure>   // Active/Blocked only
b.recover(&StopOptions) -> Result<StopOutcome, OpFailure>   // any non-idle state
b.switch_identity(timeout) -> Result<SwitchOutcome, OpFailure>  // NEWNYM
b.restore_at_boot(timeout) -> Result<BootRestore, Error>   // root; boot unit entry point
b.reboot_protection() -> RebootProtection        // is torwell-restore.service enabled?
```

`Runner` (commands: absolute program + argv + optional stdin + timeout) and `Env` (euid, user lookup, CSPRNG, clock, cookie read, control socket, /proc uids) are the injectable seams. `OpFailure { error, state }` carries the resulting core `State`: `Idle` = nothing changed, `Blocked` = enforcement re-verified, `RecoveryRequired` = unverified owned state remains. Mutations return `Error::NotRoot` unless `euid == 0`.

## Start order (deliberately differs from the advisory core plan)

1. validate options, root check, dependency preflight (trusted absolute binaries: not symlinked, root-owned, not group/other-writable, ancestors trusted; nft >= 1.0.0, tor >= 0.4.5 — thresholds are my assumption), state lock, refuse existing state or a foreign `inet torwell` table, read-only MAC discovery.
2. Record intent (`state.json`, phase `starting`).
3. Install managed assets (`/etc/torwell/torrc`, `/etc/systemd/system/torwell-tor.service`, `/etc/sysusers.d/torwell-tor.conf`; refuses files lacking the `# Managed by torwell-linux` marker), `systemd-sysusers`, `daemon-reload`, resolve `torwell-tor` (system uid 1..=999, nologin shell).
4. `nft -c -f -`, record `nft: pending`, `nft -f -` (one atomic transaction), list JSON, verify chains and **every rule expression** against the expected kernel form, record fingerprint.
5. Optional MAC (while blocking is already in force), with read-back.
6. `systemctl start`, bootstrap poll via control socket with deadline, verify listeners (`net/listeners/{socks,trans,dns}` are the sole `127.0.0.1:port`) and Tor pid uid, re-verify enforcement, then `Connected`.

Blocking is installed before the MAC change and Tor start so there is no direct window and no window under the old identity.

## nft policy (table `inet torwell`, output hook only)

* nat `output` prio -100: Tor uid and `lo` return; IPv4 UDP/53 -> DNSPort; other IPv4 TCP -> TransPort.
* filter `forward` prio 0, **policy drop**, one `reject` rule: VMs/containers routed through this host (libvirt, docker, podman bridges) never pass the output hook and would otherwise leave with the real IP. Tested with a TUN "guest" in `tests/netns/kernel_policy.py` (leaks before start, blocked after; negative control without the chain).
* filter `output` prio 0, **policy drop**: accept Tor uid, `lo`, flows the nat chain redirected to `127.0.0.1:TransPort`/`127.0.0.1:DNSPort` (`ct status dnat`), DHCPv4 client (udp 68->67, root only); `reject with tcp reset` for TCP, `reject with icmpx admin-prohibited` for the rest (other UDP, ICMP, IPv6 including DHCPv6/NDP).
* Why the redirected-flow accepts exist: in the output hook the filter chain still sees the *pre-NAT* output interface, so a redirected flow does not match `oifname "lo"`. Without them every redirected connection was rejected (`ECONNREFUSED` for TCP, `EPERM` for DNS). This bug was found by the packet test below; the earlier synthetic-JSON tests could not see it.
* No `ct state established` accept: existing direct flows are rejected. No flush/delete in the apply script. Every rule comment is `torwell:<token>:<tag>`; the 128-bit token is stored in state and proves ownership at teardown.
* No LAN exception: LAN TCP is redirected into Tor and fails. Forwarded/container traffic and the input hook are out of scope. The DHCP exception allows udp 68->67 to any address by any local process.
* Resolver files are never read or written.

## State, failure and recovery

State dir `/var/lib/torwell` (root, 0755, symlink/ownership-checked via `openat`+`O_NOFOLLOW`), `state.json` 0644 (no secrets, readable by status), `lock` 0600 `flock`. Writes are temp+fsync+rename+dir fsync.

* Failure before any enforcement exists: intent cleared, `Idle`.
* Failure after the table is installed: enforcement re-listed; if structure and fingerprint verify, `Fault::ProtectionVerified` -> `Blocked`; otherwise (or on failed MAC rollback) `Fault::Partial` -> `RecoveryRequired`. Traffic is never opened automatically; Tor is not stopped.
* `stop`/`recover` order: restore MAC (still blocked) -> stop Tor and confirm inactive -> prove token ownership then `delete table inet torwell` and confirm absent -> remove managed torrc -> clear state. Any failure leaves `RecoveryRequired` and the state file. A foreign-token table is left in place (`NotOwned`). The Tor user, unit file and sysusers file are not removed.

## Tor control

Unix `ControlSocket` plus cookie auth (no TCP ControlPort). Socket and cookie must be owned by the Tor uid with mode 0600; cookie 32 bytes, no symlink. Plain `COOKIE` AUTHENTICATE is used (SAFECOOKIE needs HMAC-SHA256; no crypto crate was available offline); the owner/mode checks and tor-owned `RuntimeDirectory` are the mitigation. Requests are pipelined (`AUTHENTICATE`, commands, `QUIT`) with read deadlines. NEWNYM success is Tor's `250 OK`; Tor may rate-limit the effect.

## MAC (optional, default off)

`nmcli` argument arrays only (run with `LC_ALL=C`, so field values are not localized; terse output is unescaped, so profile names with spaces or UTF-8 such as "Kablolu bağlantı 1" are not a problem because only UUIDs and interface names are passed).

**Capability (Inspect).** `mac_capability` is read-only and reports `Supported` when: `nmcli` is trusted, NM is running, the device is `GENERAL.NM-MANAGED=yes`, `GENERAL.TYPE` is `ethernet` or `wifi`, the state is `100 (connected)` (not `connected (externally)`, not disconnected) and `GENERAL.CON-UUID` is a real profile. `lo`, bridges, `virbr*`, `docker*`, `veth*`, `tun*`/`tap*`/`wg*` and anything resolving under `/sys/devices/virtual` are `Unsupported` with a reason (reported as `linux.mac.<iface>` capabilities). `Supported` is only eligibility; the proof is the read-back after the change. The probe costs three `nmcli` calls with a total budget of 3 s per adapter, and the engine stops probing after 5 s, so `inspect` stays inside the UI's 10 s limit. The default-route adapter (from `/proc/net/route`) is listed first.

**Apply.** The prior `cloned-mac-address` policy (including absent), the pre-change address and the prior `ipv4/ipv6.dhcp-send-hostname` values (only the properties that exist; `-1`/`0`/`1` on NM 1.52+, `yes`/`no` before) are recorded durably, then one `connection modify --temporary` sets the candidate MAC and both send-hostname properties to `no`, then `connection up`. Read-back: the profile reads the candidate, the hostname properties read `no`, and `GENERAL.HWADDR` equals the candidate (5 tries); any mismatch rolls back. Candidate: `getrandom` bytes -> core `from_candidate_bytes` (locally administered unicast).

**Restore (Stop, rollback, recover).** `connection modify --temporary` back to the recorded policy (absent = empty value, which nmcli documents as "reset to default"; the hostname default `-1` is restored the same way), `connection up`, then the profile and hostname values are read back against the record, and for `preserve`/`permanent`/`stable`/explicit policies the device address is compared with the pre-change address.

**`--temporary` semantics** (assumed from `nmcli(1)`/libnm, untested on hardware): the change lives in NetworkManager's memory only; the profile file on disk is not rewritten. An NM restart or `nmcli connection reload` while Torwell is active drops the change, and the next activation then uses the on-disk (original) MAC and hostname setting; nftables blocking stays in force. A restore with `--temporary` leaves the in-memory profile "unsaved" but equal to the original. Limits: nmcli prints unset as empty so "absent" = empty, and for an absent policy the final device address is not compared (a global NM default of `random` makes it unpredictable); `random-bia`/`stable-bia` are rejected as unsupported; wifi and real adapters are untested.

**UI flow.** Inspect (or the MAC toggle, which runs Inspect itself the first time) -> `MAC mode: toggle` selects the first `Supported` adapter (the default-route one when it qualifies) and each further press cycles to the next supported adapter, then back to off -> Start (two Enters) sends `mac: random_on_apply` plus that adapter -> the engine applies after the nft block is verified -> Connected shows the new MAC and "DHCP hostname not sent" -> Stop restores.

## Boot restore

`assets/torwell-restore.service` (`DefaultDependencies=no`, `After=local-fs.target nftables.service firewalld.service`, `Before=network-pre.target`) runs `torwell-engine restore-at-boot`, which calls `restore_at_boot`:

* no state -> `NothingToRestore`; owned table present and semantically verified -> `AlreadyEnforced`; table absent -> re-apply the same token/uid/ports, verify, fresh fingerprint, phase `Blocked` -> `Reapplied`.
* Never starts Tor, never touches NetworkManager, never deletes. A table that fails verification -> `RecoveryRequired`, nothing changed. A state without a Tor uid is refused (the uid exemption would cover root).
* `After=nftables.service`: Arch's `/etc/nftables.conf` begins with `flush ruleset`; running after it keeps that flush from deleting the restored table.
* `start` does not install or enable this unit. `reboot_protection()` reports whether it is installed and enabled; the engine/package must install it with `@TORWELL_ENGINE@` substituted and `systemctl enable` it. Until then protection does not survive a reboot.

## Tests

`cargo test` in the crate: 27 unit + 31 executor + 2 kernel-policy tests.

* Unit: nft policy properties; listing verification against a **real** `nft -j list table` captured from nftables 1.1.7 in `unshare -Urn` (`tests/fixtures/`); six semantic mutations that keep every ownership comment (uid, redirect port, redirect->accept, reject type, `lo`->`eth0`, final reject->accept) are all refused without a fingerprint.
* `tests/executor.rs`: fake runner/env, now fed the real listing; ordering, failure retention, non-root refusal, lock, fs safety, MAC rollback, boot restore (reboot simulated as table gone + Tor down).
* `tests/kernel_policy.rs` -> `tests/netns/kernel_policy.py`, inside `unshare -Urn` (script refuses the host netns): dummy0 with 10.9.9.1/24 and fd00:9::1/64, fake Tor listeners on 127.0.0.1, an observer table at output prio 100 counting what still leaves dummy0. Passed: TCP redirected (listener sees `SO_ORIGINAL_DST` 10.9.9.9:80), UDP/53 redirected to DNSPort, arbitrary UDPv4 blocked, IPv6 TCP/UDP/DNS blocked, a conntrack-established UDP flow from before enforcement blocked. Negative control: the same harness fails the ruleset without the redirected-flow accepts. Skips if unprivileged namespaces are unavailable.

These are kernel-policy tests; nothing about anonymity is proven.

* `tests/real_tor.rs` (opt-in, `TORWELL_TEST_TOR=/path/to/tor`): torwell's own rendered torrc run by a **real** Tor (0.4.9.16 from the official expert bundle, SHA-256 checked) inside `unshare -Urn` with only `lo`, so it cannot reach the Tor network. Passed: `tor --verify-config` accepts the torrc; `SystemEnv` cookie read + Unix control socket + `AUTHENTICATE`; `net/listeners/{socks,trans,dns}` are exactly `"127.0.0.1:<port>"`; `process/pid` is the tor process and its uids match; `status/bootstrap-phase` parses (`PROGRESS=0 TAG=starting`); `SIGNAL NEWNYM` -> `250 OK`; a cookie with the wrong owner is refused. (`DisableNetwork 1` is unusable for this: Tor then opens no client listeners.)
* **First real end-to-end run (2026-11-13, CachyOS, Tor 0.4.9.16 from the distro, engine installed in /usr/bin, elevated through pkexec/polkit):** start applied the block, Tor bootstrapped to 100%, `check.torproject.org/api/ip` returned `"IsTor":true` from an exit relay, an IPv6 request failed to connect, and stop restored direct networking. An earlier attempt failed because the Tor unit required the optional restore unit; the failure left the verified block in place (`Blocked`, read-back verified) and stop recovered, as designed.
* Expected Tor warning while active: `Rejecting request for anonymous connection to private address ... on a TransPort. Possible loop in your NAT rules?` A local program tried a LAN/private address; the rules send it to Tor and Tor refuses private destinations. This is the "LAN is blocked while active" policy, not a loop (the Tor uid is exempt).
* Not yet: boot protection across a real reboot, MAC change on real hardware, NetworkManager/firewalld/docker coexistence.

## Tor control spec check

Checked against spec.torproject.org control-spec: `status/bootstrap-phase`, `net/listeners/{socks,trans,dns}` (quoted, space-separated list), `process/pid`, `SIGNAL NEWNYM` -> `250 OK`, `250-key=value` / `250 OK` reply lines. Completion is `PROGRESS=100` **and** `TAG=done`. The spec marks `COOKIE` authentication deprecated; moving to `SAFECOOKIE` is a release gate.

## Unresolved (release gates)

* Real Tor bootstrap and end-to-end use on a CachyOS VM; DNS leak test with a real resolver.
* `torwell-engine` binary (protocol dispatcher + `restore-at-boot`) and installing/enabling the restore unit.
* NetworkManager/firewalld/docker coexistence; forwarded/container traffic is out of scope.
* SAFECOOKIE; minimum tool versions are assumptions.
