# torwell

A modern, fail-closed Tor traffic router in Rust, with an OpenTUI terminal interface.

Torwell is a planned successor to [TorGhost](https://github.com/SusmithKrishnan/torghost).
Its goal is to route all system TCP and DNS traffic through Tor, block everything else
(including IPv6 and any direct fallback), and be cleanly reversible: it touches only its
own nftables table and its own durable state, and never flushes or rewrites anybody
else's rules.

**Status: early development.** On CachyOS it has run end to end once: start through
pkexec/polkit, Tor bootstrapped to 100%, check.torproject.org reported `IsTor: true`, IPv6
was blocked and stop restored the network. Reboot protection, MAC change on real hardware
and other distributions are not tested yet. No anonymity claim is made.

## Goals

* All TCP and DNS through Tor, with no direct path out.
* Fail closed: IPv6, uncontrolled UDP and existing direct connections are rejected.
  Failure keeps the blocking policy in place instead of opening the network.
* Reversible: a single owned `inet torwell` nftables table, plus state under
  `/var/lib/torwell`; teardown proves ownership before deleting anything.
* Optional MAC randomization, **off by default**, only on supported adapters.
* OpenTUI dashboard that runs unprivileged and talks to a privileged helper over a
  typed, local-only protocol.

## Why not TorGhost

TorGhost is a Python script around iptables. It flushes and overwrites the existing
iptables ruleset, and on stop it sets the policies back to `ACCEPT`, so unrelated
firewall configuration is lost. It has no IPv6 handling, and its error handling is weak:
a failure partway through can leave the host in an unknown state.

Torwell instead installs one atomic nftables transaction in its own table, verifies the
installed rules by reading them back, records intent before mutating anything, and
refuses to claim success without evidence. See [docs/FEASIBILITY.md](docs/FEASIBILITY.md)
and [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md).

## Platform status

| Platform | Status | Notes |
|---|---|---|
| Linux (Arch/CachyOS first) | In development, works end to end on CachyOS | nftables policy tested with real packets in namespaces; real start/stop with Tor verified once on CachyOS |
| Windows | Code exists, **not supported** | Never run on Windows; portable tests pass on Linux and the Win32 code type-checks, nothing more |
| macOS | Out of scope | — |

No platform is claimed as supported. Compiling is not evidence of working behaviour.

## Architecture

| Crate | Role |
|---|---|
| `torwell-core` | Platform-neutral policy: config, MAC validation, capabilities, lifecycle state machine, inert plans. Changes no system state. |
| `torwell-protocol` | Versioned, typed JSON request/response contract between the UI and the engine, written to stdin/stdout. |
| `torwell-linux` | Privileged Linux backend: nftables enforcement around a dedicated systemd-managed Tor, root-owned state, boot restore, optional NetworkManager MAC change. |
| `torwell-windows` | Windows backend: persistent WFP filters, a tun2proxy-supervised Wintun tunnel, Tor bootstrap, adapter MAC override. Untested on Windows. |
| `torwell-ui` | Unprivileged OpenTUI dashboard. Read-only local inspection; all actions go to a separate engine executable. |
| `torwell-engine` | Privileged helper that exists in the tree: dispatches the protocol, elevates via pkexec/polkit, and implements `restore-at-boot` and `boot-protection`. **Never run as root yet.** |

The UI never invokes a shell and never fabricates a connected state: a missing engine is
reported as `engine_unavailable`, not as "protected". Details in
[docs/UI.md](docs/UI.md) and [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Building

The toolchain and the pinned OpenTUI native library are project-local under `.tooling/`
and are bootstrapped by `scripts/bootstrap-opentui.sh` (Linux x86_64, no sudo, no profile
edits). It also builds and smoke-tests `spikes/opentui-smoke`. Then:

```sh
source scripts/env-opentui.sh
cargo build --release --manifest-path crates/torwell-core/Cargo.toml
cargo build --release --manifest-path crates/torwell-linux/Cargo.toml
cargo build --release --manifest-path crates/torwell-ui/Cargo.toml
cargo build --release --manifest-path crates/torwell-engine/Cargo.toml
```

Each crate is standalone; there is no root workspace. `torwell-ui` links the native
OpenTUI library from `.tooling/src/opentui`, so run the bootstrap first. Tests:
`cargo test --manifest-path crates/<crate>/Cargo.toml`.

Arch packaging lives in `packaging/arch/` (`PKGBUILD`; build with `makepkg -s`).

## Safety notes and limitations

* **Torwell does not make you anonymous by itself.** Routing traffic through Tor does not
  hide identifying behaviour, logins, or browser fingerprints. Tor does not carry general
  UDP/QUIC.
* **A MAC change does not hide your IP.** It changes the link-layer address on one
  adapter; your public IP and Tor entry guard are unaffected.
* **LAN traffic is blocked while Torwell is active.** There is no LAN exception: local
  TCP is redirected into Tor and fails. The only non-Tor exceptions are loopback, Tor's
  own uid, and DHCPv4 (UDP 68→67, for any local process). Inbound, forwarded and
  container traffic are out of scope.
* **DNS only via Tor's DNSPort.** Resolver files are never modified; UDP/53 is redirected,
  and other DNS transports are blocked.
* **Reboot protection is not automatic.** `start` does not install or enable
  `torwell-restore.service`; until that unit (in `crates/torwell-linux/assets/`) is
  installed and enabled, the blocking policy does not survive a reboot.
* Everything above describes intent and tested policy, not a finished product. Real Tor
  bootstrap, DNS leak tests, NetworkManager/firewalld/docker coexistence, SAFECOOKIE and
  Windows runtime are open release gates (see [docs/LINUX.md](docs/LINUX.md) and
  [docs/WINDOWS.md](docs/WINDOWS.md)).

## Documentation

* [docs/FEASIBILITY.md](docs/FEASIBILITY.md) — feasibility decision
* [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md) — scope and invariants
* [docs/CORE.md](docs/CORE.md) — `torwell-core` API
* [docs/LINUX.md](docs/LINUX.md) — nftables policy, state, recovery, MAC, boot restore
* [docs/WINDOWS.md](docs/WINDOWS.md) — WFP/Wintun design and release gates
* [docs/UI.md](docs/UI.md), [docs/PROTOCOL.md](docs/PROTOCOL.md) — UI/engine boundary
* [docs/ENGINE.md](docs/ENGINE.md) — `torwell-engine`: CLI, protocol mode, privilege flow, boot subcommands

## License

TBD. No license has been chosen yet.

## Türkçe özet

Torwell, TorGhost'un yerini almayı hedefleyen, Rust ile yazılmış modern bir Tor trafik
yönlendiricisidir. Amaç tüm sistem TCP ve DNS trafiğini Tor üzerinden geçirmek, geri
kalan her şeyi (IPv6 ve doğrudan çıkış yolları dahil) kapalı tutmak ve yalnızca kendi
nftables tablosuna ve kendi durum dosyalarına dokunarak temiz biçimde geri alınabilmek.

TorGhost'un aksine mevcut iptables kurallarını silmez, durdururken politikaları `ACCEPT`
yapmaz, IPv6'yı dikkate alır ve hata durumunda ağı açmak yerine engellemeyi korur.

Durum: Linux (öncelikle Arch/CachyOS) geliştirme aşamasında; çekirdek güvenlik duvarı
politikası ağ ad alanlarında test edildi ancak gerçek Tor ile uçtan uca denenmedi.
Windows kodu var ama hiç Windows'ta çalıştırılmadı ve **desteklenmiyor**. macOS kapsam
dışı. MAC değişikliği isteğe bağlı ve varsayılan olarak kapalı.

Önemli sınırlar: Torwell tek başına anonimlik sağlamaz, MAC değişikliği IP adresinizi
gizlemez, etkinken yerel ağ (LAN) trafiği engellenir, DNS yalnızca Tor'un DNSPort'u
üzerinden gider ve yeniden başlatmaya karşı koruma için `torwell-restore.service`
biriminin kurulup etkinleştirilmesi gerekir. Lisans: henüz belirlenmedi (TBD).
