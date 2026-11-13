# Threat model: what Torwell does and does not protect

Goal: while Torwell is active, nothing that leaves this computer reveals its real IP
address, and nothing reaches the internet except through Tor. Anything Torwell cannot
guarantee is listed here explicitly.

## Network layer: enforced and tested

All of the following are enforced by one nftables table (`inet torwell`) and tested with
real packets in isolated network namespaces (`crates/torwell-linux/tests/kernel_policy.rs`,
each with a negative control proving the test can see the leak):

| Path | Result |
|---|---|
| IPv4 TCP from any program | redirected to Tor's TransPort |
| DNS (UDP 53) to any server | redirected to Tor's DNSPort |
| Any other UDP (QUIC, WebRTC/STUN, NTP, games, VPN tunnels) | rejected |
| IPv6, all of it | rejected |
| ICMP (ping, traceroute) | rejected |
| Connections opened before Start | rejected (no "established" exception) |
| VMs and containers (libvirt, docker, podman bridges): forwarded traffic | rejected |
| Tor not running, crashed or still bootstrapping | everything stays blocked (fail closed) |
| After a reboot | blocked again before the network starts, only if boot protection is enabled |

Exceptions, all narrow: loopback; the dedicated `torwell-tor` user (Tor itself must reach
its guards); the root-owned DHCPv4 client (UDP 68→67, to keep the LAN address).

## Tor itself

* Client only (`ClientOnly 1`): never a relay or exit; nothing listens outside loopback.
* `IsolateDestAddr` on TransPort and SocksPort: different destinations use different
  circuits, so one exit node cannot link your visits to different sites.
* Guard selection, path selection and circuit rotation are Tor's defaults. Tor Project
  advises against pinning or excluding countries/nodes: it makes you stand out and can
  weaken anonymity. Torwell does not do it.
* Exit nodes see your traffic to the destination. **Use HTTPS**: a malicious exit can read
  and modify plain HTTP.
* Your ISP can see that you use Tor (not what you do). Hiding Tor use needs bridges
  (obfs4/Snowflake) — **not implemented yet**.
* Control access: a Unix socket owned by `torwell-tor` (0700 directory) with cookie
  authentication; Torwell checks owners and modes before use.

## Local network

* Optional MAC randomization (off by default) gives the LAN/router a random MAC for the
  session; the DHCP hostname is withheld during the session. Your public IP is not
  affected by MAC changes.
* While active, all LAN traffic is blocked (printers, NAS, Deskflow, local servers).

## What Torwell cannot protect against

No system-wide Tor router can, Tails and Whonix included; these need care from you:

* **Application-level identity**: logging into accounts, cookies, browser fingerprinting,
  your writing style. Use Tor Browser for browsing; a normal browser routed through Tor is
  much easier to fingerprint.
* **Apps that put identifying data inside their traffic**: e.g. a program that sends your
  hostname, username, local IP, hardware IDs or license keys in its requests. Torwell hides
  where the packet comes from, not what it says.
* **Stop**: after Stop, open programs reconnect directly with your real IP. Close sensitive
  apps before stopping.
* **Root processes**: root can delete the table or send raw packets (`AF_PACKET`) that never
  pass nftables. Do not run untrusted software as root.
* **Timing/correlation by a global observer** watching both ends: a known limit of Tor.
* **Compromised machine**: malware with your privileges can read your data directly.

## Not verified yet

Boot protection across a real reboot; MAC change on real hardware; coexistence with
firewalld, docker's own rules and VPN clients (do not run Mullvad and Torwell at the same
time); a full DNS leak test with a real resolver; SAFECOOKIE instead of COOKIE auth.
