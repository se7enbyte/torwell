# Torwell platform feasibility — reviewed

Date: 2026-11-13. This replaces the initial agent draft, which mixed search snippets and unverified recollection. This is a design assessment based on official documentation, not a working implementation or a platform test result.

## Decision

A shared Rust application with separate operating-system backends is plausible. Equivalent protection on all systems has not been demonstrated. Start with an Arch/CachyOS prototype in an isolated VM, keeping Windows and macOS backends in the architecture from the start. A system proxy setting alone is insufficient to enforce routing for applications that ignore it.

## Traffic contract

Tor transports TCP streams. Its DNSPort listens for UDP DNS and supports A, AAAA and PTR queries; it is not a general UDP tunnel. TCP DNS must follow a separately designed TCP/forwarder path, not be redirected to a UDP-only listener. General UDP/QUIC and ICMP should be blocked in the initial policy, with narrow documented local networking exceptions.

Correction: Tor DOES support IPv6 in supported configurations, including SOCKS5 IPv6 destinations. Blocking IPv6 in the first implementation is a proposed scope/safety choice, not a Tor limitation. Full IPv6 routing requires its own leak tests. Existing direct connections must not be grandfathered by a blanket established-connection allow rule.

Source: https://man.archlinux.org/man/tor.1.en (Tor's manual distributed by Arch; DNSPort, SocksPort/IPv6Traffic, TransPort).

## Linux

Candidate: Torwell-owned nftables tables/chains, TCP redirection to Tor TransPort, UDP DNS interception, dedicated Tor process identity exclusion, and an explicit reject policy for other traffic. nftables supports redirect in output/prerouting NAT hooks. NAT bindings are established on the first packet, making existing connections a distinct enforcement problem. Do not flush unrelated firewall rules. Coexistence and hook priority must be tested with NetworkManager, firewalld and container rules.

Source: https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_(NAT)

## Windows

Candidate: the official signed Wintun driver, a userspace TCP-to-Tor-SOCKS bridge, and WFP filtering for traffic that must not bypass the tunnel. Wintun only provides a layer-3 interface; it does not itself implement Tor, DNS handling or a kill switch. Tor's own connections must use the real uplink without granting other processes a bypass.

Correction: WFP supports connection redirection via ALE callout drivers; saying it only permits/blocks was false. Writing a custom callout driver adds a separate development/distribution burden, so it is not the proposed initial path.

WFP objects created in a dynamic session are removed when the session ends. A crash-resistant blocking policy cannot rely solely on those objects. Persistent rules and startup/recovery behavior must be designed and tested separately. Wintun's official signed binaries have distribution terms distinct from its GPL source; retain their actual shipped licence and notices.

Sources: https://www.wintun.net/ ; https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection ; https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_session0

## macOS

Candidate for a distributable app: Network Extension transparent proxy, with separately validated DNS handling and failure containment. Apple's TN3134 permits transparent-proxy system extensions and direct Developer ID distribution. App-extension distribution has different restrictions. The extension must be packaged, provisioned and signed appropriately; a Rust executable alone does not supply this integration. A thin platform framework adapter may be required.

PF remains an experimental possibility, not a verified backend. No PF routing or recovery behavior was tested here. Do not promise that all traffic is captured or that extension termination cannot leak before device tests. The initial draft's blanket statement that every Network Extension requires individually approved entitlements was not established; requirements depend on the selected provider and distribution route.

Source: https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment.md

## Common architecture and acceptance tests

Rust OpenTUI frontend (unprivileged) → authenticated, narrowly typed local IPC → privileged Rust helper → OS backend and Tor supervisor. Separate MAC policy from traffic routing. Keep recoverable state with ownership checks and only remove Torwell-owned changes.

Required tests before support claims: native UI build/run; TCP and DNS observed at the physical uplink; UDP and IPv6 bypass attempts; pre-existing connections; Tor/helper/UI termination; reboot, sleep/resume and uplink changes; firewall/VPN coexistence; failed setup and rollback; MAC policy restoration on supported physical adapters. Blocking must survive failures according to a clearly defined policy, while explicit stop/recover must remain usable. Test inside disposable OS VMs first; MAC behavior needs actual adapters.

No routing, crash-recovery or leak tests ran in this research phase. See opentui-smoke.md for the separate native-artifact blocker. The OpenTUI frontend can use upstream Rust bindings; the initial draft's mandatory TypeScript frontend recommendation was outdated.
