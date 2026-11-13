# torwell: MAC address change feasibility (research note)

Date: 2026-11-13. Scope: Linux (NetworkManager / `ip link`), Windows adapter limits, macOS Intel and Apple Silicon Wi-Fi/Ethernet. Initial agent research used search snippets. The parent subsequently fetched the full official NetworkManager, Apple, Microsoft Set-NetAdapter/NDIS and iproute2 documentation, correcting the claims below. No MAC changes or runtime functionality tests were performed. Read-only version checks found NetworkManager 1.58.1-3 and iproute2 7.3.0 on the CachyOS host.

## Key distinctions

- **OS private Wi-Fi address** (Apple "Private Wi-Fi Address", Windows "Random hardware addresses", NetworkManager `cloned-mac-address` random/stable modes) is a built-in privacy feature. It is a per-network address policy, not arbitrary spoofing.
- **Arbitrary spoofing** (user-chosen MAC) is a separate, driver-dependent operation that the OS may refuse or silently ignore.
- **Temporary vs persistent:** `ip link set ... address` and `ifconfig ... ether` are runtime changes lost on reboot/driver reset. NetworkManager profile settings persist with the connection profile. Windows adapter overrides persist in the registry but are driver-dependent.
- **MAC vs public IP:** a MAC address is link-layer (same LAN segment only). Changing it does not change the public IP. Do not present it as an anonymity or Tor-related IP control; the UI should say so.

## Linux (NetworkManager)

- Current NM D-Bus docs specify `assigned-mac-address` as a string accepting explicit addresses, `preserve`, `permanent`, `random`, or `stable`. The deprecated D-Bus `cloned-mac-address` is a byte array; nmcli/libnm continue using the name `cloned-mac-address`. Default random/stable generation is locally administered and unicast; custom masks can change this. Do not assume a universal default or support unverified spellings such as `random-bia`. Sources fetched in full: https://www.networkmanager.dev/docs/api/latest/settings-802-3-ethernet.html and https://www.networkmanager.dev/docs/api/latest/settings-802-11-wireless.html
- NM 1.4.0 announcement describes stable address generation from a secret key, interface name and stable-id: https://blogs.gnome.org/thaller/?p=25
- Dynamic stable-ids (`${BOOT}`, `${CONNECTION}`, `${RANDOM}`) were added in 1.6 per the same kind of NM docs (from search summary; confirm in `man nm-settings` for the installed version).
- Fedora 40 changed Wi-Fi default to `stable-ssid`: https://fedoramagazine.org/randomize-mac-address-nm/ and https://www.fedoraproject.org/wiki/Changes/WifiMACRandomization (the exact setting name should be verified before use).
- The iproute2 manual confirms that `ip link set ... address LLADDRESS` changes an interface's station address. Link-down requirements and acceptance depend on the driver; this does not persist a NetworkManager profile. Full source: https://man7.org/linux/man-pages/man8/ip-link.8.html
- Limitation: driver support varies; some Wi-Fi drivers (including ones with firmware-managed MAC) ignore or reject changes.

## Windows

- Wi-Fi "Random hardware addresses" is a per-network setting (Settings > Network & internet > Wi-Fi, and per known network). Source: Microsoft support pages are not fully retrievable from search; third-party guides only: https://pureinfotech.com/enable-random-hardware-addresses-windows-11/ (official wording unverified).
- Availability depends on adapter, driver, OS version and management policies; a missing UI toggle alone is not conclusive capability detection.
- Microsoft documents a user-facing command: `Set-NetAdapter -Name <adapter> -MacAddress <address>`. It warns that changes may disrupt networking; this is an implementation candidate, not proof every Wi-Fi/Ethernet driver accepts overrides. Full source: https://learn.microsoft.com/en-us/powershell/module/netadapter/set-netadapter?view=windowsserver2025-ps
- The NDIS API documents how drivers read `NetworkAddress`; the HLK test describes saving/restoring the previous setting and restarting the driver. Prefer supported adapter APIs over inventing registry paths. Full sources: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ndis/nf-ndis-ndisreadnetworkaddress and https://learn.microsoft.com/en-us/windows-hardware/test/hlk/testref/d423a0dd-926e-491c-a437-0d7bc8ead98c
- Community sources report many Wi-Fi adapters ignore `NetworkAddress`, values are 12 hex characters without separators, and a change requires adapter restart/disable. Not authoritative: https://woshub.com/random-hardware-mac-address-windows/
- Admin rights and possible group-policy blocking are expected; not verified.

## macOS (Intel and Apple Silicon)

- Apple documents **Private Wi-Fi Address** (Off / Fixed / Rotating, rotating every two weeks) per network; the setting is in Wi-Fi > Details, and requires macOS Sequoia 15 or later. Default is Fixed on WPA2/WPA3 and Rotating on weak/open networks. Source: https://support.apple.com/en-al/102509 (and the Mac User Guide, https://support.apple.com/guide/mac-help/mchlb1cb3eb4/mac). Apple notes private addresses can break networks relying on device identification; enterprise MDM can disable them.
- Arbitrary Wi-Fi MAC change via `ifconfig en0 ether` is **not documented by Apple**. Developer forum reports (not primary) show it is inconsistent across Sonoma and later, machine- and driver-dependent, and sometimes accepted but a no-op. Sources: https://developer.apple.com/forums/thread/745150 and https://developer.apple.com/forums/thread/735490 (community reports; not verified on hardware here).
- Interface name is usually `en0` on Apple Silicon but not always; `networksetup -listallhardwareports` identifies it. Source: forum snippets only.
- Treat arbitrary MAC changes on macOS as unverified and do not advertise support before OS/adapter-specific tests. Apple documents macOS 15+ private-address settings, but the fetched support page does not explicitly guarantee every Intel/Apple Silicon adapter or provide an automation API. Full sources: https://support.apple.com/en-us/102509 and https://support.apple.com/guide/mac-help/mchlb1cb3eb4/mac

## Standards

- U/L bit (bit 1 of first octet): 1 = locally administered. I/G bit (bit 0): 0 = unicast. Generate locally administered unicast addresses: first octet `(x | 0x02) & 0xFE`. Source: RFC 9542 (IEEE 802 parameters), https://www.rfc-editor.org/rfc/rfc9542 . Note one SANS diary has this bit reversed in a sentence; do not copy it: https://isc.sans.edu/diary/What%27s%20Normal%3A%20MAC%20Addresses/30310

## Recommendation

1. **Capability detection first.** Inventory OS, adapter, driver and documented APIs without modifying networking. Distinguish supported, unsupported and unknown. Only after explicit opt-in attempt a change and verify read-back; an automatic capability probe must never disconnect the user. Persistence support needs separate verification.
2. **Default off.** Private-address features: offer as recommended privacy setting, not as spoofing. Arbitrary MAC: opt-in only.
3. **Explicit opt-in with disconnect acknowledgement.** Explain that changing MAC may interrupt the connection and affects local-network identity, not public IP.
4. **Generation:** locally administered unicast, random per apply, reject multicast and all-zero/all-ff values, avoid vendor OUIs.
5. **Rollback:** record the active MAC plus original profile/override policy, including whether a value was absent. Restore the prior policy, not just a previously randomized address; verify read-back. Account for restart/crash recovery and Tor reconnect ordering. Persist only when explicitly requested.
6. **Rust core:** keep platform backends behind a trait (NM D-Bus or netlink/ip on Linux; documented adapter API/Set-NetAdapter on Windows). No verified macOS automation API has been established here; use manual private-address guidance until validated. Privileged operations belong in a separate minimal helper.
7. **Testing:** only Linux can be exercised on this host, and only in a disposable/network-namespace or with explicit approval; Windows and macOS need real hardware tests before release.

## Limitations

- Windows private-Wi-Fi automation and arbitrary macOS MAC changes remain unverified. Community reports are not an implementation contract.
- No Windows or macOS runtime available; no tests executed.
- NM setting names vary by version; check against the target distro's NM.
