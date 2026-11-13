//! Optional MAC change through NetworkManager's `nmcli` (argument arrays only).
//!
//! The change is made on the *active connection profile* (`cloned-mac-address`, in-memory
//! only via `--temporary`), then the connection is re-activated, and both the profile value
//! and the device's effective address are read back. The prior profile policy (including
//! "absent") is recorded before the first modification and restored on failure or stop.
//! Support is limited to NM-managed `ethernet` and `wifi` devices (not "connected
//! externally", not virtual) with an active profile; anything else fails during discovery,
//! before any mutation. Discovery is read-only and is what `capability` reports as
//! `Supported`; the real proof is the read-back after the change, followed by a rollback
//! when it does not match.
//!
//! While the change is active the DHCP client must not send the real hostname either, so
//! `ipv4/ipv6.dhcp-send-hostname` are set to `no` in the same in-memory modification (only
//! when the property exists) and restored to exactly what they were.
//!
//! `connection modify --temporary` changes the profile in NetworkManager's memory only: the
//! file on disk is not rewritten, and an NM restart or `nmcli connection reload` drops the
//! change (the device then returns to its prior policy on its next activation). Restoring
//! also uses `--temporary`, so nothing of ours is ever written to disk.
//!
//! Limitation: nmcli prints an unset property as an empty string, and an empty string is
//! not a valid value, so empty is recorded as `Absent`.

use std::path::Path;
use std::time::Duration;

use torwell_core::{Capability, MacAddress, MacRestore, ProfileMac, Support};

use crate::env::Env;
use crate::error::Error;
use crate::runner::{Cmd, Runner};
use crate::state::{HostnamePrior, MacProgress, MacRecord};

pub struct Nm<'a> {
    pub runner: &'a mut dyn Runner,
    pub env: &'a mut dyn Env,
    pub nmcli: &'a Path,
    pub timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacTarget {
    pub interface: String,
    pub setting: &'static str,
    pub uuid: String,
    pub prior: ProfileMac,
    pub effective: Option<MacAddress>,
    /// DHCP send-hostname properties that exist on the profile, with their current values.
    /// Only filled by the full (start-time) discovery.
    pub hostname: Vec<HostnamePrior>,
}

/// DHCP "send hostname" properties. On NetworkManager 1.52+ they are ternary
/// (`default`/`no`/`yes`, read as `-1`/`0`/`1`), before that boolean.
const HOSTNAME_PROPS: [&str; 2] = ["ipv4.dhcp-send-hostname", "ipv6.dhcp-send-hostname"];

/// Device names that are never a physical LAN adapter. The NM device type is checked too;
/// this gives a clear reason first and protects against odd NM type reporting.
const VIRTUAL_PREFIXES: [&str; 17] = [
    "virbr",
    "docker",
    "veth",
    "br-",
    "tun",
    "tap",
    "wg",
    "vnet",
    "vboxnet",
    "vmnet",
    "lxc",
    "podman",
    "cni",
    "flannel",
    "tailscale",
    "zt",
    "dummy",
];

/// Why `name` is skipped as a virtual device, if it is one.
pub fn virtual_reason(name: &str) -> Option<String> {
    if name == "lo" {
        return Some("loopback device".into());
    }
    VIRTUAL_PREFIXES
        .iter()
        .find(|p| name.starts_with(**p))
        .map(|p| format!("{name} looks like a virtual device ({p}*); only physical ethernet and wifi adapters are supported"))
}

/// Canonical meaning of a send-hostname value across NM versions.
fn hostname_flag(v: &str) -> &'static str {
    match v.trim().to_ascii_lowercase().as_str() {
        "yes" | "true" | "on" | "1" => "yes",
        "no" | "false" | "off" | "0" => "no",
        _ => "default",
    }
}

/// The value that puts `prior` back. The default (`-1`) is restored by resetting the
/// property with an empty value, which is documented to mean "default".
fn hostname_restore_value(prior: &str) -> &'static str {
    match hostname_flag(prior) {
        "yes" => "yes",
        "no" => "no",
        _ => "",
    }
}

pub fn check_interface(name: &str) -> Result<(), Error> {
    let ok = !name.is_empty()
        && name.len() <= 15
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b':'));
    if ok {
        Ok(())
    } else {
        Err(Error::Config(format!("invalid interface name {name:?}")))
    }
}

pub fn check_uuid(u: &str) -> bool {
    u.len() == 36
        && u.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}

/// Splits terse (`-t -g`) output into exactly `n` fields, unescaping `\:` and `\\`.
pub fn parse_fields(out: &str, n: usize) -> Result<Vec<String>, Error> {
    let body = out.strip_suffix('\n').unwrap_or(out);
    let lines: Vec<&str> = body.split('\n').collect();
    if lines.len() != n {
        return Err(Error::Mac {
            detail: format!("expected {n} nmcli fields, got {}", lines.len()),
            rolled_back: true,
        });
    }
    Ok(lines
        .iter()
        .map(|l| l.replace("\\:", ":").replace("\\\\", "\\"))
        .collect())
}

pub fn parse_profile_mac(v: &str) -> Result<ProfileMac, Error> {
    Ok(match v.trim() {
        "" | "--" => ProfileMac::Absent,
        "preserve" => ProfileMac::Preserve,
        "permanent" => ProfileMac::Permanent,
        "random" => ProfileMac::Random,
        "stable" => ProfileMac::Stable,
        other => ProfileMac::Explicit(MacAddress::parse(other).map_err(|_| Error::Mac {
            detail: format!("unsupported cloned-mac-address policy {other:?}"),
            rolled_back: true,
        })?),
    })
}

pub fn profile_value(p: &ProfileMac) -> String {
    match p {
        ProfileMac::Absent => String::new(),
        ProfileMac::Preserve => "preserve".into(),
        ProfileMac::Permanent => "permanent".into(),
        ProfileMac::Random => "random".into(),
        ProfileMac::Stable => "stable".into(),
        ProfileMac::Explicit(m) => m.to_string(),
    }
}

fn setting_for(kind: &str) -> Option<&'static str> {
    match kind {
        "ethernet" => Some("802-3-ethernet"),
        "wifi" => Some("802-11-wireless"),
        _ => None,
    }
}

impl<'a> Nm<'a> {
    fn run_raw(&mut self, what: &str, args: &[&str]) -> Result<crate::runner::Output, Error> {
        let cmd = Cmd::new(self.nmcli, args, self.timeout);
        self.runner.run(&cmd).map_err(|e| Error::Command {
            what: what.into(),
            detail: e.to_string(),
        })
    }

    fn run(&mut self, what: &str, args: &[&str]) -> Result<String, Error> {
        let out = self.run_raw(what, args)?;
        if !out.ok() {
            return Err(Error::Command {
                what: what.into(),
                detail: format!("exit {:?}: {}", out.code, out.stderr.trim()),
            });
        }
        Ok(out.stdout)
    }

    fn read_profile(&mut self, setting: &str, uuid: &str) -> Result<ProfileMac, Error> {
        let field = format!("{setting}.cloned-mac-address");
        let out = self.run(
            "nmcli connection show",
            &["-t", "-g", &field, "connection", "show", "uuid", uuid],
        )?;
        parse_profile_mac(parse_fields(&out, 1)?[0].as_str())
    }

    fn read_effective(&mut self, iface: &str) -> Result<Option<MacAddress>, Error> {
        let out = self.run(
            "nmcli device show",
            &["-t", "-g", "GENERAL.HWADDR", "device", "show", iface],
        )?;
        let f = parse_fields(&out, 1)?;
        Ok(MacAddress::parse(&f[0]).ok())
    }

    /// `None` when the profile has no such property (an nmcli exit status, e.g. an old
    /// NetworkManager); a runner failure such as a timeout is an error, never "absent".
    fn read_hostname_prop(&mut self, prop: &str, uuid: &str) -> Result<Option<String>, Error> {
        let out = self.run_raw(
            "nmcli connection show",
            &["-t", "-g", prop, "connection", "show", "uuid", uuid],
        )?;
        if !out.ok() {
            return Ok(None);
        }
        Ok(Some(parse_fields(&out.stdout, 1)?.remove(0)))
    }

    /// Read-only discovery for starting: everything needed to apply and to restore.
    /// Fails for unknown, unmanaged, unsupported or unconnected adapters.
    pub fn discover(&mut self, iface: &str) -> Result<MacTarget, Error> {
        self.probe(iface, true)
    }

    /// Cheap read-only discovery (three nmcli calls) for `capability`.
    fn probe(&mut self, iface: &str, full: bool) -> Result<MacTarget, Error> {
        let fail = |d: String| Error::Mac {
            detail: d,
            rolled_back: true,
        };
        check_interface(iface)?;
        if let Some(why) = virtual_reason(iface) {
            return Err(fail(why));
        }
        let running = self.run("nmcli general", &["-t", "-g", "RUNNING", "general"])?;
        if running.trim() != "running" {
            return Err(fail("NetworkManager is not running".into()));
        }
        let out = self.run(
            "nmcli device show",
            &[
                "-t",
                "-g",
                "GENERAL.TYPE,GENERAL.STATE,GENERAL.CON-UUID,GENERAL.NM-MANAGED,GENERAL.HWADDR",
                "device",
                "show",
                iface,
            ],
        )?;
        let f = parse_fields(&out, 5)?;
        let setting = setting_for(&f[0]).ok_or_else(|| {
            fail(format!(
                "device type {:?} is unsupported (physical ethernet and wifi only)",
                f[0]
            ))
        })?;
        if f[3] != "yes" {
            return Err(fail(
                "device is not managed by NetworkManager (unmanaged)".into(),
            ));
        }
        if f[1].contains("externally") {
            return Err(fail(
                "device is only 'connected (externally)': no NetworkManager profile owns it".into(),
            ));
        }
        if !f[1].starts_with("100") {
            return Err(fail(format!(
                "device state {:?} is not connected: activate its profile first",
                f[1]
            )));
        }
        if !check_uuid(&f[2]) {
            return Err(fail(
                "device has no active NetworkManager connection profile".into(),
            ));
        }
        let prior = self.read_profile(setting, &f[2])?;
        let effective = MacAddress::parse(&f[4]).ok();
        let mut hostname = Vec::new();
        if full {
            for prop in HOSTNAME_PROPS {
                if let Some(v) = self.read_hostname_prop(prop, &f[2])? {
                    hostname.push(HostnamePrior {
                        property: prop.to_string(),
                        prior: v,
                    });
                }
            }
        }
        Ok(MacTarget {
            interface: iface.to_string(),
            setting,
            uuid: f[2].clone(),
            prior,
            effective,
            hostname,
        })
    }

    /// One in-memory modification (MAC policy and, when `suppress_hostname`, hostname
    /// sending off; otherwise the recorded prior hostname values), then re-activation.
    fn set_and_reactivate(
        &mut self,
        t: &MacRecord,
        iface: &str,
        value: &str,
        suppress_hostname: bool,
    ) -> Result<(), Error> {
        let prop = format!("{}.cloned-mac-address", t.setting);
        let mut args: Vec<&str> = vec![
            "connection",
            "modify",
            "--temporary",
            "uuid",
            &t.connection_uuid,
            &prop,
            value,
        ];
        for h in &t.hostname {
            args.push(&h.property);
            args.push(if suppress_hostname {
                "no"
            } else {
                hostname_restore_value(&h.prior)
            });
        }
        self.run("nmcli connection modify", &args)?;
        self.run(
            "nmcli connection up",
            &[
                "connection",
                "up",
                "uuid",
                &t.connection_uuid,
                "ifname",
                iface,
            ],
        )?;
        Ok(())
    }

    /// Properties whose current value differs from what `want` says (`None` = prior value).
    fn hostname_mismatch(
        &mut self,
        rec: &MacRecord,
        suppressed: bool,
    ) -> Result<Option<String>, Error> {
        for h in &rec.hostname {
            let now = self
                .read_hostname_prop(&h.property, &rec.connection_uuid)?
                .ok_or_else(|| Error::Mac {
                    detail: format!("{} cannot be read back", h.property),
                    rolled_back: false,
                })?;
            let want = if suppressed {
                "no"
            } else {
                hostname_flag(&h.prior)
            };
            if hostname_flag(&now) != want {
                return Ok(Some(format!("{} reads {now:?}", h.property)));
            }
        }
        Ok(None)
    }

    /// Restores the recorded prior policy (MAC and hostname sending) and verifies it reads
    /// back as recorded. When the prior policy yields a predictable address, the effective
    /// address is checked too.
    pub fn restore(&mut self, rec: &MacRecord) -> Result<(), Error> {
        let iface = rec.restore.interface().to_string();
        let prior = rec.restore.restore_profile().clone();
        let profile_differs = self.read_profile(&rec.setting, &rec.connection_uuid)? != prior;
        if profile_differs || self.hostname_mismatch(rec, false)?.is_some() {
            self.set_and_reactivate(rec, &iface, &profile_value(&prior), false)?;
        }
        let now = self.read_profile(&rec.setting, &rec.connection_uuid)?;
        if now != prior {
            return Err(Error::Mac {
                detail: format!("profile reads {now:?} after restore, expected {prior:?}"),
                rolled_back: false,
            });
        }
        if let Some(bad) = self.hostname_mismatch(rec, false)? {
            return Err(Error::Mac {
                detail: format!("{bad} after restore"),
                rolled_back: false,
            });
        }
        let predictable = matches!(
            prior,
            ProfileMac::Preserve
                | ProfileMac::Permanent
                | ProfileMac::Stable
                | ProfileMac::Explicit(_)
        );
        if let (true, Some(expect)) = (predictable, rec.restore.prior_effective()) {
            if self.read_effective(&iface)? != Some(expect) {
                return Err(Error::Mac {
                    detail: "effective address differs from the pre-change address after restore"
                        .into(),
                    rolled_back: false,
                });
            }
        }
        Ok(())
    }

    /// Applies `candidate`. `persist` is called with `Pending` BEFORE the first modification
    /// and `Applied` after verified read-back. On any failure the prior policy is restored; a
    /// failed restore is reported with `rolled_back: false`.
    pub fn apply(
        &mut self,
        t: &MacTarget,
        candidate: MacAddress,
        persist: &mut dyn FnMut(&MacRecord) -> Result<(), Error>,
    ) -> Result<MacRecord, Error> {
        let restore = MacRestore::new(&t.interface, t.prior.clone(), t.effective)
            .map_err(|_| Error::Config("bad interface name".into()))?;
        let mut rec = MacRecord {
            connection_uuid: t.uuid.clone(),
            setting: t.setting.to_string(),
            restore,
            candidate,
            progress: MacProgress::Pending,
            hostname: t.hostname.clone(),
        };
        persist(&rec)?;
        let attempt = (|| -> Result<(), Error> {
            self.set_and_reactivate(&rec, &t.interface, &candidate.to_string(), true)?;
            let profile = self.read_profile(t.setting, &t.uuid)?;
            if profile != ProfileMac::Explicit(candidate) {
                return Err(Error::Mac {
                    detail: format!("profile reads {profile:?}, expected the candidate"),
                    rolled_back: false,
                });
            }
            if let Some(bad) = self.hostname_mismatch(&rec, true)? {
                return Err(Error::Mac {
                    detail: format!("DHCP hostname sending is still on: {bad}"),
                    rolled_back: false,
                });
            }
            let mut got = None;
            for _ in 0..5 {
                got = self.read_effective(&t.interface)?;
                if got == Some(candidate) {
                    return Ok(());
                }
                self.env.sleep(Duration::from_secs(1));
            }
            Err(Error::Mac {
                detail: format!("device address reads {got:?}, expected {candidate}"),
                rolled_back: false,
            })
        })();
        match attempt {
            Ok(()) => {
                rec.progress = MacProgress::Applied;
                persist(&rec)?;
                Ok(rec)
            }
            Err(e) => match self.restore(&rec) {
                Ok(()) => Err(Error::Mac {
                    detail: e.to_string(),
                    rolled_back: true,
                }),
                Err(r) => Err(Error::Mac {
                    detail: format!("{e}; rollback failed: {r}"),
                    rolled_back: false,
                }),
            },
        }
    }
}

/// Non-mutating capability report for `interface`. `Supported` means: NM runs, the device is
/// NM-managed physical ethernet or wifi with an active profile. The post-apply read-back
/// plus rollback remain the actual proof.
pub fn capability(nm: &mut Nm, interface: &str) -> Capability {
    let (support, detail) = match nm.probe(interface, false) {
        Ok(t) => (
            Support::Supported,
            format!(
                "{} on {}: NetworkManager profile active; change is verified by read-back and rolled back on mismatch",
                t.setting, t.interface
            ),
        ),
        Err(Error::Mac { detail, .. }) => (Support::Unsupported, detail),
        Err(e) => (Support::Unsupported, e.to_string()),
    };
    Capability {
        name: "linux_mac_networkmanager".into(),
        support,
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_policy_round_trips_including_absent() {
        for v in [
            "",
            "preserve",
            "permanent",
            "random",
            "stable",
            "02:11:22:33:44:55",
        ] {
            assert_eq!(profile_value(&parse_profile_mac(v).unwrap()), v);
        }
        assert_eq!(parse_profile_mac("--").unwrap(), ProfileMac::Absent);
        assert!(parse_profile_mac("random-bia").is_err());
        assert!(parse_profile_mac("garbage").is_err());
    }

    #[test]
    fn terse_fields_unescape_and_count_strictly() {
        assert_eq!(
            parse_fields("00\\:11\\:22\\:33\\:44\\:55\n", 1).unwrap(),
            vec!["00:11:22:33:44:55"]
        );
        assert_eq!(parse_fields("a\n\nc\n", 3).unwrap(), vec!["a", "", "c"]);
        assert!(parse_fields("a\nb\n", 3).is_err());
    }

    #[test]
    fn interface_and_uuid_validation_blocks_option_injection() {
        assert!(check_interface("wlan0").is_ok());
        for bad in ["", "-x", "a b", "a;b", "abcdefghijklmnopq", "a\nb"] {
            assert!(check_interface(bad).is_err(), "{bad:?}");
        }
        assert!(check_uuid("11111111-2222-3333-4444-555555555555"));
        assert!(!check_uuid("--") && !check_uuid("11111111-2222-3333-4444-55555555555g"));
    }

    #[test]
    fn hostname_values_normalise_across_nm_versions_and_restore_the_default_by_reset() {
        for (v, flag, restore) in [
            ("-1", "default", ""),
            ("default", "default", ""),
            ("", "default", ""),
            ("0", "no", "no"),
            ("no", "no", "no"),
            ("1", "yes", "yes"),
            ("yes", "yes", "yes"),
        ] {
            assert_eq!(hostname_flag(v), flag, "{v:?}");
            assert_eq!(hostname_restore_value(v), restore, "{v:?}");
        }
    }

    #[test]
    fn virtual_names_are_refused_with_a_reason_and_physical_names_are_not() {
        for n in [
            "lo", "virbr0", "docker0", "veth12ab", "br-0a1b", "tun0", "wg0",
        ] {
            assert!(virtual_reason(n).is_some(), "{n}");
        }
        for n in ["enp37s0", "eth0", "wlan0", "wlp3s0", "eno1"] {
            assert!(virtual_reason(n).is_none(), "{n}");
        }
    }

    #[test]
    fn terse_fields_keep_utf8_and_spaces() {
        assert_eq!(
            parse_fields("Kablolu bağlantı 1\\:x\n", 1).unwrap(),
            vec!["Kablolu bağlantı 1:x"]
        );
    }
}
