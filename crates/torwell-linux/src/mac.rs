//! Optional MAC change through NetworkManager's `nmcli` (argument arrays only).
//!
//! The change is made on the *active connection profile* (`cloned-mac-address`, in-memory
//! only via `--temporary`), then the connection is re-activated, and both the profile value
//! and the device's effective address are read back. The prior profile policy (including
//! "absent") is recorded before the first modification and restored on failure or stop.
//! Support is limited to NM-managed `ethernet` and `wifi` devices with an active profile;
//! anything else fails during discovery, before any mutation. Real adapters are untested.
//!
//! Limitation: nmcli prints an unset property as an empty string, and an empty string is
//! not a valid value, so empty is recorded as `Absent`.

use std::path::Path;
use std::time::Duration;

use torwell_core::{Capability, MacAddress, MacRestore, ProfileMac, Support};

use crate::env::Env;
use crate::error::Error;
use crate::runner::{Cmd, Runner};
use crate::state::{MacProgress, MacRecord};

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
    fn run(&mut self, what: &str, args: &[&str]) -> Result<String, Error> {
        let cmd = Cmd::new(self.nmcli, args, self.timeout);
        let out = self.runner.run(&cmd).map_err(|e| Error::Command {
            what: what.into(),
            detail: e.to_string(),
        })?;
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

    /// Read-only discovery. Fails for unknown, unmanaged, unsupported or unconnected adapters.
    pub fn discover(&mut self, iface: &str) -> Result<MacTarget, Error> {
        let fail = |d: String| Error::Mac {
            detail: d,
            rolled_back: true,
        };
        check_interface(iface)?;
        let running = self.run("nmcli general", &["-t", "-g", "RUNNING", "general"])?;
        if running.trim() != "running" {
            return Err(fail("NetworkManager is not running".into()));
        }
        let out = self.run(
            "nmcli device show",
            &[
                "-t",
                "-g",
                "GENERAL.TYPE,GENERAL.STATE,GENERAL.CON-UUID",
                "device",
                "show",
                iface,
            ],
        )?;
        let f = parse_fields(&out, 3)?;
        let setting = setting_for(&f[0]).ok_or_else(|| {
            fail(format!(
                "device type {:?} is unsupported (ethernet and wifi only)",
                f[0]
            ))
        })?;
        if !f[1].starts_with("100") {
            return Err(fail(format!("device state {:?} is not connected", f[1])));
        }
        if !check_uuid(&f[2]) {
            return Err(fail(
                "device has no active NetworkManager connection profile".into(),
            ));
        }
        let prior = self.read_profile(setting, &f[2])?;
        let effective = self.read_effective(iface)?;
        Ok(MacTarget {
            interface: iface.to_string(),
            setting,
            uuid: f[2].clone(),
            prior,
            effective,
        })
    }

    fn set_and_reactivate(&mut self, t: &MacRecord, iface: &str, value: &str) -> Result<(), Error> {
        let prop = format!("{}.cloned-mac-address", t.setting);
        self.run(
            "nmcli connection modify",
            &[
                "connection",
                "modify",
                "--temporary",
                "uuid",
                &t.connection_uuid,
                &prop,
                value,
            ],
        )?;
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

    /// Restores the recorded prior policy and verifies the profile reads back as recorded.
    /// When the prior policy yields a predictable address, the effective address is checked too.
    pub fn restore(&mut self, rec: &MacRecord) -> Result<(), Error> {
        let iface = rec.restore.interface().to_string();
        let prior = rec.restore.restore_profile().clone();
        if self.read_profile(&rec.setting, &rec.connection_uuid)? != prior {
            self.set_and_reactivate(rec, &iface, &profile_value(&prior))?;
        }
        let now = self.read_profile(&rec.setting, &rec.connection_uuid)?;
        if now != prior {
            return Err(Error::Mac {
                detail: format!("profile reads {now:?} after restore, expected {prior:?}"),
                rolled_back: false,
            });
        }
        let predictable = matches!(
            prior,
            ProfileMac::Preserve | ProfileMac::Permanent | ProfileMac::Explicit(_)
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
        };
        persist(&rec)?;
        let attempt = (|| -> Result<(), Error> {
            self.set_and_reactivate(&rec, &t.interface, &candidate.to_string())?;
            let profile = self.read_profile(t.setting, &t.uuid)?;
            if profile != ProfileMac::Explicit(candidate) {
                return Err(Error::Mac {
                    detail: format!("profile reads {profile:?}, expected the candidate"),
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

/// Non-mutating capability report for `interface`.
pub fn capability(nm: &mut Nm, interface: &str) -> Capability {
    let (support, detail) = match nm.discover(interface) {
        Ok(t) => (
            Support::Unknown,
            format!(
                "{} on {} is eligible; real adapter behaviour is untested",
                t.setting, t.interface
            ),
        ),
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
}
