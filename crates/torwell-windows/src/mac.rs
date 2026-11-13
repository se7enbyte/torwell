//! Optional MAC change with supported-driver detection, CSPRNG candidates, previous-policy
//! restoration and read-back. Never mutates during discovery: [`prepare`] only reads.

use std::time::Duration;

use torwell_core::mac::{MacAddress, MacRestore, ProfileMac};

use crate::adapter::AdapterApi;
use crate::clock::Clock;
use crate::error::{Error, Result};
use crate::state::MacRecord;

pub trait Csprng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()>;
}

/// OS CSPRNG. On Windows this is `BCryptGenRandom`; elsewhere `/dev/urandom` (tests, tooling).
pub struct OsRng;

impl Csprng for OsRng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
        #[cfg(windows)]
        {
            crate::win::random::fill(buf)
        }
        #[cfg(not(windows))]
        {
            use std::io::Read;
            std::fs::File::open("/dev/urandom")
                .and_then(|mut f| f.read_exact(buf))
                .map_err(|e| Error::Mac(format!("OS random source unavailable: {e}")))
        }
    }
}

const READBACK_TIMEOUT: Duration = Duration::from_secs(45);
const POLL: Duration = Duration::from_secs(1);

/// Read-only: capture prior policy, check the driver, build a candidate. Explicitly refuses
/// drivers that do not expose `NetworkAddress` rather than guessing.
pub fn prepare(api: &dyn AdapterApi, rng: &mut dyn Csprng, adapter: &str) -> Result<MacRecord> {
    let st = api.read_mac(adapter)?;
    if !st.keyword_present {
        return Err(Error::Mac(format!(
            "adapter {adapter:?}: driver does not expose the NetworkAddress property; MAC change unsupported"
        )));
    }
    let prior = match st.override_value {
        Some(m) => ProfileMac::Explicit(m),
        None => ProfileMac::Absent,
    };
    let restore = MacRestore::new(adapter, prior, Some(st.effective))
        .map_err(|e| Error::Mac(e.to_string()))?;
    for _ in 0..16 {
        let mut b = [0u8; 6];
        rng.fill(&mut b)?;
        let cand = MacAddress::from_candidate_bytes(b);
        if cand != st.effective && Some(cand) != st.override_value {
            return Ok(MacRecord {
                restore,
                candidate: cand,
                change_attempted: false,
            });
        }
    }
    Err(Error::Mac("could not draw a distinct candidate".into()))
}

fn poll_until(
    api: &dyn AdapterApi,
    clock: &dyn Clock,
    adapter: &str,
    ok: impl Fn(&crate::adapter::MacState) -> bool,
) -> bool {
    let start = clock.now();
    loop {
        if let Ok(s) = api.read_mac(adapter) {
            if ok(&s) {
                return true;
            }
        }
        if clock.now().saturating_sub(start) >= READBACK_TIMEOUT {
            return false;
        }
        clock.sleep(POLL);
    }
}

/// Applies the candidate (adapter restarts: brief disconnect) and verifies read-back.
/// The caller must have persisted `change_attempted = true` first.
pub fn apply(api: &dyn AdapterApi, clock: &dyn Clock, rec: &MacRecord) -> Result<()> {
    let name = rec.restore.interface();
    api.set_mac_override(name, &rec.candidate)?;
    let want = rec.candidate;
    if poll_until(api, clock, name, |s| {
        s.effective == want && s.override_value == Some(want)
    }) {
        Ok(())
    } else {
        Err(Error::Mac(format!(
            "read-back did not show {want} on {name:?}; driver may ignore the override"
        )))
    }
}

/// Restores the *prior override policy* (not the effective address) and verifies read-back.
pub fn restore(api: &dyn AdapterApi, clock: &dyn Clock, rec: &MacRecord) -> Result<()> {
    if !rec.change_attempted {
        return Ok(());
    }
    let name = rec.restore.interface();
    let prior_effective = rec.restore.prior_effective();
    let expect_override = match rec.restore.restore_profile() {
        ProfileMac::Absent => {
            api.reset_mac_override(name)?;
            None
        }
        ProfileMac::Explicit(m) => {
            api.set_mac_override(name, m)?;
            Some(*m)
        }
        other => {
            return Err(Error::Mac(format!(
                "cannot restore unsupported prior policy {other:?}"
            )))
        }
    };
    let ok = poll_until(api, clock, name, |s| {
        s.override_value == expect_override && prior_effective.is_none_or(|p| s.effective == p)
    });
    if ok {
        Ok(())
    } else {
        Err(Error::Mac(format!(
            "restore read-back on {name:?} did not match the prior policy"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::MacState;
    use crate::testutil::{FakeAdapter, FakeClock, FixedRng};

    fn mac(s: &str) -> MacAddress {
        MacAddress::parse(s).unwrap()
    }

    #[test]
    fn unsupported_driver_is_explicit_and_unmodified() {
        let a = FakeAdapter::new(MacState {
            effective: mac("00:11:22:33:44:55"),
            keyword_present: false,
            override_value: None,
        });
        let e = prepare(&a, &mut FixedRng(vec![[1; 6]]), "Ethernet").unwrap_err();
        assert!(e.to_string().contains("unsupported"));
        assert!(a.calls.borrow().iter().all(|c| c.starts_with("read")));
    }

    #[test]
    fn prepare_records_prior_policy_and_candidate_differs() {
        let a = FakeAdapter::new(MacState {
            effective: mac("02:00:00:00:00:00"),
            keyword_present: true,
            override_value: Some(mac("02:00:00:00:00:00")),
        });
        // First draw collides with the current address (after U/L normalisation), second is fresh.
        let rec = prepare(
            &a,
            &mut FixedRng(vec![[0; 6], [9, 8, 7, 6, 5, 4]]),
            "Ethernet",
        )
        .unwrap();
        assert_eq!(
            rec.restore.restore_profile(),
            &ProfileMac::Explicit(mac("02:00:00:00:00:00"))
        );
        assert_ne!(rec.candidate, mac("02:00:00:00:00:00"));
        assert!(rec.candidate.is_locally_administered());
        assert!(!rec.change_attempted);
    }

    #[test]
    fn apply_verifies_readback_and_restore_returns_prior_policy() {
        let a = FakeAdapter::new(MacState {
            effective: mac("00:11:22:33:44:55"),
            keyword_present: true,
            override_value: None,
        });
        let mut rec = prepare(&a, &mut FixedRng(vec![[0x10; 6]]), "Ethernet").unwrap();
        rec.change_attempted = true;
        let clock = FakeClock::default();
        apply(&a, &clock, &rec).unwrap();
        assert_eq!(a.state.borrow().effective, rec.candidate);
        restore(&a, &clock, &rec).unwrap();
        let s = a.state.borrow();
        assert_eq!(
            s.override_value, None,
            "an absent prior override must be reset, not pinned to the old address"
        );
        assert_eq!(s.effective, mac("00:11:22:33:44:55"));
        assert!(a.calls.borrow().iter().any(|c| c == "reset"));
    }

    #[test]
    fn explicit_prior_override_is_reinstated() {
        let a = FakeAdapter::new(MacState {
            effective: mac("02:aa:aa:aa:aa:aa"),
            keyword_present: true,
            override_value: Some(mac("02:aa:aa:aa:aa:aa")),
        });
        let mut rec = prepare(&a, &mut FixedRng(vec![[0x20; 6]]), "Ethernet").unwrap();
        rec.change_attempted = true;
        let clock = FakeClock::default();
        apply(&a, &clock, &rec).unwrap();
        restore(&a, &clock, &rec).unwrap();
        assert_eq!(
            a.state.borrow().override_value,
            Some(mac("02:aa:aa:aa:aa:aa"))
        );
    }

    #[test]
    fn driver_that_ignores_override_fails_readback_by_timeout() {
        let a = FakeAdapter::new(MacState {
            effective: mac("00:11:22:33:44:55"),
            keyword_present: true,
            override_value: None,
        });
        a.ignore_set.set(true);
        let mut rec = prepare(&a, &mut FixedRng(vec![[0x10; 6]]), "Ethernet").unwrap();
        rec.change_attempted = true;
        let clock = FakeClock::default();
        assert!(apply(&a, &clock, &rec).is_err());
        assert!(clock.now() >= READBACK_TIMEOUT);
    }

    #[test]
    fn restore_is_noop_if_change_never_attempted() {
        let a = FakeAdapter::new(MacState {
            effective: mac("00:11:22:33:44:55"),
            keyword_present: true,
            override_value: None,
        });
        let rec = prepare(&a, &mut FixedRng(vec![[0x10; 6]]), "Ethernet").unwrap();
        restore(&a, &FakeClock::default(), &rec).unwrap();
        assert!(a.calls.borrow().iter().all(|c| c.starts_with("read")));
    }
}
