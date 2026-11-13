//! WFP object management over an injectable [`WfpApi`]. Objects are persistent (survive helper
//! exit and BFE restart), created inside a transaction (all or nothing), verified by read-back,
//! and removed only by Torwell's own keys. A dynamic session is never used: it would drop the
//! kill switch when the helper exits.

use std::collections::BTreeSet;

use crate::error::{Error, Result};
use crate::ids::{FilterId, Guid, PROVIDER_KEY, SUBLAYER_KEY, SUBLAYER_WEIGHT};
use crate::policy::{self, Action, FilterSpec, Layer};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterReadback {
    pub layer: Layer,
    pub action: Action,
    pub weight: u8,
    pub persistent: bool,
    pub provider: Option<Guid>,
    pub sublayer: Guid,
    pub condition_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SublayerReadback {
    pub persistent: bool,
    pub provider: Option<Guid>,
    pub weight: u16,
}

/// Narrow typed WFP surface. Implemented on Windows by `win::wfp::SystemWfp`.
pub trait WfpApi {
    fn begin(&mut self) -> Result<()>;
    fn commit(&mut self) -> Result<()>;
    fn abort(&mut self);
    /// `Some(persistent)` if the provider exists.
    fn get_provider(&mut self, key: &Guid) -> Result<Option<bool>>;
    fn add_provider(&mut self, key: &Guid, name: &str) -> Result<()>;
    fn get_sublayer(&mut self, key: &Guid) -> Result<Option<SublayerReadback>>;
    fn add_sublayer(&mut self, key: &Guid, name: &str, provider: &Guid, weight: u16) -> Result<()>;
    fn add_filter(&mut self, spec: &FilterSpec, provider: &Guid, sublayer: &Guid) -> Result<()>;
    fn get_filter(&mut self, key: &Guid) -> Result<Option<FilterReadback>>;
    /// Keys of every filter (any owner) in the given sublayer.
    fn filters_in_sublayer(&mut self, sublayer: &Guid) -> Result<Vec<Guid>>;
    /// `Ok(false)` if the filter did not exist.
    fn delete_filter(&mut self, key: &Guid) -> Result<bool>;
    fn delete_sublayer(&mut self, key: &Guid) -> Result<bool>;
    fn delete_provider(&mut self, key: &Guid) -> Result<bool>;
}

fn in_txn<A: WfpApi + ?Sized, T>(api: &mut A, f: impl FnOnce(&mut A) -> Result<T>) -> Result<T> {
    api.begin()?;
    match f(api) {
        Ok(v) => match api.commit() {
            Ok(()) => Ok(v),
            Err(e) => {
                api.abort();
                Err(e)
            }
        },
        Err(e) => {
            api.abort();
            Err(e)
        }
    }
}

/// Persistent catch-all block, loopback and Tor permits, in one transaction.
pub fn install_base<A: WfpApi + ?Sized>(api: &mut A, tor_exe: &std::path::Path) -> Result<()> {
    in_txn(api, |api| {
        match api.get_provider(&PROVIDER_KEY)? {
            Some(true) => {}
            Some(false) => {
                return Err(Error::Foreign(
                    "provider key exists but is not persistent".into(),
                ))
            }
            None => api.add_provider(&PROVIDER_KEY, crate::ids::PROVIDER_NAME)?,
        }
        if api.get_sublayer(&SUBLAYER_KEY)?.is_none() {
            api.add_sublayer(
                &SUBLAYER_KEY,
                crate::ids::SUBLAYER_NAME,
                &PROVIDER_KEY,
                SUBLAYER_WEIGHT,
            )?;
        }
        for spec in policy::base_filters(tor_exe) {
            api.add_filter(&spec, &PROVIDER_KEY, &SUBLAYER_KEY)?;
        }
        Ok(())
    })
}

pub fn install_tunnel<A: WfpApi + ?Sized>(api: &mut A, luid: u64) -> Result<()> {
    in_txn(api, |api| {
        for spec in policy::tunnel_filters(luid) {
            api.add_filter(&spec, &PROVIDER_KEY, &SUBLAYER_KEY)?;
        }
        Ok(())
    })
}

/// Read back provider, sublayer and each expected filter. Returns every discrepancy.
pub fn verify<A: WfpApi + ?Sized>(api: &mut A, expected: &[FilterSpec]) -> Result<()> {
    let mut problems = Vec::new();
    if api.get_provider(&PROVIDER_KEY)? != Some(true) {
        problems.push("provider missing or not persistent".to_string());
    }
    match api.get_sublayer(&SUBLAYER_KEY)? {
        Some(s)
            if s.persistent && s.provider == Some(PROVIDER_KEY) && s.weight == SUBLAYER_WEIGHT => {}
        _ => problems
            .push("sublayer missing, not persistent, foreign provider or wrong weight".to_string()),
    }
    for spec in expected {
        match api.get_filter(&spec.id.key())? {
            None => problems.push(format!("filter {:?} missing", spec.id)),
            Some(rb) => {
                let ok = rb.layer == spec.layer
                    && rb.action == spec.action
                    && rb.weight == spec.weight
                    && rb.persistent
                    && rb.provider == Some(PROVIDER_KEY)
                    && rb.sublayer == SUBLAYER_KEY
                    && rb.condition_count == spec.conditions.len();
                if !ok {
                    problems.push(format!("filter {:?} differs from policy: {rb:?}", spec.id));
                }
            }
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(Error::Wfp(problems.join("; ")))
    }
}

/// True if any Torwell-owned WFP object is present.
pub fn owned_present<A: WfpApi + ?Sized>(api: &mut A) -> Result<bool> {
    if api.get_provider(&PROVIDER_KEY)?.is_some() || api.get_sublayer(&SUBLAYER_KEY)?.is_some() {
        return Ok(true);
    }
    for id in crate::ids::ALL_FILTERS {
        if api.get_filter(&id.key())?.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Removes Torwell's filters, sublayer and provider. If the sublayer holds a filter Torwell does
/// not own, nothing is removed and [`Error::Foreign`] is returned. Idempotent.
pub fn remove_owned<A: WfpApi + ?Sized>(api: &mut A) -> Result<()> {
    in_txn(api, |api| {
        let present: BTreeSet<Guid> = api
            .filters_in_sublayer(&SUBLAYER_KEY)?
            .into_iter()
            .collect();
        if let Some(foreign) = present.iter().find(|k| FilterId::from_key(k).is_none()) {
            return Err(Error::Foreign(format!(
                "sublayer contains foreign filter {foreign}"
            )));
        }
        for id in crate::ids::ALL_FILTERS {
            api.delete_filter(&id.key())?;
        }
        api.delete_sublayer(&SUBLAYER_KEY)?;
        api.delete_provider(&PROVIDER_KEY)?;
        Ok(())
    })?;
    if owned_present(api)? {
        return Err(Error::Wfp("owned objects remain after removal".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::FakeWfp;
    use std::path::Path;

    const TOR: &str = r"C:\Program Files\Tor\tor.exe";

    fn expected_base() -> Vec<FilterSpec> {
        policy::base_filters(Path::new(TOR))
    }

    #[test]
    fn install_creates_persistent_objects_and_verifies() {
        let mut w = FakeWfp::default();
        install_base(&mut w, Path::new(TOR)).unwrap();
        verify(&mut w, &expected_base()).unwrap();
        let st = w.st();
        assert_eq!(st.filters.len(), 5);
        assert!(st.filters.values().all(|f| f.persistent));
    }

    #[test]
    fn failed_install_is_atomic() {
        let mut w = FakeWfp {
            fail_add_after: Some(3),
            ..Default::default()
        };
        assert!(install_base(&mut w, Path::new(TOR)).is_err());
        {
            let st = w.st();
            assert!(st.filters.is_empty() && st.providers.is_empty() && st.sublayers.is_empty());
        }
        assert!(!owned_present(&mut w).unwrap());
    }

    #[test]
    fn failed_commit_is_atomic_too() {
        let mut w = FakeWfp {
            fail_commit: true,
            ..Default::default()
        };
        assert!(install_base(&mut w, Path::new(TOR)).is_err());
        assert!(!owned_present(&mut w).unwrap());
    }

    #[test]
    fn verify_detects_tampering_and_missing() {
        let mut w = FakeWfp::default();
        install_base(&mut w, Path::new(TOR)).unwrap();
        w.st()
            .filters
            .get_mut(&FilterId::BlockAllV6.key())
            .unwrap()
            .weight = 15;
        assert!(verify(&mut w, &expected_base()).is_err());
        w.st().filters.remove(&FilterId::BlockAllV4.key());
        let msg = verify(&mut w, &expected_base()).unwrap_err().to_string();
        assert!(msg.contains("BlockAllV4"));
    }

    #[test]
    fn non_persistent_provider_is_refused_not_adopted() {
        let mut w = FakeWfp::default();
        w.st().providers.insert(PROVIDER_KEY, false);
        assert!(matches!(
            install_base(&mut w, Path::new(TOR)),
            Err(Error::Foreign(_))
        ));
    }

    #[test]
    fn tunnel_filters_add_incrementally() {
        let mut w = FakeWfp::default();
        install_base(&mut w, Path::new(TOR)).unwrap();
        install_tunnel(&mut w, 9).unwrap();
        let mut all = expected_base();
        all.extend(policy::tunnel_filters(9));
        verify(&mut w, &all).unwrap();
    }

    #[test]
    fn remove_deletes_only_owned_and_is_idempotent() {
        let mut w = FakeWfp::default();
        install_base(&mut w, Path::new(TOR)).unwrap();
        install_tunnel(&mut w, 9).unwrap();
        // Unrelated object in a different sublayer must survive.
        let other = Guid::new(1, 2, 3, [4; 8]);
        w.st().other_filters.push(other);
        remove_owned(&mut w).unwrap();
        assert!(!owned_present(&mut w).unwrap());
        assert_eq!(w.st().other_filters, vec![other]);
        remove_owned(&mut w).unwrap();
    }

    #[test]
    fn remove_refuses_when_foreign_filter_is_in_our_sublayer() {
        let mut w = FakeWfp::default();
        install_base(&mut w, Path::new(TOR)).unwrap();
        let foreign = Guid::new(9, 9, 9, [9; 8]);
        w.st().foreign_in_sublayer.push(foreign);
        assert!(matches!(remove_owned(&mut w), Err(Error::Foreign(_))));
        // Nothing was removed: the kill switch is intact.
        verify(&mut w, &expected_base()).unwrap();
    }
}
