//! Raw WFP calls (windows crate). Not compiled or run on Windows yet: see docs/WINDOWS.md.
//!
//! The engine is opened with no session, so objects are not dynamic. Provider, sublayer and
//! filters carry the PERSISTENT flag, which keeps them across helper exit and BFE restarts.
//! (WFP persists such objects only for providers without a Windows service name, which is the
//! case here.) Filters carry no CLEAR_ACTION_RIGHT flag.

use std::ffi::c_void;
use std::path::Path;

use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;

use crate::error::{Error, Result};
use crate::ids::Guid;
use crate::policy::{Action, Condition, FilterSpec, Layer};
use crate::wfp::{FilterReadback, SublayerReadback, WfpApi};

const RPC_C_AUTHN_WINNT: u32 = 10;
const NOT_FOUND: [u32; 3] = [0x8032_0003, 0x8032_0005, 0x8032_0007];

fn g(x: &Guid) -> GUID {
    GUID {
        data1: x.data1,
        data2: x.data2,
        data3: x.data3,
        data4: x.data4,
    }
}
fn ours(x: &GUID) -> Guid {
    Guid {
        data1: x.data1,
        data2: x.data2,
        data3: x.data3,
        data4: x.data4,
    }
}
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
fn check(what: &str, code: u32) -> Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(Error::Wfp(format!("{what} failed: 0x{code:08x}")))
    }
}

pub struct SystemWfp {
    engine: HANDLE,
}

impl SystemWfp {
    pub fn open() -> Result<Self> {
        let mut h = HANDLE::default();
        // SAFETY: valid out pointer; null server name = local machine; no session = non-dynamic objects.
        let rc = unsafe { FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, None, &mut h) };
        check("FwpmEngineOpen0", rc)?;
        Ok(Self { engine: h })
    }
}

impl Drop for SystemWfp {
    fn drop(&mut self) {
        // SAFETY: handle was opened by `open`.
        unsafe { FwpmEngineClose0(self.engine) };
    }
}

struct Owned<T>(*mut T);
impl<T> Drop for Owned<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let mut p = self.0 as *mut c_void;
            // SAFETY: pointer was allocated by a Fwpm*/FwpmGetAppId call.
            unsafe { FwpmFreeMemory0(&mut p) };
        }
    }
}

fn layer_key(l: Layer) -> GUID {
    match l {
        Layer::AleAuthConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        Layer::AleAuthConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    }
}
fn layer_of(k: &GUID) -> Option<Layer> {
    if *k == FWPM_LAYER_ALE_AUTH_CONNECT_V4 {
        Some(Layer::AleAuthConnectV4)
    } else if *k == FWPM_LAYER_ALE_AUTH_CONNECT_V6 {
        Some(Layer::AleAuthConnectV6)
    } else {
        None
    }
}

/// Backing storage for condition values so pointers stay valid until `FwpmFilterAdd0` returns.
/// Each value is boxed on purpose: pushing to a `Vec<T>` may reallocate and move earlier
/// elements, invalidating pointers already handed to WFP condition structs.
#[allow(clippy::vec_box)]
#[derive(Default)]
struct Storage {
    v4: Vec<Box<FWP_V4_ADDR_AND_MASK>>,
    v6: Vec<Box<FWP_V6_ADDR_AND_MASK>>,
    u64s: Vec<Box<u64>>,
    app: Vec<Owned<FWP_BYTE_BLOB>>,
}

impl WfpApi for SystemWfp {
    fn begin(&mut self) -> Result<()> {
        // SAFETY: engine handle is valid.
        check("FwpmTransactionBegin0", unsafe {
            FwpmTransactionBegin0(self.engine, 0)
        })
    }
    fn commit(&mut self) -> Result<()> {
        check("FwpmTransactionCommit0", unsafe {
            FwpmTransactionCommit0(self.engine)
        })
    }
    fn abort(&mut self) {
        unsafe { FwpmTransactionAbort0(self.engine) };
    }

    fn get_provider(&mut self, key: &Guid) -> Result<Option<bool>> {
        let k = g(key);
        let mut p: *mut FWPM_PROVIDER0 = std::ptr::null_mut();
        let rc = unsafe { FwpmProviderGetByKey0(self.engine, &k, &mut p) };
        if NOT_FOUND.contains(&rc) {
            return Ok(None);
        }
        check("FwpmProviderGetByKey0", rc)?;
        let o = Owned(p);
        Ok(Some(
            unsafe { (*o.0).flags } & FWPM_PROVIDER_FLAG_PERSISTENT != 0,
        ))
    }

    fn add_provider(&mut self, key: &Guid, name: &str) -> Result<()> {
        let mut n = wide(name);
        let p = FWPM_PROVIDER0 {
            providerKey: g(key),
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(n.as_mut_ptr()),
                description: PWSTR::null(),
            },
            flags: FWPM_PROVIDER_FLAG_PERSISTENT,
            providerData: FWP_BYTE_BLOB {
                size: 0,
                data: std::ptr::null_mut(),
            },
            serviceName: PWSTR::null(),
        };
        check("FwpmProviderAdd0", unsafe {
            FwpmProviderAdd0(self.engine, &p, None)
        })
    }

    fn get_sublayer(&mut self, key: &Guid) -> Result<Option<SublayerReadback>> {
        let k = g(key);
        let mut p: *mut FWPM_SUBLAYER0 = std::ptr::null_mut();
        let rc = unsafe { FwpmSubLayerGetByKey0(self.engine, &k, &mut p) };
        if NOT_FOUND.contains(&rc) {
            return Ok(None);
        }
        check("FwpmSubLayerGetByKey0", rc)?;
        let o = Owned(p);
        let s = unsafe { &*o.0 };
        let provider = if s.providerKey.is_null() {
            None
        } else {
            Some(ours(unsafe { &*s.providerKey }))
        };
        Ok(Some(SublayerReadback {
            persistent: s.flags & FWPM_SUBLAYER_FLAG_PERSISTENT != 0,
            provider,
            weight: s.weight,
        }))
    }

    fn add_sublayer(&mut self, key: &Guid, name: &str, provider: &Guid, weight: u16) -> Result<()> {
        let mut n = wide(name);
        let mut pk = g(provider);
        let s = FWPM_SUBLAYER0 {
            subLayerKey: g(key),
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(n.as_mut_ptr()),
                description: PWSTR::null(),
            },
            flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
            providerKey: &mut pk,
            providerData: FWP_BYTE_BLOB {
                size: 0,
                data: std::ptr::null_mut(),
            },
            weight,
        };
        check("FwpmSubLayerAdd0", unsafe {
            FwpmSubLayerAdd0(self.engine, &s, None)
        })
    }

    fn add_filter(&mut self, spec: &FilterSpec, provider: &Guid, sublayer: &Guid) -> Result<()> {
        let mut store = Storage::default();
        let mut conds: Vec<FWPM_FILTER_CONDITION0> = Vec::new();
        let empty = FWP_CONDITION_VALUE0 {
            r#type: FWP_EMPTY,
            Anonymous: unsafe { std::mem::zeroed() },
        };
        for c in &spec.conditions {
            let mut fc = FWPM_FILTER_CONDITION0 {
                fieldKey: GUID::zeroed(),
                matchType: FWP_MATCH_EQUAL,
                conditionValue: empty,
            };
            match c {
                Condition::RemoteV4 { addr, prefix } => {
                    let mask: u32 = if *prefix == 0 {
                        0
                    } else {
                        u32::MAX << (32 - *prefix as u32)
                    };
                    let mut b = Box::new(FWP_V4_ADDR_AND_MASK {
                        addr: u32::from_be_bytes(*addr),
                        mask,
                    });
                    fc.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                    fc.conditionValue.r#type = FWP_V4_ADDR_MASK;
                    fc.conditionValue.Anonymous.v4AddrMask = &mut *b;
                    store.v4.push(b);
                }
                Condition::RemoteV6Loopback => {
                    let mut a = [0u8; 16];
                    a[15] = 1;
                    let mut b = Box::new(FWP_V6_ADDR_AND_MASK {
                        addr: a,
                        prefixLength: 128,
                    });
                    fc.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                    fc.conditionValue.r#type = FWP_V6_ADDR_MASK;
                    fc.conditionValue.Anonymous.v6AddrMask = &mut *b;
                    store.v6.push(b);
                }
                Condition::AppPath(path) => {
                    let wpath = wide(&path_str(path));
                    let mut blob: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
                    // The WFP app id for a path comes from FwpmGetAppIdFromFileName0 (NT path form).
                    check("FwpmGetAppIdFromFileName0", unsafe {
                        FwpmGetAppIdFromFileName0(PCWSTR(wpath.as_ptr()), &mut blob)
                    })?;
                    fc.fieldKey = FWPM_CONDITION_ALE_APP_ID;
                    fc.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
                    fc.conditionValue.Anonymous.byteBlob = blob;
                    store.app.push(Owned(blob));
                }
                Condition::InterfaceLuid(luid) => {
                    let mut b = Box::new(*luid);
                    fc.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
                    fc.conditionValue.r#type = FWP_UINT64;
                    fc.conditionValue.Anonymous.uint64 = &mut *b;
                    store.u64s.push(b);
                }
                Condition::Tcp | Condition::Udp => {
                    fc.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
                    fc.conditionValue.r#type = FWP_UINT8;
                    fc.conditionValue.Anonymous.uint8 =
                        if matches!(c, Condition::Tcp) { 6 } else { 17 };
                }
                Condition::RemotePort(p) => {
                    fc.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
                    fc.conditionValue.r#type = FWP_UINT16;
                    fc.conditionValue.Anonymous.uint16 = *p;
                }
            }
            conds.push(fc);
        }
        let mut name = wide(&spec.id.name());
        let mut pk = g(provider);
        let mut f: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
        f.filterKey = g(&spec.id.key());
        f.displayData = FWPM_DISPLAY_DATA0 {
            name: PWSTR(name.as_mut_ptr()),
            description: PWSTR::null(),
        };
        f.flags = FWPM_FILTER_FLAG_PERSISTENT;
        f.providerKey = &mut pk;
        f.layerKey = layer_key(spec.layer);
        f.subLayerKey = g(sublayer);
        f.weight.r#type = FWP_UINT8;
        f.weight.Anonymous.uint8 = spec.weight;
        f.numFilterConditions = conds.len() as u32;
        f.filterCondition = if conds.is_empty() {
            std::ptr::null_mut()
        } else {
            conds.as_mut_ptr()
        };
        f.action.r#type = match spec.action {
            Action::Permit => FWP_ACTION_PERMIT,
            Action::Block => FWP_ACTION_BLOCK,
        };
        let rc = unsafe { FwpmFilterAdd0(self.engine, &f, None, None) };
        drop(store);
        check("FwpmFilterAdd0", rc)
    }

    fn get_filter(&mut self, key: &Guid) -> Result<Option<FilterReadback>> {
        let k = g(key);
        let mut p: *mut FWPM_FILTER0 = std::ptr::null_mut();
        let rc = unsafe { FwpmFilterGetByKey0(self.engine, &k, &mut p) };
        if NOT_FOUND.contains(&rc) {
            return Ok(None);
        }
        check("FwpmFilterGetByKey0", rc)?;
        let o = Owned(p);
        let f = unsafe { &*o.0 };
        let layer = layer_of(&f.layerKey)
            .ok_or_else(|| Error::Wfp("filter on an unexpected layer".into()))?;
        let action = if f.action.r#type == FWP_ACTION_PERMIT {
            Action::Permit
        } else if f.action.r#type == FWP_ACTION_BLOCK {
            Action::Block
        } else {
            return Err(Error::Wfp("unexpected action type".into()));
        };
        let weight = if f.weight.r#type == FWP_UINT8 {
            unsafe { f.weight.Anonymous.uint8 }
        } else {
            u8::MAX
        };
        Ok(Some(FilterReadback {
            layer,
            action,
            weight,
            persistent: f.flags.0 & FWPM_FILTER_FLAG_PERSISTENT.0 != 0,
            provider: if f.providerKey.is_null() {
                None
            } else {
                Some(ours(unsafe { &*f.providerKey }))
            },
            sublayer: ours(&f.subLayerKey),
            condition_count: f.numFilterConditions as usize,
        }))
    }

    fn filters_in_sublayer(&mut self, sublayer: &Guid) -> Result<Vec<Guid>> {
        let want = g(sublayer);
        let mut eh = HANDLE::default();
        check("FwpmFilterCreateEnumHandle0", unsafe {
            FwpmFilterCreateEnumHandle0(self.engine, None, &mut eh)
        })?;
        let mut out = Vec::new();
        let result = loop {
            let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
            let mut n = 0u32;
            let rc = unsafe { FwpmFilterEnum0(self.engine, eh, 256, &mut entries, &mut n) };
            if rc != 0 {
                break check("FwpmFilterEnum0", rc);
            }
            let batch = Owned(entries);
            for i in 0..n as usize {
                let f = unsafe { &**batch.0.add(i) };
                if f.subLayerKey == want {
                    out.push(ours(&f.filterKey));
                }
            }
            if n < 256 {
                break Ok(());
            }
        };
        unsafe { FwpmFilterDestroyEnumHandle0(self.engine, eh) };
        result.map(|_| out)
    }

    fn delete_filter(&mut self, key: &Guid) -> Result<bool> {
        let k = g(key);
        let rc = unsafe { FwpmFilterDeleteByKey0(self.engine, &k) };
        if NOT_FOUND.contains(&rc) {
            return Ok(false);
        }
        check("FwpmFilterDeleteByKey0", rc).map(|_| true)
    }
    fn delete_sublayer(&mut self, key: &Guid) -> Result<bool> {
        let k = g(key);
        let rc = unsafe { FwpmSubLayerDeleteByKey0(self.engine, &k) };
        if NOT_FOUND.contains(&rc) {
            return Ok(false);
        }
        check("FwpmSubLayerDeleteByKey0", rc).map(|_| true)
    }
    fn delete_provider(&mut self, key: &Guid) -> Result<bool> {
        let k = g(key);
        let rc = unsafe { FwpmProviderDeleteByKey0(self.engine, &k) };
        if NOT_FOUND.contains(&rc) {
            return Ok(false);
        }
        check("FwpmProviderDeleteByKey0", rc).map(|_| true)
    }
}

fn path_str(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}
