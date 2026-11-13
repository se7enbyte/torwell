//! Process control, elevation, service probe, existing-connection reaping. Not run on Windows yet.

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::NetworkManagement::IpHelper::*;
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Threading::*;

use crate::backend::ConnectionReaper;
use crate::error::{Error, Result};
use crate::exec::{CommandRunner, CommandSpec, StdRunner};
use crate::preflight::HostProbe;
use crate::proc::ProcessControl;

pub struct SystemProcs;

struct H(HANDLE);
impl Drop for H {
    fn drop(&mut self) {
        // SAFETY: handle came from OpenProcess.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

fn open(pid: u32, access: PROCESS_ACCESS_RIGHTS) -> Option<H> {
    unsafe { OpenProcess(access, false, pid).ok().map(H) }
}

impl ProcessControl for SystemProcs {
    fn image_path(&self, pid: u32) -> Option<PathBuf> {
        let h = open(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
        let mut buf = vec![0u16; 32768];
        let mut len = buf.len() as u32;
        unsafe {
            QueryFullProcessImageNameW(h.0, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len)
                .ok()?
        };
        Some(PathBuf::from(String::from_utf16_lossy(
            &buf[..len as usize],
        )))
    }
    fn terminate(&self, pid: u32) -> io::Result<()> {
        let h = open(pid, PROCESS_TERMINATE).ok_or_else(io::Error::last_os_error)?;
        unsafe { TerminateProcess(h.0, 1) }.map_err(|e| io::Error::other(e.to_string()))
    }
    fn is_alive(&self, pid: u32) -> bool {
        let Some(h) = open(pid, PROCESS_QUERY_LIMITED_INFORMATION) else {
            return false;
        };
        let mut code = 0u32;
        // STILL_ACTIVE = 259
        unsafe { GetExitCodeProcess(h.0, &mut code).is_ok() && code == 259 }
    }
}

pub struct SystemHost {
    pub sc_exe: PathBuf,
}

impl HostProbe for SystemHost {
    fn is_elevated(&self) -> Result<bool> {
        unsafe {
            let mut tok = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok)
                .map_err(|e| Error::Preflight(vec![e.to_string()]))?;
            let tok = H(tok);
            let mut el = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut ret = 0u32;
            GetTokenInformation(
                tok.0,
                TokenElevation,
                Some(&mut el as *mut _ as *mut _),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut ret,
            )
            .map_err(|e| Error::Preflight(vec![e.to_string()]))?;
            Ok(el.TokenIsElevated != 0)
        }
    }
    fn bfe_running(&self) -> Result<bool> {
        let out = StdRunner
            .run(&CommandSpec {
                program: self.sc_exe.clone(),
                args: vec!["query".into(), "BFE".into()],
                env: vec![],
                timeout: Duration::from_secs(10),
            })
            .map_err(|e| Error::Preflight(vec![e.to_string()]))?;
        Ok(out.success() && out.stdout.contains("RUNNING"))
    }
}

pub struct SystemReaper;

const AF_INET: u32 = 2;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

fn tcp4_rows() -> Result<Vec<MIB_TCPROW_OWNER_PID>> {
    let mut size = 0u32;
    let mut buf: Vec<u8> = Vec::new();
    for _ in 0..8 {
        let rc = unsafe {
            GetExtendedTcpTable(
                if buf.is_empty() {
                    None
                } else {
                    Some(buf.as_mut_ptr() as *mut _)
                },
                &mut size,
                false,
                AF_INET,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if rc == 0 && !buf.is_empty() {
            let t = buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
            let n = unsafe { (*t).dwNumEntries } as usize;
            let first = unsafe { std::ptr::addr_of!((*t).table) as *const MIB_TCPROW_OWNER_PID };
            return Ok((0..n).map(|i| unsafe { *first.add(i) }).collect());
        }
        if rc == ERROR_INSUFFICIENT_BUFFER || (rc == 0 && buf.is_empty()) {
            buf = vec![0u8; size as usize + 4096];
            size = buf.len() as u32;
            continue;
        }
        return Err(Error::Process(format!("GetExtendedTcpTable failed: {rc}")));
    }
    Err(Error::Process("TCP table kept changing size".into()))
}

fn candidates(keep: &[u32]) -> Result<Vec<MIB_TCPROW_OWNER_PID>> {
    Ok(tcp4_rows()?
        .into_iter()
        // ESTABLISHED, remote is not 127.0.0.0/8 (address is stored in network byte order), not kept.
        .filter(|r| {
            r.dwState == MIB_TCP_STATE_ESTAB.0 as u32
                && (r.dwRemoteAddr & 0xFF) != 127
                && !keep.contains(&r.dwOwningPid)
        })
        .collect())
}

impl ConnectionReaper for SystemReaper {
    fn reset_existing(&self, keep: &[u32]) -> Result<usize> {
        let mut n = 0;
        for r in candidates(keep)? {
            let row = MIB_TCPROW_LH {
                Anonymous: MIB_TCPROW_LH_0 {
                    dwState: MIB_TCP_STATE_DELETE_TCB.0 as u32,
                },
                dwLocalAddr: r.dwLocalAddr,
                dwLocalPort: r.dwLocalPort,
                dwRemoteAddr: r.dwRemoteAddr,
                dwRemotePort: r.dwRemotePort,
            };
            if unsafe { SetTcpEntry(&row) } == 0 {
                n += 1;
            }
        }
        Ok(n)
    }
    /// IPv4 only. IPv6 established connections are not enumerated or reset here: documented gap.
    fn lingering(&self, keep: &[u32]) -> Result<Vec<String>> {
        Ok(candidates(keep)?
            .into_iter()
            .map(|r| {
                format!(
                    "{}.{}.{}.{}:{} pid {}",
                    r.dwRemoteAddr & 0xFF,
                    (r.dwRemoteAddr >> 8) & 0xFF,
                    (r.dwRemoteAddr >> 16) & 0xFF,
                    r.dwRemoteAddr >> 24,
                    u16::from_be(r.dwRemotePort as u16),
                    r.dwOwningPid
                )
            })
            .collect())
    }
}
