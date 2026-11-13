//! Adapter queries and MAC override operations through the supported NetAdapter PowerShell
//! cmdlets (`Get-NetAdapter`, `Get-/Set-/Reset-NetAdapterAdvancedProperty`). Script text is
//! constant; adapter names and MAC values reach it only through environment variables that are
//! read as values. Nothing here runs during discovery except read-only queries.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

use torwell_core::mac::MacAddress;

use crate::error::{Error, Result};
use crate::exec::{CommandRunner, CommandSpec};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacState {
    pub effective: MacAddress,
    /// Whether the driver exposes the `NetworkAddress` advanced property at all.
    pub keyword_present: bool,
    /// Current override value; `None` = no override configured.
    pub override_value: Option<MacAddress>,
}

pub trait AdapterApi {
    fn tunnel_luid(&self, name: &str) -> Result<Option<u64>>;
    fn adapter_exists(&self, name: &str) -> Result<bool>;
    fn remove_adapter(&self, name: &str) -> Result<()>;
    fn uplink_ipv4(&self, name: &str) -> Result<Option<Ipv4Addr>>;
    /// Read-only. Fails for non-physical adapters.
    fn read_mac(&self, name: &str) -> Result<MacState>;
    fn set_mac_override(&self, name: &str, mac: &MacAddress) -> Result<()>;
    /// Removes the override (driver default). Used when none existed before.
    fn reset_mac_override(&self, name: &str) -> Result<()>;
}

pub fn validate_adapter_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.chars().count() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '_' | '-' | '.' | '(' | ')'))
        && name.trim() == name;
    if ok {
        Ok(())
    } else {
        Err(Error::Config(format!(
            "unsupported adapter name {name:?} (allowed: letters, digits, space _ - . ( ))"
        )))
    }
}

const PRELUDE: &str = "$ErrorActionPreference='Stop';$n=$env:TORWELL_ADAPTER;";
const LUID: &str = "$a=Get-NetAdapter -Name $n -IncludeHidden -ErrorAction SilentlyContinue;if($a){[string]$a.InterfaceLuid}";
const EXISTS: &str =
    "$a=Get-NetAdapter -Name $n -IncludeHidden -ErrorAction SilentlyContinue;if($a){'1'}else{'0'}";
const REMOVE: &str = "Remove-NetAdapter -Name $n -Confirm:$false";
const UPLINK: &str = "$ip=Get-NetIPAddress -InterfaceAlias $n -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object{$_.IPAddress -notlike '169.254.*'}|Select-Object -First 1;if($ip){$ip.IPAddress}";
const READ_MAC: &str = "$a=Get-NetAdapter -Name $n -Physical;$p=Get-NetAdapterAdvancedProperty -Name $n -RegistryKeyword NetworkAddress -ErrorAction SilentlyContinue;[pscustomobject]@{Mac=[string]$a.MacAddress;HasKeyword=($null -ne $p);Value=[string]($p.RegistryValue -join '')}|ConvertTo-Json -Compress";
const SET_MAC: &str = "Set-NetAdapterAdvancedProperty -Name $n -RegistryKeyword NetworkAddress -RegistryValue $env:TORWELL_MAC";
const RESET_MAC: &str = "Reset-NetAdapterAdvancedProperty -Name $n -RegistryKeyword NetworkAddress";

pub struct PsAdapter<R: CommandRunner> {
    pub runner: R,
    pub powershell: PathBuf,
    pub timeout: Duration,
}

impl<R: CommandRunner> PsAdapter<R> {
    pub fn new(runner: R, powershell: PathBuf) -> Self {
        Self {
            runner,
            powershell,
            timeout: Duration::from_secs(60),
        }
    }

    fn run(&self, name: &str, script: &str, mac: Option<&MacAddress>) -> Result<String> {
        validate_adapter_name(name)?;
        let mut env = vec![("TORWELL_ADAPTER".to_string(), name.to_string())];
        if let Some(m) = mac {
            env.push((
                "TORWELL_MAC".into(),
                m.octets().iter().map(|b| format!("{b:02X}")).collect(),
            ));
        }
        let spec = CommandSpec {
            program: self.powershell.clone(),
            args: [
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Restricted",
                "-Command",
            ]
            .iter()
            .map(Into::into)
            .chain(std::iter::once(format!("{PRELUDE}{script}").into()))
            .collect(),
            env,
            timeout: self.timeout,
        };
        let out = self
            .runner
            .run(&spec)
            .map_err(|e| Error::Mac(format!("cannot run powershell: {e}")))?;
        if out.timed_out {
            return Err(Error::Mac("powershell timed out".into()));
        }
        if !out.success() {
            return Err(Error::Mac(format!(
                "powershell failed ({:?}): {}",
                out.code,
                out.stderr.trim()
            )));
        }
        Ok(out.stdout.trim().to_string())
    }
}

impl<R: CommandRunner> AdapterApi for PsAdapter<R> {
    fn tunnel_luid(&self, name: &str) -> Result<Option<u64>> {
        let s = self.run(name, LUID, None)?;
        if s.is_empty() {
            return Ok(None);
        }
        s.parse()
            .map(Some)
            .map_err(|_| Error::Bridge(format!("unexpected LUID output {s:?}")))
    }
    fn adapter_exists(&self, name: &str) -> Result<bool> {
        Ok(self.run(name, EXISTS, None)? == "1")
    }
    fn remove_adapter(&self, name: &str) -> Result<()> {
        self.run(name, REMOVE, None).map(|_| ())
    }
    fn uplink_ipv4(&self, name: &str) -> Result<Option<Ipv4Addr>> {
        let s = self.run(name, UPLINK, None)?;
        if s.is_empty() {
            return Ok(None);
        }
        s.parse()
            .map(Some)
            .map_err(|_| Error::Config(format!("unexpected address output {s:?}")))
    }
    fn read_mac(&self, name: &str) -> Result<MacState> {
        let s = self.run(name, READ_MAC, None)?;
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Raw {
            mac: String,
            has_keyword: bool,
            value: String,
        }
        let raw: Raw = serde_json::from_str(&s)
            .map_err(|e| Error::Mac(format!("unparsable adapter state: {e}")))?;
        let effective = MacAddress::parse(&raw.mac)
            .map_err(|e| Error::Mac(format!("effective MAC {:?}: {e}", raw.mac)))?;
        let override_value = if raw.value.is_empty() {
            None
        } else {
            Some(
                MacAddress::parse(&raw.value)
                    .map_err(|e| Error::Mac(format!("override value {:?}: {e}", raw.value)))?,
            )
        };
        Ok(MacState {
            effective,
            keyword_present: raw.has_keyword,
            override_value,
        })
    }
    fn set_mac_override(&self, name: &str, mac: &MacAddress) -> Result<()> {
        self.run(name, SET_MAC, Some(mac)).map(|_| ())
    }
    fn reset_mac_override(&self, name: &str) -> Result<()> {
        self.run(name, RESET_MAC, None).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::CommandOutput;
    use std::cell::RefCell;

    struct Rec(RefCell<Vec<CommandSpec>>, String);
    impl CommandRunner for Rec {
        fn run(&self, s: &CommandSpec) -> std::io::Result<CommandOutput> {
            self.0.borrow_mut().push(s.clone());
            Ok(CommandOutput {
                code: Some(0),
                stdout: self.1.clone(),
                stderr: String::new(),
                timed_out: false,
            })
        }
    }

    fn api(out: &str) -> PsAdapter<Rec> {
        PsAdapter::new(
            Rec(RefCell::new(vec![]), out.into()),
            PathBuf::from(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
        )
    }

    #[test]
    fn hostile_names_are_rejected_before_any_process_runs() {
        let a = api("");
        for bad in [
            "",
            "eth0'; calc #",
            "a\"b",
            "x$(y)",
            " lead",
            "a;b",
            "n\nl",
            "`x",
        ] {
            assert!(a.read_mac(bad).is_err(), "{bad:?}");
        }
        assert!(a.runner.0.borrow().is_empty());
    }

    #[test]
    fn values_travel_in_env_not_in_script_text() {
        let a = api("");
        let mac = MacAddress::parse("02:11:22:33:44:55").unwrap();
        a.set_mac_override("Ethernet 2", &mac).unwrap();
        let calls = a.runner.0.borrow();
        let c = &calls[0];
        assert!(c
            .env
            .contains(&("TORWELL_ADAPTER".into(), "Ethernet 2".into())));
        assert!(c
            .env
            .contains(&("TORWELL_MAC".into(), "021122334455".into())));
        let script = c.args.last().unwrap().to_string_lossy().into_owned();
        assert!(!script.contains("Ethernet 2") && !script.contains("021122334455"));
        assert!(c.args.iter().any(|x| x == "-NoProfile"));
    }

    #[test]
    fn parses_mac_state_with_and_without_override() {
        let s = api(r#"{"Mac":"00-11-22-33-44-55","HasKeyword":true,"Value":""}"#)
            .read_mac("Ethernet")
            .unwrap();
        assert!(s.keyword_present && s.override_value.is_none());
        assert_eq!(s.effective.to_string(), "00:11:22:33:44:55");
        let s = api(r#"{"Mac":"02-AA-BB-CC-DD-EE","HasKeyword":true,"Value":"02AABBCCDDEE"}"#)
            .read_mac("Ethernet")
            .unwrap();
        assert_eq!(s.override_value, Some(s.effective));
        let s = api(r#"{"Mac":"00-11-22-33-44-55","HasKeyword":false,"Value":""}"#)
            .read_mac("Ethernet")
            .unwrap();
        assert!(!s.keyword_present);
        assert!(api("not json").read_mac("Ethernet").is_err());
    }

    #[test]
    fn luid_and_uplink_parsing() {
        assert_eq!(api("123").tunnel_luid("Tun").unwrap(), Some(123));
        assert_eq!(api("").tunnel_luid("Tun").unwrap(), None);
        assert!(api("abc").tunnel_luid("Tun").is_err());
        assert_eq!(
            api("10.0.0.7").uplink_ipv4("Ethernet").unwrap(),
            Some("10.0.0.7".parse().unwrap())
        );
    }
}
