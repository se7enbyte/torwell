//! Requests. The wire form is flat (`{"version":1,"command":"start","config":{..},"adapter":{..}}`)
//! and every object refuses unknown fields. Conversion to and from the typed [`Request`]
//! performs the validation, so no unchecked value reaches an engine.

use serde::{Deserialize, Serialize};
use torwell_core::config::{check_name, Config, MacMode};

use crate::{ErrorKind, ProtocolError, PROTOCOL_VERSION};

/// A command with its typed arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Read-only: host capabilities and adapters. Changes nothing.
    Inspect,
    /// Read-only: the current lifecycle state and its verification evidence.
    Status,
    /// Read-only: an inert plan for the selection. It is never an applied connection.
    Plan(Selection),
    /// Applies the selection and verifies it before reporting `connected`.
    Start(Selection),
    /// Tears down Torwell-owned state.
    Stop,
    /// Stops the current session and starts the given selection.
    Switch(Selection),
    /// Finishes a previous partial failure (`recovery_required`) without starting anything.
    Recover,
}

impl Command {
    /// The wire name, such as `"start"`.
    pub fn name(&self) -> &'static str {
        match self {
            Command::Inspect => "inspect",
            Command::Status => "status",
            Command::Plan(_) => "plan",
            Command::Start(_) => "start",
            Command::Stop => "stop",
            Command::Switch(_) => "switch",
            Command::Recover => "recover",
        }
    }
}

/// A validated core [`Config`] and an optional adapter. MAC mode `random_on_apply` requires an adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    pub config: Config,
    pub adapter: Option<Adapter>,
}

impl Selection {
    /// Validates the config (non-zero, distinct ports) and the MAC/adapter pairing.
    pub fn new(config: Config, adapter: Option<Adapter>) -> Result<Self, ProtocolError> {
        config
            .validate()
            .map_err(|e| invalid(format!("invalid config: {e}")))?;
        if config.mac == MacMode::RandomOnApply && adapter.is_none() {
            return Err(invalid(
                "MAC mode random_on_apply requires a selected adapter",
            ));
        }
        Ok(Self { config, adapter })
    }
}

/// An adapter name. Names are data, never shell or path fragments: 1 to 64 characters, no
/// control characters, no leading or trailing whitespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "AdapterWire")]
pub struct Adapter {
    pub name: String,
}

impl Adapter {
    /// Deserialization goes through this check too, so an unvalidated name cannot be decoded.
    pub fn new(name: impl Into<String>) -> Result<Self, ProtocolError> {
        let name = name.into();
        let trimmed = name.trim();
        if trimmed.len() != name.len() || check_name(&name).is_err() {
            return Err(invalid(
                "adapter name must be 1-64 characters without control characters or surrounding spaces",
            ));
        }
        Ok(Self { name })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterWire {
    name: String,
}

impl TryFrom<AdapterWire> for Adapter {
    type Error = ProtocolError;

    fn try_from(wire: AdapterWire) -> Result<Self, Self::Error> {
        Adapter::new(wire.name)
    }
}

/// A complete request. Build with [`Request::new`]; decode with [`crate::decode_request`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RequestWire", into = "RequestWire")]
pub struct Request {
    pub version: u32,
    pub command: Command,
}

impl Request {
    pub fn new(command: Command) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            command,
        }
    }

    /// Re-checks the invariants that decoding enforces. Used before encoding, so a
    /// constructed request cannot be sent in a form the engine would refuse.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != PROTOCOL_VERSION {
            return Err(ProtocolError::new(
                ErrorKind::UnsupportedVersion,
                "unsupported request version",
            ));
        }
        match &self.command {
            Command::Plan(s) | Command::Start(s) | Command::Switch(s) => {
                Selection::new(s.config.clone(), s.adapter.clone()).map(drop)
            }
            _ => Ok(()),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum CommandName {
    Inspect,
    Status,
    Plan,
    Start,
    Stop,
    Switch,
    Recover,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigWire {
    mac: MacMode,
    socks_port: u16,
    trans_port: u16,
    dns_port: u16,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RequestWire {
    version: u32,
    command: CommandName,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    config: Option<ConfigWire>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    adapter: Option<Adapter>,
}

impl TryFrom<RequestWire> for Request {
    type Error = ProtocolError;

    fn try_from(wire: RequestWire) -> Result<Self, Self::Error> {
        if wire.version != PROTOCOL_VERSION {
            return Err(ProtocolError::new(
                ErrorKind::UnsupportedVersion,
                format!("protocol version {} is not supported", wire.version),
            ));
        }
        let needs_selection = matches!(
            wire.command,
            CommandName::Plan | CommandName::Start | CommandName::Switch
        );
        if !needs_selection && (wire.config.is_some() || wire.adapter.is_some()) {
            return Err(invalid("this command takes no `config` or `adapter`"));
        }
        let adapter = wire.adapter;
        let selection = match wire.config {
            Some(c) if needs_selection => Some(Selection::new(
                Config {
                    mac: c.mac,
                    socks_port: c.socks_port,
                    trans_port: c.trans_port,
                    dns_port: c.dns_port,
                },
                adapter,
            )?),
            None if needs_selection => return Err(invalid("this command requires `config`")),
            _ => None,
        };
        let command = match (wire.command, selection) {
            (CommandName::Inspect, _) => Command::Inspect,
            (CommandName::Status, _) => Command::Status,
            (CommandName::Stop, _) => Command::Stop,
            (CommandName::Recover, _) => Command::Recover,
            (CommandName::Plan, Some(s)) => Command::Plan(s),
            (CommandName::Start, Some(s)) => Command::Start(s),
            (CommandName::Switch, Some(s)) => Command::Switch(s),
            _ => return Err(invalid("this command requires `config`")),
        };
        Ok(Request {
            version: PROTOCOL_VERSION,
            command,
        })
    }
}

impl From<Request> for RequestWire {
    fn from(request: Request) -> Self {
        let (command, selection) = match request.command {
            Command::Inspect => (CommandName::Inspect, None),
            Command::Status => (CommandName::Status, None),
            Command::Stop => (CommandName::Stop, None),
            Command::Recover => (CommandName::Recover, None),
            Command::Plan(s) => (CommandName::Plan, Some(s)),
            Command::Start(s) => (CommandName::Start, Some(s)),
            Command::Switch(s) => (CommandName::Switch, Some(s)),
        };
        let (config, adapter) = match selection {
            Some(s) => (
                Some(ConfigWire {
                    mac: s.config.mac,
                    socks_port: s.config.socks_port,
                    trans_port: s.config.trans_port,
                    dns_port: s.config.dns_port,
                }),
                s.adapter,
            ),
            None => (None, None),
        };
        RequestWire {
            version: request.version,
            command,
            config,
            adapter,
        }
    }
}

fn invalid(message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ErrorKind::InvalidRequest, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decode_request, encode_request};

    fn start_json(extra: &str) -> String {
        format!(
            r#"{{"version":1,"command":"start","config":{{"mac":"off","socks_port":9050,"trans_port":9040,"dns_port":5353}}{extra}}}"#
        )
    }

    #[test]
    fn status_round_trips_as_flat_json() {
        let bytes = encode_request(&Request::new(Command::Status)).unwrap();
        assert_eq!(bytes, br#"{"version":1,"command":"status"}"#);
        assert_eq!(
            decode_request(&bytes).unwrap(),
            Request::new(Command::Status)
        );
    }

    #[test]
    fn start_with_adapter_round_trips() {
        let selection =
            Selection::new(Config::default(), Some(Adapter::new("eth0").unwrap())).unwrap();
        let request = Request::new(Command::Start(selection));
        let bytes = encode_request(&request).unwrap();
        assert_eq!(decode_request(&bytes).unwrap(), request);
    }

    #[test]
    fn mac_is_off_by_default_when_omitted_is_refused() {
        // `mac` is required, so there is no implicit enablement path.
        let json = br#"{"version":1,"command":"plan","config":{"socks_port":9050,"trans_port":9040,"dns_port":5353}}"#;
        assert_eq!(
            decode_request(json).unwrap_err().kind,
            ErrorKind::InvalidRequest
        );
    }

    #[test]
    fn mac_random_requires_validated_adapter() {
        let json = br#"{"version":1,"command":"start","config":{"mac":"random_on_apply","socks_port":9050,"trans_port":9040,"dns_port":5353}}"#;
        let err = decode_request(json).unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidRequest);
        assert!(err.message.contains("requires a selected adapter"));

        let ok = br#"{"version":1,"command":"start","config":{"mac":"random_on_apply","socks_port":9050,"trans_port":9040,"dns_port":5353},"adapter":{"name":"wlan0"}}"#;
        assert!(decode_request(ok).is_ok());
    }

    #[test]
    fn invalid_config_is_rejected_by_core_validation() {
        let dup = br#"{"version":1,"command":"plan","config":{"mac":"off","socks_port":9050,"trans_port":9050,"dns_port":5353}}"#;
        let err = decode_request(dup).unwrap_err();
        assert!(err.message.contains("distinct"), "{err}");
        let zero = br#"{"version":1,"command":"plan","config":{"mac":"off","socks_port":0,"trans_port":9040,"dns_port":5353}}"#;
        assert!(decode_request(zero).is_err());
    }

    #[test]
    fn unknown_fields_are_refused_everywhere() {
        let top = br#"{"version":1,"command":"status","shell":"sh -c id"}"#;
        assert_eq!(
            decode_request(top).unwrap_err().kind,
            ErrorKind::InvalidRequest
        );

        let in_config = br#"{"version":1,"command":"plan","config":{"mac":"off","socks_port":9050,"trans_port":9040,"dns_port":5353,"exe":"/bin/sh"}}"#;
        assert_eq!(
            decode_request(in_config).unwrap_err().kind,
            ErrorKind::InvalidRequest
        );

        let in_adapter = start_json(r#","adapter":{"name":"eth0","path":"/tmp/x"}"#);
        assert_eq!(
            decode_request(in_adapter.as_bytes()).unwrap_err().kind,
            ErrorKind::InvalidRequest
        );
    }

    #[test]
    fn unknown_command_and_file_or_exec_style_commands_are_refused() {
        for name in ["run", "exec", "shell", "file_write", "sudo"] {
            let json = format!(r#"{{"version":1,"command":"{name}"}}"#);
            assert_eq!(
                decode_request(json.as_bytes()).unwrap_err().kind,
                ErrorKind::InvalidRequest,
                "{name}"
            );
        }
    }

    #[test]
    fn selection_on_non_selection_commands_is_refused() {
        let json = br#"{"version":1,"command":"stop","config":{"mac":"off","socks_port":9050,"trans_port":9040,"dns_port":5353}}"#;
        assert!(decode_request(json).is_err());
        let json = br#"{"version":1,"command":"plan"}"#;
        assert!(decode_request(json).is_err());
    }

    #[test]
    fn unsupported_versions_are_reported_as_versions() {
        for v in ["0", "2", "99999999999"] {
            let json = format!(r#"{{"version":{v},"command":"status","future_field":true}}"#);
            assert_eq!(
                decode_request(json.as_bytes()).unwrap_err().kind,
                ErrorKind::UnsupportedVersion,
                "version {v}"
            );
        }
        let missing = br#"{"command":"status"}"#;
        assert_eq!(
            decode_request(missing).unwrap_err().kind,
            ErrorKind::InvalidRequest
        );
    }

    #[test]
    fn size_limit_is_enforced_before_parsing() {
        let big = vec![b' '; crate::MAX_MESSAGE_BYTES + 1];
        assert_eq!(
            decode_request(&big).unwrap_err().kind,
            ErrorKind::MessageTooLarge
        );
    }

    #[test]
    fn adapter_names_are_data_not_shell_or_paths() {
        assert!(Adapter::new("Wi-Fi").is_ok());
        assert!(Adapter::new("Local Area Connection").is_ok());
        assert!(Adapter::new("").is_err());
        assert!(Adapter::new(" eth0").is_err());
        assert!(Adapter::new("eth0 ").is_err());
        assert!(Adapter::new("eth\n0").is_err());
        assert!(Adapter::new("a".repeat(65)).is_err());
    }

    #[test]
    fn encode_refuses_invalid_constructed_requests() {
        let bad = Request::new(Command::Start(Selection {
            config: Config {
                mac: MacMode::RandomOnApply,
                ..Config::default()
            },
            adapter: None,
        }));
        assert_eq!(
            encode_request(&bad).unwrap_err().kind,
            ErrorKind::InvalidRequest
        );
    }

    #[test]
    fn adapter_deserialization_is_validated() {
        let bad = br#"{"version":1,"command":"plan","config":{"mac":"off","socks_port":9050,"trans_port":9040,"dns_port":5353},"adapter":{"name":"eth\n0"}}"#;
        assert_eq!(
            decode_request(bad).unwrap_err().kind,
            ErrorKind::InvalidRequest
        );
    }
}
