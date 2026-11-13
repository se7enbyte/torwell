//! Command line: protocol mode (default) and the two operational subcommands.
//!
//! ```text
//! torwell-engine                         one request on stdin -> one response on stdout
//! torwell-engine --no-escalate           same, but never re-launch through pkexec (pkexec child)
//! torwell-engine restore-at-boot         root; used by torwell-restore.service
//! torwell-engine boot-protection enable|disable|status
//! ```
//!
//! Exit codes: 0 ok response / success, 1 error response / failed subcommand, 2 usage or not
//! root for a root-only subcommand, 3 stdout could not be written.

use std::io::Write;
use std::path::Path;

use torwell_linux::{BootRestore, SystemRunner};

use crate::boot::{self, BootPaths};
use crate::dispatch::handle_bytes;
use crate::input::read_request;
use crate::linux::LinuxOps;
use crate::ops::Ops;
use crate::privilege::{trusted_self, Escalator, PkexecEscalator, NO_ESCALATE};
use crate::reply::{error_reply, finalize, EXIT_ERROR, EXIT_IO, EXIT_OK, EXIT_USAGE};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootCmd {
    Enable,
    Disable,
    Status,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Protocol { allow_escalate: bool },
    RestoreAtBoot,
    BootProtection(BootCmd),
    Help,
    Version,
}

pub const USAGE: &str = "usage: torwell-engine [--no-escalate]\n       torwell-engine restore-at-boot\n       torwell-engine boot-protection enable|disable|status\n(no arguments: read one JSON request from stdin, write one JSON response to stdout)";

pub fn parse(args: &[String]) -> Result<Mode, String> {
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        [] => Ok(Mode::Protocol {
            allow_escalate: true,
        }),
        [f] if *f == NO_ESCALATE => Ok(Mode::Protocol {
            allow_escalate: false,
        }),
        ["restore-at-boot"] => Ok(Mode::RestoreAtBoot),
        ["boot-protection", "enable"] => Ok(Mode::BootProtection(BootCmd::Enable)),
        ["boot-protection", "disable"] => Ok(Mode::BootProtection(BootCmd::Disable)),
        ["boot-protection", "status"] => Ok(Mode::BootProtection(BootCmd::Status)),
        ["--help"] | ["-h"] => Ok(Mode::Help),
        ["--version"] | ["-V"] => Ok(Mode::Version),
        _ => Err(format!("unrecognized arguments\n{USAGE}")),
    }
}

/// Entry point used by `main`.
pub fn run(args: &[String]) -> i32 {
    match parse(args) {
        Err(m) => {
            eprintln!("torwell-engine: {m}");
            EXIT_USAGE
        }
        Ok(Mode::Help) => {
            println!("{USAGE}");
            EXIT_OK
        }
        Ok(Mode::Version) => {
            println!("torwell-engine {}", env!("CARGO_PKG_VERSION"));
            EXIT_OK
        }
        Ok(Mode::Protocol { allow_escalate }) => {
            let mut ops = LinuxOps::system();
            let esc = PkexecEscalator::system();
            protocol_mode(
                std::io::stdin().lock(),
                &mut std::io::stdout().lock(),
                &mut ops,
                &esc,
                allow_escalate,
            )
        }
        Ok(Mode::RestoreAtBoot) => restore_at_boot(&mut LinuxOps::system()),
        Ok(Mode::BootProtection(cmd)) => boot_protection(cmd),
    }
}

/// One request in, one response out. Public for tests.
pub fn protocol_mode(
    input: impl std::io::Read,
    out: &mut impl Write,
    ops: &mut dyn Ops,
    escalator: &dyn Escalator,
    allow_escalate: bool,
) -> i32 {
    let reply = match read_request(input) {
        Ok(bytes) => handle_bytes(&bytes, ops, escalator, allow_escalate),
        Err(e) => finalize(torwell_protocol::Response::err(e)),
    };
    if out
        .write_all(&reply.stdout)
        .and_then(|_| out.flush())
        .is_err()
    {
        eprintln!("torwell-engine: cannot write the response to stdout");
        return EXIT_IO;
    }
    reply.exit_code
}

/// `restore-at-boot`: root only. Diagnostics go to stderr (the journal).
pub fn restore_at_boot(ops: &mut dyn Ops) -> i32 {
    if ops.euid() != 0 {
        eprintln!("torwell-engine: restore-at-boot must run as root");
        return EXIT_USAGE;
    }
    match ops.restore_at_boot() {
        Ok(BootRestore::NothingToRestore) => {
            eprintln!("torwell-engine: no Torwell state; nothing to restore");
            EXIT_OK
        }
        Ok(BootRestore::AlreadyEnforced) => {
            eprintln!("torwell-engine: owned nftables table already present and verified");
            EXIT_OK
        }
        Ok(BootRestore::Reapplied) => {
            eprintln!("torwell-engine: blocking table re-applied and verified; Tor not started, traffic stays blocked");
            EXIT_OK
        }
        Err(e) => {
            eprintln!("torwell-engine: restore-at-boot failed: {e}");
            EXIT_ERROR
        }
    }
}

fn boot_protection(cmd: BootCmd) -> i32 {
    let paths = BootPaths::default();
    if cmd == BootCmd::Status {
        println!(
            "reboot-protection: {}",
            boot::describe(boot::protection(&paths.unit_dir))
        );
        return EXIT_OK;
    }
    if unsafe { libc::geteuid() } != 0 {
        eprintln!(
            "torwell-engine: boot-protection {} must run as root (try: pkexec /usr/bin/torwell-engine boot-protection {})",
            name(cmd),
            name(cmd)
        );
        return EXIT_USAGE;
    }
    let mut runner = SystemRunner;
    let result = match cmd {
        BootCmd::Enable => trusted_self(Path::new("/proc/self/exe"), 0)
            .map_err(|e| torwell_linux::Error::UnsafePath(e.message))
            .and_then(|engine| boot::enable(&mut runner, &paths, &engine)),
        BootCmd::Disable => boot::disable(&mut runner, &paths),
        BootCmd::Status => unreachable!("handled above"),
    };
    match result {
        Ok(p) => {
            println!("reboot-protection: {}", boot::describe(p));
            EXIT_OK
        }
        Err(e) => {
            eprintln!("torwell-engine: boot-protection {} failed: {e}", name(cmd));
            EXIT_ERROR
        }
    }
}

fn name(cmd: BootCmd) -> &'static str {
    match cmd {
        BootCmd::Enable => "enable",
        BootCmd::Disable => "disable",
        BootCmd::Status => "status",
    }
}

/// Convenience for the Windows-free build: a refusal that is still a valid response.
pub fn unavailable_reply(message: &str) -> crate::reply::Reply {
    error_reply(torwell_protocol::ErrorKind::EngineUnavailable, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::tests::{Fake, SpyEscalator};
    use torwell_protocol::{decode_response, ErrorKind};

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_modes_and_rejects_everything_else() {
        assert_eq!(
            parse(&[]).unwrap(),
            Mode::Protocol {
                allow_escalate: true
            }
        );
        assert_eq!(
            parse(&args(&["--no-escalate"])).unwrap(),
            Mode::Protocol {
                allow_escalate: false
            }
        );
        assert_eq!(
            parse(&args(&["restore-at-boot"])).unwrap(),
            Mode::RestoreAtBoot
        );
        assert_eq!(
            parse(&args(&["boot-protection", "enable"])).unwrap(),
            Mode::BootProtection(BootCmd::Enable)
        );
        for bad in [
            vec!["boot-protection"],
            vec!["boot-protection", "now"],
            vec!["restore-at-boot", "x"],
            vec!["--no-escalate", "stop"],
            vec!["/bin/sh"],
        ] {
            assert!(parse(&args(&bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn protocol_mode_writes_exactly_one_response() {
        let mut fake = Fake::new(1000);
        let esc = SpyEscalator::default();
        let mut out = Vec::new();
        let code = protocol_mode(
            &br#"{"version":1,"command":"status"}"#[..],
            &mut out,
            &mut fake,
            &esc,
            true,
        );
        assert_eq!(code, 0);
        assert!(decode_response(&out).unwrap().result.is_ok());
    }

    #[test]
    fn protocol_mode_oversized_input_is_an_error_response() {
        let mut fake = Fake::new(0);
        let esc = SpyEscalator::default();
        let mut out = Vec::new();
        let code = protocol_mode(std::io::repeat(b'x'), &mut out, &mut fake, &esc, true);
        assert_eq!(code, 1);
        assert_eq!(
            decode_response(&out).unwrap().result.unwrap_err().kind,
            ErrorKind::MessageTooLarge
        );
        assert!(fake.calls.is_empty());
    }

    #[test]
    fn restore_at_boot_needs_root_and_calls_the_backend() {
        let mut fake = Fake::new(1000);
        assert_eq!(restore_at_boot(&mut fake), EXIT_USAGE);
        assert!(fake.calls.is_empty());
        let mut fake = Fake::new(0);
        assert_eq!(restore_at_boot(&mut fake), EXIT_OK);
        assert_eq!(fake.calls, vec!["restore"]);
    }
}
