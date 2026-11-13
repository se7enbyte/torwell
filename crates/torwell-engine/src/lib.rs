//! `torwell-engine`: the process between `torwell-ui` and the platform backend.
//!
//! One JSON request on stdin, one JSON response on stdout, diagnostics on stderr (see
//! `docs/UI.md`, `docs/ENGINE.md`). Read-only commands run unprivileged; mutating commands
//! re-launch the same installed engine through pkexec. Nothing here claims `connected` or
//! `blocked` without evidence from `torwell-linux`.

pub mod input;
pub mod reply;

#[cfg(unix)]
pub mod boot;
#[cfg(unix)]
pub mod cli;
#[cfg(unix)]
pub mod dispatch;
#[cfg(unix)]
pub mod linux;
#[cfg(unix)]
pub mod map;
#[cfg(unix)]
pub mod ops;
#[cfg(unix)]
pub mod privilege;

/// Windows dispatch is out of scope: every request gets an explicit error, never a
/// simulated state.
#[cfg(not(unix))]
pub mod unsupported {
    use std::io::Write;

    use torwell_protocol::{decode_request, ErrorKind, Response};

    use crate::input::read_request;
    use crate::reply::{error, finalize};

    pub fn run() -> i32 {
        let response = match read_request(std::io::stdin().lock()).and_then(|b| decode_request(&b))
        {
            Err(e) => Response::err(e),
            Ok(_) => Response::err(error(
                ErrorKind::EngineUnavailable,
                "engine unavailable: the Windows engine dispatch is not implemented yet",
            )),
        };
        let reply = finalize(response);
        let mut out = std::io::stdout().lock();
        if out
            .write_all(&reply.stdout)
            .and_then(|_| out.flush())
            .is_err()
        {
            return crate::reply::EXIT_IO;
        }
        reply.exit_code
    }
}
