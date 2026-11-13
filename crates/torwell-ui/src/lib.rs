//! `torwell-ui`: the unprivileged OpenTUI dashboard.
//!
//! The UI never changes network, DNS, routing or MAC state itself. Menu actions become typed
//! `torwell-protocol` requests that go to the sibling `torwell-engine` process. Until that
//! engine exists, the UI reports "engine unavailable" and never a simulated network state.

pub mod art;
pub mod dashboard;
pub mod engine;
pub mod model;

use std::sync::Arc;

use opentui::prelude::*;

use crate::engine::{ChildEngine, Transport, DEFAULT_TIMEOUT};

/// Runs the dashboard until the user quits with `q` (or Ctrl+C).
pub fn run() -> opentui::Result<()> {
    let host = torwell_core::host::detect_host();
    let transport: Arc<dyn Transport> = Arc::new(ChildEngine::sibling(DEFAULT_TIMEOUT));
    let app = App::new(AppOptions::default().with_title("Torwell"))?;
    let _dashboard = dashboard::build(&app, transport, host);
    app.run()
}
