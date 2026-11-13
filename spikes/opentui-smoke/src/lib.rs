//! Minimal Torwell frontend proof: header, state line, action list. Presentation only; no network/system effects.
use opentui::prelude::*;

pub const ACTIONS: [&str; 3] = ["Inspect (read-only)", "Show plan", "Quit"];

/// Builds the UI into `app`; returns the status text handle.
pub fn build(app: &App) -> Text {
    let theme = app.theme();
    let status = Text::new(app, "State: Disconnected (nothing applied)").fg(theme.muted);
    let list = Select::new(app).options(ACTIONS).grow(1.0);
    app.root().add(
        &View::new(app)
            .border(BorderStyle::Rounded)
            .title(" Torwell ")
            .padding(1)
            .grow(1.0)
            .child(&list),
    ).add(&status);
    let s = status.clone();
    list.on_select(move |cx, index, option| {
        if index == 2 {
            cx.quit();
        } else {
            s.set_text(format!("Selected: {}", option.name));
        }
    });
    app.on_key(|cx, key| {
        if key.matches("q") {
            cx.quit();
        }
    });
    list.focus();
    status
}
