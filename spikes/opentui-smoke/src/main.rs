use opentui::prelude::*;

fn main() -> opentui::Result<()> {
    let app = App::new(AppOptions::default())?;
    opentui_smoke::build(&app);
    app.run()
}
