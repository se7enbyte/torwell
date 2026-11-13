use opentui::testing::TestApp;

#[test]
fn renders_and_reacts() {
    let app = TestApp::new(48, 16);
    opentui_smoke::build(app.app());
    let first = app.render();
    let text = app.text();
    println!("{text}");
    assert!(text.contains("Torwell"), "title missing");
    assert!(text.contains("State: Disconnected (nothing applied)"));
    for a in opentui_smoke::ACTIONS { assert!(text.contains(a), "missing {a}"); }
    let _ = first;
    app.press("down");
    app.press("enter");
    app.render();
    assert!(app.text().contains("Selected: Show plan"), "{}", app.text());
}
