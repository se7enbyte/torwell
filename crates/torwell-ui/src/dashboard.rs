//! The OpenTUI dashboard. It owns the widgets and forwards menu choices to the engine
//! transport on a worker thread. Replies come back through `AppProxy` and are applied on
//! the UI thread, so the UI never blocks on the engine.

use std::cell::{Cell as StdCell, RefCell};
use std::rc::Rc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use opentui::prelude::*;
use torwell_core::capability::Report;
use torwell_protocol::Request;

use crate::art::{self, Cell as AtCell, LayoutMode};
use crate::engine::{self, Transport};
use crate::model::{Action, EngineReply, Lines, Model, Mood, Next, Tone};

const SUBTITLE: &str = "Tor routing for Linux and Windows. macOS out of scope.";
const HELP: &str = "Up/Down move   Enter run (twice for changes)   1-8 jump   q quit";
const BAR_W: usize = 20;
/// Menu column width in wide mode.
const LEFT_W: f32 = 38.0;

/// Handle to a built dashboard. Clones share the same state.
#[derive(Clone)]
pub struct Dashboard(Rc<Ui>);

struct Ui {
    model: RefCell<Model>,
    transport: Arc<dyn Transport>,
    proxy: AppProxy,
    theme: Theme,
    w: Widgets,
    frame: StdCell<u64>,
    size: StdCell<(u16, u16)>,
    mode: StdCell<LayoutMode>,
    /// Last painted art, to skip redraws when a frame is unchanged (keeps idle CPU near zero).
    painted: RefCell<Vec<Vec<AtCell>>>,
}

struct Widgets {
    strip: Text,
    banner: Vec<Text>,
    subtitle: Text,
    cols: View,
    left: View,
    right: View,
    status_panel: View,
    host_panel: View,
    menu_panel: View,
    log_panel: View,
    connection: Text,
    protection: Text,
    bootstrap: Text,
    mac: Text,
    linux: Text,
    windows: Text,
    messages: Vec<Text>,
    select: Select,
}

fn mix(a: Color, b: Color, t: f32) -> Color {
    let m = |x: u8, y: u8| (f32::from(x) + (f32::from(y) - f32::from(x)) * t).round() as u8;
    Color::rgb(m(a.r, b.r), m(a.g, b.g), m(a.b, b.b))
}

fn panel(app: &App, theme: &Theme, title: &str) -> View {
    View::new(app)
        .column()
        .border(BorderStyle::Rounded)
        .border_color(theme.border)
        .title(format!(" {title} "))
        .title_color(theme.accent)
        .padding_x(1)
}

/// Builds the dashboard into `app`, with `host` as the presence-only capability report.
/// Nothing reaches the engine until the user chooses an action.
pub fn build(app: &App, transport: Arc<dyn Transport>, host: Report) -> Dashboard {
    let theme = app.theme();
    let label = |s: &str| Text::new(app, s);
    let w = Widgets {
        strip: label("").truncate(true),
        banner: (0..=art::LOGO_H)
            .map(|_| label("").align(Alignment::Center))
            .collect(),
        subtitle: label("").fg(theme.muted),
        cols: View::new(app).grow(1.0),
        left: View::new(app).column(),
        right: View::new(app).column().grow(1.0),
        status_panel: panel(app, &theme, "Status"),
        host_panel: panel(app, &theme, "Host (presence only)"),
        menu_panel: panel(app, &theme, "Actions"),
        log_panel: panel(app, &theme, "Log"),
        connection: label("").truncate(true),
        protection: label("").truncate(true),
        bootstrap: label("").truncate(true),
        mac: label("").truncate(true),
        linux: label("").fg(theme.muted),
        windows: label("").fg(theme.muted),
        messages: (0..crate::model::MESSAGE_LINES)
            .map(|_| label(""))
            .collect(),
        select: Select::new(app)
            .options(
                Action::ALL
                    .iter()
                    .enumerate()
                    .map(|(i, a)| SelectOption::new(format!("{} {}", i + 1, a.label()), "")),
            )
            .show_description(false)
            .grow(1.0),
    };
    let _ = (
        w.status_panel
            .add(&w.connection)
            .add(&w.protection)
            .add(&w.bootstrap)
            .add(&w.mac),
        w.host_panel.add(&w.linux).add(&w.windows),
        w.menu_panel.add(&w.select),
    );
    for message in &w.messages {
        w.log_panel.add(message);
    }
    w.left.add(&w.menu_panel);
    w.right.add(&w.host_panel).add(&w.log_panel);
    w.cols.add(&w.left).add(&w.right);
    let page = View::new(app).column().grow(1.0).padding_x(1);
    page.add(&w.strip);
    for row in &w.banner {
        page.add(row);
    }
    page.add(&w.subtitle).add(&w.status_panel).add(&w.cols);
    page.add(&label(HELP).fg(theme.muted).truncate(true));
    app.root().add(&page);

    let (cols, rows) = app.size();
    let ui = Rc::new(Ui {
        model: RefCell::new(Model::new(host)),
        transport,
        proxy: app.proxy(),
        theme,
        w,
        frame: StdCell::new(0),
        size: StdCell::new((cols, rows)),
        mode: StdCell::new(art::layout_for(cols, rows)),
        painted: RefCell::new(Vec::new()),
    });
    ui.apply_layout();

    let chooser = Rc::clone(&ui);
    ui.w.select
        .on_select(move |_cx, index, _option| chooser.activate(index));
    let replies = Rc::clone(&ui);
    app.on_message(move |_cx, reply: &EngineReply| {
        replies.model.borrow_mut().apply(reply);
        replies.refresh();
    });
    let keys = Rc::clone(&ui);
    app.on_key(move |cx, key| {
        if key.matches("q") {
            cx.quit();
            return;
        }
        for i in 0..Action::ALL.len() {
            if key.matches(format!("{}", i + 1).as_str()) {
                keys.w.select.select(i);
                keys.activate(i);
            }
        }
    });
    let resized = Rc::clone(&ui);
    app.on_resize(move |_cx, cols, rows| {
        resized.size.set((cols, rows));
        resized.mode.set(art::layout_for(cols, rows));
        resized.apply_layout();
        resized.refresh();
    });
    // Animation tick on the UI thread: never touches the engine worker, ~10 fps, and skips
    // painting when a frame is identical to the previous one.
    let ticking = Rc::downgrade(&ui);
    app.set_interval(Duration::from_millis(art::TICK_MS), move |_cx| {
        if let Some(ui) = ticking.upgrade() {
            ui.frame.set(ui.frame.get().wrapping_add(1));
            ui.paint_art();
        }
    });
    ui.w.select.focus();
    ui.refresh();
    Dashboard(ui)
}

impl Dashboard {
    /// The text of the current status lines. Exposed for tests and diagnostics.
    pub fn lines(&self) -> Lines {
        self.0.model.borrow().lines()
    }

    /// The current layout; `Compact` hides the big art.
    pub fn layout(&self) -> LayoutMode {
        self.0.mode.get()
    }

    /// The animation mood derived from real engine evidence.
    pub fn mood(&self) -> Mood {
        self.0.model.borrow().mood()
    }

    /// Whether a request is waiting for the engine.
    pub fn is_busy(&self) -> bool {
        self.0.model.borrow().busy.is_some()
    }
}

impl Ui {
    fn activate(&self, index: usize) {
        let Some(&action) = Action::ALL.get(index) else {
            return;
        };
        let next = self.model.borrow_mut().activate(action);
        if let Next::Send(action, command) = next {
            self.spawn_exchange(action, Request::new(command));
        }
        self.refresh();
    }

    fn spawn_exchange(&self, action: Action, request: Request) {
        let transport = Arc::clone(&self.transport);
        let proxy = self.proxy.clone();
        let spawned = thread::Builder::new()
            .name("torwell-engine-exchange".into())
            .spawn(move || {
                let (result, stderr) = engine::send(transport.as_ref(), &request);
                // A closed app drops the reply; nothing else is affected.
                let _ = proxy.send(EngineReply {
                    action,
                    result,
                    stderr,
                });
            });
        if let Err(error) = spawned {
            let reply = EngineReply {
                action,
                result: Err(torwell_protocol::ProtocolError::new(
                    torwell_protocol::ErrorKind::Internal,
                    format!("cannot start an engine worker: {error}"),
                )),
                stderr: String::new(),
            };
            self.model.borrow_mut().apply(&reply);
        }
    }

    fn color(&self, tone: Tone) -> Color {
        match tone {
            Tone::Good => self.theme.success,
            Tone::Busy => self.theme.accent,
            Tone::Warn => self.theme.warning,
            Tone::Bad => self.theme.error,
            Tone::Muted => self.theme.muted,
        }
    }

    fn shade(&self, tone: Tone, level: u8) -> Color {
        const T: [f32; 4] = [0.22, 0.45, 0.75, 1.0];
        mix(
            self.theme.background,
            self.color(tone),
            T[usize::from(level.min(3))],
        )
    }

    fn spans(&self, cells: &[AtCell]) -> Vec<Span<'static>> {
        let mut out: Vec<Span<'static>> = Vec::new();
        let mut i = 0;
        while i < cells.len() {
            let key = (cells[i].tone, cells[i].level);
            let mut text = String::new();
            while i < cells.len() && (cells[i].tone, cells[i].level) == key {
                text.push(cells[i].ch);
                i += 1;
            }
            let span = text.fg(self.shade(key.0, key.1));
            out.push(if key.1 == 3 { span.bold() } else { span });
        }
        out
    }

    /// Shows/hides the big art and re-flows the panels for the current size.
    fn apply_layout(&self) {
        let w = &self.w;
        let wide = self.mode.get() == LayoutMode::Wide;
        let sides = if wide { Sides::ALL } else { Sides::TOP };
        let rows = |n: f32| if wide { Length::Auto } else { Length::Cells(n) };
        w.strip.visible(!wide);
        for row in &w.banner {
            row.visible(wide);
        }
        w.subtitle.align(if wide {
            Alignment::Center
        } else {
            Alignment::Left
        });
        if wide {
            w.cols.row();
            w.left.width(Length::Cells(LEFT_W)).grow(0.0);
            w.right.grow(1.0);
            w.menu_panel.grow(1.0).height(Length::Auto);
            w.host_panel.height(Length::Cells(6.0));
            w.log_panel.grow(1.0).height(Length::Auto);
        } else {
            w.cols.column();
            w.left.width(Length::Auto).grow(0.0);
            w.right.grow(0.0);
            w.menu_panel.grow(0.0).height(Length::Cells(9.0));
            w.host_panel.height(Length::Cells(3.0));
            w.log_panel.grow(0.0).height(Length::Cells(4.0));
        }
        w.status_panel.height(rows(5.0));
        for p in [&w.status_panel, &w.host_panel, &w.menu_panel, &w.log_panel] {
            p.border_sides(sides);
        }
        for m in &w.messages {
            m.truncate(!wide);
        }
        w.linux.truncate(!wide);
        w.windows.truncate(!wide);
        self.painted.borrow_mut().clear();
    }

    /// Repaints the animated art for the current frame. Skips unchanged frames.
    fn paint_art(&self) {
        let (mood, busy) = {
            let m = self.model.borrow();
            (m.mood(), m.busy.is_some())
        };
        let frame = self.frame.get();
        let (cols, _) = self.size.get();
        let width = usize::from(cols).saturating_sub(2);
        let rows: Vec<Vec<AtCell>> = if self.mode.get() == LayoutMode::Wide {
            art::banner(frame, mood, width)
        } else {
            vec![art::strip(frame, mood, width)]
        };
        let title = if busy {
            format!(" Log  {} waiting for engine ", art::spinner(frame))
        } else {
            " Log ".to_string()
        };
        let mut painted = self.painted.borrow_mut();
        // The spinner is part of the cache key via a trailing pseudo-row.
        let mut keyed = rows.clone();
        keyed.push(
            title
                .chars()
                .map(|ch| AtCell {
                    ch,
                    tone: Tone::Muted,
                    level: 0,
                })
                .collect(),
        );
        if *painted == keyed {
            return;
        }
        if self.mode.get() == LayoutMode::Wide {
            for (text, row) in self.w.banner.iter().zip(&rows) {
                text.set_text(self.spans(row));
            }
        } else if let Some(row) = rows.first() {
            self.w.strip.set_text(self.spans(row));
        }
        self.w.log_panel.title(title);
        *painted = keyed;
    }

    fn refresh(&self) {
        let lines = self.model.borrow().lines();
        self.paint(&lines);
        self.paint_art();
    }

    fn badge(&self, text: &str, tone: Tone) -> Span<'static> {
        format!(" {text:^9} ")
            .fg(self.theme.background)
            .bg(self.color(tone))
            .bold()
    }

    fn paint(&self, lines: &Lines) {
        let w = &self.w;
        let mood = self.model.borrow().mood();
        let value =
            |label: &str, text: &str, tone: Tone, badge: Span<'static>| -> Vec<Span<'static>> {
                vec![
                    badge,
                    format!(" {label:<12}").fg(self.theme.muted),
                    text.to_string().fg(self.color(tone)),
                ]
            };
        w.connection.set_text(value(
            "Connection",
            &lines.connection.0,
            lines.connection.1,
            self.badge(mood_badge(mood), art::mood_tone(mood)),
        ));
        w.protection.set_text(value(
            "Protection",
            &lines.protection.0,
            lines.protection.1,
            self.badge(tone_badge(lines.protection.1), lines.protection.1),
        ));
        let mut boot: Vec<Span<'static>> = vec![
            format!("{:11} {:<12}", "", "Bootstrap").fg(self.theme.muted),
            lines.bootstrap.clone().into_span(),
        ];
        if let Mood::Starting(Some(p)) = mood {
            let filled = usize::from(p) * BAR_W / 100;
            boot.push("  ".into_span());
            boot.push("█".repeat(filled).fg(self.color(Tone::Busy)));
            boot.push("░".repeat(BAR_W - filled).fg(self.theme.muted));
        }
        w.bootstrap.set_text(boot);
        w.mac.set_text(vec![
            format!("{:11} {:<12}", "", "MAC mode").fg(self.theme.muted),
            lines.mac.clone().into_span(),
        ]);
        w.linux.set_text(lines.linux.clone());
        w.windows.set_text(lines.windows.clone());
        w.subtitle.set_text(if self.mode.get() == LayoutMode::Wide {
            format!("Torwell · {SUBTITLE}")
        } else {
            SUBTITLE.to_string()
        });
        for (i, text) in w.messages.iter().enumerate() {
            let line = lines.messages.get(i).cloned().unwrap_or_default();
            text.set_text(line);
        }
    }
}

fn mood_badge(mood: Mood) -> &'static str {
    match mood {
        Mood::Unknown => "UNKNOWN",
        Mood::Idle => "IDLE",
        Mood::Starting(_) => "STARTING",
        Mood::Connected => "VERIFIED",
        Mood::Blocked => "BLOCKED",
        Mood::Recovery => "RECOVER",
        Mood::Unsupported => "N/A",
    }
}

fn tone_badge(tone: Tone) -> &'static str {
    match tone {
        Tone::Good => "ACTIVE",
        Tone::Bad => "FAILED",
        Tone::Warn => "UNKNOWN",
        Tone::Busy => "WORKING",
        Tone::Muted => "OFF",
    }
}
