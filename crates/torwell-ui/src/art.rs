//! ASCII art and its animation. Everything here is a pure function of `(frame, mood, size)`
//! so frames are deterministic and unit-testable; no OpenTUI types are involved.
//!
//! The animation only reflects real state ([`Mood`]). The "steady flow" look (green tone,
//! all nodes lit, travelling packet) exists solely for [`Mood::Connected`], which the model
//! derives from verified engine evidence. Every other mood uses a different tone and motion.

use crate::model::{Mood, Tone};

/// Time between animation frames: about 10 fps.
pub const TICK_MS: u64 = 100;

/// Layout decision from the terminal size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutMode {
    /// 80x24 and similar: one-line animated strip, stacked panels, no big art.
    Compact,
    /// Big logo + onion + relay animation, two columns.
    Wide,
}

pub const WIDE_MIN_COLS: u16 = 96;
pub const WIDE_MIN_ROWS: u16 = 28;

/// The big art only shows when it fits with every panel still readable.
pub fn layout_for(cols: u16, rows: u16) -> LayoutMode {
    if cols >= WIDE_MIN_COLS && rows >= WIDE_MIN_ROWS {
        LayoutMode::Wide
    } else {
        LayoutMode::Compact
    }
}

/// One character cell of art: glyph, semantic tone and brightness `0..=3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cell {
    pub ch: char,
    pub tone: Tone,
    pub level: u8,
}

impl Cell {
    const fn blank() -> Self {
        Self {
            ch: ' ',
            tone: Tone::Muted,
            level: 0,
        }
    }
}

/// The tone the whole animation uses for a mood. `Tone::Good` only for `Connected`.
pub fn mood_tone(mood: Mood) -> Tone {
    match mood {
        Mood::Unknown | Mood::Idle => Tone::Muted,
        Mood::Starting(_) => Tone::Busy,
        Mood::Connected => Tone::Good,
        Mood::Blocked => Tone::Bad,
        Mood::Recovery | Mood::Unsupported => Tone::Warn,
    }
}

/// Braille spinner for "waiting for the engine".
pub fn spinner(frame: u64) -> char {
    const S: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    S[(frame % 10) as usize]
}

/// Triangle wave `0,1,2,1` with the given period in frames.
fn pulse(frame: u64, period: u64) -> u8 {
    let phase = (frame % period) * 4 / period;
    [0u8, 1, 2, 1][phase as usize]
}

/// Brightness of a travelling highlight: 3 at the head, fading over 4 cells behind it.
fn comet(pos: i64, head: i64) -> u8 {
    match head - pos {
        0 => 3,
        1..=2 => 2,
        3..=4 => 1,
        _ => 0,
    }
}

const GLYPH_H: usize = 6;
/// "ANSI Shadow" figlet glyphs. Widths differ per letter; every row of one glyph has the
/// same width (counted in chars). Glyphs carry their own spacing, so letters abut.
const FONT: [(char, [&str; GLYPH_H]); 6] = [
    (
        'T',
        [
            "████████╗",
            "╚══██╔══╝",
            "   ██║   ",
            "   ██║   ",
            "   ██║   ",
            "   ╚═╝   ",
        ],
    ),
    (
        'O',
        [
            " ██████╗ ",
            "██╔═══██╗",
            "██║   ██║",
            "██║   ██║",
            "╚██████╔╝",
            " ╚═════╝ ",
        ],
    ),
    (
        'R',
        [
            "██████╗ ",
            "██╔══██╗",
            "██████╔╝",
            "██╔══██╗",
            "██║  ██║",
            "╚═╝  ╚═╝",
        ],
    ),
    (
        'W',
        [
            "██╗    ██╗",
            "██║    ██║",
            "██║ █╗ ██║",
            "██║███╗██║",
            "╚███╔███╔╝",
            " ╚══╝╚══╝ ",
        ],
    ),
    (
        'E',
        [
            "███████╗",
            "██╔════╝",
            "█████╗  ",
            "██╔══╝  ",
            "███████╗",
            "╚══════╝",
        ],
    ),
    (
        'L',
        [
            "██╗     ",
            "██║     ",
            "██║     ",
            "██║     ",
            "███████╗",
            "╚══════╝",
        ],
    ),
];

/// Width of the block logo "TORWELL".
pub const LOGO_W: usize = 9 + 9 + 8 + 10 + 8 + 8 + 8; // T O R W E L L
/// Height of logo and onion.
pub const LOGO_H: usize = GLYPH_H;

// The wide layout keeps the onion (ONION_W) beside the logo, so it must stay narrow.
const _: () = assert!(LOGO_W <= 60);

fn glyph(c: char) -> &'static [&'static str; GLYPH_H] {
    &FONT
        .iter()
        .find(|(l, _)| *l == c)
        .expect("letter in font")
        .1
}

/// The block-letter "TORWELL" logo, shimmering according to `mood`.
pub fn logo(frame: u64, mood: Mood) -> Vec<Vec<Cell>> {
    let tone = mood_tone(mood);
    let f = frame as i64;
    let span = LOGO_W as i64 + 10;
    (0..GLYPH_H)
        .map(|y| {
            let mut row = Vec::with_capacity(LOGO_W);
            for c in "TORWELL".chars() {
                for ch in glyph(c)[y].chars() {
                    let x = row.len() as i64;
                    let level = if ch == ' ' {
                        0
                    } else {
                        logo_level(mood, f, span, x, y as i64)
                    };
                    row.push(Cell {
                        ch,
                        tone,
                        level: if ch == ' ' { 0 } else { level.max(1) },
                    });
                }
            }
            row
        })
        .collect()
}

fn logo_level(mood: Mood, f: i64, span: i64, x: i64, y: i64) -> u8 {
    let diag = x + 2 * y;
    match mood {
        // Dim, slow, uniform pulse: nothing is known to be happening.
        Mood::Unknown | Mood::Idle => pulse(f as u64, 40),
        // Progress-driven: letters fill left to right with the reported percentage.
        Mood::Starting(Some(p)) => {
            let filled = x * 100 < i64::from(p) * LOGO_W as i64;
            if filled {
                2u8.max(comet(diag, (f * 3) % span))
            } else {
                0
            }
        }
        Mood::Starting(None) => comet(diag, (f * 3) % span).max(1),
        // Steady flow: constant brightness with a gentle band sweeping through.
        Mood::Connected => 2u8.max(comet(diag, (f * 2) % span)),
        Mood::Blocked => {
            if (f / 5) % 2 == 0 {
                2
            } else {
                1
            }
        }
        Mood::Recovery => {
            if (f / 4) % 2 == 0 {
                3
            } else {
                1
            }
        }
        Mood::Unsupported => 1,
    }
}

const ONION_W: usize = 11;
const ONION: [(&str, &str); 5] = [
    ("  .-'''-.  ", "  0000000  "),
    (" / .---. \\ ", " 0 11111 0 "),
    ("| | (o) | |", "0 1 222 1 0"),
    (" \\ '---' / ", " 0 11111 0 "),
    ("  '-...-'  ", "  0000000  "),
];

/// Onion art whose three layers light up according to `mood`.
pub fn onion(frame: u64, mood: Mood) -> Vec<Vec<Cell>> {
    let tone = mood_tone(mood);
    ONION
        .iter()
        .map(|(chars, layers)| {
            chars
                .chars()
                .zip(layers.chars())
                .map(|(ch, layer)| match layer.to_digit(10) {
                    Some(l) if ch != ' ' => Cell {
                        ch,
                        tone,
                        level: onion_level(mood, frame, l as u64),
                    },
                    _ => Cell::blank(),
                })
                .collect()
        })
        .collect()
}

fn onion_level(mood: Mood, frame: u64, layer: u64) -> u8 {
    let spin = (frame / 4) % 3;
    match mood {
        Mood::Unknown | Mood::Idle => pulse(frame, 40),
        // Layers light outer-to-inner as bootstrap advances; a highlight orbits the lit ones.
        Mood::Starting(Some(p)) => {
            let lit = if p < 34 {
                1
            } else if p < 67 {
                2
            } else {
                3
            };
            if layer >= lit {
                0
            } else if layer == spin % lit {
                3
            } else {
                2
            }
        }
        Mood::Starting(None) => {
            if layer == spin {
                3
            } else {
                1
            }
        }
        // Steady: every layer lit, highlight rotating inward.
        Mood::Connected => {
            if layer == spin {
                3
            } else {
                2
            }
        }
        Mood::Blocked => {
            if (frame / 5).is_multiple_of(2) {
                2
            } else {
                1
            }
        }
        Mood::Recovery => {
            if (frame / 4).is_multiple_of(2) {
                3
            } else {
                1
            }
        }
        Mood::Unsupported => 1,
    }
}

/// A relay path `●──●──●──●──●` of `width` cells. A packet travels it only when the state
/// justifies it: progress-driven while starting, steady when verified connected; a blocked
/// path stops at an `X`.
pub fn relay_line(frame: u64, mood: Mood, width: usize) -> Vec<Cell> {
    let width = width.max(10);
    let tone = mood_tone(mood);
    let nodes: Vec<usize> = (0..5).map(|i| i * (width - 1) / 4).collect();
    let f = frame as i64;
    // Packet head position, if any.
    let head: Option<i64> = match mood {
        Mood::Starting(Some(p)) => Some((i64::from(p) * (width as i64 - 1)) / 100),
        Mood::Starting(None) => Some((f * 2) % (width as i64 + 6)),
        Mood::Connected => Some(f % (width as i64 + 6)),
        _ => None,
    };
    let blocked_at = nodes[3];
    (0..width)
        .map(|x| {
            let is_node = nodes.contains(&x);
            let xi = x as i64;
            let (ch, level) = match mood {
                Mood::Unknown | Mood::Idle => (if is_node { '○' } else { '─' }, pulse(frame, 40)),
                Mood::Unsupported => (if is_node { '○' } else { '·' }, 1),
                Mood::Recovery => (
                    if is_node { '○' } else { '┄' },
                    if (f / 4) % 2 == 0 { 3 } else { 1 },
                ),
                Mood::Blocked => {
                    let blink = if (f / 5) % 2 == 0 { 3 } else { 2 };
                    if x == blocked_at {
                        ('X', 3)
                    } else if x > blocked_at {
                        (' ', 0)
                    } else {
                        (if is_node { '●' } else { '─' }, blink.min(2))
                    }
                }
                Mood::Starting(Some(_)) | Mood::Starting(None) | Mood::Connected => {
                    let head = head.expect("moving moods have a head");
                    let trail = comet(xi, head);
                    // Starting(Some): cells already passed stay lit; the rest are dim.
                    let passed = matches!(mood, Mood::Starting(Some(_))) && xi <= head;
                    let lit = mood == Mood::Connected || passed || trail > 0;
                    let level = if trail == 3 {
                        3
                    } else if mood == Mood::Connected {
                        trail.max(1)
                    } else if passed {
                        2.max(trail)
                    } else {
                        trail
                    };
                    let ch = if is_node {
                        if lit {
                            '●'
                        } else {
                            '○'
                        }
                    } else if trail == 3 {
                        '●'
                    } else if lit && level >= 2 {
                        '━'
                    } else {
                        '─'
                    };
                    (ch, level)
                }
            };
            Cell { ch, tone, level }
        })
        .collect()
}

/// The full wide-mode banner: onion and logo stacked over `LOGO_H` rows, relay path on the
/// last row, each row centered in `width`. Always `LOGO_H + 1` rows.
pub fn banner(frame: u64, mood: Mood, width: usize) -> Vec<Vec<Cell>> {
    let onion = onion(frame, mood);
    let logo = logo(frame, mood);
    let inner = ONION_W + 4 + LOGO_W;
    let pad = width.saturating_sub(inner) / 2;
    let mut rows: Vec<Vec<Cell>> = (0..LOGO_H)
        .map(|y| {
            let mut row = vec![Cell::blank(); pad];
            if let Some(line) = onion.get(y) {
                row.extend(line.iter().copied());
            } else {
                row.extend(std::iter::repeat_n(Cell::blank(), ONION_W));
            }
            row.extend(std::iter::repeat_n(Cell::blank(), 4));
            row.extend(logo[y].iter().copied());
            row
        })
        .collect();
    let mut path = vec![Cell::blank(); pad];
    path.extend(relay_line(frame, mood, inner));
    rows.push(path);
    rows
}

/// Compact one-line strip: the word "Torwell" and a short relay path. At most `width` cells.
pub fn strip(frame: u64, mood: Mood, width: usize) -> Vec<Cell> {
    let tone = mood_tone(mood);
    let mut cells: Vec<Cell> = "Torwell "
        .chars()
        .map(|ch| Cell {
            ch,
            tone,
            level: if ch == ' ' { 0 } else { 3 },
        })
        .collect();
    let room = width.saturating_sub(cells.len()).min(48);
    if room >= 10 {
        cells.extend(relay_line(frame, mood, room));
    }
    cells.truncate(width);
    cells
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOODS: [Mood; 9] = [
        Mood::Unknown,
        Mood::Idle,
        Mood::Starting(None),
        Mood::Starting(Some(0)),
        Mood::Starting(Some(55)),
        Mood::Starting(Some(100)),
        Mood::Blocked,
        Mood::Recovery,
        Mood::Unsupported,
    ];

    #[test]
    fn frames_are_deterministic() {
        for mood in MOODS.iter().copied().chain([Mood::Connected]) {
            for f in [0u64, 1, 7, 99, 12345] {
                assert_eq!(banner(f, mood, 100), banner(f, mood, 100));
                assert_eq!(strip(f, mood, 78), strip(f, mood, 78));
            }
        }
    }

    #[test]
    fn banner_has_fixed_shape() {
        for mood in MOODS {
            let b = banner(3, mood, 100);
            assert_eq!(b.len(), LOGO_H + 1);
            assert!(b.iter().all(|r| r.len() <= 100));
        }
        let text: String = logo(0, Mood::Idle)[0].iter().map(|c| c.ch).collect();
        assert!(text.starts_with("███████"));
        let rows = logo(0, Mood::Idle);
        assert!(rows.iter().all(|r| r.len() == LOGO_W));
    }

    #[test]
    fn glyph_rows_are_even_and_the_logo_fits() {
        for (letter, rows) in FONT {
            let w = rows[0].chars().count();
            for row in rows {
                assert_eq!(row.chars().count(), w, "{letter} glyph row {row:?}");
            }
        }
        let text: String = logo(0, Mood::Idle)
            .iter()
            .map(|r| r.iter().map(|c| c.ch).collect::<String>() + "\n")
            .collect();
        println!("{text}");
        let widest = logo(0, Mood::Idle)
            .iter()
            .map(|row| row.len())
            .max()
            .expect("logo has rows");
        assert_eq!(widest, LOGO_W);
        assert!(widest <= 60, "logo is {widest} columns");
    }

    #[test]
    fn connected_style_never_appears_without_connected_mood() {
        for mood in MOODS {
            for f in 0..200 {
                let cells = banner(f, mood, 100)
                    .into_iter()
                    .flatten()
                    .chain(strip(f, mood, 78));
                for c in cells {
                    assert_ne!(
                        c.tone,
                        Tone::Good,
                        "{mood:?} frame {f} used the connected tone"
                    );
                }
            }
        }
        assert_eq!(mood_tone(Mood::Connected), Tone::Good);
    }

    #[test]
    fn idle_is_dim_and_starting_is_progress_driven() {
        for f in 0..80 {
            assert!(logo(f, Mood::Unknown)
                .iter()
                .flatten()
                .all(|c| c.level <= 2));
        }
        let lit = |p| {
            relay_line(0, Mood::Starting(Some(p)), 40)
                .iter()
                .filter(|c| c.level >= 2)
                .count()
        };
        assert!(lit(10) < lit(50) && lit(50) < lit(90));
        // Progress frames do not depend on time: same percentage, different frame, same packet head.
        let head = |f| {
            relay_line(f, Mood::Starting(Some(50)), 40)
                .iter()
                .position(|c| c.level == 3)
        };
        assert_eq!(head(0), head(33));
    }

    #[test]
    fn blocked_path_stops_at_a_gate() {
        let line: String = relay_line(0, Mood::Blocked, 40)
            .iter()
            .map(|c| c.ch)
            .collect();
        assert!(line.contains('X'));
        assert!(line.trim_end().ends_with('X'));
    }

    #[test]
    fn layout_hides_art_when_small() {
        assert_eq!(layout_for(80, 24), LayoutMode::Compact);
        assert_eq!(layout_for(100, 24), LayoutMode::Compact);
        assert_eq!(layout_for(95, 40), LayoutMode::Compact);
        assert_eq!(layout_for(100, 30), LayoutMode::Wide);
    }
}
