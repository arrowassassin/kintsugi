//! The launch splash — an animated wordmark that "fills with gold", the kintsugi
//! metaphor: a break repaired with molten gold becomes more beautiful than new.
//!
//! The animation is honest about the terminal medium. With color, the block
//! letters fill left-to-right with kintsugi gold; without color (or `NO_COLOR`),
//! the same sweep is shown by swapping the unfilled cells' glyph (`░` → `█`), so
//! the motion never depends on color alone. It is purely decorative and any key
//! skips it.

use ratatui::prelude::*;
use ratatui::widgets::Paragraph;

/// Total animation frames before the splash hands off to the app.
pub const FRAMES: usize = 30;
/// Frames over which the gold "fills" the wordmark (then it holds, shimmering).
const FILL_FRAMES: usize = 20;

/// Kintsugi gold, and the muted seam it flows into.
const GOLD: Color = Color::Rgb(212, 175, 55);
const SEAM: Color = Color::Rgb(90, 90, 90);

const TAGLINE: &str = "a local-first safety layer for AI coding agents";

/// 5-row block glyphs for K I N T S U G I, assembled at render time.
const GLYPHS: &[[&str; 5]] = &[
    ["█  █", "█ █ ", "██  ", "█ █ ", "█  █"],      // K
    ["███", " █ ", " █ ", " █ ", "███"],           // I
    ["█  █", "██ █", "█ ██", "█  █", "█  █"],      // N
    ["█████", "  █  ", "  █  ", "  █  ", "  █  "], // T
    [" ███", "█   ", " ██ ", "   █", "███ "],      // S
    ["█  █", "█  █", "█  █", "█  █", " ██ "],      // U
    [" ███", "█   ", "█ ██", "█  █", " ███"],      // G
    ["███", " █ ", " █ ", " █ ", "███"],           // I
];

/// Assemble the eight glyphs into five rows separated by a single space column.
fn wordmark_rows() -> [String; 5] {
    let mut rows: [String; 5] = Default::default();
    for (gi, g) in GLYPHS.iter().enumerate() {
        for (r, row) in rows.iter_mut().enumerate() {
            if gi > 0 {
                row.push(' ');
            }
            row.push_str(g[r]);
        }
    }
    rows
}

/// Render the splash at animation `frame` into `area`. `color` gates styling.
pub fn render(f: &mut Frame, area: Rect, frame: usize, color: bool) {
    let rows = wordmark_rows();
    let width = rows[0].chars().count();

    // Too narrow for the block banner: degrade to a simple centered wordmark.
    if (area.width as usize) < width + 2 {
        let lines = vec![
            Line::from(""),
            Line::from(Span::styled(
                "KINTSUGI",
                style_if(color, Style::default().fg(GOLD)).add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(TAGLINE, dim_if(color))),
        ];
        f.render_widget(
            Paragraph::new(lines).alignment(Alignment::Center),
            centered(area, 3),
        );
        return;
    }

    // How far the gold has flowed across the wordmark (in columns).
    let fill = (frame.min(FILL_FRAMES) as f32 / FILL_FRAMES as f32 * width as f32).round() as usize;
    // A one-cell bright "leading edge" shimmer once filled.
    let done = frame >= FILL_FRAMES;

    let mut lines: Vec<Line> = Vec::new();
    // The brand mark — a tile rejoined by a golden seam — above the wordmark,
    // when there's vertical room. Mirrors the web/README logo in the terminal.
    if area.height >= 16 {
        for ml in mark_lines(color) {
            lines.push(ml);
        }
        lines.push(Line::from(""));
    }
    for row in &rows {
        let mut spans = Vec::new();
        for (col, ch) in row.chars().enumerate() {
            if ch == '█' {
                let filled = col < fill;
                let glyph = if filled || done { "█" } else { "░" };
                let style = if !color {
                    Style::default()
                } else if filled || done {
                    Style::default().fg(GOLD).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(SEAM)
                };
                spans.push(Span::styled(glyph.to_string(), style));
            } else {
                spans.push(Span::raw(" "));
            }
        }
        lines.push(Line::from(spans));
    }

    // Tagline fades in once the gold is past halfway; the hint comes at the end.
    lines.push(Line::from(""));
    if fill * 2 >= width {
        lines.push(Line::from(Span::styled(TAGLINE, dim_if(color))));
    } else {
        lines.push(Line::from(""));
    }
    lines.push(Line::from(""));
    if done {
        lines.push(Line::from(Span::styled("press any key", dim_if(color))));
    } else {
        lines.push(Line::from(""));
    }

    let content_height = lines.len() as u16;
    f.render_widget(
        Paragraph::new(lines).alignment(Alignment::Center),
        centered(area, content_height),
    );
}

/// The brand mark: a 5-row tile crossed by a golden kintsugi seam. The seam
/// glyphs are gold (when color is on); the frame is dim. Returns centered Lines.
fn mark_lines(color: bool) -> Vec<Line<'static>> {
    let frame_style = if color {
        Style::default().fg(SEAM)
    } else {
        Style::default()
    };
    let gold = if color {
        Style::default().fg(GOLD).add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    // Each tile row: a bordered cell with a seam segment (the ╲ ╳ ╱ run) in gold.
    let row = |left: &'static str, seam: &'static str, right: &'static str| {
        Line::from(vec![
            Span::styled(left, frame_style),
            Span::styled(seam, gold),
            Span::styled(right, frame_style),
        ])
    };
    // Inner content between the borders is always 7 columns wide, so the tile
    // stays a perfect rectangle.
    vec![
        Line::from(Span::styled("╭───────╮", frame_style)),
        row("│  ", "╲", "    │"),
        row("│  ", "╲ ╱", "  │"),
        row("│   ", "╳", "   │"),
        row("│  ", "╱ ╲", "  │"),
        row("│  ", "╱", "    │"),
        Line::from(Span::styled("╰───────╯", frame_style)),
    ]
}

/// A vertically-centered sub-rect of `area` that is `height` rows tall.
fn centered(area: Rect, height: u16) -> Rect {
    let h = height.min(area.height);
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    Rect {
        x: area.x,
        y,
        width: area.width,
        height: h,
    }
}

fn dim_if(color: bool) -> Style {
    style_if(color, Style::default().add_modifier(Modifier::DIM))
}

fn style_if(color: bool, s: Style) -> Style {
    if color {
        s
    } else {
        Style::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn frame_text(frame: usize, color: bool, w: u16, h: u16) -> String {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| render(f, f.area(), frame, color)).unwrap();
        let buf = term.backend().buffer().clone();
        buf.content().iter().map(|c| c.symbol()).collect()
    }

    #[test]
    fn wordmark_rows_are_aligned() {
        let rows = wordmark_rows();
        let w = rows[0].chars().count();
        assert!(rows.iter().all(|r| r.chars().count() == w), "rows ragged");
        assert!(w >= 30, "banner should be a real width");
    }

    #[test]
    fn early_frame_shows_unfilled_seam_glyph() {
        // At frame 0 nothing is filled yet → the seam glyph '░' is present.
        let text = frame_text(0, true, 80, 24);
        assert!(text.contains('░'), "expected unfilled seam at frame 0");
    }

    #[test]
    fn final_frame_is_fully_filled_and_prompts() {
        let text = frame_text(FRAMES, true, 80, 24);
        assert!(text.contains('█'), "expected filled blocks at the end");
        assert!(!text.contains('░'), "nothing should remain unfilled");
        assert!(text.contains("press any key"));
        assert!(text.contains("safety layer"));
    }

    #[test]
    fn mono_animation_still_sweeps_without_color() {
        // Without color the motion is carried by the glyph swap, not the palette.
        let early = frame_text(0, false, 80, 24);
        let late = frame_text(FRAMES, false, 80, 24);
        assert!(early.contains('░'));
        assert!(!late.contains('░'));
    }

    #[test]
    fn narrow_terminal_degrades_without_panic() {
        let text = frame_text(10, true, 24, 10);
        assert!(text.contains("KINTSUGI"));
    }

    #[test]
    fn brand_mark_is_a_perfect_rectangle() {
        // Every tile row must be the same display width or the box looks broken.
        let lines = mark_lines(false);
        let widths: Vec<usize> = lines
            .iter()
            .map(|l| l.spans.iter().map(|s| s.content.chars().count()).sum())
            .collect();
        assert!(
            widths.windows(2).all(|w| w[0] == w[1]),
            "tile rows ragged: {widths:?}"
        );
    }
}
