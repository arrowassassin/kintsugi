//! Rendering for the Aegis TUI.
//!
//! Design direction (from `CLAUDE.md` / the design doc): calm until it must
//! shout. One reserved accent for danger, everything else the terminal's default
//! foreground. Every state is also a word, never color alone. `NO_COLOR` is
//! honored via [`App::color`]. The layout reflows at any size and shows a
//! deliberate notice when the terminal is too small.

use aegis_core::{Class, Decision, LoggedEvent};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap};
use time::macros::format_description;

use crate::app::{App, Mode, MIN_HEIGHT, MIN_WIDTH};

const ACCENT: Color = Color::Yellow; // the one reserved accent (held)
const DANGER: Color = Color::Red; // denied / catastrophic

/// Render the whole UI for the current frame.
pub fn render(f: &mut Frame, app: &App) {
    let area = f.area();
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        render_too_small(f, area);
        return;
    }

    let chunks = Layout::vertical([
        Constraint::Length(1), // header
        Constraint::Min(1),    // body
        Constraint::Length(2), // footer
    ])
    .split(area);

    render_header(f, app, chunks[0]);
    if app.is_empty() {
        render_empty(f, app, chunks[1]);
    } else if app.mode == Mode::Detail {
        render_detail(f, app, chunks[1]);
    } else {
        render_table(f, app, chunks[1]);
    }
    render_footer(f, app, chunks[2]);
}

fn dim(app: &App) -> Style {
    if app.color {
        Style::default().add_modifier(Modifier::DIM)
    } else {
        Style::default()
    }
}

fn render_too_small(f: &mut Frame, area: Rect) {
    let p = Paragraph::new(format!(
        "Terminal too small.\nResize to at least {MIN_WIDTH}×{MIN_HEIGHT}."
    ))
    .alignment(Alignment::Center)
    .wrap(Wrap { trim: true });
    f.render_widget(p, area);
}

fn render_header(f: &mut Frame, app: &App, area: Rect) {
    let total = app.visible().len();
    let left = Span::styled("Aegis", Style::default().add_modifier(Modifier::BOLD));
    let mid = Span::styled("  timeline", dim(app));
    let right = Span::styled(format!("{total} events"), dim(app));
    let used = "Aegis  timeline".len() as u16;
    let pad = area.width.saturating_sub(used + right.content.len() as u16) as usize;
    let line = Line::from(vec![left, mid, Span::raw(" ".repeat(pad)), right]);
    f.render_widget(Paragraph::new(line), area);
}

fn render_empty(f: &mut Frame, app: &App, area: Rect) {
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "No events yet.",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Aegis is watching. Run a command through a wired agent",
            dim(app),
        )),
        Line::from(Span::styled(
            "(or the $PATH shim) and it will appear here.",
            dim(app),
        )),
    ];
    f.render_widget(Paragraph::new(lines).alignment(Alignment::Center), area);
}

fn outcome_word(d: Decision) -> &'static str {
    match d {
        Decision::Allow => "allowed",
        Decision::Deny => "denied",
        Decision::Hold => "held",
    }
}

fn class_tag(c: Class) -> &'static str {
    match c {
        Class::Safe => "",
        Class::Catastrophic => "[catastrophic] ",
        Class::Ambiguous => "[ambiguous] ",
    }
}

/// The single-accent style for a row, by decision. Words still carry the meaning.
fn row_style(app: &App, d: Decision) -> Style {
    if !app.color {
        return Style::default();
    }
    match d {
        Decision::Deny => Style::default().fg(DANGER),
        Decision::Hold => Style::default().fg(ACCENT),
        Decision::Allow => Style::default(),
    }
}

fn fmt_time(ev: &LoggedEvent) -> String {
    let f = format_description!("[hour]:[minute]:[second]");
    ev.ts.format(&f).unwrap_or_else(|_| "--:--:--".into())
}

fn render_table(f: &mut Frame, app: &App, area: Rect) {
    let visible = app.visible();
    let header = Row::new(["", "time", "agent", "outcome", "command"])
        .style(dim(app))
        .height(1);

    let rows = visible.iter().enumerate().map(|(i, ev)| {
        let marker = if i == app.selected { "›" } else { " " };
        let command = format!("{}{}", class_tag(ev.class), ev.command);
        let mut style = row_style(app, ev.decision);
        if i == app.selected {
            style = style.add_modifier(Modifier::REVERSED);
        }
        Row::new(vec![
            Cell::from(marker),
            Cell::from(fmt_time(ev)),
            Cell::from(truncate(&ev.agent, 12)),
            Cell::from(outcome_word(ev.decision)),
            Cell::from(command),
        ])
        .style(style)
    });

    let widths = [
        Constraint::Length(2),
        Constraint::Length(8),
        Constraint::Length(12),
        Constraint::Length(8),
        Constraint::Min(10),
    ];
    f.render_widget(Table::new(rows, widths).header(header), area);
}

fn render_detail(f: &mut Frame, app: &App, area: Rect) {
    let Some(ev) = app.selected_event() else {
        render_table(f, app, area);
        return;
    };
    let accent = row_style(app, ev.decision);
    let mut lines = vec![
        Line::from(Span::styled(
            format!("{} · {}", outcome_word(ev.decision), ev.class.as_str()),
            accent.add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("command  ", dim(app)),
            Span::raw(ev.command.clone()),
        ]),
        Line::from(vec![
            Span::styled("agent    ", dim(app)),
            Span::raw(ev.agent.clone()),
        ]),
        Line::from(vec![
            Span::styled("when     ", dim(app)),
            Span::raw(fmt_time(ev)),
        ]),
        Line::from(vec![
            Span::styled("reason   ", dim(app)),
            Span::raw(ev.reason.clone()),
        ]),
    ];
    if let Some(summary) = &ev.summary {
        lines.push(Line::from(vec![
            Span::styled("summary  ", dim(app)),
            Span::raw(summary.clone()),
        ]));
    }
    if let Some(risk) = ev.risk {
        lines.push(Line::from(vec![
            Span::styled("risk     ", dim(app)),
            Span::raw(format!("{risk}/100")),
        ]));
    }
    if let Some(snap) = &ev.snapshot_id {
        lines.push(Line::from(vec![
            Span::styled("snapshot ", dim(app)),
            Span::raw(snap.clone()),
        ]));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" detail · esc to go back ");
    f.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_footer(f: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).split(area);

    let help = "j/k move · enter detail · a/d approve/deny · u undo · / filter · q quit";
    f.render_widget(Paragraph::new(Span::styled(help, dim(app))), rows[0]);

    let second = match app.mode {
        Mode::Filter => Line::from(vec![
            Span::styled("/", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(app.filter.clone()),
            Span::styled("▏", dim(app)),
        ]),
        _ => {
            if let Some(status) = &app.status {
                Line::from(Span::raw(status.clone()))
            } else if !app.filter.is_empty() {
                Line::from(Span::styled(format!("filter: {}", app.filter), dim(app)))
            } else {
                Line::from("")
            }
        }
    };
    f.render_widget(Paragraph::new(second), rows[1]);
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::{EventLog, ProposedCommand, Verdict};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn ev(agent: &str, raw: &str, class: Class, decision: Decision) -> LoggedEvent {
        let log = EventLog::open_in_memory().unwrap();
        let cmd = ProposedCommand::new(agent, "/tmp", vec![raw.into()], raw);
        log.log_event(&cmd, &Verdict::rules(class, decision, "rule"), None)
            .unwrap()
    }

    fn app_with_events() -> App {
        let mut app = App::new(false);
        app.set_events(vec![
            ev("claude-code", "ls -la", Class::Safe, Decision::Allow),
            ev("shim", "rm -rf /", Class::Catastrophic, Decision::Hold),
        ]);
        app
    }

    fn buffer_text(app: &App, w: u16, h: u16) -> String {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| render(f, app)).unwrap();
        let buf = term.backend().buffer().clone();
        buf.content().iter().map(|c| c.symbol()).collect()
    }

    #[test]
    fn renders_timeline_at_standard_size() {
        let text = buffer_text(&app_with_events(), 80, 24);
        assert!(text.contains("Aegis"));
        assert!(text.contains("timeline"));
        assert!(text.contains("rm -rf /"));
        assert!(text.contains("held"));
        assert!(text.contains("[catastrophic]"));
        assert!(text.contains("q quit"));
    }

    #[test]
    fn reflows_small_and_large() {
        // Just under the minimum → notice.
        let text = buffer_text(&app_with_events(), 50, 8);
        assert!(text.contains("too small"));
        // Large terminal still renders the timeline without panicking.
        let big = buffer_text(&app_with_events(), 200, 60);
        assert!(big.contains("rm -rf /"));
    }

    #[test]
    fn empty_state_is_designed() {
        let app = App::new(false);
        let text = buffer_text(&app, 80, 24);
        assert!(text.contains("No events yet"));
        assert!(text.contains("watching"));
    }

    #[test]
    fn detail_view_shows_fields() {
        let mut app = app_with_events();
        app.selected = 1;
        app.on_key(crossterm::event::KeyCode::Enter);
        let text = buffer_text(&app, 80, 24);
        assert!(text.contains("detail"));
        assert!(text.contains("rm -rf /"));
        assert!(text.contains("reason"));
    }

    #[test]
    fn filter_mode_shows_input_line() {
        let mut app = app_with_events();
        app.on_key(crossterm::event::KeyCode::Char('/'));
        app.on_key(crossterm::event::KeyCode::Char('r'));
        app.on_key(crossterm::event::KeyCode::Char('m'));
        let text = buffer_text(&app, 80, 24);
        assert!(text.contains("/rm"));
        assert!(text.contains("rm -rf /"));
        assert!(!text.contains("ls -la"), "filtered out the safe row");
    }
}
