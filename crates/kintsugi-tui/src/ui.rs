//! Rendering for the Kintsugi TUI.
//!
//! Craft borrowed from the ratatui showcase — bordered panels, a split
//! list/detail layout, a real risk gauge, proper selection highlight — but the
//! design language stays Kintsugi's: calm until it must shout. One reserved danger
//! accent, every state also a word (never color alone), `NO_COLOR` honored via
//! [`App::color`], reflows at any size, and a deliberate "too small" notice.

use kintsugi_core::{Class, Decision, LoggedEvent};
use ratatui::prelude::*;
use ratatui::widgets::{
    Block, BorderType, Borders, Cell, Gauge, Paragraph, Row, Scrollbar, ScrollbarOrientation,
    ScrollbarState, Table, TableState, Wrap,
};
use time::macros::format_description;
use time::UtcOffset;

use crate::app::{outcome_word, App, Mode, Screen, Tab, MIN_HEIGHT, MIN_WIDTH};

const ACCENT: Color = Color::Yellow; // the one reserved accent (held / ambiguous)
const DANGER: Color = Color::Red; // denied / catastrophic
const OKGREEN: Color = Color::Green; // allowed
/// Below this width the detail pane stacks out; the list takes the full width.
const SPLIT_WIDTH: u16 = 100;

/// Render the whole UI for the current frame.
pub fn render(f: &mut Frame, app: &App) {
    let area = f.area();
    // The splash and login own the whole screen and render at any size.
    if app.screen == Screen::Splash {
        crate::splash::render(f, area, app.splash_frame, app.color);
        return;
    }
    if app.screen == Screen::Login {
        render_login(f, app, area);
        return;
    }
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        render_too_small(f, area);
        return;
    }
    if app.screen == Screen::Settings {
        render_settings(f, app, area);
        return;
    }

    let rows = Layout::vertical([
        Constraint::Length(1), // header
        Constraint::Min(1),    // body
        Constraint::Length(2), // footer
    ])
    .split(area);

    render_header(f, app, rows[0]);
    if app.visible().is_empty() {
        render_empty(f, app, rows[1]);
    } else if app.mode == Mode::Detail {
        render_detail(f, app, rows[1], true);
    } else if rows[1].width >= SPLIT_WIDTH {
        let cols = Layout::horizontal([Constraint::Percentage(58), Constraint::Percentage(42)])
            .split(rows[1]);
        render_list(f, app, cols[0]);
        render_detail(f, app, cols[1], false);
    } else {
        render_list(f, app, rows[1]);
    }
    render_footer(f, app, rows[2]);
}

fn dim(app: &App) -> Style {
    if app.color {
        Style::default().add_modifier(Modifier::DIM)
    } else {
        Style::default()
    }
}

fn accent_fg(app: &App, c: Color) -> Style {
    if app.color {
        Style::default().fg(c)
    } else {
        Style::default()
    }
}

/// The settings control panel: the locked settings as a selectable list, each a
/// label + current value, with a save/result line. Read-only when unprovisioned.
fn render_settings(f: &mut Frame, app: &App, area: Rect) {
    use crate::app::SettingRow;
    let rows = Layout::vertical([
        Constraint::Length(1), // header
        Constraint::Min(1),    // body
        Constraint::Length(2), // footer
    ])
    .split(area);

    // Header.
    let editable = app.settings_editable();
    let lock = if editable {
        "unlocked for this session"
    } else {
        "read-only (not provisioned)"
    };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("▦ Kintsugi", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled("  settings", dim(app)),
        ])),
        rows[0],
    );
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(lock, dim(app))).right_aligned()),
        rows[0],
    );

    // Body: the settings table.
    let default = kintsugi_core::admin::LockedSettings::default();
    let s = app.settings.as_ref().unwrap_or(&default);
    let table_rows = SettingRow::ALL.iter().enumerate().map(|(i, row)| {
        let selected = i == app.settings_selected;
        let marker = if selected { "› " } else { "  " };
        let val = row.value(s);
        // The danger accent is reserved: only fail-closed "on" and the value of
        // require-password-to-stop "off" (a loosening) warrant attention; here we
        // keep it calm and use the accent for the *on* booleans.
        let val_style = accent_fg(app, ACCENT);
        Row::new(vec![
            Cell::from(format!("{marker}{}", row.label())),
            Cell::from(Span::styled(val, val_style)),
        ])
    });
    let table = Table::new(table_rows, [Constraint::Length(28), Constraint::Min(10)])
        .block(panel(app, " locked settings "));
    f.render_widget(table, rows[1]);

    // Footer: help + transient status.
    let foot = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).split(rows[2]);
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "j/k move · enter/space toggle · esc back",
            dim(app),
        ))),
        foot[0],
    );
    if let Some(status) = &app.settings_status {
        let danger = status.starts_with("could not") || status.contains("read-only");
        let style = if danger {
            accent_fg(app, DANGER)
        } else {
            accent_fg(app, OKGREEN)
        };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(status.clone(), style))),
            foot[1],
        );
    }
}

/// The admin password gate. Centered card, masked input, error under the field.
fn render_login(f: &mut Frame, app: &App, area: Rect) {
    // Mask the password with bullets — its length is the only thing on screen.
    let masked: String = "•".repeat(app.login_input.chars().count());
    let mut lines = vec![
        Line::from(Span::styled(
            "▦ Kintsugi",
            accent_fg(app, ACCENT).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled("admin-locked", dim(app))),
        Line::from(""),
        Line::from("Enter the admin password to manage Kintsugi."),
        Line::from(""),
        Line::from(vec![
            Span::styled("password ", dim(app)),
            Span::raw(masked),
            Span::styled("▏", dim(app)),
        ]),
    ];
    if let Some(err) = &app.login_error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("✗ {err}"),
            accent_fg(app, DANGER).add_modifier(Modifier::BOLD),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "enter unlock · esc quit",
        dim(app),
    )));

    // A bordered card, centered, sized to the content.
    let h = (lines.len() as u16 + 2).min(area.height);
    let w = 52.min(area.width);
    let card = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    };
    f.render_widget(
        Paragraph::new(lines)
            .block(panel(app, " login "))
            .alignment(Alignment::Center),
        card,
    );
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
    // Left: brand + tab bar. The active tab is bracketed *and* bold/accent, so it
    // reads as selected without relying on color (NO_COLOR-safe).
    let mut spans = vec![
        Span::styled("▦ Kintsugi", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw("  "),
    ];
    for (i, tab) in Tab::ALL.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" · ", dim(app)));
        }
        let active = *tab == app.tab;
        // The active tab is bracketed *and* bold/accent, so it reads as selected
        // without color (NO_COLOR-safe); each tab carries its row count as a badge.
        let label = if active {
            format!("[{}]", tab.title())
        } else {
            format!(" {} ", tab.title())
        };
        let style = if active {
            accent_fg(app, ACCENT).add_modifier(Modifier::BOLD)
        } else {
            dim(app)
        };
        spans.push(Span::styled(label, style));
        spans.push(Span::styled(format!(" {}", app.tab_total(*tab)), dim(app)));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);

    // Right: live vitals — counts (global) and daemon health, all worded.
    let (total, held, catastrophic) = app.vitals();
    let mut vitals = vec![Span::styled(format!("{total} events"), dim(app))];
    if held > 0 {
        vitals.push(Span::styled(" · ", dim(app)));
        vitals.push(Span::styled(format!("{held} held"), accent_fg(app, ACCENT)));
    }
    if catastrophic > 0 {
        vitals.push(Span::styled(" · ", dim(app)));
        vitals.push(Span::styled(
            format!("{catastrophic} catastrophic"),
            accent_fg(app, DANGER),
        ));
    }
    vitals.push(Span::styled(" · ", dim(app)));
    if app.daemon_up {
        let scorer = app.scorer.as_deref().unwrap_or("ready");
        vitals.push(Span::styled(
            format!("● daemon {scorer}"),
            accent_fg(app, OKGREEN),
        ));
    } else {
        vitals.push(Span::styled("○ daemon down", dim(app)));
    }
    f.render_widget(Paragraph::new(Line::from(vitals).right_aligned()), area);
}

fn render_empty(f: &mut Frame, app: &App, area: Rect) {
    let block = panel(app, &format!(" {} ", app.tab.title().to_lowercase()));
    // Distinguish "this slice is genuinely empty" from "the filter hid everything".
    let (headline, hint): (&str, String) = if !app.filter.is_empty() {
        (
            "No rows match the filter.",
            format!("filter: {}", app.filter),
        )
    } else {
        ("Nothing here yet.", app.tab.empty_copy().to_string())
    };
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            headline,
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(hint, dim(app))),
    ];
    f.render_widget(
        Paragraph::new(lines)
            .block(block)
            .alignment(Alignment::Center),
        area,
    );
}

/// A rounded bordered panel with a title.
fn panel(app: &App, title: &str) -> Block<'static> {
    let b = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(Span::styled(title.to_string(), dim(app)));
    if app.color {
        b.border_style(Style::default().fg(Color::DarkGray))
    } else {
        b
    }
}

fn class_tag(c: Class) -> &'static str {
    match c {
        Class::Safe => "",
        Class::Catastrophic => "[catastrophic] ",
        Class::Ambiguous => "[ambiguous] ",
    }
}

fn decision_color(d: Decision) -> Color {
    match d {
        Decision::Allow => OKGREEN,
        Decision::Deny => DANGER,
        Decision::Hold => ACCENT,
    }
}

/// `HH:MM:SS` in the viewer's local zone (events are stored in UTC).
fn fmt_time(ev: &LoggedEvent, offset: UtcOffset) -> String {
    let f = format_description!("[hour]:[minute]:[second]");
    ev.ts
        .to_offset(offset)
        .format(&f)
        .unwrap_or_else(|_| "--:--:--".into())
}

/// `Mon DD` in the viewer's local zone — the day a row's command happened. Used
/// as a group label: shown only when the date changes down the list.
fn fmt_date(ev: &LoggedEvent, offset: UtcOffset) -> String {
    let f = format_description!("[month repr:short] [day]");
    ev.ts
        .to_offset(offset)
        .format(&f)
        .unwrap_or_else(|_| "------".into())
}

/// Full `YYYY-MM-DD HH:MM:SS ±HH:MM` for the detail pane — unambiguous, with the
/// offset spelled out so there's no doubt which zone it's in.
fn fmt_datetime(ev: &LoggedEvent, offset: UtcOffset) -> String {
    let f = format_description!(
        "[year]-[month]-[day] [hour]:[minute]:[second] [offset_hour sign:mandatory]:[offset_minute]"
    );
    ev.ts
        .to_offset(offset)
        .format(&f)
        .unwrap_or_else(|_| "—".into())
}

/// The local calendar day of an event, for deciding when to print a date label.
fn local_day(ev: &LoggedEvent, offset: UtcOffset) -> time::Date {
    ev.ts.to_offset(offset).date()
}

fn short_session(ev: &LoggedEvent) -> String {
    match &ev.session {
        Some(s) => s.chars().take(8).collect(),
        None => "—".to_string(),
    }
}

// Fixed column widths (the command column flexes to fill the rest).
const W_DATE: u16 = 6; // "Jun 17"
const W_TIME: u16 = 8; // "11:43:30"
const W_AGENT: u16 = 12;
const W_SESSION: u16 = 8;
const W_OUTCOME: u16 = 7; // "allowed"

fn render_list(f: &mut Frame, app: &App, area: Rect) {
    let visible = app.visible();
    let offset = app.local_offset;
    // Show a session column when there's room; the detail pane always has the
    // full id, so on narrow terminals we drop the column rather than scroll.
    let show_session = area.width >= 92;

    let mut head = vec!["date", "time", "agent"];
    if show_session {
        head.push("session");
    }
    head.push("outcome");
    head.push("command");
    let n_cols = head.len() as u16;
    let header = Row::new(head)
        .style(dim(app).add_modifier(Modifier::BOLD))
        .height(1);

    // Budget for the flexing command column, so we can ellipsize cleanly instead
    // of letting ratatui hard-clip mid-word at the panel edge.
    let fixed = W_DATE + W_TIME + W_AGENT + W_OUTCOME + if show_session { W_SESSION } else { 0 };
    let chrome = 2 /* borders */ + 2 /* highlight symbol */ + (n_cols - 1) /* column gaps */;
    let cmd_width = area.width.saturating_sub(fixed + chrome).max(8) as usize;

    let mut prev_day: Option<time::Date> = None;
    let rows: Vec<Row> = visible
        .iter()
        .map(|ev| {
            // Group by day: print the date only when it changes down the list, so
            // a long run of same-day rows reads as one block (git-log style).
            let day = local_day(ev, offset);
            let date_cell = if prev_day != Some(day) {
                Cell::from(Span::styled(fmt_date(ev, offset), dim(app)))
            } else {
                Cell::from("")
            };
            prev_day = Some(day);

            let outcome = Cell::from(Span::styled(
                outcome_word(ev.decision),
                accent_fg(app, decision_color(ev.decision)),
            ));
            let tag = class_tag(ev.class);
            let body = ellipsize(&ev.command, cmd_width.saturating_sub(tag.len()));
            let command = Line::from(vec![
                Span::styled(tag, accent_fg(app, decision_color(ev.decision))),
                Span::raw(body),
            ]);
            let mut cells = vec![
                date_cell,
                Cell::from(fmt_time(ev, offset)),
                Cell::from(truncate(&ev.agent, W_AGENT as usize)),
            ];
            if show_session {
                cells.push(Cell::from(Span::styled(short_session(ev), dim(app))));
            }
            cells.push(outcome);
            cells.push(Cell::from(command));
            Row::new(cells)
        })
        .collect();

    let mut widths = vec![
        Constraint::Length(W_DATE),
        Constraint::Length(W_TIME),
        Constraint::Length(W_AGENT),
    ];
    if show_session {
        widths.push(Constraint::Length(W_SESSION));
    }
    widths.push(Constraint::Length(W_OUTCOME));
    widths.push(Constraint::Min(10));

    let highlight = if app.color {
        Style::default()
            .bg(Color::Indexed(236))
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().add_modifier(Modifier::REVERSED)
    };
    // Title carries the position so the count is always in view: "timeline 42/830".
    let title = format!(
        " {} {}/{} ",
        app.tab.title().to_lowercase(),
        (app.selected + 1).min(visible.len()),
        visible.len()
    );
    let table = Table::new(rows, widths)
        .header(header)
        .block(panel(app, &title))
        .row_highlight_style(highlight)
        .highlight_symbol("› ");

    let mut state = TableState::default().with_selected(Some(app.selected));
    f.render_stateful_widget(table, area, &mut state);

    // A scrollbar on the right border when the list overflows the viewport, so
    // there's a visible sense of position and how much is off-screen. Drawn on
    // the border itself (not over data); calm in monochrome too. The viewport is
    // derived from the render area (height minus the two borders and the header
    // row), not the event loop's page_rows, so it's correct in any render path.
    let rows_on_screen = area.height.saturating_sub(3).max(1) as usize;
    if visible.len() > rows_on_screen {
        let mut sb_state = ScrollbarState::new(visible.len())
            .viewport_content_length(rows_on_screen)
            .position(app.selected);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("↑"))
            .end_symbol(Some("↓"))
            .track_symbol(Some("│"))
            .thumb_symbol("█")
            .style(dim(app));
        f.render_stateful_widget(
            scrollbar,
            area.inner(Margin {
                vertical: 1,
                horizontal: 0,
            }),
            &mut sb_state,
        );
    }
}

/// Truncate a single-line string to `max` display columns, appending '…' when it
/// doesn't fit. `max == 0` yields an empty string.
fn ellipsize(s: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    truncate(s, max)
}

fn render_detail(f: &mut Frame, app: &App, area: Rect, full: bool) {
    let block = panel(
        app,
        if full {
            " detail · esc to go back "
        } else {
            " detail "
        },
    );
    let Some(ev) = app.selected_event() else {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "Select a row to inspect it.",
                dim(app),
            )))
            .block(block),
            area,
        );
        return;
    };

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Reserve a gauge row for held/ambiguous items that carry a risk score.
    let (top, gauge_area) = if ev.risk.is_some() && inner.height >= 4 {
        let parts = Layout::vertical([Constraint::Min(1), Constraint::Length(2)]).split(inner);
        (parts[0], Some(parts[1]))
    } else {
        (inner, None)
    };

    let label = |k: &str| Span::styled(format!("{k:<9}"), dim(app));
    let headline = if ev.redacted {
        "redacted · hidden".to_string()
    } else {
        format!("{} · {}", outcome_word(ev.decision), ev.class.as_str())
    };
    let mut lines = vec![
        Line::from(Span::styled(
            headline,
            accent_fg(app, decision_color(ev.decision)).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![label("command"), Span::raw(ev.command.clone())]),
        Line::from(vec![label("agent"), Span::raw(ev.agent.clone())]),
    ];
    if let Some(session) = &ev.session {
        lines.push(Line::from(vec![
            label("session"),
            Span::raw(session.clone()),
        ]));
    }
    lines.push(Line::from(vec![
        label("when"),
        Span::raw(fmt_datetime(ev, app.local_offset)),
    ]));
    lines.push(Line::from(vec![
        label("reason"),
        Span::raw(ev.reason.clone()),
    ]));
    if let Some(summary) = &ev.summary {
        // The model summary may carry "• " pointer lines (newline-separated);
        // a single Span won't break on '\n', so render each line on its own —
        // the label on the first, indented continuations after.
        let mut parts = summary.split('\n');
        if let Some(first) = parts.next() {
            lines.push(Line::from(vec![
                label("summary"),
                Span::raw(first.to_string()),
            ]));
        }
        for cont in parts {
            if cont.trim().is_empty() {
                continue;
            }
            lines.push(Line::from(vec![
                Span::raw("           "),
                Span::raw(cont.to_string()),
            ]));
        }
    }
    if let Some(snap) = &ev.snapshot_id {
        lines.push(Line::from(vec![
            label("snapshot"),
            Span::raw(snap.chars().take(12).collect::<String>()),
        ]));
    }
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), top);

    if let (Some(area), Some(risk)) = (gauge_area, ev.risk) {
        let color = if ev.class == Class::Catastrophic {
            DANGER
        } else {
            ACCENT
        };
        let gauge = Gauge::default()
            .ratio((risk as f64 / 100.0).clamp(0.0, 1.0))
            .label(format!("risk {risk}/100"))
            .gauge_style(accent_fg(app, color))
            .use_unicode(true);
        // Auto width: size the bar to ~half the panel (bounded 14..=40), one row
        // high, so it reads as a meter — not a full-width block that overruns.
        f.render_widget(gauge, gauge_rect(area));
    }
}

/// A bounded, single-row sub-rect for the risk meter inside its reserved area.
fn gauge_rect(area: Rect) -> Rect {
    let width = (area.width / 2).clamp(14, 40).min(area.width);
    Rect {
        x: area.x,
        y: area.y,
        width,
        height: 1,
    }
}

fn render_footer(f: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).split(area);
    let help = "j/k move · space/b page · tab · a/d resolve · u undo · / filter · q quit";
    // Right-aligned position indicator so paging has a frame of reference — both
    // the row and the page of the current viewport — shown only when it fits
    // without crowding the help (narrow terminals show help alone).
    let total = app.visible().len();
    let pos = if total > 0 {
        let per = app.page_rows.max(1);
        let page = app.selected / per + 1;
        let pages = total.div_ceil(per);
        format!("row {}/{} · pg {}/{}", app.selected + 1, total, page, pages)
    } else {
        String::new()
    };
    let width = area.width as usize;
    let help_line = if !pos.is_empty() && width > help.chars().count() + pos.chars().count() + 1 {
        let pad = width - help.chars().count() - pos.chars().count();
        Line::from(vec![
            Span::styled(help, dim(app)),
            Span::raw(" ".repeat(pad)),
            Span::styled(pos, dim(app)),
        ])
    } else {
        Line::from(Span::styled(help, dim(app)))
    };
    f.render_widget(Paragraph::new(help_line), rows[0]);

    let second = match app.mode {
        Mode::Filter => {
            let mut spans = vec![
                Span::styled("/", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(app.filter.clone()),
                Span::styled("▏", dim(app)),
            ];
            if app.filter.is_empty() {
                spans.push(Span::styled(
                    "  agent:claude-code · session:4a87 · since:10m · before:1d · or text",
                    dim(app),
                ));
            }
            Line::from(spans)
        }
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
    use kintsugi_core::{EventLog, ProposedCommand, Verdict};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn gauge_rect_is_bounded_and_single_row() {
        // Wide panel: capped at 40, one row high, anchored at the area origin.
        let wide = gauge_rect(Rect {
            x: 5,
            y: 9,
            width: 200,
            height: 2,
        });
        assert_eq!(wide.width, 40);
        assert_eq!(wide.height, 1);
        assert_eq!((wide.x, wide.y), (5, 9));
        // Narrow panel: never wider than the area it's given.
        let narrow = gauge_rect(Rect {
            x: 0,
            y: 0,
            width: 10,
            height: 2,
        });
        assert!(narrow.width <= 10);
        assert_eq!(narrow.height, 1);
    }

    fn ev(agent: &str, raw: &str, class: Class, decision: Decision) -> LoggedEvent {
        let log = EventLog::open_in_memory().unwrap();
        let cmd = ProposedCommand::new(agent, "/tmp", vec![raw.into()], raw);
        let mut v = Verdict::rules(class, decision, "rule");
        if class == Class::Ambiguous {
            v.risk = Some(60);
            v.summary = Some("needs your call".into());
        }
        log.log_event(&cmd, &v, None).unwrap()
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
        assert!(text.contains("Kintsugi"));
        assert!(text.contains("timeline"));
        assert!(text.contains("rm -rf /"));
        assert!(text.contains("held"));
        assert!(text.contains("[catastrophic]"));
        assert!(text.contains("q quit"));
    }

    #[test]
    fn split_layout_shows_detail_pane_when_wide() {
        let mut app = app_with_events();
        app.selected = 1;
        let text = buffer_text(&app, 120, 24);
        // The detail panel and its labels appear alongside the list.
        assert!(text.contains("detail"));
        assert!(text.contains("reason"));
    }

    #[test]
    fn reflows_small_and_large() {
        let text = buffer_text(&app_with_events(), 50, 8);
        assert!(text.contains("too small"));
        let big = buffer_text(&app_with_events(), 200, 60);
        assert!(big.contains("rm -rf /"));
    }

    #[test]
    fn empty_state_is_designed() {
        let app = App::new(false);
        let text = buffer_text(&app, 80, 24);
        assert!(text.contains("Nothing here yet"));
        assert!(text.contains("wired agent"));
    }

    #[test]
    fn detail_view_shows_fields_and_risk() {
        let mut app = app_with_events();
        // Add an ambiguous (risk-bearing) row and open it.
        app.set_events(vec![ev(
            "qwen",
            "make deploy",
            Class::Ambiguous,
            Decision::Hold,
        )]);
        app.selected = 0;
        app.on_key(crossterm::event::KeyCode::Enter);
        let text = buffer_text(&app, 80, 24);
        assert!(text.contains("detail"));
        assert!(text.contains("make deploy"));
        assert!(text.contains("reason"));
        assert!(text.contains("risk"));
    }

    #[test]
    fn color_mode_renders_without_panic() {
        // Exercises the color branches (accent fg, border style, highlight, gauge).
        let mut app = App::new(true);
        app.set_events(vec![
            ev("qwen", "make deploy", Class::Ambiguous, Decision::Hold),
            ev("shim", "rm -rf /", Class::Catastrophic, Decision::Hold),
        ]);
        app.selected = 0; // the ambiguous row carries a risk score → gauge shows
        let wide = buffer_text(&app, 120, 24); // split + detail + gauge
        assert!(wide.contains("make deploy"));
        assert!(wide.contains("risk"));
        let narrow = buffer_text(&app, 80, 24); // list only
        assert!(narrow.contains("held"));
    }

    #[test]
    fn settings_screen_lists_rows_and_values() {
        let mut app = App::new(false);
        app.open_settings(); // read-only defaults (no vault)
        let text = buffer_text(&app, 80, 24);
        assert!(text.contains("locked settings"));
        assert!(text.contains("recording"));
        assert!(text.contains("enforcement"));
        assert!(text.contains("attended"));
        assert!(text.contains("read-only"));
        assert!(text.contains("esc back"));
    }

    #[test]
    fn login_screen_masks_input_and_shows_errors() {
        let mut app = App::new(false);
        // Force the login screen without a real vault by setting state directly.
        app.screen = crate::app::Screen::Login;
        app.login_input = zeroize::Zeroizing::new("secret".to_string());
        app.login_error = Some("incorrect password".into());
        let text = buffer_text(&app, 80, 24);
        assert!(text.contains("admin-locked"));
        assert!(text.contains("••••••"), "password must be masked");
        assert!(!text.contains("secret"), "raw password must never render");
        assert!(text.contains("incorrect password"));
        assert!(text.contains("esc quit"));
    }

    fn ev_at(ts: time::OffsetDateTime, agent: &str, raw: &str) -> LoggedEvent {
        let mut e = ev(agent, raw, Class::Safe, Decision::Allow);
        e.ts = ts;
        e
    }

    #[test]
    fn time_and_date_render_in_the_local_offset() {
        use time::macros::datetime;
        let e = ev_at(datetime!(2026-06-17 23:30:00 UTC), "shell", "ls");
        // UTC: late evening on the 17th.
        assert_eq!(fmt_time(&e, UtcOffset::UTC), "23:30:00");
        assert_eq!(fmt_date(&e, UtcOffset::UTC), "Jun 17");
        // +02:00 rolls both the clock and the calendar day forward.
        let plus2 = UtcOffset::from_hms(2, 0, 0).unwrap();
        assert_eq!(fmt_time(&e, plus2), "01:30:00");
        assert_eq!(fmt_date(&e, plus2), "Jun 18");
        assert!(fmt_datetime(&e, plus2).contains("+02:00"));
    }

    #[test]
    fn date_column_groups_by_day() {
        use time::macros::datetime;
        let mut app = App::new(false);
        app.set_events(vec![
            ev_at(datetime!(2026-06-16 09:00:00 UTC), "shell", "older"),
            ev_at(datetime!(2026-06-17 09:00:00 UTC), "shell", "first-today"),
            ev_at(datetime!(2026-06-17 10:00:00 UTC), "shell", "second-today"),
        ]);
        let text = buffer_text(&app, 100, 24);
        // Each day is labelled once; the second same-day row repeats no date.
        assert_eq!(
            text.matches("Jun 17").count(),
            1,
            "consecutive same-day rows share one date label"
        );
        assert!(text.contains("Jun 16"));
    }

    #[test]
    fn scrollbar_shows_only_when_the_list_overflows() {
        let mut app = App::new(false);
        let many: Vec<LoggedEvent> = (0..50)
            .map(|_| ev("shell", "ls", Class::Safe, Decision::Allow))
            .collect();
        app.set_events(many);
        let overflow = buffer_text(&app, 80, 12);
        assert!(
            overflow.contains('█') || overflow.contains('↓'),
            "an overflowing list must show a scrollbar"
        );

        app.set_events(vec![ev("shell", "ls", Class::Safe, Decision::Allow)]);
        let fits = buffer_text(&app, 80, 24);
        assert!(
            !fits.contains('█') && !fits.contains('↓'),
            "no scrollbar when everything fits"
        );
    }

    #[test]
    fn footer_shows_row_and_page_position() {
        let mut app = App::new(false);
        app.page_rows = 5;
        let many: Vec<LoggedEvent> = (0..12)
            .map(|_| ev("shell", "ls", Class::Safe, Decision::Allow))
            .collect();
        app.set_events(many);
        let text = buffer_text(&app, 100, 14);
        assert!(text.contains("row 1/12"));
        assert!(text.contains("pg 1/3"));
    }

    #[test]
    fn tab_bar_shows_count_badges() {
        let mut app = App::new(false);
        app.set_events(vec![
            ev("claude-code", "ls", Class::Safe, Decision::Allow),
            ev("shim", "rm -rf /", Class::Catastrophic, Decision::Hold),
        ]);
        let text = buffer_text(&app, 100, 24);
        // Timeline holds both; Audit holds only the catastrophic one.
        assert!(text.contains("Timeline] 2"));
        assert!(text.contains("Audit  1") || text.contains("Audit 1"));
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
