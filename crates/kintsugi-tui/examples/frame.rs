//! Render a representative Kintsugi TUI frame to plain text (one row per line), so
//! `scripts/gen_svg.py` can turn it into a pixel-perfect, aligned SVG. This uses
//! the *real* render path (ratatui `TestBackend`), so the boxes always line up
//! and the risk gauge matches the actual app.
//!
//!   cargo run -p kintsugi-tui --example frame > /tmp/tui.txt

use kintsugi_core::{Class, Decision, EventLog, ProposedCommand, Verdict};
use kintsugi_tui::app::App;
use kintsugi_tui::ui;
use ratatui::backend::TestBackend;
use ratatui::Terminal;

#[allow(clippy::too_many_arguments)]
fn ev(
    log: &EventLog,
    agent: &str,
    session: Option<&str>,
    raw: &str,
    class: Class,
    decision: Decision,
    summary: Option<&str>,
    risk: Option<u8>,
) -> kintsugi_core::LoggedEvent {
    let cmd = ProposedCommand::new(agent, "/repo", vec![raw.to_string()], raw)
        .with_session(session.map(str::to_string));
    let verdict = Verdict {
        class,
        decision,
        tier: if risk.is_some() { 2 } else { 1 },
        reason: "rule".into(),
        summary: summary.map(str::to_string),
        risk,
    };
    log.log_event(&cmd, &verdict, None).unwrap()
}

fn main() {
    let log = EventLog::open_in_memory().unwrap();
    let events = vec![
        ev(
            &log,
            "claude-code",
            Some("4a876f17"),
            "git status",
            Class::Safe,
            Decision::Allow,
            None,
            None,
        ),
        ev(
            &log,
            "claude-code",
            Some("4a876f17"),
            "cargo test",
            Class::Safe,
            Decision::Allow,
            None,
            None,
        ),
        ev(
            &log,
            "cursor",
            Some("b3a1b340"),
            "make deploy",
            Class::Ambiguous,
            Decision::Hold,
            Some("Runs the deploy target; may push or mutate infra."),
            Some(64),
        ),
        ev(
            &log,
            "shim",
            None,
            "git push --force origin main",
            Class::Catastrophic,
            Decision::Hold,
            Some("Force-pushes, overwriting remote history."),
            None,
        ),
        ev(
            &log,
            "shim",
            None,
            "rm -rf build",
            Class::Catastrophic,
            Decision::Deny,
            None,
            None,
        ),
        ev(
            &log,
            "claude-code",
            Some("4a876f17"),
            "npm run lint",
            Class::Safe,
            Decision::Allow,
            None,
            None,
        ),
    ];

    let mut app = App::new(true);
    app.set_events(events);
    app.selected = 2; // the ambiguous "make deploy" — carries a risk gauge

    let (w, h) = (108u16, 20u16);
    let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
    term.draw(|f| ui::render(f, &app)).unwrap();
    let buf = term.backend().buffer().clone();

    for y in 0..h {
        let mut line = String::new();
        for x in 0..w {
            line.push_str(buf[(x, y)].symbol());
        }
        println!("{}", line.trim_end());
    }
}
