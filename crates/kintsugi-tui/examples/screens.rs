//! Render representative TUI screens to plain text (one char per cell) so the
//! docs pipeline (`scripts/gen_svg.py`) can turn the *real* redesigned UI into the
//! site's terminal SVGs — no hand-drawn mockups.
//!
//!   cargo run -p kintsugi-tui --example screens -- main  > /tmp/tui.txt
//!   cargo run -p kintsugi-tui --example screens -- login > /tmp/login.txt

use crossterm::event::KeyCode;
use kintsugi_core::{Class, Decision, EventLog, LoggedEvent, ProposedCommand, Verdict};
use kintsugi_tui::{App, Screen};
use ratatui::{backend::TestBackend, Terminal};

fn ev(log: &EventLog, agent: &str, raw: &str, class: Class, decision: Decision) -> LoggedEvent {
    let cmd = ProposedCommand::new(agent, "/srv/app", vec![raw.into()], raw);
    let mut v = Verdict::rules(class, decision, "rule");
    match class {
        Class::Ambiguous => {
            v.risk = Some(62);
            v.summary = Some("touches many files under node_modules".into());
        }
        Class::Catastrophic => {
            v.summary = Some("recursive force-delete of a data directory".into());
        }
        Class::Safe => {}
    }
    log.log_event(&cmd, &v, None).unwrap()
}

fn main() {
    let which = std::env::args().nth(1).unwrap_or_else(|| "main".into());
    let (w, h) = (110u16, 32u16);

    let log = EventLog::open_in_memory().unwrap();
    let events = vec![
        ev(&log, "claude-code", "git status", Class::Safe, Decision::Allow),
        ev(&log, "shell", "psql -c 'TRUNCATE events'", Class::Catastrophic, Decision::Allow),
        ev(&log, "cursor", "npm install", Class::Ambiguous, Decision::Hold),
        ev(&log, "shim", "rm -rf /srv/app/data", Class::Catastrophic, Decision::Hold),
        ev(&log, "claude-code", "cargo build --release", Class::Safe, Decision::Allow),
        ev(&log, "shell", "mysql -p[redacted] -e 'DROP DATABASE staging'", Class::Catastrophic, Decision::Allow),
    ];

    let mut app = App::new(true);
    app.set_events(events);
    app.daemon_up = true;
    app.scorer = Some("llama:Qwen3-4B".into());

    if which == "login" {
        let prov =
            kintsugi_core::admin::provision("demo-password", &kintsugi_core::admin::LockedSettings::default())
                .unwrap();
        app.set_vault(Some(prov.vault));
        app.screen = Screen::Login;
        for c in "demo".chars() {
            app.on_key(KeyCode::Char(c));
        }
    } else {
        app.screen = Screen::Main;
    }

    let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
    term.draw(|f| kintsugi_tui::ui::render(f, &app)).unwrap();
    let buf = term.backend().buffer().clone();

    // The TestBackend buffer is row-major; reassemble rows of `w` cells.
    let cells: Vec<&str> = buf.content().iter().map(|c| c.symbol()).collect();
    for row in cells.chunks(w as usize) {
        println!("{}", row.concat().trim_end());
    }
}
