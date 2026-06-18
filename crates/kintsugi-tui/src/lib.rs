//! Kintsugi ratatui terminal UI (Phase 4).
//!
//! A real, interactive timeline over the live event log: keyboard navigation,
//! filtering, a detail view, and undo — all driven by data read from the SQLite
//! log (polled, so updates appear without a restart). The event loop never blocks
//! on I/O long enough to freeze rendering, and the terminal is always restored on
//! exit, panic, or signal (`ratatui::init`/`restore` install the teardown).

#![forbid(unsafe_code)]

pub mod app;
pub mod splash;
pub mod ui;

use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{self, Event, KeyEventKind};
use kintsugi_core::EventLog;

pub use app::{Action, App, Mode, Screen};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The fs-watch backstop is a firehose; cap its live view. Full history is on
/// the append-only log (`kintsugi log`) and reachable by filtering (below).
const BACKSTOP_TAIL: usize = 500;
/// Commands / audit / recorder are low-volume; load effectively all and let the
/// in-view scroll paginate, so backstop noise can never evict a command row.
/// Also the depth the backstop is loaded to while a filter is active.
const TIMELINE_TAIL: usize = 5000;
/// How often to poll for new events.
const POLL: Duration = Duration::from_millis(250);
/// Frame cadence while the launch splash animates (≈60ms → ~1.8s total).
const SPLASH_TICK: Duration = Duration::from_millis(60);

/// Run the TUI against the event log at `db_path`, with snapshots under
/// `snapshot_dir` (for undo). Restores the terminal on any exit path.
pub fn run(db_path: &Path, snapshot_dir: &Path) -> Result<()> {
    let color = std::env::var_os("NO_COLOR").is_none();
    let mut app = App::new(color);
    // Read the local timezone offset now, before ratatui spawns anything: the
    // time crate only proves `current_local_offset` sound while single-threaded.
    // Events are stored in UTC; this renders them in the viewer's zone. Falls
    // back to UTC if the offset can't be determined safely.
    app.set_local_offset(time::UtcOffset::current_local_offset().unwrap_or(time::UtcOffset::UTC));
    // A locked settings vault gates the app behind the admin password.
    if let kintsugi_core::admin::VaultState::Locked(v) =
        kintsugi_core::admin::load_vault(&kintsugi_core::admin::default_vault_path())
    {
        app.set_vault(Some(*v));
    }
    app.start_on_splash();

    let mut terminal = ratatui::init(); // installs the panic-safe teardown hook
    let result = event_loop(&mut terminal, &mut app, db_path, snapshot_dir);
    ratatui::restore();
    result
}

fn event_loop(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    db_path: &Path,
    snapshot_dir: &Path,
) -> Result<()> {
    // Open the event log once and reuse it across polls — re-opening a SQLite
    // connection every 250ms (4×/sec) was needless syscalls + parsing on the hot
    // path. The connection is opened lazily (the daemon may create the db after
    // the TUI starts) and held for the session.
    let mut log: Option<EventLog> = None;
    reload(app, db_path, &mut log);
    loop {
        // Page step = timeline data-rows on screen: total height minus the 1-row
        // header, 2-row footer, and the table's 2 borders + 1 header row.
        app.page_rows = (terminal.size()?.height as usize).saturating_sub(6).max(1);
        terminal.draw(|f| ui::render(f, app))?;

        // The splash runs on a fast cadence so the animation is smooth; the live
        // app polls slower and refreshes data on idle ticks.
        let tick = if app.screen == Screen::Splash {
            SPLASH_TICK
        } else {
            POLL
        };

        if event::poll(tick)? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => match app.on_key(key.code) {
                    Action::Quit => break,
                    Action::Undo => undo(app, db_path, snapshot_dir, &mut log),
                    Action::Approve(id) => resolve(app, &id, true),
                    Action::Deny(id) => resolve(app, &id, false),
                    Action::None => {}
                },
                Event::Resize(_, _) => { /* redrawn next iteration */ }
                _ => {}
            }
        } else if app.screen == Screen::Splash {
            app.tick_splash();
        } else {
            reload(app, db_path, &mut log);
        }
    }
    Ok(())
}

/// Approve or deny a held command via the daemon, surfacing the result.
fn resolve(app: &mut App, id: &str, approve: bool) {
    let res = if approve {
        kintsugi_daemon::Client::approve(id)
    } else {
        kintsugi_daemon::Client::deny(id)
    };
    app.status = Some(match res {
        Ok(()) if approve => "approved — the requesting agent may proceed".to_string(),
        Ok(()) => "denied".to_string(),
        Err(e) => format!("could not resolve (is the daemon running?): {e}"),
    });
}

/// Load the most recent events into the app (live refresh), and refresh the
/// daemon vitals (up/down + active scorer) for the header strip. `log` is the
/// reused connection (opened lazily once the db exists), avoiding a per-poll
/// re-open on the hot path.
fn reload(app: &mut App, db_path: &Path, log: &mut Option<EventLog>) {
    // Cheap liveness ping + scorer id; both fail-soft so the TUI works headless.
    app.daemon_up = kintsugi_daemon::Client::is_daemon_running();
    app.scorer = if app.daemon_up {
        kintsugi_daemon::Client::status_scorer().ok()
    } else {
        None
    };
    if log.is_none() && db_path.exists() {
        *log = EventLog::open(db_path).ok();
    }
    if let Some(l) = log.as_ref() {
        let seq = l.latest_seq().unwrap_or(0);
        // Skip the heavy load when nothing that affects it changed: the log didn't
        // grow AND the filter is unchanged. Keeps the 250ms poll near-free when idle.
        if seq == app.last_seq && app.filter == app.last_filter {
            return;
        }
        let filtering = !app.filter.trim().is_empty();
        // 500 cap is for the idle live tail; while the user is actively filtering,
        // load the backstop as deep as the command tabs so the universal filter
        // reaches the same depth on every tab (Timeline/Audit/Recorder/Backstop).
        let backstop_limit = if filtering {
            TIMELINE_TAIL
        } else {
            BACKSTOP_TAIL
        };

        // Two windows: the command timeline (everything except fs-watch) and the
        // backstop. Unioned, they feed the existing tab partitioning, so a noisy
        // backstop can no longer push commands out of the fetch window.
        use kintsugi_core::log::Filter;
        let mut events = l
            .query(&Filter {
                agent_not: Some("fs-watch".to_string()),
                limit: Some(TIMELINE_TAIL),
                ..Filter::default()
            })
            .unwrap_or_default();
        if let Ok(mut backstop) = l.query(&Filter {
            agent: Some("fs-watch".to_string()),
            limit: Some(backstop_limit),
            ..Filter::default()
        }) {
            events.append(&mut backstop);
        }
        // Newest-first for display (matches the prior tail().reverse() ordering).
        events.sort_by_key(|e| std::cmp::Reverse(e.seq));
        app.set_events(events);
        app.last_seq = seq;
        app.last_filter = app.filter.clone();
    }
}

/// Undo the most recent not-yet-reverted snapshot, surfacing the result as a
/// transient status line.
fn undo(app: &mut App, db_path: &Path, snapshot_dir: &Path, log: &mut Option<EventLog>) {
    app.status = Some(match try_undo(db_path, snapshot_dir) {
        Ok(Some(cmd)) => format!("undid `{cmd}`"),
        Ok(None) => "nothing to undo".to_string(),
        Err(e) => format!("undo failed: {e}"),
    });
    app.last_seq = -1; // force the gate to reload so the result shows immediately
    reload(app, db_path, log);
}

fn try_undo(db_path: &Path, snapshot_dir: &Path) -> Result<Option<String>> {
    if !db_path.exists() {
        return Ok(None);
    }
    let log = EventLog::open(db_path)?;
    let Some(manifest) = log.latest_unreverted_snapshot()? else {
        return Ok(None);
    };
    kintsugi_core::restore_snapshot(snapshot_dir, &manifest)?;
    log.mark_reverted(&manifest.id)?;
    Ok(Some(manifest.command))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kintsugi_core::{Class, Decision, ProposedCommand, Verdict};

    #[test]
    fn reload_reads_live_events() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("e.db");
        {
            let log = EventLog::open(&db).unwrap();
            let cmd = ProposedCommand::new("shim", "/tmp", vec!["ls".into()], "ls");
            log.log_event(
                &cmd,
                &Verdict::rules(Class::Safe, Decision::Allow, "r"),
                None,
            )
            .unwrap();
        }
        let mut app = App::new(false);
        let mut log = None;
        reload(&mut app, &db, &mut log);
        assert_eq!(app.visible().len(), 1);
        assert!(log.is_some(), "the connection is opened once and reused");
    }

    #[test]
    fn undo_with_nothing_reports_so() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("e.db");
        EventLog::open(&db).unwrap();
        let mut app = App::new(false);
        undo(&mut app, &db, &tmp.path().join("snapshots"), &mut None);
        assert_eq!(app.status.as_deref(), Some("nothing to undo"));
    }

    #[test]
    fn undo_restores_via_snapshot() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("e.db");
        let snaps = tmp.path().join("snapshots");
        let work = tmp.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        let file = work.join("f.txt");
        std::fs::write(&file, b"orig").unwrap();

        {
            let log = EventLog::open(&db).unwrap();
            let cmd =
                ProposedCommand::new("shim", &work, vec!["rm".into(), "f.txt".into()], "rm f.txt");
            let m = kintsugi_core::capture_snapshot(&snaps, &cmd)
                .unwrap()
                .unwrap();
            log.record_snapshot(&m).unwrap();
        }
        std::fs::write(&file, b"changed").unwrap();

        let mut app = App::new(false);
        undo(&mut app, &db, &snaps, &mut None);
        assert!(app.status.as_deref().unwrap().contains("undid"));
        assert_eq!(std::fs::read(&file).unwrap(), b"orig");
    }
}
