//! Filesystem-watcher backstop.
//!
//! Records FS changes even from actions that dodged the hook/shim/MCP, so the
//! timeline and `kintsugi undo` stay complete — the honest guarantee is "nothing is
//! unrecoverable", not "nothing runs un-warned". Observations are sent to the
//! daemon over IPC so its single writer keeps the hash chain intact (never a
//! second concurrent writer racing on `prev_hash`).
//!
//! On by default for the work tree (via `kintsugi init`); also `kintsugi watch <path>`.
//!
//! Scope is deliberately narrow so the append-only log stays signal, not noise:
//! the backstop records the *destructive* filesystem changes it exists to catch —
//! deletions and renames/moves — and **not** every file create or save (which a
//! normal edit/build storm produces by the thousand, and which interception +
//! snapshots already cover for agent writes). It also skips well-known build /
//! VCS / editor-scratch paths entirely.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use notify::{EventKind, RecursiveMode, Watcher};

use crate::ipc::{Client, Observation};

/// Directory names whose contents are never interesting to the backstop: VCS
/// internals, dependency/build trees, and tool caches. A change anywhere beneath
/// one of these is ignored.
const IGNORED_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "target",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "__pycache__",
    ".venv",
    "venv",
    ".cache",
    ".idea",
    ".vscode",
    ".mypy_cache",
    ".pytest_cache",
    ".gradle",
    ".terraform",
    ".DS_Store",
    // macOS ~/Library + Unity/Xcode churn: renames/removes here are pure OS noise,
    // not user activity, and otherwise bury real events in the timeline.
    "Library",
    "Caches",
    "DerivedData",
];

/// Map a notify event kind to a stable label, or `None` to ignore it.
///
/// Only deletions and renames are recorded: those are the destructive,
/// recoverable-or-auditable signals a bypassing actor leaves. Creates and
/// content modifications are intentionally dropped — they are the bulk of a
/// working tree's churn (every save, every compiler temp) and would bloat the
/// append-only log without telling you anything you can act on.
pub fn kind_label(kind: &EventKind) -> Option<&'static str> {
    match kind {
        EventKind::Modify(notify::event::ModifyKind::Name(_)) => Some("renamed"),
        EventKind::Remove(_) => Some("removed"),
        _ => None,
    }
}

/// Whether a path lives under a build/VCS/cache dir or is an editor scratch file,
/// so the backstop can skip it. Keeps the log to changes a human would care about.
pub fn is_ignored(path: &Path) -> bool {
    use std::path::Component;
    for c in path.components() {
        if let Component::Normal(os) = c {
            if let Some(s) = os.to_str() {
                if IGNORED_DIRS.contains(&s) {
                    return true;
                }
            }
        }
    }
    // Editor / tool scratch files: vim swap & probe, backups, temp, lockfiles.
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if name == ".DS_Store"
            || name == "4913" // vim's writability probe
            || name.starts_with(".#") // emacs lock
            || name.ends_with('~')
            || name.ends_with(".swp")
            || name.ends_with(".swx")
            || name.ends_with(".tmp")
        {
            return true;
        }
    }
    false
}

/// Watch `roots` recursively, forwarding each change to the daemon. Long-running.
pub fn run(roots: &[PathBuf]) -> Result<()> {
    if roots.is_empty() {
        anyhow::bail!("nothing to watch (pass one or more paths)");
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher = notify::recommended_watcher(move |res| {
        let _ = tx.send(res);
    })
    .context("create filesystem watcher")?;

    let mut registered = 0usize;
    for root in roots {
        match watcher.watch(root, RecursiveMode::Recursive) {
            Ok(()) => {
                registered += 1;
                eprintln!("kintsugi-watch: watching {}", root.display());
            }
            // A single root we can't watch is a partial blind spot, not a reason
            // to abandon the others — record the gap and carry on.
            Err(e) => record_marker(&format!("cannot watch {}: {e}", root.display())),
        }
    }
    if registered == 0 {
        anyhow::bail!("could not watch any of the requested paths");
    }

    for res in rx {
        match res {
            Ok(event) => {
                // The OS dropped events (queue overflow): the backstop missed
                // changes in this window. Surface it instead of silently losing
                // coverage — the honest guarantee depends on knowing the gap.
                if event.need_rescan() {
                    record_marker("event queue overflow — some changes were not recorded");
                }
                forward(&event);
            }
            Err(e) => record_marker(&format!("watch error: {e}")),
        }
    }
    Ok(())
}

/// Surface a backstop degradation: log it and record a `backstop-degraded`
/// observation so the timeline shows the watcher's coverage was reduced rather
/// than failing silently.
fn record_marker(reason: &str) {
    eprintln!("kintsugi-watch: backstop degraded: {reason}");
    let obs = Observation {
        kind: "backstop-degraded".into(),
        path: reason.into(),
    };
    if let Err(e) = Client::observe(&obs) {
        eprintln!("kintsugi-watch: could not record degradation marker: {e}");
    }
}

/// Forward one notify event's interesting paths to the daemon.
fn forward(event: &notify::Event) {
    let Some(kind) = kind_label(&event.kind) else {
        return;
    };
    for path in &event.paths {
        if is_ignored(path) {
            continue;
        }
        let obs = Observation {
            kind: kind.to_string(),
            path: path.display().to_string(),
        };
        if let Err(e) = Client::observe(&obs) {
            eprintln!("kintsugi-watch: could not record {}: {e}", path.display());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use notify::event::{CreateKind, ModifyKind, RemoveKind};

    #[test]
    fn records_only_destructive_kinds() {
        // Deletions and renames are the backstop's signal.
        assert_eq!(
            kind_label(&EventKind::Remove(RemoveKind::File)),
            Some("removed")
        );
        assert_eq!(
            kind_label(&EventKind::Modify(ModifyKind::Name(
                notify::event::RenameMode::Any
            ))),
            Some("renamed")
        );
        // Creates and content edits are the bulk of churn — intentionally dropped.
        assert_eq!(kind_label(&EventKind::Create(CreateKind::File)), None);
        assert_eq!(
            kind_label(&EventKind::Modify(ModifyKind::Data(
                notify::event::DataChange::Any
            ))),
            None
        );
        assert_eq!(
            kind_label(&EventKind::Access(notify::event::AccessKind::Any)),
            None
        );
    }

    #[test]
    fn ignores_build_vcs_and_scratch_paths() {
        assert!(is_ignored(Path::new("/home/u/proj/.git/index")));
        assert!(is_ignored(Path::new("/home/u/proj/node_modules/x/y.js")));
        assert!(is_ignored(Path::new("/home/u/proj/target/debug/foo")));
        assert!(is_ignored(Path::new("/home/u/proj/src/.main.rs.swp")));
        assert!(is_ignored(Path::new("/home/u/proj/.DS_Store")));
        assert!(is_ignored(Path::new("/home/u/proj/src/main.rs~")));
        // macOS OS churn under ~/Library is ignored (pure noise, not user activity).
        assert!(is_ignored(Path::new(
            "/Users/x/Library/Preferences/foo.plist"
        )));
        assert!(is_ignored(Path::new("/Users/x/Library/Caches/bar")));
        // A real source file is not ignored.
        assert!(!is_ignored(Path::new("/home/u/proj/src/main.rs")));
        assert!(!is_ignored(Path::new("/home/u/proj/data/users.sql")));
    }

    #[test]
    fn empty_roots_is_an_error() {
        assert!(run(&[]).is_err());
    }

    /// Point the IPC client at a socket that can't exist, so the degradation
    /// marker's `Client::observe` fails fast and is never written to a real daemon
    /// (these tests assert the fail-soft path, not delivery).
    fn isolate_socket() {
        std::env::set_var(
            "KINTSUGI_SOCKET",
            "/kintsugi-nonexistent-test-socket-xyzzy.sock",
        );
    }

    #[test]
    fn unwatchable_root_records_a_marker_and_bails() {
        // A path that can't be watched (it doesn't exist) is a partial blind spot:
        // the per-root `.watch()` Err arm records a degradation marker, and with no
        // root successfully registered `run` bails rather than watching nothing.
        isolate_socket();
        let bogus = PathBuf::from("/kintsugi-nonexistent-watch-root-xyzzy");
        assert!(
            run(&[bogus]).is_err(),
            "no watchable root must be an error, not a silent no-op"
        );
    }

    #[test]
    fn record_marker_is_resilient_without_a_daemon() {
        // The degradation marker is best-effort: with no daemon listening, the
        // Client::observe send fails and is logged, but record_marker must not
        // panic (the watcher keeps running).
        isolate_socket();
        record_marker("test degradation reason");
    }

    #[test]
    fn forward_skips_ignored_and_non_destructive_events_without_panic() {
        isolate_socket();
        // A non-destructive kind (create) is dropped before any path work.
        let create = notify::Event::new(EventKind::Create(notify::event::CreateKind::File))
            .add_path(PathBuf::from("/work/tree/new.rs"));
        forward(&create);
        // A destructive event under an ignored dir is skipped per-path.
        let in_ignored = notify::Event::new(EventKind::Remove(notify::event::RemoveKind::File))
            .add_path(PathBuf::from("/work/tree/node_modules/x.js"));
        forward(&in_ignored);
        // A destructive event on a real path is forwarded (observe fails soft with
        // no daemon — the point is it walks the happy path without panicking).
        let real = notify::Event::new(EventKind::Remove(notify::event::RemoveKind::File))
            .add_path(PathBuf::from("/work/tree/src/main.rs"));
        forward(&real);
    }
}
