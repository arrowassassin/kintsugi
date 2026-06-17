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

    for root in roots {
        watcher
            .watch(root, RecursiveMode::Recursive)
            .with_context(|| format!("watch {}", root.display()))?;
        eprintln!("kintsugi-watch: watching {}", root.display());
    }

    for res in rx {
        match res {
            Ok(event) => forward(&event),
            Err(e) => eprintln!("kintsugi-watch: watch error: {e}"),
        }
    }
    Ok(())
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
        // A real source file is not ignored.
        assert!(!is_ignored(Path::new("/home/u/proj/src/main.rs")));
        assert!(!is_ignored(Path::new("/home/u/proj/data/users.sql")));
    }

    #[test]
    fn empty_roots_is_an_error() {
        assert!(run(&[]).is_err());
    }
}
