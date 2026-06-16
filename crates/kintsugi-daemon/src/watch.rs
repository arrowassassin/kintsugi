//! Filesystem-watcher backstop.
//!
//! Records FS changes even from actions that dodged the hook/shim/MCP, so the
//! timeline and `kintsugi undo` stay complete — the honest guarantee is "nothing is
//! unrecoverable", not "nothing runs un-warned". Observations are sent to the
//! daemon over IPC so its single writer keeps the hash chain intact (never a
//! second concurrent writer racing on `prev_hash`).
//!
//! Off by default; opt in with `kintsugi watch <path>`.

use std::path::PathBuf;

use anyhow::{Context, Result};
use notify::{EventKind, RecursiveMode, Watcher};

use crate::ipc::{Client, Observation};

/// Map a notify event kind to a stable label, or `None` to ignore it (access
/// events and metadata-only noise are not interesting for the backstop).
pub fn kind_label(kind: &EventKind) -> Option<&'static str> {
    match kind {
        EventKind::Create(_) => Some("created"),
        EventKind::Modify(notify::event::ModifyKind::Name(_)) => Some("renamed"),
        EventKind::Modify(_) => Some("modified"),
        EventKind::Remove(_) => Some("removed"),
        _ => None,
    }
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
    fn maps_interesting_kinds() {
        assert_eq!(
            kind_label(&EventKind::Create(CreateKind::File)),
            Some("created")
        );
        assert_eq!(
            kind_label(&EventKind::Remove(RemoveKind::File)),
            Some("removed")
        );
        assert_eq!(
            kind_label(&EventKind::Modify(ModifyKind::Data(
                notify::event::DataChange::Any
            ))),
            Some("modified")
        );
        assert_eq!(
            kind_label(&EventKind::Access(notify::event::AccessKind::Any)),
            None
        );
    }

    #[test]
    fn empty_roots_is_an_error() {
        assert!(run(&[]).is_err());
    }
}
