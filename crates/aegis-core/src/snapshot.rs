//! Snapshots for reversibility ("nothing is unrecoverable").
//!
//! Before an allowed destructive command runs, Aegis copies the paths it is
//! likely to touch into a content-addressed store; `aegis undo` restores them.
//! Copies use reflink CoW where the filesystem supports it (APFS/btrfs/ReFS) and
//! fall back to a plain copy everywhere else.
//!
//! Scope (stated plainly): this covers **files that existed before** the command
//! — restoring overwrites and recreating deletions. It does not remove
//! newly-created files, and it cannot undo network calls, external APIs, or
//! already-pushed commits.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::shell;
use crate::types::ProposedCommand;

/// One captured path within a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// The original absolute path.
    pub original: PathBuf,
    /// Relative location inside the snapshot store dir.
    pub stored: String,
    /// Whether the original was a directory.
    pub is_dir: bool,
}

/// A snapshot manifest: enough to restore every captured path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    /// Snapshot id (also the store sub-directory name).
    pub id: String,
    /// The raw command this snapshot guards.
    pub command: String,
    /// Captured paths.
    pub entries: Vec<Entry>,
}

/// Predict the filesystem paths a command is likely to touch.
///
/// Conservative and dependency-free: resolves non-flag arguments (and a `>`
/// redirect target) against the command's cwd. Bogus candidates are harmless —
/// only paths that actually exist are ever captured.
pub fn predict_paths(cmd: &ProposedCommand) -> Vec<PathBuf> {
    let tokens = shell::split(&cmd.raw);
    let mut out = Vec::new();
    let mut iter = tokens.iter().peekable();
    // Skip the program name (first token).
    let _ = iter.next();
    while let Some(tok) = iter.next() {
        if tok == ">" || tok == ">>" {
            if let Some(target) = iter.next() {
                out.push(resolve(&cmd.cwd, target));
            }
            continue;
        }
        if let Some(rest) = tok.strip_prefix('>') {
            if !rest.is_empty() {
                out.push(resolve(&cmd.cwd, rest.trim_start_matches('>')));
            }
            continue;
        }
        if tok.starts_with('-') || tok.contains('=') {
            continue; // a flag or env assignment, not a path
        }
        out.push(resolve(&cmd.cwd, tok));
    }
    out.sort();
    out.dedup();
    out
}

fn resolve(cwd: &Path, arg: &str) -> PathBuf {
    let a = arg.trim_matches(['"', '\'']);
    let p = PathBuf::from(a);
    if p.is_absolute() {
        p
    } else {
        cwd.join(p)
    }
}

/// Capture a snapshot of the existing predicted paths into `store_root`.
///
/// Returns `Ok(None)` when nothing existed to capture (so callers can skip
/// recording an empty snapshot). The store sub-directory is `store_root/<id>`.
pub fn capture(store_root: &Path, cmd: &ProposedCommand) -> std::io::Result<Option<Manifest>> {
    let candidates = predict_paths(cmd);
    let existing: Vec<PathBuf> = candidates.into_iter().filter(|p| p.exists()).collect();
    if existing.is_empty() {
        return Ok(None);
    }

    let id = Uuid::new_v4().to_string();
    let dir = store_root.join(&id);
    std::fs::create_dir_all(&dir)?;

    let mut entries = Vec::new();
    for (i, path) in existing.iter().enumerate() {
        let stored = i.to_string();
        let dest = dir.join(&stored);
        let is_dir = path.is_dir();
        if is_dir {
            copy_tree(path, &dest)?;
        } else {
            copy_file(path, &dest)?;
        }
        entries.push(Entry {
            original: path.clone(),
            stored,
            is_dir,
        });
    }

    Ok(Some(Manifest {
        id,
        command: cmd.raw.clone(),
        entries,
    }))
}

/// Restore every captured path back to its original location.
pub fn restore(store_root: &Path, manifest: &Manifest) -> std::io::Result<()> {
    let dir = store_root.join(&manifest.id);
    for entry in &manifest.entries {
        let src = dir.join(&entry.stored);
        let dst = &entry.original;
        // Clear whatever is there now, then restore from the store.
        if dst.exists() {
            if dst.is_dir() {
                std::fs::remove_dir_all(dst)?;
            } else {
                std::fs::remove_file(dst)?;
            }
        }
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if entry.is_dir {
            copy_tree(&src, dst)?;
        } else {
            copy_file(&src, dst)?;
        }
    }
    Ok(())
}

/// Copy a single file, preferring reflink CoW, falling back to a plain copy.
fn copy_file(src: &Path, dst: &Path) -> std::io::Result<()> {
    // `reflink_or_copy` reflinks where supported and copies otherwise.
    reflink_copy::reflink_or_copy(src, dst).map(|_| ())
}

/// Recursively copy a directory tree (reflinking each file where possible).
fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&from, &to)?;
        } else {
            copy_file(&from, &to)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(cwd: &Path, raw: &str) -> ProposedCommand {
        ProposedCommand::new("shim", cwd, shell::split(raw), raw)
    }

    #[test]
    fn predicts_non_flag_args_and_redirects() {
        let cwd = Path::new("/work");
        let p = predict_paths(&cmd(cwd, "rm -rf build dist"));
        assert!(p.contains(&PathBuf::from("/work/build")));
        assert!(p.contains(&PathBuf::from("/work/dist")));
        // Flags are not paths.
        assert!(!p.iter().any(|x| x.ends_with("-rf")));

        let r = predict_paths(&cmd(cwd, "echo hi > out.txt"));
        assert!(r.contains(&PathBuf::from("/work/out.txt")));

        let abs = predict_paths(&cmd(cwd, "rm /etc/hosts"));
        assert!(abs.contains(&PathBuf::from("/etc/hosts")));
    }

    #[test]
    fn capture_and_restore_overwrite() {
        let tmp = tempfile::tempdir().unwrap();
        let store = tmp.path().join("store");
        let work = tmp.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        let file = work.join("data.txt");
        std::fs::write(&file, b"original").unwrap();

        let manifest = capture(&store, &cmd(&work, "rm data.txt"))
            .unwrap()
            .expect("something to capture");
        assert_eq!(manifest.entries.len(), 1);

        // Simulate the command: overwrite then delete.
        std::fs::write(&file, b"corrupted").unwrap();
        restore(&store, &manifest).unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), b"original");

        // And restore after a delete.
        std::fs::remove_file(&file).unwrap();
        restore(&store, &manifest).unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), b"original");
    }

    #[test]
    fn capture_returns_none_when_nothing_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let store = tmp.path().join("store");
        let work = tmp.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        // Targets a path that doesn't exist.
        let m = capture(&store, &cmd(&work, "rm ghost.txt")).unwrap();
        assert!(m.is_none());
    }

    #[test]
    fn capture_and_restore_directory_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let store = tmp.path().join("store");
        let work = tmp.path().join("work");
        std::fs::create_dir_all(work.join("src")).unwrap();
        std::fs::write(work.join("src/a.rs"), b"fn a() {}").unwrap();
        std::fs::write(work.join("src/b.rs"), b"fn b() {}").unwrap();

        let manifest = capture(&store, &cmd(&work, "rm -rf src")).unwrap().unwrap();

        std::fs::remove_dir_all(work.join("src")).unwrap();
        restore(&store, &manifest).unwrap();
        assert_eq!(std::fs::read(work.join("src/a.rs")).unwrap(), b"fn a() {}");
        assert_eq!(std::fs::read(work.join("src/b.rs")).unwrap(), b"fn b() {}");
    }
}
