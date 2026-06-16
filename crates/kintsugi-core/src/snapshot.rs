//! Snapshots for reversibility ("nothing is unrecoverable").
//!
//! Before an allowed destructive command runs, Kintsugi copies the paths it is
//! likely to touch into a content-addressed store; `kintsugi undo` restores them.
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
/// Conservative and dependency-free, but shell-segment aware: the raw line is
/// split on `;`, `&&`, `||`, `|` and newlines (outside quotes), each segment is
/// tokenised, and a leading `cd <dir>` updates the effective cwd for the rest of
/// the line — so `cd build; rm -rf ../dist` resolves `../dist` against `build`,
/// not the original cwd. Non-flag arguments and redirect targets become
/// candidates; bogus ones are harmless (only paths that exist are captured).
pub fn predict_paths(cmd: &ProposedCommand) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut cwd = cmd.cwd.clone();
    for segment in split_segments(&cmd.raw) {
        let tokens = shell::split(&segment);
        let mut iter = tokens.iter();
        let Some(prog) = iter.next() else { continue };
        // A `cd` moves the effective directory for the rest of the line.
        if prog == "cd" {
            if let Some(dir) = iter.next() {
                cwd = resolve(&cwd, dir);
            }
            continue;
        }
        for tok in iter.by_ref() {
            if matches!(tok.as_str(), ">" | ">>" | "2>" | "&>" | "2>>") {
                continue; // the next token is the target; handled below
            }
            if let Some(rest) = tok.strip_prefix('>') {
                let r = rest.trim_start_matches('>');
                if !r.is_empty() {
                    out.push(resolve(&cwd, r));
                }
                continue;
            }
            if tok.starts_with('-') || tok.contains('=') {
                continue; // a flag or env assignment, not a path
            }
            out.push(resolve(&cwd, tok));
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Whether a snapshot can faithfully cover this command — i.e. whether
/// `kintsugi undo` is an honest promise for it.
///
/// Returns `false` when a target is *unbounded* and can't be snapshotted: a glob
/// (`* ? [`), a shell expansion (`$`, backticks, `~`), the filesystem root, or a
/// device node. For those, `kintsugi undo` cannot guarantee a rollback and the
/// filesystem-watcher backstop is the real net — callers must say so honestly.
pub fn is_fully_reversible(cmd: &ProposedCommand) -> bool {
    let mut cwd = cmd.cwd.clone();
    for segment in split_segments(&cmd.raw) {
        let tokens = shell::split(&segment);
        let mut iter = tokens.iter();
        let Some(prog) = iter.next() else { continue };
        if prog == "cd" {
            if let Some(dir) = iter.next() {
                cwd = resolve(&cwd, dir);
            }
            continue;
        }
        for tok in iter {
            if tok.starts_with('-') {
                continue;
            }
            // For `key=value` args (env assignments, but also dd's `of=…`), judge
            // the value — so `dd of=/dev/sda` is caught while `FOO=bar` isn't.
            let candidate = tok.split_once('=').map(|(_, v)| v).unwrap_or(tok.as_str());
            if candidate.is_empty() {
                continue;
            }
            // Shell expansions / globs: real targets are unknown ahead of time.
            if candidate.contains(['*', '?', '[', '$', '`', '~']) {
                return false;
            }
            let resolved = resolve(&cwd, candidate);
            // The root, a top-level path, or a device can't be meaningfully copied.
            if resolved == Path::new("/")
                || resolved.starts_with("/dev")
                || resolved.parent() == Some(Path::new("/"))
            {
                return false;
            }
        }
    }
    true
}

/// Split a raw command line into sequential segments on `;`, `&&`, `||`, `|` and
/// newlines, ignoring separators inside single or double quotes.
fn split_segments(raw: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        match quote {
            Some(q) => {
                cur.push(c);
                if c == q {
                    quote = None;
                }
            }
            None => match c {
                '\'' | '"' => {
                    quote = Some(c);
                    cur.push(c);
                }
                ';' | '\n' | '|' => {
                    if c == '|' && chars.peek() == Some(&'|') {
                        chars.next();
                    }
                    segments.push(std::mem::take(&mut cur));
                }
                '&' if chars.peek() == Some(&'&') => {
                    chars.next();
                    segments.push(std::mem::take(&mut cur));
                }
                _ => cur.push(c),
            },
        }
    }
    segments.push(cur);
    segments
        .into_iter()
        .filter(|s| !s.trim().is_empty())
        .collect()
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
    fn predicts_across_segments_and_tracks_cd() {
        let cwd = Path::new("/work");
        // The destructive target is relative to the `cd`, not the original cwd.
        let p = predict_paths(&cmd(cwd, "cd build && rm -rf ../dist"));
        assert!(
            p.contains(&PathBuf::from("/work/build/../dist")),
            "got {p:?}"
        );
        // A piped/chained second command's paths are still seen.
        let q = predict_paths(&cmd(cwd, "ls; rm notes.txt"));
        assert!(q.contains(&PathBuf::from("/work/notes.txt")));
        // A pipe `|` also splits segments.
        let r = predict_paths(&cmd(cwd, "cat a.txt | rm b.txt"));
        assert!(r.contains(&PathBuf::from("/work/b.txt")), "got {r:?}");
    }

    #[test]
    fn predicts_redirect_variants() {
        let cwd = Path::new("/work");
        for raw in ["echo x >> log.txt", "echo x 2> err.txt", "echo x >out.txt"] {
            let p = predict_paths(&cmd(cwd, raw));
            assert!(
                p.iter().any(|x| x.to_string_lossy().ends_with(".txt")),
                "{raw}: {p:?}"
            );
        }
    }

    #[test]
    fn reversibility_flags_unbounded_targets() {
        let cwd = Path::new("/work");
        // Bounded, ordinary targets → reversible.
        assert!(is_fully_reversible(&cmd(cwd, "rm -rf build")));
        assert!(is_fully_reversible(&cmd(cwd, "cd src && rm a.txt")));
        // Globs, expansions, root, and devices → NOT fully reversible.
        assert!(!is_fully_reversible(&cmd(cwd, "rm -rf *")));
        assert!(!is_fully_reversible(&cmd(cwd, "rm -rf $HOME/x")));
        assert!(!is_fully_reversible(&cmd(cwd, "rm -rf /")));
        assert!(!is_fully_reversible(&cmd(
            cwd,
            "dd if=/dev/zero of=/dev/sda"
        )));
    }

    #[test]
    fn captures_and_restores_a_directory_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let store = tmp.path().join("store");
        let work = tmp.path().join("work");
        std::fs::create_dir_all(work.join("sub/deep")).unwrap();
        std::fs::write(work.join("sub/a.txt"), b"one").unwrap();
        std::fs::write(work.join("sub/deep/b.txt"), b"two").unwrap();

        let manifest = capture(&store, &cmd(&work, "rm -rf sub"))
            .unwrap()
            .expect("a directory to capture");
        assert!(manifest.entries.iter().any(|e| e.is_dir), "captured a dir");

        // Delete the whole tree, then restore it from the snapshot.
        std::fs::remove_dir_all(work.join("sub")).unwrap();
        restore(&store, &manifest).unwrap();
        assert_eq!(std::fs::read(work.join("sub/a.txt")).unwrap(), b"one");
        assert_eq!(std::fs::read(work.join("sub/deep/b.txt")).unwrap(), b"two");
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
