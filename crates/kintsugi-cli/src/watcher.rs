//! Default-on filesystem-watcher backstop — lifecycle (start / stop / status).
//!
//! The watcher records changes that bypass the hook / shim / MCP (an agent in an
//! auto-approve "yolo" mode, or a tool invoked by absolute path like `/bin/rm`),
//! so the audit trail and `kintsugi undo` stay complete. This is the honest
//! guarantee — "nothing is unrecoverable", not "nothing runs un-warned".
//!
//! `init` turns it on for the work tree by default; `stop` turns it off. It runs
//! as a managed background process that forwards observations to the daemon over
//! IPC, so the daemon remains the single writer of the hash-chained log (no
//! second process racing on `prev_hash`).
//!
//! Opt out with `--no-watch` or `KINTSUGI_NO_WATCH=1`; override the scope with
//! `KINTSUGI_WATCH_DIR`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Where the running watcher's pid and scope are recorded (next to the daemon
/// pid file, in the same data dir).
fn pid_path() -> PathBuf {
    kintsugi_daemon::pid_file_path().with_file_name("watch.pid")
}

/// The running watcher's `(pid, root)`, or `None` if no live watcher is recorded.
/// A stale pid file (process gone) reads as `None` so callers treat it as off.
pub fn running() -> Option<(String, String)> {
    running_at(&pid_path())
}

/// Inner form taking an explicit pid-file path, so the live/stale/missing cases
/// are unit-testable without touching process-global environment.
fn running_at(pid_file: &Path) -> Option<(String, String)> {
    let body = std::fs::read_to_string(pid_file).ok()?;
    let mut lines = body.lines();
    let pid = lines.next()?.trim().to_string();
    let root = lines.next().unwrap_or("").trim().to_string();
    if pid.is_empty() || !pid_alive(&pid) {
        return None;
    }
    Some((pid, root))
}

/// The default scope to watch: `KINTSUGI_WATCH_DIR` if set, else the enclosing
/// project (git) root, else the current dir.
pub fn default_root() -> PathBuf {
    if let Some(d) = std::env::var_os("KINTSUGI_WATCH_DIR") {
        return PathBuf::from(d);
    }
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    project_root_of(&cwd)
}

/// The enclosing project root: the nearest ancestor of `start` containing a
/// `.git`, else `start` itself. Prefer it so the backstop watches the work tree,
/// not an arbitrarily broad parent like `$HOME` (which floods the log with OS
/// churn — macOS `~/Library` renames, app-container temp files).
fn project_root_of(start: &Path) -> PathBuf {
    let mut dir = start;
    loop {
        if dir.join(".git").exists() {
            return dir.to_path_buf();
        }
        match dir.parent() {
            Some(p) => dir = p,
            None => break,
        }
    }
    start.to_path_buf()
}

/// Whether the backstop has been opted out for this invocation.
pub fn opted_out() -> bool {
    std::env::var_os("KINTSUGI_NO_WATCH").is_some()
}

/// Start the backstop watcher scoped to `root`. No-ops (returning `Ok(false)`)
/// when opted out; returns `Ok(true)` when one is already running or is started.
/// Records the child's pid and scope so `stop`/`status` can find it.
pub fn start(root: &Path) -> Result<bool> {
    if opted_out() {
        return Ok(false);
    }
    if running().is_some() {
        return Ok(true);
    }
    let exe = std::env::current_exe().context("locate the kintsugi binary")?;
    let child = std::process::Command::new(&exe)
        .arg("watch")
        .arg(root)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("start the backstop watcher on {}", root.display()))?;

    let pid_file = pid_path();
    if let Some(dir) = pid_file.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    std::fs::write(&pid_file, format!("{}\n{}\n", child.id(), root.display()))
        .with_context(|| format!("write {}", pid_file.display()))?;
    Ok(true)
}

/// Stop the backstop watcher if one is running; returns its scope for messaging.
pub fn stop() -> Option<String> {
    let (pid, root) = running()?;
    crate::kill_pid(&pid);
    let _ = std::fs::remove_file(pid_path());
    Some(root)
}

/// Liveness probe that sends no signal — `kill -0` on Unix.
#[cfg(unix)]
fn pid_alive(pid: &str) -> bool {
    std::process::Command::new("kill")
        .args(["-0", pid])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Liveness probe on Windows — `tasklist` lists the process only if it exists.
#[cfg(not(unix))]
fn pid_alive(pid: &str) -> bool {
    std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains(pid))
        .unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_root_prefers_the_git_root() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        let sub = repo.join("sub");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::create_dir_all(&sub).unwrap();
        // From a subdir, the watch root walks up to the repo (work tree).
        assert_eq!(project_root_of(&sub), repo);
        assert_eq!(project_root_of(&repo), repo);
    }

    #[test]
    fn project_root_falls_back_to_start_without_git() {
        let tmp = tempfile::tempdir().unwrap();
        let plain = tmp.path().join("no-vcs");
        std::fs::create_dir_all(&plain).unwrap();
        // No `.git` anywhere up to the temp root → the start dir itself.
        assert_eq!(project_root_of(&plain), plain);
    }

    #[test]
    fn running_is_none_when_pid_file_is_absent() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(running_at(&tmp.path().join("watch.pid")).is_none());
    }

    #[test]
    fn running_is_none_for_a_stale_pid() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("watch.pid");
        // A pid that is almost certainly not a live process.
        std::fs::write(&p, "2147483646\n/some/root\n").unwrap();
        assert!(running_at(&p).is_none(), "a dead pid must read as off");
    }

    #[cfg(unix)]
    #[test]
    fn running_reports_a_live_pid_and_scope() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("watch.pid");
        // This test process is, by definition, alive.
        std::fs::write(&p, format!("{}\n/work/tree\n", std::process::id())).unwrap();
        let (pid, root) = running_at(&p).expect("a live pid must read as on");
        assert_eq!(pid, std::process::id().to_string());
        assert_eq!(root, "/work/tree");
    }
}
