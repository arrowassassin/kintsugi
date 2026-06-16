//! P0.4 acceptance: a shimmed `rm` deletes the file AND logs the event, with the
//! real binary's exit code preserved. Unix-only (uses symlinks + a filesystem
//! socket); the same code path covers Windows via named pipes.
#![cfg(unix)]

use std::os::unix::fs::symlink;
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;

use kintsugi_core::{Class, Decision, EventLog};
use kintsugi_daemon::{Daemon, Server};

fn serial_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

struct Harness {
    _guard: MutexGuard<'static, ()>,
    tmp: tempfile::TempDir,
    shim_dir: std::path::PathBuf,
    db: std::path::PathBuf,
    server: Option<thread::JoinHandle<()>>,
}

/// Start a daemon serving `requests` connections, with a shim dir on a private
/// socket/db. Symlink each requested command name to the built `kintsugi-shim`.
fn start(requests: usize, link_as: &[&str]) -> Harness {
    let guard = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    let sock = tmp.path().join("kintsugi.sock");
    let db = tmp.path().join("events.db");
    let shim_dir = tmp.path().join("shimdir");
    std::fs::create_dir_all(&shim_dir).unwrap();

    let shim_bin = env!("CARGO_BIN_EXE_kintsugi-shim");
    for name in link_as {
        symlink(shim_bin, shim_dir.join(name)).unwrap();
    }

    std::env::set_var("KINTSUGI_SOCKET", &sock);
    std::env::set_var("KINTSUGI_DB", &db);

    let db_for_thread = db.clone();
    let server = Server::bind().unwrap();
    let handle = thread::spawn(move || {
        let daemon = Daemon::open(&db_for_thread).unwrap();
        server
            .serve_n(requests, |req| daemon.handle_request(req))
            .unwrap();
    });

    Harness {
        _guard: guard,
        tmp,
        shim_dir,
        db,
        server: Some(handle),
    }
}

impl Harness {
    /// PATH with the shim dir first, then the inherited PATH.
    fn shimmed_path(&self) -> String {
        let orig = std::env::var("PATH").unwrap_or_default();
        format!("{}:{}", self.shim_dir.display(), orig)
    }

    fn join(&mut self) {
        if let Some(h) = self.server.take() {
            h.join().unwrap();
        }
    }
}

#[test]
fn shimmed_catastrophic_rm_is_held_and_does_not_run() {
    let mut h = start(1, &["rm"]);

    // A directory the real rm -rf would destroy.
    let work = h.tmp.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let victim = work.join("data");
    std::fs::create_dir_all(&victim).unwrap();
    std::fs::write(victim.join("keep.txt"), b"important").unwrap();

    // The shim has no TTY to approve on, so a held command must NOT run.
    let status = Command::new(h.shim_dir.join("rm"))
        .arg("-rf")
        .arg("data")
        .current_dir(&work)
        .stdin(std::process::Stdio::null())
        .env("PATH", h.shimmed_path())
        .env("KINTSUGI_SOCKET", h.tmp.path().join("kintsugi.sock"))
        .env("KINTSUGI_DB", &h.db)
        .status()
        .unwrap();

    assert!(!status.success(), "a held command must not exit 0");
    assert!(victim.exists(), "the directory must survive — rm was held");

    h.join();

    let log = EventLog::open(&h.db).unwrap();
    let tail = log.tail(10).unwrap();
    assert_eq!(tail.len(), 1);
    assert_eq!(tail[0].agent, "shim");
    assert_eq!(tail[0].command, "rm -rf data");
    assert_eq!(tail[0].class, Class::Catastrophic);
    assert_eq!(tail[0].decision, Decision::Hold);
    assert!(log.verify_chain().unwrap().is_intact());
}

#[test]
fn shimmed_command_propagates_nonzero_exit_code() {
    let mut h = start(1, &["false"]);

    // `false` exits 1; the shim must forward that exact code.
    let status = Command::new(h.shim_dir.join("false"))
        .current_dir(h.tmp.path())
        .env("PATH", h.shimmed_path())
        .env("KINTSUGI_SOCKET", h.tmp.path().join("kintsugi.sock"))
        .env("KINTSUGI_DB", &h.db)
        .status()
        .unwrap();

    assert_eq!(status.code(), Some(1), "exit code must be preserved");

    h.join();
    let log = EventLog::open(&h.db).unwrap();
    assert_eq!(log.tail(10).unwrap()[0].command, "false");
}

/// Run the shimmed command feeding `key` to its stdin (the hold-card answer).
fn run_with_key(h: &Harness, prog: &str, args: &[&str], work: &std::path::Path, key: &str) -> i32 {
    use std::io::Write;
    let mut child = Command::new(h.shim_dir.join(prog))
        .args(args)
        .current_dir(work)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .env("PATH", h.shimmed_path())
        .env("NO_COLOR", "1")
        .env("KINTSUGI_SOCKET", h.tmp.path().join("kintsugi.sock"))
        .env("KINTSUGI_DB", &h.db)
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(key.as_bytes())
        .unwrap();
    child.wait().unwrap().code().unwrap_or(-1)
}

#[test]
fn hold_card_allow_runs_and_records_resolution() {
    // Propose + Resolve = 2 connections.
    let mut h = start(2, &["rm"]);
    let work = h.tmp.path().join("w1");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(work.join("f"), b"x").unwrap();

    // 'a' = allow once → the real rm runs and deletes the file.
    let code = run_with_key(&h, "rm", &["f"], &work, "a\n");
    assert_eq!(code, 0, "allowed command should run and exit 0");
    assert!(
        !work.join("f").exists(),
        "file should be deleted after allow"
    );

    h.join();
    let log = EventLog::open(&h.db).unwrap();
    let tail = log.tail(10).unwrap();
    // Two events: the initial Hold, then the human's allow resolution.
    assert_eq!(tail.len(), 2);
    assert_eq!(tail[0].decision, Decision::Hold);
    assert_eq!(tail[1].decision, Decision::Allow);
    assert!(log.verify_chain().unwrap().is_intact());
}

#[test]
fn hold_card_deny_blocks_and_records() {
    let mut h = start(2, &["rm"]);
    let work = h.tmp.path().join("w2");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(work.join("f"), b"x").unwrap();

    // 'd' = deny → the command does not run; file survives.
    let code = run_with_key(&h, "rm", &["f"], &work, "d\n");
    assert_ne!(code, 0, "denied command must not exit 0");
    assert!(work.join("f").exists(), "file should survive a deny");

    h.join();
    let log = EventLog::open(&h.db).unwrap();
    let tail = log.tail(10).unwrap();
    assert_eq!(tail.last().unwrap().decision, Decision::Deny);
}

#[test]
fn hold_card_remember_auto_allows_next_time() {
    // First run: Hold + Resolve(remember). Second run: memory auto-allow (1 conn).
    let mut h = start(3, &["rm"]);
    // Make the work dir a git repo so the memory key is the repo root.
    let work = h.tmp.path().join("repo");
    std::fs::create_dir_all(work.join(".git")).unwrap();
    std::fs::write(work.join("a"), b"1").unwrap();

    // 'r' = always allow here → runs now and remembers.
    let code1 = run_with_key(&h, "rm", &["a"], &work, "r\n");
    assert_eq!(code1, 0);
    assert!(!work.join("a").exists());

    // Re-create the file; the same exact command should now auto-allow from
    // memory with no prompt (empty stdin).
    std::fs::write(work.join("a"), b"again").unwrap();
    let code2 = run_with_key(&h, "rm", &["a"], &work, "");
    assert_eq!(code2, 0, "remembered command should auto-allow");
    assert!(!work.join("a").exists(), "memory-allowed rm should run");

    h.join();
    let log = EventLog::open(&h.db).unwrap();
    let events = log.tail(20).unwrap();
    // Hold, then always-allow resolution, then a memory-allow on the second run.
    let memory_allow = events
        .iter()
        .any(|e| e.decision == Decision::Allow && e.reason.contains("memory:allow"));
    assert!(
        memory_allow,
        "second run should be recorded as a memory allow"
    );
}

#[test]
fn shimmed_command_forwards_stdout() {
    let mut h = start(1, &["echo"]);

    let out = Command::new(h.shim_dir.join("echo"))
        .arg("hello-from-shim")
        .current_dir(h.tmp.path())
        .env("PATH", h.shimmed_path())
        .env("KINTSUGI_SOCKET", h.tmp.path().join("kintsugi.sock"))
        .env("KINTSUGI_DB", &h.db)
        .output()
        .unwrap();

    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "hello-from-shim"
    );

    h.join();
}
