//! P0.5 acceptance: a Claude Code hook payload becomes a logged event tagged
//! `agent = "claude-code"`, and the verdict maps to the hook protocol.
#![cfg(unix)]

use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;

use kintsugi_core::{Decision, EventLog};
use kintsugi_daemon::{Daemon, Server};
use kintsugi_intercept::hook::{handle, HookOutcome};

fn serial_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

struct Harness {
    _guard: MutexGuard<'static, ()>,
    _tmp: tempfile::TempDir,
    db: std::path::PathBuf,
    server: Option<thread::JoinHandle<()>>,
}

fn start(requests: usize) -> Harness {
    let guard = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("KINTSUGI_SOCKET", tmp.path().join("kintsugi.sock"));
    std::env::set_var("KINTSUGI_DB", tmp.path().join("events.db"));
    let db = tmp.path().join("events.db");

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
        _tmp: tmp,
        db,
        server: Some(handle),
    }
}

impl Harness {
    fn join(&mut self) {
        if let Some(h) = self.server.take() {
            h.join().unwrap();
        }
    }
}

#[test]
fn safe_bash_hook_payload_is_logged_as_claude_code() {
    let mut h = start(1);

    let payload = r#"{
        "session_id": "abc",
        "cwd": "/home/dev/project",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "git status", "description": "check" }
    }"#;

    // A safe command is allowed silently (Claude proceeds; the event is logged).
    let outcome = handle(payload);
    assert_eq!(
        outcome,
        HookOutcome {
            stdout: None,
            exit_code: 0
        }
    );

    h.join();

    let log = EventLog::open(&h.db).unwrap();
    let tail = log.tail(10).unwrap();
    assert_eq!(tail.len(), 1);
    assert_eq!(tail[0].agent, "claude-code");
    assert_eq!(tail[0].command, "git status");
    assert_eq!(tail[0].argv, vec!["git", "status"]);
    assert_eq!(tail[0].cwd, "/home/dev/project");
    assert_eq!(tail[0].decision, Decision::Allow);
    assert!(log.verify_chain().unwrap().is_intact());
}

#[test]
fn catastrophic_bash_hook_payload_is_denied_not_ask() {
    let mut h = start(1);

    let payload = r#"{
        "cwd": "/home/dev/project",
        "tool_name": "Bash",
        "tool_input": { "command": "rm -rf /" }
    }"#;

    // A catastrophic hold is mapped to "deny" (NOT "ask"): a one-click allow in
    // Claude's UI would bypass Kintsugi's snapshot. It must go through a guarded path.
    let outcome = handle(payload);
    let body: serde_json::Value = serde_json::from_str(outcome.stdout.as_deref().unwrap()).unwrap();
    assert_eq!(body["hookSpecificOutput"]["permissionDecision"], "deny");
    // The deny must be honest: the agent won't run it, and the guarded way to
    // run it yourself is the shim (so the agent can relay that instead of
    // silently working around the block).
    let reason = body["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert!(
        reason.contains("will not run") && reason.contains("kintsugi run "),
        "deny reason should explain the agent won't run it and give `kintsugi run <id>`: {reason}"
    );

    h.join();
    let log = EventLog::open(&h.db).unwrap();
    let tail = log.tail(1).unwrap();
    assert_eq!(tail[0].decision, Decision::Hold);
    assert_eq!(tail[0].class, kintsugi_core::Class::Catastrophic);
}

#[test]
fn ambiguous_bash_hook_payload_is_ask() {
    let mut h = start(1);
    let payload = r#"{ "tool_name": "Bash", "tool_input": { "command": "make deploy" } }"#;
    let outcome = handle(payload);
    let body: serde_json::Value = serde_json::from_str(outcome.stdout.as_deref().unwrap()).unwrap();
    assert_eq!(body["hookSpecificOutput"]["permissionDecision"], "ask");
    h.join();
}

#[test]
fn non_shell_tool_does_not_reach_the_daemon() {
    // No daemon needed: an Edit tool call is allowed without any round-trip.
    let _guard = serial_lock();
    // Point at a socket that does not exist to prove we never connect.
    std::env::set_var("KINTSUGI_SOCKET", "/nonexistent/kintsugi.sock");
    let payload = r#"{"tool_name":"Edit","tool_input":{"file_path":"x"}}"#;
    assert_eq!(
        handle(payload),
        HookOutcome {
            stdout: None,
            exit_code: 0
        }
    );
}

#[test]
fn daemon_down_fails_open_for_non_catastrophic() {
    let _guard = serial_lock();
    std::env::set_var("KINTSUGI_SOCKET", "/nonexistent/kintsugi.sock");
    std::env::remove_var("KINTSUGI_FAIL_CLOSED");
    let payload = r#"{"tool_name":"Bash","tool_input":{"command":"npm test"}}"#;
    // Fail-open: a non-catastrophic command runs rather than block Claude Code.
    assert_eq!(
        handle(payload),
        HookOutcome {
            stdout: None,
            exit_code: 0
        }
    );
}

#[test]
fn daemon_down_still_blocks_catastrophic_fail_closed() {
    let _guard = serial_lock();
    std::env::set_var("KINTSUGI_SOCKET", "/nonexistent/kintsugi.sock");
    std::env::remove_var("KINTSUGI_FAIL_CLOSED");
    // Even fail-open by default, a catastrophic command is blocked when the
    // daemon is down — local Tier-1 classification enforces the hard floor.
    let payload = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;
    let outcome = handle(payload);
    let body: serde_json::Value = serde_json::from_str(outcome.stdout.as_deref().unwrap()).unwrap();
    assert_eq!(body["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn daemon_down_fail_closed_denies() {
    let _guard = serial_lock();
    std::env::set_var("KINTSUGI_SOCKET", "/nonexistent/kintsugi.sock");
    std::env::set_var("KINTSUGI_FAIL_CLOSED", "1");
    let payload = r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#;
    let outcome = handle(payload);
    std::env::remove_var("KINTSUGI_FAIL_CLOSED");
    let body: serde_json::Value = serde_json::from_str(outcome.stdout.as_deref().unwrap()).unwrap();
    assert_eq!(body["hookSpecificOutput"]["permissionDecision"], "deny");
}
