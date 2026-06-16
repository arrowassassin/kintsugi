//! P0.6 acceptance: an MCP `tools/call` to `kintsugi-exec` runs the command and
//! logs it tagged with the calling agent.
#![cfg(unix)]

use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;

use kintsugi_core::{Decision, EventLog};
use kintsugi_daemon::{Daemon, Server};
use kintsugi_intercept::mcp::handle_message;
use serde_json::Value;

fn serial_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

struct Harness {
    _guard: MutexGuard<'static, ()>,
    tmp: tempfile::TempDir,
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
        tmp,
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
fn kintsugi_exec_runs_command_and_logs_with_agent() {
    let mut h = start(1);
    let work = h.tmp.path().to_string_lossy().to_string();

    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "kintsugi-exec",
            "arguments": {
                "command": "echo hello-mcp",
                "cwd": work,
                "agent": "qwen"
            }
        }
    })
    .to_string();

    let resp: Value = serde_json::from_str(&handle_message(&req).unwrap()).unwrap();
    assert_eq!(resp["id"], 7);
    assert_eq!(resp["result"]["isError"], false);
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("hello-mcp"),
        "tool output should include command stdout: {text}"
    );
    assert!(text.contains("exit code: 0"));

    h.join();

    let log = EventLog::open(&h.db).unwrap();
    let tail = log.tail(10).unwrap();
    assert_eq!(tail.len(), 1);
    assert_eq!(tail[0].agent, "qwen");
    assert_eq!(tail[0].command, "echo hello-mcp");
    assert_eq!(tail[0].decision, Decision::Allow);
    assert!(log.verify_chain().unwrap().is_intact());
}

#[test]
fn kintsugi_exec_reports_nonzero_exit_as_error() {
    let mut h = start(1);
    let work = h.tmp.path().to_string_lossy().to_string();

    // A safe command (grep) that exits non-zero: allowed, runs, reports the code.
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 8,
        "method": "tools/call",
        "params": {
            "name": "kintsugi-exec",
            "arguments": { "command": "grep __no_such_token__ /dev/null", "cwd": work }
        }
    })
    .to_string();

    let resp: Value = serde_json::from_str(&handle_message(&req).unwrap()).unwrap();
    assert_eq!(resp["result"]["isError"], true);
    assert!(resp["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("exit code: 1"));

    h.join();
    // The command (agent defaults to "mcp") is still recorded.
    let log = EventLog::open(&h.db).unwrap();
    assert_eq!(log.tail(1).unwrap()[0].agent, "mcp");
}

#[test]
fn kintsugi_exec_blocks_catastrophic_without_running() {
    let mut h = start(1);
    let work = h.tmp.path().join("guard");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(work.join("keep"), b"x").unwrap();
    let work_s = work.to_string_lossy().to_string();

    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "tools/call",
        "params": {
            "name": "kintsugi-exec",
            "arguments": { "command": "rm -rf .", "cwd": work_s, "agent": "codex" }
        }
    })
    .to_string();

    let resp: Value = serde_json::from_str(&handle_message(&req).unwrap()).unwrap();
    assert_eq!(
        resp["result"]["isError"], true,
        "catastrophic must be blocked"
    );
    assert!(
        work.join("keep").exists(),
        "the file must survive — command not run"
    );

    h.join();
    let log = EventLog::open(&h.db).unwrap();
    let last = log.tail(1).unwrap().pop().unwrap();
    assert_eq!(last.agent, "codex");
    assert_eq!(last.decision, Decision::Hold);
}

#[test]
fn held_command_runs_after_human_approves_in_band() {
    // The whole point of the queue: agent calls → held → a human approves from
    // elsewhere → the same MCP call proceeds and runs the command.
    let _guard = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("KINTSUGI_SOCKET", tmp.path().join("kintsugi.sock"));
    std::env::set_var("KINTSUGI_DB", tmp.path().join("events.db"));
    std::env::set_var("KINTSUGI_CONFIG", tmp.path().join("none.toml"));
    std::env::set_var("KINTSUGI_APPROVAL_TIMEOUT", "10"); // enable in-band wait

    let work = tmp.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let victim = work.join("tmpfile");
    std::fs::write(&victim, b"bye").unwrap();
    let work_s = work.to_string_lossy().to_string();

    // Daemon serving in the background (infinite; the process ends with the test).
    let server = Server::bind().unwrap();
    let db = tmp.path().join("events.db");
    thread::spawn(move || {
        let daemon = Daemon::open(&db).unwrap();
        server.serve(|req| daemon.handle_request(req)).unwrap();
    });

    // Approver: once something is pending, approve it (retry until it sticks —
    // the daemon is single-threaded so a concurrent connect may transiently fail).
    thread::spawn(|| loop {
        if let Ok(items) = kintsugi_daemon::Client::list_pending() {
            if let Some(it) = items.first() {
                if kintsugi_daemon::Client::approve(&it.command.id.to_string()).is_ok() {
                    break;
                }
            }
        }
        thread::sleep(std::time::Duration::from_millis(50));
    });

    // `rm tmpfile` is ambiguous → held → waits → approved → runs.
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 21,
        "method": "tools/call",
        "params": { "name": "kintsugi-exec", "arguments": { "command": "rm tmpfile", "cwd": work_s } }
    })
    .to_string();

    let resp: Value = serde_json::from_str(&handle_message(&req).unwrap()).unwrap();
    assert_eq!(
        resp["result"]["isError"], false,
        "approved command should run"
    );
    assert!(
        !victim.exists(),
        "the file should be deleted after approval"
    );

    std::env::remove_var("KINTSUGI_APPROVAL_TIMEOUT");
}

#[test]
fn unknown_tool_name_is_an_error() {
    let req =
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"nope","arguments":{}}}"#;
    let resp: Value = serde_json::from_str(&handle_message(req).unwrap()).unwrap();
    assert_eq!(resp["error"]["code"], -32602);
}

#[test]
fn ping_is_answered() {
    let req = r#"{"jsonrpc":"2.0","id":5,"method":"ping"}"#;
    let resp: Value = serde_json::from_str(&handle_message(req).unwrap()).unwrap();
    assert!(resp["result"].is_object());
}
