//! P0.6 acceptance: an MCP `tools/call` to `aegis-exec` runs the command and
//! logs it tagged with the calling agent.
#![cfg(unix)]

use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;

use aegis_core::{Decision, EventLog};
use aegis_daemon::{Daemon, Server};
use aegis_intercept::mcp::handle_message;
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
    std::env::set_var("AEGIS_SOCKET", tmp.path().join("aegis.sock"));
    std::env::set_var("AEGIS_DB", tmp.path().join("events.db"));
    let db = tmp.path().join("events.db");

    let db_for_thread = db.clone();
    let server = Server::bind().unwrap();
    let handle = thread::spawn(move || {
        let daemon = Daemon::open(&db_for_thread).unwrap();
        server.serve_n(requests, |cmd| daemon.handle(cmd)).unwrap();
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
fn aegis_exec_runs_command_and_logs_with_agent() {
    let mut h = start(1);
    let work = h.tmp.path().to_string_lossy().to_string();

    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "aegis-exec",
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
fn aegis_exec_reports_nonzero_exit_as_error() {
    let mut h = start(1);
    let work = h.tmp.path().to_string_lossy().to_string();

    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 8,
        "method": "tools/call",
        "params": {
            "name": "aegis-exec",
            "arguments": { "command": "exit 3", "cwd": work }
        }
    })
    .to_string();

    let resp: Value = serde_json::from_str(&handle_message(&req).unwrap()).unwrap();
    assert_eq!(resp["result"]["isError"], true);
    assert!(resp["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("exit code: 3"));

    h.join();
    // The command (agent defaults to "mcp") is still recorded.
    let log = EventLog::open(&h.db).unwrap();
    assert_eq!(log.tail(1).unwrap()[0].agent, "mcp");
}
