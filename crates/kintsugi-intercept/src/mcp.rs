//! The `kintsugi-exec` MCP server.
//!
//! Tool-calling agents (Cursor CLI, Codex CLI, Qwen Code, Gemini CLI, and any
//! custom MCP client) that speak the Model Context Protocol can call the
//! `kintsugi-exec` tool to run a shell command *through*
//! Kintsugi instead of shelling out raw. Each call is normalized to a
//! [`ProposedCommand`], sent to the daemon, and — on allow — executed, with the
//! command's output returned to the agent. Every call is recorded.
//!
//! Transport: newline-delimited JSON-RPC 2.0 over stdio (the MCP stdio
//! transport). Implemented by hand to avoid pulling an MCP framework dependency.

use std::path::PathBuf;
use std::process::Command;

use kintsugi_core::{shell, Decision, ProposedCommand};
use kintsugi_daemon::Client;
use serde_json::{json, Value};

/// Default protocol version advertised when the client doesn't pin one.
const DEFAULT_PROTOCOL_VERSION: &str = "2024-11-05";
/// Tool name agents call.
pub const TOOL_NAME: &str = "kintsugi-exec";

/// Handle one JSON-RPC message line. Returns the response line, or `None` for
/// notifications (which get no reply).
pub fn handle_message(line: &str) -> Option<String> {
    let req: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            return Some(error_response(
                Value::Null,
                -32700,
                &format!("parse error: {e}"),
            ));
        }
    };

    let id = req.get("id").cloned();
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");

    // Notifications (no id) are acknowledged silently (`?` yields None).
    let id = id?;

    match method {
        "initialize" => Some(initialize_response(id, &req)),
        "tools/list" => Some(tools_list_response(id)),
        "tools/call" => Some(tools_call_response(id, &req)),
        "ping" => Some(result_response(id, json!({}))),
        other => Some(error_response(
            id,
            -32601,
            &format!("method not found: {other}"),
        )),
    }
}

fn initialize_response(id: Value, req: &Value) -> String {
    let protocol = req
        .get("params")
        .and_then(|p| p.get("protocolVersion"))
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_PROTOCOL_VERSION)
        .to_string();

    result_response(
        id,
        json!({
            "protocolVersion": protocol,
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "kintsugi-exec", "version": crate::VERSION },
            "instructions": "Run shell commands via the kintsugi-exec tool so Kintsugi can guard and record them."
        }),
    )
}

fn tools_list_response(id: Value) -> String {
    result_response(
        id,
        json!({
            "tools": [{
                "name": TOOL_NAME,
                "description": "Run a shell command guarded and recorded by Kintsugi. \
                    Use this instead of shelling out directly so dangerous commands \
                    are held and everything is logged to the tamper-evident audit log.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": { "type": "string", "description": "The shell command to run." },
                        "cwd": { "type": "string", "description": "Working directory (optional)." },
                        "agent": { "type": "string", "description": "Calling agent name, e.g. 'qwen' or 'codex' (optional)." },
                        "session": { "type": "string", "description": "Session id for grouping in the timeline (optional)." }
                    },
                    "required": ["command"]
                }
            }]
        }),
    )
}

fn tools_call_response(id: Value, req: &Value) -> String {
    let params = req.get("params").cloned().unwrap_or(Value::Null);
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    if name != TOOL_NAME {
        return error_response(id, -32602, &format!("unknown tool: {name}"));
    }
    let args = params.get("arguments").cloned().unwrap_or(json!({}));
    let command = match args.get("command").and_then(Value::as_str) {
        Some(c) if !c.trim().is_empty() => c.to_string(),
        _ => return error_response(id, -32602, "missing required argument: command"),
    };
    let agent = args
        .get("agent")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("mcp")
        .to_string();
    let cwd = args
        .get("cwd")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    // One session per server process (a client connection), overridable per call.
    let session = args
        .get("session")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("mcp-{}", std::process::id()));

    let outcome = exec_through_kintsugi(&agent, cwd, &session, &command);
    result_response(
        id,
        json!({
            "content": [{ "type": "text", "text": outcome.text }],
            "isError": outcome.is_error,
        }),
    )
}

struct ToolOutcome {
    text: String,
    is_error: bool,
}

/// The full guarded-execution path: propose → decide → (allow) run → report.
fn exec_through_kintsugi(agent: &str, cwd: PathBuf, session: &str, command: &str) -> ToolOutcome {
    let argv = shell::split(command);
    let proposed = ProposedCommand::new(agent, cwd.clone(), argv, command.to_string())
        .with_session(Some(session.to_string()));

    let id = proposed.id.to_string();
    let decision = match Client::send(&proposed) {
        // A held command waits (bounded) for a human to approve/deny so the agent
        // can proceed in the same call. See `approval_timeout`.
        Ok(verdict) if verdict.decision == Decision::Hold => wait_for_approval(&id),
        Ok(verdict) => verdict.decision,
        Err(e) => {
            // Daemon down: locally classify so a catastrophic command is still
            // refused (fail-closed for the hard floor), even though it can't be
            // recorded. Non-catastrophic honors the fail-open default.
            if kintsugi_core::classify(&proposed).class == kintsugi_core::Class::Catastrophic {
                return ToolOutcome {
                    text: format!(
                        "Kintsugi daemon unreachable; catastrophic command refused (fail-closed): {e}"
                    ),
                    is_error: true,
                };
            }
            if fail_closed() {
                return ToolOutcome {
                    text: format!(
                        "Kintsugi daemon unreachable; refusing to run (fail-closed): {e}"
                    ),
                    is_error: true,
                };
            }
            // Fail-open: run unguarded but say so.
            eprintln!("kintsugi-mcp: warning: daemon unreachable; running unguarded: {e}");
            Decision::Allow
        }
    };

    let short = &id[..id.len().min(8)];
    match decision {
        Decision::Allow => run_command(&cwd, command),
        Decision::Deny => ToolOutcome {
            text: format!("Kintsugi blocked this command: {command}"),
            is_error: true,
        },
        Decision::Hold => ToolOutcome {
            text: format!(
                "Kintsugi is holding this command for human approval (id {short}). It was not run. \
                 A human can approve it with `kintsugi approve {short}` (then re-run), or you can \
                 proceed with a different approach."
            ),
            is_error: true,
        },
    }
}

/// How long the MCP tool waits for a human to resolve a held command, in seconds.
/// `0` (default) means do not wait — return "pending" immediately. Set
/// `KINTSUGI_APPROVAL_TIMEOUT` to enable in-band wait-for-approval.
fn approval_timeout() -> std::time::Duration {
    let secs = std::env::var("KINTSUGI_APPROVAL_TIMEOUT")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    std::time::Duration::from_secs(secs)
}

/// Poll the daemon until a held command is approved/denied, the deadline passes,
/// or it leaves the queue. Returns the resulting decision (`Hold` = still pending).
fn wait_for_approval(id: &str) -> Decision {
    let deadline = std::time::Instant::now() + approval_timeout();
    // Tolerate a few transient connection blips (the daemon is single-threaded and
    // a concurrent connect can momentarily fail), but give up fast if the daemon
    // is actually gone rather than busy-polling a dead socket for the whole timeout.
    let mut consecutive_errors = 0u32;
    loop {
        match Client::pending_status(id) {
            Ok(s) if s == "approved" => return Decision::Allow,
            Ok(s) if s == "denied" => return Decision::Deny,
            Ok(s) if s == "gone" => return Decision::Hold, // resolved/removed elsewhere
            Ok(_) => consecutive_errors = 0,               // "pending" — keep waiting
            Err(_) => {
                consecutive_errors += 1;
                if consecutive_errors >= 5 {
                    return Decision::Hold; // daemon unreachable; don't hang
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            return Decision::Hold;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// Run the command in a shell, capturing output.
fn run_command(cwd: &PathBuf, command: &str) -> ToolOutcome {
    #[cfg(unix)]
    let mut cmd = {
        let mut c = Command::new("sh");
        c.arg("-c").arg(command);
        c
    };
    #[cfg(not(unix))]
    let mut cmd = {
        let mut c = Command::new("cmd");
        c.arg("/C").arg(command);
        c
    };
    cmd.current_dir(cwd);

    match cmd.output() {
        Ok(out) => {
            let code = out.status.code().unwrap_or(-1);
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            let mut text = format!("exit code: {code}\n");
            if !stdout.is_empty() {
                text.push_str("stdout:\n");
                text.push_str(&stdout);
                if !stdout.ends_with('\n') {
                    text.push('\n');
                }
            }
            if !stderr.is_empty() {
                text.push_str("stderr:\n");
                text.push_str(&stderr);
            }
            ToolOutcome {
                text: text.trim_end().to_string(),
                is_error: !out.status.success(),
            }
        }
        Err(e) => ToolOutcome {
            text: format!("failed to run command: {e}"),
            is_error: true,
        },
    }
}

fn fail_closed() -> bool {
    matches!(
        std::env::var("KINTSUGI_FAIL_CLOSED").ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    )
}

fn result_response(id: Value, result: Value) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string()
}

fn error_response(id: Value, code: i64, message: &str) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }).to_string()
}

/// Run the MCP server: read JSON-RPC lines from stdin, write responses to stdout.
pub fn run() -> anyhow::Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    run_io(stdin.lock(), stdout.lock())
}

/// The server loop over arbitrary reader/writer (testable).
pub fn run_io<R: std::io::BufRead, W: std::io::Write>(
    reader: R,
    mut writer: W,
) -> anyhow::Result<()> {
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Some(resp) = handle_message(&line) {
            writeln!(writer, "{resp}")?;
            writer.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_reports_server_info() {
        let req = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#;
        let resp: Value = serde_json::from_str(&handle_message(req).unwrap()).unwrap();
        assert_eq!(resp["id"], 1);
        assert_eq!(resp["result"]["serverInfo"]["name"], "kintsugi-exec");
        // Echoes the client's requested protocol version.
        assert_eq!(resp["result"]["protocolVersion"], "2025-06-18");
    }

    #[test]
    fn tools_list_includes_kintsugi_exec() {
        let req = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
        let resp: Value = serde_json::from_str(&handle_message(req).unwrap()).unwrap();
        let tools = resp["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], TOOL_NAME);
        assert!(tools[0]["inputSchema"]["properties"]["command"].is_object());
    }

    #[test]
    fn notification_gets_no_response() {
        let note = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        assert!(handle_message(note).is_none());
    }

    #[test]
    fn unknown_method_is_an_error() {
        let req = r#"{"jsonrpc":"2.0","id":9,"method":"does/not/exist"}"#;
        let resp: Value = serde_json::from_str(&handle_message(req).unwrap()).unwrap();
        assert_eq!(resp["error"]["code"], -32601);
    }

    #[test]
    fn call_without_command_is_an_error() {
        let req = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"kintsugi-exec","arguments":{}}}"#;
        let resp: Value = serde_json::from_str(&handle_message(req).unwrap()).unwrap();
        assert_eq!(resp["error"]["code"], -32602);
    }

    #[test]
    fn run_io_responds_to_requests_and_skips_notifications() {
        let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n",
            "\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n",
        );
        let mut out = Vec::new();
        run_io(std::io::Cursor::new(input), &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        // Two responses (initialize, tools/list); the notification yields none.
        assert_eq!(text.lines().count(), 2);
        assert!(text.contains("serverInfo"));
        assert!(text.contains(TOOL_NAME));
    }
}
