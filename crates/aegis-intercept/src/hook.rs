//! Claude Code hook adapter.
//!
//! Claude Code can run a `PreToolUse` hook before executing a tool. The hook
//! receives a JSON event on stdin and may emit a JSON decision on stdout. This
//! adapter bridges that payload to a [`ProposedCommand`] tagged
//! `agent = "claude-code"`, asks the daemon, and maps the [`Verdict`] back to
//! Claude Code's permission-decision protocol.
//!
//! Mapping:
//! - `Allow` → exit 0, no decision (Claude proceeds normally; the event is logged).
//! - `Deny`  → `permissionDecision: "deny"` with the rule reason.
//! - `Hold`  → `permissionDecision: "ask"` (defer to the user, since a hook
//!   cannot block interactively).
//!
//! Fail-open: a malformed payload, a non-shell tool, or an unreachable daemon
//! never blocks Claude Code (unless `AEGIS_FAIL_CLOSED=1`).

use aegis_core::{shell, Decision, ProposedCommand, Verdict};
use aegis_daemon::Client;
use serde::Deserialize;

/// The subset of the Claude Code hook payload we care about.
#[derive(Debug, Deserialize)]
struct HookInput {
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    tool_name: Option<String>,
    #[serde(default)]
    tool_input: Option<ToolInput>,
}

#[derive(Debug, Deserialize)]
struct ToolInput {
    #[serde(default)]
    command: Option<String>,
}

/// What the adapter decided to print and which code to exit with.
#[derive(Debug, PartialEq, Eq)]
pub struct HookOutcome {
    /// JSON to print on stdout (Claude Code reads this), if any.
    pub stdout: Option<String>,
    /// Process exit code.
    pub exit_code: i32,
}

impl HookOutcome {
    fn allow_silent() -> Self {
        Self {
            stdout: None,
            exit_code: 0,
        }
    }
}

/// Names of the Claude Code tools that run shell commands.
fn is_shell_tool(name: &str) -> bool {
    matches!(name, "Bash" | "Shell" | "bash" | "shell")
}

/// Handle one hook payload, performing the daemon round-trip.
pub fn handle(input: &str) -> HookOutcome {
    let parsed: HookInput = match serde_json::from_str(input) {
        Ok(p) => p,
        Err(e) => {
            // Never block Claude Code on a payload we couldn't parse.
            eprintln!("aegis-hook: could not parse hook payload: {e}");
            return HookOutcome::allow_silent();
        }
    };

    let tool = parsed.tool_name.as_deref().unwrap_or_default();
    if !is_shell_tool(tool) {
        // Not a shell command — outside Aegis's scope for this adapter.
        return HookOutcome::allow_silent();
    }

    let command = match parsed.tool_input.and_then(|t| t.command) {
        Some(c) if !c.trim().is_empty() => c,
        _ => return HookOutcome::allow_silent(),
    };

    let cwd = parsed
        .cwd
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    let argv = shell::split(&command);
    let proposed = ProposedCommand::new("claude-code", cwd, argv, command);

    match Client::send(&proposed) {
        Ok(verdict) => map_verdict(&verdict),
        Err(e) => {
            if fail_closed() {
                eprintln!("aegis-hook: daemon unreachable; denying (fail-closed): {e}");
                deny_output("Aegis daemon unreachable (fail-closed)")
            } else {
                eprintln!("aegis-hook: warning: daemon unreachable; allowing unguarded: {e}");
                HookOutcome::allow_silent()
            }
        }
    }
}

fn map_verdict(verdict: &Verdict) -> HookOutcome {
    match verdict.decision {
        Decision::Allow => HookOutcome::allow_silent(),
        Decision::Deny => deny_output(&verdict.reason),
        Decision::Hold => ask_output(&verdict.reason),
    }
}

fn decision_json(decision: &str, reason: &str) -> String {
    serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    })
    .to_string()
}

fn deny_output(reason: &str) -> HookOutcome {
    HookOutcome {
        stdout: Some(decision_json("deny", reason)),
        exit_code: 0,
    }
}

fn ask_output(reason: &str) -> HookOutcome {
    HookOutcome {
        stdout: Some(decision_json("ask", reason)),
        exit_code: 0,
    }
}

fn fail_closed() -> bool {
    matches!(
        std::env::var("AEGIS_FAIL_CLOSED").ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    )
}

/// Read the hook payload from stdin and emit the outcome.
pub fn run() -> i32 {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    run_io(stdin.lock(), stdout.lock())
}

/// The hook over arbitrary reader/writer (testable).
pub fn run_io<R: std::io::Read, W: std::io::Write>(mut reader: R, mut writer: W) -> i32 {
    let mut input = String::new();
    if let Err(e) = reader.read_to_string(&mut input) {
        eprintln!("aegis-hook: failed to read stdin: {e}");
        return 0; // fail-open
    }
    let outcome = handle(&input);
    if let Some(out) = outcome.stdout {
        let _ = writeln!(writer, "{out}");
    }
    outcome.exit_code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_shell_tool_is_allowed_silently() {
        let payload = r#"{"tool_name":"Edit","tool_input":{"file_path":"x"}}"#;
        assert_eq!(handle(payload), HookOutcome::allow_silent());
    }

    #[test]
    fn malformed_payload_is_allowed_silently() {
        assert_eq!(handle("not json"), HookOutcome::allow_silent());
    }

    #[test]
    fn empty_command_is_allowed_silently() {
        let payload = r#"{"tool_name":"Bash","tool_input":{"command":"   "}}"#;
        assert_eq!(handle(payload), HookOutcome::allow_silent());
    }

    #[test]
    fn run_io_allows_non_shell_tool_silently() {
        let input = br#"{"tool_name":"Edit","tool_input":{"file_path":"x"}}"#;
        let mut out = Vec::new();
        let code = run_io(&input[..], &mut out);
        assert_eq!(code, 0);
        assert!(out.is_empty(), "allow-silent writes nothing");
    }

    #[test]
    fn decision_json_shape_is_correct() {
        let v: serde_json::Value =
            serde_json::from_str(&deny_output("nope").stdout.unwrap()).unwrap();
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
        assert_eq!(v["hookSpecificOutput"]["permissionDecisionReason"], "nope");
        assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    }
}
