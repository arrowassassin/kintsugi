//! Per-CLI hook dialects.
//!
//! Every supported agent CLI exposes a "run a command before the tool executes,
//! read a decision back" hook — but each speaks a slightly different protocol on
//! stdin and stdout. A [`Dialect`] knows how to (a) parse one CLI's PreTool
//! payload into a normalized [`Shell`] command and (b) serialize the daemon's
//! [`Verdict`] back into that CLI's decision protocol.
//!
//! The decision *policy* (what Allow/Deny/Hold means, and that a catastrophic
//! hold becomes a deny) lives in [`crate::hook`] and is identical for every
//! dialect — only the wire format differs here. This keeps the security spine in
//! one place and the per-CLI glue mechanical.
//!
//! Protocols, as researched against each CLI's docs:
//! - Claude Code / Qwen Code / Codex CLI: `{tool_name, tool_input.command}` in;
//!   `{hookSpecificOutput:{permissionDecision: allow|deny|ask, …}}` out.
//! - Gemini CLI: `{tool_name, tool_input.command}` in; `{decision: allow|deny}`
//!   out (no native "ask" — an ambiguous hold is mapped to deny).
//! - GitHub Copilot CLI: `{toolName, toolArgs.command}` in (camelCase);
//!   `{permissionDecision: allow|deny|ask, permissionDecisionReason}` out.
//! - Cursor CLI: `{command, cwd}` in (beforeShellExecution); `{permission:
//!   allow|deny|ask, userMessage, agentMessage}` out.
//! - OpenCode: no external-command hook — a bundled JS plugin bridges to us with
//!   a simple `{command, cwd}` in / `{decision: allow|deny|ask, reason}` out.
//! - Google Antigravity: plugin `PreToolUse` hook (matcher `run_command`).
//!   `{toolCall:{name, arguments:{CommandLine, Cwd}}, conversationId}` in
//!   (PascalCase argument keys); `{decision: allow|deny, reason}` out — no native
//!   ask, so an ambiguous hold is mapped to deny.

use std::path::PathBuf;

use kintsugi_core::{Class, Decision, Verdict};
use serde::Deserialize;

/// Which agent CLI's hook protocol to speak.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dialect {
    Claude,
    Qwen,
    Gemini,
    Copilot,
    Cursor,
    OpenCode,
    Codex,
    Antigravity,
}

/// A normalized shell command extracted from a hook payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shell {
    pub command: String,
    pub cwd: PathBuf,
    pub session_id: Option<String>,
}

/// A non-shell, content-ingesting tool call surfaced for provenance observation
/// (a `WebFetch`, `Read`, web-search, MCP call). The raw `input` object is handed
/// to [`crate::observe::classify_tool_ingest`]; we never read the *result* bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentCall {
    pub tool: String,
    pub input: serde_json::Value,
    pub cwd: PathBuf,
    pub session_id: Option<String>,
}

/// Result of parsing a hook payload.
#[derive(Debug, PartialEq, Eq)]
pub enum Parsed {
    /// A shell command to send to the daemon.
    Shell(Shell),
    /// A well-formed payload that isn't a shell tool call — out of scope, pass.
    NotShell,
    /// An unparseable payload — fail open (never block on our own parse bug).
    Bad(String),
}

/// The resolved, dialect-independent decision the daemon's verdict maps to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    Allow,
    Deny(String),
    Ask(String),
}

/// What the adapter prints on stdout and exits with for one payload.
#[derive(Debug, PartialEq, Eq)]
pub struct HookOutcome {
    pub stdout: Option<String>,
    pub exit_code: i32,
}

impl HookOutcome {
    /// Emit nothing, exit 0 — "Kintsugi has no opinion, use your default flow."
    pub fn silent() -> Self {
        Self {
            stdout: None,
            exit_code: 0,
        }
    }
    fn json(value: serde_json::Value) -> Self {
        Self {
            stdout: Some(value.to_string()),
            exit_code: 0,
        }
    }
}

impl Dialect {
    /// Map an `--agent` value to a dialect. Accepts the CLI's stable id.
    pub fn from_agent(s: &str) -> Option<Self> {
        Some(match s {
            "claude" | "claude-code" => Dialect::Claude,
            "qwen" => Dialect::Qwen,
            "gemini" => Dialect::Gemini,
            "copilot" => Dialect::Copilot,
            "cursor" => Dialect::Cursor,
            "opencode" => Dialect::OpenCode,
            "codex" => Dialect::Codex,
            "antigravity" => Dialect::Antigravity,
            _ => return None,
        })
    }

    /// The `agent` tag stamped onto the [`kintsugi_core::ProposedCommand`] so the
    /// log and TUI attribute the command to the right CLI.
    pub fn agent_id(self) -> &'static str {
        match self {
            Dialect::Claude => "claude-code",
            Dialect::Qwen => "qwen",
            Dialect::Gemini => "gemini",
            Dialect::Copilot => "copilot",
            Dialect::Cursor => "cursor",
            Dialect::OpenCode => "opencode",
            Dialect::Codex => "codex",
            Dialect::Antigravity => "antigravity",
        }
    }

    /// Does this CLI have a native "ask the user" decision? If not, an ambiguous
    /// hold is mapped to deny — safe per the monotonic-caution rule (the model
    /// may only add caution, never remove it).
    fn supports_ask(self) -> bool {
        // Gemini's decision enum is allow/deny/block, and Antigravity's hook
        // decision is allow/deny — neither has an interactive ask.
        !matches!(self, Dialect::Gemini | Dialect::Antigravity)
    }

    /// Parse one CLI's hook payload into a normalized command.
    pub fn parse(self, input: &str) -> Parsed {
        match self {
            Dialect::Claude | Dialect::Qwen | Dialect::Gemini | Dialect::Codex => {
                self.parse_tool_style(input)
            }
            Dialect::Copilot => parse_copilot(input),
            Dialect::Cursor | Dialect::OpenCode => parse_flat(input),
            Dialect::Antigravity => parse_antigravity(input),
        }
    }

    /// Extract a non-shell content-tool call for provenance observation, if this
    /// payload is one. Tolerant: returns `None` (rather than erroring) for shell
    /// tools, unparseable input, or dialects that only ever carry shell commands
    /// (Cursor / OpenCode). Observation never blocks, so a miss is harmless.
    pub fn parse_content(self, input: &str) -> Option<ContentCall> {
        let v: serde_json::Value = serde_json::from_str(input).ok()?;
        let get_str = |val: &serde_json::Value, k: &str| {
            val.get(k).and_then(|s| s.as_str()).map(String::from)
        };
        let (tool, args, cwd, session) = match self {
            Dialect::Claude | Dialect::Qwen | Dialect::Gemini | Dialect::Codex => (
                get_str(&v, "tool_name")?,
                v.get("tool_input")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
                get_str(&v, "cwd"),
                get_str(&v, "session_id"),
            ),
            Dialect::Copilot => (
                get_str(&v, "toolName")?,
                v.get("toolArgs")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
                get_str(&v, "cwd"),
                get_str(&v, "sessionId"),
            ),
            Dialect::Antigravity => {
                let tc = v.get("toolCall")?;
                let args = tc
                    .get("arguments")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                let cwd = args.get("Cwd").and_then(|s| s.as_str()).map(String::from);
                (
                    get_str(tc, "name")?,
                    args,
                    cwd,
                    get_str(&v, "conversationId"),
                )
            }
            // These dialects' hooks only ever deliver a shell command — no content
            // tool to observe through this surface.
            Dialect::Cursor | Dialect::OpenCode => return None,
        };
        Some(ContentCall {
            tool,
            input: args,
            cwd: cwd_or_current(cwd),
            session_id: session,
        })
    }

    /// Claude/Qwen/Gemini share `{tool_name, tool_input:{command}}`.
    fn parse_tool_style(self, input: &str) -> Parsed {
        let p: ToolStyle = match serde_json::from_str(input) {
            Ok(p) => p,
            Err(e) => return Parsed::Bad(e.to_string()),
        };
        let tool = p.tool_name.as_deref().unwrap_or_default();
        if !self.is_shell_tool(tool) {
            return Parsed::NotShell;
        }
        match p.tool_input.and_then(|t| t.command) {
            Some(c) if !c.trim().is_empty() => Parsed::Shell(Shell {
                command: c,
                cwd: cwd_or_current(p.cwd),
                session_id: p.session_id,
            }),
            _ => Parsed::NotShell,
        }
    }

    /// Is `name` this dialect's shell tool? The canonical name delivered in the
    /// payload differs per CLI; we also accept the cross-CLI aliases so a
    /// version that reports a different label still matches.
    fn is_shell_tool(self, name: &str) -> bool {
        match self {
            // Claude reports Bash; accept the lowercase/Shell variants too.
            Dialect::Claude => matches!(name, "Bash" | "Shell" | "bash" | "shell"),
            // Qwen's canonical name is run_shell_command, with Claude-compat
            // aliases Bash/Shell/ShellTool.
            Dialect::Qwen => matches!(
                name,
                "run_shell_command" | "Bash" | "Shell" | "ShellTool" | "bash" | "shell"
            ),
            // Gemini only ever reports run_shell_command.
            Dialect::Gemini => matches!(name, "run_shell_command" | "Shell" | "shell"),
            // Codex modeled its hooks on Claude Code; its shell tool is Bash.
            Dialect::Codex => matches!(name, "Bash" | "Shell" | "bash" | "shell"),
            _ => false,
        }
    }

    /// Serialize a resolved decision into this CLI's stdout protocol.
    pub fn format(self, resolved: &Resolved) -> HookOutcome {
        // Downgrade Ask -> Deny for dialects without a native ask.
        let resolved = match (resolved, self.supports_ask()) {
            (Resolved::Ask(reason), false) => &Resolved::Deny(reason.clone()),
            (other, _) => other,
        };
        match self {
            Dialect::Claude | Dialect::Qwen | Dialect::Codex => format_claude_style(resolved),
            Dialect::Gemini => format_gemini(resolved),
            Dialect::Copilot => format_copilot(resolved),
            Dialect::Cursor => format_cursor(resolved),
            Dialect::OpenCode => format_opencode(resolved),
            Dialect::Antigravity => format_antigravity(resolved),
        }
    }

    /// The "allow / no opinion" output used on the fail-open path and for SAFE
    /// commands. Most CLIs treat empty output as "proceed normally"; Cursor's
    /// beforeShellExecution gate is answered with an explicit allow.
    pub fn pass(self) -> HookOutcome {
        match self {
            Dialect::Cursor => format_cursor(&Resolved::Allow),
            // Antigravity's contract is "read a JSON decision object from stdout",
            // so answer its gate with an explicit allow rather than silence.
            Dialect::Antigravity => format_antigravity(&Resolved::Allow),
            _ => HookOutcome::silent(),
        }
    }
}

/// The message Kintsugi surfaces through the agent's OWN approval prompt when it
/// holds an ambiguous command. It names Kintsugi and the rule that fired, and
/// folds in the local model's plain-English summary (and risk score) when the
/// model scored the command — so the human decides with context, not a bare
/// yes/no. The verbatim command is shown by the agent's prompt itself.
fn flag_reason(verdict: &Verdict) -> String {
    let mut msg = format!(
        "Kintsugi flagged this as {} (rule: {})",
        verdict.class, verdict.reason
    );
    if let Some(summary) = verdict.summary.as_deref().filter(|s| !s.is_empty()) {
        msg.push_str(" — ");
        msg.push_str(summary);
    }
    if let Some(risk) = verdict.risk {
        msg.push_str(&format!(" [risk {risk}/100]"));
    }
    msg.push_str(". Approve only if you intended this.");
    msg
}

/// Map a daemon verdict to the dialect-independent decision.
///
/// A catastrophic *hold* becomes a deny, not an ask: letting the CLI's own UI
/// one-click "allow" it would run it with no Kintsugi snapshot, voiding the
/// reversibility guarantee. Only ambiguous holds become an ask — and that ask
/// carries Kintsugi's flag + the model's summary so the human understands it.
pub fn resolve(verdict: &Verdict) -> Resolved {
    match verdict.decision {
        Decision::Allow => Resolved::Allow,
        Decision::Deny => Resolved::Deny(verdict.reason.clone()),
        Decision::Hold if verdict.class == Class::Catastrophic => {
            Resolved::Deny(verdict.reason.clone())
        }
        Decision::Hold => Resolved::Ask(flag_reason(verdict)),
    }
}

// ----- payload structs -------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ToolStyle {
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    tool_name: Option<String>,
    #[serde(default)]
    tool_input: Option<CmdInput>,
}

#[derive(Debug, Deserialize)]
struct CmdInput {
    #[serde(default)]
    command: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CopilotStyle {
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default, rename = "sessionId")]
    session_id: Option<String>,
    #[serde(default, rename = "toolName")]
    tool_name: Option<String>,
    #[serde(default, rename = "toolArgs")]
    tool_args: Option<CmdInput>,
}

#[derive(Debug, Deserialize)]
struct FlatStyle {
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    conversation_id: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
}

fn parse_copilot(input: &str) -> Parsed {
    let p: CopilotStyle = match serde_json::from_str(input) {
        Ok(p) => p,
        Err(e) => return Parsed::Bad(e.to_string()),
    };
    // Copilot's shell tool is named "bash" (and "powershell" on Windows).
    let tool = p.tool_name.as_deref().unwrap_or_default();
    if !matches!(tool, "bash" | "shell") {
        return Parsed::NotShell;
    }
    match p.tool_args.and_then(|t| t.command) {
        Some(c) if !c.trim().is_empty() => Parsed::Shell(Shell {
            command: c,
            cwd: cwd_or_current(p.cwd),
            session_id: p.session_id,
        }),
        _ => Parsed::NotShell,
    }
}

/// Antigravity's `PreToolUse` payload: the command lives in
/// `toolCall.arguments.CommandLine` (PascalCase), the tool name in
/// `toolCall.name`, and the session in `conversationId`.
#[derive(Debug, Deserialize)]
struct AntigravityStyle {
    #[serde(default, rename = "toolCall")]
    tool_call: Option<AntigravityToolCall>,
    #[serde(default, rename = "conversationId")]
    conversation_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AntigravityToolCall {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    arguments: Option<AntigravityArgs>,
}

#[derive(Debug, Deserialize)]
struct AntigravityArgs {
    #[serde(default, rename = "CommandLine")]
    command_line: Option<String>,
    #[serde(default, rename = "Cwd")]
    cwd: Option<String>,
}

fn parse_antigravity(input: &str) -> Parsed {
    let p: AntigravityStyle = match serde_json::from_str(input) {
        Ok(p) => p,
        Err(e) => return Parsed::Bad(e.to_string()),
    };
    let Some(tc) = p.tool_call else {
        return Parsed::NotShell;
    };
    // Antigravity's shell tool is `run_command`; accept the common aliases too.
    let tool = tc.name.as_deref().unwrap_or_default();
    if !matches!(
        tool,
        "run_command" | "run_shell_command" | "Bash" | "bash" | "shell"
    ) {
        return Parsed::NotShell;
    }
    let Some(args) = tc.arguments else {
        return Parsed::NotShell;
    };
    match args.command_line {
        Some(c) if !c.trim().is_empty() => Parsed::Shell(Shell {
            command: c,
            cwd: cwd_or_current(args.cwd),
            session_id: p.conversation_id,
        }),
        _ => Parsed::NotShell,
    }
}

fn parse_flat(input: &str) -> Parsed {
    let p: FlatStyle = match serde_json::from_str(input) {
        Ok(p) => p,
        Err(e) => return Parsed::Bad(e.to_string()),
    };
    match p.command {
        Some(c) if !c.trim().is_empty() => Parsed::Shell(Shell {
            command: c,
            cwd: cwd_or_current(p.cwd),
            session_id: p.session_id.or(p.conversation_id),
        }),
        _ => Parsed::NotShell,
    }
}

fn cwd_or_current(cwd: Option<String>) -> PathBuf {
    cwd.filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default())
}

// ----- output formats --------------------------------------------------------

/// Claude Code & Qwen Code: `hookSpecificOutput.permissionDecision`.
fn format_claude_style(resolved: &Resolved) -> HookOutcome {
    let (decision, reason) = match resolved {
        Resolved::Allow => return HookOutcome::silent(),
        Resolved::Deny(r) => ("deny", r),
        Resolved::Ask(r) => ("ask", r),
    };
    HookOutcome::json(serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }))
}

/// Gemini CLI: `{decision: allow|deny, reason}` (no ask — already downgraded).
fn format_gemini(resolved: &Resolved) -> HookOutcome {
    match resolved {
        Resolved::Allow => HookOutcome::silent(),
        Resolved::Deny(r) => HookOutcome::json(serde_json::json!({
            "decision": "deny",
            "reason": r,
            "systemMessage": format!("Kintsugi: {r}"),
        })),
        // Unreachable: Gemini doesn't support ask, so resolve→format downgrades
        // it to Deny before we get here. Treat defensively as a deny.
        Resolved::Ask(r) => HookOutcome::json(serde_json::json!({
            "decision": "deny",
            "reason": r,
        })),
    }
}

/// GitHub Copilot CLI: flat `{permissionDecision, permissionDecisionReason}`.
fn format_copilot(resolved: &Resolved) -> HookOutcome {
    let (decision, reason) = match resolved {
        Resolved::Allow => return HookOutcome::silent(),
        Resolved::Deny(r) => ("deny", r),
        Resolved::Ask(r) => ("ask", r),
    };
    HookOutcome::json(serde_json::json!({
        "permissionDecision": decision,
        "permissionDecisionReason": reason,
    }))
}

/// Cursor CLI: `{permission, userMessage, agentMessage}`. We emit both camelCase
/// and snake_case message keys because Cursor's docs are inconsistent across
/// versions about which it reads; `permission` is the only load-bearing field.
fn format_cursor(resolved: &Resolved) -> HookOutcome {
    let (permission, reason) = match resolved {
        Resolved::Allow => ("allow", None),
        Resolved::Deny(r) => ("deny", Some(r)),
        Resolved::Ask(r) => ("ask", Some(r)),
    };
    let mut obj = serde_json::json!({ "permission": permission });
    if let Some(r) = reason {
        let map = obj.as_object_mut().unwrap();
        map.insert(
            "userMessage".into(),
            serde_json::json!(format!("Kintsugi: {r}")),
        );
        map.insert("agentMessage".into(), serde_json::json!(r));
        map.insert(
            "user_message".into(),
            serde_json::json!(format!("Kintsugi: {r}")),
        );
        map.insert("agent_message".into(), serde_json::json!(r));
    }
    HookOutcome::json(obj)
}

/// OpenCode bridge: `{decision: allow|deny|ask, reason}`. The bundled JS plugin
/// reads this and throws (aborting the tool call) on deny/ask.
fn format_opencode(resolved: &Resolved) -> HookOutcome {
    let (decision, reason) = match resolved {
        Resolved::Allow => ("allow", String::new()),
        Resolved::Deny(r) => ("deny", r.clone()),
        Resolved::Ask(r) => ("ask", r.clone()),
    };
    HookOutcome::json(serde_json::json!({ "decision": decision, "reason": reason }))
}

/// Google Antigravity: `{decision: allow|deny, reason}` (no ask — already
/// downgraded). Allow is explicit (its contract expects a decision object).
fn format_antigravity(resolved: &Resolved) -> HookOutcome {
    let (decision, reason) = match resolved {
        Resolved::Allow => ("allow", None),
        Resolved::Deny(r) => ("deny", Some(r)),
        // Unreachable: Antigravity has no ask, so resolve→format downgrades it to
        // Deny before we get here. Treat defensively as a deny.
        Resolved::Ask(r) => ("deny", Some(r)),
    };
    let mut obj = serde_json::json!({ "decision": decision });
    if let Some(r) = reason {
        let map = obj.as_object_mut().unwrap();
        map.insert("reason".into(), serde_json::json!(r));
        map.insert(
            "systemMessage".into(),
            serde_json::json!(format!("Kintsugi: {r}")),
        );
    }
    HookOutcome::json(obj)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shell(cmd: &str) -> Parsed {
        Parsed::Shell(Shell {
            command: cmd.into(),
            cwd: std::env::current_dir().unwrap_or_default(),
            session_id: None,
        })
    }

    #[test]
    fn from_agent_accepts_known_ids() {
        assert_eq!(Dialect::from_agent("claude"), Some(Dialect::Claude));
        assert_eq!(Dialect::from_agent("claude-code"), Some(Dialect::Claude));
        assert_eq!(Dialect::from_agent("qwen"), Some(Dialect::Qwen));
        assert_eq!(Dialect::from_agent("gemini"), Some(Dialect::Gemini));
        assert_eq!(Dialect::from_agent("copilot"), Some(Dialect::Copilot));
        assert_eq!(Dialect::from_agent("cursor"), Some(Dialect::Cursor));
        assert_eq!(Dialect::from_agent("opencode"), Some(Dialect::OpenCode));
        assert_eq!(Dialect::from_agent("codex"), Some(Dialect::Codex));
        assert_eq!(
            Dialect::from_agent("antigravity"),
            Some(Dialect::Antigravity)
        );
        assert_eq!(Dialect::from_agent("nope"), None);
    }

    #[test]
    fn antigravity_parses_run_command_with_pascalcase_args() {
        let p = Dialect::Antigravity.parse(
            r#"{"toolCall":{"name":"run_command","arguments":{"CommandLine":"rm -rf /","Cwd":"/work"}},"conversationId":"c9"}"#,
        );
        match p {
            Parsed::Shell(s) => {
                assert_eq!(s.command, "rm -rf /");
                assert_eq!(s.cwd, PathBuf::from("/work"));
                assert_eq!(s.session_id.as_deref(), Some("c9"));
            }
            other => panic!("expected shell, got {other:?}"),
        }
    }

    #[test]
    fn antigravity_non_shell_tool_is_not_shell() {
        let p = Dialect::Antigravity
            .parse(r#"{"toolCall":{"name":"write_file","arguments":{"Path":"x"}}}"#);
        assert_eq!(p, Parsed::NotShell);
    }

    #[test]
    fn antigravity_denies_and_downgrades_ask_to_deny() {
        // Deny carries a decision + reason.
        let out = Dialect::Antigravity.format(&Resolved::Deny("boom".into()));
        let v: serde_json::Value = serde_json::from_str(&out.stdout.unwrap()).unwrap();
        assert_eq!(v["decision"], "deny");
        assert_eq!(v["reason"], "boom");
        // No native ask → a hold becomes deny.
        let out = Dialect::Antigravity.format(&Resolved::Ask("held".into()));
        let v: serde_json::Value = serde_json::from_str(&out.stdout.unwrap()).unwrap();
        assert_eq!(v["decision"], "deny", "antigravity has no ask; must deny");
    }

    #[test]
    fn antigravity_allow_and_pass_are_explicit() {
        let allow = Dialect::Antigravity.format(&Resolved::Allow);
        let v: serde_json::Value = serde_json::from_str(&allow.stdout.unwrap()).unwrap();
        assert_eq!(v["decision"], "allow");
        assert_eq!(
            Dialect::Antigravity.pass(),
            format_antigravity(&Resolved::Allow),
            "antigravity must answer its gate with an explicit allow"
        );
    }

    #[test]
    fn codex_parses_bash_and_formats_claude_style() {
        let p = Dialect::Codex.parse(r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#);
        assert_eq!(p, shell("rm -rf /"));
        let out = Dialect::Codex.format(&Resolved::Deny("boom".into()));
        let v: serde_json::Value = serde_json::from_str(&out.stdout.unwrap()).unwrap();
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    }

    #[test]
    fn claude_parses_bash_command() {
        let p = Dialect::Claude.parse(r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#);
        match p {
            Parsed::Shell(s) => assert_eq!(s.command, "ls"),
            other => panic!("expected shell, got {other:?}"),
        }
    }

    #[test]
    fn claude_non_shell_tool_is_not_shell() {
        let p = Dialect::Claude.parse(r#"{"tool_name":"Edit","tool_input":{"file_path":"x"}}"#);
        assert_eq!(p, Parsed::NotShell);
    }

    #[test]
    fn qwen_parses_run_shell_command_canonical_name() {
        let p = Dialect::Qwen
            .parse(r#"{"tool_name":"run_shell_command","tool_input":{"command":"rm -rf x"}}"#);
        assert_eq!(p, shell("rm -rf x"));
    }

    #[test]
    fn gemini_parses_run_shell_command() {
        let p = Dialect::Gemini
            .parse(r#"{"tool_name":"run_shell_command","tool_input":{"command":"git push"}}"#);
        assert_eq!(p, shell("git push"));
    }

    #[test]
    fn gemini_ignores_bash_alias() {
        // Gemini never emits "Bash"; treat it as not-our-shell-tool.
        let p = Dialect::Gemini.parse(r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#);
        assert_eq!(p, Parsed::NotShell);
    }

    #[test]
    fn copilot_parses_camelcase_toolargs() {
        let p = Dialect::Copilot
            .parse(r#"{"toolName":"bash","toolArgs":{"command":"sudo rm"},"sessionId":"s1"}"#);
        match p {
            Parsed::Shell(s) => {
                assert_eq!(s.command, "sudo rm");
                assert_eq!(s.session_id.as_deref(), Some("s1"));
            }
            other => panic!("expected shell, got {other:?}"),
        }
    }

    #[test]
    fn cursor_parses_flat_command() {
        let p = Dialect::Cursor.parse(
            r#"{"command":"git status","cwd":"/tmp","hook_event_name":"beforeShellExecution","conversation_id":"c1"}"#,
        );
        match p {
            Parsed::Shell(s) => {
                assert_eq!(s.command, "git status");
                assert_eq!(s.cwd, PathBuf::from("/tmp"));
                assert_eq!(s.session_id.as_deref(), Some("c1"));
            }
            other => panic!("expected shell, got {other:?}"),
        }
    }

    #[test]
    fn opencode_bridge_parses_flat_command() {
        let p = Dialect::OpenCode.parse(r#"{"command":"dd if=/dev/zero","cwd":"/work"}"#);
        assert_eq!(
            p,
            Parsed::Shell(Shell {
                command: "dd if=/dev/zero".into(),
                cwd: PathBuf::from("/work"),
                session_id: None,
            })
        );
    }

    #[test]
    fn bad_payload_is_bad_for_every_dialect() {
        for d in [
            Dialect::Claude,
            Dialect::Qwen,
            Dialect::Gemini,
            Dialect::Copilot,
            Dialect::Cursor,
            Dialect::OpenCode,
            Dialect::Codex,
            Dialect::Antigravity,
        ] {
            assert!(matches!(d.parse("not json"), Parsed::Bad(_)), "{d:?}");
        }
    }

    #[test]
    fn claude_style_allow_is_silent_deny_is_json() {
        assert_eq!(
            Dialect::Claude.format(&Resolved::Allow),
            HookOutcome::silent()
        );
        let out = Dialect::Claude.format(&Resolved::Deny("nope".into()));
        let v: serde_json::Value = serde_json::from_str(&out.stdout.unwrap()).unwrap();
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
        assert_eq!(v["hookSpecificOutput"]["permissionDecisionReason"], "nope");
        assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    }

    #[test]
    fn qwen_ask_round_trips() {
        let out = Dialect::Qwen.format(&Resolved::Ask("held".into()));
        let v: serde_json::Value = serde_json::from_str(&out.stdout.unwrap()).unwrap();
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
    }

    #[test]
    fn gemini_downgrades_ask_to_deny() {
        let out = Dialect::Gemini.format(&Resolved::Ask("held".into()));
        let v: serde_json::Value = serde_json::from_str(&out.stdout.unwrap()).unwrap();
        assert_eq!(v["decision"], "deny", "gemini has no ask; must deny");
    }

    #[test]
    fn copilot_flat_decision_shape() {
        let out = Dialect::Copilot.format(&Resolved::Deny("x".into()));
        let v: serde_json::Value = serde_json::from_str(&out.stdout.unwrap()).unwrap();
        assert_eq!(v["permissionDecision"], "deny");
        assert_eq!(v["permissionDecisionReason"], "x");
    }

    #[test]
    fn cursor_allow_is_explicit_and_deny_has_both_message_cases() {
        let allow = Dialect::Cursor.format(&Resolved::Allow);
        let v: serde_json::Value = serde_json::from_str(&allow.stdout.unwrap()).unwrap();
        assert_eq!(v["permission"], "allow");

        let deny = Dialect::Cursor.format(&Resolved::Deny("bad".into()));
        let v: serde_json::Value = serde_json::from_str(&deny.stdout.unwrap()).unwrap();
        assert_eq!(v["permission"], "deny");
        assert_eq!(v["agentMessage"], "bad");
        assert_eq!(v["agent_message"], "bad");
    }

    #[test]
    fn opencode_decision_shape() {
        let out = Dialect::OpenCode.format(&Resolved::Ask("hold".into()));
        let v: serde_json::Value = serde_json::from_str(&out.stdout.unwrap()).unwrap();
        assert_eq!(v["decision"], "ask");
        assert_eq!(v["reason"], "hold");
    }

    #[test]
    fn cursor_pass_is_explicit_allow_others_silent() {
        assert_eq!(
            Dialect::Cursor.pass(),
            format_cursor(&Resolved::Allow),
            "cursor must answer its gate with an explicit allow"
        );
        assert_eq!(Dialect::Claude.pass(), HookOutcome::silent());
        assert_eq!(Dialect::Gemini.pass(), HookOutcome::silent());
    }

    #[test]
    fn resolve_maps_catastrophic_hold_to_deny() {
        use kintsugi_core::Verdict;
        let v = Verdict::rules(Class::Catastrophic, Decision::Hold, "boom");
        assert_eq!(resolve(&v), Resolved::Deny("boom".into()));
    }

    #[test]
    fn resolve_maps_ambiguous_hold_to_ask() {
        use kintsugi_core::Verdict;
        let v = Verdict::rules(Class::Ambiguous, Decision::Hold, "maybe");
        assert_eq!(
            resolve(&v),
            Resolved::Ask(
                "Kintsugi flagged this as ambiguous (rule: maybe). Approve only if you intended this."
                    .into()
            )
        );
    }

    #[test]
    fn ambiguous_ask_folds_in_the_model_summary() {
        use kintsugi_core::Verdict;
        let mut v = Verdict::rules(Class::Ambiguous, Decision::Hold, "ambiguous:cargo");
        v.summary = Some("updates a dependency and runs its build script".into());
        v.risk = Some(42);
        let Resolved::Ask(msg) = resolve(&v) else {
            panic!("expected ask")
        };
        assert!(msg.contains("Kintsugi flagged this"));
        assert!(msg.contains("updates a dependency and runs its build script"));
        assert!(msg.contains("risk 42/100"));
    }
}
