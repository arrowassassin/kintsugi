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
//!   allow|deny|ask, userMessage, agentMessage}` out. Its file-write events
//!   (`Write`/`StrReplace` pre-tool, `afterFileEdit`) are parsed by
//!   [`Dialect::parse_write`] for provenance, on the explicit `--event write`
//!   route.
//! - OpenCode: no external-command hook — a bundled JS plugin bridges to us with
//!   a simple `{command, cwd}` in / `{decision: allow|deny|ask, reason}` out, and
//!   forwards write/edit calls as `{tool, args, session, cwd}` on
//!   `--event write` ([`Dialect::parse_write`]).
//! - Google Antigravity: plugin `PreToolUse` hook (matcher `run_command`).
//!   `{toolCall:{name, arguments:{CommandLine, Cwd}}, conversationId}` in
//!   (PascalCase argument keys); `{decision: allow|deny, reason}` out — no native
//!   ask, so an ambiguous hold is mapped to deny.
//!
//! V1.1 adds a *post-tool* surface for the dialects that expose one (Claude,
//! Codex, Antigravity): [`Dialect::parse_post`] normalizes a completed call's
//! input + opaque result for result-content observation, and a *write* surface
//! for Cursor and OpenCode ([`Dialect::parse_write`]) so a tainted session's
//! file writes propagate taint to the path. Shapes are pinned to the fixture
//! files in `tests/fixtures/` — never to docs alone.

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

/// A completed tool call surfaced by a `PostToolUse`-style event, normalized for
/// V1.1 *result-content* observation. `response` is the agent's (opaque) result
/// payload — only its presence is ever consulted downstream; result bytes are
/// never persisted or logged (spine #6). The source id for any taint comes from
/// `input` (url / path / tool name), never from `response`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostToolCall {
    pub tool: String,
    pub input: serde_json::Value,
    pub response: serde_json::Value,
    pub cwd: PathBuf,
    pub session_id: Option<String>,
}

/// A non-shell **file-write** tool call surfaced for provenance observation: a
/// Cursor `Write` / `StrReplace` / `afterFileEdit`, or an OpenCode `write` /
/// `edit`. The raw `input` object is handed to
/// [`crate::observe::classify_tool_write`], which extracts the target path — the
/// write *body* (a `content` field, or `old_string`/`new_string` pairs) is never
/// read, persisted, or logged (spine #6).
///
/// The fields are deliberately the same normalized shape as [`ContentCall`]
/// because both classifiers consume (tool, args, workspace); a distinct type
/// keeps the ingest and write observation surfaces honest at the call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteCall {
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
            // No *ingest* shape is pinned for these dialects: their hooks carry
            // file writes, not content-tool results. Writes ride the explicit
            // `--event write` route through [`parse_write`] instead, so nothing
            // is guessed here (the 0.2.1 lesson).
            Dialect::Cursor | Dialect::OpenCode => return None,
        };
        Some(ContentCall {
            tool,
            input: args,
            cwd: cwd_or_current(cwd),
            session_id: session,
        })
    }

    /// Extract a file-write call from a payload delivered on the explicit
    /// `--event write` route (the generated OpenCode plugin, or a Cursor write
    /// matcher). Tolerant like [`parse_content`]: `None` for a non-write payload,
    /// unparseable input, an unknown tool name, or a dialect with no pinned write
    /// surface. Observation never blocks, so a miss is harmless.
    ///
    /// Every shape parsed here traces to a pinned fixture in `tests/fixtures/`:
    /// Cursor `cursor-write.json`, `cursor-str-replace.json`,
    /// `cursor-after-file-edit.json`; OpenCode `opencode-write-v1.json`,
    /// `opencode-write-v2.json`. This is deliberately separate from
    /// [`parse_content`]: that surface feeds the *ingest* classifier, and
    /// emitting a call there for a Cursor payload would claim a Read/WebFetch arg
    /// shape no fixture pins.
    pub fn parse_write(self, input: &str) -> Option<WriteCall> {
        let v: serde_json::Value = serde_json::from_str(input).ok()?;
        let get_str = |val: &serde_json::Value, k: &str| {
            val.get(k).and_then(|s| s.as_str()).map(String::from)
        };
        let (tool, args, cwd, session) = match self {
            Dialect::Cursor => {
                if let Some(tool) = get_str(&v, "tool_name") {
                    // preToolUse write/edit (fixtures cursor-write.json,
                    // cursor-str-replace.json). Cursor's exact content-tool name
                    // set is a live-verification gap, so only the pinned names
                    // are accepted — an unknown name is a miss, never a guess.
                    if !matches!(tool.as_str(), "Write" | "StrReplace") {
                        return None;
                    }
                    (
                        tool,
                        v.get("tool_input")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null),
                        get_str(&v, "cwd"),
                        get_str(&v, "conversation_id"),
                    )
                } else {
                    // afterFileEdit (fixture cursor-after-file-edit.json): no tool
                    // identity, and the path sits at the top level. The whole
                    // payload is handed over; the classifier reads only the path
                    // key. No per-call cwd on this surface, so the documented
                    // workspace root is the closest honest trust boundary.
                    if get_str(&v, "hook_event_name").as_deref() != Some("afterFileEdit") {
                        return None;
                    }
                    (
                        "afterFileEdit".to_string(),
                        v.clone(),
                        v.get("workspace_roots")
                            .and_then(|w| w.as_array())
                            .and_then(|a| a.first())
                            .and_then(|p| p.as_str())
                            .map(String::from),
                        get_str(&v, "conversation_id"),
                    )
                }
            }
            Dialect::OpenCode => {
                if let Some(tool) = get_str(&v, "tool") {
                    // The shape the generated plugin forwards (our own contract:
                    // tool + args + session + cwd), and V2's raw event shape
                    // `{tool, input}`. V2 documents no session field, so it stays
                    // absent and the hook skips it rather than inventing one.
                    (
                        tool,
                        v.get("args")
                            .or_else(|| v.get("input"))
                            .cloned()
                            .unwrap_or(serde_json::Value::Null),
                        get_str(&v, "cwd"),
                        get_str(&v, "session").or_else(|| get_str(&v, "sessionID")),
                    )
                } else {
                    // The raw V1 plugin callback (fixture opencode-write-v1.json):
                    // input{tool, sessionID} + output{args}.
                    let inner = v.get("input")?;
                    (
                        get_str(inner, "tool")?,
                        v.get("output")
                            .and_then(|o| o.get("args"))
                            .cloned()
                            .unwrap_or(serde_json::Value::Null),
                        None,
                        get_str(inner, "sessionID"),
                    )
                }
            }
            // No write surface is pinned for these dialects (Task 1 pinned Cursor
            // and OpenCode only); report that honestly rather than guess.
            Dialect::Claude
            | Dialect::Qwen
            | Dialect::Gemini
            | Dialect::Copilot
            | Dialect::Codex
            | Dialect::Antigravity => return None,
        };
        Some(WriteCall {
            tool,
            input: args,
            cwd: cwd_or_current(cwd),
            session_id: session,
        })
    }

    /// Extract a completed tool call from a `PostToolUse`-style payload, for
    /// V1.1 *result-content* observation. Tolerant in the same way as
    /// [`parse_content`]: returns `None` for unparseable input, missing
    /// identity/response fields, or a dialect with no pinned post surface —
    /// observation never blocks, so a miss is harmless. Every shape parsed
    /// here traces to a pinned fixture in `tests/fixtures/` (the 0.2.1
    /// lesson: never write to a documented-but-unverified shape).
    ///
    /// Divergence note (Antigravity): the documented post payload is camelCase
    /// `toolCall.args`, which is what this parser reads — while the pre-tool
    /// parser reads `toolCall.arguments`. At least one of the two is wrong for
    /// the live wire; only a live CLI can say which. The pre-tool path is
    /// deliberately left unchanged here; reconciliation rides on the
    /// live-verification checkbox in the fixtures README.
    pub fn parse_post(self, input: &str) -> Option<PostToolCall> {
        let v: serde_json::Value = serde_json::from_str(input).ok()?;
        let get_str = |val: &serde_json::Value, k: &str| {
            val.get(k).and_then(|s| s.as_str()).map(String::from)
        };
        let (tool, args, response, cwd, session) = match self {
            // Claude Code & Codex share the PostToolUse envelope:
            // tool_name / tool_input / tool_response / cwd / session_id
            // (fixtures: claude-post-tool-use.json, codex-post-tool-use.json).
            // A post payload without a response is malformed — there is
            // nothing to observe.
            Dialect::Claude | Dialect::Codex => (
                get_str(&v, "tool_name")?,
                v.get("tool_input")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
                v.get("tool_response").cloned()?,
                get_str(&v, "cwd"),
                get_str(&v, "session_id"),
            ),
            // Antigravity's documented PostToolUse carries `toolCall{name,
            // args}` and NO result bytes — its hook output is advisory-only, so
            // the response is honestly null here and result-content
            // classification for this dialect is act-confirmation at best
            // (fixture: antigravity-post-tool.json).
            Dialect::Antigravity => {
                let tc = v.get("toolCall")?;
                let args = tc.get("args").cloned().unwrap_or(serde_json::Value::Null);
                // No per-call cwd on this surface; the session's workspace
                // roots are the closest honest stand-in.
                let cwd = v
                    .get("workspacePaths")
                    .and_then(|w| w.as_array())
                    .and_then(|a| a.first())
                    .and_then(|p| p.as_str())
                    .map(String::from);
                (
                    get_str(tc, "name")?,
                    args,
                    serde_json::Value::Null,
                    cwd,
                    get_str(&v, "conversationId"),
                )
            }
            // No pinned post fixture exists for these dialects (Qwen's
            // PostToolUse is unpinned; Cursor/OpenCode write surfaces are
            // Task 3; Copilot postToolUse has no tool_use_id — open upstream
            // issue; Gemini uses a different AfterTool contract).
            Dialect::Qwen
            | Dialect::Gemini
            | Dialect::Copilot
            | Dialect::Cursor
            | Dialect::OpenCode => return None,
        };
        Some(PostToolCall {
            tool,
            input: args,
            response,
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
    /// The shape the gate documents.
    #[serde(default)]
    arguments: Option<AntigravityArgs>,
    /// The shape the post-tool surface documents (`toolCall.args`). Both are
    /// accepted because a mismatch here means the gate parses no command and
    /// silently allows every `run_command` — a catastrophic-classified-as-safe
    /// outcome. Widening the parser can only add classification.
    #[serde(default)]
    args: Option<AntigravityArgs>,
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
    let Some(args) = tc.arguments.or(tc.args) else {
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

    // ----- PostToolUse result observation (V1.1) ------------------------------
    // Every post-tool parse must trace to a pinned fixture in tests/fixtures/
    // (the 0.2.1 lesson: adapters written to documented shapes, never
    // round-trip-verified). No inline duplication of the pinned shapes: the
    // files on disk are the contract.

    fn fixture_text(name: &str) -> String {
        std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(name),
        )
        .unwrap_or_else(|e| panic!("fixture {name}: {e}"))
    }

    /// A programmatic mutation of a pinned fixture (single source of truth:
    /// the file on disk), for the adversarial variants.
    fn mutated_fixture(name: &str, edit: impl FnOnce(&mut serde_json::Value)) -> String {
        let mut v: serde_json::Value =
            serde_json::from_str(&fixture_text(name)).unwrap_or_else(|e| panic!("{e}"));
        edit(&mut v);
        v.to_string()
    }

    #[test]
    fn all_pinned_fixture_files_are_valid_json() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let mut checked = 0;
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                let text = std::fs::read_to_string(&path).unwrap();
                serde_json::from_str::<serde_json::Value>(&text)
                    .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
                checked += 1;
            }
        }
        assert!(
            checked >= 8,
            "expected the pinned V1.1 fixture set, found {checked}"
        );
    }

    #[test]
    fn claude_post_tool_fixture_parses() {
        let call = Dialect::Claude
            .parse_post(&fixture_text("claude-post-tool-use.json"))
            .expect("pinned claude post fixture must round-trip");
        assert_eq!(call.tool, "WebFetch");
        assert_eq!(call.input["url"], "https://example.com/advisory");
        // The response rides along opaquely — parsed, never interpreted here.
        assert!(call.response.is_string());
        assert_eq!(call.cwd, PathBuf::from("/work/repo"));
        assert_eq!(
            call.session_id.as_deref(),
            Some("e3f8a1c2-7b49-4d62-9a15-6c2d8e4f9b01")
        );
    }

    #[test]
    fn codex_post_tool_fixture_parses() {
        let call = Dialect::Codex
            .parse_post(&fixture_text("codex-post-tool-use.json"))
            .expect("pinned codex post fixture must round-trip");
        assert_eq!(call.tool, "mcp__webdocs__fetch_page");
        assert_eq!(call.input["url"], "https://example.com/advisory");
        assert!(call.response.is_string());
        assert_eq!(call.cwd, PathBuf::from("/work/repo"));
        assert_eq!(
            call.session_id.as_deref(),
            Some("b1e5d0a2-3f47-4c98-9d62-1a7b8c5e2f30")
        );
    }

    #[test]
    fn antigravity_post_tool_fixture_parses_the_documented_args_shape() {
        let call = Dialect::Antigravity
            .parse_post(&fixture_text("antigravity-post-tool.json"))
            .expect("pinned antigravity post fixture must round-trip");
        assert_eq!(call.tool, "read_url_content");
        // The DOCUMENTED `toolCall.args` shape. Divergence note: the pre-tool
        // Antigravity parser reads `toolCall.arguments` — at least one of the
        // two is wrong for the live wire, and only a live CLI can say which
        // (open checkbox in the fixtures README). The pre-tool path is left
        // unchanged by this task; reconciliation rides on that checkbox.
        assert_eq!(call.input["Url"], "https://example.com/advisory");
        // No result bytes exist on this surface (its output is advisory-only
        // `{}`), so the response is honestly null — never invented content.
        assert_eq!(call.response, serde_json::Value::Null);
        assert_eq!(call.cwd, PathBuf::from("/work/repo"));
        assert_eq!(
            call.session_id.as_deref(),
            Some("ec33ebf9-0cba-4100-8142-c61503f6c587")
        );
    }

    #[test]
    fn post_tool_malformed_variants_parse_to_none() {
        // Truncated JSON — an adversarial variant of every pinned fixture
        // (char-safe halving: fixtures contain multi-byte characters).
        for (dialect, name) in [
            (Dialect::Claude, "claude-post-tool-use.json"),
            (Dialect::Codex, "codex-post-tool-use.json"),
            (Dialect::Antigravity, "antigravity-post-tool.json"),
        ] {
            let text = fixture_text(name);
            let truncated: String = text.chars().take(text.chars().count() / 2).collect();
            assert_eq!(dialect.parse_post(&truncated), None, "truncated {name}");
        }

        // Missing tool identity.
        let no_tool = mutated_fixture("claude-post-tool-use.json", |v| {
            v.as_object_mut().unwrap().remove("tool_name");
        });
        assert_eq!(Dialect::Claude.parse_post(&no_tool), None);

        // Missing response (the plan's malformed case): a post payload with
        // no result to observe is malformed, not a silent success.
        for dialect in [Dialect::Claude, Dialect::Codex] {
            let name = if dialect == Dialect::Claude {
                "claude-post-tool-use.json"
            } else {
                "codex-post-tool-use.json"
            };
            let no_response = mutated_fixture(name, |v| {
                v.as_object_mut().unwrap().remove("tool_response");
            });
            assert_eq!(dialect.parse_post(&no_response), None, "{dialect:?}");
        }

        // Missing toolCall (Antigravity).
        let no_tc = mutated_fixture("antigravity-post-tool.json", |v| {
            v.as_object_mut().unwrap().remove("toolCall");
        });
        assert_eq!(Dialect::Antigravity.parse_post(&no_tc), None);

        // Wrong types.
        let bad_type = mutated_fixture("claude-post-tool-use.json", |v| {
            v["tool_name"] = serde_json::json!(7);
        });
        assert_eq!(Dialect::Claude.parse_post(&bad_type), None);
        let bad_type = mutated_fixture("antigravity-post-tool.json", |v| {
            v["toolCall"] = serde_json::json!("not-an-object");
        });
        assert_eq!(Dialect::Antigravity.parse_post(&bad_type), None);
    }

    #[test]
    fn an_explicitly_null_post_response_parses_but_carries_no_content() {
        // Present-but-null is NOT malformed (absent vs null are different
        // states on the wire); it just observes nothing, per the classifier.
        let null_response = mutated_fixture("claude-post-tool-use.json", |v| {
            v["tool_response"] = serde_json::Value::Null;
        });
        assert!(Dialect::Claude.parse_post(&null_response).is_some());
    }

    // ----- File-write observation (V1.1 Task 3) -------------------------------
    // Every write parse must trace to a pinned fixture in tests/fixtures/ (the
    // cursor-write / cursor-str-replace / cursor-after-file-edit /
    // opencode-write-v1 / opencode-write-v2 files). No inline shapes.

    #[test]
    fn cursor_write_fixture_normalizes_to_a_write_call() {
        let call = Dialect::Cursor
            .parse_write(&fixture_text("cursor-write.json"))
            .expect("pinned cursor Write fixture must parse");
        assert_eq!(call.tool, "Write");
        assert_eq!(call.input["file_path"], "/work/repo/src/notes.rs");
        // The per-call cwd is the trust boundary the classifier resolves against.
        assert_eq!(call.cwd, PathBuf::from("/work/repo"));
        assert_eq!(call.session_id.as_deref(), Some("conv-4d2f9a1c"));
    }

    #[test]
    fn cursor_str_replace_fixture_normalizes_to_a_write_call() {
        let call = Dialect::Cursor
            .parse_write(&fixture_text("cursor-str-replace.json"))
            .expect("pinned cursor StrReplace fixture must parse");
        assert_eq!(call.tool, "StrReplace");
        assert_eq!(call.input["file_path"], "/work/repo/src/lib.rs");
        assert_eq!(call.session_id.as_deref(), Some("conv-4d2f9a1c"));
    }

    #[test]
    fn cursor_after_file_edit_fixture_normalizes_to_a_write_call() {
        let call = Dialect::Cursor
            .parse_write(&fixture_text("cursor-after-file-edit.json"))
            .expect("pinned cursor afterFileEdit fixture must parse");
        // No tool identity on this event; the event name is the honest label.
        assert_eq!(call.tool, "afterFileEdit");
        // The path is top-level on this surface (pinned shape).
        assert_eq!(call.input["file_path"], "/work/repo/src/notes.rs");
        // No `cwd` field: the documented workspace root is the closest honest root.
        assert_eq!(call.cwd, PathBuf::from("/work/repo"));
        assert_eq!(call.session_id.as_deref(), Some("conv-4d2f9a1c"));
    }

    #[test]
    fn opencode_v1_write_fixture_normalizes_with_its_session() {
        // The pinned V1 plugin callback shape: input{tool, sessionID} + output{args}.
        let call = Dialect::OpenCode
            .parse_write(&fixture_text("opencode-write-v1.json"))
            .expect("pinned opencode V1 write fixture must parse");
        assert_eq!(call.tool, "write");
        assert_eq!(call.input["filePath"], "/work/repo/src/notes.rs");
        assert_eq!(call.session_id.as_deref(), Some("ses_9f2a41"));
    }

    #[test]
    fn opencode_v2_write_fixture_parses_but_carries_no_session() {
        // V2's documented before-event has `tool` + `input` and NO session field.
        // We parse the shape honestly and leave the session absent: the hook then
        // skips the observation (sessionless by design) rather than inventing an
        // identifier. Tracked as a live-verification gap in the fixtures README.
        let call = Dialect::OpenCode
            .parse_write(&fixture_text("opencode-write-v2.json"))
            .expect("pinned opencode V2 write fixture must parse");
        assert_eq!(call.tool, "write");
        assert_eq!(call.input["filePath"], "/work/repo/src/notes.rs");
        assert_eq!(call.session_id, None, "V2 documents no session field");
    }

    #[test]
    fn the_generated_opencode_bridge_shape_normalizes() {
        // What the generated plugin forwards on `--event write` (our own contract,
        // pinned by the init.rs unit test): tool + args + session + cwd.
        let payload = r#"{
            "tool": "write",
            "args": { "filePath": "/work/repo/src/notes.rs" },
            "session": "ses_9f2a41",
            "cwd": "/work/repo"
        }"#;
        let call = Dialect::OpenCode
            .parse_write(payload)
            .expect("bridge shape");
        assert_eq!(call.tool, "write");
        assert_eq!(call.input["filePath"], "/work/repo/src/notes.rs");
        assert_eq!(call.cwd, PathBuf::from("/work/repo"));
        assert_eq!(call.session_id.as_deref(), Some("ses_9f2a41"));
    }

    #[test]
    fn shell_payloads_are_never_mistaken_for_writes() {
        // The flat `{command, cwd}` contract both dialects already speak is
        // untouched: it carries no write identity, so the write route declines it.
        let cursor_shell = r#"{"command":"git status","cwd":"/tmp","hook_event_name":"beforeShellExecution","conversation_id":"c1"}"#;
        assert_eq!(Dialect::Cursor.parse_write(cursor_shell), None);
        let opencode_shell = r#"{"command":"dd if=/dev/zero","cwd":"/work"}"#;
        assert_eq!(Dialect::OpenCode.parse_write(opencode_shell), None);
        // …and their PRE-tool shell parsing still works exactly as before.
        assert!(matches!(
            Dialect::Cursor.parse(cursor_shell),
            Parsed::Shell(_)
        ));
        assert!(matches!(
            Dialect::OpenCode.parse(opencode_shell),
            Parsed::Shell(_)
        ));
    }

    #[test]
    fn only_the_pinned_cursor_content_tools_are_writes() {
        // The exact Cursor content-tool name set is a live-verification gap, so
        // only the fixture-pinned names are accepted (0.2.1 lesson: never guess a
        // shape). An unknown tool is a miss, never a wrong parse.
        let read = mutated_fixture("cursor-write.json", |v| {
            v["tool_name"] = serde_json::json!("Read");
        });
        assert_eq!(Dialect::Cursor.parse_write(&read), None);
        let delete = mutated_fixture("cursor-write.json", |v| {
            v["tool_name"] = serde_json::json!("Delete");
        });
        assert_eq!(Dialect::Cursor.parse_write(&delete), None);
    }

    #[test]
    fn write_parse_is_tolerant_of_malformed_payloads() {
        for (dialect, name) in [
            (Dialect::Cursor, "cursor-write.json"),
            (Dialect::Cursor, "cursor-after-file-edit.json"),
            (Dialect::OpenCode, "opencode-write-v1.json"),
            (Dialect::OpenCode, "opencode-write-v2.json"),
        ] {
            let text = fixture_text(name);
            let truncated: String = text.chars().take(text.chars().count() / 2).collect();
            assert_eq!(dialect.parse_write(&truncated), None, "truncated {name}");
        }
        // Missing identity.
        let no_tool = mutated_fixture("cursor-write.json", |v| {
            v.as_object_mut().unwrap().remove("tool_name");
        });
        assert_eq!(Dialect::Cursor.parse_write(&no_tool), None);
        // An `afterFileEdit` payload without the event marker is not a write.
        let no_event = mutated_fixture("cursor-after-file-edit.json", |v| {
            v.as_object_mut().unwrap().remove("hook_event_name");
        });
        assert_eq!(Dialect::Cursor.parse_write(&no_event), None);
        // Wrong types.
        let bad_type = mutated_fixture("cursor-write.json", |v| {
            v["tool_name"] = serde_json::json!(7);
        });
        assert_eq!(Dialect::Cursor.parse_write(&bad_type), None);
    }

    #[test]
    fn dialects_without_a_pinned_write_surface_return_none() {
        // Task 1 pinned write shapes for Cursor and OpenCode only. Every other
        // dialect reports "no write surface" rather than guessing (its post-tool
        // or shell coverage is unaffected).
        let cursor_write = fixture_text("cursor-write.json");
        for d in [
            Dialect::Claude,
            Dialect::Qwen,
            Dialect::Gemini,
            Dialect::Copilot,
            Dialect::Codex,
            Dialect::Antigravity,
        ] {
            assert_eq!(d.parse_write(&cursor_write), None, "{d:?}");
        }
    }

    #[test]
    fn dialects_without_a_pinned_post_surface_return_none() {
        // No Task-1 fixture pins these dialects' post shapes, so Kintsugi
        // honestly reports "no post surface" rather than guessing at a wire
        // format (the 0.2.1 lesson). Qwen's PostToolUse exists upstream but is
        // unpinned; Cursor/OpenCode write surfaces are Task 3; Copilot's
        // postToolUse lacks a tool_use_id (open issue, out of scope); Gemini
        // uses AfterTool, a different contract entirely.
        let claude_fixture = fixture_text("claude-post-tool-use.json");
        for d in [
            Dialect::Qwen,
            Dialect::Gemini,
            Dialect::Copilot,
            Dialect::Cursor,
            Dialect::OpenCode,
        ] {
            assert_eq!(d.parse_post(&claude_fixture), None, "{d:?}");
        }
        // Their PRE-tool shell payloads parse exactly as before.
        let cursor_shell = r#"{"command":"git status","cwd":"/tmp","hook_event_name":"beforeShellExecution","conversation_id":"c1"}"#;
        assert!(matches!(
            Dialect::Cursor.parse(cursor_shell),
            Parsed::Shell(_)
        ));
        assert_eq!(Dialect::Cursor.parse_post(cursor_shell), None);
    }
}
