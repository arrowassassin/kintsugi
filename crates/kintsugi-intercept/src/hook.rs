//! Agent-CLI hook adapter.
//!
//! Many AI coding CLIs can run a command before they execute a tool, hand it a
//! JSON description of the call, and read a decision back. This adapter bridges
//! that payload to a [`ProposedCommand`], asks the daemon, and maps the
//! [`Verdict`] to the CLI's decision protocol.
//!
//! The per-CLI wire formats live in [`crate::dialect`]; this module owns the
//! shared *policy*: the daemon round-trip, the fail-closed-catastrophic
//! backstop, and the Allow/Deny/Hold → decision mapping. Selecting a dialect is
//! one `--agent <id>` flag, so a single `kintsugi-hook` binary serves every CLI.
//!
//! Fail-open: a malformed payload, a non-shell tool, or an unreachable daemon
//! never blocks the agent — *except* a catastrophic command with the daemon
//! down (denied fail-closed), or when `KINTSUGI_FAIL_CLOSED=1`.

use std::path::Path;

use kintsugi_core::{shell, Class, Decision, ObservedIngest, ProposedCommand};
use kintsugi_daemon::Client;
use serde::Deserialize;

pub use crate::dialect::HookOutcome;

use crate::dialect::{self, Dialect, Parsed, Resolved};
use crate::observe;

/// Which hook event the caller asked us to handle (`--event`). The default is the
/// pre-tool decision path, so an invocation without the flag is byte-identical to
/// the pre-V1.1 behaviour — a typo or a missing flag can never disarm the shell
/// gate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HookEvent {
    /// Pre-tool: judge a shell command (the original contract).
    #[default]
    PreToolUse,
    /// File-write observation: label the written path for provenance so a tainted
    /// session's output carries the taint into a later reader. Observation only —
    /// it never blocks, and it never touches a command verdict.
    Write,
}

/// Handle one hook payload for a given dialect, performing the daemon round-trip.
pub fn handle_with(dialect: Dialect, input: &str) -> HookOutcome {
    handle_with_event(dialect, input, HookEvent::PreToolUse)
}

/// Handle one hook payload for an explicit event kind (the `--event` flag).
///
/// [`HookEvent::Write`] is routed to write observation *before* any shell
/// parsing and returns silent/0 unconditionally: a write label can never gate the
/// agent. Every other event takes the exact pre-tool path below.
pub fn handle_with_event(dialect: Dialect, input: &str, event: HookEvent) -> HookOutcome {
    if event == HookEvent::Write {
        observe_write_call(dialect, input);
        return HookOutcome::silent();
    }
    // Route on the explicit event marker BEFORE any shell parsing: a
    // PostToolUse payload reports a call that ALREADY ran. Re-judging it as a
    // proposal would double-log a command nobody proposed and "deny" an
    // action that cannot be undone by a deny. The observation below only
    // labels the session for future commands — it never blocks and never
    // touches the verdict path a PreToolUse payload takes.
    if is_post_tool_use(input) {
        observe_post_call(dialect, input);
        return HookOutcome::silent();
    }
    let parsed = match dialect.parse(input) {
        Parsed::Shell(s) => s,
        Parsed::NotShell => {
            // Not a shell tool — but it may be a content-ingesting one (a web
            // fetch, search, MCP call, out-of-workspace read). Observe it for
            // provenance taint, then pass: observation only labels, never blocks.
            observe_content_call(dialect, input);
            return HookOutcome::silent();
        }
        Parsed::Bad(e) => {
            // Never block the agent on a payload we couldn't parse.
            eprintln!(
                "kintsugi-hook: could not parse {} payload: {e}",
                dialect.agent_id()
            );
            return HookOutcome::silent();
        }
    };

    let argv = shell::split(&parsed.command);
    let session = parsed.session_id.clone();
    let cwd = parsed.cwd.clone();
    let proposed =
        ProposedCommand::new(dialect.agent_id(), parsed.cwd, argv.clone(), parsed.command)
            .with_session(parsed.session_id);

    match Client::send(&proposed) {
        Ok(verdict) => {
            let resolved = match dialect::resolve(&verdict) {
                // A catastrophic command is held in Kintsugi's queue but denied to
                // the agent: an in-agent "allow" would run it with no snapshot,
                // voiding reversibility. The agent can't offer that approval, so
                // tell the human where it lives — otherwise the agent just sees a
                // bare deny and silently works around it.
                Resolved::Deny(reason)
                    if verdict.decision == Decision::Hold
                        && verdict.class == Class::Catastrophic =>
                {
                    Resolved::Deny(held_for_approval(&reason, &proposed.id.to_string()))
                }
                other => other,
            };
            let outcome = dialect.format(&resolved);
            // A shell command that fetches remote content (`curl`/`wget`/`git
            // clone`) taints the session for FUTURE commands. Observe it only when
            // it will actually run (Allow) and AFTER the verdict — so the fetch is
            // judged against prior state and isn't tripped by its own taint.
            if matches!(resolved, Resolved::Allow) {
                observe_shell_ingest(dialect, &argv, session.as_deref(), &cwd);
            }
            outcome
        }
        Err(e) => {
            // Daemon down: locally classify so a catastrophic command is still
            // denied (fail-closed for the hard floor); non-catastrophic honors
            // the fail-open default.
            if kintsugi_core::classify(&proposed).class == Class::Catastrophic {
                eprintln!(
                    "kintsugi-hook: daemon unreachable; denying catastrophic (fail-closed): {e}"
                );
                dialect.format(&dialect::Resolved::Deny(
                    "Kintsugi daemon unreachable; catastrophic command blocked (fail-closed)"
                        .into(),
                ))
            } else if fail_closed() {
                eprintln!("kintsugi-hook: daemon unreachable; denying (fail-closed): {e}");
                dialect.format(&dialect::Resolved::Deny(
                    "Kintsugi daemon unreachable (fail-closed)".into(),
                ))
            } else {
                eprintln!("kintsugi-hook: warning: daemon unreachable; allowing unguarded: {e}");
                dialect.pass()
            }
        }
    }
}

/// Backwards-compatible Claude Code entry point.
pub fn handle(input: &str) -> HookOutcome {
    handle_with(Dialect::Claude, input)
}

/// Observe a non-shell content-tool call (web fetch / search / MCP / read) as a
/// provenance taint source. Best-effort and silent: a parse miss, an untracked
/// session, or an unreachable daemon must never affect the agent — observation
/// only labels, it is not a gate.
fn observe_content_call(dialect: Dialect, input: &str) {
    let Some(call) = dialect.parse_content(input) else {
        return;
    };
    if let Some(src) = observe::classify_tool_ingest(&call.tool, &call.input, &call.cwd) {
        send_ingest(dialect, src, call.session_id.as_deref(), &call.cwd);
    }
}

/// Observe a *completed* tool call's result as a provenance taint source (V1.1
/// result-content, fed by a PostToolUse event). Same contract as
/// [`observe_content_call`]: best-effort and silent — a parse miss, an untracked
/// session, or an unreachable daemon never affects the agent. The tool already
/// ran, so there is nothing to gate; this only labels the session for FUTURE
/// commands, purely additively on top of the pre-tool act taint.
fn observe_post_call(dialect: Dialect, input: &str) {
    let Some(call) = dialect.parse_post(input) else {
        return;
    };
    if let Some(src) =
        observe::classify_result_ingest(&call.tool, &call.input, &call.response, &call.cwd)
    {
        send_ingest(dialect, src, call.session_id.as_deref(), &call.cwd);
    }
}

/// Observe a file write by the agent's session as a provenance propagation step
/// (V1.1): a session that has ingested untrusted content taints the paths it
/// writes, so a later reader of that file inherits the taint. Same contract as
/// the ingest observers: best-effort and silent — a parse miss, an untracked
/// session, or an unreachable daemon never affects the agent.
fn observe_write_call(dialect: Dialect, input: &str) {
    let Some(call) = dialect.parse_write(input) else {
        return;
    };
    if let Some(path) = observe::classify_tool_write(&call.tool, &call.input, &call.cwd) {
        send_write(call.session_id.as_deref(), &path, &call.cwd);
    }
}

/// Report a write observation to the daemon. Skips untracked sessions (a
/// `None`/empty session can never be taint-tracked, so there is nothing to
/// propagate — the same convention as [`send_ingest`]) and swallows any IPC error
/// (observation never blocks the agent).
fn send_write(session: Option<&str>, path: &str, cwd: &Path) {
    let Some(session) = session.filter(|s| !s.is_empty()) else {
        return;
    };
    let _ = Client::write_observed(session, path, cwd);
}

/// The narrow event-marker probe used to route PostToolUse payloads. Only the
/// explicit `hook_event_name` the agent itself stamps decides — never payload
/// shape (a PreToolUse shell payload misrouted onto the post path would
/// bypass the decision gate, so a guess is never acceptable).
#[derive(Debug, Deserialize)]
struct EventMarker {
    #[serde(default)]
    hook_event_name: Option<String>,
}

/// Is this payload a `PostToolUse` event? Malformed input, other events, and
/// missing markers all answer no — the decision path is the default.
fn is_post_tool_use(input: &str) -> bool {
    serde_json::from_str::<EventMarker>(input)
        .ok()
        .and_then(|e| e.hook_event_name)
        .is_some_and(|name| name == "PostToolUse")
}

/// Observe a shell command that ingests remote content (`curl`/`wget`/`git
/// clone`). Best-effort and silent, same as [`observe_content_call`].
fn observe_shell_ingest(dialect: Dialect, argv: &[String], session: Option<&str>, cwd: &Path) {
    if let Some(src) = observe::classify_shell_ingest(argv) {
        send_ingest(dialect, src, session, cwd);
    }
}

/// Build and send an [`ObservedIngest`] to the daemon. Skips untracked sessions
/// (a `None`/empty session can never be taint-tracked, so there is nothing to
/// label) and swallows any IPC error (observation never blocks the agent).
fn send_ingest(dialect: Dialect, src: observe::IngestSource, session: Option<&str>, cwd: &Path) {
    let Some(session) = session.filter(|s| !s.is_empty()) else {
        return;
    };
    let observed = ObservedIngest::now(src.kind, src.id, dialect.agent_id(), session, cwd);
    let _ = Client::ingest(&observed);
}

/// Augment a catastrophic deny with the stop → approve → continue flow.
///
/// A hook is one-shot: by the time you see this, the agent already got the deny
/// and there is no parked tool call to resume. The agent must never run a
/// catastrophic itself, and approving it elsewhere does NOT auto-resume the agent.
/// So this message tells the agent to *stop and hand off to the human*, who can
/// run it from the trusted UI (Held → Approve & run) or via `kintsugi run <id>` —
/// both snapshot first (so `kintsugi undo` works) and are gated on a deliberate
/// human action (a real-terminal keypress on the CLI; a click in the unlocked app)
/// so an agent shelling out still can't self-approve. After the human handles it,
/// they tell the agent to continue. The short id prefix is surfaced for the CLI.
fn held_for_approval(reason: &str, id: &str) -> String {
    let short = id.get(..8).unwrap_or(id);
    format!(
        "{reason} Kintsugi blocked this catastrophic command — do NOT run it or try to work \
         around it. Stop and tell the user: if they want it, they can approve it in the Kintsugi \
         app (Held → Approve & run) or run `kintsugi run {short}` in their terminal — either way \
         it is snapshotted first, so `kintsugi undo` can roll it back. You will not resume \
         automatically; once they've handled it, they can tell you to continue."
    )
}

/// True if the admin-set fail-closed marker is present (an agent can't unset a
/// root-owned marker) OR the `KINTSUGI_FAIL_CLOSED` env var opts in. The marker
/// wins, so `KINTSUGI_FAIL_CLOSED=0` can't re-open the gate.
fn fail_closed() -> bool {
    kintsugi_daemon::is_fail_closed_marked()
        || matches!(
            std::env::var("KINTSUGI_FAIL_CLOSED").ok().as_deref(),
            Some("1") | Some("true") | Some("yes")
        )
}

/// Parse the `--agent <id>` flag from argv, defaulting to Claude Code.
///
/// Unknown ids fall back to Claude with a warning rather than failing — a
/// misconfigured hook should still guard, not crash the agent.
pub fn dialect_from_args<I: IntoIterator<Item = String>>(args: I) -> Dialect {
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        let value = if let Some(v) = a.strip_prefix("--agent=") {
            Some(v.to_string())
        } else if a == "--agent" {
            it.next()
        } else {
            None
        };
        if let Some(v) = value {
            match Dialect::from_agent(&v) {
                Some(d) => return d,
                None => {
                    eprintln!("kintsugi-hook: unknown --agent '{v}', defaulting to claude-code");
                    return Dialect::Claude;
                }
            }
        }
    }
    Dialect::Claude
}

/// Read the `--event <kind>` flag from argv, defaulting to the pre-tool path.
///
/// Unknown values fall back to the pre-tool path with a warning rather than
/// failing or silently doing nothing: the shell gate is the default, so an
/// unrecognized flag cannot weaken it.
pub fn event_from_args<I: IntoIterator<Item = String>>(args: I) -> HookEvent {
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        let value = if let Some(v) = a.strip_prefix("--event=") {
            Some(v.to_string())
        } else if a == "--event" {
            it.next()
        } else {
            None
        };
        if let Some(v) = value {
            return match v.as_str() {
                "write" => HookEvent::Write,
                other => {
                    eprintln!("kintsugi-hook: unknown --event '{other}', using the pre-tool path");
                    HookEvent::PreToolUse
                }
            };
        }
    }
    HookEvent::PreToolUse
}

/// Read the hook payload from stdin and emit the outcome, picking the dialect and
/// event kind from the process arguments.
pub fn run() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dialect = dialect_from_args(args.iter().cloned());
    let event = event_from_args(args);
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    run_io_event(dialect, event, stdin.lock(), stdout.lock())
}

/// The hook over arbitrary reader/writer for a given dialect (testable). Takes
/// the original pre-tool path.
pub fn run_io<R: std::io::Read, W: std::io::Write>(dialect: Dialect, reader: R, writer: W) -> i32 {
    run_io_event(dialect, HookEvent::PreToolUse, reader, writer)
}

/// The hook over arbitrary reader/writer for a dialect and event kind (testable).
pub fn run_io_event<R: std::io::Read, W: std::io::Write>(
    dialect: Dialect,
    event: HookEvent,
    mut reader: R,
    mut writer: W,
) -> i32 {
    let mut input = String::new();
    if let Err(e) = reader.read_to_string(&mut input) {
        eprintln!("kintsugi-hook: failed to read stdin: {e}");
        return 0; // fail-open
    }
    let outcome = handle_with_event(dialect, &input, event);
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
        assert_eq!(handle(payload), HookOutcome::silent());
    }

    #[test]
    fn held_for_approval_guides_stop_approve_continue() {
        let msg = held_for_approval("recursively deletes files.", "abcd1234-5678-90ab-cdef");
        assert!(msg.contains("recursively deletes files."));
        assert!(
            msg.contains("do NOT run it") && msg.contains("work around"),
            "must tell the agent to stop, not run or work around it"
        );
        assert!(
            msg.contains("Kintsugi app") || msg.contains("Approve & run"),
            "should point at approving in the app"
        );
        assert!(
            msg.contains("kintsugi run abcd1234"),
            "should give the guarded CLI run command with the short id"
        );
        assert!(msg.contains("undo"), "should mention reversibility");
        assert!(
            msg.contains("continue"),
            "should set up the human-driven resume (tell the agent to continue)"
        );
    }

    #[test]
    fn malformed_payload_is_allowed_silently() {
        assert_eq!(handle("not json"), HookOutcome::silent());
    }

    #[test]
    fn empty_command_is_allowed_silently() {
        let payload = r#"{"tool_name":"Bash","tool_input":{"command":"   "}}"#;
        assert_eq!(handle(payload), HookOutcome::silent());
    }

    #[test]
    fn run_io_allows_non_shell_tool_silently() {
        let input = br#"{"tool_name":"Edit","tool_input":{"file_path":"x"}}"#;
        let mut out = Vec::new();
        let code = run_io(Dialect::Claude, &input[..], &mut out);
        assert_eq!(code, 0);
        assert!(out.is_empty(), "allow-silent writes nothing");
    }

    #[test]
    fn dialect_from_args_reads_flag_forms() {
        assert_eq!(
            dialect_from_args(["--agent".to_string(), "cursor".to_string()]),
            Dialect::Cursor
        );
        assert_eq!(
            dialect_from_args(["--agent=qwen".to_string()]),
            Dialect::Qwen
        );
        // No flag → Claude (backwards compatible).
        assert_eq!(dialect_from_args(Vec::<String>::new()), Dialect::Claude);
        // Unknown → Claude fallback.
        assert_eq!(
            dialect_from_args(["--agent=banana".to_string()]),
            Dialect::Claude
        );
    }

    // ----- PostToolUse routing (V1.1) -----------------------------------------

    #[test]
    fn post_tool_use_event_is_observed_never_gated() {
        // Sessionless so the ingest send is skipped (no daemon in unit
        // tests): a post event is pure observation — silent, no verdict.
        let payload = r#"{
            "hook_event_name": "PostToolUse",
            "tool_name": "WebFetch",
            "tool_input": { "url": "https://example.com/p" },
            "tool_response": "page body",
            "cwd": "/work"
        }"#;
        assert_eq!(handle(payload), HookOutcome::silent());
    }

    #[test]
    fn post_tool_use_shell_result_is_never_rejudged_as_a_proposal() {
        // The same catastrophic Bash call, but as a PostToolUse event: it
        // already ran. Re-judging a completed call would double-log it and
        // "deny" an action that cannot be undone by a deny — and the pre-tool
        // path WOULD deny this fail-closed, so silence here proves the post
        // routing held and never touched the decision path.
        let payload = r#"{
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": "rm -rf /" },
            "tool_response": "done"
        }"#;
        assert_eq!(handle(payload), HookOutcome::silent());
    }

    #[test]
    fn is_post_tool_use_matches_only_the_explicit_event_marker() {
        assert!(is_post_tool_use(
            r#"{"hook_event_name":"PostToolUse","tool_name":"Read"}"#
        ));
        // Pre-tool events, other events, a missing marker, and garbage all
        // take the decision path — the post route is never entered on a guess
        // (misrouting a PreToolUse payload here would bypass the shell gate).
        assert!(!is_post_tool_use(
            r#"{"hook_event_name":"PreToolUse","tool_name":"Bash"}"#
        ));
        assert!(!is_post_tool_use(
            r#"{"hook_event_name":"postToolUse","tool_name":"Bash"}"#
        ));
        assert!(!is_post_tool_use(r#"{"tool_name":"Bash"}"#));
        assert!(!is_post_tool_use("not json"));
        assert!(!is_post_tool_use(r#"["an array"]"#));
        assert!(!is_post_tool_use("42"));
    }

    // ----- --event (V1.1 file-write observation) ------------------------------

    #[test]
    fn event_from_args_defaults_to_the_pre_tool_path() {
        // No flag (every pre-V1.1 invocation) and an unknown value both take the
        // exact original path — a typo can never silently disable the shell gate.
        assert_eq!(event_from_args(Vec::<String>::new()), HookEvent::PreToolUse);
        assert_eq!(
            event_from_args(["--agent".to_string(), "opencode".to_string()]),
            HookEvent::PreToolUse
        );
        assert_eq!(
            event_from_args(["--event".to_string(), "writes".to_string()]),
            HookEvent::PreToolUse
        );
        // Both flag forms.
        assert_eq!(
            event_from_args(["--event".to_string(), "write".to_string()]),
            HookEvent::Write
        );
        assert_eq!(
            event_from_args(["--agent=opencode".to_string(), "--event=write".to_string()]),
            HookEvent::Write
        );
    }

    #[test]
    fn a_write_event_is_observation_only_and_never_gates() {
        // No session → send_write skips before any IPC, so this is a pure unit
        // test. The contract: silent, exit 0, whatever the payload.
        let payload = r#"{
            "tool": "write",
            "args": { "filePath": "/work/repo/src/notes.rs" },
            "cwd": "/work/repo"
        }"#;
        assert_eq!(
            handle_with_event(Dialect::OpenCode, payload, HookEvent::Write),
            HookOutcome::silent()
        );
    }

    #[test]
    fn a_write_event_never_routes_into_the_shell_decision_path() {
        // Even a payload that would be a catastrophic shell command is inert on
        // the write route: a write observation can never deny, and shell parsing
        // is not entered at all.
        let payload = r#"{"command":"rm -rf /","cwd":"/work"}"#;
        assert_eq!(
            handle_with_event(Dialect::Cursor, payload, HookEvent::Write),
            HookOutcome::silent()
        );
        // Garbage is equally harmless.
        assert_eq!(
            handle_with_event(Dialect::OpenCode, "not json", HookEvent::Write),
            HookOutcome::silent()
        );
    }

    #[test]
    fn run_io_event_handles_the_write_route() {
        let input = br#"{"tool":"write","args":{"filePath":"/work/repo/x"},"cwd":"/work/repo"}"#;
        let mut out = Vec::new();
        let code = run_io_event(Dialect::OpenCode, HookEvent::Write, &input[..], &mut out);
        assert_eq!(code, 0);
        assert!(out.is_empty(), "a write observation writes nothing");
    }
}
