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
//! one `--agent <id>` flag, so a single `aegis-hook` binary serves every CLI.
//!
//! Fail-open: a malformed payload, a non-shell tool, or an unreachable daemon
//! never blocks the agent — *except* a catastrophic command with the daemon
//! down (denied fail-closed), or when `AEGIS_FAIL_CLOSED=1`.

use aegis_core::{shell, Class, Decision, ProposedCommand};
use aegis_daemon::Client;

pub use crate::dialect::HookOutcome;

use crate::dialect::{self, Dialect, Parsed, Resolved};

/// Handle one hook payload for a given dialect, performing the daemon round-trip.
pub fn handle_with(dialect: Dialect, input: &str) -> HookOutcome {
    let parsed = match dialect.parse(input) {
        Parsed::Shell(s) => s,
        Parsed::NotShell => return HookOutcome::silent(),
        Parsed::Bad(e) => {
            // Never block the agent on a payload we couldn't parse.
            eprintln!(
                "aegis-hook: could not parse {} payload: {e}",
                dialect.agent_id()
            );
            return HookOutcome::silent();
        }
    };

    let argv = shell::split(&parsed.command);
    let proposed = ProposedCommand::new(dialect.agent_id(), parsed.cwd, argv, parsed.command)
        .with_session(parsed.session_id);

    match Client::send(&proposed) {
        Ok(verdict) => {
            let resolved = match dialect::resolve(&verdict) {
                // A catastrophic command is held in Aegis's queue but denied to
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
            dialect.format(&resolved)
        }
        Err(e) => {
            // Daemon down: locally classify so a catastrophic command is still
            // denied (fail-closed for the hard floor); non-catastrophic honors
            // the fail-open default.
            if aegis_core::classify(&proposed).class == Class::Catastrophic {
                eprintln!(
                    "aegis-hook: daemon unreachable; denying catastrophic (fail-closed): {e}"
                );
                dialect.format(&dialect::Resolved::Deny(
                    "Aegis daemon unreachable; catastrophic command blocked (fail-closed)".into(),
                ))
            } else if fail_closed() {
                eprintln!("aegis-hook: daemon unreachable; denying (fail-closed): {e}");
                dialect.format(&dialect::Resolved::Deny(
                    "Aegis daemon unreachable (fail-closed)".into(),
                ))
            } else {
                eprintln!("aegis-hook: warning: daemon unreachable; allowing unguarded: {e}");
                dialect.pass()
            }
        }
    }
}

/// Backwards-compatible Claude Code entry point.
pub fn handle(input: &str) -> HookOutcome {
    handle_with(Dialect::Claude, input)
}

/// Augment a catastrophic deny with the guarded way to run it yourself.
///
/// A hook is one-shot: by the time you see this, the agent already got the deny.
/// The agent must never run a catastrophic itself, but the human can — via
/// `aegis run <id>`, which snapshots first (so `aegis undo` works), runs the
/// command in its original directory, and is gated on a real-terminal keypress
/// (so an agent shelling out to it still can't self-approve). The queue id is
/// the command's id, so we surface its short prefix here.
fn held_for_approval(reason: &str, id: &str) -> String {
    let short = id.get(..8).unwrap_or(id);
    format!(
        "{reason} Aegis blocked it; the agent will not run it. To run it yourself: \
         `aegis run {short}` — it snapshots the affected files first (so `aegis undo` \
         can roll them back) and confirms with a code typed at your terminal."
    )
}

fn fail_closed() -> bool {
    matches!(
        std::env::var("AEGIS_FAIL_CLOSED").ok().as_deref(),
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
                    eprintln!("aegis-hook: unknown --agent '{v}', defaulting to claude-code");
                    return Dialect::Claude;
                }
            }
        }
    }
    Dialect::Claude
}

/// Read the hook payload from stdin and emit the outcome, picking the dialect
/// from the process arguments.
pub fn run() -> i32 {
    let dialect = dialect_from_args(std::env::args().skip(1));
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    run_io(dialect, stdin.lock(), stdout.lock())
}

/// The hook over arbitrary reader/writer for a given dialect (testable).
pub fn run_io<R: std::io::Read, W: std::io::Write>(
    dialect: Dialect,
    mut reader: R,
    mut writer: W,
) -> i32 {
    let mut input = String::new();
    if let Err(e) = reader.read_to_string(&mut input) {
        eprintln!("aegis-hook: failed to read stdin: {e}");
        return 0; // fail-open
    }
    let outcome = handle_with(dialect, &input);
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
    fn held_for_approval_points_at_aegis_run_with_short_id() {
        let msg = held_for_approval("recursively deletes files.", "abcd1234-5678-90ab-cdef");
        assert!(msg.contains("recursively deletes files."));
        assert!(
            msg.contains("will not run"),
            "must say the agent won't run it"
        );
        assert!(
            msg.contains("aegis run abcd1234"),
            "should give the guarded run command"
        );
        assert!(msg.contains("undo"), "should mention reversibility");
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
}
