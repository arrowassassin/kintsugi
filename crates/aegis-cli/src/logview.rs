//! Rendering for `aegis log` and `aegis status`.
//!
//! Pure functions that turn event-log rows into text. Following the design
//! direction: calm by default, a single accent reserved for the one state that
//! must stand out (a held/denied dangerous action). Every state is also a word,
//! never color alone, and `NO_COLOR` is respected by the caller.

use aegis_core::{Class, Decision, LoggedEvent};
use time::macros::format_description;

const ACCENT: &str = "\u{1b}[1;33m"; // bold yellow — the one reserved accent
const DENY: &str = "\u{1b}[1;31m"; // bold red — a blocked action
const DIM: &str = "\u{1b}[2m";
const RESET: &str = "\u{1b}[0m";

/// Whether color should be used: honor `NO_COLOR`, otherwise follow the caller.
pub fn use_color(no_color_env: bool, is_tty: bool) -> bool {
    !no_color_env && is_tty
}

/// A short, fixed label for a decision (word, not just color).
fn decision_label(d: Decision) -> &'static str {
    match d {
        Decision::Allow => "allowed",
        Decision::Deny => "denied ",
        Decision::Hold => "held   ",
    }
}

/// Render a timeline of events, newest at the bottom (chronological).
pub fn render_log(events: &[LoggedEvent], color: bool) -> String {
    if events.is_empty() {
        return empty_state();
    }

    let time_fmt = format_description!("[hour]:[minute]:[second]");
    let mut out = String::new();
    out.push_str(&header(color));

    for ev in events {
        let t = ev
            .ts
            .format(&time_fmt)
            .unwrap_or_else(|_| "--:--:--".into());
        let decision = decision_label(ev.decision);
        let tag = if ev.redacted {
            String::new()
        } else {
            class_tag(ev.class)
        };
        let command = if ev.redacted {
            "⟨redacted⟩".to_string()
        } else {
            truncate(&ev.command, 60)
        };

        let line = format!(
            "{t}  {agent:<12}  {decision}  {tag}{command}",
            agent = truncate(&ev.agent, 12),
        );

        if color {
            if ev.redacted {
                out.push_str(&format!("{DIM}{line}{RESET}\n"));
            } else {
                match ev.decision {
                    Decision::Deny => out.push_str(&format!("{DENY}{line}{RESET}\n")),
                    Decision::Hold => out.push_str(&format!("{ACCENT}{line}{RESET}\n")),
                    Decision::Allow => out.push_str(&format!("{line}\n")),
                }
            }
        } else {
            out.push_str(&line);
            out.push('\n');
        }
    }
    out
}

fn header(color: bool) -> String {
    let h = format!(
        "{:<8}  {:<12}  {:<7}  {}\n",
        "time", "agent", "outcome", "command"
    );
    if color {
        format!("{DIM}{h}{RESET}")
    } else {
        h
    }
}

/// A bracketed tag for non-safe classes; empty for safe (keep the line quiet).
fn class_tag(class: Class) -> String {
    match class {
        Class::Safe => String::new(),
        Class::Catastrophic => "[catastrophic] ".to_string(),
        Class::Ambiguous => "[ambiguous] ".to_string(),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

fn empty_state() -> String {
    "No events yet.\n\nAegis is watching. Run a command through a wired agent \
     (or the $PATH shim) and it will appear here.\n"
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::ProposedCommand;
    use aegis_core::Verdict;

    fn event(agent: &str, raw: &str, class: Class, decision: Decision) -> LoggedEvent {
        // Build a LoggedEvent via the log so timestamps/fields are realistic.
        let log = aegis_core::EventLog::open_in_memory().unwrap();
        let cmd = ProposedCommand::new(agent, "/tmp", vec![raw.into()], raw);
        let verdict = Verdict::rules(class, decision, "test-rule");
        log.log_event(&cmd, &verdict, None).unwrap()
    }

    #[test]
    fn empty_log_shows_a_designed_empty_state() {
        let out = render_log(&[], false);
        assert!(out.contains("No events yet"));
        assert!(out.contains("watching"));
    }

    #[test]
    fn renders_rows_with_outcome_words() {
        let evs = vec![
            event("claude-code", "ls", Class::Safe, Decision::Allow),
            event("shim", "rm -rf /", Class::Catastrophic, Decision::Hold),
        ];
        let out = render_log(&evs, false);
        assert!(out.contains("allowed"));
        assert!(out.contains("held"));
        assert!(out.contains("[catastrophic]"));
        assert!(out.contains("rm -rf /"));
        // No ANSI codes when color is off.
        assert!(!out.contains('\u{1b}'));
    }

    #[test]
    fn color_mode_accents_only_dangerous_rows() {
        let evs = vec![
            event("a", "ls", Class::Safe, Decision::Allow),
            event("b", "drop table", Class::Catastrophic, Decision::Deny),
        ];
        let out = render_log(&evs, true);
        assert!(out.contains(DENY), "denied row should use the deny accent");
    }

    #[test]
    fn long_commands_are_truncated() {
        let long = "echo ".to_string() + &"x".repeat(200);
        let evs = vec![event("a", &long, Class::Safe, Decision::Allow)];
        let out = render_log(&evs, false);
        assert!(out.contains('…'));
    }

    #[test]
    fn no_color_env_disables_color() {
        assert!(!use_color(true, true));
        assert!(use_color(false, true));
        assert!(!use_color(false, false));
    }
}
