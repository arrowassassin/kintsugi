//! The "hold card" — the one moment Aegis must be unmissable.
//!
//! Calm authority: one plain-English line naming the risk, the raw command in a
//! quiet block beneath it, and two (well, three) keys. A single reserved accent
//! appears only here. Per the design system, every state is also a word, never
//! color alone, and `NO_COLOR` is respected.

use aegis_core::{Class, Verdict};

const ACCENT: &str = "\u{1b}[1;33m"; // bold yellow — the one reserved accent
const DENY: &str = "\u{1b}[1;31m"; // bold red — catastrophic
const DIM: &str = "\u{1b}[2m";
const RESET: &str = "\u{1b}[0m";

/// Render the hold card for a held command. `color` enables the single accent.
pub fn render(raw: &str, verdict: &Verdict, color: bool) -> String {
    let (accent, headline) = match verdict.class {
        Class::Catastrophic => (DENY, "This command is catastrophic and cannot be undone."),
        Class::Ambiguous => (ACCENT, "This command needs your decision."),
        Class::Safe => (ACCENT, "This command is held."),
    };
    // Prefer the model's one-line summary (Phase 2); fall back to the rule phrase.
    let reason = verdict
        .summary
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| friendly_reason(&verdict.reason));

    let mut out = String::new();
    let bar = "─".repeat(60);
    let paint = |s: &str, code: &str| {
        if color {
            format!("{code}{s}{RESET}")
        } else {
            s.to_string()
        }
    };

    out.push('\n');
    out.push_str(&paint(&bar, DIM));
    out.push('\n');
    out.push_str(&paint(&format!("⚠ Aegis hold — {headline}"), accent));
    out.push('\n');
    if !reason.is_empty() {
        out.push_str(&paint(&format!("  {reason}"), DIM));
        out.push('\n');
    }
    if let Some(risk) = verdict.risk {
        out.push_str(&paint(&format!("  risk {}", risk_bar(risk)), DIM));
        out.push('\n');
    }
    out.push('\n');
    // The raw command, verbatim, in a quiet indented block.
    out.push_str("    ");
    out.push_str(raw);
    out.push('\n');
    out.push('\n');
    out.push_str("  [a] allow once   [d] deny   [r] always allow here");
    out.push('\n');
    out.push_str(&paint(&bar, DIM));
    out.push('\n');
    out
}

/// A 10-cell risk meter plus the numeric score (text, never color-only).
fn risk_bar(risk: u8) -> String {
    let filled = (risk as usize * 10 / 100).min(10);
    let meter: String = "█".repeat(filled) + &"░".repeat(10 - filled);
    format!("[{meter}] {risk}/100")
}

/// Turn a terse rule id into a short human phrase for the card.
fn friendly_reason(rule: &str) -> String {
    let base = rule.split_whitespace().next().unwrap_or(rule);
    match base {
        "rm:recursive" => "Recursively deletes files and directories.",
        "rm:force-root" => "Force-deletes a top-level path.",
        "git:force-push" => "Force-pushes, overwriting remote history.",
        "git:reset-hard" => "Discards local changes and commits.",
        "git:clean" => "Deletes untracked files.",
        "git:history-rewrite" => "Rewrites git history.",
        "git:branch-delete" => "Force-deletes a branch.",
        "terraform:destroy" => "Tears down infrastructure.",
        "kubectl:delete" => "Deletes Kubernetes resources.",
        "helm:uninstall" => "Uninstalls a release.",
        "sql:destructive" | "sql:truncate" => "Runs destructive SQL.",
        "dd:write" | "disk:destructive" | "disk:mkfs" | "disk:block-device-write" => {
            "Writes directly to a disk/device."
        }
        "secret:read" => "Reads a secret or credential file.",
        "net:pipe-to-shell" => "Pipes a download straight into a shell.",
        "docker:system-prune" | "docker:volume-destroy" => "Destroys Docker data.",
        "forkbomb" => "Fork bomb — will exhaust the system.",
        _ => "",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::{Class, Decision};

    fn verdict(class: Class, rule: &str) -> Verdict {
        Verdict::rules(class, Decision::Hold, rule)
    }

    #[test]
    fn card_shows_raw_command_verbatim() {
        let card = render(
            "rm -rf /",
            &verdict(Class::Catastrophic, "rm:recursive"),
            false,
        );
        assert!(card.contains("rm -rf /"));
        assert!(card.contains("catastrophic") || card.contains("cannot be undone"));
        assert!(card.contains("[a] allow"));
        assert!(card.contains("[d] deny"));
        assert!(card.contains("[r] always allow"));
    }

    #[test]
    fn card_has_no_ansi_without_color() {
        let card = render(
            "rm -rf /",
            &verdict(Class::Catastrophic, "rm:recursive"),
            false,
        );
        assert!(!card.contains('\u{1b}'));
    }

    #[test]
    fn card_uses_accent_with_color() {
        let card = render(
            "rm -rf /",
            &verdict(Class::Catastrophic, "rm:recursive"),
            true,
        );
        assert!(card.contains('\u{1b}'));
    }

    #[test]
    fn friendly_reason_explains_known_rules() {
        assert!(!friendly_reason("terraform:destroy").is_empty());
        assert!(friendly_reason("ambiguous:python").is_empty());
    }

    #[test]
    fn card_prefers_model_summary_and_shows_risk() {
        let mut v = Verdict::rules(Class::Ambiguous, Decision::Hold, "ambiguous:make");
        v.summary = Some("Builds and deploys the project.".into());
        v.risk = Some(70);
        let card = render("make deploy", &v, false);
        assert!(card.contains("Builds and deploys the project."));
        assert!(card.contains("70/100"));
    }

    #[test]
    fn risk_bar_is_clamped() {
        assert!(risk_bar(0).contains("0/100"));
        assert!(risk_bar(100).contains("100/100"));
        assert!(risk_bar(200).contains("200/100")); // numeric passthrough, bar capped
    }
}
