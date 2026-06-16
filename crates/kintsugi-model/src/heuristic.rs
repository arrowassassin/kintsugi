//! The deterministic, dependency-free scorer.
//!
//! Always available, sub-microsecond, and the graceful-degradation path when no
//! GGUF model is present. It produces an honest one-line summary from the Tier-1
//! rule id and a severity score from the class plus signal words in the command.
//! It never sees a catastrophic command in the decision path (the daemon only
//! scores the ambiguous band), but it can summarize one for the hold card.

use kintsugi_core::{Class, ProposedCommand};

use crate::{ModelOutput, Scorer};

/// A fixed scoring backend with no external dependencies.
#[derive(Debug, Default, Clone)]
pub struct HeuristicScorer;

impl HeuristicScorer {
    pub fn new() -> Self {
        Self
    }
}

impl Scorer for HeuristicScorer {
    fn name(&self) -> &str {
        "heuristic"
    }

    fn score(&self, cmd: &ProposedCommand, class: Class, rule: &str) -> ModelOutput {
        ModelOutput {
            summary: summarize(&cmd.raw, class, rule),
            risk: risk_for(&cmd.raw, class),
        }
    }
}

/// One plain-English sentence about the command.
fn summarize(raw: &str, class: Class, rule: &str) -> String {
    let prog = raw.split_whitespace().next().unwrap_or("the command");
    let detail = friendly(rule);
    match class {
        Class::Safe => format!("Runs `{prog}` — a read-only or build/test command."),
        Class::Ambiguous => {
            if detail.is_empty() {
                format!("Runs `{prog}`; effects are unclear, so it needs your call.")
            } else {
                format!("Runs `{prog}` — {detail}")
            }
        }
        Class::Catastrophic => {
            if detail.is_empty() {
                format!("`{prog}` is destructive and may be irreversible.")
            } else {
                format!("{detail} This is hard or impossible to undo.")
            }
        }
    }
}

/// A severity score 0..=100, anchored by class and nudged by signal words.
fn risk_for(raw: &str, class: Class) -> u8 {
    let base: i32 = match class {
        Class::Safe => 5,
        Class::Ambiguous => 45,
        Class::Catastrophic => 95,
    };
    let lower = raw.to_lowercase();
    let mut score = base;
    // Words that signal blast radius / irreversibility.
    for (needle, bump) in [
        ("--force", 15),
        ("-f", 8),
        ("--hard", 15),
        ("-rf", 20),
        ("-r ", 8),
        ("prod", 20),
        ("production", 20),
        ("--all", 12),
        ("-a ", 6),
        ("/", 4),
        ("sudo", 10),
        ("--no-preserve-root", 25),
        ("drop ", 20),
        ("delete", 12),
        ("destroy", 20),
    ] {
        if lower.contains(needle) {
            score += bump;
        }
    }
    score.clamp(0, 100) as u8
}

/// Short human phrase for a rule id (kept terse for a one-line summary).
fn friendly(rule: &str) -> &'static str {
    match rule.split_whitespace().next().unwrap_or(rule) {
        "rm:recursive" => "recursively deletes files and directories.",
        "rm:force-root" => "force-deletes a top-level path.",
        "git:force-push" => "force-pushes, overwriting remote history.",
        "git:reset-hard" => "discards local commits and changes.",
        "git:clean" => "deletes untracked files.",
        "git:history-rewrite" => "rewrites git history.",
        "git:branch-delete" => "force-deletes a branch.",
        "terraform:destroy" => "tears down infrastructure.",
        "kubectl:delete" => "deletes Kubernetes resources.",
        "helm:uninstall" => "uninstalls a release.",
        "sql:destructive" | "sql:truncate" => "runs destructive SQL.",
        "dd:write" | "disk:destructive" | "disk:mkfs" | "disk:block-device-write" => {
            "writes directly to a disk or device."
        }
        "secret:read" => "reads a secret or credential file.",
        "net:pipe-to-shell" => "pipes a download straight into a shell.",
        "docker:system-prune" | "docker:volume-destroy" => "destroys Docker data.",
        "forkbomb" => "is a fork bomb that will exhaust the system.",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(raw: &str) -> ProposedCommand {
        ProposedCommand::new("t", "/tmp", vec![raw.into()], raw)
    }

    #[test]
    fn safe_is_low_risk() {
        let out = HeuristicScorer::new().score(&cmd("ls -la"), Class::Safe, "safe:ls");
        assert!(out.risk < 20);
        assert!(out.summary.contains("read-only") || out.summary.contains("build"));
    }

    #[test]
    fn catastrophic_is_high_risk_and_explained() {
        let out =
            HeuristicScorer::new().score(&cmd("rm -rf /"), Class::Catastrophic, "rm:recursive");
        assert!(out.risk >= 95);
        assert!(out.summary.to_lowercase().contains("undo") || out.summary.contains("delete"));
    }

    #[test]
    fn ambiguous_signal_words_raise_score() {
        let plain =
            HeuristicScorer::new().score(&cmd("make build"), Class::Ambiguous, "ambiguous:make");
        let prod = HeuristicScorer::new().score(
            &cmd("./deploy.sh --force production"),
            Class::Ambiguous,
            "ambiguous:deploy.sh",
        );
        assert!(prod.risk > plain.risk, "prod/force should score higher");
        assert!(prod.risk <= 100);
    }

    #[test]
    fn risk_is_always_in_range() {
        let out = HeuristicScorer::new().score(
            &cmd("sudo rm -rf / --no-preserve-root --force production drop destroy"),
            Class::Catastrophic,
            "rm:recursive",
        );
        assert!(out.risk <= 100);
    }
}
