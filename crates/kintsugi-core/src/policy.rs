//! Project and global policy (`.kintsugi.toml`).
//!
//! A repo may commit an `.kintsugi.toml` to add allow/deny rules and set the mode;
//! global defaults live under the user's config dir. Repo settings override
//! global ones. This module is pure: parsing, merging, matching, and applying a
//! policy to a verdict. Loading the files from disk is the daemon's job.
//!
//! Security spine: policy may always *add* caution (a `deny` rule escalates any
//! command to Hold/Deny). A policy `allow` may tame the ambiguous band, but it
//! **never downgrades a rule-based catastrophic block** — that hard floor stands.
//! The one auth-posture knob (`[security] require_approval_proof`, default on) is
//! deliberately NOT symmetric across scopes: a repo may require the proof but can
//! never waive it, because the repo file lives in the workspace an agent writes.
//! Only the user-owned global scope can turn it off, and a waiving approval is
//! still recorded as an audit event.

use serde::Deserialize;

use crate::types::{Class, Decision, Mode, Verdict};

/// A parsed policy document.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct Policy {
    /// Optional operating mode for this scope.
    #[serde(default)]
    pub mode: Option<Mode>,
    /// Risk threshold (0..=100) for the graduated unattended band: an ambiguous
    /// command scored at/above this is denied+queued, below it is allowed.
    #[serde(default)]
    pub threshold: Option<u8>,
    /// Allow/deny rule lists.
    #[serde(default)]
    pub rules: Rules,
    /// Provenance (taint-aware trifecta guard) settings.
    #[serde(default)]
    pub provenance: Provenance,
    /// Security-posture settings.
    #[serde(default)]
    pub security: Security,
}

/// Security-posture settings (`[security]`).
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct Security {
    /// Whether approving a held command over IPC requires proof of the admin
    /// password. Absent ⇒ required (the Phase 7 default, a deliberate
    /// human-approved behavior change): a same-user agent process that can
    /// reach the owner-only socket and speak the protocol cannot approve its
    /// own held command silently — the attempt fails loudly and is audited.
    ///
    /// Only the **user-owned global** policy may waive it. A repo-level
    /// `.kintsugi.toml` can require the proof but can never waive it: that file
    /// lives in the workspace an agent writes, so honouring a repo `false` would
    /// let one ordinary file write re-enable silent self-approval. A waived
    /// approval still writes its audit row, so it can never look like a human's.
    #[serde(default)]
    pub require_approval_proof: Option<bool>,
}

/// Provenance / taint-aware flow-control settings (`[provenance]`).
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct Provenance {
    /// Whether the trifecta guard is active. Absent ⇒ on (the safe default): the
    /// guard only ever *adds* caution, so it is enabled unless explicitly turned
    /// off for a noisy scope.
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// Default risk threshold for the ambiguous band when none is configured.
pub const DEFAULT_THRESHOLD: u8 = 50;

/// The allow/deny rule lists.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct Rules {
    /// Commands to treat as auto-allow (tames the ambiguous band; never
    /// downgrades a catastrophic block).
    #[serde(default)]
    pub allow: Vec<String>,
    /// Commands to force to Hold/Deny regardless of class.
    #[serde(default)]
    pub deny: Vec<String>,
}

/// What a policy says about a specific command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    /// No rule matched.
    None,
    /// An allow rule matched.
    Allow,
    /// A deny rule matched (takes precedence over allow).
    Deny,
}

impl Policy {
    /// Parse a policy from TOML text.
    pub fn parse(toml_str: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(toml_str)
    }

    /// Merge `repo` over `global`: repo mode wins; rule lists are concatenated
    /// (global first, then repo).
    pub fn merge(global: Policy, repo: Policy) -> Policy {
        let mut allow = global.rules.allow;
        allow.extend(repo.rules.allow);
        let mut deny = global.rules.deny;
        deny.extend(repo.rules.deny);
        Policy {
            mode: repo.mode.or(global.mode),
            threshold: repo.threshold.or(global.threshold),
            rules: Rules { allow, deny },
            provenance: Provenance {
                // Same scope rule as `[security]` below, for the same reason: the
                // repo file is agent-writable, so it may ENABLE a guardrail but
                // never disable one. Only the user-owned global scope can opt out.
                enabled: match (repo.provenance.enabled, global.provenance.enabled) {
                    (Some(true), _) => Some(true),
                    (_, Some(false)) => Some(false),
                    (_, Some(true)) => Some(true),
                    _ => None,
                },
            },
            security: Security {
                // A repo may REQUIRE the proof; it may never waive it. The repo
                // policy file lives in the workspace the agent writes, so any
                // weakening here is agent-reachable — the opt-out is honoured
                // only from the user-owned global scope.
                require_approval_proof: match (
                    repo.security.require_approval_proof,
                    global.security.require_approval_proof,
                ) {
                    (Some(true), _) => Some(true),   // a repo can always tighten
                    (_, Some(false)) => Some(false), // the user's scope can waive
                    (_, Some(true)) => Some(true),
                    _ => None, // default (true) applies
                },
            },
        }
    }

    /// The effective risk threshold for the ambiguous band.
    pub fn risk_threshold(&self) -> u8 {
        self.threshold.unwrap_or(DEFAULT_THRESHOLD)
    }

    /// Whether the provenance trifecta guard is enabled (default: true).
    pub fn provenance_enabled(&self) -> bool {
        self.provenance.enabled.unwrap_or(true)
    }

    /// Whether IPC approval requires an admin-password proof (default: true —
    /// see [`Security::require_approval_proof`]). Only meaningful on a daemon
    /// with a provisioned vault; with no vault there is nothing to prove and
    /// approval stays bare (the shutdown mirror).
    pub fn require_approval_proof(&self) -> bool {
        self.security.require_approval_proof.unwrap_or(true)
    }

    /// Decide what this policy says about a command. Deny wins over allow.
    pub fn action_for(&self, command: &str) -> PolicyAction {
        let cmd = command.trim();
        if self.rules.deny.iter().any(|p| matches(p, cmd)) {
            return PolicyAction::Deny;
        }
        if self.rules.allow.iter().any(|p| matches(p, cmd)) {
            return PolicyAction::Allow;
        }
        PolicyAction::None
    }
}

/// Apply a policy action to a verdict under a mode.
///
/// - `Deny` escalates: Attended→Hold, Unattended→Deny, Notify→unchanged (notify
///   never blocks). The class is preserved.
/// - `Allow` downgrades Safe/Ambiguous to Allow, but leaves a Catastrophic
///   command held — the hard floor is never lifted by static config.
/// - `None` leaves the verdict untouched.
pub fn adjust_for_policy(mut verdict: Verdict, action: PolicyAction, mode: Mode) -> Verdict {
    match action {
        PolicyAction::None => verdict,
        PolicyAction::Deny => {
            match mode {
                Mode::Attended => verdict.decision = Decision::Hold,
                Mode::Unattended => verdict.decision = Decision::Deny,
                Mode::Notify => {} // visibility-first: record but never block
            }
            verdict.reason = format!("policy:deny ({})", verdict.reason);
            verdict
        }
        PolicyAction::Allow => {
            if verdict.class == Class::Catastrophic {
                // Hard floor: never auto-allow a catastrophic command via config.
                verdict.reason = format!("policy:allow-ignored-catastrophic ({})", verdict.reason);
                verdict
            } else {
                verdict.decision = Decision::Allow;
                verdict.reason = format!("policy:allow ({})", verdict.reason);
                verdict
            }
        }
    }
}

/// Match a policy pattern against a command.
///
/// `*` is a wildcard. Without a wildcard, a pattern matches the whole command or
/// a token-prefix of it (so `git push` matches `git push --force origin main`).
pub fn matches(pattern: &str, command: &str) -> bool {
    let pattern = pattern.trim();
    let command = command.trim();
    if pattern.is_empty() {
        return false;
    }
    if pattern.contains('*') {
        glob_match(pattern, command)
    } else {
        command == pattern || command.starts_with(&format!("{pattern} "))
    }
}

/// A tiny glob matcher supporting only `*` (matches any run of characters).
fn glob_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    let anchored_start = !pattern.starts_with('*');
    let anchored_end = !pattern.ends_with('*');

    let mut pos = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        match text[pos..].find(part) {
            Some(idx) => {
                let abs = pos + idx;
                if i == 0 && anchored_start && abs != 0 {
                    return false;
                }
                pos = abs + part.len();
            }
            None => return false,
        }
    }
    if anchored_end {
        if let Some(last) = parts.iter().rev().find(|p| !p.is_empty()) {
            return text.ends_with(last);
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mode_and_rules() {
        let p = Policy::parse(
            r#"
            mode = "notify"
            [rules]
            allow = ["cargo run"]
            deny = ["git push *", "rm -rf"]
            "#,
        )
        .unwrap();
        assert_eq!(p.mode, Some(Mode::Notify));
        assert_eq!(p.rules.allow, vec!["cargo run"]);
        assert_eq!(p.rules.deny.len(), 2);
    }

    #[test]
    fn empty_policy_parses() {
        let p = Policy::parse("").unwrap();
        assert_eq!(p, Policy::default());
    }

    #[test]
    fn prefix_matching() {
        assert!(matches("git push", "git push --force origin main"));
        assert!(matches("git push", "git push"));
        assert!(!matches("git push", "git pushing")); // token boundary
        assert!(!matches("git push", "git status"));
    }

    #[test]
    fn glob_matching() {
        assert!(matches("rm *", "rm file.txt"));
        assert!(matches("*secret*", "cat my-secret-file"));
        assert!(matches("git * --force", "git push --force"));
        assert!(!matches("git * --force", "git push origin"));
    }

    #[test]
    fn deny_takes_precedence_over_allow() {
        let p = Policy {
            mode: None,
            threshold: None,
            rules: Rules {
                allow: vec!["deploy".into()],
                deny: vec!["deploy".into()],
            },
            provenance: Provenance::default(),
            security: Security::default(),
        };
        assert_eq!(p.action_for("deploy now"), PolicyAction::Deny);
        assert_eq!(p.risk_threshold(), DEFAULT_THRESHOLD);
    }

    #[test]
    fn approval_proof_defaults_on_and_parses_off() {
        // Absent ⇒ required (the Phase 7 default: a same-user agent approving its
        // own held command becomes loud, failed, and audited instead of silent).
        assert!(Policy::default().require_approval_proof());
        assert!(Policy::parse("mode = \"attended\"")
            .unwrap()
            .require_approval_proof());
        // Explicitly disabled (the documented opt-out for the pre-Phase-7 flow).
        let off = Policy::parse("[security]\nrequire_approval_proof = false").unwrap();
        assert!(!off.require_approval_proof());
        // Explicit on.
        let on = Policy::parse("[security]\nrequire_approval_proof = true").unwrap();
        assert!(on.require_approval_proof());
    }

    #[test]
    fn merge_repo_can_tighten_but_never_waive_approval_proof() {
        // A repo-level `.kintsugi.toml` lives in the workspace an agent writes, so
        // it may only ever ADD the requirement. Ignoring a repo's `false` is the
        // whole point: otherwise one ordinary file write re-enables bare
        // self-approval for a held catastrophic command.
        let repo_off = Policy::parse("[security]\nrequire_approval_proof = false").unwrap();
        assert!(
            Policy::merge(Policy::default(), repo_off.clone()).require_approval_proof(),
            "a repo must not be able to waive the proof"
        );

        // The user-owned global scope IS allowed to waive it…
        let global_off = Policy::parse("[security]\nrequire_approval_proof = false").unwrap();
        assert!(!Policy::merge(global_off.clone(), Policy::default()).require_approval_proof());
        assert!(!Policy::merge(global_off.clone(), repo_off.clone()).require_approval_proof());

        // …but a repo may still re-arm it for its own scope.
        let repo_on = Policy::parse("[security]\nrequire_approval_proof = true").unwrap();
        assert!(Policy::merge(global_off, repo_on).require_approval_proof());

        // And a global opt-in is never weakened by a repo saying false.
        let global_on = Policy::parse("[security]\nrequire_approval_proof = true").unwrap();
        assert!(Policy::merge(global_on, repo_off).require_approval_proof());
    }

    #[test]
    fn provenance_defaults_on_and_parses_off() {
        // Absent ⇒ enabled (safe default).
        assert!(Policy::default().provenance_enabled());
        assert!(Policy::parse("mode = \"attended\"")
            .unwrap()
            .provenance_enabled());
        // Explicitly disabled for a noisy scope.
        let off = Policy::parse("[provenance]\nenabled = false").unwrap();
        assert!(!off.provenance_enabled());
        // Explicit on.
        let on = Policy::parse("[provenance]\nenabled = true").unwrap();
        assert!(on.provenance_enabled());
    }

    #[test]
    fn merge_repo_can_enable_but_not_disable_provenance() {
        // Same scope rule as the approval proof: the repo file is agent-writable,
        // so it may turn the guardrail ON for its own scope and never OFF.
        let repo_off = Policy::parse("[provenance]\nenabled = false").unwrap();
        assert!(
            Policy::merge(Policy::default(), repo_off.clone()).provenance_enabled(),
            "a repo must not be able to disable the trifecta guard"
        );

        // The user-owned global scope may disable it…
        let global_off = Policy::parse("[provenance]\nenabled = false").unwrap();
        assert!(!Policy::merge(global_off.clone(), Policy::default()).provenance_enabled());

        // …and a repo may still re-arm it locally.
        let repo_on = Policy::parse("[provenance]\nenabled = true").unwrap();
        assert!(Policy::merge(global_off, repo_on).provenance_enabled());
    }

    #[test]
    fn merge_repo_overrides_mode_and_extends_rules() {
        let global = Policy::parse("mode = \"attended\"\n[rules]\nallow=[\"a\"]").unwrap();
        let repo = Policy::parse("mode = \"notify\"\n[rules]\ndeny=[\"b\"]").unwrap();
        let merged = Policy::merge(global, repo);
        assert_eq!(merged.mode, Some(Mode::Notify));
        assert_eq!(merged.rules.allow, vec!["a"]);
        assert_eq!(merged.rules.deny, vec!["b"]);
    }

    #[test]
    fn deny_escalates_safe_to_hold_in_attended() {
        let v = Verdict::rules(Class::Safe, Decision::Allow, "safe:ls");
        let adjusted = adjust_for_policy(v, PolicyAction::Deny, Mode::Attended);
        assert_eq!(adjusted.decision, Decision::Hold);
        assert!(adjusted.reason.starts_with("policy:deny"));
    }

    #[test]
    fn deny_in_notify_does_not_block() {
        let v = Verdict::rules(Class::Safe, Decision::Allow, "safe:ls");
        let adjusted = adjust_for_policy(v, PolicyAction::Deny, Mode::Notify);
        assert_eq!(adjusted.decision, Decision::Allow);
    }

    #[test]
    fn allow_never_downgrades_catastrophic() {
        let v = Verdict::rules(Class::Catastrophic, Decision::Hold, "rm:recursive");
        let adjusted = adjust_for_policy(v, PolicyAction::Allow, Mode::Attended);
        assert_eq!(adjusted.decision, Decision::Hold, "hard floor must stand");
    }

    #[test]
    fn allow_tames_ambiguous() {
        let v = Verdict::rules(Class::Ambiguous, Decision::Hold, "ambiguous:make");
        let adjusted = adjust_for_policy(v, PolicyAction::Allow, Mode::Attended);
        assert_eq!(adjusted.decision, Decision::Allow);
    }
}
