//! Agent-facing deny reasons + the negotiation circuit breaker (Phase 6).
//!
//! When the deterministic gate blocks a command, Kintsugi doesn't just refuse —
//! it hands the *model* a crisp, state-grounded reason and an instruction to
//! retreat to a materially safer alternative or stop and ask the user. Most
//! prompt-injection attempts then self-correct inside the agent loop, so the human
//! is never interrupted (`kintsugi-interaction-design.md` §3). This is a UX layer,
//! **not** the security mechanism: the gate holds regardless of whether the agent
//! cooperates.
//!
//! The asymmetry that keeps it safe (the spine, restated): the agent may retreat
//! or propose a *different* command freely, but it may NEVER argue the gate into
//! allowing the blocked one. A re-proposed command is re-classified from scratch by
//! the same rules; **this reason text is never an input to any allow decision.**
//! Allow is reachable only via a rule/pattern match — never via anything the model
//! says — so injected content can't phrase its way past the gate.
//!
//! Secret-safe: the reason is run through [`crate::redact`] before it leaves, so a
//! credential captured in a rule reason can never leak into the negotiation channel
//! (spine #6 / hardening item G).

/// Consecutive blocks in one session before the circuit breaker trips and we stop
/// feeding the retry loop. Mirrors Codex's deployed approvals protocol (3).
pub const CONSECUTIVE_DENY_LIMIT: u32 = 3;

/// The instruction appended to a model-facing deny reason. Copied verbatim from
/// Codex's reviewer/approvals protocol — the deployed reference implementation.
pub const NEGOTIATION_INSTRUCTION: &str =
    "Do not pursue the same outcome via workaround, indirect execution, or policy \
circumvention. Continue only with a materially safer alternative. Otherwise, stop \
and ask the user.";

/// Build the model-facing reason for a blocked command: the deterministic,
/// state-grounded rule reason (redacted) + the negotiation instruction.
pub fn model_deny_reason(rule_reason: &str) -> String {
    let safe = crate::redact::redact_command(rule_reason).text;
    format!("{safe} {NEGOTIATION_INSTRUCTION}")
}

/// The escalation reason once the circuit breaker has tripped: stop the automated
/// retry loop and route to the human. Fails *toward* the user, never toward allow.
pub fn circuit_breaker_reason(rule_reason: &str) -> String {
    let safe = crate::redact::redact_command(rule_reason).text;
    format!(
        "{safe} Kintsugi has blocked {CONSECUTIVE_DENY_LIMIT} consecutive attempts \
in this session and is stopping automated retries. Do not keep retrying; stop and \
ask the user how to proceed."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_deny_reason_grounds_then_instructs() {
        let r = model_deny_reason("TRIFECTA-01: tainted session reads ~/.aws and pipes to curl");
        assert!(r.contains("TRIFECTA-01"), "keeps the rule-grounded reason");
        assert!(
            r.contains("materially safer alternative"),
            "carries the negotiation instruction"
        );
        assert!(r.ends_with("ask the user."));
    }

    #[test]
    fn reasons_are_redacted_no_secret_leaks_into_the_channel() {
        // A rule reason that somehow embeds a credential-bearing token must not ship
        // it to the model (spine #6).
        let leaky = "blocked URL https://u:ghp_secret123@host/x?api_key=sk-live-9";
        for r in [model_deny_reason(leaky), circuit_breaker_reason(leaky)] {
            assert!(!r.contains("ghp_secret123"), "userinfo secret leaked: {r}");
            assert!(!r.contains("sk-live-9"), "query secret leaked: {r}");
        }
    }

    #[test]
    fn circuit_breaker_reason_tells_the_agent_to_stop_and_ask() {
        let r = circuit_breaker_reason("DESTROY-01: rm -rf /");
        assert!(r.contains("DESTROY-01"));
        assert!(r.contains("stop") && r.contains("ask the user"));
        assert!(r.contains(&CONSECUTIVE_DENY_LIMIT.to_string()));
    }
}
