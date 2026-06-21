//! Phase 6 — agent-facing deny reasons + the negotiation circuit breaker.
//!
//! The negotiation layer reframes a *block* for the model and counts consecutive
//! blocks per session, but it is decision-preserving: it can never turn a block
//! into an allow, and it never denies work the rules would allow. Security is the
//! deterministic gate; negotiation only changes who/whether we interrupt.

use kintsugi_core::{negotiate, Class, Decision, ProposedCommand};
use kintsugi_daemon::Daemon;

fn cmd(raw: &str, session: &str, cwd: &std::path::Path) -> ProposedCommand {
    ProposedCommand::new("claude-code", cwd, vec![], raw).with_session(Some(session.to_string()))
}

#[test]
fn a_block_carries_the_model_facing_negotiation_instruction() {
    let tmp = tempfile::tempdir().unwrap();
    let daemon = Daemon::open(tmp.path().join("e.db")).unwrap();
    // Catastrophic is Held in attended mode (the adapter maps that to a deny).
    let v = daemon.handle(cmd("rm -rf /", "s1", tmp.path()));
    assert_eq!(v.decision, Decision::Hold);
    assert_eq!(v.class, Class::Catastrophic);
    assert!(
        v.reason.contains("materially safer alternative") && v.reason.contains("ask the user"),
        "block reason must instruct the model: {}",
        v.reason
    );
}

#[test]
fn an_ambiguous_ask_is_not_reframed_as_a_negotiation_deny() {
    let tmp = tempfile::tempdir().unwrap();
    let daemon = Daemon::open(tmp.path().join("e.db")).unwrap();
    // `make deploy` is ambiguous → Hold → a native `ask`, not a deny: it must keep
    // its clean reason (no "materially safer alternative" retry instruction).
    let v = daemon.handle(cmd("make deploy", "s1", tmp.path()));
    assert_eq!(v.decision, Decision::Hold);
    assert_eq!(v.class, Class::Ambiguous);
    assert!(
        !v.reason.contains("materially safer alternative"),
        "an ask must not carry the deny instruction: {}",
        v.reason
    );
}

#[test]
fn circuit_breaker_trips_after_three_consecutive_blocks() {
    let tmp = tempfile::tempdir().unwrap();
    let daemon = Daemon::open(tmp.path().join("e.db")).unwrap();

    let r1 = daemon.handle(cmd("rm -rf /", "s1", tmp.path())).reason;
    let r2 = daemon.handle(cmd("rm -rf /etc", "s1", tmp.path())).reason;
    assert!(
        !r1.contains("consecutive"),
        "first block is not yet tripped"
    );
    assert!(
        !r2.contains("consecutive"),
        "second block is not yet tripped"
    );

    let v3 = daemon.handle(cmd("rm -rf /var", "s1", tmp.path()));
    assert!(
        v3.reason.contains("consecutive attempts") && v3.reason.contains("ask the user"),
        "the {}rd block trips the breaker: {}",
        negotiate::CONSECUTIVE_DENY_LIMIT,
        v3.reason
    );
    // Tripping changes only the reason — never the decision (still a hard block).
    assert_eq!(v3.decision, Decision::Hold);
    assert_eq!(v3.class, Class::Catastrophic);
}

#[test]
fn the_streak_is_per_session_and_resets_on_an_allow() {
    let tmp = tempfile::tempdir().unwrap();
    let daemon = Daemon::open(tmp.path().join("e.db")).unwrap();

    // Two blocks in s1, but a different session s2 is unaffected (isolation).
    daemon.handle(cmd("rm -rf /", "s1", tmp.path()));
    daemon.handle(cmd("rm -rf /etc", "s1", tmp.path()));
    let other = daemon.handle(cmd("rm -rf /", "s2", tmp.path()));
    assert!(
        !other.reason.contains("consecutive"),
        "s2's first block must not see s1's streak"
    );

    // A safe, allowed command in s1 resets the streak…
    let safe = daemon.handle(cmd("ls -la", "s1", tmp.path()));
    assert_eq!(safe.decision, Decision::Allow);
    // …so the next block starts counting from one again (not tripped).
    let after = daemon.handle(cmd("rm -rf /", "s1", tmp.path()));
    assert!(
        !after.reason.contains("consecutive"),
        "an allow must reset the consecutive-block streak: {}",
        after.reason
    );
}

#[test]
fn the_breaker_never_denies_work_the_rules_allow() {
    // The safety invariant: negotiation/the breaker is escalation-of-messaging only.
    // Even after the breaker has tripped, a command the rules classify Safe is still
    // allowed — the gate's allow path is reachable only via rules, never blocked (or
    // opened) by anything the negotiation layer tracks.
    let tmp = tempfile::tempdir().unwrap();
    let daemon = Daemon::open(tmp.path().join("e.db")).unwrap();
    for raw in ["rm -rf /", "rm -rf /etc", "rm -rf /var", "rm -rf /usr"] {
        daemon.handle(cmd(raw, "s1", tmp.path())); // trip and exceed the breaker
    }
    let v = daemon.handle(cmd("git status", "s1", tmp.path()));
    assert_eq!(
        v.decision,
        Decision::Allow,
        "safe work stays allowed: {}",
        v.reason
    );
}

#[test]
fn negotiation_reason_does_not_pollute_the_audit_log() {
    // The model-facing instruction rides only on the returned verdict; the durable
    // log keeps the clean, rule-grounded reason for forensic review.
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("e.db");
    let daemon = Daemon::open(&db).unwrap();
    daemon.handle(cmd("rm -rf /", "s1", tmp.path()));

    let log = kintsugi_core::EventLog::open(&db).unwrap();
    let tail = log.tail(1).unwrap();
    assert!(
        !tail[0].reason.contains("materially safer alternative"),
        "the negotiation instruction must not be written to the audit log: {}",
        tail[0].reason
    );
}
