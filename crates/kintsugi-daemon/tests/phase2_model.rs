//! Phase 2 acceptance: the Tier-2 model fills summary/risk for the ambiguous
//! band, the graduated unattended threshold flips allow/deny, and the catastrophic
//! hard floor stands regardless of the model's score.

use std::sync::{Mutex, MutexGuard, OnceLock};

use kintsugi_core::{Class, Decision, Mode, ProposedCommand};
use kintsugi_daemon::Daemon;
use kintsugi_model::{ModelOutput, Scorer};

fn serial_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// A scorer that returns a fixed risk, to test the threshold boundary exactly.
struct FixedScorer(u8);
impl Scorer for FixedScorer {
    fn name(&self) -> &str {
        "fixed"
    }
    fn score(&self, _cmd: &ProposedCommand, _class: Class, _rule: &str) -> ModelOutput {
        ModelOutput {
            summary: "fixed summary".into(),
            risk: self.0,
        }
    }
}

fn propose(cwd: &std::path::Path, raw: &str) -> ProposedCommand {
    ProposedCommand::new(
        "shim",
        cwd,
        raw.split_whitespace().map(str::to_string).collect(),
        raw,
    )
}

fn daemon(tmp: &std::path::Path, mode: Mode, risk: u8) -> Daemon {
    std::env::set_var("KINTSUGI_CONFIG", tmp.join("none.toml"));
    Daemon::open(tmp.join("e.db"))
        .unwrap()
        .with_mode(mode)
        .with_scorer(Box::new(FixedScorer(risk)))
}

#[test]
fn ambiguous_gets_summary_and_risk_in_attended() {
    let _g = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    let d = daemon(tmp.path(), Mode::Attended, 42);
    let v = d.decide(&propose(tmp.path(), "make deploy"));

    assert_eq!(v.class, Class::Ambiguous);
    assert_eq!(v.decision, Decision::Hold, "attended still holds ambiguous");
    assert_eq!(v.tier, 2);
    assert_eq!(v.summary.as_deref(), Some("fixed summary"));
    assert_eq!(v.risk, Some(42));
}

#[test]
fn unattended_holds_ambiguous_and_model_never_downgrades() {
    let _g = serial_lock();
    let tmp = tempfile::tempdir().unwrap();

    // Spine rule #2: the model may only ADD caution. Unattended ambiguous is
    // denied (queued for review) regardless of how LOW the model scores it — the
    // model can never flip Deny -> Allow.
    for risk in [0u8, 30, 49, 80, 100] {
        let d = daemon(tmp.path(), Mode::Unattended, risk);
        let v = d.decide(&propose(tmp.path(), "make x"));
        assert_eq!(
            v.decision,
            Decision::Deny,
            "unattended ambiguous must deny at risk {risk} (model never auto-allows)"
        );
        // It still records the model's risk/summary for the human reviewing the queue.
        assert_eq!(v.risk, Some(risk));
        assert_eq!(v.tier, 2);
        assert!(v.summary.is_some());
    }
}

#[test]
fn catastrophic_floor_holds_regardless_of_low_risk() {
    let _g = serial_lock();
    let tmp = tempfile::tempdir().unwrap();

    // Even a risk of 0, the catastrophic command is never allowed by the model.
    let attended = daemon(tmp.path(), Mode::Attended, 0);
    let v = attended.decide(&propose(tmp.path(), "rm -rf /"));
    assert_eq!(v.class, Class::Catastrophic);
    assert_eq!(v.decision, Decision::Hold);
    assert!(
        v.summary.is_some(),
        "catastrophic still gets a hold-card summary"
    );

    let unattended = daemon(tmp.path(), Mode::Unattended, 0);
    assert_eq!(
        unattended.decide(&propose(tmp.path(), "rm -rf /")).decision,
        Decision::Deny,
        "unattended hard floor denies catastrophic"
    );
}

#[test]
fn safe_stays_on_the_model_free_fast_path() {
    let _g = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    // A scorer that would assign max risk; a Safe command must not consult it.
    let d = daemon(tmp.path(), Mode::Unattended, 100);
    let v = d.decide(&propose(tmp.path(), "ls -la"));
    assert_eq!(v.decision, Decision::Allow);
    assert_eq!(v.tier, 1, "safe path never bumps to tier 2");
    assert!(v.risk.is_none());
}

#[test]
fn explicit_human_allowlist_is_the_only_unattended_auto_proceed() {
    let _g = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("KINTSUGI_CONFIG", tmp.path().join("none.toml"));
    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    // A human-authored allow rule (not the model) lets a specific ambiguous
    // command proceed unattended — even at max model risk. This is the safe
    // escape valve that replaces the (removed) graduated auto-allow.
    std::fs::write(
        repo.join(".kintsugi.toml"),
        "mode = \"unattended\"\n\n[rules]\nallow = [\"make deploy\"]\n",
    )
    .unwrap();

    let d = Daemon::open(tmp.path().join("e.db"))
        .unwrap()
        .with_scorer(Box::new(FixedScorer(100)));
    // Allowlisted ambiguous command proceeds (human decision).
    assert_eq!(
        d.decide(&propose(&repo, "make deploy")).decision,
        Decision::Allow
    );
    // A different ambiguous command is still denied (model can't auto-allow).
    assert_eq!(
        d.decide(&propose(&repo, "make publish")).decision,
        Decision::Deny
    );

    std::env::remove_var("KINTSUGI_CONFIG");
}
