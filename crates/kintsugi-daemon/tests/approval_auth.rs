//! Daemon-side proof-of-human approval over IPC (Phase 7, T2.1).
//!
//! A same-user agent process can reach the owner-only socket and speak the
//! protocol; the point of approval auth is that a *bare* `Approve` from such a
//! process becomes loud (a clear error), failed (the queue item stays pending),
//! and audited (a hash-chained `admin` row) instead of silently succeeding.
//! The human path is the exact shutdown ritual: `AuthBegin("approve:<id>")` →
//! password → nonce-bound, op-bound, one-shot proof.
//!
//! Honest boundary (docs/security-assessment.md): this is not a boundary against
//! malicious code already running as your user that can read the vault; it makes
//! self-approval loud instead of silent.
#![cfg(unix)]

use std::sync::{Mutex, MutexGuard, OnceLock};

use kintsugi_core::admin;
use kintsugi_core::{Decision, Filter, ProposedCommand};
use kintsugi_daemon::{ipc, Daemon};

fn serial_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Provision a vault at `path` and point the daemon's resolver at it.
fn provision_at(path: &std::path::Path, pw: &str) {
    let prov = admin::provision(pw, &admin::LockedSettings::default()).unwrap();
    admin::save_vault(path, &prov.vault).unwrap();
}

/// The reasons of the `admin approve:<id>` audit rows for `id`.
fn approve_audit_reasons(daemon: &Daemon, id: &str) -> Vec<String> {
    let filter = Filter {
        grep: Some(format!("admin approve:{id}")),
        ..Filter::default()
    };
    daemon
        .log()
        .query(&filter)
        .unwrap()
        .into_iter()
        .map(|e| e.reason)
        .collect()
}

/// Propose an ambiguous command through the daemon (in-process, no socket):
/// held and enqueued. Returns the queue id.
fn held(daemon: &Daemon, cwd: &std::path::Path) -> String {
    let cmd = ProposedCommand::new("mcp", cwd, vec!["rm".into(), "x".into()], "rm x");
    match daemon.handle_request(ipc::Request::Propose(cmd.clone())) {
        ipc::Response::Verdict(v) => assert_eq!(v.decision, Decision::Hold, "seed must hold"),
        other => panic!("expected Verdict, got {other:?}"),
    }
    cmd.id.to_string()
}

fn challenge(resp: ipc::Response) -> (bool, String, String, admin::KdfParams) {
    match resp {
        ipc::Response::Challenge {
            locked,
            nonce,
            salt,
            params,
        } => (locked, nonce, salt, params),
        other => panic!("expected Challenge, got {other:?}"),
    }
}

/// AuthBegin + correct-password proof for `op`, ready to send:
/// (locked, nonce_hex, salt, params, proof_hex).
fn valid_proof(
    daemon: &Daemon,
    pw: &str,
    op: &str,
) -> (bool, String, String, admin::KdfParams, String) {
    let (locked, nonce, salt, params) =
        challenge(daemon.handle_request(ipc::Request::AuthBegin { op: op.into() }));
    assert!(locked, "a provisioned daemon must be locked");
    let nonce_bytes = hex::decode(&nonce).unwrap();
    let proof = admin::compute_proof(pw, &salt, params, &nonce_bytes, op.as_bytes()).unwrap();
    (locked, nonce, salt, params, hex::encode(proof))
}

/// Unwrap a `Pending { status }` response (the queue-status reply shape).
fn pending_status_of(resp: ipc::Response) -> String {
    match resp {
        ipc::Response::Pending { status } => status,
        other => panic!("expected Pending, got {other:?}"),
    }
}

/// One test's environment: a locked daemon + a held queue item.
struct Fixture {
    _tmp: tempfile::TempDir,
    daemon: Daemon,
    id: String,
}

const PW: &str = "correct horse battery staple";

/// A locked daemon under DEFAULT policy (approval proof required), with one
/// held item queued from `cwd` (the policy scope that matters).
fn locked_daemon_with_hold(cwd: &std::path::Path) -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("vault.json");
    let db = tmp.path().join("events.db");
    provision_at(&vault, PW);
    std::env::set_var("KINTSUGI_VAULT", &vault);
    std::env::set_var("KINTSUGI_DB", &db);
    // No global policy file → the safe default (require_approval_proof = true).
    std::env::set_var("KINTSUGI_CONFIG", tmp.path().join("no-global.toml"));
    let daemon = Daemon::open(&db).unwrap();
    let id = held(&daemon, cwd);
    Fixture {
        _tmp: tmp,
        daemon,
        id,
    }
}

/// Point the vault resolver at an absent file (unprovisioned) and open a daemon.
fn unprovisioned_daemon() -> (tempfile::TempDir, Daemon) {
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("KINTSUGI_VAULT", tmp.path().join("absent.json"));
    let db = tmp.path().join("events.db");
    std::env::set_var("KINTSUGI_DB", &db);
    std::env::set_var("KINTSUGI_CONFIG", tmp.path().join("no-global.toml"));
    let daemon = Daemon::open(&db).unwrap();
    (tmp, daemon)
}

fn cleanup() {
    std::env::remove_var("KINTSUGI_VAULT");
    std::env::remove_var("KINTSUGI_DB");
    std::env::remove_var("KINTSUGI_CONFIG");
}

#[test]
fn bare_approve_on_a_locked_daemon_is_blocked_audited_and_throttled() {
    let _g = serial_lock();
    let cwd = tempfile::tempdir().unwrap();
    let f = locked_daemon_with_hold(cwd.path());

    // A bare Approve (the old client / an agent speaking the protocol) is
    // refused loudly, with an actionable pointer at the human path.
    let resp = f.daemon.handle_request(ipc::Request::Approve {
        id: f.id.clone(),
        nonce: None,
        proof: None,
    });
    match resp {
        ipc::Response::Error { message } => {
            assert!(
                message.contains("approval requires proof"),
                "error should say what's missing: {message}"
            );
            assert!(
                message.contains(&format!("kintsugi approve {}", f.id)),
                "error should point at the human path: {message}"
            );
        }
        other => panic!("bare approve must be refused, got {other:?}"),
    }
    // The item is untouched — the agent did not approve itself.
    assert_eq!(
        pending_status_of(
            f.daemon
                .handle_request(ipc::Request::PendingStatus { id: f.id.clone() })
        ),
        "pending"
    );
    // The attempt is a hash-chained audit event.
    let reasons = approve_audit_reasons(&f.daemon, &f.id);
    assert!(
        reasons.iter().any(|r| r.contains("self-approval blocked")),
        "expected a self-approval-blocked audit row, got {reasons:?}"
    );

    // The throttle counts bare attempts with the same bounds as shutdown auth:
    // past the free budget the daemon locks out instead of re-checking.
    let mut locked_out = false;
    for _ in 0..5 {
        if let ipc::Response::Error { message } = f.daemon.handle_request(ipc::Request::Approve {
            id: f.id.clone(),
            nonce: None,
            proof: None,
        }) {
            if message.contains("locked out") {
                locked_out = true;
                break;
            }
        }
    }
    assert!(locked_out, "a bare-approve hammer must trigger the lockout");

    cleanup();
}

#[test]
fn empty_string_nonce_and_proof_are_treated_as_bare_not_as_a_proof() {
    // None ≠ "" by design: an empty string is a placeholder, never a real
    // nonce/proof, so it must take the bare path (loud refusal), not the
    // crypto path.
    let _g = serial_lock();
    let cwd = tempfile::tempdir().unwrap();
    let f = locked_daemon_with_hold(cwd.path());
    let resp = f.daemon.handle_request(ipc::Request::Approve {
        id: f.id.clone(),
        nonce: Some(String::new()),
        proof: Some(String::new()),
    });
    match resp {
        ipc::Response::Error { message } => assert!(message.contains("approval requires proof")),
        other => panic!("empty-string placeholders must be refused as bare, got {other:?}"),
    }
    cleanup();
}

#[test]
fn full_proof_flow_approves_and_resolves_the_queue_item() {
    let _g = serial_lock();
    let cwd = tempfile::tempdir().unwrap();
    let f = locked_daemon_with_hold(cwd.path());

    let op = format!("approve:{}", f.id);
    let (_, _nonce, _salt, _params, proof_hex) = valid_proof(&f.daemon, PW, &op);
    let resp = f.daemon.handle_request(ipc::Request::Approve {
        id: f.id.clone(),
        nonce: Some(_nonce),
        proof: Some(proof_hex),
    });
    assert!(matches!(resp, ipc::Response::Ack), "got {resp:?}");
    // The queue item resolved — this is the effect a human approval has.
    assert_eq!(
        pending_status_of(
            f.daemon
                .handle_request(ipc::Request::PendingStatus { id: f.id.clone() })
        ),
        "approved"
    );
    // Every auth attempt is audited; the success says authenticated.
    let reasons = approve_audit_reasons(&f.daemon, &f.id);
    assert!(
        reasons.iter().any(|r| r.contains("authenticated")),
        "expected an authenticated audit row, got {reasons:?}"
    );
    // The resolution itself is the usual human:allow row.
    let filter = Filter {
        grep: Some("rm x".into()),
        ..Filter::default()
    };
    let rows = f.daemon.log().query(&filter).unwrap();
    assert!(
        rows.iter()
            .any(|e| e.decision == Decision::Allow && e.reason == "human:allow"),
        "the approved command must be logged as human:allow, got {rows:?}"
    );

    cleanup();
}

#[test]
fn wrong_password_fails_still_pending_and_lockout_bounds_hold() {
    let _g = serial_lock();
    let cwd = tempfile::tempdir().unwrap();
    let f = locked_daemon_with_hold(cwd.path());

    let op = format!("approve:{}", f.id);
    // Five wrong-password proofs (AuthBegin + bad proof each time: the
    // challenge is one-shot, so each attempt needs a fresh one).
    for i in 0..5 {
        let (_, nonce, salt, params, bad) = {
            let (locked, nonce, salt, params) = challenge(
                f.daemon
                    .handle_request(ipc::Request::AuthBegin { op: op.clone() }),
            );
            assert!(locked);
            let nb = hex::decode(&nonce).unwrap();
            let proof =
                admin::compute_proof("wrong guess", &salt, params, &nb, op.as_bytes()).unwrap();
            (locked, nonce, salt, params, hex::encode(proof))
        };
        let _ = salt;
        let _ = params;
        let resp = f.daemon.handle_request(ipc::Request::Approve {
            id: f.id.clone(),
            nonce: Some(nonce),
            proof: Some(bad),
        });
        assert!(
            matches!(resp, ipc::Response::Error { .. }),
            "attempt {i} must fail"
        );
    }
    // Still pending — no partial effect.
    assert_eq!(
        pending_status_of(
            f.daemon
                .handle_request(ipc::Request::PendingStatus { id: f.id.clone() })
        ),
        "pending"
    );
    // The 6th attempt is refused by the lockout without even checking a proof.
    let resp = f.daemon.handle_request(ipc::Request::Approve {
        id: f.id.clone(),
        nonce: None,
        proof: Some("00".into()),
    });
    match resp {
        ipc::Response::Error { message } => assert!(message.contains("locked out")),
        other => panic!("expected lockout, got {other:?}"),
    }
    let reasons = approve_audit_reasons(&f.daemon, &f.id);
    assert!(
        reasons
            .iter()
            .filter(|r| r.contains("authentication failed"))
            .count()
            >= 5,
        "each wrong password is audited, got {reasons:?}"
    );

    cleanup();
}

#[test]
fn a_captured_proof_cannot_approve_a_different_id_or_replay() {
    let _g = serial_lock();
    let cwd = tempfile::tempdir().unwrap();
    let f = locked_daemon_with_hold(cwd.path());
    // A second held item: the proof must be bound to THIS id, not any item.
    let second = held(&f.daemon, cwd.path());

    let op = format!("approve:{}", f.id);
    let (_, nonce, _s, _p, proof) = valid_proof(&f.daemon, PW, &op);

    // Spending the proof on a different id → the op binding fails. The failed
    // attempt still consumed the one-shot challenge (the shutdown mirror: take
    // regardless of the outcome), so this nonce+proof pair is now dead.
    let resp = f.daemon.handle_request(ipc::Request::Approve {
        id: second.clone(),
        nonce: Some(nonce.clone()),
        proof: Some(proof.clone()),
    });
    assert!(
        matches!(resp, ipc::Response::Error { .. }),
        "a proof for one id must not approve another"
    );
    // The second item is untouched.
    assert_eq!(
        pending_status_of(
            f.daemon
                .handle_request(ipc::Request::PendingStatus { id: second.clone() })
        ),
        "pending"
    );
    // …and replaying the consumed pair on the BOUND id fails too (one-shot).
    let resp = f.daemon.handle_request(ipc::Request::Approve {
        id: f.id.clone(),
        nonce: Some(nonce),
        proof: Some(proof),
    });
    assert!(
        matches!(resp, ipc::Response::Error { .. }),
        "a consumed challenge must not authorize a later approve"
    );
    assert_eq!(
        pending_status_of(
            f.daemon
                .handle_request(ipc::Request::PendingStatus { id: f.id.clone() })
        ),
        "pending"
    );

    // A FRESH challenge for the bound id works — and is consumed by its first
    // successful use; replaying it afterwards fails.
    let op = format!("approve:{}", f.id);
    let (_, nonce, _s, _p, proof) = valid_proof(&f.daemon, PW, &op);
    let resp = f.daemon.handle_request(ipc::Request::Approve {
        id: f.id.clone(),
        nonce: Some(nonce.clone()),
        proof: Some(proof.clone()),
    });
    assert!(matches!(resp, ipc::Response::Ack), "got {resp:?}");
    // Replay the same pair → rejected (the challenge is one-shot).
    let resp = f.daemon.handle_request(ipc::Request::Approve {
        id: f.id.clone(),
        nonce: Some(nonce),
        proof: Some(proof),
    });
    assert!(
        matches!(resp, ipc::Response::Error { .. }),
        "replay after the one-shot consume must fail"
    );

    cleanup();
}

#[test]
fn a_shutdown_proof_cannot_approve_and_vice_versa() {
    let _g = serial_lock();
    let cwd = tempfile::tempdir().unwrap();
    let f = locked_daemon_with_hold(cwd.path());

    // A challenge begun for shutdown, answered on the approve op → rejected.
    let (_, nonce, _s, _p, proof) = valid_proof(&f.daemon, PW, "shutdown");
    let resp = f.daemon.handle_request(ipc::Request::Approve {
        id: f.id.clone(),
        nonce: Some(nonce),
        proof: Some(proof),
    });
    assert!(
        matches!(resp, ipc::Response::Error { .. }),
        "a shutdown proof must not approve"
    );
    // Still pending.
    assert_eq!(
        pending_status_of(
            f.daemon
                .handle_request(ipc::Request::PendingStatus { id: f.id.clone() })
        ),
        "pending"
    );

    // And the mirror: an approve challenge cannot stop the daemon.
    let op = format!("approve:{}", f.id);
    let (_, nonce, _s, _p, proof) = valid_proof(&f.daemon, PW, &op);
    let resp = f.daemon.handle_request(ipc::Request::Shutdown {
        op: op.clone(),
        nonce: Some(nonce),
        proof: Some(proof),
    });
    assert!(
        matches!(resp, ipc::Response::Error { .. }),
        "an approve proof must not shut down"
    );
    assert!(!f.daemon.should_shutdown());

    cleanup();
}

#[test]
fn an_authbegin_for_approve_supersedes_an_unconsumed_shutdown_challenge() {
    // The pending-challenge slot is single and one-shot: an AuthBegin for
    // approve replaces an unconsumed shutdown challenge (and vice versa).
    // Accepted by design (documented in docs/policy.md); pinned here so a
    // change to the slot is a deliberate decision.
    let _g = serial_lock();
    let cwd = tempfile::tempdir().unwrap();
    let f = locked_daemon_with_hold(cwd.path());

    // Begin a shutdown challenge, never answer it…
    let _ = valid_proof_probe(&f.daemon, "shutdown");
    // …then begin the approve challenge — it wins the slot.
    let op = format!("approve:{}", f.id);
    let (_, nonce, _s, _p, proof) = valid_proof(&f.daemon, PW, &op);
    let resp = f.daemon.handle_request(ipc::Request::Approve {
        id: f.id.clone(),
        nonce: Some(nonce),
        proof: Some(proof),
    });
    assert!(matches!(resp, ipc::Response::Ack), "got {resp:?}");
    assert_eq!(
        pending_status_of(
            f.daemon
                .handle_request(ipc::Request::PendingStatus { id: f.id.clone() })
        ),
        "approved"
    );

    cleanup();
}

/// AuthBegin for `op`, returning the raw challenge parts (no proof computed).
fn valid_proof_probe(daemon: &Daemon, op: &str) -> (bool, String, String, admin::KdfParams) {
    challenge(daemon.handle_request(ipc::Request::AuthBegin { op: op.into() }))
}

#[test]
fn policy_opt_out_accepts_bare_approve_again() {
    let _g = serial_lock();
    let cwd = tempfile::tempdir().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("vault.json");
    let db = tmp.path().join("events.db");
    provision_at(&vault, PW);
    std::env::set_var("KINTSUGI_VAULT", &vault);
    std::env::set_var("KINTSUGI_DB", &db);
    // The documented opt-out, as a GLOBAL policy file.
    let config = tmp.path().join("config.toml");
    std::fs::write(&config, "[security]\nrequire_approval_proof = false\n").unwrap();
    std::env::set_var("KINTSUGI_CONFIG", &config);

    let daemon = Daemon::open(&db).unwrap();
    let id = held(&daemon, cwd.path());
    // Bare approve is accepted again — the pre-Phase-7 behavior.
    let resp = daemon.handle_request(ipc::Request::Approve {
        id: id.clone(),
        nonce: None,
        proof: None,
    });
    assert!(matches!(resp, ipc::Response::Ack), "got {resp:?}");
    assert_eq!(
        pending_status_of(daemon.handle_request(ipc::Request::PendingStatus { id })),
        "approved"
    );

    cleanup();
}

#[test]
fn repo_policy_opt_out_scopes_to_the_held_commands_repo() {
    // The auth gate reads the policy scoped to the held command's repo (the
    // same `.kintsugi.toml` scope that produced the hold), so one repo can opt
    // out without weakening the default everywhere.
    let _g = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("vault.json");
    let db = tmp.path().join("events.db");
    provision_at(&vault, PW);
    std::env::set_var("KINTSUGI_VAULT", &vault);
    std::env::set_var("KINTSUGI_DB", &db);
    std::env::set_var("KINTSUGI_CONFIG", tmp.path().join("no-global.toml"));

    // A repo whose held commands opt out…
    let opting_out = tmp.path().join("repo-opted-out");
    std::fs::create_dir_all(&opting_out).unwrap();
    std::fs::write(
        opting_out.join(".kintsugi.toml"),
        "[security]\nrequire_approval_proof = false\n",
    )
    .unwrap();
    // …and one that keeps the default.
    let default_repo = tmp.path().join("repo-default");
    std::fs::create_dir_all(&default_repo).unwrap();

    let daemon = Daemon::open(&db).unwrap();
    let opted_id = held(&daemon, &opting_out);
    let default_id = held(&daemon, &default_repo);

    // The opted-out repo: bare approve accepted.
    assert!(matches!(
        daemon.handle_request(ipc::Request::Approve {
            id: opted_id.clone(),
            nonce: None,
            proof: None,
        }),
        ipc::Response::Ack
    ));
    assert_eq!(
        pending_status_of(daemon.handle_request(ipc::Request::PendingStatus { id: opted_id })),
        "approved"
    );

    // The default repo, same daemon: bare approve still blocked.
    match daemon.handle_request(ipc::Request::Approve {
        id: default_id.clone(),
        nonce: None,
        proof: None,
    }) {
        ipc::Response::Error { message } => {
            assert!(message.contains("approval requires proof"))
        }
        other => panic!("default repo must keep the gate, got {other:?}"),
    }
    assert_eq!(
        pending_status_of(daemon.handle_request(ipc::Request::PendingStatus { id: default_id })),
        "pending"
    );

    cleanup();
}

#[test]
fn deny_and_prune_stay_bare_under_default_policy() {
    // An agent self-deny is a nuisance, not a threat, and prune only touches
    // the queue (never the log) — neither needs a proof. Under DEFAULT policy
    // (proof required for approve) both still work bare.
    let _g = serial_lock();
    let cwd = tempfile::tempdir().unwrap();
    let f = locked_daemon_with_hold(cwd.path());
    let second = held(&f.daemon, cwd.path());

    assert!(matches!(
        f.daemon
            .handle_request(ipc::Request::Deny { id: f.id.clone() }),
        ipc::Response::Ack
    ));
    assert_eq!(
        pending_status_of(
            f.daemon
                .handle_request(ipc::Request::PendingStatus { id: f.id.clone() })
        ),
        "denied"
    );

    match f.daemon.handle_request(ipc::Request::PrunePending) {
        ipc::Response::Pending { status } => assert_eq!(status, "1", "one item left to prune"),
        other => panic!("prune must stay bare, got {other:?}"),
    }
    assert_eq!(
        pending_status_of(
            f.daemon
                .handle_request(ipc::Request::PendingStatus { id: second })
        ),
        "gone"
    );

    cleanup();
}

#[test]
fn kill_switch_still_refuses_allow_on_every_approve_path() {
    // The kill-switch floor is auth-independent: neither an authenticated
    // approve nor a policy opt-out lifts it. Regression guard for the guard.
    let _g = serial_lock();
    let cwd = tempfile::tempdir().unwrap();
    let f = locked_daemon_with_hold(cwd.path());
    // Engage the kill-switch (flag file next to the db).
    std::fs::write(
        std::path::Path::new(&std::env::var("KINTSUGI_DB").unwrap())
            .parent()
            .unwrap()
            .join(kintsugi_daemon::KILL_SWITCH_FILE),
        b"panic\n",
    )
    .unwrap();

    // Authenticated approve → the kill-switch guard refuses the Allow.
    let op = format!("approve:{}", f.id);
    let (_, nonce, _s, _p, proof) = valid_proof(&f.daemon, PW, &op);
    let resp = f.daemon.handle_request(ipc::Request::Approve {
        id: f.id.clone(),
        nonce: Some(nonce),
        proof: Some(proof),
    });
    match resp {
        ipc::Response::Error { message } => assert!(message.contains("kill-switch")),
        other => panic!("kill-switch must refuse allow, got {other:?}"),
    }
    // Still pending: nothing was resolved.
    assert_eq!(
        pending_status_of(
            f.daemon
                .handle_request(ipc::Request::PendingStatus { id: f.id.clone() })
        ),
        "pending"
    );
    // Deny stays available (the safe direction) while the switch is engaged.
    assert!(matches!(
        f.daemon
            .handle_request(ipc::Request::Deny { id: f.id.clone() }),
        ipc::Response::Ack
    ));

    cleanup();
}

#[test]
fn unprovisioned_daemon_accepts_bare_approve_without_a_brick() {
    // No vault → there is no secret to prove possession of. The shutdown
    // mirror: approval stays bare (the owner-only socket is the boundary),
    // documented honestly in docs/security-assessment.md. This is what keeps
    // the queue usable for users who never provisioned a vault.
    let _g = serial_lock();
    let cwd = tempfile::tempdir().unwrap();
    let (tmp, daemon) = unprovisioned_daemon();
    let id = held(&daemon, cwd.path());

    // AuthBegin honestly reports unlocked.
    let (locked, _n, _s, _p) = challenge(daemon.handle_request(ipc::Request::AuthBegin {
        op: format!("approve:{id}"),
    }));
    assert!(!locked, "no vault → nothing to prove");

    let resp = daemon.handle_request(ipc::Request::Approve {
        id: id.clone(),
        nonce: None,
        proof: None,
    });
    assert!(matches!(resp, ipc::Response::Ack), "got {resp:?}");
    assert_eq!(
        pending_status_of(daemon.handle_request(ipc::Request::PendingStatus { id })),
        "approved"
    );
    drop(tmp);

    cleanup();
}
