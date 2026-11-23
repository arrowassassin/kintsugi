//! `kintsugi anchor export|verify` + the status anchored line (Phase 7, T1.4).
//!
//! Hermetic: every test runs the real binary against a temp dir via
//! `KINTSUGI_DB` / `KINTSUGI_VAULT` / `KINTSUGI_SOCKET` env overrides — no
//! daemon, no network, no home-directory state. Anchor operations talk to
//! the LOG, never the daemon.

use std::process::Command;

use kintsugi_core::{Class, Decision, EventLog, Filter, ProposedCommand, Verdict};

fn kintsugi() -> Command {
    Command::new(env!("CARGO_BIN_EXE_kintsugi"))
}

fn pw() -> String {
    // Runtime-built, per the repo's credential-scanner convention.
    format!("kintsugi-test-pw-{}-anchor", std::process::id())
}

/// Log one allowed event and return its seq.
fn seed(db: &std::path::Path, raw: &str) -> i64 {
    let log = EventLog::open(db).unwrap();
    let cmd = ProposedCommand::new(
        "shim",
        "/tmp/project",
        raw.split_whitespace().map(str::to_string).collect(),
        raw,
    );
    let e = log
        .log_event(
            &cmd,
            &Verdict::rules(Class::Safe, Decision::Allow, "t"),
            None,
        )
        .unwrap();
    e.seq
}

/// Common env for every anchor invocation: isolated db + no daemon.
fn env(c: &mut Command, dir: &std::path::Path) {
    c.env("KINTSUGI_DATA_DIR", dir)
        .env("KINTSUGI_DB", dir.join("events.db"))
        .env("KINTSUGI_VAULT", dir.join("vault.json"))
        .env("KINTSUGI_SOCKET", dir.join("nowhere.sock"))
        .env("NO_COLOR", "1");
}

/// Provision an admin vault inside `dir`; returns the password-file path.
fn provision(dir: &std::path::Path) -> std::path::PathBuf {
    let pw_file = dir.join("pw");
    std::fs::write(&pw_file, pw()).unwrap();
    let out = kintsugi()
        .args(["admin", "provision", "--password-file"])
        .arg(&pw_file)
        .env("KINTSUGI_VAULT", dir.join("vault.json"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "provision failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    pw_file
}

fn export(
    dir: &std::path::Path,
    out: Option<&std::path::Path>,
    origin: Option<&str>,
    pw_file: Option<&std::path::Path>,
    no_sign: bool,
) -> std::process::Output {
    let mut c = kintsugi();
    c.args(["anchor", "export"]);
    if let Some(o) = out {
        c.arg("--out").arg(o);
    }
    if let Some(origin) = origin {
        c.arg("--origin").arg(origin);
    }
    if let Some(pw) = pw_file {
        c.arg("--password-file").arg(pw);
    }
    if no_sign {
        c.arg("--no-sign");
    }
    env(&mut c, dir);
    c.output().unwrap()
}

fn verify(dir: &std::path::Path, checkpoint: Option<&std::path::Path>) -> std::process::Output {
    let mut c = kintsugi();
    c.args(["anchor", "verify"]);
    if let Some(p) = checkpoint {
        c.arg("--checkpoint").arg(p);
    }
    env(&mut c, dir);
    c.output().unwrap()
}

fn text(out: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn a_checkpoint_signed_by_a_foreign_key_is_invalid_not_intact() {
    // Two machines, two vaults. `signature_is_valid()` alone accepts A's
    // checkpoint on B, because it trusts the key the file carries — so without the
    // pin against B's own vault, a forger who rewrites the log and re-signs it with
    // a key of their choosing would read INTACT, exit 0. The pin is what makes the
    // verdict mean "signed by a key this machine trusts".
    let a = tempfile::tempdir().unwrap();
    seed(&a.path().join("events.db"), "git status");
    let pw_a = provision(a.path());
    let file = a.path().join("checkpoint-from-a.txt");
    let out = export(a.path(), Some(&file), None, Some(&pw_a), false);
    assert!(out.status.success(), "export failed: {}", text(&out));

    // Machine B: its own log and its own vault, provisioned with a different
    // password (a different key generation).
    let b = tempfile::tempdir().unwrap();
    seed(&b.path().join("events.db"), "git status");
    let pw_b = b.path().join("pw-b");
    std::fs::write(&pw_b, format!("{}-another-machine", pw())).unwrap();
    let prov = kintsugi()
        .args(["admin", "provision", "--password-file"])
        .arg(&pw_b)
        .env("KINTSUGI_VAULT", b.path().join("vault.json"))
        .output()
        .unwrap();
    assert!(prov.status.success(), "provision B failed: {}", text(&prov));

    let v = verify(b.path(), Some(&file));
    let t = text(&v);
    assert_eq!(
        v.status.code(),
        Some(3),
        "a foreign-key checkpoint must be INVALID (3), got {:?}:\n{t}",
        v.status.code()
    );
    assert!(
        t.contains("this vault does not own"),
        "the refusal must name the reason:\n{t}"
    );

    // And the same file DOES verify on the machine that signed it.
    let own = verify(a.path(), Some(&file));
    assert_eq!(own.status.code(), Some(0), "got:\n{}", text(&own));
}

#[test]
fn export_records_signs_and_verifies_intact() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("events.db");
    seed(&db, "echo one");
    seed(&db, "echo two");
    let pw_file = provision(dir.path());
    let out_file = dir.path().join("cp.txt");

    let out = export(dir.path(), Some(&out_file), None, Some(&pw_file), false);
    assert!(
        out.status.success(),
        "export failed: {}",
        text(&out).replace(&pw(), "<pw>")
    );
    let body = std::fs::read_to_string(&out_file).unwrap();
    assert!(body.starts_with("kintsugi-checkpoint/1"), "got:\n{body}");
    assert!(body.contains("key_id="), "the key_id must be embedded");
    assert!(
        body.contains("sig="),
        "with a vault present the export is signed"
    );
    assert_eq!(seed_count_anchors(&db), 1, "the anchor row is recorded");

    // File-based verify: INTACT, exit 0.
    let v = verify(dir.path(), Some(&out_file));
    assert_eq!(v.status.code(), Some(0), "got:\n{}", text(&v));
    assert!(
        text(&v).contains("INTACT through anchor 2"),
        "got:\n{}",
        text(&v)
    );

    // DB-based verify (no --checkpoint): also INTACT through the anchor row.
    let v = verify(dir.path(), None);
    assert_eq!(v.status.code(), Some(0), "got:\n{}", text(&v));
    assert!(
        text(&v).contains("INTACT through anchor 2"),
        "got:\n{}",
        text(&v)
    );
}

#[test]
fn verify_without_any_anchor_is_unverifiable() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("events.db");
    seed(&db, "echo one");

    let v = verify(dir.path(), None);
    assert_eq!(v.status.code(), Some(4), "got:\n{}", text(&v));
    assert!(
        text(&v).contains("UNVERIFIABLE: no anchor recorded"),
        "got:\n{}",
        text(&v)
    );
    assert!(text(&v).contains("anchor export"), "the hint names the fix");
}

#[test]
fn unsigned_export_is_unverifiable_with_hint() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("events.db");
    seed(&db, "echo one");
    let out_file = dir.path().join("cp.txt");

    // No vault configured: the export is honest about being unsigned.
    let out = export(dir.path(), Some(&out_file), None, None, false);
    assert!(out.status.success(), "got:\n{}", text(&out));
    let body = std::fs::read_to_string(&out_file).unwrap();
    assert!(!body.contains("sig="), "no signature without a vault");
    let t = text(&out);
    assert!(
        t.to_lowercase().contains("unsigned"),
        "the export says so: got:\n{t}"
    );
    assert!(
        t.contains("kintsugi admin provision"),
        "the hint names how to get signatures"
    );
    // And it still records the export in the anchors table.
    assert_eq!(seed_count_anchors(&db), 1);

    let v = verify(dir.path(), Some(&out_file));
    assert_eq!(v.status.code(), Some(4), "got:\n{}", text(&v));
    assert!(text(&v).contains("UNVERIFIABLE"), "got:\n{}", text(&v));
    assert!(text(&v).contains("unsigned"), "got:\n{}", text(&v));
}

#[test]
fn tampered_log_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("events.db");
    seed(&db, "echo one");
    seed(&db, "echo two");
    seed(&db, "echo three");
    let pw_file = provision(dir.path());
    let out_file = dir.path().join("cp.txt");
    let out = export(dir.path(), Some(&out_file), None, Some(&pw_file), false);
    assert!(out.status.success(), "got:\n{}", text(&out));

    // The attacker's move: silently delete a middle row (no rechain).
    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute("DELETE FROM events WHERE seq = 2", [])
        .unwrap();
    drop(conn);

    let v = verify(dir.path(), Some(&out_file));
    assert_eq!(v.status.code(), Some(2), "got:\n{}", text(&v));
    assert!(
        text(&v).contains("TAMPERED: chain diverges before anchor 3"),
        "got:\n{}",
        text(&v)
    );
}

#[test]
fn stale_checkpoint_after_new_events() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("events.db");
    seed(&db, "echo one");
    let pw_file = provision(dir.path());
    let out_file = dir.path().join("cp.txt");
    let out = export(dir.path(), Some(&out_file), None, Some(&pw_file), false);
    assert!(out.status.success(), "got:\n{}", text(&out));

    seed(&db, "echo two");
    seed(&db, "echo three");

    let v = verify(dir.path(), Some(&out_file));
    assert_eq!(v.status.code(), Some(1), "got:\n{}", text(&v));
    assert!(
        text(&v).contains("STALE: 2 events since the anchor"),
        "got:\n{}",
        text(&v)
    );
    assert!(
        text(&v).contains("export a fresh checkpoint"),
        "the remedy is named"
    );
}

#[test]
fn invalid_signature_is_distinct_from_chain_verdicts() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("events.db");
    seed(&db, "echo one");
    let pw_file = provision(dir.path());
    let out_file = dir.path().join("cp.txt");
    let out = export(dir.path(), Some(&out_file), None, Some(&pw_file), false);
    assert!(out.status.success(), "got:\n{}", text(&out));

    // Tamper the checkpoint FILE itself (head value) — the signature must
    // fail, loudly and distinctly, never falling through to a chain verdict.
    let body = std::fs::read_to_string(&out_file).unwrap();
    let tampered = body.replace("head=", "head=f"); // one hex digit changed
    assert_ne!(tampered, body);
    std::fs::write(&out_file, tampered).unwrap();

    let v = verify(dir.path(), Some(&out_file));
    assert_eq!(v.status.code(), Some(3), "got:\n{}", text(&v));
    assert!(text(&v).contains("INVALID"), "got:\n{}", text(&v));
    assert!(
        text(&v).contains("does not verify"),
        "the failure is named: got:\n{}",
        text(&v)
    );
}

#[test]
fn purge_then_re_export_verifies_intact_with_marker() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("events.db");
    seed(&db, "echo keep one");
    seed(&db, "echo secret thing");
    seed(&db, "echo keep two");
    let pw_file = provision(dir.path());
    let old_file = dir.path().join("cp-old.txt");
    let out = export(dir.path(), Some(&old_file), None, Some(&pw_file), false);
    assert!(out.status.success(), "got:\n{}", text(&out));

    // A real purge through the CLI (hard delete + rechain + marker).
    let mut c = kintsugi();
    c.args([
        "purge",
        "--yes",
        "--reason",
        "privacy",
        "--grep",
        "secret thing",
    ]);
    env(&mut c, dir.path());
    let p = c.output().unwrap();
    assert!(p.status.success(), "purge failed:\n{}", text(&p));

    // Export again at the post-purge head; verify INTACT against it.
    let new_file = dir.path().join("cp-new.txt");
    let out = export(dir.path(), Some(&new_file), None, Some(&pw_file), false);
    assert!(out.status.success(), "got:\n{}", text(&out));
    let v = verify(dir.path(), Some(&new_file));
    assert_eq!(v.status.code(), Some(0), "got:\n{}", text(&v));
    assert!(text(&v).contains("INTACT"), "got:\n{}", text(&v));

    // The why is preserved: the audit:purge marker is still in the log.
    let log = EventLog::open(&db).unwrap();
    let all = log
        .query(&Filter {
            include_redacted: true,
            ..Filter::default()
        })
        .unwrap();
    assert!(
        all.iter().any(|e| e.reason.contains("audit:purge")),
        "the purge marker survives the re-anchor"
    );
}

#[test]
fn fork_attempt_is_refused_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("events.db");
    seed(&db, "echo one");
    seed(&db, "echo two");
    let pw_file = provision(dir.path());
    let out = export(dir.path(), None, None, Some(&pw_file), false);
    assert!(out.status.success(), "got:\n{}", text(&out));

    // The restored-backup shape: events rows vanish (an older events table
    // restored over a newer log) while the anchors table survives. The next
    // export must refuse to fork the recorded series — loudly, and without
    // recording anything.
    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute("DELETE FROM events", []).unwrap();
    drop(conn);

    let before = seed_count_anchors(&db);
    let out = export(dir.path(), None, None, Some(&pw_file), false);
    assert_ne!(out.status.code(), Some(0), "a fork must not succeed");
    let t = text(&out);
    assert!(
        t.to_lowercase().contains("refus") || t.to_lowercase().contains("fork"),
        "the refusal is explained: got:\n{t}"
    );
    assert_eq!(
        seed_count_anchors(&db),
        before,
        "a refused export records nothing"
    );
}

#[test]
fn wrong_password_records_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("events.db");
    seed(&db, "echo one");
    let _pw_file = provision(dir.path());
    let bad = dir.path().join("bad-pw");
    std::fs::write(&bad, "definitely not the password").unwrap();

    let out = export(dir.path(), None, None, Some(&bad), false);
    assert_ne!(out.status.code(), Some(0), "got:\n{}", text(&out));
    assert!(
        text(&out).contains("wrong admin password"),
        "got:\n{}",
        text(&out)
    );
    assert_eq!(
        seed_count_anchors(&db),
        0,
        "a failed authentication records nothing"
    );
}

#[test]
fn status_shows_the_anchored_line_only_when_anchors_exist() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("events.db");
    seed(&db, "echo one");

    let mut c = kintsugi();
    c.arg("status");
    env(&mut c, dir.path());
    let s = text(&c.output().unwrap());
    assert!(
        !s.contains("anchored:"),
        "no anchor recorded yet, so no anchored line: got:\n{s}"
    );

    let pw_file = provision(dir.path());
    let out = export(dir.path(), None, None, Some(&pw_file), false);
    assert!(out.status.success(), "got:\n{}", text(&out));

    let mut c = kintsugi();
    c.arg("status");
    env(&mut c, dir.path());
    let s = text(&c.output().unwrap());
    assert!(s.contains("anchored:"), "got:\n{s}");
    assert!(s.contains("events ago"), "got:\n{s}");

    // One more event lands: the line counts it.
    seed(&db, "echo two");
    let mut c = kintsugi();
    c.arg("status");
    env(&mut c, dir.path());
    let s = text(&c.output().unwrap());
    assert!(s.contains("anchored:"), "got:\n{s}");
    assert!(
        s.contains("(1 events ago,"),
        "the count must survive the age suffix: got:\n{s}"
    );
}

#[test]
fn origin_override_and_stdout_print() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("events.db");
    seed(&db, "echo one");
    let pw_file = provision(dir.path());

    // Without --out the checkpoint itself goes to stdout.
    let out = export(dir.path(), None, Some("my-laptop"), Some(&pw_file), false);
    assert!(out.status.success(), "got:\n{}", text(&out));
    let s = text(&out);
    assert!(s.contains("kintsugi-checkpoint/1"), "got:\n{s}");
    assert!(s.contains("origin=my-laptop"), "got:\n{s}");

    // And the recorded anchor carries the override.
    let log = EventLog::open(&db).unwrap();
    assert_eq!(
        log.latest_anchor().unwrap().unwrap().origin,
        "my-laptop",
        "--origin is the recorded identity"
    );
}

#[test]
fn export_with_no_log_errors_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope").join("events.db");

    let mut c = kintsugi();
    c.args(["anchor", "export"]);
    c.env("KINTSUGI_DATA_DIR", dir.path())
        .env("KINTSUGI_DB", &missing)
        .env("KINTSUGI_VAULT", dir.path().join("vault.json"))
        .env("KINTSUGI_SOCKET", dir.path().join("nowhere.sock"));
    let out = c.output().unwrap();
    assert_ne!(out.status.code(), Some(0), "got:\n{}", text(&out));
    assert!(
        text(&out).contains("no event log"),
        "the error names the problem: got:\n{}",
        text(&out)
    );
    assert!(!missing.exists(), "export must not create a log to anchor");
}

/// Count anchor rows through the public API (used by refusal assertions).
fn seed_count_anchors(db: &std::path::Path) -> usize {
    let log = EventLog::open(db).unwrap();
    match log.latest_anchor().unwrap() {
        Some(a) => a.id as usize,
        None => 0,
    }
}
