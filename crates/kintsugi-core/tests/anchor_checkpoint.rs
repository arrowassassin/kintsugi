//! Checkpoint envelope + recorded-anchor round-trip (Phase 7, T1.4 core side).
//!
//! The envelope is the user-held artifact (`kintsugi anchor export` writes it,
//! `kintsugi anchor verify` reads it back); the recorded-anchor round-trip
//! locks the property the whole design rests on: an anchor ROW can rebuild
//! the exact canonical bytes that were signed, so a checkpoint is verifiable
//! from the log itself, not just from the exported file.

use kintsugi_core::anchor::{AnchorError, Checkpoint};
use kintsugi_core::{Class, Decision, EventLog, ProposedCommand, Verdict};
use time::format_description::well_known::Rfc3339;

fn sample(raw: &str) -> ProposedCommand {
    ProposedCommand::new(
        "shim",
        "/tmp/project",
        raw.split_whitespace().map(str::to_string).collect(),
        raw,
    )
}

fn allow() -> Verdict {
    Verdict::rules(Class::Safe, Decision::Allow, "test")
}

fn checkpoint(sig: Option<&str>) -> Checkpoint {
    Checkpoint {
        origin: "user@host".into(),
        seq: 3,
        head: "a".repeat(64),
        key_id: "b".repeat(64),
        ts: "2026-11-22T12:34:56Z".into(),
        sig: sig.map(str::to_string),
    }
}

#[test]
fn checkpoint_render_parse_round_trips_signed_and_unsigned() {
    for cp in [checkpoint(Some(&"c".repeat(128))), checkpoint(None)] {
        let text = cp.render();
        assert_eq!(Checkpoint::parse(&text).unwrap(), cp, "round trip: {text}");
    }
}

#[test]
fn checkpoint_parse_rejects_hostile_files() {
    // Not a checkpoint at all.
    assert_eq!(
        Checkpoint::parse("").unwrap_err(),
        AnchorError::NotCheckpoint
    );
    assert_eq!(
        Checkpoint::parse("hello world").unwrap_err(),
        AnchorError::NotCheckpoint
    );
    assert_eq!(
        Checkpoint::parse("kintsugi-checkpoint/2\nseq=1").unwrap_err(),
        AnchorError::NotCheckpoint
    );
    // Right header, garbage body.
    let head = "kintsugi-checkpoint/1\n";
    assert_eq!(
        Checkpoint::parse(&format!("{head}what is this line")).unwrap_err(),
        AnchorError::MalformedLine(2)
    );
    assert_eq!(
        Checkpoint::parse(&format!("{head}seq=not-a-number")).unwrap_err(),
        AnchorError::BadSeq("not-a-number".into())
    );
    // Missing required fields, one per case.
    for missing in ["origin", "seq", "head", "key_id", "ts"] {
        let text = checkpoint(None).render();
        let text = match missing {
            "origin" => text.replace("origin=user@host\n", ""),
            "seq" => text.replace("seq=3\n", ""),
            "head" => text.replace(&format!("head={}\n", "a".repeat(64)), ""),
            "key_id" => text.replace(&format!("key_id={}\n", "b".repeat(64)), ""),
            _ => text.replace("ts=2026-11-22T12:34:56Z\n", ""),
        };
        assert_eq!(
            Checkpoint::parse(&text).unwrap_err(),
            AnchorError::MissingField(missing),
            "field {missing} is required"
        );
    }
}

#[test]
fn checkpoint_parse_tolerates_blank_and_unknown_lines() {
    // Forward compatibility in the C2SP style: extension lines (and stray
    // whitespace) are ignored, not fatal — they are outside the signature.
    let cp = checkpoint(Some(&"c".repeat(128)));
    let text = format!("{}\n\nnote=whatever the future adds\n", cp.render());
    assert_eq!(Checkpoint::parse(&text).unwrap(), cp);
}

#[test]
fn record_anchor_stores_the_exact_checkpoint_including_signature() {
    let log = EventLog::open_in_memory().unwrap();
    let cp = checkpoint(Some(&"c".repeat(128)));
    let anchor = log.record_anchor(&cp).unwrap();

    let back = log.latest_anchor().unwrap().unwrap();
    assert_eq!(back.origin, cp.origin);
    assert_eq!(back.seq, cp.seq);
    assert_eq!(back.head, cp.head);
    assert_eq!(back.key_id, cp.key_id);
    // The signature is recorded, not dropped.
    assert_eq!(back.sig, cp.sig);
    // The stored timestamp reformats byte-identically to the checkpoint's ts
    // (the whole-second RFC3339 fixed point) — so the ROW can rebuild the
    // exact canonical bytes that were signed.
    let ts_back = back.created_ts.format(&Rfc3339).unwrap();
    assert_eq!(
        ts_back, cp.ts,
        "the row's timestamp must reformat to the signed string"
    );
    let rebuilt = Checkpoint {
        origin: back.origin.clone(),
        seq: back.seq,
        head: back.head.clone(),
        key_id: back.key_id.clone(),
        ts: ts_back,
        sig: back.sig.clone(),
    };
    assert_eq!(rebuilt.bytes(), cp.bytes());
    assert_eq!(anchor, back);
}

#[test]
fn hash_at_seq_returns_the_row_hash_or_none() {
    let log = EventLog::open_in_memory().unwrap();
    let e1 = log.log_event(&sample("echo one"), &allow(), None).unwrap();
    let e2 = log.log_event(&sample("echo two"), &allow(), None).unwrap();

    assert_eq!(log.hash_at_seq(e1.seq).unwrap(), Some(e1.hash));
    assert_eq!(log.hash_at_seq(e2.seq).unwrap(), Some(e2.hash));
    // A missing row is a miss, not an error.
    assert_eq!(log.hash_at_seq(99).unwrap(), None);
    assert_eq!(log.hash_at_seq(0).unwrap(), None);
}

#[test]
fn re_anchoring_the_same_head_with_a_signature_upgrades_the_row() {
    // export-unsigned → provision a vault → re-export is a normal path. Returning
    // the old unsigned row would leave the log unable to produce a signed verdict
    // (`anchor verify` with no file reads the recorded row), right after the export
    // printed "Signed under key_id". The upgrade appends a *new* row at the same
    // (seq, head) — allowed by the no-fork guard, and still append-only.
    let log = EventLog::open_in_memory().unwrap();
    let e = log.log_event(&sample("ls -la"), &allow(), None).unwrap();
    let (seq, head) = log.chain_head().unwrap();

    let mut unsigned_cp = checkpoint(None);
    unsigned_cp.seq = seq;
    unsigned_cp.head = head.clone();
    unsigned_cp.key_id = String::new();
    let unsigned = log.record_anchor(&unsigned_cp).unwrap();
    assert_eq!(unsigned.sig, None);

    let mut signed_cp = unsigned_cp.clone();
    signed_cp.key_id = "b".repeat(64);
    signed_cp.sig = Some("aabbcc".to_string());
    let upgraded = log.record_anchor(&signed_cp).unwrap();
    assert_ne!(upgraded.id, unsigned.id, "the upgrade is a new row");
    assert_eq!(upgraded.sig.as_deref(), Some("aabbcc"));
    assert_eq!(
        log.latest_anchor().unwrap().unwrap().sig.as_deref(),
        Some("aabbcc")
    );

    // Re-recording the *same* signed checkpoint is idempotent again.
    let again = log.record_anchor(&signed_cp).unwrap();
    assert_eq!(again.id, upgraded.id);
    assert_eq!(e.seq, seq);
}
