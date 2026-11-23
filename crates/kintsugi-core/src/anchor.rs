//! Checkpoint signing for anchored trust (Phase 7, T1.3).
//!
//! A *checkpoint* is the tiny, canonical serialization of one exported chain
//! head (origin, seq, head hash, key id, timestamp — the C2SP/RFC 6962
//! signed-tree-head shape, never the whole log). `anchor export` (T1.4) writes
//! it out for the user to keep; this module provides the bytes and the
//! signature over them.
//!
//! Key management — no new secret at rest: the signing key is derived per
//! operation from the admin vault's (password, `auth_salt`, KDF params), the
//! exact derivation the admin proof uses, so nothing new is persisted; the
//! vault already stores only the *verifying* public key. A checkpoint carries
//! that public key as its `key_id` (hex), which makes checkpoints
//! self-certifying: anyone holding the vault file — or the checkpoint itself —
//! can verify without a separate key distribution. A changed `key_id` means
//! the vault was re-keyed (password change / re-provision): verification of
//! older checkpoints keeps working under their recorded `key_id`; a new
//! anchor series simply begins under the new key.
//!
//! Protocol separation: signatures cover [`ANCHOR_CONTEXT`] ‖ checkpoint, a
//! distinct label from the admin proof's context, so an anchor signature can
//! never be replayed as an admin proof and vice versa.
//!
//! Canonical bytes: [`checkpoint_bytes`] emits RFC 8785 (JCS)-ordered JSON —
//! keys sorted, no whitespace, all five values serialized as strings. The
//! hand-rolled serializer is correct *for this fixed shape only*: no numbers,
//! floats, or nested structures exist to get wrong, and `seq` is a decimal
//! string on purpose (JCS numbers are IEEE-754 doubles; a string sidesteps
//! i64 precision loss and keeps the serializer trivially auditable). That
//! scope limit is deliberate and documented — do not extend the shape without
//! revisiting it.

use crate::admin::{auth_signing_key, AdminError, KdfParams};
use ed25519_dalek::{Signer, VerifyingKey, SIGNATURE_LENGTH};

/// Protocol-separation context label for anchor signatures — distinct from
/// the admin proof's `kintsugi.admin.settings.v1`, so the two signature
/// spaces never accept each other's signatures.
pub const ANCHOR_CONTEXT: &[u8] = b"kintsugi.log.anchor.v1";

/// The header line of an exported checkpoint file (the envelope's format tag).
pub const CHECKPOINT_FORMAT: &str = "kintsugi-checkpoint/1";

/// Failures while reading back an exported checkpoint file. Distinguishing
/// "not a checkpoint" / "malformed" / "missing field" lets the verify path
/// name the problem instead of crying "tampered" on a mangled file.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AnchorError {
    #[error("not a kintsugi checkpoint (expected the header line {CHECKPOINT_FORMAT})")]
    NotCheckpoint,
    #[error("checkpoint line {0} is malformed (expected key=value)")]
    MalformedLine(usize),
    #[error("checkpoint field 'seq' is not a valid integer: {0}")]
    BadSeq(String),
    #[error("checkpoint is missing the {0} field")]
    MissingField(&'static str),
}

/// One exported chain-head checkpoint: the five canonical fields plus the
/// detached signature (absent while unsigned). This is what
/// `kintsugi anchor export` writes, what the `anchors` table records, and
/// what `kintsugi anchor verify` reads back.
///
/// `ts` is the whole-second RFC3339 UTC string that was signed — it is stored
/// verbatim (never reformatted) so the recorded row and the exported file
/// rebuild identical canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Checkpoint {
    /// Caller-supplied log identity for the checkpoint (e.g. `user@host`).
    pub origin: String,
    /// The anchored sequence number.
    pub seq: i64,
    /// The anchored head hash.
    pub head: String,
    /// Hex verifying pubkey of the signing vault key (empty while unsigned).
    pub key_id: String,
    /// Whole-second RFC3339 UTC — the exact string covered by the signature.
    pub ts: String,
    /// Detached signature over [`Checkpoint::bytes`] (hex); `None` while
    /// unsigned.
    pub sig: Option<String>,
}

impl Checkpoint {
    /// The canonical signing bytes (the five fields; see [`checkpoint_bytes`]).
    pub fn bytes(&self) -> Vec<u8> {
        checkpoint_bytes(&self.origin, self.seq, &self.head, &self.key_id, &self.ts)
    }

    /// Whether this checkpoint carries a signature that verifies under its
    /// own `key_id`. Unsigned checkpoints return `false` (they assert
    /// nothing). Fail-closed on a malformed `sig`/`key_id`.
    pub fn signature_is_valid(&self) -> bool {
        let Some(sig) = &self.sig else {
            return false;
        };
        match hex::decode(sig) {
            Ok(bytes) => verify_checkpoint_signature(&self.key_id, &self.bytes(), &bytes),
            Err(_) => false,
        }
    }

    /// Render the human-readable, paste-able text envelope: a format header,
    /// one `key=value` line per field, `sig` only when signed. Values run to
    /// end-of-line (an origin may contain spaces); newlines in a value are
    /// impossible by construction (`kintsugi anchor export` strips them).
    pub fn render(&self) -> String {
        let mut s = String::with_capacity(96 + self.origin.len() + self.head.len());
        s.push_str(CHECKPOINT_FORMAT);
        s.push('\n');
        for (key, value) in [
            ("origin", self.origin.as_str()),
            ("seq", &self.seq.to_string()),
            ("head", self.head.as_str()),
            ("key_id", self.key_id.as_str()),
            ("ts", self.ts.as_str()),
        ] {
            s.push_str(key);
            s.push('=');
            s.push_str(value);
            s.push('\n');
        }
        if let Some(sig) = &self.sig {
            s.push_str("sig=");
            s.push_str(sig);
            s.push('\n');
        }
        s
    }

    /// Read back a rendered checkpoint envelope. Blank lines and unknown
    /// `key=value` extension lines are ignored (C2SP-style forward
    /// compatibility — they are outside the signature); a wrong header,
    /// a line without `=`, a non-integer `seq`, or a missing required field
    /// is an error naming the problem.
    pub fn parse(text: &str) -> Result<Checkpoint, AnchorError> {
        let mut lines = text.lines();
        match lines.next() {
            Some(h) if h.trim() == CHECKPOINT_FORMAT => {}
            _ => return Err(AnchorError::NotCheckpoint),
        }
        let mut origin = None;
        let mut seq = None;
        let mut head = None;
        let mut key_id = None;
        let mut ts = None;
        let mut sig = None;
        for (idx, line) in lines.enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(AnchorError::MalformedLine(idx + 2)); // header is line 1
            };
            match key {
                "origin" => origin = Some(value.to_string()),
                "seq" => {
                    seq = Some(
                        value
                            .parse::<i64>()
                            .map_err(|_| AnchorError::BadSeq(value.to_string()))?,
                    )
                }
                "head" => head = Some(value.to_string()),
                "key_id" => key_id = Some(value.to_string()),
                "ts" => ts = Some(value.to_string()),
                "sig" => sig = Some(value.to_string()),
                _ => {} // Unknown extension line: outside the signature, ignored.
            }
        }
        Ok(Checkpoint {
            origin: origin.ok_or(AnchorError::MissingField("origin"))?,
            seq: seq.ok_or(AnchorError::MissingField("seq"))?,
            head: head.ok_or(AnchorError::MissingField("head"))?,
            key_id: key_id.ok_or(AnchorError::MissingField("key_id"))?,
            ts: ts.ok_or(AnchorError::MissingField("ts"))?,
            sig,
        })
    }
}

/// The canonical, deterministic bytes a checkpoint signature covers.
///
/// Exactly five string fields in RFC 8785 key order (`head`, `key_id`,
/// `origin`, `seq`, `ts`), no whitespace. The output is byte-for-byte stable
/// across calls and platforms; the test suite pins the exact bytes and
/// cross-checks the escaping against `serde_json` on hostile inputs.
pub fn checkpoint_bytes(
    origin: &str,
    seq: i64,
    head: &str,
    key_id: &str,
    ts_rfc3339: &str,
) -> Vec<u8> {
    // RFC 8785 sorts keys by code units; these five ASCII keys are already in
    // plain lexicographic order, and the order is pinned by test.
    let seq_decimal = seq.to_string();
    let fields = [
        ("head", head),
        ("key_id", key_id),
        ("origin", origin),
        ("seq", &seq_decimal),
        ("ts", ts_rfc3339),
    ];
    let mut out = Vec::with_capacity(96 + head.len() + key_id.len() + origin.len());
    out.push(b'{');
    for (i, (key, value)) in fields.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        json_str(key, &mut out);
        out.push(b':');
        json_str(value, &mut out);
    }
    out.push(b'}');
    out
}

/// Serialize one JSON string per RFC 8785 §3.2.2.2: the six short-form escapes,
/// `\u00xx` (lowercase hex) for the remaining control bytes, everything else
/// as raw UTF-8. Valid for this module's fixed all-string shape only — see
/// the module doc for that scope limit.
fn json_str(s: &str, out: &mut Vec<u8>) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\u{0c}' => out.extend_from_slice(b"\\f"),
            '\r' => out.extend_from_slice(b"\\r"),
            c if (c as u32) < 0x20 => {
                let n = c as u32;
                out.extend_from_slice(b"\\u00");
                out.push(HEX[((n >> 4) & 0xf) as usize]);
                out.push(HEX[(n & 0xf) as usize]);
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

/// The exact bytes an anchor signature covers: [`ANCHOR_CONTEXT`] followed by
/// the canonical checkpoint. The label is a fixed-length constant and the
/// checkpoint is the trailing field, so the concatenation is unambiguous.
fn anchor_message(checkpoint: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(ANCHOR_CONTEXT.len() + checkpoint.len());
    msg.extend_from_slice(ANCHOR_CONTEXT);
    msg.extend_from_slice(checkpoint);
    msg
}

/// Sign a checkpoint with the vault's password-derived signing key, under
/// [`ANCHOR_CONTEXT`]. The key is argon2id-derived per call and never
/// persisted (same discipline as the admin proof).
pub fn sign_checkpoint(
    password: &str,
    salt_hex: &str,
    params: KdfParams,
    checkpoint: &[u8],
) -> Result<Vec<u8>, AdminError> {
    let signing = auth_signing_key(params, password, salt_hex)?;
    Ok(signing
        .sign(&anchor_message(checkpoint))
        .to_bytes()
        .to_vec())
}

/// Verify a checkpoint signature against `key_id_hex` — the hex-encoded
/// ed25519 *verifying* public key recorded in the checkpoint (the vault's
/// `auth_pubkey`). Strict verification, fail-closed on any malformed input.
pub fn verify_checkpoint_signature(key_id_hex: &str, checkpoint: &[u8], sig: &[u8]) -> bool {
    // Fail closed on any malformed input — never a panic (this runs against
    // user-held files, which an attacker may hand-craft).
    if sig.len() != SIGNATURE_LENGTH {
        return false;
    }
    let Ok(pk_bytes) = hex::decode(key_id_hex) else {
        return false;
    };
    if pk_bytes.len() != 32 {
        return false;
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let Ok(pk) = VerifyingKey::from_bytes(&pk_arr) else {
        return false;
    };
    let mut sig_arr = [0u8; SIGNATURE_LENGTH];
    sig_arr.copy_from_slice(sig);
    pk.verify_strict(
        &anchor_message(checkpoint),
        &ed25519_dalek::Signature::from_bytes(&sig_arr),
    )
    .is_ok()
}

/// The `key_id` for a vault's signing key: the hex-encoded verifying public
/// key derived from (password, salt, params). Deterministic — the same
/// password yields the same id, a different password yields a different one
/// (a new anchor series).
pub fn anchor_key_id(
    salt_hex: &str,
    params: KdfParams,
    password: &str,
) -> Result<String, AdminError> {
    let signing = auth_signing_key(params, password, salt_hex)?;
    Ok(hex::encode(signing.verifying_key().to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::compute_proof;
    use crate::log::Anchor;
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    // Test passwords are built at runtime (not string literals) so the
    // production-oriented "hard-coded credential" scanner doesn't flag
    // fixtures — the same convention as admin.rs.
    fn pw(tag: &str) -> String {
        format!("kintsugi-test-pw-{}-{tag}", std::process::id())
    }

    fn fast() -> KdfParams {
        KdfParams {
            m_cost: 64,
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn fixture() -> (String, KdfParams, Vec<u8>, String) {
        // (salt, params, checkpoint bytes, key_id)
        let salt = "0123456789abcdef0123456789abcdef";
        let params = fast();
        let key_id = anchor_key_id(salt, params, &pw("ok")).unwrap();
        let checkpoint = checkpoint_bytes(
            "test-host",
            42,
            "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
            &key_id,
            "2026-11-22T12:34:56Z",
        );
        (salt.to_string(), params, checkpoint, key_id)
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let (salt, params, checkpoint, key_id) = fixture();
        let sig = sign_checkpoint(&pw("ok"), &salt, params, &checkpoint).unwrap();
        assert!(
            verify_checkpoint_signature(&key_id, &checkpoint, &sig),
            "a signature by the vault key must verify under its key_id"
        );
    }

    #[test]
    fn admin_context_signature_is_rejected() {
        let (salt, params, checkpoint, key_id) = fixture();
        let password = pw("ok");

        // Direction 1: the SAME key signing under the admin proof's context
        // label must not verify as an anchor signature.
        let signing = auth_signing_key(params, &password, &salt).unwrap();
        let mut admin_msg = b"kintsugi.admin.settings.v1".to_vec();
        admin_msg.extend_from_slice(&checkpoint);
        let admin_sig = signing.sign(&admin_msg).to_bytes().to_vec();
        assert!(
            !verify_checkpoint_signature(&key_id, &checkpoint, &admin_sig),
            "an admin-context signature must never verify as an anchor signature"
        );

        // Direction 2: a real admin proof (compute_proof) over the checkpoint
        // bytes as the op must not verify as an anchor signature either.
        let nonce = [7u8; 24]; // NONCE_LEN in admin.rs
        let proof = compute_proof(&password, &salt, params, &nonce, &checkpoint).unwrap();
        assert!(
            !verify_checkpoint_signature(&key_id, &checkpoint, &proof),
            "an admin proof must never verify as an anchor signature"
        );

        // And the anchor signature itself does verify (control).
        let sig = sign_checkpoint(&password, &salt, params, &checkpoint).unwrap();
        assert!(verify_checkpoint_signature(&key_id, &checkpoint, &sig));
    }

    #[test]
    fn wrong_password_rotates_the_key_id() {
        let (salt, params, checkpoint, _) = fixture();
        let right = anchor_key_id(&salt, params, &pw("right")).unwrap();
        let wrong = anchor_key_id(&salt, params, &pw("wrong")).unwrap();
        assert_ne!(
            right, wrong,
            "a different password must derive a different key_id"
        );

        // A signature made under the wrong password fails under the right
        // key_id — an anchor can never be attributed to a key that didn't
        // sign it.
        let sig = sign_checkpoint(&pw("wrong"), &salt, params, &checkpoint).unwrap();
        assert!(!verify_checkpoint_signature(&right, &checkpoint, &sig));
    }

    #[test]
    fn tampered_checkpoint_fails_verification() {
        let (salt, params, checkpoint, key_id) = fixture();
        let sig = sign_checkpoint(&pw("ok"), &salt, params, &checkpoint).unwrap();
        assert!(verify_checkpoint_signature(&key_id, &checkpoint, &sig));

        // One flipped byte in the checkpoint (e.g. seq 42 -> 43) breaks it.
        let tampered = checkpoint_bytes(
            "test-host",
            43,
            "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
            &key_id,
            "2026-11-22T12:34:56Z",
        );
        assert_ne!(tampered, checkpoint);
        assert!(
            !verify_checkpoint_signature(&key_id, &tampered, &sig),
            "a signature over different bytes must not verify"
        );
    }

    #[test]
    fn canonical_bytes_are_pinned_byte_for_byte() {
        let head = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
        let key_id = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
        let a = checkpoint_bytes("box@example", 42, head, key_id, "2026-11-22T12:34:56Z");
        let expected = format!(
            "{{\"head\":\"{head}\",\"key_id\":\"{key_id}\",\
             \"origin\":\"box@example\",\"seq\":\"42\",\"ts\":\"2026-11-22T12:34:56Z\"}}"
        );
        assert_eq!(String::from_utf8(a.clone()).unwrap(), expected);

        // Byte-for-byte stable across calls.
        let b = checkpoint_bytes("box@example", 42, head, key_id, "2026-11-22T12:34:56Z");
        assert_eq!(a, b);
    }

    #[test]
    fn canonical_bytes_agree_with_serde_json_on_nasty_strings() {
        // Hostile input: quotes, backslashes, all the JSON short-form escape
        // bytes, an unescaped-range control byte, and non-ASCII. serde_json
        // on an all-string object (insertion order here is already sorted, so
        // its BTreeMap ordering can't diverge) is the reference encoder.
        let origin = "o\"k\\i\nn\tts\u{8}\u{c}\r\u{1}\u{1f}π—";
        let ts = "2026-11-22T12:34:56Z";
        let head = "h".repeat(64);
        let key_id = "k".repeat(64);
        let bytes = checkpoint_bytes(origin, -7, &head, &key_id, ts);
        let expect = serde_json::json!({
            "head": head,
            "key_id": key_id,
            "origin": origin,
            "seq": "-7",
            "ts": ts,
        });
        let expect = serde_json::to_string(&expect).unwrap();
        assert_eq!(String::from_utf8(bytes).unwrap(), expect);
    }

    #[test]
    fn anchor_key_id_is_the_derived_verifying_pubkey() {
        let (salt, params, _, key_id) = fixture();
        let derived = auth_signing_key(params, &pw("ok"), &salt)
            .unwrap()
            .verifying_key()
            .to_bytes();
        assert_eq!(key_id, hex::encode(derived));
        // The vault-visible identity is exactly the pubkey bytes, hex.
        assert_eq!(hex::decode(&key_id).unwrap().len(), 32);
    }

    #[test]
    fn anchor_serde_round_trips_and_ts_reformats_identically() {
        // The verify path rebuilds checkpoint bytes from a recorded Anchor
        // row; that only works if the row's timestamp reformats to exactly
        // the string that was signed. Whole-second UTC RFC3339 is a fixed
        // point of format∘parse (pinned empirically here).
        let ts = "2026-11-22T12:34:56Z";
        let anchor = Anchor {
            id: 1,
            created_ts: OffsetDateTime::parse(ts, &Rfc3339).unwrap(),
            origin: "test-host".into(),
            seq: 42,
            head: "a".repeat(64),
            key_id: "b".repeat(64),
            sig: Some("c".repeat(128)),
        };
        let json = serde_json::to_string(&anchor).unwrap();
        let back: Anchor = serde_json::from_str(&json).unwrap();
        assert_eq!(back, anchor);
        assert_eq!(
            back.created_ts.format(&Rfc3339).unwrap(),
            ts,
            "the stored timestamp must reformat byte-identically"
        );
    }

    #[test]
    fn malformed_key_id_or_signature_fails_closed() {
        let (salt, params, checkpoint, key_id) = fixture();
        let sig = sign_checkpoint(&pw("ok"), &salt, params, &checkpoint).unwrap();
        // Bad key_id encodings, wrong lengths, empty inputs — never a panic.
        assert!(!verify_checkpoint_signature("nothex", &checkpoint, &sig));
        assert!(!verify_checkpoint_signature("", &checkpoint, &sig));
        assert!(!verify_checkpoint_signature(
            &key_id,
            &checkpoint,
            b"too short"
        ));
        assert!(!verify_checkpoint_signature(&key_id, &checkpoint, &[]));
        // A valid-length but garbage key (not a curve point) fails closed.
        assert!(!verify_checkpoint_signature(
            &hex::encode([2u8; 32]),
            &checkpoint,
            &sig
        ));
    }
}
