//! Public-surface tests for checkpoint signing (Phase 7, T1.3).
//!
//! The inline suite in `src/anchor.rs` covers the behavior red-first; this
//! file exercises the *re-exported* API the way the CLI (T1.4) and any
//! external consumer see it, with an external-crate view of `KdfParams`.

use kintsugi_core::admin::KdfParams;
use kintsugi_core::{
    anchor_key_id, checkpoint_bytes, sign_checkpoint, verify_checkpoint_signature,
};

#[test]
fn public_surface_signs_and_verifies_round_trip() {
    // Cheap KDF params, tests only — same values `KdfParams::fast()` uses
    // in-crate; constructed here because that helper is cfg(test)-private.
    let params = KdfParams {
        m_cost: 64,
        t_cost: 1,
        p_cost: 1,
    };
    let salt = "0123456789abcdef0123456789abcdef";
    let password = format!("kintsugi-test-pw-{}-anchor", std::process::id());

    let key_id = anchor_key_id(salt, params, &password).unwrap();
    assert_eq!(key_id.len(), 64, "key_id is the hex verifying pubkey");
    let checkpoint = checkpoint_bytes(
        "integration-host",
        7,
        &"e5".repeat(32),
        &key_id,
        "2026-11-22T12:34:56Z",
    );
    let sig = sign_checkpoint(&password, salt, params, &checkpoint).unwrap();
    assert!(verify_checkpoint_signature(&key_id, &checkpoint, &sig));

    // Hostile inputs fail closed through the public surface too.
    assert!(!verify_checkpoint_signature(&key_id, b"tampered", &sig));
    assert!(!verify_checkpoint_signature("zz", &checkpoint, &sig));
    assert!(!verify_checkpoint_signature(&key_id, &checkpoint, b"short"));
}

#[test]
fn anchor_context_label_is_the_pinned_constant() {
    assert_eq!(kintsugi_core::ANCHOR_CONTEXT, b"kintsugi.log.anchor.v1");
}
