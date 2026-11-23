//! `kintsugi anchor` — user-controlled chain-head checkpoints (Phase 7, T1.4).
//!
//! Anchoring is export-only by design: **the daemon never pushes anything;
//! Kintsugi makes no network call.** The user copies the checkpoint somewhere
//! the log cannot reach (a private repo, a second device, removable media)
//! and verifies later against that copy. Anchor operations talk to the LOG,
//! never the daemon.
//!
//! Honest scope: a checkpoint makes the log **tamper-evident against casual
//! modification and externally verifiable against a user-held copy** — it is
//! not tamper-PROOF, and nothing here is an unbypassable firewall. See
//! `docs/anchoring.md` for what anchoring does and does not buy.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use kintsugi_core::admin::{self, VaultState};
use kintsugi_core::anchor::Checkpoint;
use kintsugi_core::{anchor_key_id, sign_checkpoint, ChainStatus, EventLog, LogError};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::admin_cmd::read_password;

/// Verify exit codes — distinct on purpose, so automation can tell the
/// outcomes apart without parsing prose. Anything non-zero means verification
/// did not fully pass; `0` is INTACT only.
pub const EXIT_STALE: i32 = 1;
pub const EXIT_TAMPERED: i32 = 2;
pub const EXIT_INVALID: i32 = 3;
pub const EXIT_UNVERIFIABLE: i32 = 4;

/// `kintsugi anchor export [--out FILE] [--origin ID] [--no-sign]
/// [--password-file FILE]` — write the checkpoint for the current chain head
/// and record it in the log's anchors table.
pub fn export(
    out: Option<PathBuf>,
    origin: Option<String>,
    no_sign: bool,
    password_file: Option<PathBuf>,
) -> Result<()> {
    let db = kintsugi_daemon::default_db_path();
    if !db.exists() {
        bail!(
            "no event log at {} — nothing to anchor (run `kintsugi init` first)",
            db.display()
        );
    }
    let log = EventLog::open(&db).with_context(|| format!("open log {}", db.display()))?;
    let (seq, head) = log.chain_head()?;
    let origin = sanitize_origin(&origin.unwrap_or_else(default_origin));
    let ts = now_ts()?;

    // Sign with the vault's password-derived key when a usable vault exists
    // (and signing wasn't deliberately declined). NO new secret at rest: the
    // key is derived per operation and only the verifying pubkey is embedded.
    let mut checkpoint = Checkpoint {
        origin,
        seq,
        head,
        key_id: String::new(),
        ts,
        sig: None,
    };
    let mut vault_note = String::new();
    match (admin::load_vault(&admin::default_vault_path()), no_sign) {
        (VaultState::Locked(vault), false) => {
            let password =
                read_password("Admin password (signs the checkpoint): ", &password_file)?;
            if !vault.verify_password(&password) {
                bail!("wrong admin password — nothing was recorded or exported");
            }
            let (salt, params) = vault.auth_challenge();
            let key_id = anchor_key_id(&salt, params, &password)?;
            checkpoint.key_id = key_id;
            let sig = sign_checkpoint(&password, &salt, params, &checkpoint.bytes())?;
            checkpoint.sig = Some(hex::encode(sig));
        }
        (VaultState::Degraded(reason), _) => {
            // Fail loud, not silent: a corrupt vault cannot sign, so this
            // export is unsigned and says so.
            vault_note = format!(
                "warning: the admin vault is unreadable ({reason}) — this checkpoint is UNSIGNED."
            );
        }
        (VaultState::Unprovisioned, _) | (_, true) => {}
    }

    // Record BEFORE handing anything out: a refused fork must leave the
    // user holding nothing, and a failed write must never fabricate an anchor.
    let anchor = match log.record_anchor(&checkpoint) {
        Ok(anchor) => anchor,
        Err(LogError::Fork(msg)) => bail!(
            "refused: {msg}\n  Nothing was recorded or exported. The anchors table records \
             a series the events table no longer extends — typically an older log \
             restored over a newer one. Re-anchor only after deciding which log is real."
        ),
        Err(e) => return Err(e).context("record anchor"),
    };

    let body = checkpoint.render();
    match &out {
        Some(path) => {
            std::fs::write(path, &body)
                .with_context(|| format!("write checkpoint {}", path.display()))?;
            println!("Checkpoint written to {}", path.display());
        }
        None => print!("{body}"),
    }
    println!();
    println!("Recorded as anchor {} in {}.", anchor.id, db.display());
    println!(
        "Keep this copy somewhere the log cannot reach: a private repo, a second device, or removable media."
    );
    println!(
        "The daemon never pushes anything; Kintsugi makes no network call — the copy is yours to make."
    );
    if !vault_note.is_empty() {
        println!("{vault_note}");
    }
    if checkpoint.sig.is_some() {
        println!(
            "Signed under key_id {} — verify later with `kintsugi anchor verify --checkpoint <file>`.",
            checkpoint.key_id
        );
    } else {
        println!(
            "This checkpoint is UNSIGNED — `kintsugi anchor verify` will report it UNVERIFIABLE."
        );
        println!("  To sign future exports, provision an admin vault: `kintsugi admin provision`.");
    }
    Ok(())
}

/// `kintsugi anchor verify [--checkpoint FILE]` — check the log against a
/// checkpoint file (default: the last recorded anchor).
///
/// Distinct results, distinct exit codes, honest language:
/// `INTACT through anchor N` (0) · `STALE: N events since the anchor` (1) ·
/// `TAMPERED: chain diverges before anchor N` (2) · `INVALID: ...` signature
/// failure (3) · `UNVERIFIABLE: ...` (4, unsigned/missing/unreadable). This
/// function exits the process itself — every can't-verify condition is
/// caught and mapped to its code, so no path falls out to a generic error.
pub fn verify(checkpoint: Option<PathBuf>) -> Result<()> {
    let db = kintsugi_daemon::default_db_path();
    if !db.exists() {
        println!(
            "UNVERIFIABLE: no event log at {} to verify against.",
            db.display()
        );
        std::process::exit(EXIT_UNVERIFIABLE);
    }
    let log = match EventLog::open(&db) {
        Ok(log) => log,
        Err(e) => {
            println!("UNVERIFIABLE: could not open the log — {e}.");
            std::process::exit(EXIT_UNVERIFIABLE);
        }
    };

    // The verification target: the caller's file, else the last anchor row.
    let checkpoint = match checkpoint {
        Some(path) => {
            let text = match std::fs::read_to_string(&path) {
                Ok(text) => text,
                Err(e) => {
                    println!("UNVERIFIABLE: could not read {} — {e}.", path.display());
                    std::process::exit(EXIT_UNVERIFIABLE);
                }
            };
            match Checkpoint::parse(&text) {
                Ok(cp) => cp,
                Err(e) => {
                    println!(
                        "UNVERIFIABLE: {} is not a readable checkpoint — {e}.",
                        path.display()
                    );
                    std::process::exit(EXIT_UNVERIFIABLE);
                }
            }
        }
        None => {
            let anchor = match log.latest_anchor() {
                Ok(Some(anchor)) => anchor,
                Ok(None) => {
                    println!(
                        "UNVERIFIABLE: no anchor recorded — run `kintsugi anchor export` first."
                    );
                    std::process::exit(EXIT_UNVERIFIABLE);
                }
                Err(e) => {
                    println!("UNVERIFIABLE: could not read the recorded anchor — {e}.");
                    std::process::exit(EXIT_UNVERIFIABLE);
                }
            };
            // Rebuild the checkpoint from the row: the whole-second RFC3339
            // fixed point guarantees the canonical bytes match what was
            // signed at export time.
            let ts = match anchor.created_ts.format(&Rfc3339) {
                Ok(ts) => ts,
                Err(e) => {
                    println!("UNVERIFIABLE: the recorded anchor timestamp is malformed — {e}.");
                    std::process::exit(EXIT_UNVERIFIABLE);
                }
            };
            Checkpoint {
                origin: anchor.origin,
                seq: anchor.seq,
                head: anchor.head,
                key_id: anchor.key_id,
                ts,
                sig: anchor.sig,
            }
        }
    };

    if checkpoint.sig.is_none() {
        println!(
            "UNVERIFIABLE: this checkpoint is unsigned — it asserts nothing about who wrote it."
        );
        println!(
            "  Provision an admin vault (`kintsugi admin provision`) and export again for a signed one."
        );
        std::process::exit(EXIT_UNVERIFIABLE);
    }
    if !checkpoint.signature_is_valid() {
        println!("INVALID: the checkpoint's signature does not verify under its own key_id.");
        println!("  The file was modified, corrupted, or forged — its contents prove nothing.");
        // Never fall through silently to a chain-only verdict: but a chain
        // that is ALSO broken is independent evidence, so note it, loudly.
        if let Ok(ChainStatus::Broken { seq, detail }) = log.verify_chain() {
            println!("  Note: the local chain is also broken (at seq {seq}: {detail}).");
        }
        std::process::exit(EXIT_INVALID);
    }

    let n = checkpoint.seq;
    let chain = match log.verify_chain() {
        Ok(chain) => chain,
        Err(e) => {
            println!("UNVERIFIABLE: the chain walk failed — {e}.");
            std::process::exit(EXIT_UNVERIFIABLE);
        }
    };
    if let ChainStatus::Broken { seq, detail } = &chain {
        println!(
            "TAMPERED: chain diverges before anchor {n} — chain break at seq {seq} ({detail})."
        );
        std::process::exit(EXIT_TAMPERED);
    }

    let (latest, head_now) = match log.chain_head() {
        Ok(pair) => pair,
        Err(e) => {
            println!("UNVERIFIABLE: could not read the chain head — {e}.");
            std::process::exit(EXIT_UNVERIFIABLE);
        }
    };
    if latest == checkpoint.seq && head_now == checkpoint.head {
        println!("INTACT through anchor {n}");
        std::process::exit(0);
    }
    // The anchored head must be REACHABLE at its own seq — a chain that is
    // intact today proves nothing about the anchor if a purge or rewrite
    // rebuilt it below the checkpoint.
    let at_seq = match log.hash_at_seq(checkpoint.seq) {
        Ok(at_seq) => at_seq,
        Err(e) => {
            println!("UNVERIFIABLE: could not read the anchored row — {e}.");
            std::process::exit(EXIT_UNVERIFIABLE);
        }
    };
    match at_seq {
        Some(h) if h == checkpoint.head => {
            let since = latest - checkpoint.seq;
            println!("STALE: {since} events since the anchor — export a fresh checkpoint (`kintsugi anchor export`).");
            std::process::exit(EXIT_STALE);
        }
        _ => {
            println!(
                "TAMPERED: chain diverges before anchor {n} — the anchored head is not at its seq \
                 (the log was purged or rewritten after this anchor)."
            );
            std::process::exit(EXIT_TAMPERED);
        }
    }
}

/// The `anchored:` line for `kintsugi status`, when an anchor is on record.
/// `None` leaves status exactly as it was before anchoring existed.
pub fn anchored_status_line(log: &EventLog) -> Option<String> {
    let anchor = log.latest_anchor().ok()??;
    let latest = log.latest_seq().unwrap_or(anchor.seq);
    let since = (latest - anchor.seq).max(0);
    let ts = anchor.created_ts.format(&Rfc3339).ok()?;
    let unsigned = if anchor.key_id.is_empty() {
        " — unsigned"
    } else {
        ""
    };
    Some(format!("  anchored: {ts} ({since} events ago){unsigned}"))
}

/// Whole-second RFC3339 UTC. Seconds precision is deliberate: it is a fixed
/// point of format∘parse (pinned by test), so a recorded anchor row rebuilds
/// the exact bytes that were signed.
fn now_ts() -> Result<String> {
    let now = OffsetDateTime::now_utc();
    let whole = now.replace_nanosecond(0).unwrap_or(now);
    Ok(whole.format(&Rfc3339)?)
}

/// The default checkpoint origin: user@hostname. The `hostname` command is
/// the only cross-platform way to get it without a new dependency; every
/// failure path degrades to an explicit placeholder, never a guess.
fn default_origin() -> String {
    let host = std::process::Command::new("hostname")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "unknown-host".to_string());
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown-user".to_string());
    format!("{user}@{host}")
}

/// The checkpoint envelope is line-based: a newline inside an origin would
/// corrupt it, so strip the only characters that can break lines.
fn sanitize_origin(origin: &str) -> String {
    origin.replace(['\r', '\n'], " ")
}
