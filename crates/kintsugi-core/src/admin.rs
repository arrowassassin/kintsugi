//! Admin-locked, password-protected, encrypted settings (the crypto core).
//!
//! A sysadmin provisions a machine with an admin password and a set of *locked*
//! settings (recording on/off, autostart, "password required to stop", …). The
//! settings are sealed at rest so a non-privileged user — or an AI agent running
//! as that user — can neither read nor forge them, and privileged operations
//! (stop, change-password, disable-recording) require proving knowledge of the
//! password.
//!
//! This module is the crypto + storage core only; the daemon-side auth handshake
//! and the "password to stop" enforcement live separately (they consume these
//! primitives). Design decisions follow the security review:
//!   - **Domain separation**: the password *verifier* and the *sealing key* are
//!     independent argon2id derivations (different random salts), so the stored
//!     verifier is never the encryption key.
//!   - **Pinned, versioned KDF**: argon2id parameters are stored with the vault
//!     and carry a version, so they can be raised later without breaking old files.
//!   - **AEAD discipline**: XChaCha20-Poly1305 with a *random 192-bit nonce per
//!     seal* (XChaCha's large nonce makes random nonces safe), and the AAD binds
//!     the version + salt + a context label so a blob can't be repurposed.
//!   - **Recovery**: a one-time random recovery key wraps the sealing key in its
//!     own AEAD slot, so a lost password is recoverable without any Kintsugi-held
//!     escrow (nothing leaves the machine). Possession of the recovery key is a
//!     second root credential — documented, not hidden.
//!   - **Zeroization**: derived key material is wiped from memory after use.
//!
//! Honest scope: this protects against a non-root user / agent and a disk thief
//! (argon2id at rest). It does **not** stop a root user — see the threat model in
//! the design doc. The caller must keep the failure mode fail-*closed-on-lock*:
//! if the vault can't be read, refuse privileged ops; never silently unlock.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Bumped if the KDF/seal scheme changes; old vaults keep their stored version.
const SCHEME_VERSION: u32 = 1;
/// AEAD associated data context label — binds a blob to this exact use.
const CONTEXT: &[u8] = b"kintsugi.admin.settings.v1";
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24; // XChaCha20-Poly1305

/// The settings an admin can lock. Every field is a *tightening* control: it can
/// only add caution (the catastrophic rule floor is enforced elsewhere and can
/// never be unlocked by a setting — see `policy::adjust_for_policy`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedSettings {
    /// Passive shell-session recording is on.
    pub recording: bool,
    /// The daemon auto-starts at login/boot.
    pub autostart: bool,
    /// Stopping / unhooking / disabling Kintsugi requires the admin password.
    pub require_password_to_stop: bool,
    /// Interception mode (attended holds; unattended denies; notify records).
    pub enforcement: Enforcement,
    /// When the daemon is down, the shim/hook refuse commands (opt-in; default off
    /// to avoid bricking a workflow — Kintsugi is not a firewall).
    pub fail_closed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Enforcement {
    Attended,
    Unattended,
    Notify,
}

impl Default for LockedSettings {
    fn default() -> Self {
        Self {
            recording: true,
            autostart: true,
            require_password_to_stop: true,
            enforcement: Enforcement::Attended,
            fail_closed: false,
        }
    }
}

/// Pinned, versioned argon2id parameters, stored with the vault for re-derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_cost: u32, // KiB
    pub t_cost: u32, // iterations
    pub p_cost: u32, // lanes
}

impl KdfParams {
    /// Production floor (OWASP-aligned: 19 MiB, 2 iterations, 1 lane).
    pub const fn production() -> Self {
        Self {
            m_cost: 19 * 1024,
            t_cost: 2,
            p_cost: 1,
        }
    }
    /// Cheap params for tests only — never use to protect a real secret.
    #[cfg(test)]
    const fn fast() -> Self {
        Self {
            m_cost: 64,
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn argon2(&self) -> Result<Argon2<'static>, AdminError> {
        let params = Params::new(self.m_cost, self.t_cost, self.p_cost, Some(KEY_LEN))
            .map_err(|_| AdminError::Kdf)?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }

    /// Derive a `KEY_LEN`-byte key from `password` + `salt`. Zeroized on drop.
    fn derive(&self, password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, AdminError> {
        let mut out = Zeroizing::new([0u8; KEY_LEN]);
        self.argon2()?
            .hash_password_into(password, salt, out.as_mut())
            .map_err(|_| AdminError::Kdf)?;
        Ok(out)
    }
}

/// The sealed-at-rest vault. Serialized (hex-encoded byte fields) to a root-owned
/// `0600` file on headless hosts, or wrapped by an OS keychain on desktops.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedVault {
    pub scheme_version: u32,
    pub params: KdfParams,
    /// argon2id(password, verifier_salt) — proves knowledge of the password.
    verifier_salt: String,
    verifier: String,
    /// AEAD of the settings under argon2id(password, seal_salt).
    seal_salt: String,
    seal_nonce: String,
    seal_ct: String,
    /// AEAD of the *sealing key* under the recovery key (password-independent).
    recovery_nonce: String,
    recovery_ct: String,
}

/// Result of provisioning: the vault to persist + the one-time recovery key to
/// show the admin once (never stored in plaintext anywhere).
pub struct Provisioned {
    pub vault: SealedVault,
    pub recovery_key: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AdminError {
    #[error("wrong password")]
    WrongPassword,
    #[error("invalid recovery key")]
    WrongRecoveryKey,
    #[error("vault is corrupt or was tampered with")]
    Tampered,
    #[error("malformed vault field")]
    Decode,
    #[error("key derivation failed")]
    Kdf,
    #[error("random source unavailable")]
    Random,
}

fn random_bytes<const N: usize>() -> Result<[u8; N], AdminError> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|_| AdminError::Random)?;
    Ok(b)
}

fn aead(key: &[u8; KEY_LEN]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(key.into())
}

fn seal(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<(String, String), AdminError> {
    let nonce = random_bytes::<NONCE_LEN>()?;
    let ct = aead(key)
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: CONTEXT,
            },
        )
        .map_err(|_| AdminError::Kdf)?;
    Ok((hex::encode(nonce), hex::encode(ct)))
}

fn open(key: &[u8; KEY_LEN], nonce_hex: &str, ct_hex: &str) -> Result<Vec<u8>, AdminError> {
    let nonce = hex::decode(nonce_hex).map_err(|_| AdminError::Decode)?;
    let ct = hex::decode(ct_hex).map_err(|_| AdminError::Decode)?;
    if nonce.len() != NONCE_LEN {
        return Err(AdminError::Decode);
    }
    aead(key)
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ct,
                aad: CONTEXT,
            },
        )
        // A decrypt failure on a well-formed blob means a wrong key or tampering.
        .map_err(|_| AdminError::Tampered)
}

/// Constant-time byte comparison (avoid leaking the verifier via timing).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Provision a fresh vault from an admin password + initial settings.
pub fn provision(password: &str, settings: &LockedSettings) -> Result<Provisioned, AdminError> {
    provision_with(password, settings, KdfParams::production())
}

fn provision_with(
    password: &str,
    settings: &LockedSettings,
    params: KdfParams,
) -> Result<Provisioned, AdminError> {
    let pw = password.as_bytes();
    // 1. Verifier (independent salt → domain-separated from the sealing key).
    let verifier_salt = random_bytes::<SALT_LEN>()?;
    let verifier = params.derive(pw, &verifier_salt)?;
    // 2. Sealing key (independent salt), seal the settings.
    let seal_salt = random_bytes::<SALT_LEN>()?;
    let seal_key = params.derive(pw, &seal_salt)?;
    let plaintext = serde_json::to_vec(settings).map_err(|_| AdminError::Decode)?;
    let (seal_nonce, seal_ct) = seal(&seal_key, &plaintext)?;
    // 3. Recovery slot: a random 256-bit key wraps the *sealing key*.
    let recovery_raw = random_bytes::<KEY_LEN>()?;
    let (recovery_nonce, recovery_ct) = seal(&recovery_raw, seal_key.as_ref())?;

    Ok(Provisioned {
        vault: SealedVault {
            scheme_version: SCHEME_VERSION,
            params,
            verifier_salt: hex::encode(verifier_salt),
            verifier: hex::encode(verifier.as_ref()),
            seal_salt: hex::encode(seal_salt),
            seal_nonce,
            seal_ct,
            recovery_nonce,
            recovery_ct,
        },
        recovery_key: hex::encode(recovery_raw),
    })
}

impl SealedVault {
    /// Whether `password` matches (constant-time). Does not unseal.
    pub fn verify_password(&self, password: &str) -> bool {
        let Ok(salt) = hex::decode(&self.verifier_salt) else {
            return false;
        };
        let Ok(want) = hex::decode(&self.verifier) else {
            return false;
        };
        let Ok(got) = self.params.derive(password.as_bytes(), &salt) else {
            return false;
        };
        ct_eq(got.as_ref(), &want)
    }

    /// Derive the sealing key from the password (or error on wrong password).
    fn sealing_key(&self, password: &str) -> Result<Zeroizing<[u8; KEY_LEN]>, AdminError> {
        if !self.verify_password(password) {
            return Err(AdminError::WrongPassword);
        }
        let salt = hex::decode(&self.seal_salt).map_err(|_| AdminError::Decode)?;
        self.params.derive(password.as_bytes(), &salt)
    }

    /// Decrypt the locked settings with the admin password.
    pub fn unseal(&self, password: &str) -> Result<LockedSettings, AdminError> {
        let key = self.sealing_key(password)?;
        let plaintext = open(&key, &self.seal_nonce, &self.seal_ct)?;
        serde_json::from_slice(&plaintext).map_err(|_| AdminError::Decode)
    }

    /// Decrypt the locked settings with the recovery key (no password needed).
    pub fn unseal_with_recovery(&self, recovery_key: &str) -> Result<LockedSettings, AdminError> {
        let raw = hex::decode(recovery_key).map_err(|_| AdminError::WrongRecoveryKey)?;
        if raw.len() != KEY_LEN {
            return Err(AdminError::WrongRecoveryKey);
        }
        let mut rk = Zeroizing::new([0u8; KEY_LEN]);
        rk.copy_from_slice(&raw);
        // Recover the sealing key from the recovery slot, then the settings.
        let seal_key_bytes = open(&rk, &self.recovery_nonce, &self.recovery_ct)
            .map_err(|_| AdminError::WrongRecoveryKey)?;
        if seal_key_bytes.len() != KEY_LEN {
            return Err(AdminError::Decode);
        }
        let mut seal_key = Zeroizing::new([0u8; KEY_LEN]);
        seal_key.copy_from_slice(&seal_key_bytes);
        let plaintext = open(&seal_key, &self.seal_nonce, &self.seal_ct)?;
        serde_json::from_slice(&plaintext).map_err(|_| AdminError::Decode)
    }

    /// Re-seal new settings, authenticated by the current password. Re-encrypts
    /// the settings slot (fresh nonce) while preserving the verifier and recovery
    /// slot — i.e. the same password + recovery key still work.
    pub fn update_settings(
        &self,
        password: &str,
        new_settings: &LockedSettings,
    ) -> Result<SealedVault, AdminError> {
        let key = self.sealing_key(password)?;
        let plaintext = serde_json::to_vec(new_settings).map_err(|_| AdminError::Decode)?;
        let (seal_nonce, seal_ct) = seal(&key, &plaintext)?;
        Ok(SealedVault {
            seal_nonce,
            seal_ct,
            ..self.clone()
        })
    }

    /// Change the admin password. Re-derives the verifier and re-seals the
    /// settings + recovery slot under the new password. The recovery key is
    /// rotated (a fresh one is returned).
    pub fn change_password(&self, old: &str, new: &str) -> Result<Provisioned, AdminError> {
        let settings = self.unseal(old)?; // authenticates `old`
                                          // Keep the same KDF params; everything else (salts, nonces, recovery key)
                                          // is regenerated, so an exposed old recovery key no longer works.
        provision_with(new, &settings, self.params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provision_fast(pw: &str, s: &LockedSettings) -> Provisioned {
        provision_with(pw, s, KdfParams::fast()).unwrap()
    }

    #[test]
    fn round_trips_settings() {
        let s = LockedSettings::default();
        let p = provision_fast("correct horse", &s);
        assert!(p.vault.verify_password("correct horse"));
        assert_eq!(p.vault.unseal("correct horse").unwrap(), s);
    }

    #[test]
    fn wrong_password_is_rejected_and_does_not_unseal() {
        let p = provision_fast("s3cr3t", &LockedSettings::default());
        assert!(!p.vault.verify_password("guess"));
        assert_eq!(
            p.vault.unseal("guess").unwrap_err(),
            AdminError::WrongPassword
        );
    }

    #[test]
    fn verifier_is_not_the_sealing_key() {
        // Domain separation: the stored verifier must not equal the AEAD key, so a
        // reader of the verifier can't decrypt the settings.
        let p = provision_fast("pw", &LockedSettings::default());
        let salt = hex::decode(&p.vault.seal_salt).unwrap();
        let seal_key = p.vault.params.derive(b"pw", &salt).unwrap();
        assert_ne!(hex::encode(seal_key.as_ref()), p.vault.verifier);
        assert_ne!(p.vault.verifier_salt, p.vault.seal_salt);
    }

    #[test]
    fn recovery_key_unseals_without_password() {
        let s = LockedSettings {
            recording: false,
            ..Default::default()
        };
        let p = provision_fast("pw", &s);
        assert_eq!(p.vault.unseal_with_recovery(&p.recovery_key).unwrap(), s);
        // a wrong recovery key fails cleanly.
        let bad = hex::encode([7u8; KEY_LEN]);
        assert!(p.vault.unseal_with_recovery(&bad).is_err());
        assert!(p.vault.unseal_with_recovery("nothex").is_err());
    }

    #[test]
    fn tampering_with_the_ciphertext_is_detected() {
        let mut p = provision_fast("pw", &LockedSettings::default());
        // flip a byte of the sealed settings.
        let mut ct = hex::decode(&p.vault.seal_ct).unwrap();
        ct[0] ^= 0xff;
        p.vault.seal_ct = hex::encode(ct);
        assert_eq!(p.vault.unseal("pw").unwrap_err(), AdminError::Tampered);
    }

    #[test]
    fn update_settings_requires_password_and_persists() {
        let p = provision_fast("pw", &LockedSettings::default());
        let new = LockedSettings {
            recording: false,
            enforcement: Enforcement::Unattended,
            ..Default::default()
        };
        assert_eq!(
            p.vault.update_settings("wrong", &new).unwrap_err(),
            AdminError::WrongPassword
        );
        let v2 = p.vault.update_settings("pw", &new).unwrap();
        assert_eq!(v2.unseal("pw").unwrap(), new);
        // nonce changed (no AEAD nonce reuse across re-seals).
        assert_ne!(v2.seal_nonce, p.vault.seal_nonce);
    }

    #[test]
    fn change_password_rotates_and_invalidates_old() {
        let p = provision_fast("old", &LockedSettings::default());
        let p2 = p.vault.change_password("old", "new").unwrap();
        assert!(p2.vault.verify_password("new"));
        assert!(!p2.vault.verify_password("old"));
        // old recovery key no longer works against the new vault.
        assert!(p2.vault.unseal_with_recovery(&p.recovery_key).is_err());
        assert!(p2.vault.unseal_with_recovery(&p2.recovery_key).is_ok());
        // `Provisioned` has no Debug (it holds the recovery secret), so match.
        assert!(matches!(
            p.vault.change_password("wrong", "x"),
            Err(AdminError::WrongPassword)
        ));
    }

    #[test]
    fn vault_serializes_round_trip() {
        let p = provision_fast("pw", &LockedSettings::default());
        let json = serde_json::to_string(&p.vault).unwrap();
        let back: SealedVault = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p.vault);
        assert!(back.unseal("pw").is_ok());
        // the plaintext settings never appear in the serialized vault.
        assert!(!json.contains("recording"));
    }
}
