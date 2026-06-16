//! Fuzz / property tests for the security-critical surfaces added recently:
//! command-line **redaction** (must never leak a secret) and the **admin vault**
//! (round-trip + wrong-password invariants). No external fuzzing dependency — a
//! tiny deterministic PRNG drives thousands of randomized inputs so the run is
//! reproducible in CI.

use kintsugi_core::admin::{self, LockedSettings};
use kintsugi_core::redact::redact_command;

/// Deterministic xorshift64* PRNG — reproducible, no dependency.
struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
}

/// A random secret from a realistic password/token charset (no whitespace or
/// quotes, so it stays a single shell token in a credential slot). Length 8–23.
fn secret(rng: &mut Rng) -> String {
    // Charset includes `@`, `/`, and `%` — the hard cases for URI userinfo parsing
    // (a password can contain `@`/`/`; `%2F` is an encoded slash). No whitespace or
    // quotes, so the secret stays a single shell token in a credential slot.
    const CS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-+/@%";
    let len = 8 + rng.below(16);
    (0..len).map(|_| CS[rng.below(CS.len())] as char).collect()
}

#[test]
fn redaction_never_leaks_a_secret_across_many_inputs() {
    let mut rng = Rng(0x9E3779B97F4A7C15);
    // Templates Kintsugi's redactor is responsible for. `{}` is the secret slot.
    let templates: &[fn(&str) -> String] = &[
        |s| format!("mysql -p{s} -u root"),
        |s| format!("mysql --password={s} -h db"),
        |s| format!("PGPASSWORD={s} psql -h db -U app"),
        |s| format!("redis-cli -a {s} ping"),
        |s| format!("psql postgres://app:{s}@db.internal/prod"),
        |s| format!("curl --token={s} https://api.example.com"),
        |s| format!("sudo mysql -p{s}"),
        |s| format!("env MYSQL_PWD={s} mysql"),
        // A secret in the query string AFTER userinfo (must redact both halves).
        |s| format!("psql postgres://app:userpw@db.internal/prod?password={s}"),
        // Empty-host DSN (default host / socket): the real `@` precedes `/`.
        |s| format!("psql postgresql://user:{s}@/dbname"),
    ];

    for _ in 0..8000 {
        let s = secret(&mut rng);
        let t = templates[rng.below(templates.len())];
        let cmd = t(&s);
        let red = redact_command(&cmd);

        assert!(
            !red.text.contains(&s),
            "secret leaked!\n  input:    {cmd}\n  redacted: {}\n  secret:   {s}",
            red.text
        );
        assert!(
            red.any(),
            "a credential slot must redact at least once: {cmd}"
        );
        // Idempotent: redacting the already-redacted text introduces no new secret.
        let again = redact_command(&red.text);
        assert!(
            !again.text.contains(&s),
            "secret reappeared on re-redaction"
        );
    }
}

#[test]
fn redaction_leaves_non_secret_commands_byte_identical() {
    // A corpus of ordinary commands must pass through untouched (count 0).
    let safe = [
        "git status",
        "ls -la /var/log",
        "cargo build --release",
        "kubectl get pods -n prod",
        "rm -rf ./build",
        "docker run -p 8080:80 nginx", // -p here is a PORT, not a password
        "grep -r TODO src/",
    ];
    for cmd in safe {
        let red = redact_command(cmd);
        assert_eq!(red.text, cmd, "non-secret command must be unchanged: {cmd}");
        assert!(!red.any(), "no redaction expected for: {cmd}");
    }
}

#[test]
fn admin_vault_round_trips_and_rejects_wrong_passwords_under_fuzz() {
    let mut rng = Rng(0xD1B54A32D192ED03);
    // Production argon2id is intentionally expensive, so keep the count modest;
    // the redaction test above carries the high-volume fuzzing.
    for _ in 0..8 {
        let pw = secret(&mut rng);
        let wrong = format!("{pw}x"); // guaranteed different
        let settings = LockedSettings {
            recording: rng.below(2) == 0,
            autostart: rng.below(2) == 0,
            ..Default::default()
        };
        let prov = admin::provision(&pw, &settings).unwrap();

        // Correct password round-trips the exact settings.
        assert!(prov.vault.verify_password(&pw));
        assert_eq!(prov.vault.unseal(&pw).unwrap(), settings);

        // Wrong password never verifies and never unseals.
        assert!(!prov.vault.verify_password(&wrong));
        assert!(prov.vault.unseal(&wrong).is_err());

        // The sealed vault never carries the password or plaintext settings.
        let json = serde_json::to_string(&prov.vault).unwrap();
        assert!(!json.contains(&pw), "password leaked into the sealed vault");
        assert!(
            !json.contains("recording"),
            "plaintext settings in the vault"
        );
    }
}
