//! `kintsugi admin` + "password to stop" integration tests.

use std::process::Command;

fn kintsugi() -> Command {
    Command::new(env!("CARGO_BIN_EXE_kintsugi"))
}

#[test]
fn provision_locks_and_status_reports_locked() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.json");
    let pw = dir.path().join("pw");
    std::fs::write(&pw, "correct horse battery").unwrap();

    let out = kintsugi()
        .args(["admin", "provision", "--password-file"])
        .arg(&pw)
        .env("KINTSUGI_VAULT", &vault)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "provision failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(vault.exists(), "vault must be written");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("admin-locked"));
    assert!(stdout.contains("RECOVERY KEY"));
    // the vault on disk must not contain the password or settings in the clear.
    let raw = std::fs::read_to_string(&vault).unwrap();
    assert!(!raw.contains("correct horse"));
    assert!(!raw.contains("recording"));

    let st = kintsugi()
        .args(["admin", "status"])
        .env("KINTSUGI_VAULT", &vault)
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&st.stdout).contains("LOCKED"));
}

#[test]
fn settings_view_and_set_round_trip_with_password_file() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.json");
    let pw = dir.path().join("pw");
    std::fs::write(&pw, "correct horse battery").unwrap();

    // Provision, then read settings back (defaults: recording on).
    let prov = kintsugi()
        .args(["admin", "provision", "--password-file"])
        .arg(&pw)
        .env("KINTSUGI_VAULT", &vault)
        .output()
        .unwrap();
    assert!(prov.status.success());

    let view = kintsugi()
        .args(["admin", "settings", "--password-file"])
        .arg(&pw)
        .env("KINTSUGI_VAULT", &vault)
        .output()
        .unwrap();
    assert!(
        view.status.success(),
        "{}",
        String::from_utf8_lossy(&view.stderr)
    );
    let s = String::from_utf8_lossy(&view.stdout);
    assert!(s.contains("recording                 on"), "view: {s}");

    // Turn recording off, then confirm it persisted (sealed + re-read).
    let set = kintsugi()
        .args(["admin", "set", "recording", "off", "--password-file"])
        .arg(&pw)
        .env("KINTSUGI_VAULT", &vault)
        .output()
        .unwrap();
    assert!(
        set.status.success(),
        "{}",
        String::from_utf8_lossy(&set.stderr)
    );

    let view2 = kintsugi()
        .args(["admin", "settings", "--password-file"])
        .arg(&pw)
        .env("KINTSUGI_VAULT", &vault)
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&view2.stdout).contains("recording                 off"));
}

#[test]
fn set_with_wrong_password_fails_and_does_not_change_settings() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.json");
    let pw = dir.path().join("pw");
    let wrong = dir.path().join("wrong");
    std::fs::write(&pw, "correct horse battery").unwrap();
    std::fs::write(&wrong, "incorrect horse staple").unwrap();
    kintsugi()
        .args(["admin", "provision", "--password-file"])
        .arg(&pw)
        .env("KINTSUGI_VAULT", &vault)
        .output()
        .unwrap();

    let set = kintsugi()
        .args(["admin", "set", "recording", "off", "--password-file"])
        .arg(&wrong)
        .env("KINTSUGI_VAULT", &vault)
        .output()
        .unwrap();
    assert!(!set.status.success(), "wrong password must be rejected");

    // Setting is unchanged (still on).
    let view = kintsugi()
        .args(["admin", "settings", "--password-file"])
        .arg(&pw)
        .env("KINTSUGI_VAULT", &vault)
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&view.stdout).contains("recording                 on"));
}

#[test]
fn set_rejects_an_unknown_key() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.json");
    let pw = dir.path().join("pw");
    std::fs::write(&pw, "correct horse battery").unwrap();
    kintsugi()
        .args(["admin", "provision", "--password-file"])
        .arg(&pw)
        .env("KINTSUGI_VAULT", &vault)
        .output()
        .unwrap();
    let set = kintsugi()
        .args(["admin", "set", "allow-rm-rf-slash", "on", "--password-file"])
        .arg(&pw)
        .env("KINTSUGI_VAULT", &vault)
        .output()
        .unwrap();
    assert!(
        !set.status.success(),
        "there is no setting that loosens the floor"
    );
    assert!(String::from_utf8_lossy(&set.stderr).contains("unknown setting"));
}

#[test]
fn short_password_is_rejected_and_no_vault_written() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.json");
    let pw = dir.path().join("pw");
    std::fs::write(&pw, "short").unwrap();
    let out = kintsugi()
        .args(["admin", "provision", "--password-file"])
        .arg(&pw)
        .env("KINTSUGI_VAULT", &vault)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!vault.exists());
}

#[test]
fn degraded_vault_refuses_stop() {
    // A corrupt vault is Degraded → `stop` must refuse (fail-closed), without
    // prompting (so no tty interaction / no hang).
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.json");
    std::fs::write(&vault, b"{ this is not valid json").unwrap();
    let out = kintsugi()
        .arg("stop")
        .env("KINTSUGI_VAULT", &vault)
        .output()
        .unwrap();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(combined.contains("degraded"), "must refuse: {combined}");
    assert!(!combined.contains("stopped the daemon"));
}

#[test]
fn unprovisioned_stop_is_not_gated() {
    // No vault → stop proceeds normally (here: reports the daemon isn't running).
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("absent.json");
    let out = kintsugi()
        .arg("stop")
        .env("KINTSUGI_VAULT", &vault)
        .env("KINTSUGI_DB", dir.path().join("e.db"))
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("not running"));
}
