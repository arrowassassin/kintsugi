//! End-to-end: `kintsugi approve` against a running daemon (Phase 7, T2.2).
//!
//! In its own test binary so its process-global env (the shared socket/db)
//! can't contaminate the parallel tests in `cli.rs` / `cli_queue.rs`.
//!
//! Convention (see `cli.rs`): the vault resolver is pointed at an absent file
//! so most tests stay on the unprovisioned path and never touch the machine's
//! real vault or a tty. The vault-LOCKED path (AuthBegin → password → nonce-bound
//! proof) is driven here through `--password-file`, the same non-interactive
//! discipline `admin provision` and `anchor export` already use — the interactive
//! prompt reads `/dev/tty`, which a harness must not drive.
#![cfg(unix)]

use std::process::Command;

use kintsugi_core::{Decision, ProposedCommand};

fn kintsugi() -> Command {
    Command::new(env!("CARGO_BIN_EXE_kintsugi"))
}

/// Spawn the real daemon binary on an isolated socket/db and wait for it.
fn start_daemon(
    sock: &std::path::Path,
    db: &std::path::Path,
    config: &std::path::Path,
) -> std::process::Child {
    start_daemon_with(sock, db, config, None)
}

fn start_daemon_with(
    sock: &std::path::Path,
    db: &std::path::Path,
    config: &std::path::Path,
    vault: Option<&std::path::Path>,
) -> std::process::Child {
    let daemon_bin =
        std::path::Path::new(env!("CARGO_BIN_EXE_kintsugi")).with_file_name("kintsugi-daemon");
    let daemon = Command::new(&daemon_bin)
        .env("KINTSUGI_SOCKET", sock)
        .env("KINTSUGI_DB", db)
        .env("KINTSUGI_CONFIG", config)
        .env(
            "KINTSUGI_VAULT",
            vault
                .map(|v| v.to_path_buf())
                .unwrap_or_else(|| sock.with_extension("absent-vault.json")),
        )
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if kintsugi_daemon::Client::is_daemon_running() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    daemon
}

#[test]
fn approve_flow_against_a_real_daemon() {
    let tmp = tempfile::tempdir().unwrap();
    let sock = tmp.path().join("a.sock");
    let db = tmp.path().join("e.db");
    let config = tmp.path().join("none.toml");
    // The test process shares the daemon's socket/db so it can seed a hold.
    std::env::set_var("KINTSUGI_SOCKET", &sock);
    std::env::set_var("KINTSUGI_DB", &db);
    std::env::set_var("KINTSUGI_CONFIG", &config);
    // Never the machine's real vault: this test drives the unprovisioned path.
    std::env::set_var("KINTSUGI_VAULT", tmp.path().join("absent-vault.json"));

    let mut daemon = start_daemon(&sock, &db, &config);
    // Seed a held command directly via the daemon client.
    let cmd = ProposedCommand::new("mcp", tmp.path(), vec!["rm".into(), "x".into()], "rm x");
    let id = cmd.id.to_string();
    assert_eq!(
        kintsugi_daemon::Client::send(&cmd).unwrap().decision,
        Decision::Hold
    );

    let common = |c: &mut Command| {
        c.env("KINTSUGI_SOCKET", &sock)
            .env("KINTSUGI_DB", &db)
            .env("KINTSUGI_VAULT", tmp.path().join("absent-vault.json"))
            .env("NO_COLOR", "1");
    };

    // `kintsugi approve <prefix>` completes the handshake (AuthBegin → locked
    // = false → bare) and resolves the queue item.
    let mut a = kintsugi();
    a.args(["approve", &id[..8]]);
    common(&mut a);
    let aout = a.output().unwrap();
    assert!(
        aout.status.success(),
        "approve failed: {}",
        String::from_utf8_lossy(&aout.stderr)
    );
    assert!(String::from_utf8_lossy(&aout.stdout).contains("approved"));
    assert_eq!(
        kintsugi_daemon::Client::pending_status(&id).unwrap(),
        "approved"
    );

    let _ = daemon.kill();
    let _ = daemon.wait();

    std::env::remove_var("KINTSUGI_VAULT");
    std::env::remove_var("KINTSUGI_DB");
    std::env::remove_var("KINTSUGI_SOCKET");
    std::env::remove_var("KINTSUGI_CONFIG");
}

/// The locked path: provision a vault, seed a hold, approve with the password
/// read from a file. This is the branch every provisioned user depends on and it
/// had no automated coverage at all — a wrong op string or a nonce-encoding slip
/// here would silently break approval for everyone who provisioned a vault.
#[test]
fn approve_flow_with_a_locked_vault_uses_the_password_file() {
    let tmp = tempfile::tempdir().unwrap();
    let sock = tmp.path().join("locked.sock");
    let db = tmp.path().join("locked.db");
    let config = tmp.path().join("none.toml");
    let vault = tmp.path().join("vault.json");
    let pw_file = tmp.path().join("pw");
    // Runtime-built, per the repo's credential-scanner convention.
    let pw = format!("locked-approve-pw-{}-kintsugi", std::process::id());
    std::fs::write(&pw_file, &pw).unwrap();

    // Provision through the CLI: this also records the `audit:provision` latch.
    let out = kintsugi()
        .args(["admin", "provision", "--password-file"])
        .arg(&pw_file)
        .env("KINTSUGI_DB", &db)
        .env("KINTSUGI_VAULT", &vault)
        .env("KINTSUGI_CONFIG", &config)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "provision failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    std::env::set_var("KINTSUGI_SOCKET", &sock);
    std::env::set_var("KINTSUGI_DB", &db);
    std::env::set_var("KINTSUGI_CONFIG", &config);
    std::env::set_var("KINTSUGI_VAULT", &vault);

    let mut daemon = start_daemon_with(&sock, &db, &config, Some(&vault));
    let cmd = ProposedCommand::new("mcp", tmp.path(), vec!["rm".into(), "x".into()], "rm x");
    let id = cmd.id.to_string();
    assert_eq!(
        kintsugi_daemon::Client::send(&cmd).unwrap().decision,
        Decision::Hold
    );

    // A bare approve is refused on a locked daemon…
    let bare = kintsugi().args(["approve", &id]).output().unwrap();
    assert!(
        !bare.status.success(),
        "a bare approve must fail on a locked daemon"
    );
    // On a locked daemon the CLI refuses before touching the wire: with no tty and
    // no --password-file it can only explain how to proceed. (The daemon-side
    // refusal for a *sent* bare approve is pinned in approval_auth.rs.)
    let stderr = String::from_utf8_lossy(&bare.stderr).to_string();
    assert!(
        stderr.contains("password-file") || stderr.contains("approval requires proof"),
        "the refusal must say what to do: {stderr}"
    );

    // …and the password-file path completes the real handshake.
    let ok = kintsugi()
        .args(["approve", &id, "--password-file"])
        .arg(&pw_file)
        .output()
        .unwrap();
    assert!(
        ok.status.success(),
        "locked approve failed: {}{}",
        String::from_utf8_lossy(&ok.stdout),
        String::from_utf8_lossy(&ok.stderr)
    );
    let status = kintsugi_daemon::Client::pending_status(&id).unwrap_or_default();
    assert_eq!(status, "approved");

    // A wrong password fails loudly and leaves the item pending.
    let cmd2 = ProposedCommand::new("mcp", tmp.path(), vec!["rm".into(), "y".into()], "rm y");
    let id2 = cmd2.id.to_string();
    assert_eq!(
        kintsugi_daemon::Client::send(&cmd2).unwrap().decision,
        Decision::Hold
    );
    let bad_pw = tmp.path().join("pw-bad");
    std::fs::write(&bad_pw, "definitely-not-the-password").unwrap();
    let bad = kintsugi()
        .args(["approve", &id2, "--password-file"])
        .arg(&bad_pw)
        .output()
        .unwrap();
    assert!(!bad.status.success(), "a wrong password must not approve");
    assert_eq!(
        kintsugi_daemon::Client::pending_status(&id2).unwrap_or_default(),
        "pending"
    );

    let _ = daemon.kill();
    let _ = daemon.wait();
}
