//! End-to-end: `kintsugi approve` against a running daemon (Phase 7, T2.2).
//!
//! In its own test binary so its process-global env (the shared socket/db)
//! can't contaminate the parallel tests in `cli.rs` / `cli_queue.rs`.
//!
//! Convention (see `cli.rs`): the vault resolver is pointed at an absent file
//! so the test stays on the unprovisioned path and never touches the machine's
//! real vault or a tty. The vault-locked path (AuthBegin → password prompt →
//! proof) is exercised daemon-side in `kintsugi-daemon/tests/approval_auth.rs`
//! and verified interactively — the password prompt reads `/dev/tty`, which a
//! test harness must not drive.
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
    let daemon_bin =
        std::path::Path::new(env!("CARGO_BIN_EXE_kintsugi")).with_file_name("kintsugi-daemon");
    let daemon = Command::new(&daemon_bin)
        .env("KINTSUGI_SOCKET", sock)
        .env("KINTSUGI_DB", db)
        .env("KINTSUGI_CONFIG", config)
        .env("KINTSUGI_VAULT", sock.with_extension("absent-vault.json"))
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
