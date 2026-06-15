//! End-to-end: `aegis queue` / `aegis approve` against a running daemon.
//!
//! In its own test binary so its process-global env (the shared socket/db) can't
//! contaminate the parallel tests in `cli.rs`.
#![cfg(unix)]

use std::process::Command;

use aegis_core::{Decision, ProposedCommand};

fn aegis() -> Command {
    Command::new(env!("CARGO_BIN_EXE_aegis"))
}

#[test]
fn queue_and_approve_with_running_daemon() {
    let tmp = tempfile::tempdir().unwrap();
    let sock = tmp.path().join("a.sock");
    let db = tmp.path().join("e.db");
    let config = tmp.path().join("none.toml");
    // The test process shares the daemon's socket/db so it can seed a held command.
    std::env::set_var("AEGIS_SOCKET", &sock);
    std::env::set_var("AEGIS_DB", &db);
    std::env::set_var("AEGIS_CONFIG", &config);

    // Start the real daemon binary (sibling of the `aegis` test binary).
    let daemon_bin =
        std::path::Path::new(env!("CARGO_BIN_EXE_aegis")).with_file_name("aegis-daemon");
    let mut daemon = Command::new(&daemon_bin)
        .env("AEGIS_SOCKET", &sock)
        .env("AEGIS_DB", &db)
        .env("AEGIS_CONFIG", &config)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if aegis_daemon::Client::is_daemon_running() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    // Seed a held command directly via the daemon client.
    let cmd = ProposedCommand::new("mcp", tmp.path(), vec!["rm".into(), "x".into()], "rm x");
    let id = cmd.id.to_string();
    assert_eq!(
        aegis_daemon::Client::send(&cmd).unwrap().decision,
        Decision::Hold
    );

    let common = |c: &mut Command| {
        c.env("AEGIS_SOCKET", &sock)
            .env("AEGIS_DB", &db)
            .env("NO_COLOR", "1");
    };

    // `aegis queue` lists it.
    let mut q = aegis();
    q.arg("queue");
    common(&mut q);
    let qout = q.output().unwrap();
    assert!(String::from_utf8_lossy(&qout.stdout).contains("rm x"));

    // `aegis approve <prefix>` resolves it; the agent may now proceed.
    let mut a = aegis();
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
        aegis_daemon::Client::pending_status(&id).unwrap(),
        "approved"
    );

    let _ = daemon.kill();
    let _ = daemon.wait();
}
