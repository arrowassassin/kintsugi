//! `kintsugi record` / `ingest` / `report` CLI integration tests.

use std::process::Command;

fn kintsugi() -> Command {
    Command::new(env!("CARGO_BIN_EXE_kintsugi"))
}

/// Point the binary at an isolated db + a dead socket so the daemon is "down".
fn isolated(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let db = dir.join("events.db");
    let sock = dir.join("nobody.sock");
    (db, sock)
}

#[test]
fn ingest_spools_when_daemon_is_down() {
    let tmp = tempfile::tempdir().unwrap();
    let (db, sock) = isolated(tmp.path());

    let out = kintsugi()
        .args(["ingest", "--cwd", "/srv", "--", "rm -rf /srv/data"])
        .env("KINTSUGI_DB", &db)
        .env("KINTSUGI_SOCKET", &sock)
        .output()
        .unwrap();
    assert!(out.status.success(), "ingest must never fail the shell");

    // The command lands in the spool next to the db, with its raw text intact.
    let spool = db.with_file_name("record-spool.jsonl");
    let body = std::fs::read_to_string(&spool).unwrap();
    assert!(body.contains("rm -rf /srv/data"), "spooled: {body}");

    // `record status` reports the daemon down and a non-empty spool.
    let st = kintsugi()
        .args(["record", "status"])
        .env("KINTSUGI_DB", &db)
        .env("KINTSUGI_SOCKET", &sock)
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&st.stdout);
    assert!(s.contains("DOWN"), "status: {s}");
    assert!(s.contains("1 command"), "status: {s}");
}

#[test]
fn spooled_command_never_contains_a_secret() {
    // With the daemon down, a credential command must be redacted BEFORE it is
    // written to the on-disk spool (no cleartext secret at rest).
    let tmp = tempfile::tempdir().unwrap();
    let (db, sock) = isolated(tmp.path());
    let out = kintsugi()
        .args([
            "ingest",
            "--cwd",
            "/srv",
            "--",
            "mysql -ps3cr3tPa55 -u root",
        ])
        .env("KINTSUGI_DB", &db)
        .env("KINTSUGI_SOCKET", &sock)
        .output()
        .unwrap();
    assert!(out.status.success());
    let body = std::fs::read_to_string(db.with_file_name("record-spool.jsonl")).unwrap();
    assert!(
        !body.contains("s3cr3tPa55"),
        "secret leaked to spool: {body}"
    );
    assert!(
        body.contains("[redacted]"),
        "expected a redaction marker: {body}"
    );
}

#[test]
fn empty_ingest_is_a_noop() {
    let tmp = tempfile::tempdir().unwrap();
    let (db, sock) = isolated(tmp.path());
    let out = kintsugi()
        .args(["ingest", "--cwd", "/srv", "--", "   "])
        .env("KINTSUGI_DB", &db)
        .env("KINTSUGI_SOCKET", &sock)
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(
        !db.with_file_name("record-spool.jsonl").exists(),
        "a blank command must not create a spool"
    );
}

#[test]
fn record_install_prints_a_sourceable_hook() {
    let out = kintsugi().args(["record", "install"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    // The hook must be valid for both shells and call ingest.
    assert!(s.contains("kintsugi session recorder"));
    assert!(s.contains("kintsugi ingest"));
    assert!(s.contains("ZSH_VERSION"));
    assert!(s.contains("BASH_VERSION"));
    assert!(s.contains("preexec"));
}

#[test]
fn report_on_empty_log_is_clean() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("events.db");
    let out = kintsugi()
        .args(["report"])
        .env("KINTSUGI_DB", &db)
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("nothing to report"));
}
