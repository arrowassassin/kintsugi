//! The approval queue over the real socket: list, deny, and status via `Client`.
#![cfg(unix)]

use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::Duration;

use kintsugi_core::ProposedCommand;
use kintsugi_daemon::{Client, Daemon, Server};

fn serial_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

#[test]
fn list_status_and_deny_over_socket() {
    let _g = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("KINTSUGI_SOCKET", tmp.path().join("a.sock"));
    std::env::set_var("KINTSUGI_DB", tmp.path().join("e.db"));
    std::env::set_var("KINTSUGI_CONFIG", tmp.path().join("none.toml"));
    let db = tmp.path().join("e.db");

    let server = Server::bind().unwrap();
    thread::spawn(move || {
        let daemon = Daemon::open(&db).unwrap();
        server.serve(|req| daemon.handle_request(req)).unwrap();
    });
    // Give the listener a moment.
    thread::sleep(Duration::from_millis(50));

    // Propose an ambiguous command → held → enqueued.
    let cmd = ProposedCommand::new("mcp", tmp.path(), vec!["rm".into(), "x".into()], "rm x");
    let id = cmd.id.to_string();
    assert_eq!(
        Client::send(&cmd).unwrap().decision,
        kintsugi_core::Decision::Hold
    );

    let items = Client::list_pending().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].command.id.to_string(), id);
    assert_eq!(Client::pending_status(&id).unwrap(), "pending");

    // Deny over the socket → status flips, queue empties.
    Client::deny(&id).unwrap();
    assert_eq!(Client::pending_status(&id).unwrap(), "denied");
    assert!(Client::list_pending().unwrap().is_empty());

    // Unknown id reports "gone"; approving it errors.
    assert_eq!(Client::pending_status("nope").unwrap(), "gone");
    assert!(Client::approve("nope").is_err());
}
