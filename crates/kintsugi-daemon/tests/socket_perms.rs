//! Security: the IPC socket is owner-only (0600) so another local user cannot
//! connect and Approve/Deny/Resolve.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;

use kintsugi_daemon::ipc::Server;

#[test]
fn socket_is_owner_only() {
    let tmp = tempfile::tempdir().unwrap();
    let sock = tmp.path().join("kintsugi.sock");
    std::env::set_var("KINTSUGI_SOCKET", &sock);

    let _server = Server::bind().expect("bind socket");
    let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
    std::env::remove_var("KINTSUGI_SOCKET");

    assert_eq!(
        mode, 0o600,
        "socket must be rw for owner only, got {mode:o}"
    );
}
