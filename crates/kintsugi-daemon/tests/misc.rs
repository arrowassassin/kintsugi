//! Small surface tests for daemon accessors, paths, and IPC serde.

use std::sync::{Mutex, MutexGuard, OnceLock};

use kintsugi_daemon::ipc::{Observation, Request, Resolution, Response};
use kintsugi_daemon::Daemon;

fn serial_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

#[test]
fn accessors_report_defaults() {
    let _g = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("KINTSUGI_CONFIG", tmp.path().join("none.toml"));
    let d = Daemon::open(tmp.path().join("e.db")).unwrap();
    assert_eq!(d.scorer_name(), "heuristic");
    assert_eq!(d.mode(), kintsugi_core::Mode::Attended);
    assert!(d.snapshot_dir().ends_with("snapshots"));
    assert!(!d.kill_switch_engaged());
}

#[test]
fn kill_switch_path_is_beside_the_db() {
    let _g = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("KINTSUGI_DB", tmp.path().join("events.db"));
    let p = kintsugi_daemon::kill_switch_path();
    assert_eq!(p, tmp.path().join(kintsugi_daemon::KILL_SWITCH_FILE));
    std::env::remove_var("KINTSUGI_DB");
}

#[test]
fn ipc_messages_roundtrip_through_json() {
    let obs = Request::Observe(Observation {
        kind: "created".into(),
        path: "/x/y".into(),
    });
    let s = serde_json::to_string(&obs).unwrap();
    assert!(matches!(
        serde_json::from_str::<Request>(&s).unwrap(),
        Request::Observe(_)
    ));

    let res = Request::Resolve(Resolution {
        command: kintsugi_core::ProposedCommand::new("t", "/tmp", vec!["ls".into()], "ls"),
        decision: kintsugi_core::Decision::Allow,
        remember: true,
    });
    let s = serde_json::to_string(&res).unwrap();
    assert!(matches!(
        serde_json::from_str::<Request>(&s).unwrap(),
        Request::Resolve(_)
    ));

    let resp = Response::Error {
        message: "boom".into(),
    };
    let s = serde_json::to_string(&resp).unwrap();
    assert!(matches!(
        serde_json::from_str::<Response>(&s).unwrap(),
        Response::Error { .. }
    ));
}

#[test]
fn load_policy_defaults_when_absent() {
    let _g = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("KINTSUGI_CONFIG", tmp.path().join("none.toml"));
    let p = kintsugi_daemon::load_policy(tmp.path());
    assert_eq!(p.risk_threshold(), kintsugi_core::policy::DEFAULT_THRESHOLD);
    assert!(p.mode.is_none());
}
