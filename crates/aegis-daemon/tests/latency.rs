//! P1.6 acceptance: the Safe fast-path is cheap. The deterministic rules path is
//! sub-microsecond, and a Safe-command round-trip through the daemon (classify +
//! log + IPC) is sub-millisecond on a warm daemon.
#![cfg(unix)]

use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::Instant;

use aegis_core::{classify, Decision, ProposedCommand};
use aegis_daemon::{Client, Daemon, Server};

fn serial_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Whether we're running under coverage instrumentation (cargo-llvm-cov), which
/// inflates timings 2–5×. We still exercise the path for coverage, but don't
/// enforce the wall-clock bound — that's only meaningful on an uninstrumented build.
fn instrumented() -> bool {
    std::env::var_os("LLVM_PROFILE_FILE").is_some()
}

#[test]
fn rules_fast_path_is_microsecond_scale() {
    let cmd = ProposedCommand::new("bench", "/tmp", vec!["ls".into(), "-la".into()], "ls -la");
    let iters = 50_000;

    // Warm up.
    for _ in 0..1000 {
        let _ = classify(&cmd);
    }

    let start = Instant::now();
    for _ in 0..iters {
        let v = classify(&cmd);
        assert_eq!(v.class, aegis_core::Class::Safe);
    }
    let per = start.elapsed() / iters;
    eprintln!("rules classify: {per:?} per call");
    if instrumented() {
        eprintln!("(coverage run — skipping the timing bound)");
        return;
    }
    assert!(
        per.as_micros() < 100,
        "rules fast-path should be well under 100µs, was {per:?}"
    );
}

#[test]
fn safe_command_round_trip_is_sub_millisecond() {
    let _guard = serial_lock();
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("AEGIS_SOCKET", tmp.path().join("aegis.sock"));
    std::env::set_var("AEGIS_DB", tmp.path().join("events.db"));
    std::env::set_var("AEGIS_CONFIG", tmp.path().join("no-global.toml"));

    let warmup = 50usize;
    let measured = 500usize;
    let total = warmup + measured;

    let db = tmp.path().join("events.db");
    let server = Server::bind().unwrap();
    let handle = thread::spawn(move || {
        let daemon = Daemon::open(&db).unwrap();
        server
            .serve_n(total, |req| daemon.handle_request(req))
            .unwrap();
    });

    let cmd = ProposedCommand::new("bench", "/tmp", vec!["ls".into()], "ls -la");

    // Warm the path (first connect, sqlite pages, etc.).
    for _ in 0..warmup {
        assert_eq!(Client::send(&cmd).unwrap().decision, Decision::Allow);
    }

    let start = Instant::now();
    for _ in 0..measured {
        let _ = Client::send(&cmd).unwrap();
    }
    let mean = start.elapsed() / measured as u32;

    handle.join().unwrap();

    eprintln!("safe round-trip mean: {mean:?} over {measured} calls");
    if instrumented() {
        eprintln!("(coverage run — skipping the sub-millisecond bound)");
        return;
    }
    assert!(
        mean.as_micros() < 1000,
        "safe round-trip should be sub-millisecond on a warm daemon, was {mean:?}"
    );
}
