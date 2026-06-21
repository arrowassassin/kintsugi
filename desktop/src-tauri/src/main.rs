//! Kintsugi Control Room — Tauri shell.
//!
//! The app is a **dashboard, not a gate** (`kintsugi-interaction-design.md`): it
//! reads what the daemon and the append-only event log already decided and shows
//! it. Every command here is a thin wrapper over [`kintsugi_app`], the tested
//! data-binding engine — no decision logic lives in the webview process. The
//! frontend (`../ui`) binds these over `window.__TAURI__.core.invoke`.

// Hide the console window on Windows release builds.
#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use kintsugi_app::{ChainVerify, EngineStatus, Metrics, ProvenanceView, QueueRow, TimelineRow};

fn db() -> std::path::PathBuf {
    kintsugi_daemon::default_db_path()
}

/// The audit timeline (read-only event log), newest `limit` rows.
#[tauri::command]
fn timeline(limit: usize) -> Result<Vec<TimelineRow>, String> {
    kintsugi_app::timeline(&db(), limit).map_err(|e| e.to_string())
}

/// Audit-log search by command substring.
#[tauri::command]
fn audit(query: String, limit: usize) -> Result<Vec<TimelineRow>, String> {
    kintsugi_app::audit(&db(), &query, limit).map_err(|e| e.to_string())
}

/// Dashboard metric counts.
#[tauri::command]
fn metrics() -> Result<Metrics, String> {
    kintsugi_app::metrics(&db()).map_err(|e| e.to_string())
}

/// Tamper-evidence status of the append-only log.
#[tauri::command]
fn verify() -> Result<ChainVerify, String> {
    kintsugi_app::verify(&db()).map_err(|e| e.to_string())
}

/// The live approval queue (held commands), over IPC.
#[tauri::command]
fn queue() -> Result<Vec<QueueRow>, String> {
    kintsugi_app::queue().map_err(|e| e.to_string())
}

/// The provenance trail for a session (optionally evaluating a command's legs).
#[tauri::command]
fn provenance(session: String, command: Option<String>) -> Result<ProvenanceView, String> {
    kintsugi_app::provenance(&session, command.as_deref()).map_err(|e| e.to_string())
}

/// Resolve a held command from the dashboard (the rare in-app decision). Returns
/// `true` on success (a bool round-trips through `invoke` more cleanly than unit).
#[tauri::command]
fn resolve(id: String, allow: bool) -> Result<bool, String> {
    kintsugi_app::resolve(&id, allow)
        .map(|()| true)
        .map_err(|e| e.to_string())
}

/// Engine status for the window chrome.
#[tauri::command]
fn status() -> EngineStatus {
    kintsugi_app::status()
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            timeline, audit, metrics, verify, queue, provenance, resolve, status
        ])
        .run(tauri::generate_context!())
        .expect("error while running the Kintsugi Control Room");
}
