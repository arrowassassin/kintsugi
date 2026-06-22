//! Backend bindings — the in-process integration layer.
//!
//! Because this is a Dioxus *desktop* app, the UI runs in the same process as the
//! engine: these are plain function calls into `kintsugi-app` (read-only views)
//! and the daemon controls (on/off/panic). No `invoke`, no IPC round-trip — which
//! is exactly why clicks are instant here.
//!
//! Read views are derived from the daemon + the append-only log; they make no
//! decision and add no egress (the spine holds). The engine controls act on the
//! daemon process and the kill-switch flag the daemon already honors.

use std::path::PathBuf;

use kintsugi_app as app;
pub use app::{ChainVerify, EngineStatus, Metrics, ProvenanceView, QueueRow, TimelineRow};

fn db() -> PathBuf {
    kintsugi_daemon::default_db_path()
}

// ---- read-only views (cheap local reads; safe to call from a resource) -----

pub fn status() -> EngineStatus {
    app::status()
}
pub fn metrics() -> Metrics {
    app::metrics(&db()).unwrap_or_default()
}
/// Flip an oldest-first page into newest-first for display. `EventLog::query`
/// selects the newest N rows but re-sorts them ascending; every list in the UI
/// wants the freshest row at the top.
fn newest_first(mut rows: Vec<TimelineRow>) -> Vec<TimelineRow> {
    rows.reverse();
    rows
}
pub fn timeline(limit: usize) -> Vec<TimelineRow> {
    newest_first(app::timeline(&db(), limit).unwrap_or_default())
}
pub fn audit(query: &str, limit: usize) -> Vec<TimelineRow> {
    newest_first(app::audit(&db(), query, limit).unwrap_or_default())
}
pub fn queue() -> Vec<QueueRow> {
    let mut q = app::queue().unwrap_or_default();
    q.reverse();
    q
}
pub fn verify() -> Option<ChainVerify> {
    app::verify(&db()).ok()
}
pub fn provenance(session: &str, command: Option<&str>) -> Option<ProvenanceView> {
    app::provenance(session, command).ok()
}
pub fn resolve(id: &str, allow: bool) -> bool {
    app::resolve(id, allow).is_ok()
}

// ---- engine controls (the on / off / panic switches) -----------------------

/// Is the resident daemon up? Drives the status dot.
pub fn engine_running() -> bool {
    kintsugi_daemon::Client::is_daemon_running()
}

/// Is the panic kill-switch engaged? (The daemon halts everything while the flag
/// file exists — see `Daemon::kill_switch_engaged`.)
pub fn panic_engaged() -> bool {
    kintsugi_daemon::kill_switch_path().exists()
}

/// Engage (`on=true`) or clear the panic kill-switch by writing/removing its flag
/// — the same file the daemon reads, so it takes effect immediately and survives
/// a daemon restart.
pub fn set_panic(on: bool) -> std::io::Result<()> {
    let p = kintsugi_daemon::kill_switch_path();
    if on {
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&p, b"panic\n")
    } else if p.exists() {
        std::fs::remove_file(&p)
    } else {
        Ok(())
    }
}

/// Start the resident daemon (the "on" half of the single toggle): spawn it
/// detached, then wait up to ~3s for it to bind. Surfaces a clear error if the
/// binary can't be found or doesn't come up (no more silent no-op).
pub fn start_engine() -> anyhow::Result<()> {
    use kintsugi_daemon::Client;
    if Client::is_daemon_running() {
        return Ok(());
    }
    let exe = daemon_exe();
    std::process::Command::new(&exe)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| anyhow::anyhow!("couldn't start {}: {e}", exe.display()))?;
    for _ in 0..150 {
        if Client::is_daemon_running() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    anyhow::bail!("daemon started but didn't respond within 3s")
}

/// Whether stopping needs the admin password (a vault is provisioned). The toggle
/// checks this to decide whether to open the password prompt.
pub fn stop_needs_password() -> bool {
    vault_provisioned()
}

/// Stop the daemon (the "off" half). With no vault, stops directly; with a vault,
/// returns the sentinel error `"password-required"` so the UI can prompt.
pub fn stop_engine() -> anyhow::Result<()> {
    use kintsugi_daemon::Client;
    if !Client::is_daemon_running() {
        return Ok(());
    }
    let (locked, _nonce, _salt, _params) = Client::auth_begin("shutdown")?;
    if locked {
        anyhow::bail!("password-required");
    }
    Client::shutdown("shutdown", "", "").map_err(|e| anyhow::anyhow!("couldn't stop daemon: {e}"))
}

/// Stop with the admin password — runs the full challenge/proof handshake. The
/// password never leaves the machine; only an Ed25519 signature crosses the socket.
pub fn stop_engine_with_password(password: &str) -> anyhow::Result<()> {
    use kintsugi_daemon::Client;
    if !Client::is_daemon_running() {
        return Ok(());
    }
    let (locked, nonce, salt, params) = Client::auth_begin("shutdown")?;
    if !locked {
        return Client::shutdown("shutdown", "", "").map_err(|e| anyhow::anyhow!("{e}"));
    }
    let nonce_bytes = hex::decode(&nonce).map_err(|e| anyhow::anyhow!("bad nonce: {e}"))?;
    let proof = kintsugi_core::admin::compute_proof(password, &salt, params, &nonce_bytes, b"shutdown")
        .map_err(|e| anyhow::anyhow!("couldn't derive proof: {e:?}"))?;
    // Preserve the daemon's actual message. Only relabel the plain auth failure
    // as "wrong password" — lockout, degraded-vault, and "no auth key" messages
    // are distinct and actionable, and masking them sends the user down the
    // wrong recovery path (and silent retries extend the lockout backoff).
    Client::shutdown("shutdown", &nonce, &hex::encode(proof)).map_err(|e| {
        let msg = e.to_string();
        if msg.contains("authentication failed") {
            anyhow::anyhow!("wrong password")
        } else {
            anyhow::anyhow!("{msg}")
        }
    })
}

// ---- snapshots / undo (the Undo screen) ------------------------------------

/// One restore point: the command it guards and how many paths it covers.
#[derive(Clone, PartialEq)]
pub struct SnapshotRow {
    pub id: String,
    pub command: String,
    pub paths: usize,
}

fn snapshot_dir() -> PathBuf {
    db().with_file_name("snapshots")
}

/// Not-yet-reverted restore points, newest first.
pub fn snapshots() -> Vec<SnapshotRow> {
    let Ok(log) = kintsugi_core::EventLog::open(&db()) else {
        return Vec::new();
    };
    log.unreverted_snapshots()
        .unwrap_or_default()
        .into_iter()
        .map(|m| SnapshotRow {
            id: m.id,
            command: m.command,
            paths: m.entries.len(),
        })
        .collect()
}

/// Roll a restore point back (the Undo action): restore its files, then mark it
/// reverted so it leaves the list — mirrors `kintsugi undo`.
pub fn undo(id: &str) -> anyhow::Result<()> {
    let log = kintsugi_core::EventLog::open(&db())?;
    let manifest = log
        .unreverted_snapshots()?
        .into_iter()
        .find(|m| m.id == id)
        .ok_or_else(|| anyhow::anyhow!("no restore point {id}"))?;
    kintsugi_core::restore_snapshot(&snapshot_dir(), &manifest)?;
    log.mark_reverted(id)?;
    Ok(())
}

// ---- fail-closed posture (a Settings toggle that's a real config write) ----

pub fn fail_closed() -> bool {
    kintsugi_daemon::is_fail_closed_marked()
}
pub fn set_fail_closed(on: bool) -> std::io::Result<()> {
    kintsugi_daemon::set_fail_closed_marker(on)
}

/// Locate the `kintsugi-daemon` binary: a sibling of our own executable, else any
/// cargo `target/{debug,release}/` found by walking up from us (covers `cargo run`
/// from this detached crate, where the daemon lives in the main workspace target),
/// else the bare name on `PATH`.
fn daemon_exe() -> PathBuf {
    let name = if cfg!(windows) { "kintsugi-daemon.exe" } else { "kintsugi-daemon" };
    if let Ok(cur) = std::env::current_exe() {
        if let Some(dir) = cur.parent() {
            let sib = dir.join(name);
            if sib.exists() {
                return sib;
            }
        }
        let mut d: Option<&std::path::Path> = Some(cur.as_path());
        while let Some(p) = d {
            for prof in ["debug", "release"] {
                let c = p.join("target").join(prof).join(name);
                if c.exists() {
                    return c;
                }
            }
            d = p.parent();
        }
    }
    PathBuf::from(name)
}

// ---- master-password auth (real login + change-password in Settings) -------
// In-process verification against the argon2id vault — no daemon needed to
// unlock (the TUI does the same). The password never leaves the machine.

use kintsugi_core::admin::{self, VaultState};

/// Whether a master password has been set (an admin vault exists).
pub fn vault_provisioned() -> bool {
    matches!(
        admin::load_vault(&admin::default_vault_path()),
        VaultState::Locked(_)
    )
}

/// Verify a typed master password to unlock (in-process, argon2id ~100ms).
/// If no vault is provisioned yet, the first unlock is allowed (the UI then
/// offers to set a password). A corrupt/degraded vault fails closed.
pub fn verify_master_password(password: &str) -> bool {
    match admin::load_vault(&admin::default_vault_path()) {
        VaultState::Locked(v) => v.verify_password(password),
        VaultState::Unprovisioned => true,
        VaultState::Degraded(_) => false,
    }
}

/// Set the master password for the first time (no vault yet). Returns the one-time
/// recovery key to show the user once and never again.
pub fn set_master_password(password: &str) -> anyhow::Result<String> {
    if vault_provisioned() {
        anyhow::bail!("a master password is already set — change it instead");
    }
    let prov = admin::provision(password, &admin::LockedSettings::default())
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    admin::save_vault(&admin::default_vault_path(), &prov.vault).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(prov.recovery_key)
}

/// Change the master password (current must verify). Returns the NEW recovery key.
pub fn change_master_password(old: &str, new: &str) -> anyhow::Result<String> {
    match admin::load_vault(&admin::default_vault_path()) {
        VaultState::Locked(v) => {
            let prov = v.change_password(old, new).map_err(|e| match e {
                admin::AdminError::WrongPassword => anyhow::anyhow!("current password is wrong"),
                other => anyhow::anyhow!("{other}"),
            })?;
            admin::save_vault(&admin::default_vault_path(), &prov.vault)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            Ok(prov.recovery_key)
        }
        VaultState::Unprovisioned => set_master_password(new),
        VaultState::Degraded(_) => anyhow::bail!("admin vault is unreadable"),
    }
}

/// Remove the master password entirely (verify current, then delete the sealed
/// vault). After this, stopping/loosening Kintsugi no longer needs a password.
pub fn remove_master_password(current: &str) -> anyhow::Result<()> {
    match admin::load_vault(&admin::default_vault_path()) {
        VaultState::Locked(v) => {
            if !v.verify_password(current) {
                anyhow::bail!("current password is wrong");
            }
            std::fs::remove_file(admin::default_vault_path())
                .map_err(|e| anyhow::anyhow!("couldn't remove the vault: {e}"))
        }
        VaultState::Unprovisioned => anyhow::bail!("no master password is set"),
        VaultState::Degraded(_) => anyhow::bail!("admin vault is unreadable"),
    }
}

// ---- sectioned reads (mirror the TUI; keep fs-watch out of the main feed) ----

/// Agent commands only — the main Activity feed, fs-watch excluded.
pub fn commands(limit: usize) -> Vec<TimelineRow> {
    newest_first(app::timeline_excluding(&db(), "fs-watch", limit).unwrap_or_default())
}
/// The filesystem-watcher backstop (its own quiet section).
pub fn file_changes(limit: usize) -> Vec<TimelineRow> {
    newest_first(app::timeline_for_agent(&db(), "fs-watch", limit).unwrap_or_default())
}
/// The human shell-session recorder.
pub fn shell_log(limit: usize) -> Vec<TimelineRow> {
    newest_first(app::timeline_for_agent(&db(), "shell", limit).unwrap_or_default())
}
/// History as the ENFORCEMENT record: only the commands Kintsugi actually acted
/// on — held or blocked. This is the distinction from Activity (the full live
/// feed): History answers "what did Kintsugi catch?", not "what happened?".
pub fn history(limit: usize) -> Vec<TimelineRow> {
    let mut rows = app::timeline_excluding(&db(), "fs-watch", 800).unwrap_or_default();
    rows.retain(|r| r.outcome == "held" || r.outcome == "denied");
    rows.reverse(); // newest-first
    rows.truncate(limit); // keep the freshest `limit`, not the oldest
    rows
}

// ---- local model (Settings: show installed model + scorer summary) ----------

/// The installed model's filename, if one is configured.
pub fn installed_model() -> Option<String> {
    kintsugi_model::config::configured_model()
        .and_then(|p| p.file_name().map(|f| f.to_string_lossy().to_string()))
}
/// A plain-language summary of the active scorer (the "model summary").
pub fn scorer_summary() -> String {
    match kintsugi_daemon::Client::status_scorer() {
        Ok(name) if name.starts_with("llama:") => {
            format!("Local model · {}", name.trim_start_matches("llama:"))
        }
        Ok(_) => "Heuristic scorer · runs offline (no local model)".to_string(),
        Err(_) => "Engine offline".to_string(),
    }
}
/// Point Kintsugi at a chosen `.gguf` (persist the selection).
pub fn set_model(path: &str) -> anyhow::Result<()> {
    kintsugi_model::config::set_configured_model(std::path::Path::new(path))
        .map_err(|e| anyhow::anyhow!("{e}"))
}
pub fn clear_model() -> anyhow::Result<()> {
    kintsugi_model::config::clear_configured_model().map_err(|e| anyhow::anyhow!("{e}"))
}

/// Delete a downloaded `.gguf` from disk. If it's the active selection, drop back
/// to the heuristic first so the daemon doesn't point at a missing file.
pub fn delete_model_file(path: &str) -> anyhow::Result<()> {
    let is_active = kintsugi_model::config::configured_model()
        .map(|p| p.to_string_lossy() == path)
        .unwrap_or(false);
    if is_active {
        let _ = clear_model();
    }
    std::fs::remove_file(path).map_err(|e| anyhow::anyhow!("couldn't delete model: {e}"))
}

/// Is a real GGUF actually loaded by the daemon right now (vs the heuristic)?
/// This is the source of truth — a configured model is NOT necessarily loaded
/// (the daemon needs the `llama` build + a restart to pick it up).
pub fn model_loaded() -> bool {
    matches!(kintsugi_daemon::Client::status_scorer(), Ok(n) if n.starts_with("llama:"))
}

/// One downloaded model file found on disk.
#[derive(Clone, PartialEq)]
pub struct LocalModel {
    pub name: String,
    pub path: String,
    pub size: String,
    pub active: bool,
}

/// Where weights may live: the parent of the configured model, plus the default
/// dir `pick-model.sh` uses (`$KINTSUGI_MODEL_DIR` or `~/.local/share/kintsugi/models`).
fn model_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(p) = kintsugi_model::config::configured_model().and_then(|p| p.parent().map(|x| x.to_path_buf())) {
        dirs.push(p);
    }
    if let Ok(d) = std::env::var("KINTSUGI_MODEL_DIR") {
        dirs.push(PathBuf::from(d));
    } else if let Some(home) = std::env::var_os("HOME") {
        dirs.push(PathBuf::from(home).join(".local/share/kintsugi/models"));
    }
    dirs.sort();
    dirs.dedup();
    dirs
}

fn human_size(bytes: u64) -> String {
    let gb = bytes as f64 / 1e9;
    if gb >= 1.0 { format!("{gb:.1} GB") } else { format!("{:.0} MB", bytes as f64 / 1e6) }
}

/// Scan disk for the user's real downloaded `.gguf` models (no mock catalog).
pub fn available_models() -> Vec<LocalModel> {
    let active = kintsugi_model::config::configured_model().map(|p| p.to_string_lossy().to_string());
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<LocalModel> = Vec::new();
    for dir in model_dirs() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for e in entries.flatten() {
            let path = e.path();
            if path.extension().and_then(|x| x.to_str()) != Some("gguf") {
                continue;
            }
            let ps = path.to_string_lossy().to_string();
            if !seen.insert(ps.clone()) {
                continue;
            }
            out.push(LocalModel {
                name: path.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default(),
                size: e.metadata().ok().map(|m| human_size(m.len())).unwrap_or_default(),
                active: active.as_deref() == Some(ps.as_str()),
                path: ps,
            });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

// ---- Hugging Face live search + GGUF download -------------------------------

/// A model repo from the Hugging Face search API.
#[derive(Clone, PartialEq, serde::Deserialize)]
pub struct HfModel {
    pub id: String,
    #[serde(default)]
    pub downloads: u64,
    #[serde(default)]
    pub likes: u64,
}

fn hf_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent("kintsugi-control-room")
        .build()
        .unwrap_or_default()
}

fn hf_query(search: &str, limit: usize) -> anyhow::Result<Vec<HfModel>> {
    let limit = limit.to_string();
    let models: Vec<HfModel> = hf_client()
        .get("https://huggingface.co/api/models")
        .query(&[
            ("search", search),
            ("filter", "gguf"),
            ("sort", "downloads"),
            ("direction", "-1"),
            ("limit", &limit),
        ])
        .send()?
        .error_for_status()?
        .json()?;
    Ok(models)
}

/// Live search Hugging Face for GGUF models. Empty query → the suggested set.
pub fn hf_search(query: &str) -> Vec<HfModel> {
    if query.trim().is_empty() {
        return hf_suggested();
    }
    hf_query(query.trim(), 12).unwrap_or_default()
}

/// A short, RAM-appropriate suggested list (small instruct GGUFs), shown by
/// default — same spirit as `pick-model.sh`'s curated picks.
pub fn hf_suggested() -> Vec<HfModel> {
    hf_query("Qwen3 4B Instruct GGUF", 5).unwrap_or_default()
}

/// Resolve a downloadable Q4_K_M `.gguf` in a repo (prefer Q4_K_M, else any gguf).
fn hf_pick_gguf(id: &str) -> anyhow::Result<(String, String)> {
    let v: serde_json::Value = hf_client()
        .get(format!("https://huggingface.co/api/models/{id}"))
        .send()?
        .error_for_status()?
        .json()?;
    let files: Vec<String> = v["siblings"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|s| s["rfilename"].as_str().map(|x| x.to_string()))
                .filter(|f| f.to_lowercase().ends_with(".gguf"))
                .collect()
        })
        .unwrap_or_default();
    let pick = files
        .iter()
        .find(|f| f.to_lowercase().contains("q4_k_m"))
        .or_else(|| files.first())
        .ok_or_else(|| anyhow::anyhow!("no .gguf file found in {id}"))?;
    let url = format!("https://huggingface.co/{id}/resolve/main/{pick}?download=true");
    Ok((url, pick.clone()))
}

fn models_download_dir() -> PathBuf {
    if let Ok(d) = std::env::var("KINTSUGI_MODEL_DIR") {
        return PathBuf::from(d);
    }
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    home.join(".local/share/kintsugi/models")
}

/// Download the chosen repo's GGUF into the models dir (blocking; call from a
/// background task). Streams to a `.part` file, then renames on success. Returns
/// the saved filename.
pub fn download_model(id: &str) -> anyhow::Result<String> {
    let (url, filename) = hf_pick_gguf(id)?;
    let dir = models_download_dir();
    std::fs::create_dir_all(&dir)?;
    let dest = dir.join(&filename);
    let part = dir.join(format!("{filename}.part"));
    let mut resp = hf_client().get(&url).send()?.error_for_status()?;
    let mut file = std::fs::File::create(&part)?;
    resp.copy_to(&mut file)?;
    std::fs::rename(&part, &dest)?;
    Ok(filename)
}

/// Restart the daemon (stop + start) so a model selection takes effect. Uses the
/// session password for the authenticated shutdown.
pub fn restart_engine_with_password(password: &str) -> anyhow::Result<()> {
    if kintsugi_daemon::Client::is_daemon_running() {
        stop_engine_with_password(password)?;
        for _ in 0..120 {
            if !kintsugi_daemon::Client::is_daemon_running() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
    start_engine()
}

// ---- policy / rules (the Rules screen) -------------------------------------

#[derive(Clone, PartialEq)]
pub struct PolicyView {
    pub mode: String,
    pub threshold: u8,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub provenance_enabled: bool,
}

/// The effective merged policy (global ← repo) for the current directory.
pub fn policy_view() -> PolicyView {
    let cwd = std::env::current_dir().unwrap_or_default();
    let p = kintsugi_daemon::load_policy(&cwd);
    PolicyView {
        mode: p.mode.map(|m| m.as_str().to_string()).unwrap_or_else(|| "attended".to_string()),
        threshold: p.risk_threshold(),
        allow: p.rules.allow.clone(),
        deny: p.rules.deny.clone(),
        provenance_enabled: p.provenance_enabled(),
    }
}

/// The built-in deterministic protections — always on, the heart of the gate.
pub fn builtin_protections() -> Vec<(&'static str, &'static str)> {
    vec![
        ("Recursive delete", "rm -rf / rmdir on home or root"),
        ("Force-push & history rewrite", "git push --force, reset --hard, filter-branch"),
        ("Secret reads", ".env, ~/.ssh, ~/.aws, keychains"),
        ("Destructive SQL", "DROP TABLE, DELETE FROM, TRUNCATE"),
        ("Pipe-to-shell", "curl | sh, wget | bash"),
        ("Disk & device writes", "dd of=, mkfs, writes to /dev/*"),
        ("Infrastructure teardown", "terraform destroy, kubectl delete, docker prune"),
        ("Lethal trifecta", "untrusted content + secret read + egress → blocked"),
        ("Self-protection", "uninstalling or deleting Kintsugi itself"),
    ]
}
