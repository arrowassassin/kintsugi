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

pub use app::{ChainVerify, EngineStatus, Metrics, ProvenanceView, QueueRow, TimelineRow};
use kintsugi_app as app;

/// The desktop's marker for "first-run setup wizard already shown". Lives next
/// to the event log so it survives daemon restarts and travels with the data dir.
fn setup_marker() -> PathBuf {
    kintsugi_daemon::default_db_path().with_file_name("desktop-setup-done")
}

/// Has the user already completed (or skipped) the first-run setup wizard?
pub fn setup_done() -> bool {
    setup_marker().exists()
}

/// Mark the first-run setup as complete so the wizard never reappears unless
/// the user clears the marker.
pub fn mark_setup_done() -> anyhow::Result<()> {
    let p = setup_marker();
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&p, b"ok\n").map_err(|e| anyhow::anyhow!("{e}"))
}

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
    let mut q = app::queue(&db()).unwrap_or_default();
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

/// Approve a held command **and run it from the app** — the GUI equivalent of
/// `kintsugi run <id>`.
///
/// For an *out-of-band* hold (a one-shot agent hook like claude-code already got
/// the deny and left, so nothing is waiting to execute it), the human runs it
/// here: the daemon's `approve` snapshots the predicted paths first (so
/// `kintsugi undo` can roll it back) and records the Allow, then we execute the
/// raw command in its original directory. For an *in-band* hold (mcp/shim) a
/// caller is parked waiting, so we only approve and let that caller run it —
/// running here too would double-run it.
///
/// Safe by construction: this lives in the GUI binary and is reachable only by a
/// human clicking in the unlocked app — never over the daemon socket — so an agent
/// shelling out cannot self-approve-and-run. That process isolation, plus the
/// two-step confirm in the UI, is the GUI's equivalent of the CLI's typed-at-the-
/// terminal code gate.
pub fn approve_and_run(id: &str) -> anyhow::Result<String> {
    use kintsugi_daemon::Client;
    let item = Client::list_pending()?
        .into_iter()
        .find(|i| i.command.id.to_string() == id)
        .ok_or_else(|| anyhow::anyhow!("that command is no longer held"))?;
    // mcp/shim: a caller is waiting to run it on approval; just approve.
    let in_band = matches!(item.command.agent.as_str(), "mcp" | "shim");
    // approve: snapshots the predicted paths, records the Allow, marks resolved.
    Client::approve(id).map_err(|e| anyhow::anyhow!("approve failed: {e}"))?;
    if in_band {
        return Ok("Approved — the waiting agent will run it.".to_string());
    }
    let status = run_in_shell(&item.command.cwd, &item.command.raw)?;
    Ok(match status.code() {
        Some(0) => "Ran it. `kintsugi undo` can roll back the snapshot.".to_string(),
        Some(code) => format!("Ran it — the command exited with code {code}."),
        None => "Ran it (terminated by a signal).".to_string(),
    })
}

/// Execute a raw command line in `cwd` via the platform shell, inheriting stdio.
/// Mirrors the CLI's `run_in_shell` so chaining/redirects behave identically.
fn run_in_shell(cwd: &std::path::Path, raw: &str) -> anyhow::Result<std::process::ExitStatus> {
    let mut cmd = if cfg!(windows) {
        let mut c = std::process::Command::new("cmd");
        c.arg("/C").arg(raw);
        c
    } else {
        let mut c = std::process::Command::new("sh");
        c.arg("-c").arg(raw);
        c
    };
    cmd.current_dir(cwd);
    cmd.status()
        .map_err(|e| anyhow::anyhow!("run `{raw}`: {e}"))
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
    Client::shutdown("shutdown", None, None)
        .map_err(|e| anyhow::anyhow!("couldn't stop daemon: {e}"))
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
        return Client::shutdown("shutdown", None, None).map_err(|e| anyhow::anyhow!("{e}"));
    }
    let nonce_bytes = hex::decode(&nonce).map_err(|e| anyhow::anyhow!("bad nonce: {e}"))?;
    let proof =
        kintsugi_core::admin::compute_proof(password, &salt, params, &nonce_bytes, b"shutdown")
            .map_err(|e| anyhow::anyhow!("couldn't derive proof: {e:?}"))?;
    // Preserve the daemon's actual message. Only relabel the plain auth failure
    // as "wrong password" — lockout, degraded-vault, and "no auth key" messages
    // are distinct and actionable, and masking them sends the user down the
    // wrong recovery path (and silent retries extend the lockout backoff).
    Client::shutdown("shutdown", Some(&nonce), Some(&hex::encode(proof))).map_err(|e| {
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
    let name = if cfg!(windows) {
        "kintsugi-daemon.exe"
    } else {
        "kintsugi-daemon"
    };

    // Prefer the INSTALLED daemon (what `kintsugi init` puts on PATH / ~/.local/bin).
    // It's the user's real, model-capable build; a plain `cargo build` in the repo
    // overwrites target/debug with a heuristic daemon (the `llama` feature is
    // opt-in), so the dev-target walk-up is only a last resort.
    if let Some(home) = std::env::var_os("HOME") {
        for sub in [".local/bin", "bin"] {
            let c = PathBuf::from(&home).join(sub).join(name);
            if c.exists() {
                return c;
            }
        }
    }
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let c = dir.join(name);
            if c.exists() {
                return c;
            }
        }
    }

    // Dev fallback: a sibling of the app binary, then the repo target dir.
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
    admin::save_vault(&admin::default_vault_path(), &prov.vault)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
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
/// Newest catastrophic-class commands, fs-watch excluded — a class-targeted query
/// so the (usually small) catastrophic set is never windowed out by a flood of
/// ambiguous holds. Backs the Activity "Catastrophic" filter and the History merge.
pub fn catastrophic(limit: usize) -> Vec<TimelineRow> {
    newest_first(
        app::timeline_by_class(&db(), kintsugi_core::Class::Catastrophic, limit)
            .unwrap_or_default(),
    )
}

/// History as the ENFORCEMENT record: only the commands Kintsugi actually acted
/// on — held or blocked. This is the distinction from Activity (the full live
/// feed): History answers "what did Kintsugi catch?", not "what happened?".
pub fn history(limit: usize) -> Vec<TimelineRow> {
    let mut rows = app::timeline_excluding(&db(), "fs-watch", 800).unwrap_or_default();
    rows.retain(|r| r.outcome == "held" || r.outcome == "denied");
    // Always fold in catastrophic-class events even if they fell outside the 800
    // window (e.g. buried under hundreds of ambiguous holds) — they're the whole
    // point of an enforcement record. Dedupe by id, then sort newest-first.
    for c in app::timeline_by_class(&db(), kintsugi_core::Class::Catastrophic, 200)
        .unwrap_or_default()
    {
        if !rows.iter().any(|r| r.id == c.id) {
            rows.push(c);
        }
    }
    rows.sort_by(|a, b| b.ts.cmp(&a.ts)); // RFC3339 strings sort chronologically
    rows.truncate(limit); // keep the freshest `limit`
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
    if let Some(p) =
        kintsugi_model::config::configured_model().and_then(|p| p.parent().map(|x| x.to_path_buf()))
    {
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
    if gb >= 1.0 {
        format!("{gb:.1} GB")
    } else {
        format!("{:.0} MB", bytes as f64 / 1e6)
    }
}

/// Scan disk for the user's real downloaded `.gguf` models (no mock catalog).
pub fn available_models() -> Vec<LocalModel> {
    let active =
        kintsugi_model::config::configured_model().map(|p| p.to_string_lossy().to_string());
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<LocalModel> = Vec::new();
    for dir in model_dirs() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
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
                name: path
                    .file_name()
                    .map(|f| f.to_string_lossy().to_string())
                    .unwrap_or_default(),
                size: e
                    .metadata()
                    .ok()
                    .map(|m| human_size(m.len()))
                    .unwrap_or_default(),
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
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
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

/// Drop every still-pending entry from the queue (orphan recovery). Returns the
/// number pruned. Use after the spine fix to clear the historical backlog.
pub fn prune_pending() -> anyhow::Result<u64> {
    kintsugi_daemon::Client::prune_pending()
}

// ---- agent hooks (Settings: list + per-CLI on/off + refresh) --------------

#[derive(Clone, PartialEq, serde::Deserialize)]
pub struct AgentHook {
    pub id: String,
    pub name: String,
    pub installed: bool,
    pub config_path: String,
}

fn kintsugi_bin() -> PathBuf {
    let name = if cfg!(windows) {
        "kintsugi.exe"
    } else {
        "kintsugi"
    };
    // The installed CLI, in install-order of likelihood: `kintsugi init`'s target,
    // then a `cargo install kintsugi` location. A GUI app launched from the dock
    // may have a minimal PATH, so probe the known dirs before falling back to PATH.
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        for sub in [".local/bin", ".cargo/bin"] {
            let p = home.join(sub).join(name);
            if p.exists() {
                return p;
            }
        }
    }
    PathBuf::from(name)
}

/// List detected agent CLIs + whether the Kintsugi hook is installed in each.
pub fn agent_hooks() -> Vec<AgentHook> {
    let out = std::process::Command::new(kintsugi_bin())
        .args(["hook", "list", "--json"])
        .output();
    let Ok(out) = out else { return Vec::new() };
    serde_json::from_slice(&out.stdout).unwrap_or_default()
}

pub fn enable_agent_hook(id: &str) -> anyhow::Result<()> {
    let out = std::process::Command::new(kintsugi_bin())
        .args(["hook", "enable", "--agent", id])
        .output()?;
    if !out.status.success() {
        anyhow::bail!("{}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(())
}

pub fn disable_agent_hook(id: &str) -> anyhow::Result<()> {
    let out = std::process::Command::new(kintsugi_bin())
        .args(["hook", "disable", "--agent", id])
        .output()?;
    if !out.status.success() {
        anyhow::bail!("{}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(())
}

// ---- passive session recording (Settings toggle) --------------------------

fn shell_rc() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    // Same priority pick-model.sh uses: zsh first on macOS, else bash.
    let zsh = home.join(".zshrc");
    let bash = home.join(".bashrc");
    if zsh.exists() {
        Some(zsh)
    } else if bash.exists() {
        Some(bash)
    } else if cfg!(target_os = "macos") {
        Some(zsh)
    } else {
        Some(bash)
    }
}

/// Is the passive recorder block currently present in the user's shell rc?
pub fn recording_installed() -> bool {
    let Some(rc) = shell_rc() else { return false };
    std::fs::read_to_string(&rc)
        .map(|s| s.contains("kintsugi session recorder"))
        .unwrap_or(false)
}

pub fn install_recording() -> anyhow::Result<()> {
    let rc = shell_rc().ok_or_else(|| anyhow::anyhow!("no shell rc"))?;
    let out = std::process::Command::new(kintsugi_bin())
        .args(["record", "install", "--write"])
        .arg(&rc)
        .output()?;
    if !out.status.success() {
        anyhow::bail!("{}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(())
}

pub fn uninstall_recording() -> anyhow::Result<()> {
    let rc = shell_rc().ok_or_else(|| anyhow::anyhow!("no shell rc"))?;
    let out = std::process::Command::new(kintsugi_bin())
        .args(["record", "uninstall", "--write"])
        .arg(&rc)
        .output()?;
    if !out.status.success() {
        anyhow::bail!("{}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(())
}

// ---- auto-restart service (Settings toggle) -------------------------------

/// Is the OS supervisor (systemd / launchd) installed for the daemon?
pub fn service_installed() -> bool {
    let out = std::process::Command::new(kintsugi_bin())
        .args(["service", "status"])
        .output();
    match out {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout).to_string()
                + &String::from_utf8_lossy(&o.stderr);
            s.contains("installed") && !s.contains("not installed")
        }
        Err(_) => false,
    }
}

pub fn install_service() -> anyhow::Result<()> {
    let out = std::process::Command::new(kintsugi_bin())
        .args(["service", "install"])
        .output()?;
    if !out.status.success() {
        anyhow::bail!("{}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(())
}

pub fn uninstall_service() -> anyhow::Result<()> {
    let out = std::process::Command::new(kintsugi_bin())
        .args(["service", "uninstall"])
        .output()?;
    if !out.status.success() {
        anyhow::bail!("{}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(())
}

/// Run `kintsugi uninstall --yes` (password already verified by the UI), so the
/// CLI does the actual destructive work — the same code path the terminal flow
/// uses. The UI captures the password into the env so the CLI doesn't re-prompt.
pub fn run_uninstall(password: &str, purge: bool) -> anyhow::Result<String> {
    // Verify the password in-process FIRST so a wrong one never spawns the CLI.
    if vault_provisioned() {
        if !verify_master_password(password) {
            anyhow::bail!("wrong password");
        }
    }
    let bin = std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join(".local/bin/kintsugi"))
        .filter(|p| p.exists())
        .unwrap_or_else(|| PathBuf::from("kintsugi"));
    let mut cmd = std::process::Command::new(&bin);
    cmd.arg("uninstall").arg("--yes");
    if purge {
        cmd.arg("--purge");
    }
    // KINTSUGI_PW lets the CLI skip its own TTY prompt when it's set (the UI
    // already proved the password). The CLI never logs this env var.
    cmd.env("KINTSUGI_PW", password);
    let out = cmd.output()?;
    let s = String::from_utf8_lossy(&out.stdout).to_string();
    if !out.status.success() {
        anyhow::bail!("uninstall failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(s)
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
        mode: p
            .mode
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "attended".to_string()),
        threshold: p.risk_threshold(),
        allow: p.rules.allow.clone(),
        deny: p.rules.deny.clone(),
        provenance_enabled: p.provenance_enabled(),
    }
}

// ---- persisted UI prefs (theme + menu-bar visibility) ----------------------

/// Where the desktop's UI prefs live — next to the event log, like the setup
/// marker, so they survive restarts and travel with the data dir.
fn prefs_path() -> PathBuf {
    kintsugi_daemon::default_db_path().with_file_name("desktop-prefs.json")
}

/// Load the persisted theme + menu-bar (`nav_open`) state. A missing or corrupt
/// file falls back to the historical defaults (dark theme, menu open), so a fresh
/// install looks exactly as it did before this was persisted.
pub fn load_ui_prefs() -> (crate::theme::Theme, bool) {
    let default = (crate::theme::Theme::Dark, true);
    let Ok(text) = std::fs::read_to_string(prefs_path()) else {
        return default;
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
        return default;
    };
    let theme = v
        .get("theme")
        .and_then(|t| t.as_str())
        .map(crate::theme::Theme::from_key)
        .unwrap_or(default.0);
    let nav_open = v.get("nav_open").and_then(|b| b.as_bool()).unwrap_or(default.1);
    (theme, nav_open)
}

/// Persist the theme + menu-bar state. Best-effort: a write failure just means
/// the choice won't survive the next restart — never block a toggle or surface it.
pub fn save_ui_prefs(theme: crate::theme::Theme, nav_open: bool) {
    let p = prefs_path();
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let body = serde_json::json!({ "theme": theme.key(), "nav_open": nav_open });
    let _ = std::fs::write(&p, serde_json::to_vec_pretty(&body).unwrap_or_default());
}

// ---- updates (Settings → "Check for updates") -----------------------------

/// Result of a `kintsugi update --check` run, for the Settings update control.
#[derive(Clone, PartialEq)]
pub enum UpdateStatus {
    /// Already on the latest release; carries the version string to show.
    UpToDate { version: String },
    /// A newer release exists.
    Available { current: String, latest: String },
    /// The check couldn't complete (offline, no CLI on PATH, …); carries why.
    Failed { message: String },
}

/// Pull the first whitespace-delimited token that looks like a version
/// (`1.2.3` / `v1.2.3`) out of a line — tolerant of surrounding prose.
fn first_version_token(line: &str) -> Option<String> {
    line.split(|c: char| c.is_whitespace() || c == '(' || c == ')')
        .map(|t| t.trim_start_matches('v').trim_end_matches('.'))
        .find(|t| {
            let mut parts = t.split('.');
            parts.clone().count() >= 2
                && parts.all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        })
        .map(|t| t.to_string())
}

/// Ask the installed CLI whether a newer release exists — the GUI equivalent of
/// `kintsugi update --check`. Shells out so the result is byte-for-byte the same
/// logic (release lookup + version compare) the CLI uses; no duplicated policy.
pub fn check_for_update() -> UpdateStatus {
    let out = std::process::Command::new(kintsugi_bin())
        .args(["update", "--check"])
        .output();
    let out = match out {
        Ok(o) => o,
        Err(e) => {
            return UpdateStatus::Failed {
                message: format!("couldn't run the kintsugi CLI: {e}"),
            }
        }
    };
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // "  ↑ update available: 0.2.1 → 0.3.0"
    if let Some(idx) = text.find("update available:") {
        let line = text[idx..].lines().next().unwrap_or("");
        if let Some((cur, lat)) = line.split_once('→') {
            if let (Some(current), Some(latest)) =
                (first_version_token(cur), first_version_token(lat))
            {
                return UpdateStatus::Available { current, latest };
            }
        }
    }
    // "  ✓ up to date (latest release is v0.2.1)."
    if let Some(line) = text.lines().find(|l| l.contains("up to date")) {
        return UpdateStatus::UpToDate {
            version: first_version_token(line).unwrap_or_else(|| "latest".to_string()),
        };
    }
    UpdateStatus::Failed {
        message: text
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("update check failed")
            .trim()
            .to_string(),
    }
}

/// Download and install the latest release — the GUI equivalent of
/// `kintsugi update --yes` (non-interactive, so no TTY prompt). Returns the CLI's
/// summary on success. Heavy (downloads + may rebuild the model engine), so the
/// caller runs it off the UI thread.
pub fn apply_update() -> anyhow::Result<String> {
    let out = std::process::Command::new(kintsugi_bin())
        .args(["update", "--yes"])
        .output()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if !out.status.success() {
        anyhow::bail!("{}", text.trim());
    }
    Ok(text.trim().to_string())
}

/// What provenance tracks, for the Rules view — the untrusted ingest channels
/// that taint a session. Sourced from kintsugi-core's `SourceKind`, so the
/// displayed list is the real one the interception layer classifies, never a
/// drifting copy.
pub fn untrusted_sources() -> Vec<(&'static str, &'static str)> {
    kintsugi_core::untrusted_sources()
}

/// The egress channels provenance watches for the "data leaves the machine" leg
/// (curl, wget, ssh, scp, `git push`, DNS tools, …). Sourced from kintsugi-core's
/// `is_egress_sink` catalog so it stays in lock-step with what actually fires.
pub fn egress_channels() -> Vec<(&'static str, &'static str)> {
    kintsugi_core::egress_channels()
}

/// The built-in deterministic protections — always on, the heart of the gate.
pub fn builtin_protections() -> Vec<(&'static str, &'static str)> {
    vec![
        ("Recursive delete", "rm -rf / rmdir on home or root"),
        (
            "Force-push & history rewrite",
            "git push --force, reset --hard, filter-branch",
        ),
        ("Secret reads", ".env, ~/.ssh, ~/.aws, keychains"),
        ("Destructive SQL", "DROP TABLE, DELETE FROM, TRUNCATE"),
        ("Pipe-to-shell", "curl | sh, wget | bash"),
        ("Disk & device writes", "dd of=, mkfs, writes to /dev/*"),
        (
            "Infrastructure teardown",
            "terraform destroy, kubectl delete, docker prune",
        ),
        (
            "Lethal trifecta",
            "untrusted content + secret read + egress → blocked",
        ),
        (
            "Self-protection",
            "uninstalling or deleting Kintsugi itself",
        ),
    ]
}
