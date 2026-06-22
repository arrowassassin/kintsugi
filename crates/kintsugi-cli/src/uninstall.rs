//! `kintsugi uninstall` — clean teardown: stop the daemon, strip the agent
//! hooks, remove the shim dir and the installed binaries, and (with `--purge`)
//! erase stored data. Password-gated when a vault is set; always prints a plan
//! and asks before touching anything. Every removal is best-effort so a partial
//! environment never makes it panic.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;
use kintsugi_core::admin::{self, VaultState};
use serde_json::Value;

use crate::{cmd_stop, init, shim_dir};

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
}

/// The dir holding the running `kintsugi` (its siblings are the other binaries).
fn bin_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| home().join(".local/bin"))
}

/// Agent config files we may have merged a hook into.
fn hook_files(home: &Path) -> Vec<PathBuf> {
    vec![
        home.join(".claude/settings.json"),
        home.join(".qwen/settings.json"),
        home.join(".gemini/settings.json"),
        home.join(".cursor/hooks.json"),
        home.join(".codex/config.toml"),
    ]
}

/// Recursively drop any JSON array element that references a kintsugi binary.
fn scrub_json(v: &mut Value) -> bool {
    let mut changed = false;
    match v {
        Value::Array(arr) => {
            let before = arr.len();
            arr.retain(|el| !el.to_string().contains("kintsugi"));
            changed |= arr.len() != before;
            for el in arr.iter_mut() {
                changed |= scrub_json(el);
            }
        }
        Value::Object(map) => {
            for val in map.values_mut() {
                changed |= scrub_json(val);
            }
        }
        _ => {}
    }
    changed
}

/// Strip the Kintsugi hook from every config we can find. Returns the cleaned
/// paths for the summary. Never errors — a malformed file is just skipped.
fn strip_hooks(home: &Path) -> Vec<String> {
    let mut cleaned = Vec::new();

    // Standalone kintsugi-only hook files: delete outright.
    for p in [
        home.join(".copilot/hooks/kintsugi.json"),
        home.join(".config/opencode/plugin/kintsugi.js"),
    ] {
        if p.is_file() && std::fs::remove_file(&p).is_ok() {
            cleaned.push(p.display().to_string());
        }
    }

    // Antigravity installs into a kintsugi-owned plugin subtree
    // (`~/.gemini/antigravity-cli/plugins/kintsugi/{hooks.json,...}`, see
    // init::antigravity_hooks_config / antigravity_mcp_config). The whole
    // directory is ours, so remove it wholesale — deleting a single guessed
    // file used to leave the live hook behind, still firing at a now-absent
    // binary after uninstall.
    let antigravity_dir = home.join(".gemini/antigravity-cli/plugins/kintsugi");
    if antigravity_dir.is_dir() && std::fs::remove_dir_all(&antigravity_dir).is_ok() {
        cleaned.push(antigravity_dir.display().to_string());
    }

    for p in hook_files(home) {
        let Ok(text) = std::fs::read_to_string(&p) else {
            continue;
        };
        if !text.contains("kintsugi") {
            continue;
        }
        if p.extension().map(|e| e == "json").unwrap_or(false) {
            if let Ok(mut v) = serde_json::from_str::<Value>(&text) {
                if scrub_json(&mut v) {
                    if let Ok(out) = serde_json::to_string_pretty(&v) {
                        if std::fs::write(&p, out).is_ok() {
                            cleaned.push(p.display().to_string());
                        }
                    }
                }
            }
        } else {
            // TOML / other: drop any line mentioning kintsugi (best-effort).
            let total = text.lines().count();
            let kept: Vec<&str> = text.lines().filter(|l| !l.contains("kintsugi")).collect();
            if kept.len() != total && std::fs::write(&p, kept.join("\n")).is_ok() {
                cleaned.push(format!("{} (lines)", p.display()));
            }
        }
    }
    cleaned
}

/// Remove the desktop Control Room app's OS integration — the part that
/// `--install` (and the packaged `.dmg`/`.msi`/`.deb`) put OUTSIDE the data dir.
/// Mirrors the paths in `desktop-dx/src/install.rs`. Without this, `kintsugi
/// uninstall` left the app in `/Applications` (macOS), the app launcher (Linux),
/// or the Programs folder (Windows) — where it could still be opened and, if data
/// was kept, unlock and show it. Returns the paths actually removed.
fn remove_desktop_app(home: &Path) -> Vec<String> {
    // (path, is_dir)
    let mut targets: Vec<(PathBuf, bool)> = Vec::new();
    #[cfg(target_os = "macos")]
    targets.push((home.join("Applications/Kintsugi.app"), true));
    #[cfg(target_os = "linux")]
    {
        targets.push((home.join(".local/bin/kintsugi-control-room"), false));
        targets.push((
            home.join(".local/share/applications/kintsugi-control-room.desktop"),
            false,
        ));
        for size in [16, 32, 64, 128, 256, 512] {
            targets.push((
                home.join(format!(
                    ".local/share/icons/hicolor/{size}x{size}/apps/kintsugi-control-room.png"
                )),
                false,
            ));
        }
    }
    #[cfg(target_os = "windows")]
    {
        let local = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join("AppData/Local"));
        targets.push((local.join("Programs/Kintsugi"), true));
        let roaming = std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join("AppData/Roaming"));
        targets.push((
            roaming.join("Microsoft/Windows/Start Menu/Programs/Kintsugi.lnk"),
            false,
        ));
    }
    let mut removed = Vec::new();
    for (p, is_dir) in targets {
        let gone = if is_dir {
            p.is_dir() && std::fs::remove_dir_all(&p).is_ok()
        } else {
            p.is_file() && std::fs::remove_file(&p).is_ok()
        };
        if gone {
            removed.push(p.display().to_string());
        }
    }
    removed
}

/// Reset Kintsugi to a fresh-install state WITHOUT touching the audit data:
/// remove the admin password (vault), the model pick, the posture markers, and
/// the runtime/app state — but keep `events.db` (+ its WAL/SHM) and `snapshots/`.
/// So `uninstall` always strips the password and settings; the history only goes
/// with `--purge`. Returns short labels for what was removed.
fn reset_system_config(data: &Path, vault: &Path) -> Vec<String> {
    let mut removed = Vec::new();
    if vault.is_file() && std::fs::remove_file(vault).is_ok() {
        removed.push("admin password (vault)".to_string());
    }
    // System config / runtime state in the data dir — NOT the audit log/snapshots.
    for f in [
        "model.path",         // picked local model → back to the heuristic default
        "fail-closed.flag",   // posture marker
        "panic.flag",         // kill-switch flag
        "desktop-prefs.json", // app theme / menu prefs
        "desktop-setup-done", // first-run wizard marker
        "record-spool.jsonl", // pending recorder spool
        "kintsugi.pid",
        "kintsugi.sock",
        "watch.pid",
    ] {
        let p = data.join(f);
        if p.is_file() && std::fs::remove_file(&p).is_ok() {
            removed.push(f.to_string());
        }
    }
    removed
}

pub fn run(purge: bool, yes: bool) -> Result<()> {
    let home = home();

    // 1. Password gate — same vault that gates stopping the daemon. The UI sets
    // KINTSUGI_PW after verifying the password itself, so we don't double-prompt.
    if let VaultState::Locked(vault) = admin::load_vault(&admin::default_vault_path()) {
        let pw = match std::env::var("KINTSUGI_PW") {
            Ok(p) if !p.is_empty() => p,
            _ => crate::admin_cmd::read_password_tty("Admin password to uninstall: ")?,
        };
        if !vault.verify_password(&pw) {
            anyhow::bail!("wrong password — uninstall aborted");
        }
    }

    let shim = shim_dir();
    let data = kintsugi_daemon::default_db_path()
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let bdir = bin_dir();
    // Order: the daemon's dependents first, `kintsugi` itself last.
    let bins = [
        "kintsugi-daemon",
        "kintsugi-hook",
        "kintsugi-shim",
        "kintsugi-mcp",
        "kintsugi",
    ];
    let agents = init::detect_agents(&home);

    // 2. Plan.
    println!("kintsugi uninstall will:");
    println!("  • stop the running daemon");
    if agents.is_empty() {
        println!("  • check agent configs for the Kintsugi hook (none detected)");
    } else {
        let names: Vec<&str> = agents.iter().map(|a| a.name).collect();
        println!("  • strip the Kintsugi hook from: {}", names.join(", "));
    }
    println!("  • remove the shim dir:    {}", shim.display());
    println!("  • remove the binaries in: {}", bdir.display());
    println!("  • remove the desktop app (Applications / launcher / Start menu) if installed");
    println!("  • remove the auto-restart watchdog (service), if installed");
    println!("  • remove your admin password and reset settings to defaults");
    println!("      (vault, model pick, fail-closed posture, autostart, app prefs)");
    if purge {
        println!(
            "  • PURGE everything else too:  {}  (audit log + snapshots — UNRECOVERABLE)",
            data.display()
        );
    } else {
        println!(
            "  • KEEP your audit log + snapshots:  {}  (pass --purge to erase them too)",
            data.display()
        );
    }
    println!();

    // 3. Confirm.
    if !yes {
        print!("Type 'uninstall' to proceed: ");
        std::io::stdout().flush().ok();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        if line.trim() != "uninstall" {
            println!("Aborted — nothing was removed.");
            return Ok(());
        }
    }

    // 4. Execute (best-effort; keep going if a step is already gone).
    let _ = cmd_stop();
    // Remove the auto-restart watchdog FIRST, or it would relaunch the daemon we
    // just stopped. `_unattended` skips the password re-prompt — we already gated.
    let _ = crate::service::uninstall_unattended();
    for c in strip_hooks(&home) {
        println!("  stripped hook: {c}");
    }
    if shim.is_dir() && std::fs::remove_dir_all(&shim).is_ok() {
        println!("  removed shims: {}", shim.display());
    }
    for b in bins {
        let p = bdir.join(b);
        if p.exists() && std::fs::remove_file(&p).is_ok() {
            println!("  removed: {}", p.display());
        }
    }
    for p in remove_desktop_app(&home) {
        println!("  removed desktop app: {p}");
    }
    if purge {
        // Full wipe: the password vault + everything in the data dir (audit log,
        // snapshots, config). Remove the vault explicitly too in case it lives
        // outside the data dir (KINTSUGI_VAULT override).
        let _ = std::fs::remove_file(admin::default_vault_path());
        if data.is_dir() && std::fs::remove_dir_all(&data).is_ok() {
            println!("  purged data: {}", data.display());
        }
    } else {
        // Reset to defaults — remove the password + system config/runtime state,
        // but KEEP the audit log and snapshots.
        for f in reset_system_config(&data, &admin::default_vault_path()) {
            println!("  reset: {f}");
        }
    }

    println!(
        "\nKintsugi uninstalled — password removed, settings reset to defaults.{}",
        if purge {
            ""
        } else {
            " Your audit log and snapshots were kept (--purge to erase them)."
        }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::reset_system_config;

    #[test]
    fn reset_removes_password_and_config_but_keeps_audit_data() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path();
        let vault = data.join("admin-vault.json");

        // The password vault + system config / runtime state.
        std::fs::write(&vault, b"{}").unwrap();
        for f in [
            "model.path",
            "fail-closed.flag",
            "panic.flag",
            "desktop-prefs.json",
            "desktop-setup-done",
            "kintsugi.pid",
            "kintsugi.sock",
            "watch.pid",
        ] {
            std::fs::write(data.join(f), b"x").unwrap();
        }
        // The audit data that MUST survive a non-purge uninstall.
        for f in ["events.db", "events.db-wal", "events.db-shm"] {
            std::fs::write(data.join(f), b"log").unwrap();
        }
        std::fs::create_dir(data.join("snapshots")).unwrap();
        std::fs::write(data.join("snapshots/s1"), b"snap").unwrap();

        let removed = reset_system_config(data, &vault);

        // Password + system config are gone.
        assert!(
            !vault.exists(),
            "the admin password (vault) must be removed"
        );
        for f in [
            "model.path",
            "fail-closed.flag",
            "desktop-prefs.json",
            "kintsugi.pid",
        ] {
            assert!(!data.join(f).exists(), "{f} (system config) must be reset");
        }
        assert!(
            removed.iter().any(|r| r.contains("password")),
            "removal summary should mention the password"
        );

        // The audit log + snapshots are kept.
        for f in ["events.db", "events.db-wal", "events.db-shm"] {
            assert!(data.join(f).exists(), "{f} (audit log) must be kept");
        }
        assert!(
            data.join("snapshots/s1").exists(),
            "snapshots must be kept on a non-purge uninstall"
        );
    }
}
