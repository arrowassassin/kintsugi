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
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default()
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
        home.join(".gemini/antigravity-cli/hooks.json"),
        home.join(".config/opencode/plugin/kintsugi.js"),
    ] {
        if p.is_file() && std::fs::remove_file(&p).is_ok() {
            cleaned.push(p.display().to_string());
        }
    }

    for p in hook_files(home) {
        let Ok(text) = std::fs::read_to_string(&p) else { continue };
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

pub fn run(purge: bool, yes: bool) -> Result<()> {
    let home = home();

    // 1. Password gate — same vault that gates stopping the daemon.
    if let VaultState::Locked(vault) = admin::load_vault(&admin::default_vault_path()) {
        let pw = crate::admin_cmd::read_password_tty("Admin password to uninstall: ")?;
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
    if purge {
        println!("  • PURGE all stored data:  {}  (events, vault, model — UNRECOVERABLE)", data.display());
    } else {
        println!("  • KEEP your stored data:  {}  (pass --purge to erase it)", data.display());
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
    if purge && data.is_dir() && std::fs::remove_dir_all(&data).is_ok() {
        println!("  purged data: {}", data.display());
    }

    println!(
        "\nKintsugi uninstalled.{}",
        if purge { "" } else { " Your data was kept." }
    );
    Ok(())
}
