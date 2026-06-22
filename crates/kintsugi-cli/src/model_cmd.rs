//! `kintsugi model` — manage the optional Tier-2 local model.
//!
//! Kintsugi always works without a model (the heuristic scorer is always on).
//! This command surface lets a user point the daemon at any local GGUF, swap to a
//! newer one without updating Kintsugi, build the inference engine after a plain
//! `cargo install`, or remove the model entirely. The chosen path is persisted by
//! [`kintsugi_model::config`] so the daemon loads it across restarts without a
//! shell env var — the bug that made a freshly-downloaded model not take effect.
//!
//! Security spine: the model only ever *explains* and scores the ambiguous band;
//! none of these commands touch the deterministic rule floor. The only network
//! egress is the user-invoked installer/picker download (`pick` / `install`).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};
use kintsugi_daemon::Client;

/// The model Kintsugi will actually load: the `KINTSUGI_MODEL_FILE` env override
/// (matching the daemon's precedence) wins, then the persisted selection.
fn effective_model() -> Option<(PathBuf, &'static str)> {
    if let Some(p) = std::env::var_os("KINTSUGI_MODEL_FILE") {
        let p = PathBuf::from(p);
        if !p.as_os_str().is_empty() {
            return Some((p, "from KINTSUGI_MODEL_FILE"));
        }
    }
    kintsugi_model::config::configured_model().map(|p| (p, "configured"))
}

/// `kintsugi model status`: what's configured, whether the daemon can run it, and
/// what it's scoring with right now — so the common "model set but still
/// heuristic" surprise is diagnosable in one place.
pub fn status() -> Result<()> {
    println!("kintsugi model");

    match effective_model() {
        Some((path, src)) => {
            println!("  configured: {} ({src})", path.display());
            if !path.is_file() {
                println!(
                    "              ⚠ file is missing — set it again: kintsugi model use <path>"
                );
            } else if !looks_like_gguf(&path) {
                println!(
                    "              ⚠ file is not a valid GGUF (truncated or half-downloaded) —"
                );
                println!("                re-download it: kintsugi model pick");
            }
        }
        None => println!("  configured: none — using the heuristic scorer"),
    }

    if daemon_has_llama() {
        println!("  engine:     llama.cpp inference available");
    } else {
        println!("  engine:     not built — build it with: kintsugi model install");
    }

    if Client::is_daemon_running() {
        match active_scorer_label() {
            Some(label) => println!("  scoring:    {label}"),
            None => println!("  scoring:    (daemon not answering)"),
        }
    } else {
        println!("  scoring:    daemon stopped (start it with: kintsugi init)");
    }

    // The common mismatch: a model is set, but the installed daemon has no engine,
    // so it still scores heuristically. Say so plainly rather than leave it silent.
    if let Some((path, _)) = effective_model() {
        if path.is_file() && !daemon_has_llama() {
            println!();
            println!("  A model is configured but this daemon has no inference engine, so it");
            println!("  still scores heuristically. Build the engine:  kintsugi model install");
        }
    }
    Ok(())
}

/// `kintsugi model use <path>`: point the daemon at a local GGUF and load it.
pub fn use_model(path: &Path) -> Result<()> {
    if !path.is_file() {
        anyhow::bail!("not a readable file: {}", path.display());
    }
    let is_gguf = path
        .extension()
        .map(|e| e.eq_ignore_ascii_case("gguf"))
        .unwrap_or(false);
    if !is_gguf {
        eprintln!(
            "kintsugi: warning — {} is not a .gguf file; the model may fail to load.",
            path.display()
        );
    } else if !looks_like_gguf(path) {
        eprintln!(
            "kintsugi: warning — {} doesn't start with the GGUF header; it looks truncated or",
            path.display()
        );
        eprintln!(
            "  corrupt and will likely fail to load. Re-download it with: kintsugi model pick"
        );
    }
    // Persist an absolute path: the daemon runs from a different working directory,
    // so a relative path would not resolve.
    let abs = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    kintsugi_model::config::set_configured_model(&abs)?;
    println!("kintsugi: model set to {}", abs.display());

    if !daemon_has_llama() {
        println!("  note: this daemon has no inference engine yet, so it will keep scoring");
        println!("  heuristically until you build it:  kintsugi model install");
    }
    restart_if_running()
}

/// The directory downloaded weights live in (matches `pick-model.sh`).
fn models_dir() -> PathBuf {
    if let Ok(d) = std::env::var("KINTSUGI_MODEL_DIR") {
        return PathBuf::from(d);
    }
    if let Ok(d) = std::env::var("KINTSUGI_DATA_DIR") {
        return PathBuf::from(d).join("models");
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    home.join(".local/share/kintsugi/models")
}

/// `kintsugi model rm <name>`: delete a downloaded GGUF from disk. Accepts a
/// filename in the models dir, a substring match, or an absolute path. If it was
/// the active model, also forgets it (back to heuristic) and restarts the daemon.
pub fn rm(name: &str) -> Result<()> {
    let direct = PathBuf::from(name);
    let path = if direct.is_file() {
        direct
    } else {
        let dir = models_dir();
        let exact = dir.join(name);
        if exact.is_file() {
            exact
        } else {
            std::fs::read_dir(&dir)
                .ok()
                .and_then(|rd| {
                    rd.flatten().map(|e| e.path()).find(|p| {
                        p.extension()
                            .map(|e| e.eq_ignore_ascii_case("gguf"))
                            .unwrap_or(false)
                            && p.file_name()
                                .map(|f| f.to_string_lossy().contains(name))
                                .unwrap_or(false)
                    })
                })
                .ok_or_else(|| anyhow::anyhow!("no model matching '{name}' in {}", dir.display()))?
        }
    };
    let abs = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
    let was_active = kintsugi_model::config::configured_model()
        .map(|c| std::fs::canonicalize(&c).unwrap_or(c) == abs)
        .unwrap_or(false);
    std::fs::remove_file(&abs).with_context(|| format!("delete {}", abs.display()))?;
    println!("kintsugi: deleted {}", abs.display());
    if was_active {
        kintsugi_model::config::clear_configured_model()?;
        println!("  it was the active model — falling back to the heuristic scorer.");
        return restart_if_running();
    }
    Ok(())
}

/// `kintsugi model remove`: forget the configured model.
pub fn remove() -> Result<()> {
    kintsugi_model::config::clear_configured_model()?;
    if std::env::var_os("KINTSUGI_MODEL_FILE").is_some() {
        println!("kintsugi: cleared the configured model.");
        println!(
            "  note: KINTSUGI_MODEL_FILE is still set in your environment and overrides this —"
        );
        println!(
            "  unset it (and remove it from your shell profile) to fully fall back to heuristic."
        );
    } else {
        println!("kintsugi: cleared the configured model — falling back to the heuristic scorer.");
    }
    restart_if_running()
}

/// `kintsugi model pick`: download/choose a GGUF from Hugging Face, then load it.
pub fn pick() -> Result<()> {
    if !daemon_has_llama() {
        println!(
            "kintsugi: this daemon has no inference engine, so a downloaded model can't run yet."
        );
        println!(
            "  It will be downloaded and remembered; build the engine with: kintsugi model install"
        );
    }
    run_remote_script(crate::PICKER_URL, &[]).context("run the model picker")?;
    adopt_downloaded_model()
}

/// `kintsugi model install`: build the engine (needs a toolchain) and get a model.
/// Re-runs the official installer in model-only mode (no agent re-wiring), the
/// same proven path the curl installer uses — so `cargo install` users get a
/// working model with one command.
pub fn install() -> Result<()> {
    println!("kintsugi: setting up the local model — building the engine and downloading a GGUF.");
    println!("  This compiles llama.cpp once (a few minutes) and needs a C/C++ toolchain.");
    run_remote_script(crate::INSTALL_URL, &["--with-model", "--no-init"])
        .context("run the installer's model setup")?;
    adopt_downloaded_model()
}

/// After the picker/installer drops a GGUF in the model dir, record it in our
/// config (so the daemon loads it without a shell env var) and restart.
fn adopt_downloaded_model() -> Result<()> {
    let dir = picker_model_dir();
    match newest_gguf(&dir) {
        Some(model) => {
            kintsugi_model::config::set_configured_model(&model)?;
            println!("kintsugi: model set to {}", model.display());
            restart_if_running()
        }
        None => {
            eprintln!(
                "kintsugi: no .gguf found in {} — nothing to load.",
                dir.display()
            );
            Ok(())
        }
    }
}

/// Restart a running daemon so it picks up the new selection. If none is running,
/// just say how to start it (and avoid spawning one as a side effect). If the
/// daemon refuses to stop (admin-locked), surface that instead of silently
/// leaving the old scorer in place.
fn restart_if_running() -> Result<()> {
    if !Client::is_daemon_running() {
        println!("  • daemon not running — it will load the model on next start: kintsugi init");
        return Ok(());
    }
    println!("  • restarting the daemon to apply the change…");
    crate::cmd_stop()?;
    for _ in 0..150 {
        if !Client::is_daemon_running() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    if Client::is_daemon_running() {
        anyhow::bail!(
            "the daemon did not stop (admin-locked?). Unlock it, then: kintsugi stop && kintsugi init"
        );
    }
    crate::start_daemon()?;
    if let Some(label) = active_scorer_label() {
        println!("  ✓ scoring with: {label}");
    }
    Ok(())
}

/// Fetch a setup script and run it with the user's terminal attached (so the
/// picker's menu and progress spinner work). Network egress is user-invoked.
fn run_remote_script(url: &str, args: &[&str]) -> Result<()> {
    let script = crate::http_get(url).with_context(|| format!("download {url}"))?;
    let tmp = std::env::temp_dir().join(format!("kintsugi-model-{}.sh", std::process::id()));
    std::fs::write(&tmp, &script).with_context(|| format!("write {}", tmp.display()))?;
    let status = Command::new("sh")
        .arg(&tmp)
        .args(args)
        .status()
        .with_context(|| format!("run {}", tmp.display()));
    let _ = std::fs::remove_file(&tmp);
    let status = status?;
    if !status.success() {
        anyhow::bail!("the setup script exited with {status}");
    }
    Ok(())
}

/// Where the picker/installer save GGUFs — mirrors `pick-model.sh`'s resolution
/// (`KINTSUGI_MODEL_DIR`, else `$KINTSUGI_DATA_DIR/models`, else
/// `~/.local/share/kintsugi/models`).
fn picker_model_dir() -> PathBuf {
    if let Ok(d) = std::env::var("KINTSUGI_MODEL_DIR") {
        return PathBuf::from(d);
    }
    if let Ok(d) = std::env::var("KINTSUGI_DATA_DIR") {
        return PathBuf::from(d).join("models");
    }
    if let Some(home) = crate::home_dir() {
        return home.join(".local/share/kintsugi/models");
    }
    std::env::temp_dir().join("kintsugi-models")
}

/// The most recently modified `.gguf` under `dir`, if any.
fn newest_gguf(dir: &Path) -> Option<PathBuf> {
    let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let path = entry.path();
        let is_gguf = path
            .extension()
            .map(|e| e.eq_ignore_ascii_case("gguf"))
            .unwrap_or(false);
        if !is_gguf {
            continue;
        }
        let Ok(mtime) = entry.metadata().and_then(|m| m.modified()) else {
            continue;
        };
        if newest.as_ref().map(|(t, _)| mtime > *t).unwrap_or(true) {
            newest = Some((mtime, path));
        }
    }
    newest.map(|(_, p)| p)
}

/// A real GGUF file starts with the four ASCII bytes `GGUF`. A file that exists
/// but fails this is truncated, half-downloaded, or not a model at all — exactly
/// the case that makes the daemon load fail and silently drop to the heuristic
/// scorer. This is a cheap header check, not a full validation. `false` for a
/// missing/unreadable file too (callers report those separately).
fn looks_like_gguf(path: &Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic).is_ok() && &magic == b"GGUF"
}

// Re-export the daemon probes from `main` so this module reads cleanly.
use crate::{active_scorer_label, daemon_has_llama};

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    /// Env vars are process-global; serialize the tests that touch them.
    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn touch(path: &Path) {
        std::fs::write(path, b"x").unwrap();
    }

    #[test]
    fn newest_gguf_picks_most_recent_and_ignores_others() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        touch(&d.join("notes.txt"));
        let old = d.join("old.gguf");
        touch(&old);
        // Make `new.gguf` strictly newer than `old.gguf`.
        std::thread::sleep(Duration::from_millis(20));
        let new = d.join("new.gguf");
        touch(&new);
        assert_eq!(newest_gguf(d), Some(new));
    }

    #[test]
    fn looks_like_gguf_detects_magic_and_corruption() {
        let tmp = tempfile::tempdir().unwrap();
        // A real GGUF starts with the "GGUF" magic.
        let good = tmp.path().join("good.gguf");
        std::fs::write(&good, b"GGUF\x03\x00\x00\x00rest-of-header").unwrap();
        assert!(looks_like_gguf(&good));

        // A truncated / half-downloaded file (no magic, or too short) is rejected.
        let truncated = tmp.path().join("truncated.gguf");
        std::fs::write(&truncated, b"GG").unwrap();
        assert!(!looks_like_gguf(&truncated));

        // An HTML error page saved as .gguf is rejected.
        let html = tmp.path().join("oops.gguf");
        std::fs::write(&html, b"<!DOCTYPE html><html>404</html>").unwrap();
        assert!(!looks_like_gguf(&html));

        // A missing file is rejected (not a panic).
        assert!(!looks_like_gguf(&tmp.path().join("nope.gguf")));
    }

    #[test]
    fn newest_gguf_none_when_empty_or_missing() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(newest_gguf(tmp.path()), None);
        assert_eq!(newest_gguf(&tmp.path().join("nope")), None);
    }

    #[test]
    fn picker_model_dir_honors_overrides() {
        let _g = env_lock();
        std::env::set_var("KINTSUGI_MODEL_DIR", "/tmp/explicit");
        assert_eq!(picker_model_dir(), PathBuf::from("/tmp/explicit"));
        std::env::remove_var("KINTSUGI_MODEL_DIR");

        std::env::set_var("KINTSUGI_DATA_DIR", "/tmp/data");
        assert_eq!(picker_model_dir(), PathBuf::from("/tmp/data/models"));
        std::env::remove_var("KINTSUGI_DATA_DIR");
    }

    #[test]
    fn effective_model_prefers_env_then_config() {
        let _g = env_lock();
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("KINTSUGI_DATA_DIR", tmp.path());
        std::env::remove_var("KINTSUGI_MODEL_FILE");

        // No env, no config → none.
        kintsugi_model::config::clear_configured_model().unwrap();
        assert!(effective_model().is_none());

        // Config only → configured.
        kintsugi_model::config::set_configured_model(Path::new("/m/cfg.gguf")).unwrap();
        let (p, src) = effective_model().unwrap();
        assert_eq!(p, PathBuf::from("/m/cfg.gguf"));
        assert_eq!(src, "configured");

        // Env overrides config.
        std::env::set_var("KINTSUGI_MODEL_FILE", "/m/env.gguf");
        let (p, src) = effective_model().unwrap();
        assert_eq!(p, PathBuf::from("/m/env.gguf"));
        assert_eq!(src, "from KINTSUGI_MODEL_FILE");

        std::env::remove_var("KINTSUGI_MODEL_FILE");
        std::env::remove_var("KINTSUGI_DATA_DIR");
    }
}
