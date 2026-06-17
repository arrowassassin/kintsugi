//! Enterprise shell enforcement — make the interception wiring sit in a place a
//! normal user cannot remove.
//!
//! By default `kintsugi init` only *prints* the PATH line, or a user adds it to
//! their own `~/.bashrc` / `~/.zshrc` — which that same user can trivially delete,
//! silently disabling the gate. On a shared/enterprise host that's the wrong
//! trust boundary. This module installs the wiring at the **system level**, in
//! files owned by root (Unix) or the machine environment (Windows), which a
//! non-privileged user has no permission to change. Only root / an administrator
//! can remove it.
//!
//! Honest scope (see `kintsugi limits`): this stops a *normal user* (or an agent
//! running as them) from removing the wiring by editing their own profile. It does
//! NOT stop a root/Administrator user — who owns the box and can edit the
//! system files directly. That is the documented boundary: Kintsugi guards against
//! mistakes and ordinary users, reversibly; it never claims to bind root.
//!
//! Tests point `KINTSUGI_ETC_DIR` at a temp dir so the install/remove/detect logic
//! is exercised without root or touching the real `/etc`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Markers for the managed block we own inside a shared system file. Re-running
/// install replaces the block in place (idempotent); remove deletes just it.
/// The marker strings live in `kintsugi-core` as the single source of truth.
#[cfg(unix)]
use kintsugi_core::{END, START as BEGIN};

/// The system config root. `/etc` in production; overridable for tests.
#[cfg(unix)]
fn etc_dir() -> PathBuf {
    std::env::var_os("KINTSUGI_ETC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc"))
}

/// The POSIX-sh snippet that prepends the shim dir, guarded so re-sourcing a
/// profile never lists it twice.
#[cfg(unix)]
fn block(shim: &Path) -> String {
    format!(
        "{BEGIN}\n\
         # Prepends Kintsugi's shim dir so raw shell-outs are guarded. Installed by\n\
         # `kintsugi admin enforce-shell`; remove with `kintsugi admin enforce-shell --remove`\n\
         # (root/admin only). See `kintsugi limits` for the honest scope.\n\
         case \":$PATH:\" in\n\
         \x20 *\":{shim}:\"*) ;;\n\
         \x20 *) export PATH=\"{shim}:$PATH\" ;;\n\
         esac\n\
         {END}\n",
        shim = shim.display()
    )
}

/// The system files we wire on Unix:
/// - `zshenv` — read by *every* zsh (login, interactive, and scripts), so it is
///   the most reliable single hook for zsh users.
/// - a POSIX profile for sh/bash login shells: a dedicated file under
///   `profile.d` when that dir exists (the clean, distro-standard drop-in), else
///   a managed block appended to `profile`.
#[cfg(unix)]
fn unix_targets() -> Vec<PathBuf> {
    let etc = etc_dir();
    let mut targets = vec![etc.join("zshenv")];
    let profile_d = etc.join("profile.d");
    if profile_d.is_dir() {
        targets.push(profile_d.join("kintsugi.sh"));
    } else {
        targets.push(etc.join("profile"));
    }
    targets
}

/// Is the enforced wiring currently in place? (Any target carries it.)
pub fn is_enforced() -> bool {
    #[cfg(unix)]
    {
        unix_targets().iter().any(|p| file_has_block(p))
    }
    #[cfg(not(unix))]
    {
        windows_machine_path_has_shim()
    }
}

/// True only when the wiring is present **and** in root-owned files — i.e.
/// genuinely un-removable by a normal user. This is the stronger property the
/// "only root/admin can remove" claim in `kintsugi status` actually depends on;
/// `is_enforced` alone only checks presence (which a writable override dir could
/// satisfy without the ownership that makes it stick).
pub fn is_root_enforced() -> bool {
    #[cfg(unix)]
    {
        unix_targets()
            .iter()
            .any(|p| file_has_block(p) && root_owned(p))
    }
    #[cfg(not(unix))]
    {
        // On Windows the machine PATH lives in HKLM, which only an Administrator
        // can write — presence there is itself the ownership guarantee.
        windows_machine_path_has_shim()
    }
}

/// Whether a file contains our managed block, or (for our own `profile.d` file)
/// simply exists.
#[cfg(unix)]
fn file_has_block(path: &Path) -> bool {
    match std::fs::read_to_string(path) {
        Ok(body) => body.contains(BEGIN),
        Err(_) => false,
    }
}

/// Install the system-level wiring for `shim`. Returns the files written. Bails
/// with a clear "needs root/admin" message when the system files aren't writable.
pub fn install(shim: &Path) -> Result<Vec<PathBuf>> {
    #[cfg(unix)]
    {
        let block = block(shim);
        let mut written = Vec::new();
        for target in unix_targets() {
            if let Some(dir) = target.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            // A dedicated profile.d file is ours to own outright; a shared file
            // (zshenv / profile) gets just our managed block, upserted.
            let is_own_file = target
                .file_name()
                .map(|n| n == "kintsugi.sh")
                .unwrap_or(false);
            let result = if is_own_file {
                std::fs::write(&target, block.as_bytes())
            } else {
                upsert_block(&target, &block)
            };
            map_privilege(result, &target)?;
            written.push(target);
        }
        Ok(written)
    }
    #[cfg(not(unix))]
    {
        windows_install(shim)
    }
}

/// Remove the system-level wiring. Returns the files changed.
pub fn uninstall() -> Result<Vec<PathBuf>> {
    #[cfg(unix)]
    {
        let mut changed = Vec::new();
        for target in unix_targets() {
            let is_own_file = target
                .file_name()
                .map(|n| n == "kintsugi.sh")
                .unwrap_or(false);
            if is_own_file {
                if target.exists() {
                    map_privilege(std::fs::remove_file(&target), &target)?;
                    changed.push(target);
                }
            } else if file_has_block(&target) {
                map_privilege(remove_block(&target), &target)?;
                changed.push(target);
            }
        }
        Ok(changed)
    }
    #[cfg(not(unix))]
    {
        windows_uninstall()
    }
}

/// Print whether the enforced wiring is installed, where, and whether those files
/// are actually root-owned (the property that makes it un-removable by a user).
pub fn status() -> Result<()> {
    if !is_enforced() {
        println!("shell enforcement: off (per-user wiring; a user can remove it themselves)");
        println!("  lock it system-wide (root/admin):  kintsugi admin enforce-shell");
        return Ok(());
    }
    println!("shell enforcement: on — wiring is system-level, not in user profiles");
    #[cfg(unix)]
    for target in unix_targets() {
        if file_has_block(&target) || (target.exists() && is_own(&target)) {
            let owner = if root_owned(&target) {
                "root-owned ✓"
            } else {
                "NOT root-owned — a user could still edit it; re-run as root"
            };
            println!("  {} ({owner})", target.display());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn is_own(target: &Path) -> bool {
    target
        .file_name()
        .map(|n| n == "kintsugi.sh")
        .unwrap_or(false)
}

/// Insert or replace our managed block in a shared file, preserving the rest.
#[cfg(unix)]
fn upsert_block(path: &Path, block: &str) -> std::io::Result<()> {
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let next = match (existing.find(BEGIN), existing.find(END)) {
        (Some(b), Some(e)) if e > b => {
            let end = e + END.len();
            let mut s = String::with_capacity(existing.len());
            s.push_str(&existing[..b]);
            s.push_str(block.trim_end());
            s.push_str(&existing[end..]);
            s
        }
        _ => {
            let mut s = existing;
            if !s.is_empty() && !s.ends_with('\n') {
                s.push('\n');
            }
            s.push_str(block);
            s
        }
    };
    std::fs::write(path, next.as_bytes())
}

/// Remove our managed block from a shared file, leaving everything else intact.
#[cfg(unix)]
fn remove_block(path: &Path) -> std::io::Result<()> {
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    if let (Some(b), Some(e)) = (existing.find(BEGIN), existing.find(END)) {
        if e > b {
            let mut end = e + END.len();
            // Swallow a trailing newline after the block so we don't leave a gap.
            if existing[end..].starts_with('\n') {
                end += 1;
            }
            let mut s = String::with_capacity(existing.len());
            s.push_str(&existing[..b]);
            s.push_str(&existing[end..]);
            return std::fs::write(path, s.as_bytes());
        }
    }
    Ok(())
}

/// Turn a permission error into an actionable "needs root/admin" message; pass
/// other errors through with the file path for context.
#[cfg(unix)]
fn map_privilege(result: std::io::Result<()>, path: &Path) -> Result<()> {
    match result {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Err(anyhow::anyhow!(
            "cannot write {} — system-level enforcement needs root.\n  \
             Re-run with sudo:  sudo kintsugi admin enforce-shell",
            path.display()
        )),
        Err(e) => Err(anyhow::Error::from(e)).with_context(|| format!("write {}", path.display())),
    }
}

#[cfg(unix)]
fn root_owned(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path)
        .map(|m| m.uid() == 0)
        .unwrap_or(false)
}

// ---- Windows: the machine (all-users) PATH, which only an Administrator may set.

#[cfg(not(unix))]
fn windows_machine_path() -> String {
    let out = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "[Environment]::GetEnvironmentVariable('Path','Machine')",
        ])
        .output();
    out.map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

#[cfg(not(unix))]
fn windows_machine_path_has_shim() -> bool {
    // Best-effort: the marker is the shim dir's presence in the machine PATH.
    !windows_machine_path().is_empty() && windows_machine_path().to_lowercase().contains("kintsugi")
}

/// Reject a shim path carrying characters that could break out of the
/// single-quoted PowerShell string literals below. A genuine Windows path never
/// contains these; this closes a command-injection vector where a non-admin sets
/// a hostile `KINTSUGI_DATA_DIR` and an admin later runs enforce-shell.
#[cfg(not(unix))]
fn reject_unsafe_shim(shim: &str) -> Result<()> {
    if shim.contains(['\'', '"', ';', '`', '$', '&', '|', '\n', '\r']) {
        anyhow::bail!(
            "refusing to enforce: the shim path contains unsafe characters ({shim}).\n  \
             Set a clean KINTSUGI_DATA_DIR and re-run."
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn windows_install(shim: &Path) -> Result<Vec<PathBuf>> {
    let shim = shim.display().to_string();
    reject_unsafe_shim(&shim)?;
    let script = format!(
        "$m=[Environment]::GetEnvironmentVariable('Path','Machine'); \
         if($m -notlike '*{shim}*'){{[Environment]::SetEnvironmentVariable('Path','{shim};'+$m,'Machine')}}"
    );
    let status = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .status()
        .context("set machine PATH via PowerShell")?;
    if !status.success() {
        anyhow::bail!(
            "could not set the machine PATH — system-level enforcement needs an elevated \
             (Administrator) shell."
        );
    }
    Ok(vec![PathBuf::from("HKLM\\…\\Environment\\Path (machine)")])
}

#[cfg(not(unix))]
fn windows_uninstall() -> Result<Vec<PathBuf>> {
    let script = "$m=[Environment]::GetEnvironmentVariable('Path','Machine'); \
         $p=($m -split ';' | Where-Object {$_ -notlike '*kintsugi*'}) -join ';'; \
         [Environment]::SetEnvironmentVariable('Path',$p,'Machine')";
    let status = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", script])
        .status()
        .context("update machine PATH via PowerShell")?;
    if !status.success() {
        anyhow::bail!("could not update the machine PATH — run from an elevated shell.");
    }
    Ok(vec![PathBuf::from("HKLM\\…\\Environment\\Path (machine)")])
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Point enforcement at a temp `/etc` for the duration of a test.
    fn with_etc<T>(etc: &Path, f: impl FnOnce() -> T) -> T {
        let _g = env_lock();
        std::env::set_var("KINTSUGI_ETC_DIR", etc);
        let out = f();
        std::env::remove_var("KINTSUGI_ETC_DIR");
        out
    }

    #[test]
    fn install_writes_zshenv_and_profile_then_uninstall_removes_them() {
        let tmp = tempfile::tempdir().unwrap();
        let etc = tmp.path();
        let shim = Path::new("/opt/kintsugi/shims");
        with_etc(etc, || {
            assert!(!is_enforced());
            install(shim).unwrap();
            assert!(is_enforced());

            // zshenv carries the managed block with the shim path.
            let zshenv = std::fs::read_to_string(etc.join("zshenv")).unwrap();
            assert!(zshenv.contains(BEGIN));
            assert!(zshenv.contains("/opt/kintsugi/shims"));
            // No profile.d dir here → the block lands in /etc/profile.
            assert!(std::fs::read_to_string(etc.join("profile"))
                .unwrap()
                .contains(BEGIN));

            uninstall().unwrap();
            assert!(!is_enforced());
        });
    }

    #[test]
    fn install_preserves_existing_file_contents() {
        let tmp = tempfile::tempdir().unwrap();
        let etc = tmp.path();
        std::fs::write(
            etc.join("zshenv"),
            "# user's own zshenv\nexport EDITOR=vim\n",
        )
        .unwrap();
        with_etc(etc, || {
            install(Path::new("/k/shims")).unwrap();
            let body = std::fs::read_to_string(etc.join("zshenv")).unwrap();
            assert!(
                body.contains("export EDITOR=vim"),
                "pre-existing content kept"
            );
            assert!(body.contains(BEGIN));
            uninstall().unwrap();
            let body = std::fs::read_to_string(etc.join("zshenv")).unwrap();
            assert!(
                body.contains("export EDITOR=vim"),
                "content kept after removal"
            );
            assert!(!body.contains(BEGIN), "managed block removed");
        });
    }

    #[test]
    fn install_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let etc = tmp.path();
        with_etc(etc, || {
            install(Path::new("/k/shims")).unwrap();
            install(Path::new("/k/shims")).unwrap();
            let body = std::fs::read_to_string(etc.join("zshenv")).unwrap();
            assert_eq!(body.matches(BEGIN).count(), 1, "block must not duplicate");
        });
    }

    #[test]
    fn uses_profile_d_dropin_when_the_dir_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let etc = tmp.path();
        std::fs::create_dir_all(etc.join("profile.d")).unwrap();
        with_etc(etc, || {
            install(Path::new("/k/shims")).unwrap();
            assert!(etc.join("profile.d/kintsugi.sh").is_file());
            assert!(
                !etc.join("profile").exists(),
                "profile untouched when profile.d exists"
            );
            uninstall().unwrap();
            assert!(!etc.join("profile.d/kintsugi.sh").exists());
        });
    }
}
