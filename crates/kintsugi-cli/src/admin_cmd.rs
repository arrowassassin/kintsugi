//! `kintsugi admin` — provision/manage the password-locked settings, and the
//! gate that makes stopping Kintsugi require the admin password.
//!
//! Honest scope (see the design doc threat matrix): this defeats an AI agent or a
//! normal user running `kintsugi stop` / `kintsugi admin …` without the password —
//! the 90% case. It does **not** stop a root user, who can `kill` the daemon PID
//! directly; the watchdog (relaunch) and daemon-side IPC enforcement are the
//! stronger follow-on tiers. We make a forced stop harder and (later) visible,
//! never claim it's impossible.
//!
//! Known limitation of this CLI tier: the vault location honors `KINTSUGI_VAULT`,
//! so an actor that controls the *environment* of the `kintsugi` process it
//! spawns can point the gate at an empty vault and bypass the prompt. This is the
//! same class of power as `kill`, and it is mitigated the same way: with the
//! auto-restart **watchdog** installed, the daemon a bypassed `stop` kills simply
//! relaunches — turning a forced stop into a logged, recoverable event rather than
//! a silent kill. The real fix (deferred) is daemon-side IPC authentication, where
//! the *daemon* — started by the admin/systemd, not the agent — owns the vault
//! path and the agent's environment is irrelevant.

use std::io::{Read, Write};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use kintsugi_core::admin::{self, Enforcement, LockedSettings, VaultState};

/// Where the sealed admin vault lives (see [`admin::default_vault_path`]).
pub fn vault_path() -> PathBuf {
    admin::default_vault_path()
}

const MIN_PASSWORD_LEN: usize = 8;

/// `kintsugi admin provision` — set the admin password and lock the settings.
pub fn provision(password_file: Option<PathBuf>, force: bool) -> Result<()> {
    let path = vault_path();
    if let VaultState::Locked(_) = admin::load_vault(&path) {
        if !force {
            bail!(
                "already provisioned at {}\n  Use --force to re-provision (rotates the password and recovery key).",
                path.display()
            );
        }
    }
    let pw = read_password("Set admin password: ", &password_file)?;
    if pw.chars().count() < MIN_PASSWORD_LEN {
        bail!("password too short (minimum {MIN_PASSWORD_LEN} characters)");
    }
    if password_file.is_none() {
        let confirm = read_password_tty("Confirm admin password: ")?;
        if pw != confirm {
            bail!("passwords did not match");
        }
    }
    let settings = LockedSettings::default();
    let prov = admin::provision(&pw, &settings).map_err(|e| anyhow::anyhow!("{e}"))?;
    admin::save_vault(&path, &prov.vault)
        .with_context(|| format!("write vault {}", path.display()))?;
    // Keep the daemon-free fail-closed marker in sync with the sealed setting, so
    // the shim/hook honor it even with the daemon down (default: off).
    let _ = kintsugi_daemon::set_fail_closed_marker(settings.fail_closed);

    println!("✓ Kintsugi is now admin-locked — stopping or disabling it requires this password.");
    println!("  vault: {}", path.display());
    println!();
    println!("  RECOVERY KEY — store this offline. It is shown ONCE and cannot be");
    println!("  recovered. It can unlock the settings if the password is lost:");
    println!();
    println!("    {}", prov.recovery_key);
    println!();
    Ok(())
}

/// `kintsugi admin status` — show the lock state (no password needed).
pub fn status() -> Result<()> {
    match admin::load_vault(&vault_path()) {
        VaultState::Unprovisioned => {
            println!("admin lock: not provisioned (unlocked)");
            println!("  Run `kintsugi admin provision` to lock settings behind a password.");
        }
        VaultState::Locked(_) => {
            println!("admin lock: LOCKED");
            println!("  Stopping / disabling Kintsugi requires the admin password.");
        }
        VaultState::Degraded(reason) => {
            println!("admin lock: DEGRADED — {reason}");
            println!("  Privileged operations are refused until the vault is restored or");
            println!("  you re-provision with `--force` (using the recovery key offline).");
        }
    }
    Ok(())
}

/// `kintsugi admin change-password`.
pub fn change_password() -> Result<()> {
    let path = vault_path();
    let vault = match admin::load_vault(&path) {
        VaultState::Locked(v) => *v,
        VaultState::Unprovisioned => bail!("not provisioned — nothing to change"),
        VaultState::Degraded(r) => bail!("vault is degraded ({r}); restore or re-provision first"),
    };
    let old = read_password_tty("Current admin password: ")?;
    let new = read_password_tty("New admin password: ")?;
    if new.chars().count() < MIN_PASSWORD_LEN {
        bail!("password too short (minimum {MIN_PASSWORD_LEN} characters)");
    }
    let confirm = read_password_tty("Confirm new password: ")?;
    if new != confirm {
        bail!("new passwords did not match");
    }
    let prov = vault
        .change_password(&old, &new)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    admin::save_vault(&path, &prov.vault)?;
    println!("✓ Admin password changed.");
    println!();
    println!("  NEW RECOVERY KEY (the previous one no longer works):");
    println!();
    println!("    {}", prov.recovery_key);
    println!();
    Ok(())
}

/// `kintsugi admin settings` — show the locked settings. Sealed, so it needs the
/// admin password to decrypt (confidentiality is part of the lock).
pub fn settings(password_file: Option<PathBuf>) -> Result<()> {
    let vault = match admin::load_vault(&vault_path()) {
        VaultState::Locked(v) => *v,
        VaultState::Unprovisioned => {
            println!("Not provisioned — settings are at their defaults (unlocked).");
            print_settings(&LockedSettings::default());
            return Ok(());
        }
        VaultState::Degraded(r) => bail!("vault is degraded ({r}); restore or re-provision first"),
    };
    let pw = read_password("Admin password to read settings: ", &password_file)?;
    let s = vault
        .unseal(&pw)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("decrypt settings")?;
    print_settings(&s);
    Ok(())
}

/// `kintsugi admin set <key> <value>` — change one locked setting (password-gated).
///
/// Spine #1/#2: every setting is a *tightening* control, so changing one can only
/// add caution — there is deliberately no key that unlocks the catastrophic floor.
pub fn set(key: &str, value: &str, password_file: Option<PathBuf>) -> Result<()> {
    let path = vault_path();
    let vault = match admin::load_vault(&path) {
        VaultState::Locked(v) => *v,
        VaultState::Unprovisioned => {
            bail!(
                "not provisioned — run `kintsugi admin provision` before changing locked settings"
            )
        }
        VaultState::Degraded(r) => bail!("vault is degraded ({r}); restore or re-provision first"),
    };
    let pw = read_password("Admin password to change settings: ", &password_file)?;
    let mut s = vault
        .unseal(&pw)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("decrypt settings")?;

    apply_setting(&mut s, key, value)?;

    let updated = vault
        .update_settings(&pw, &s)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    admin::save_vault(&path, &updated)?;
    println!("✓ {key} updated.");
    print_settings(&s);

    // The autostart flag drives a real action: install/remove the OS supervisor
    // so the setting isn't a dead toggle. Best-effort + logged by `service`.
    if key.eq_ignore_ascii_case("autostart") {
        let _ = if s.autostart {
            crate::service::install_unattended()
        } else {
            crate::service::uninstall_unattended()
        };
    }
    Ok(())
}

/// Mutate one field of `LockedSettings` from a `key`/`value` pair.
fn apply_setting(s: &mut LockedSettings, key: &str, value: &str) -> Result<()> {
    let on = parse_bool(value);
    match key.to_ascii_lowercase().replace('_', "-").as_str() {
        "recording" => s.recording = on?,
        "autostart" => s.autostart = on?,
        "require-password-to-stop" => s.require_password_to_stop = on?,
        "fail-closed" => s.fail_closed = on?,
        "enforcement" => {
            s.enforcement = match value.to_ascii_lowercase().as_str() {
                "attended" => Enforcement::Attended,
                "unattended" => Enforcement::Unattended,
                "notify" => Enforcement::Notify,
                other => bail!("invalid enforcement '{other}' (attended|unattended|notify)"),
            }
        }
        other => bail!(
            "unknown setting '{other}'\n  keys: recording, autostart, require-password-to-stop, \
             fail-closed (on|off); enforcement (attended|unattended|notify)"
        ),
    }
    Ok(())
}

/// Parse a boolean toggle: on/off, true/false, yes/no, 1/0.
fn parse_bool(value: &str) -> Result<bool> {
    match value.to_ascii_lowercase().as_str() {
        "on" | "true" | "yes" | "1" | "enable" | "enabled" => Ok(true),
        "off" | "false" | "no" | "0" | "disable" | "disabled" => Ok(false),
        other => bail!("expected on|off (got '{other}')"),
    }
}

/// Render the settings as a labelled block (text, never color-only).
fn print_settings(s: &LockedSettings) {
    let yn = |b: bool| if b { "on" } else { "off" };
    let mode = match s.enforcement {
        Enforcement::Attended => "attended (holds for approval)",
        Enforcement::Unattended => "unattended (denies / queues)",
        Enforcement::Notify => "notify (records, doesn't block)",
    };
    println!("locked settings:");
    println!("  recording                 {}", yn(s.recording));
    println!("  autostart                 {}", yn(s.autostart));
    println!(
        "  require-password-to-stop  {}",
        yn(s.require_password_to_stop)
    );
    println!("  fail-closed               {}", yn(s.fail_closed));
    println!("  enforcement               {mode}");
}

/// Whether `kintsugi stop` is allowed to proceed. Unprovisioned → yes; Locked →
/// only with the correct password; Degraded → refuse (fail-closed).
pub fn allow_stop() -> bool {
    allow_admin("Admin password to stop Kintsugi: ")
}

/// Gate an admin action behind the locked vault: allow when unprovisioned, refuse
/// when degraded, and require the admin password when locked. Shared by `stop` and
/// by removing the enforced shell wiring, so both honor the same lock.
pub fn allow_admin(prompt: &str) -> bool {
    match admin::load_vault(&vault_path()) {
        VaultState::Unprovisioned => true,
        VaultState::Degraded(reason) => {
            eprintln!(
                "kintsugi: admin vault is degraded ({reason}); refusing.\n  \
                 Restore the vault, or re-provision with the recovery key."
            );
            false
        }
        VaultState::Locked(vault) => match read_password_tty(prompt) {
            Ok(pw) if vault.verify_password(&pw) => true,
            Ok(_) => {
                eprintln!("kintsugi: wrong admin password.");
                false
            }
            Err(e) => {
                eprintln!("kintsugi: {e}");
                false
            }
        },
    }
}

/// Prompt for the admin password on the controlling terminal (echo off). Used by
/// the daemon shutdown handshake; the value is sent only as a derived proof.
pub fn read_admin_password(prompt: &str) -> Result<String> {
    read_password_tty(prompt)
}

/// Read a password from a file (trailing newline trimmed) or interactively.
fn read_password(prompt: &str, file: &Option<PathBuf>) -> Result<String> {
    if let Some(f) = file {
        let s = std::fs::read_to_string(f)
            .with_context(|| format!("read password file {}", f.display()))?;
        return Ok(s.trim_end_matches(['\n', '\r']).to_string());
    }
    read_password_tty(prompt)
}

/// Read a line from the real terminal with echo disabled. Reads `/dev/tty`, not
/// stdin, so an agent with piped stdio can't feed the password and a recorder
/// can't capture it from the command line.
///
/// If echo cannot be disabled we **refuse to read** rather than prompt with echo
/// on (which would leak the password to the screen, scrollback, and any session
/// recorder). The whole line is read (no 512-byte truncation), and the byte
/// buffer is zeroized.
pub(crate) fn read_password_tty(prompt: &str) -> Result<String> {
    use zeroize::Zeroizing;
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("no terminal for password entry — use --password-file")?;
    write!(tty, "{prompt}")?;
    tty.flush()?;

    if !set_echo(false) {
        let _ = writeln!(tty);
        bail!("could not disable terminal echo for password entry — use --password-file");
    }

    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    let mut chunk = [0u8; 256];
    let read_result = loop {
        match tty.read(&mut chunk) {
            Ok(0) => break Ok(()),
            Ok(n) => {
                if let Some(pos) = chunk[..n].iter().position(|&b| b == b'\n') {
                    buf.extend_from_slice(&chunk[..pos]);
                    break Ok(());
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > 4096 {
                    break Ok(()); // sane bound; a password this long is enough
                }
            }
            Err(e) => break Err(e),
        }
    };
    // Always restore echo, whatever happened.
    set_echo(true);
    let _ = writeln!(tty);
    read_result.context("read password from terminal")?;

    let line = String::from_utf8_lossy(&buf);
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

/// Toggle terminal echo on the controlling tty (so the password isn't shown).
/// Returns whether the change was applied — the caller must NOT read a password
/// when disabling echo failed.
#[cfg(unix)]
fn set_echo(on: bool) -> bool {
    let Ok(tty) = std::fs::File::open("/dev/tty") else {
        return false;
    };
    std::process::Command::new("stty")
        .arg(if on { "echo" } else { "-echo" })
        .stdin(tty)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
#[cfg(not(unix))]
fn set_echo(_on: bool) -> bool {
    false
}
