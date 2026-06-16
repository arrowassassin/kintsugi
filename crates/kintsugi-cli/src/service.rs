//! `kintsugi service` — run the daemon under an OS supervisor that **auto-restarts
//! it**, so a `kill`/`pkill` isn't permanent.
//!
//! This is the layer that answers "if pkill can kill it, what's the use?": with a
//! systemd/launchd unit configured to restart-always, a killed daemon relaunches
//! within seconds, and *disabling* the supervisor (the only way to keep it dead)
//! is a privileged operation. Combined with running as a dedicated system account
//! (the locked system posture), a non-root user/agent genuinely cannot stop it;
//! root still can, but only by disabling the unit — visibly. Honest, not absolute.
//!
//! `service uninstall` (and disabling autostart) is gated by the admin password
//! when the settings are locked.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

#[allow(dead_code)] // used on macOS + in tests; dead in the Linux bin build
const LAUNCHD_LABEL: &str = "com.kintsugi.daemon";

/// The systemd unit text (auto-restart). Pure so it can be unit-tested.
#[allow(dead_code)] // used on Linux + in tests; dead in the macOS/Windows bin build
pub fn systemd_unit(daemon_exe: &Path) -> String {
    format!(
        "[Unit]\n\
         Description=Kintsugi safety daemon\n\
         After=default.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={exe}\n\
         Restart=always\n\
         RestartSec=2\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        exe = daemon_exe.display()
    )
}

/// The launchd LaunchAgent plist text (KeepAlive = auto-restart). Pure.
#[allow(dead_code)] // used on macOS + in tests; dead in the Linux bin build
pub fn launchd_plist(daemon_exe: &Path) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \t<key>Label</key><string>{label}</string>\n\
         \t<key>ProgramArguments</key>\n\
         \t<array><string>{exe}</string></array>\n\
         \t<key>KeepAlive</key><true/>\n\
         \t<key>RunAtLoad</key><true/>\n\
         </dict>\n\
         </plist>\n",
        label = LAUNCHD_LABEL,
        exe = daemon_exe.display()
    )
}

/// Resolve the `kintsugi-daemon` executable (sibling of the running `kintsugi`).
fn daemon_exe() -> Result<PathBuf> {
    let me = std::env::current_exe().context("locate the running kintsugi binary")?;
    let dir = me.parent().context("kintsugi binary has no parent dir")?;
    let name = if cfg!(windows) {
        "kintsugi-daemon.exe"
    } else {
        "kintsugi-daemon"
    };
    let candidate = dir.join(name);
    if candidate.exists() {
        Ok(candidate)
    } else {
        // Fall back to a bare name (rely on PATH) so a split install still works.
        Ok(PathBuf::from(name))
    }
}

#[cfg(target_os = "linux")]
fn unit_path() -> Result<PathBuf> {
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("HOME").map(|h| PathBuf::from(h).join(".config")))
        .context("no HOME/XDG_CONFIG_HOME for the systemd user unit")?;
    Ok(base.join("systemd/user/kintsugi.service"))
}

#[cfg(target_os = "macos")]
fn unit_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("no HOME for the LaunchAgent")?;
    Ok(PathBuf::from(home).join(format!("Library/LaunchAgents/{LAUNCHD_LABEL}.plist")))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn unit_path() -> Result<PathBuf> {
    anyhow::bail!("`kintsugi service` is supported on Linux (systemd) and macOS (launchd) for now");
}

/// `kintsugi service install` — write the auto-restart unit and enable it.
#[allow(unreachable_code)] // the unsupported-OS arm `bail!`s, making the tail unreachable there
pub fn install() -> Result<()> {
    let exe = daemon_exe()?;
    let path = unit_path()?;
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }

    #[cfg(target_os = "linux")]
    {
        std::fs::write(&path, systemd_unit(&exe))?;
        println!("✓ wrote {}", path.display());
        run("systemctl", &["--user", "daemon-reload"]);
        run(
            "systemctl",
            &["--user", "enable", "--now", "kintsugi.service"],
        );
        println!(
            "  Kintsugi runs under systemd with Restart=always — a kill relaunches it.\n  \
             For a kill a non-root user can't do, install as a system service running\n  \
             as a dedicated `kintsugi` account (see docs/service.md)."
        );
    }
    #[cfg(target_os = "macos")]
    {
        std::fs::write(&path, launchd_plist(&exe))?;
        println!("✓ wrote {}", path.display());
        let target = format!("gui/{}", current_uid());
        run(
            "launchctl",
            &["bootstrap", &target, &path.to_string_lossy()],
        );
        println!("  Kintsugi runs under launchd with KeepAlive — a kill relaunches it.");
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = exe;
        anyhow::bail!("`kintsugi service` is supported on Linux and macOS for now");
    }
    Ok(())
}

/// `kintsugi service uninstall` — disable + remove the unit. Gated by the admin
/// password when settings are locked (disabling the watchdog is privileged).
pub fn uninstall() -> Result<()> {
    if !crate::admin_cmd::allow_stop() {
        return Ok(());
    }
    do_uninstall()
}

/// Install without prompting — used by `admin set autostart on`, where the caller
/// has already authenticated with the admin password.
pub fn install_unattended() -> Result<()> {
    install()
}

/// Uninstall without the password gate — used by `admin set autostart off`, where
/// the caller has already authenticated. (The gate exists to stop an *unauthed*
/// disable; here we are past it.)
pub fn uninstall_unattended() -> Result<()> {
    do_uninstall()
}

fn do_uninstall() -> Result<()> {
    let path = unit_path()?;
    #[cfg(target_os = "linux")]
    {
        run(
            "systemctl",
            &["--user", "disable", "--now", "kintsugi.service"],
        );
    }
    #[cfg(target_os = "macos")]
    {
        let target = format!("gui/{}/{LAUNCHD_LABEL}", current_uid());
        run("launchctl", &["bootout", &target]);
    }
    let existed = std::fs::remove_file(&path).is_ok();
    println!(
        "✓ kintsugi service removed{}",
        if existed { "" } else { " (was not installed)" }
    );
    Ok(())
}

/// `kintsugi service status` — whether the unit file is present.
pub fn status() -> Result<()> {
    let path = unit_path()?;
    if path.exists() {
        println!("service: installed ({})", path.display());
        println!("  auto-restart is on — a killed daemon relaunches.");
    } else {
        println!("service: not installed");
        println!("  Run `kintsugi service install` so a kill/pkill auto-relaunches it.");
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run(cmd: &str, args: &[&str]) {
    let ok = std::process::Command::new(cmd)
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        eprintln!(
            "  note: `{cmd} {}` did not succeed (run it manually if needed)",
            args.join(" ")
        );
    }
}

/// Current uid via `id -u` (avoids an unsafe libc call; the crate forbids unsafe).
#[cfg(target_os = "macos")]
fn current_uid() -> String {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn systemd_unit_has_auto_restart() {
        let u = systemd_unit(Path::new("/usr/local/bin/kintsugi-daemon"));
        assert!(u.contains("ExecStart=/usr/local/bin/kintsugi-daemon"));
        assert!(u.contains("Restart=always"));
        assert!(u.contains("WantedBy=default.target"));
    }

    #[test]
    fn launchd_plist_has_keepalive() {
        let p = launchd_plist(Path::new("/opt/kintsugi/kintsugi-daemon"));
        assert!(p.contains("<key>KeepAlive</key><true/>"));
        assert!(p.contains("<string>/opt/kintsugi/kintsugi-daemon</string>"));
        assert!(p.contains(LAUNCHD_LABEL));
        assert!(p.starts_with("<?xml"));
    }
}
