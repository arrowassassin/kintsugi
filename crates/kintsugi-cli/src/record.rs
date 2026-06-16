//! `kintsugi record` — passive session recording with **no AI-agent hook**.
//!
//! A shell preexec hook calls `kintsugi ingest` on every command a human runs,
//! so a DBA / operator gets the same tamper-evident, classified audit trail
//! Kintsugi keeps for agents — without any command being blocked. This is an
//! *after-the-fact recorder*, not a gate: by the time we hear about a command it
//! has already run, so we classify it (to flag destructive actions in the
//! timeline and `kintsugi report`) but never hold, deny, or snapshot it.
//!
//! Honest guarantee: this preserves "a tamper-evident record of everything,"
//! NOT "nothing runs un-warned" — the latter never applied to commands a person
//! typed outside Kintsugi. To keep the record complete across daemon restarts,
//! `ingest` **spools** to a local file when the daemon is down and drains it on
//! the next successful ingest, so a brief daemon outage doesn't punch a hole in
//! the audit trail.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use kintsugi_core::ProposedCommand;
use kintsugi_daemon::{default_db_path, Client};

/// The combined bash/zsh hook. Auto-detects the shell so a single snippet works
/// appended to either `~/.bashrc` or `~/.zshrc`.
const HOOK: &str = r#"# >>> kintsugi session recorder >>>
# Records every command you run to Kintsugi's tamper-evident audit log.
# Passive: nothing is blocked. Remove this block to stop recording.
_kintsugi_record() {
  command kintsugi ingest --cwd "$PWD" -- "$1" >/dev/null 2>&1 &
}
if [ -n "$ZSH_VERSION" ]; then
  autoload -Uz add-zsh-hook 2>/dev/null && add-zsh-hook preexec _kintsugi_record
elif [ -n "$BASH_VERSION" ]; then
  _kintsugi_record_bash() {
    [ -n "$COMP_LINE" ] && return
    [ "$BASH_COMMAND" = "$PROMPT_COMMAND" ] && return
    _kintsugi_record "$BASH_COMMAND"
  }
  trap '_kintsugi_record_bash' DEBUG
fi
# <<< kintsugi session recorder <<<"#;

/// The spool file holding commands that couldn't reach the daemon yet (one
/// serialized [`ProposedCommand`] per line). Lives next to the event log.
pub fn spool_path() -> PathBuf {
    default_db_path().with_file_name("record-spool.jsonl")
}

/// `kintsugi record install` — print the shell hook to source from rc.
pub fn install() -> Result<()> {
    // Print to stdout so it composes with a redirect: `… install >> ~/.bashrc`.
    // We never edit the user's rc ourselves — that's their file to own.
    println!("{HOOK}");
    eprintln!(
        "# Appended nothing yet — pipe this into your shell rc, e.g.:\n\
         #   kintsugi record install >> ~/.bashrc   # or ~/.zshrc\n\
         # then restart your shell. Verify with `kintsugi record status`."
    );
    Ok(())
}

/// `kintsugi record uninstall` — explain how to remove the hook.
pub fn uninstall() -> Result<()> {
    println!(
        "To stop recording, delete the block between\n  \
         '# >>> kintsugi session recorder >>>' and '# <<< kintsugi session recorder <<<'\n  \
         from your shell rc (~/.bashrc or ~/.zshrc), then restart your shell."
    );
    Ok(())
}

/// `kintsugi record status` — daemon reachability + any spooled backlog.
pub fn status() -> Result<()> {
    let running = Client::is_daemon_running();
    if running {
        println!("recorder: daemon is up — commands are recorded live.");
    } else {
        println!("recorder: daemon is DOWN — commands are spooled until it returns.");
    }
    let spool = spool_path();
    let depth = spool_depth(&spool);
    if depth > 0 {
        println!(
            "  spool: {depth} command(s) waiting at {} (drained on the next ingest).",
            spool.display()
        );
    } else {
        println!("  spool: empty.");
    }
    println!("  Install the shell hook with `kintsugi record install >> ~/.bashrc` (or ~/.zshrc).");
    Ok(())
}

/// `kintsugi ingest` — record one already-run command. Fire-and-forget: it must
/// never fail the caller's shell, so every error path is swallowed and it always
/// returns `Ok`. When the daemon is reachable it first drains any spool (so the
/// audit trail is replayed in order) and then records this command live;
/// otherwise it appends to the spool.
pub fn ingest(command: &str, cwd: Option<PathBuf>) -> Result<()> {
    let command = command.trim();
    if command.is_empty() {
        return Ok(());
    }
    let cwd = cwd.unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    let cmd = ProposedCommand::new("shell", cwd, kintsugi_core::shell::split(command), command);

    if Client::is_daemon_running() {
        drain_spool();
        // Best-effort: if the live record fails (daemon raced down), spool it so
        // it isn't lost. Never surface the error to the shell.
        if Client::record(&cmd).is_err() {
            let _ = append_spool(&cmd);
        }
    } else {
        let _ = append_spool(&cmd);
    }
    Ok(())
}

/// Append one command to the spool (newline-delimited JSON), best-effort.
fn append_spool(cmd: &ProposedCommand) -> Result<()> {
    let path = spool_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let mut line = serde_json::to_string(cmd).context("serialize spooled command")?;
    line.push('\n');
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("open spool {}", path.display()))?;
    // Keep the spool owner-only — it holds verbatim commands (already redacted at
    // log time, but raw on the way in).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    f.write_all(line.as_bytes())
        .with_context(|| format!("write spool {}", path.display()))?;
    Ok(())
}

/// Drain the spool into the daemon, in order. Claims the file by renaming it
/// first (so concurrent ingests don't double-record), then replays each line;
/// any lines that still fail are written back to the spool.
fn drain_spool() {
    let path = spool_path();
    if !path.exists() {
        return;
    }
    // Atomically claim the backlog: rename to a unique temp so a second ingest
    // racing us picks up a fresh (empty) spool rather than the same lines.
    let claimed = path.with_extension(format!("jsonl.draining.{}", std::process::id()));
    if std::fs::rename(&path, &claimed).is_err() {
        return; // another ingest is draining, or nothing to do.
    }
    let contents = match std::fs::read_to_string(&claimed) {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut unsent: Vec<String> = Vec::new();
    for line in contents.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<ProposedCommand>(line) {
            Ok(cmd) => {
                if Client::record(&cmd).is_err() {
                    unsent.push(line.to_string());
                }
            }
            // Unparseable line: keep it rather than silently drop audit data.
            Err(_) => unsent.push(line.to_string()),
        }
    }
    let _ = std::fs::remove_file(&claimed);
    // Anything that still didn't land goes back onto the live spool.
    if !unsent.is_empty() {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = f.write_all((unsent.join("\n") + "\n").as_bytes());
        }
    }
}

/// Count spooled commands (lines) — best-effort; 0 if the file is absent.
fn spool_depth(path: &Path) -> usize {
    std::fs::read_to_string(path)
        .map(|c| c.lines().filter(|l| !l.trim().is_empty()).count())
        .unwrap_or(0)
}
