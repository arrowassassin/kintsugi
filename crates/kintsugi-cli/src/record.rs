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
  case "$1" in
    *kintsugi\ ingest*|kintsugi\ ingest*) return ;;   # never record our own plumbing
  esac
  command kintsugi ingest --cwd "$PWD" -- "$1" >/dev/null 2>&1 &
}
if [ -n "$ZSH_VERSION" ]; then
  autoload -Uz add-zsh-hook 2>/dev/null && add-zsh-hook preexec _kintsugi_record
elif [ -n "$BASH_VERSION" ]; then
  _kintsugi_record_bash() {
    [ -n "$COMP_LINE" ] && return                     # skip completion
    [ -n "$_KINTSUGI_IN_PROMPT" ] && return           # skip PROMPT_COMMAND hooks
    case "$BASH_COMMAND" in _kintsugi_*) return ;; esac
    _kintsugi_record "$BASH_COMMAND"
  }
  # Mark the prompt window so the DEBUG trap ignores PROMPT_COMMAND's own commands.
  PROMPT_COMMAND="_KINTSUGI_IN_PROMPT=1${PROMPT_COMMAND:+; $PROMPT_COMMAND}; _KINTSUGI_IN_PROMPT="
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
/// returns `Ok`. Records the command live; on success it also drains any spooled
/// backlog. If the daemon is down it appends to the spool for later.
pub fn ingest(command: &str, cwd: Option<PathBuf>) -> Result<()> {
    let command = command.trim();
    if command.is_empty() {
        return Ok(());
    }
    let cwd = cwd.unwrap_or_else(|| std::env::current_dir().unwrap_or_default());

    // Redact command-line secrets up front, so a credential never travels the
    // socket *or* lands in the on-disk spool in the clear (the daemon also
    // redacts at log time; this makes the recorder path safe at every hop).
    let red = kintsugi_core::redact::redact_command(command);
    let (text, argv) = if red.any() {
        (red.text.clone(), kintsugi_core::shell::split(&red.text))
    } else {
        (command.to_string(), kintsugi_core::shell::split(command))
    };
    let cmd = ProposedCommand::new("shell", cwd, argv, text);

    // One connection on the happy path: try to record live; if that lands, also
    // drain any backlog; if it fails (daemon down), spool for later. No separate
    // liveness probe (it was a second, redundant connect per command).
    if Client::record(&cmd).is_ok() {
        drain_spool();
    } else {
        let _ = append_spool(&cmd);
    }
    Ok(())
}

/// Append one command to the spool (newline-delimited JSON), best-effort. The
/// file is created `0600` atomically (mode at open, not a chmod-after-create, so
/// there is no world-readable window), and the spooled command is already
/// redacted by `ingest`, so no secret is ever written to disk in the clear.
fn append_spool(cmd: &ProposedCommand) -> Result<()> {
    let path = spool_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let mut line = serde_json::to_string(cmd).context("serialize spooled command")?;
    line.push('\n');
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&path)
        .with_context(|| format!("open spool {}", path.display()))?;
    f.write_all(line.as_bytes())
        .with_context(|| format!("write spool {}", path.display()))?;
    Ok(())
}

/// Drain the spool into the daemon, in order. Claims the file by renaming it
/// first (so concurrent ingests don't double-record), then replays each line;
/// any lines that still fail are written back to the spool.
fn drain_spool() {
    // First, re-adopt any *stale* `.draining.*` files left by a process that
    // crashed mid-drain (after the rename-claim, before write-back), folding them
    // back into the live spool so those events aren't orphaned. "Stale" = older
    // than 60s, so we never steal a concurrent drainer's in-flight file.
    adopt_orphaned_draining();

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

/// Count spooled commands (lines) across the live spool AND any leftover
/// `.draining.*` files — best-effort; 0 when nothing is pending. Counting the
/// draining files too means a crash mid-drain doesn't report a false "empty".
fn spool_depth(path: &Path) -> usize {
    let count = |p: &Path| {
        std::fs::read_to_string(p)
            .map(|c| c.lines().filter(|l| !l.trim().is_empty()).count())
            .unwrap_or(0)
    };
    let mut total = count(path);
    for f in draining_files(path) {
        total += count(&f);
    }
    total
}

/// All `record-spool.jsonl.draining.*` files next to the spool (orphans from a
/// crashed drain, or a concurrent drainer's in-flight file).
fn draining_files(spool: &Path) -> Vec<PathBuf> {
    let Some(dir) = spool.parent() else {
        return Vec::new();
    };
    let Some(name) = spool.file_name().and_then(|n| n.to_str()) else {
        return Vec::new();
    };
    let prefix = format!("{name}.draining.");
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    rd.flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(&prefix))
        })
        .collect()
}

/// Fold stale (>60s old) `.draining.*` orphans back into the live spool so a
/// crash mid-drain doesn't lose those events. The age gate avoids stealing a
/// concurrent drainer's in-flight file.
fn adopt_orphaned_draining() {
    let spool = spool_path();
    let now = std::time::SystemTime::now();
    for f in draining_files(&spool) {
        let stale = std::fs::metadata(&f)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| now.duration_since(t).ok())
            .is_some_and(|age| age.as_secs() > 60);
        if !stale {
            continue;
        }
        if let Ok(body) = std::fs::read_to_string(&f) {
            if !body.trim().is_empty() {
                if let Ok(mut s) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&spool)
                {
                    let _ = s.write_all(body.as_bytes());
                }
            }
        }
        let _ = std::fs::remove_file(&f);
    }
}
