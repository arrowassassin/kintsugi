//! `kintsugi record` — passive session recording with **no AI-agent hook**.
//!
//! A shell preexec hook calls `kintsugi ingest` on every command a human runs,
//! so a DBA / operator gets the same tamper-evident, classified audit trail
//! Kintsugi keeps for agents — without any command being blocked. This is an
//! recorder, not a gate: it never holds or denies a human's command. It does
//! classify each one (to flag destructive actions in the timeline and
//! `kintsugi report`), and — because the preexec hook fires *before* the command
//! runs — the daemon snapshots destructive commands just-in-time so `kintsugi
//! undo` can recover a human's mistake (the recoverer).
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
  # Run detached in a subshell so the interactive shell never prints job-control
  # notices ("[1] 12345" / "[1]  + done …") for our fire-and-forget recorder.
  ( command kintsugi ingest --cwd "$PWD" -- "$1" >/dev/null 2>&1 & )
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

/// The fence markers delimiting Kintsugi's managed block in an rc file. They are
/// the first/last lines of [`HOOK`], so install can idempotently replace the block.
const FENCE_BEGIN: &str = "# >>> kintsugi session recorder >>>";
const FENCE_END: &str = "# <<< kintsugi session recorder <<<";

/// Gated variant of the recorder hook. Same fences as `HOOK`, so it cleanly
/// replaces the passive block on a re-install. Synchronously runs the gate
/// before each command — describes (model summary), confirms risky, declines
/// catastrophic. The gate itself fails open (daemon down / no TTY → exit 0).
///
/// zsh: rebinds Enter (`^M`) to a ZLE widget that runs the gate, then either
/// `.accept-line`s the buffer or clears it. bash: enables `extdebug` so a
/// nonzero DEBUG trap return prevents the next command from running.
const HOOK_GATE: &str = r#"# >>> kintsugi session recorder >>>
# GATED recorder: describes every command and asks before running risky ones.
# Tier-1 safe stays silent. Remove this block to stop gating + recording.
_kintsugi_skip() {
  case "$1" in
    *kintsugi*|"") return 0 ;;
  esac
  return 1
}
if [ -n "$ZSH_VERSION" ]; then
  _kintsugi_gate_accept() {
    local cmd="$BUFFER"
    if _kintsugi_skip "$cmd"; then
      zle .accept-line
      return
    fi
    if command kintsugi ingest --gate --cwd "$PWD" -- "$cmd"; then
      zle .accept-line
    else
      BUFFER=""
      zle reset-prompt
    fi
  }
  zle -N _kintsugi_gate_accept
  bindkey '^M' _kintsugi_gate_accept
elif [ -n "$BASH_VERSION" ]; then
  shopt -s extdebug 2>/dev/null   # so a nonzero DEBUG trap return cancels the next command
  _kintsugi_gate_bash() {
    [ -n "$COMP_LINE" ] && return 0
    [ -n "$_KINTSUGI_IN_PROMPT" ] && return 0
    case "$BASH_COMMAND" in _kintsugi_*) return 0 ;; esac
    if _kintsugi_skip "$BASH_COMMAND"; then return 0; fi
    command kintsugi ingest --gate --cwd "$PWD" -- "$BASH_COMMAND"
  }
  PROMPT_COMMAND="_KINTSUGI_IN_PROMPT=1${PROMPT_COMMAND:+; $PROMPT_COMMAND}; _KINTSUGI_IN_PROMPT="
  trap '_kintsugi_gate_bash' DEBUG
fi
# <<< kintsugi session recorder <<<"#;

/// `kintsugi record install` — print the hook (default), or with `--write <rc>`
/// install it as an idempotent, fenced block in that file. With `--gate`, install
/// the gated variant that describes commands and confirms risky ones.
pub fn install(write: Option<PathBuf>, gate: bool) -> Result<()> {
    let hook = if gate { HOOK_GATE } else { HOOK };
    let kind = if gate {
        "gated recorder"
    } else {
        "passive recorder"
    };
    let Some(rc) = write else {
        // Default: print to stdout so it composes with a redirect, and never touch
        // the user's rc ourselves — that's their file to own.
        println!("{hook}");
        eprintln!(
            "# Appended nothing yet — pipe this into your shell rc, e.g.:\n\
             #   kintsugi record install{gate_flag} >> ~/.bashrc   # or ~/.zshrc\n\
             # (or let Kintsugi manage it: `kintsugi record install{gate_flag} --write ~/.bashrc`)\n\
             # then restart your shell. Verify with `kintsugi record status`.",
            gate_flag = if gate { " --gate" } else { "" }
        );
        return Ok(());
    };
    let existing = std::fs::read_to_string(&rc).unwrap_or_default();
    let (replaced, body) = replace_block(&existing, Some(hook));
    atomic_write(&rc, &body)?;
    println!(
        "✓ {} the Kintsugi {kind} block in {}",
        if replaced { "updated" } else { "installed" },
        rc.display()
    );
    println!(
        "  Restart your shell (or `source {}`) to start.",
        rc.display()
    );
    Ok(())
}

/// `kintsugi record uninstall` — remove the managed block from `--write <rc>`, or
/// explain how to remove it by hand.
pub fn uninstall(write: Option<PathBuf>) -> Result<()> {
    let Some(rc) = write else {
        println!(
            "To stop recording, delete the block between\n  \
             '{FENCE_BEGIN}' and '{FENCE_END}'\n  \
             from your shell rc (~/.bashrc or ~/.zshrc), then restart your shell.\n  \
             (or let Kintsugi remove it: `kintsugi record uninstall --write ~/.bashrc`)"
        );
        return Ok(());
    };
    let existing = std::fs::read_to_string(&rc).unwrap_or_default();
    let (removed, body) = replace_block(&existing, None);
    if !removed {
        println!("No Kintsugi recorder block found in {}.", rc.display());
        return Ok(());
    }
    atomic_write(&rc, &body)?;
    println!(
        "✓ removed the Kintsugi recorder block from {}.",
        rc.display()
    );
    println!("  Restart your shell to stop recording.");
    Ok(())
}

/// Replace the fenced Kintsugi block in `content`: drop any existing block, then
/// append `replacement` (when `Some`). Returns `(had_existing_block, new_content)`.
/// Idempotent — re-running never duplicates the block.
fn replace_block(content: &str, replacement: Option<&str>) -> (bool, String) {
    let mut out = String::with_capacity(content.len() + replacement.map_or(0, |r| r.len() + 2));
    let mut had = false;
    let mut skipping = false;
    // Buffer the lines inside a block so an UNCLOSED block (a BEGIN with no END —
    // a truncated install or a hand-edit) doesn't silently eat the rest of the
    // user's file: if we hit EOF still skipping, we put those lines back.
    let mut skipped: Vec<&str> = Vec::new();
    for line in content.lines() {
        if line.trim() == FENCE_BEGIN {
            had = true;
            skipping = true;
            skipped.clear();
            continue;
        }
        if line.trim() == FENCE_END {
            skipping = false;
            skipped.clear();
            continue;
        }
        if skipping {
            skipped.push(line);
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    // Unclosed block: the END fence was missing, so the "block" wasn't really one —
    // restore the buffered lines rather than dropping the user's content.
    if skipping {
        for line in skipped {
            out.push_str(line);
            out.push('\n');
        }
    }
    // Trim trailing blank lines left behind, then append the fresh block.
    while out.ends_with("\n\n") {
        out.pop();
    }
    if let Some(block) = replacement {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(block);
        out.push('\n');
    }
    (had, out)
}

/// Write `content` to `path` atomically (temp file in the same dir + rename).
/// The temp name *appends* a suffix to the full file name (so it never clobbers a
/// real extension like `.sh`), and on Unix we copy the original file's mode onto
/// the temp before the rename — so we never widen a user's hardened rc (e.g.
/// `chmod 600 ~/.bashrc`). A brand-new file keeps the default (umask) mode.
fn atomic_write(path: &Path, content: &str) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir).ok();
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("rc");
    let tmp = dir.join(format!(".{name}.kintsugi-tmp-{}", std::process::id()));
    std::fs::write(&tmp, content).with_context(|| format!("write {}", tmp.display()))?;
    #[cfg(unix)]
    if let Ok(meta) = std::fs::metadata(path) {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode));
    }
    std::fs::rename(&tmp, path).with_context(|| format!("install into {}", path.display()))?;
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

/// `kintsugi ingest --gate` — describe a command before it runs and (for the
/// ambiguous/catastrophic band) ask the user via /dev/tty whether to proceed.
/// Returns:
///   * `Ok(0)` for safe/allow → the shell may run the command.
///   * `Ok(1)` for deny → the shell should NOT run the command.
///
/// Never crashes the shell: a parse error, daemon outage, or no TTY all fall
/// back to passive recording + exit 0 (i.e. the existing behavior).
pub fn ingest_gate(command: &str, cwd: Option<PathBuf>) -> Result<i32> {
    use kintsugi_core::{Class, Decision};
    use std::io::Write;

    let command = command.trim();
    if command.is_empty() {
        return Ok(0);
    }
    let cwd = cwd.unwrap_or_else(|| std::env::current_dir().unwrap_or_default());

    let red = kintsugi_core::redact::redact_command(command);
    let (text, argv) = if red.any() {
        (red.text.clone(), kintsugi_core::shell::split(&red.text))
    } else {
        (command.to_string(), kintsugi_core::shell::split(command))
    };
    let cmd = ProposedCommand::new("shell", cwd, argv, text);

    // Score synchronously. If the daemon is down, fall back to passive (record
    // via spool, allow) — the gate must never be the reason a normal shell
    // command can't run.
    let Ok(verdict) = Client::send(&cmd) else {
        let _ = append_spool(&cmd);
        return Ok(0);
    };

    // Safe → silently allow (matches the existing recorder UX).
    if verdict.class == Class::Safe {
        let _ = Client::record(&cmd);
        return Ok(0);
    }

    // Describe to the user. The model's summary is the "plain English" part the
    // user explicitly wanted; we name Kintsugi so the prompt is unmistakable.
    let class_word = match verdict.class {
        Class::Catastrophic => "catastrophic",
        Class::Ambiguous => "ambiguous",
        Class::Safe => "safe",
    };
    let summary = verdict
        .summary
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(verdict.reason.as_str());

    // /dev/tty so the prompt survives the shell trap's redirected stdout.
    let mut tty_w = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok();
    let Some(ref mut tty) = tty_w else {
        // No interactive terminal (script / non-TTY) → revert to passive record.
        let _ = Client::record(&cmd);
        return Ok(0);
    };

    let _ = writeln!(tty, "\n\x1b[1;33m⚠ Kintsugi\x1b[0m {class_word}: {summary}");
    if let Some(risk) = verdict.risk {
        let _ = writeln!(tty, "   risk {risk}/100");
    }
    // Catastrophic: never ask — print and decline.
    if verdict.class == Class::Catastrophic {
        let _ = writeln!(
            tty,
            "   declined — catastrophic commands aren't gated through y/n."
        );
        let _ = writeln!(tty, "   re-run via `kintsugi run` if you really mean it.");
        let _ = Client::record(&cmd);
        return Ok(1);
    }
    let _ = write!(tty, "   run it anyway? [y/N] ");
    let _ = tty.flush();
    let mut line = String::new();
    let mut buf = [0u8; 1];
    while line.len() < 8 {
        match std::io::Read::read(tty, &mut buf) {
            Ok(0) => break,
            Ok(_) => {
                if buf[0] == b'\n' {
                    break;
                }
                line.push(buf[0] as char);
            }
            Err(_) => break,
        }
    }
    let yes = matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes");

    if !yes {
        // Record the (denied) decision so the audit log reflects reality.
        let mut declined = cmd.clone();
        declined.raw = format!("[user declined] {}", declined.raw);
        let _ = Client::record(&declined);
        return Ok(1);
    }
    // Approved: record and allow.
    let _ = Client::record(&cmd);
    let _ = verdict.decision; // suppresses any unused-binding warnings on this path
    let _: Decision = verdict.decision;
    Ok(0)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replace_block_is_idempotent_and_preserves_content() {
        let base = "export A=1\n# mine\n";
        let (had, once) = replace_block(base, Some(HOOK));
        assert!(!had);
        assert!(once.contains("export A=1") && once.contains("# mine"));
        assert_eq!(once.matches(FENCE_BEGIN).count(), 1);
        // Re-running replaces, never duplicates.
        let (had2, twice) = replace_block(&once, Some(HOOK));
        assert!(had2);
        assert_eq!(twice.matches(FENCE_BEGIN).count(), 1);
        // Removal leaves the user's content.
        let (removed, gone) = replace_block(&twice, None);
        assert!(removed);
        assert!(!gone.contains(FENCE_BEGIN));
        assert!(gone.contains("export A=1") && gone.contains("# mine"));
    }

    #[test]
    fn unclosed_block_does_not_eat_user_content() {
        // A BEGIN fence with no END (truncated install / hand-edit) must NOT drop
        // everything after it — the lines are restored.
        let corrupt = format!("export A=1\n{FENCE_BEGIN}\nalias gs='git status'\nexport B=2\n");
        let (_had, out) = replace_block(&corrupt, None);
        assert!(out.contains("alias gs='git status'"), "data lost: {out}");
        assert!(out.contains("export B=2"), "data lost: {out}");
    }
}
