//! The `aegis` command-line interface.
//!
//! Phase 0/1 surface: `init` (detect agents, wire interception, start the
//! daemon), `status`, and `log` (the recent timeline). Approval/undo arrive in
//! later phases.

mod init;
mod logview;

use std::io::IsTerminal;
use std::path::PathBuf;

use aegis_core::{Class, Decision, EventLog, ProposedCommand, Verdict};
use aegis_daemon::{default_db_path, ipc, Client};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

/// Aegis — a local-first safety layer for AI coding agents.
#[derive(Debug, Parser)]
#[command(name = "aegis", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Detect installed agents, wire interception, and start the daemon.
    Init {
        /// Wire interception but do not start the daemon.
        #[arg(long)]
        no_daemon: bool,
        /// Print only the shell line that adds the shim dir to PATH, then exit.
        /// Use as: `eval "$(aegis init --print-path)"`.
        #[arg(long)]
        print_path: bool,
    },
    /// Show daemon, socket, log, and interception status.
    Status,
    /// Show the recent command timeline from the event log.
    Log {
        /// How many recent events to show.
        #[arg(short = 'n', long, default_value_t = 20)]
        number: usize,
        /// Also show redacted entries (as ⟨redacted⟩ placeholders).
        #[arg(long)]
        show_redacted: bool,
        #[command(flatten)]
        filter: FilterArgs,
    },
    /// Redact (hide) events without breaking the hash chain. Pass an ID to hide
    /// one, or filters to hide many. The rows stay on disk; use `purge` to erase.
    Redact {
        /// The event id (or unique prefix) to redact. Omit to redact by filter.
        id: Option<String>,
        /// Why it's being hidden (recorded in the redaction).
        #[arg(long, default_value = "redacted by user")]
        reason: String,
        #[command(flatten)]
        filter: FilterArgs,
    },
    /// Hard-erase events matching filters: delete rows, rebuild the chain, and
    /// record a purge marker. Deliberate and irreversible — requires --yes.
    Purge {
        /// Confirm the erasure (required; this rewrites history for the span).
        #[arg(long)]
        yes: bool,
        /// Why it's being erased (recorded in the purge marker).
        #[arg(long, default_value = "purged by user")]
        reason: String,
        #[command(flatten)]
        filter: FilterArgs,
    },
    /// Undo the last destructive action (or the whole session with --session).
    Undo {
        /// Undo every not-yet-reverted snapshot, newest first.
        #[arg(long)]
        session: bool,
    },
    /// Backstop: watch paths and record filesystem changes (even un-intercepted).
    Watch {
        /// One or more directories to watch recursively.
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    /// Open the live timeline TUI.
    Tui,
    /// List commands held for approval.
    Queue,
    /// Approve a held command by id (or unique id prefix).
    Approve {
        /// The queue id (or a unique prefix).
        id: String,
    },
    /// Deny a held command by id (or unique id prefix).
    Deny {
        /// The queue id (or a unique prefix).
        id: String,
    },
    /// PANIC: engage the kill-switch — halt all current and queued agent actions.
    Panic,
    /// Clear the kill-switch and resume normal operation.
    Resume,
}

/// Shared filter flags for `log`, `redact`, and `purge`.
#[derive(Debug, Clone, clap::Args)]
struct FilterArgs {
    /// Only this agent (claude-code, cursor, codex, qwen, gemini, shim, mcp).
    #[arg(long)]
    agent: Option<String>,
    /// Only this session id.
    #[arg(long)]
    session: Option<String>,
    /// Only this class (safe | ambiguous | catastrophic).
    #[arg(long)]
    class: Option<String>,
    /// Case-insensitive substring match on the command (literal, not a pattern).
    #[arg(long)]
    grep: Option<String>,
    /// Only events at/after this time (RFC3339, or relative: day|week|month|<N>d|<N>h).
    #[arg(long)]
    since: Option<String>,
    /// Only events before this time (same formats as --since).
    #[arg(long)]
    before: Option<String>,
}

impl FilterArgs {
    /// True when no filter at all is set (a guard against accidental bulk ops).
    fn is_empty(&self) -> bool {
        self.agent.is_none()
            && self.session.is_none()
            && self.class.is_none()
            && self.grep.is_none()
            && self.since.is_none()
            && self.before.is_none()
    }

    /// Build a core [`Filter`] from these flags.
    fn to_filter(
        &self,
        include_redacted: bool,
        limit: Option<usize>,
    ) -> Result<aegis_core::Filter> {
        let class = match self.class.as_deref() {
            None => None,
            Some("safe") => Some(aegis_core::Class::Safe),
            Some("ambiguous") => Some(aegis_core::Class::Ambiguous),
            Some("catastrophic") => Some(aegis_core::Class::Catastrophic),
            Some(other) => anyhow::bail!("unknown class '{other}' (safe|ambiguous|catastrophic)"),
        };
        Ok(aegis_core::Filter {
            agent: self.agent.clone(),
            session: self.session.clone(),
            class,
            grep: self.grep.clone(),
            since: self.since.as_deref().map(parse_instant).transpose()?,
            until: self.before.as_deref().map(parse_instant).transpose()?,
            include_redacted,
            limit,
        })
    }
}

/// Parse an instant: RFC3339, or a relative spec meaning "that long ago"
/// (`day`, `week`, `month`, `<N>d`, `<N>h`).
fn parse_instant(s: &str) -> Result<time::OffsetDateTime> {
    use time::{Duration, OffsetDateTime};
    let now = OffsetDateTime::now_utc();
    let ago = |d: Duration| now - d;
    let s = s.trim();
    let parsed = match s {
        "day" => ago(Duration::days(1)),
        "week" => ago(Duration::weeks(1)),
        "month" => ago(Duration::days(30)),
        other => {
            if let Some(n) = other.strip_suffix('d').and_then(|n| n.parse::<i64>().ok()) {
                ago(Duration::days(n))
            } else if let Some(n) = other.strip_suffix('h').and_then(|n| n.parse::<i64>().ok()) {
                ago(Duration::hours(n))
            } else {
                OffsetDateTime::parse(other, &time::format_description::well_known::Rfc3339)
                    .with_context(|| {
                        format!("invalid time '{other}' (RFC3339 or day|week|month|<N>d|<N>h)")
                    })?
            }
        }
    };
    Ok(parsed)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        None => {
            println!("aegis {}", env!("CARGO_PKG_VERSION"));
            println!("A local-first safety layer for AI coding agents.");
            println!("Run `aegis --help` for usage, or `aegis init` to get started.");
            Ok(())
        }
        Some(Command::Init {
            no_daemon,
            print_path,
        }) => {
            if print_path {
                println!("export PATH=\"{}:$PATH\"", shim_dir().display());
                Ok(())
            } else {
                cmd_init(no_daemon)
            }
        }
        Some(Command::Status) => cmd_status(),
        Some(Command::Log {
            number,
            show_redacted,
            filter,
        }) => cmd_log(number, show_redacted, &filter),
        Some(Command::Redact { id, reason, filter }) => cmd_redact(id, &reason, &filter),
        Some(Command::Purge {
            yes,
            reason,
            filter,
        }) => cmd_purge(yes, &reason, &filter),
        Some(Command::Undo { session }) => cmd_undo(session),
        Some(Command::Watch { paths }) => aegis_daemon::watch::run(&paths),
        Some(Command::Tui) => aegis_tui::run(&default_db_path(), &snapshot_dir()),
        Some(Command::Queue) => cmd_queue(),
        Some(Command::Approve { id }) => cmd_resolve_pending(&id, true),
        Some(Command::Deny { id }) => cmd_resolve_pending(&id, false),
        Some(Command::Panic) => cmd_panic(),
        Some(Command::Resume) => cmd_resume(),
    }
}

fn cmd_queue() -> Result<()> {
    if !Client::is_daemon_running() {
        println!("The daemon isn't running. Start it with `aegis init`.");
        return Ok(());
    }
    let items = Client::list_pending().context("list pending")?;
    if items.is_empty() {
        println!("The approval queue is empty.");
        return Ok(());
    }
    println!("{:<10}  {:<13}  command", "id", "class");
    for it in &items {
        let id = it.command.id.to_string();
        println!(
            "{:<10}  {:<13}  {}",
            &id[..id.len().min(8)],
            it.class.as_str(),
            it.command.raw
        );
    }
    println!();
    println!("Approve with `aegis approve <id>` or deny with `aegis deny <id>`.");
    Ok(())
}

fn cmd_resolve_pending(id: &str, approve: bool) -> Result<()> {
    if !Client::is_daemon_running() {
        anyhow::bail!("the daemon isn't running; start it with `aegis init`");
    }
    // Resolve a prefix to a full id via the queue, for convenience.
    let items = Client::list_pending().context("list pending")?;
    let matches: Vec<String> = items
        .iter()
        .map(|i| i.command.id.to_string())
        .filter(|full| full.starts_with(id))
        .collect();
    let full = match matches.as_slice() {
        [one] => one.clone(),
        [] => anyhow::bail!("no pending command matches id `{id}`"),
        _ => anyhow::bail!("id `{id}` is ambiguous; use more characters"),
    };

    let short = full.get(..8).unwrap_or(&full);
    if approve {
        Client::approve(&full).context("approve")?;
        println!("✓ approved {short} — the requesting agent may now proceed.");
    } else {
        Client::deny(&full).context("deny")?;
        println!("✗ denied {short}.");
    }
    Ok(())
}

fn cmd_panic() -> Result<()> {
    let path = aegis_daemon::kill_switch_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&path, b"engaged\n").with_context(|| format!("write {}", path.display()))?;
    log_control_event("panic", Decision::Deny, "kill-switch:engaged");
    println!("⛔ Kill-switch ENGAGED. All agent actions are now denied.");
    println!("   Run `aegis resume` to restore normal operation.");
    Ok(())
}

fn cmd_resume() -> Result<()> {
    let path = aegis_daemon::kill_switch_path();
    if path.exists() {
        std::fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
    }
    log_control_event("resume", Decision::Allow, "kill-switch:cleared");
    println!("✓ Kill-switch cleared. Normal operation resumed.");
    Ok(())
}

/// Append a control action (panic/resume) to the event log directly.
fn log_control_event(name: &str, decision: Decision, reason: &str) {
    let db = default_db_path();
    if let Some(parent) = db.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    if let Ok(log) = EventLog::open(&db) {
        let cwd = std::env::current_dir().unwrap_or_default();
        let cmd = ProposedCommand::new("aegis", cwd, vec![name.to_string()], name);
        let _ = log.log_event(&cmd, &Verdict::rules(Class::Safe, decision, reason), None);
    }
}

/// Where snapshots live: alongside the event-log database.
fn snapshot_dir() -> PathBuf {
    default_db_path()
        .parent()
        .map(|p| p.join("snapshots"))
        .unwrap_or_else(|| std::env::temp_dir().join("aegis-snapshots"))
}

fn cmd_undo(session: bool) -> Result<()> {
    let db = default_db_path();
    if !db.exists() {
        println!("Nothing to undo.");
        return Ok(());
    }
    let log = EventLog::open(&db).with_context(|| format!("open log {}", db.display()))?;
    let dir = snapshot_dir();

    let targets = if session {
        log.unreverted_snapshots()?
    } else {
        log.latest_unreverted_snapshot()?.into_iter().collect()
    };

    if targets.is_empty() {
        println!("Nothing to undo.");
        return Ok(());
    }

    for m in &targets {
        aegis_core::restore_snapshot(&dir, m)
            .with_context(|| format!("restore snapshot for `{}`", m.command))?;
        log.mark_reverted(&m.id)?;
        // Record the undo itself (append-only; never rewrite history).
        let cwd = std::env::current_dir().unwrap_or_default();
        let raw = format!("undo {}", m.command);
        let cmd = ProposedCommand::new("aegis", cwd, vec!["undo".into(), m.id.clone()], raw);
        log.log_event(
            &cmd,
            &Verdict::rules(Class::Safe, Decision::Allow, "undo"),
            None,
        )?;
        println!(
            "✓ undid `{}` ({} path(s) restored)",
            m.command,
            m.entries.len()
        );
    }

    println!();
    println!(
        "Restored {} snapshot(s). Note: undo covers files only — not network calls, \
         external APIs, or already-pushed commits.",
        targets.len()
    );
    Ok(())
}

fn home_dir() -> Option<PathBuf> {
    directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf())
}

fn shim_dir() -> PathBuf {
    // `AEGIS_DATA_DIR` overrides the platform data dir (deterministic in tests and
    // portable across OSes, where `directories` resolves the data dir differently).
    if let Ok(dir) = std::env::var("AEGIS_DATA_DIR") {
        return PathBuf::from(dir).join("shims");
    }
    if let Some(dirs) = directories::ProjectDirs::from("", "", "aegis") {
        return dirs.data_dir().join("shims");
    }
    std::env::temp_dir().join("aegis-shims")
}

fn cmd_init(no_daemon: bool) -> Result<()> {
    println!("aegis init");
    println!();

    // 1. Shims for raw shell-outs.
    let shim_bin = init::sibling_bin("aegis-shim");
    let shim_dir = shim_dir();
    let linked = init::create_shims(&shim_dir, &shim_bin, init::SHIM_COMMANDS)
        .context("create $PATH shims")?;
    println!(
        "  ✓ shim: linked {} commands in {}",
        linked.len(),
        shim_dir.display()
    );
    println!("      add this to your PATH (prepend) to guard raw shell-outs:");
    println!("        export PATH=\"{}:$PATH\"", shim_dir.display());

    // 2. Detect agents and wire them.
    let home = home_dir();
    let agents = home.as_deref().map(init::detect_agents).unwrap_or_default();
    if agents.is_empty() {
        println!(
            "  • no agent config dirs detected (~/.claude, ~/.codex, ~/.cursor, ~/.qwen, ~/.gemini)"
        );
    }
    let mut mcp_agents = Vec::new();
    for agent in &agents {
        match agent.via {
            init::Interception::Hook => {
                wire_claude_hook(home.as_deref())?;
                println!("  ✓ {}: wired via {}", agent.name, agent.via.as_str());
            }
            init::Interception::Mcp => {
                mcp_agents.push(agent.name);
                println!("  • {}: intercept via {}", agent.name, agent.via.as_str());
            }
        }
    }
    if !mcp_agents.is_empty() {
        println!();
        println!(
            "  To wire MCP agents ({}), add the aegis-exec server:",
            mcp_agents.join(", ")
        );
        println!(
            "        command = \"{}\"",
            init::sibling_bin("aegis-mcp").display()
        );
        println!("      (see docs/mcp.md). The shim still covers their raw shell-outs.");
    }

    // 3. Start the daemon.
    if no_daemon {
        println!();
        println!("  • daemon not started (--no-daemon)");
    } else if Client::is_daemon_running() {
        println!();
        println!(
            "  ✓ daemon already running on {}",
            ipc::socket_path().display()
        );
    } else {
        start_daemon()?;
        println!();
        println!("  ✓ daemon started on {}", ipc::socket_path().display());
    }

    println!();
    println!("Done. Try: aegis status");
    Ok(())
}

fn wire_claude_hook(home: Option<&std::path::Path>) -> Result<()> {
    let Some(home) = home else {
        return Ok(());
    };
    let settings_path = home.join(".claude").join("settings.json");
    let existing = std::fs::read_to_string(&settings_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());

    // Back up before modifying anything the user owns.
    if settings_path.exists() {
        let backup = settings_path.with_extension("json.aegis-bak");
        let _ = std::fs::copy(&settings_path, &backup);
    }

    let hook_cmd = init::sibling_bin("aegis-hook");
    let merged = init::merge_claude_settings(existing, &hook_cmd.to_string_lossy());
    if let Some(parent) = settings_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&settings_path, serde_json::to_string_pretty(&merged)?)
        .with_context(|| format!("write {}", settings_path.display()))?;
    Ok(())
}

fn start_daemon() -> Result<()> {
    let daemon_bin = init::sibling_bin("aegis-daemon");
    std::process::Command::new(&daemon_bin)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("start daemon {}", daemon_bin.display()))?;
    // Give it a moment to bind the socket.
    for _ in 0..50 {
        if Client::is_daemon_running() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    Ok(())
}

fn cmd_status() -> Result<()> {
    println!("aegis {}", env!("CARGO_PKG_VERSION"));
    let running = Client::is_daemon_running();
    println!("  daemon:  {}", if running { "running" } else { "stopped" });
    println!("  socket:  {}", ipc::socket_path().display());

    // The panic kill-switch is the loudest state — surface it prominently.
    if aegis_daemon::kill_switch_path().exists() {
        println!("  KILL-SWITCH: ENGAGED — all actions denied (run `aegis resume`)");
    }

    let db = default_db_path();
    println!("  log:     {}", db.display());
    if db.exists() {
        match EventLog::open(&db) {
            Ok(log) => {
                let count = log.count().unwrap_or(0);
                let chain = log.verify_chain()?;
                println!("  events:  {count}");
                println!(
                    "  chain:   {}",
                    if chain.is_intact() {
                        "intact".to_string()
                    } else {
                        format!("BROKEN ({chain:?})")
                    }
                );
            }
            Err(e) => println!("  events:  (could not open log: {e})"),
        }
    } else {
        println!("  events:  0 (no log yet)");
    }
    Ok(())
}

fn cmd_log(number: usize, show_redacted: bool, filter: &FilterArgs) -> Result<()> {
    let db = default_db_path();
    if !db.exists() {
        print!("{}", logview::render_log(&[], false));
        return Ok(());
    }
    let log = EventLog::open(&db).with_context(|| format!("open log {}", db.display()))?;
    let f = filter.to_filter(show_redacted, Some(number))?;
    let events = log.query(&f)?;
    let color = logview::use_color(
        std::env::var_os("NO_COLOR").is_some(),
        std::io::stdout().is_terminal(),
    );
    print!("{}", logview::render_log(&events, color));
    Ok(())
}

fn cmd_redact(id: Option<String>, reason: &str, filter: &FilterArgs) -> Result<()> {
    let db = default_db_path();
    let log = EventLog::open(&db).with_context(|| format!("open log {}", db.display()))?;

    if let Some(prefix) = id {
        // Resolve a (possibly abbreviated) id to the one matching event.
        let full = resolve_event_id(&log, &prefix)?;
        if log.redact(&full, reason)? {
            println!("redacted {}", &full[..full.len().min(8)]);
        } else {
            println!("already redacted (or no such event)");
        }
        return Ok(());
    }

    if filter.is_empty() {
        anyhow::bail!("refusing to redact everything: pass an ID or at least one filter");
    }
    let f = filter.to_filter(false, None)?;
    let n = log.redact_matching(&f, reason)?;
    println!(
        "redacted {n} event(s) — hidden from views; chain intact (use `aegis purge` to erase)"
    );
    Ok(())
}

fn cmd_purge(yes: bool, reason: &str, filter: &FilterArgs) -> Result<()> {
    let db = default_db_path();
    let log = EventLog::open(&db).with_context(|| format!("open log {}", db.display()))?;

    if filter.is_empty() {
        anyhow::bail!(
            "refusing to purge everything: pass at least one filter (--agent/--before/…)"
        );
    }
    let f = filter.to_filter(true, None)?;
    let count = log.count_matching(&f)?;
    if count == 0 {
        println!("nothing matched — nothing purged");
        return Ok(());
    }
    if !yes {
        anyhow::bail!(
            "this will PERMANENTLY erase {count} event(s) and rewrite the chain for that span.\n  \
             Re-run with --yes to confirm."
        );
    }
    let removed = log.purge_matching(&f, reason)?;
    println!("purged {removed} event(s); chain rebuilt and a purge marker recorded");
    Ok(())
}

/// Resolve a full event id from a possibly-abbreviated prefix (unique match).
fn resolve_event_id(log: &EventLog, prefix: &str) -> Result<String> {
    let all = log.query(&aegis_core::Filter {
        include_redacted: true,
        ..aegis_core::Filter::default()
    })?;
    let matches: Vec<String> = all
        .iter()
        .map(|e| e.id.to_string())
        .filter(|id| id.starts_with(prefix))
        .collect();
    match matches.len() {
        0 => anyhow::bail!("no event matches id '{prefix}'"),
        1 => Ok(matches.into_iter().next().unwrap()),
        n => anyhow::bail!("'{prefix}' is ambiguous ({n} events match) — use more characters"),
    }
}

#[cfg(test)]
mod filter_tests {
    use super::*;

    #[test]
    fn parse_instant_relative_and_rfc3339() {
        let now = time::OffsetDateTime::now_utc();
        let wk = parse_instant("week").unwrap();
        assert!(wk < now && (now - wk) >= time::Duration::days(6));
        let h = parse_instant("12h").unwrap();
        assert!((now - h) >= time::Duration::hours(11));
        let d = parse_instant("3d").unwrap();
        assert!((now - d) >= time::Duration::days(2));
        assert!(parse_instant("2020-01-01T00:00:00Z").is_ok());
        assert!(parse_instant("not-a-time").is_err());
    }

    #[test]
    fn empty_filter_is_detected() {
        let empty = FilterArgs {
            agent: None,
            session: None,
            class: None,
            grep: None,
            since: None,
            before: None,
        };
        assert!(empty.is_empty());
        let set = FilterArgs {
            agent: Some("shim".into()),
            ..empty.clone()
        };
        assert!(!set.is_empty());
    }

    #[test]
    fn to_filter_maps_class_and_rejects_unknown() {
        let f = FilterArgs {
            agent: Some("cursor".into()),
            session: None,
            class: Some("catastrophic".into()),
            grep: Some("rm".into()),
            since: None,
            before: None,
        };
        let core = f.to_filter(false, Some(10)).unwrap();
        assert_eq!(core.agent.as_deref(), Some("cursor"));
        assert_eq!(core.class, Some(aegis_core::Class::Catastrophic));
        assert_eq!(core.limit, Some(10));

        let bad = FilterArgs {
            class: Some("nope".into()),
            ..f
        };
        assert!(bad.to_filter(false, None).is_err());
    }
}
