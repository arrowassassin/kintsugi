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
        Some(Command::Log { number }) => cmd_log(number),
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

fn cmd_log(number: usize) -> Result<()> {
    let db = default_db_path();
    if !db.exists() {
        print!("{}", logview::render_log(&[], false));
        return Ok(());
    }
    let log = EventLog::open(&db).with_context(|| format!("open log {}", db.display()))?;
    let events = log.tail(number)?;
    let color = logview::use_color(
        std::env::var_os("NO_COLOR").is_some(),
        std::io::stdout().is_terminal(),
    );
    print!("{}", logview::render_log(&events, color));
    Ok(())
}
