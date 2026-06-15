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
        Some(Command::Init { no_daemon }) => cmd_init(no_daemon),
        Some(Command::Status) => cmd_status(),
        Some(Command::Log { number }) => cmd_log(number),
        Some(Command::Undo { session }) => cmd_undo(session),
        Some(Command::Watch { paths }) => aegis_daemon::watch::run(&paths),
        Some(Command::Tui) => aegis_tui::run(&default_db_path(), &snapshot_dir()),
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
        println!("  • no agent config dirs detected (~/.claude, ~/.codex, ~/.qwen, ~/.gemini)");
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
