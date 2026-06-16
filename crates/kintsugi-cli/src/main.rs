//! The `kintsugi` command-line interface.
//!
//! Phase 0/1 surface: `init` (detect agents, wire interception, start the
//! daemon), `status`, and `log` (the recent timeline). Approval/undo arrive in
//! later phases.

mod admin_cmd;
mod init;
mod logview;
mod record;
mod service;

use std::io::IsTerminal;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use kintsugi_core::{Class, Decision, EventLog, ProposedCommand, Verdict};
use kintsugi_daemon::{default_db_path, ipc, Client};

/// Kintsugi — a local-first safety layer for AI coding agents.
#[derive(Debug, Parser)]
#[command(name = "kintsugi", version, about, long_about = None)]
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
        /// Use as: `eval "$(kintsugi init --print-path)"`.
        #[arg(long)]
        print_path: bool,
    },
    /// Show daemon, socket, log, and interception status.
    Status,
    /// Stop the background daemon (the inverse of `kintsugi init`).
    Stop,
    /// Admin-lock settings behind a password (provision / status / change-password).
    Admin {
        #[command(subcommand)]
        cmd: AdminCmd,
    },
    /// Run the daemon under an OS supervisor that auto-restarts it (so a kill /
    /// pkill relaunches it). install / uninstall / status.
    Service {
        #[command(subcommand)]
        cmd: ServiceCmd,
    },
    /// Check GitHub for a newer release and install it in place. A manual,
    /// user-invoked check that sends no data — only fetches the latest release
    /// tag and (with consent) the verified installer. There are no automatic or
    /// background update checks.
    Update {
        /// Only report whether a newer release exists; do not install anything.
        #[arg(long)]
        check: bool,
        /// Install without the confirmation prompt.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Show the recent command timeline from the event log (newest first).
    Log {
        /// Page size — how many events per page.
        #[arg(short = 'n', long, default_value_t = 20)]
        number: usize,
        /// Which page to show (1 = newest). Older events are on higher pages.
        #[arg(short = 'p', long, default_value_t = 1)]
        page: usize,
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
    /// Dry-run: show how Kintsugi would classify a command, without running it.
    /// Try it: `kintsugi test "cd build && rm -rf ../dist"`.
    Test {
        /// The command line to classify (quote it).
        command: String,
    },
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
    /// Run a held command yourself, reversibly. Kintsugi snapshots the paths it
    /// will touch (so `kintsugi undo` can roll it back), executes it in its original
    /// directory, and records the run. This is the guarded way to run a command
    /// an agent hook blocked — the agent never runs it, you do.
    ///
    /// The confirmation is read from the real terminal (`/dev/tty`), not stdin,
    /// so it is a human keypress by construction: even if an agent invokes this,
    /// only the person at the keyboard can approve it. There is intentionally no
    /// `--yes` bypass.
    Run {
        /// The queue id (or a unique prefix). Omit when exactly one is held.
        id: Option<String>,
    },
    /// PANIC: engage the kill-switch — halt all current and queued agent actions.
    Panic,
    /// Clear the kill-switch and resume normal operation.
    Resume,
    /// Passive session recording (no AI agent): record shell commands a human ran
    /// for an audit/compliance trail. install / uninstall / status the shell hook.
    Record {
        #[command(subcommand)]
        cmd: RecordCmd,
    },
    /// Record a single shell command that already ran. This is the primitive the
    /// shell hook calls on every command (`kintsugi record install`); it is
    /// fire-and-forget and never blocks the shell — if the daemon is down the
    /// command is spooled so the audit trail survives daemon restarts.
    Ingest {
        /// The command line that was run (quote it).
        command: String,
        /// The working directory it ran in (defaults to the current dir).
        #[arg(long)]
        cwd: Option<PathBuf>,
    },
    /// Audit report: the destructive commands on the timeline (for compliance /
    /// DBA review). By default shows catastrophic + ambiguous; filterable.
    Report {
        /// Show only catastrophic commands (drop ambiguous).
        #[arg(long)]
        catastrophic_only: bool,
        /// How many to show.
        #[arg(short = 'n', long, default_value_t = 50)]
        number: usize,
        #[command(flatten)]
        filter: FilterArgs,
    },
}

/// `kintsugi record` subcommands (passive session recorder).
#[derive(Debug, Subcommand)]
enum RecordCmd {
    /// Print the shell hook to source from your rc file (bash/zsh). Use as:
    /// `kintsugi record install >> ~/.bashrc` (or `~/.zshrc`), then restart the shell.
    Install,
    /// Print how to remove the shell hook.
    Uninstall,
    /// Show whether the daemon is up to receive recordings, and any spooled gap.
    Status,
}

/// `kintsugi admin` subcommands.
#[derive(Debug, Subcommand)]
enum AdminCmd {
    /// Set the admin password and lock settings (stopping Kintsugi then needs it).
    Provision {
        /// Read the password from a file instead of prompting (for config
        /// management / unattended provisioning).
        #[arg(long)]
        password_file: Option<std::path::PathBuf>,
        /// Re-provision even if already locked (rotates password + recovery key).
        #[arg(long)]
        force: bool,
    },
    /// Show whether settings are admin-locked.
    Status,
    /// Change the admin password (and rotate the recovery key).
    ChangePassword,
}

/// `kintsugi service` subcommands.
#[derive(Debug, Subcommand)]
enum ServiceCmd {
    /// Install + enable the auto-restart service (systemd user unit / launchd agent).
    Install,
    /// Disable + remove it (requires the admin password when locked).
    Uninstall,
    /// Show whether the auto-restart service is installed.
    Status,
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
    ) -> Result<kintsugi_core::Filter> {
        self.to_filter_paged(include_redacted, limit, None)
    }

    /// Like [`to_filter`], with a page offset (skip the newest `offset` matches
    /// first) for `kintsugi log --page N`.
    fn to_filter_paged(
        &self,
        include_redacted: bool,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<kintsugi_core::Filter> {
        let class = match self.class.as_deref() {
            None => None,
            Some("safe") => Some(kintsugi_core::Class::Safe),
            Some("ambiguous") => Some(kintsugi_core::Class::Ambiguous),
            Some("catastrophic") => Some(kintsugi_core::Class::Catastrophic),
            Some(other) => anyhow::bail!("unknown class '{other}' (safe|ambiguous|catastrophic)"),
        };
        Ok(kintsugi_core::Filter {
            agent: self.agent.clone(),
            session: self.session.clone(),
            class,
            grep: self.grep.clone(),
            since: self.since.as_deref().map(parse_instant).transpose()?,
            until: self.before.as_deref().map(parse_instant).transpose()?,
            include_redacted,
            limit,
            offset,
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
        None => cmd_banner(),
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
        Some(Command::Stop) => cmd_stop(),
        Some(Command::Admin { cmd }) => match cmd {
            AdminCmd::Provision {
                password_file,
                force,
            } => admin_cmd::provision(password_file, force),
            AdminCmd::Status => admin_cmd::status(),
            AdminCmd::ChangePassword => admin_cmd::change_password(),
        },
        Some(Command::Service { cmd }) => match cmd {
            ServiceCmd::Install => service::install(),
            ServiceCmd::Uninstall => service::uninstall(),
            ServiceCmd::Status => service::status(),
        },
        Some(Command::Update { check, yes }) => cmd_update(check, yes),
        Some(Command::Log {
            number,
            page,
            show_redacted,
            filter,
        }) => cmd_log(number, page, show_redacted, &filter),
        Some(Command::Redact { id, reason, filter }) => cmd_redact(id, &reason, &filter),
        Some(Command::Purge {
            yes,
            reason,
            filter,
        }) => cmd_purge(yes, &reason, &filter),
        Some(Command::Undo { session }) => cmd_undo(session),
        Some(Command::Watch { paths }) => kintsugi_daemon::watch::run(&paths),
        Some(Command::Tui) => kintsugi_tui::run(&default_db_path(), &snapshot_dir()),
        Some(Command::Test { command }) => cmd_test(&command),
        Some(Command::Queue) => cmd_queue(),
        Some(Command::Approve { id }) => cmd_resolve_pending(&id, true),
        Some(Command::Deny { id }) => cmd_resolve_pending(&id, false),
        Some(Command::Run { id }) => cmd_run(id.as_deref()),
        Some(Command::Panic) => cmd_panic(),
        Some(Command::Resume) => cmd_resume(),
        Some(Command::Record { cmd }) => match cmd {
            RecordCmd::Install => record::install(),
            RecordCmd::Uninstall => record::uninstall(),
            RecordCmd::Status => record::status(),
        },
        Some(Command::Ingest { command, cwd }) => record::ingest(&command, cwd),
        Some(Command::Report {
            catastrophic_only,
            number,
            filter,
        }) => cmd_report(catastrophic_only, number, &filter),
    }
}

/// Dry-run classifier: show how Kintsugi would classify a command and what would
/// happen, plus the simple commands the AST sees inside it — without running,
/// logging, or contacting the daemon. A safe way to explore the rules.
fn cmd_test(raw: &str) -> Result<()> {
    use kintsugi_core::rules;
    let m = rules::classify_line(raw);
    let decision = rules::decide(m.class, kintsugi_core::Mode::Attended);

    let label = match m.class {
        kintsugi_core::Class::Catastrophic => "⛔ CATASTROPHIC",
        kintsugi_core::Class::Ambiguous => "● AMBIGUOUS",
        kintsugi_core::Class::Safe => "✓ SAFE",
    };
    let outcome = match (m.class, decision) {
        (_, kintsugi_core::Decision::Allow) => "allowed — runs normally; recorded on the timeline.",
        (kintsugi_core::Class::Catastrophic, _) => {
            "blocked — the agent won't run it; you'd run it yourself, reversibly."
        }
        (_, kintsugi_core::Decision::Hold) => "held — paused for your one-key approval.",
        (_, kintsugi_core::Decision::Deny) => "denied.",
    };

    println!("command:   {raw}");
    println!("class:     {label}   (rule: {})", m.rule);
    println!("with you:  {outcome}");

    // Show what the parser actually sees — including commands hidden inside
    // $(…), here-docs, or compound commands. This is the AST pass in action.
    if let Some(analysis) = kintsugi_core::parse::analyze(raw) {
        if analysis.commands.len() > 1
            || analysis
                .commands
                .first()
                .map(|c| !c.args.is_empty())
                .unwrap_or(false)
        {
            println!();
            println!("Kintsugi sees these commands:");
            for c in &analysis.commands {
                let args = c.args.join(" ");
                if args.is_empty() {
                    println!("  • {}", c.program);
                } else {
                    println!("  • {} {}", c.program, args);
                }
            }
        }
    } else {
        println!();
        println!("(couldn't fully parse this line — Kintsugi stays cautious and would hold it.)");
    }

    println!();
    println!("Dry run: nothing was executed, logged, or sent anywhere.");
    Ok(())
}

fn cmd_queue() -> Result<()> {
    if !Client::is_daemon_running() {
        println!("The daemon isn't running. Start it with `kintsugi init`.");
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
    // Two verbs, by origin: an in-band command (shim/MCP) has a caller waiting,
    // so `approve` runs it there; a hook-blocked command has no waiter, so you
    // run it yourself with `kintsugi run`.
    println!("In-band (shim/MCP): `kintsugi approve <id>` runs it where it's waiting.");
    println!("Hook-blocked:       `kintsugi run <id>` runs it yourself, reversibly.");
    println!("Either:             `kintsugi deny <id>` to drop it.");
    Ok(())
}

/// Whether a queued command's origin has a caller waiting in-band to execute it
/// on approval (the shim and the MCP server), versus a one-shot hook that has
/// already returned and moved on.
fn is_in_band(agent: &str) -> bool {
    matches!(agent, "shim" | "mcp")
}

fn cmd_resolve_pending(id: &str, approve: bool) -> Result<()> {
    if !Client::is_daemon_running() {
        anyhow::bail!("the daemon isn't running; start it with `kintsugi init`");
    }
    // Resolve a prefix to a full id via the queue, for convenience.
    let items = Client::list_pending().context("list pending")?;
    let matches: Vec<_> = items
        .iter()
        .filter(|i| i.command.id.to_string().starts_with(id))
        .collect();
    let item = match matches.as_slice() {
        [one] => *one,
        [] => anyhow::bail!("no pending command matches id `{id}`"),
        _ => anyhow::bail!("id `{id}` is ambiguous; use more characters"),
    };
    let full = item.command.id.to_string();
    let short = full.get(..8).unwrap_or(&full);
    if approve {
        Client::approve(&full).context("approve")?;
        if is_in_band(&item.command.agent) {
            println!("✓ approved {short} — the requesting agent may now proceed.");
        } else {
            // A hook origin has no waiter; approving alone won't execute it.
            println!("✓ approved {short} (recorded). It came from a hook, so nothing is");
            println!("  waiting to run it — use `kintsugi run {short}` to run it yourself.");
        }
    } else {
        Client::deny(&full).context("deny")?;
        println!("✗ denied {short}.");
    }
    Ok(())
}

/// Run a held command yourself, reversibly.
///
/// Resolves the id (or the sole held command when none is given), shows exactly
/// what will run and whether `kintsugi undo` can cover it, asks for a typed code on
/// the real terminal, then approves it through the daemon (which snapshots the
/// predicted paths and logs the resolution) and executes the raw command in its
/// original directory.
///
/// The agent never runs the command — this is the human, in their own terminal.
/// The confirmation is a random code shown on `/dev/tty` that the human types
/// back, so an agent shelling out to this can't self-approve by pre-stuffing a
/// keypress. (A determined same-user process that can read your terminal could
/// still echo the code — Kintsugi guards mistakes, not a malicious local process;
/// see the honest guarantee in CLAUDE.md.)
fn cmd_run(id: Option<&str>) -> Result<()> {
    if !Client::is_daemon_running() {
        anyhow::bail!("the daemon isn't running; start it with `kintsugi init`");
    }
    let items = Client::list_pending().context("list pending")?;
    if items.is_empty() {
        println!("The approval queue is empty — nothing to run.");
        return Ok(());
    }
    let item = match id {
        Some(prefix) => {
            let m: Vec<_> = items
                .iter()
                .filter(|i| i.command.id.to_string().starts_with(prefix))
                .collect();
            match m.as_slice() {
                [one] => *one,
                [] => anyhow::bail!("no held command matches id `{prefix}` (see `kintsugi queue`)"),
                _ => anyhow::bail!("id `{prefix}` is ambiguous; use more characters"),
            }
        }
        // No id and exactly one held command: use it. Otherwise ask for an id.
        None => match items.as_slice() {
            [one] => one,
            _ => anyhow::bail!(
                "{} commands are held — pass an id (see `kintsugi queue`)",
                items.len()
            ),
        },
    };
    let full = item.command.id.to_string();
    let short = full.get(..8).unwrap_or(&full);

    // In-band origins (shim / MCP) have a caller already waiting to execute on
    // approval; running it here too would double-run it. Redirect to approve.
    if is_in_band(&item.command.agent) {
        anyhow::bail!(
            "{short} came from the `{}` adapter, which is waiting to run it itself — \
             approve it with `kintsugi approve {short}` (or press `a` in `kintsugi tui`).",
            item.command.agent
        );
    }

    let reversible = kintsugi_core::snapshot::is_fully_reversible(&item.command);
    println!("Run this held command yourself? Kintsugi snapshots first, then runs it in");
    println!("its original directory. The agent does not run it — you do.");
    println!();
    println!("    {}", item.command.raw);
    println!();
    println!("  dir:    {}", item.command.cwd.display());
    println!("  class:  {}", item.class.as_str());
    println!("  reason: {}", item.reason);
    if reversible {
        println!("  undo:   `kintsugi undo` can roll this back — the snapshot covers its targets.");
    } else {
        println!("  undo:   ⚠ unbounded target (glob/expansion/root/device): a snapshot may NOT");
        println!("          fully cover it. The filesystem-watcher backstop is the only net.");
    }
    println!();

    if !confirm_code_on_tty() {
        println!("Not run. (It stays queued; `kintsugi deny {short}` to drop it.)");
        return Ok(());
    }

    // Approve via the daemon: snapshots the predicted paths, logs the Allow
    // resolution, and marks the queue entry resolved (CAS, exactly once). Honors
    // the kill-switch.
    Client::approve(&full).context("approve for run")?;
    // Execute the raw command (preserving chaining/redirects) in its original
    // directory, inheriting stdio so the user sees output live.
    let status = run_in_shell(&item.command.cwd, &item.command.raw)?;
    let code = status.code().unwrap_or(1);
    println!();
    if code == 0 {
        let tail = if reversible {
            " Reverse it with `kintsugi undo`."
        } else {
            ""
        };
        println!("✓ ran {short}.{tail}");
    } else {
        println!("• {short} exited with code {code}.");
    }
    std::process::exit(code);
}

/// Execute a raw command line in `cwd` via the platform shell, inheriting stdio.
fn run_in_shell(cwd: &std::path::Path, raw: &str) -> Result<std::process::ExitStatus> {
    let mut cmd = if cfg!(windows) {
        let mut c = std::process::Command::new("cmd");
        c.arg("/C").arg(raw);
        c
    } else {
        let mut c = std::process::Command::new("sh");
        c.arg("-c").arg(raw);
        c
    };
    cmd.current_dir(cwd);
    cmd.status().with_context(|| format!("run `{raw}`"))
}

/// Confirm by showing a random code on the real terminal (`/dev/tty`) and
/// requiring the human to type it back. Reading from `/dev/tty` (not stdin)
/// means an agent with piped stdio can't answer; the *random* code means a
/// pre-stuffed terminal buffer won't match either. Returns false with no tty.
#[cfg(unix)]
fn confirm_code_on_tty() -> bool {
    use std::io::{Read, Write};
    let code = tty_code();
    let Ok(mut tty) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
    else {
        eprintln!(
            "kintsugi: no terminal to confirm on — run `kintsugi run` from an interactive shell."
        );
        return false;
    };
    let _ = write!(
        tty,
        "This prompt is Kintsugi (not the agent). To run it, type  {code}  then Enter: "
    );
    let _ = tty.flush();
    let mut buf = [0u8; 64];
    let n = tty.read(&mut buf).unwrap_or(0);
    String::from_utf8_lossy(&buf[..n]).trim() == code
}

/// A short unpredictable code from the OS RNG (falls back to a time seed).
#[cfg(unix)]
fn tty_code() -> String {
    use std::io::Read;
    let mut b = [0u8; 2];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .is_err()
    {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        b = [(n >> 8) as u8, n as u8];
    }
    format!("{:02x}{:02x}", b[0], b[1])
}

#[cfg(not(unix))]
fn confirm_code_on_tty() -> bool {
    use std::io::Write;
    // Best effort on non-Unix: prompt and read a line from stdin.
    print!("Type 'yes' to run it: ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim(), "yes" | "YES")
}

fn cmd_panic() -> Result<()> {
    let path = kintsugi_daemon::kill_switch_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&path, b"engaged\n").with_context(|| format!("write {}", path.display()))?;
    log_control_event("panic", Decision::Deny, "kill-switch:engaged");
    println!("⛔ Kill-switch ENGAGED. All agent actions are now denied.");
    println!("   Run `kintsugi resume` to restore normal operation.");
    Ok(())
}

fn cmd_resume() -> Result<()> {
    let path = kintsugi_daemon::kill_switch_path();
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
        let cmd = ProposedCommand::new("kintsugi", cwd, vec![name.to_string()], name);
        let _ = log.log_event(&cmd, &Verdict::rules(Class::Safe, decision, reason), None);
    }
}

/// Where snapshots live: alongside the event-log database.
fn snapshot_dir() -> PathBuf {
    default_db_path()
        .parent()
        .map(|p| p.join("snapshots"))
        .unwrap_or_else(|| std::env::temp_dir().join("kintsugi-snapshots"))
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
        kintsugi_core::restore_snapshot(&dir, m)
            .with_context(|| format!("restore snapshot for `{}`", m.command))?;
        log.mark_reverted(&m.id)?;
        // Record the undo itself (append-only; never rewrite history).
        let cwd = std::env::current_dir().unwrap_or_default();
        let raw = format!("undo {}", m.command);
        let cmd = ProposedCommand::new("kintsugi", cwd, vec!["undo".into(), m.id.clone()], raw);
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
    // `KINTSUGI_DATA_DIR` overrides the platform data dir (deterministic in tests and
    // portable across OSes, where `directories` resolves the data dir differently).
    if let Ok(dir) = std::env::var("KINTSUGI_DATA_DIR") {
        return PathBuf::from(dir).join("shims");
    }
    if let Some(dirs) = directories::ProjectDirs::from("", "", "kintsugi") {
        return dirs.data_dir().join("shims");
    }
    std::env::temp_dir().join("kintsugi-shims")
}

fn cmd_init(no_daemon: bool) -> Result<()> {
    println!("kintsugi init");
    println!();

    // 1. Shims for raw shell-outs.
    let shim_bin = init::sibling_bin("kintsugi-shim");
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
            "  • no agent config dirs detected (~/.claude, ~/.qwen, ~/.gemini, ~/.copilot, ~/.cursor, ~/.codex, ~/.config/opencode)"
        );
    }
    let mut mcp_agents = Vec::new();
    for agent in &agents {
        match agent.via {
            init::Interception::Hook(kind) => match wire_hook(kind, home.as_deref()) {
                Ok(()) => println!("  ✓ {}: wired via {}", agent.name, agent.via.as_str()),
                Err(e) => println!("  ✗ {}: could not wire ({e})", agent.name),
            },
            init::Interception::Mcp => {
                mcp_agents.push(agent.name);
                println!("  • {}: intercept via {}", agent.name, agent.via.as_str());
            }
        }
    }
    if !mcp_agents.is_empty() {
        println!();
        println!(
            "  To wire MCP agents ({}), add the kintsugi-exec server:",
            mcp_agents.join(", ")
        );
        println!(
            "        command = \"{}\"",
            init::sibling_bin("kintsugi-mcp").display()
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

    // Report the active scorer so a model-less daemon (the most common surprise
    // after setting up a model) is visible right here, not silently degraded.
    if !no_daemon {
        if let Some(label) = active_scorer_label() {
            println!("  ✓ scoring with: {label}");
        }
    }

    println!();
    println!("Done. Try: kintsugi status");
    Ok(())
}

/// The `kintsugi-hook --agent <id>` command string a CLI's config should invoke.
fn hook_command(agent: &str) -> String {
    format!(
        "{} --agent {agent}",
        init::sibling_bin("kintsugi-hook").display()
    )
}

/// Back up a user-owned file before we modify it, once, next to the original.
fn backup_once(path: &std::path::Path) {
    if path.exists() {
        let backup = path.with_extension(format!(
            "{}.kintsugi-bak",
            path.extension().and_then(|e| e.to_str()).unwrap_or("bak")
        ));
        let _ = std::fs::copy(path, backup);
    }
}

fn write_file(path: &std::path::Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(path, contents).with_context(|| format!("write {}", path.display()))
}

/// Wire a single detected agent by writing its CLI-specific hook config.
fn wire_hook(kind: init::HookKind, home: Option<&std::path::Path>) -> Result<()> {
    let Some(home) = home else {
        return Ok(());
    };
    use init::HookKind::*;
    match kind {
        Claude => wire_settings_json(home, ".claude", "PreToolUse", "Bash", "claude"),
        Qwen => wire_settings_json(
            home,
            ".qwen",
            "PreToolUse",
            "run_shell_command|Bash|Shell|ShellTool",
            "qwen",
        ),
        Gemini => wire_settings_json(home, ".gemini", "BeforeTool", "run_shell_command", "gemini"),
        Cursor => wire_cursor(home),
        Copilot => wire_copilot(home),
        Codex => wire_codex(home),
        OpenCode => wire_opencode(home),
    }
}

/// Claude/Qwen/Gemini: merge a hook into `~/.<dir>/settings.json`.
fn wire_settings_json(
    home: &std::path::Path,
    dir: &str,
    event: &str,
    matcher: &str,
    agent: &str,
) -> Result<()> {
    let path = home.join(dir).join("settings.json");
    let existing = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());
    backup_once(&path);
    let merged = init::merge_settings_hook(existing, event, matcher, &hook_command(agent));
    write_file(&path, &serde_json::to_string_pretty(&merged)?)
}

/// Cursor: merge a `beforeShellExecution` hook into `~/.cursor/hooks.json`.
fn wire_cursor(home: &std::path::Path) -> Result<()> {
    let path = home.join(".cursor").join("hooks.json");
    let existing = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());
    backup_once(&path);
    let merged = init::merge_cursor_hooks(existing, &hook_command("cursor"));
    write_file(&path, &serde_json::to_string_pretty(&merged)?)
}

/// Copilot: write `~/.copilot/hooks/kintsugi.json` (a file Kintsugi owns wholesale).
fn wire_copilot(home: &std::path::Path) -> Result<()> {
    let path = home.join(".copilot").join("hooks").join("kintsugi.json");
    let cfg = init::copilot_hooks_config(&hook_command("copilot"));
    write_file(&path, &serde_json::to_string_pretty(&cfg)?)
}

/// Codex: merge a `[[hooks.PreToolUse]]` block into `~/.codex/config.toml`.
fn wire_codex(home: &std::path::Path) -> Result<()> {
    let path = home.join(".codex").join("config.toml");
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    backup_once(&path);
    let merged = init::merge_codex_toml(&existing, &hook_command("codex"))?;
    write_file(&path, &merged)
}

/// OpenCode: write the JS bridge plugin to `~/.config/opencode/plugin/kintsugi.js`.
fn wire_opencode(home: &std::path::Path) -> Result<()> {
    let path = home
        .join(".config")
        .join("opencode")
        .join("plugin")
        .join("kintsugi.js");
    let hook_bin = init::sibling_bin("kintsugi-hook");
    let js = init::opencode_plugin_js(&hook_bin.to_string_lossy());
    write_file(&path, &js)
}

/// Bare `kintsugi`: a short banner that tells you the current state and the next step.
fn cmd_banner() -> Result<()> {
    println!("kintsugi {}", env!("CARGO_PKG_VERSION"));
    println!("A local-first safety layer for AI coding agents.");
    println!();
    if kintsugi_daemon::kill_switch_path().exists() {
        println!("  ⚠ KILL-SWITCH ENGAGED — all agent actions are denied.");
        println!("    run `kintsugi resume` to clear it.");
    } else if Client::is_daemon_running() {
        println!("  ✓ running and guarding your machine.");
        if let Some(label) = active_scorer_label() {
            println!("    model: {label}");
        }
        println!("    `kintsugi tui` (live timeline) · `kintsugi status` · `kintsugi stop`");
    } else {
        println!("  • not running yet.");
        println!("    run `kintsugi init` to detect your agents and start the daemon.");
    }
    println!();
    println!("Run `kintsugi --help` for all commands.");
    Ok(())
}

fn cmd_stop() -> Result<()> {
    // When settings are admin-locked, stopping requires the admin password.
    if !admin_cmd::allow_stop() {
        return Ok(());
    }
    let running = Client::is_daemon_running();
    let pid_path = kintsugi_daemon::pid_file_path();
    let pid = std::fs::read_to_string(&pid_path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    match pid {
        Some(pid) => {
            kill_pid(&pid);
            let _ = std::fs::remove_file(&pid_path);
            println!("kintsugi: stopped the daemon (pid {pid}).");
        }
        None if running => {
            println!(
                "kintsugi: the daemon is running but its PID file is missing.\n  \
                 Stop it manually (e.g. `pkill kintsugi-daemon`)."
            );
        }
        None => println!("kintsugi: the daemon is not running."),
    }
    Ok(())
}

/// The GitHub repo + installer URL. The installer is the single source of
/// truth for download/checksum/source-fallback logic — `update` just re-runs it.
const UPDATE_REPO: &str = "arrowassassin/kintsugi";
const INSTALL_URL: &str =
    "https://github.com/arrowassassin/kintsugi/releases/latest/download/install.sh";

/// `kintsugi update`: check GitHub for a newer release and (with consent) install it.
///
/// Egress here is the one explicit, user-invoked exception to the "never phone
/// home" guardrail: it is never automatic, sends no command/code/telemetry, and
/// only fetches the latest release tag (and, on install, the verified installer).
fn cmd_update(check_only: bool, yes: bool) -> Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    println!("kintsugi {current} — checking GitHub for a newer release…");

    let tag = latest_release_tag().context("check for the latest release")?;
    let latest = tag.trim_start_matches('v');
    if !version_is_newer(&tag, current) {
        println!("  ✓ up to date (latest release is {tag}).");
        return Ok(());
    }
    println!("  ↑ update available: {current} → {latest}");

    let one_liner = format!("curl -fsSL {INSTALL_URL} | sh -s -- --bin-only");
    if check_only {
        println!("    install it with:");
        println!("      {one_liner}");
        return Ok(());
    }
    // If the running daemon has the in-process llama engine, the update must
    // rebuild it for the new version (and keep the configured model) rather than
    // drop back to the prebuilt heuristic-only build.
    let had_llama = daemon_has_llama();
    let prompt = if had_llama {
        "Download the update and rebuild the local model engine now?"
    } else {
        "Download and install the new binaries now?"
    };
    if !yes && !confirm(prompt)? {
        println!("  • skipped. To update later:  kintsugi update   (or: {one_liner})");
        return Ok(());
    }

    run_installer(&tag, had_llama).context("install the update")?;
    println!(
        "  ✓ updated to {latest}. Restart the daemon to run it:  kintsugi stop && kintsugi init"
    );
    Ok(())
}

/// Whether the installed `kintsugi-daemon` (sibling of this binary) has the llama
/// engine compiled in — probed without starting it.
fn daemon_has_llama() -> bool {
    let Some(daemon) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("kintsugi-daemon")))
    else {
        return false;
    };
    std::process::Command::new(daemon)
        .arg("--has-llama")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Fetch the `tag_name` of the latest GitHub release via curl/wget.
fn latest_release_tag() -> Result<String> {
    let url = format!("https://api.github.com/repos/{UPDATE_REPO}/releases/latest");
    let body = http_get(&url)?;
    let json: serde_json::Value =
        serde_json::from_slice(&body).context("parse the GitHub release response")?;
    json.get("tag_name")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .context("no tag_name in the GitHub response (no published release yet?)")
}

/// HTTP GET via curl (then wget). No headers beyond the tool's defaults, no body
/// — so no user data leaves the machine. Returns the response bytes.
fn http_get(url: &str) -> Result<Vec<u8>> {
    let attempts: [(&str, &[&str]); 2] = [("curl", &["-fsSL", url]), ("wget", &["-qO-", url])];
    for (bin, args) in attempts {
        match std::process::Command::new(bin).args(args).output() {
            Ok(out) if out.status.success() => return Ok(out.stdout),
            // Tool ran but the request failed (or the tool is missing): try the next.
            Ok(_) | Err(_) => continue,
        }
    }
    anyhow::bail!("could not reach GitHub — need curl or wget and network access")
}

/// Download the installer and run it, targeting the dir the running `kintsugi`
/// binary lives in so the update lands in the same place. Pins to `tag` so the
/// binaries (and, when rebuilding, the engine) all match the resolved release.
/// With `had_llama`, rebuilds the local engine and keeps the model instead of
/// installing the prebuilt heuristic-only binaries.
fn run_installer(tag: &str, had_llama: bool) -> Result<()> {
    let script = http_get(INSTALL_URL).context("download the installer")?;
    let tmp = std::env::temp_dir().join(format!("kintsugi-update-{}.sh", std::process::id()));
    std::fs::write(&tmp, &script).with_context(|| format!("write {}", tmp.display()))?;

    let mut cmd = std::process::Command::new("sh");
    cmd.arg(&tmp).arg("--version").arg(tag);
    if had_llama {
        // Install the new binaries, then rebuild the engine for this version and
        // keep the configured model; don't re-wire agents (--no-init).
        cmd.arg("--no-init").arg("--with-model");
    } else {
        cmd.arg("--bin-only");
    }
    // Target the dir the running binary lives in, so the update lands in place.
    let exe = std::env::current_exe().ok();
    if let Some(parent) = exe.as_deref().and_then(|p| p.parent()) {
        cmd.arg("--bin-dir").arg(parent);
    }
    let status = cmd.status().context("run the installer");
    let _ = std::fs::remove_file(&tmp);
    let status = status?;
    if !status.success() {
        anyhow::bail!("installer exited unsuccessfully ({status})");
    }
    Ok(())
}

/// A y/N confirmation read from the terminal. Non-interactive ⇒ `false` (never
/// modify binaries without an explicit answer).
fn confirm(prompt: &str) -> Result<bool> {
    use std::io::Write;
    if !std::io::stdin().is_terminal() {
        return Ok(false);
    }
    print!("{prompt} [y/N] ");
    std::io::stdout().flush().ok();
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "Yes"))
}

/// Parse a `vMAJOR.MINOR.PATCH`-ish version into a comparable tuple. Tolerant of
/// a leading `v` and pre-release/build suffixes (compared on the numeric core).
fn parse_version(s: &str) -> Option<(u64, u64, u64)> {
    let core = s.trim().trim_start_matches('v');
    let mut parts = core.split(['.', '-', '+']);
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;
    Some((major, minor, patch))
}

/// True when `latest` is a strictly newer release than `current`. If either is
/// unparseable, fall back to "they differ" rather than silently claiming current.
fn version_is_newer(latest: &str, current: &str) -> bool {
    match (parse_version(latest), parse_version(current)) {
        (Some(l), Some(c)) => l > c,
        _ => latest.trim_start_matches('v') != current.trim_start_matches('v'),
    }
}

/// Best-effort terminate a PID across platforms.
#[cfg(unix)]
fn kill_pid(pid: &str) {
    let _ = std::process::Command::new("kill").arg(pid).status();
}
#[cfg(not(unix))]
fn kill_pid(pid: &str) {
    let _ = std::process::Command::new("taskkill")
        .args(["/PID", pid, "/F"])
        .status();
}

fn start_daemon() -> Result<()> {
    let daemon_bin = init::sibling_bin("kintsugi-daemon");
    std::process::Command::new(&daemon_bin)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("start daemon {}", daemon_bin.display()))?;
    // The daemon writes its own PID file (used by `kintsugi stop`) once it binds.
    // Wait (generously, for loaded CI) for it to bind before returning.
    for _ in 0..150 {
        if Client::is_daemon_running() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    Ok(())
}

/// Map a daemon scorer backend id to a one-line, human-readable description.
/// `llama:<model>` means the local model loaded; `heuristic` is the always-on
/// offline fallback (and a hint at why, so a missing `KINTSUGI_MODEL_FILE` is
/// diagnosable without reading the daemon's swallowed stderr).
fn describe_scorer(name: &str) -> String {
    if let Some(model) = name.strip_prefix("llama:") {
        format!("{model} (local model)")
    } else if name == "heuristic" {
        "heuristic fallback (no local model — set KINTSUGI_MODEL_FILE)".to_string()
    } else {
        name.to_string()
    }
}

/// Human-friendly description of the daemon's active scorer, asked over IPC.
/// `None` when the daemon isn't running or doesn't answer.
fn active_scorer_label() -> Option<String> {
    Client::status_scorer().ok().map(|n| describe_scorer(&n))
}

fn cmd_status() -> Result<()> {
    println!("kintsugi {}", env!("CARGO_PKG_VERSION"));
    let running = Client::is_daemon_running();
    println!("  daemon:  {}", if running { "running" } else { "stopped" });
    println!("  socket:  {}", ipc::socket_path().display());
    if running {
        match Client::status_scorer() {
            Ok(name) => println!("  model:   {}", describe_scorer(&name)),
            Err(_) => println!("  model:   (daemon not answering)"),
        }
    }

    // The panic kill-switch is the loudest state — surface it prominently.
    if kintsugi_daemon::kill_switch_path().exists() {
        println!("  KILL-SWITCH: ENGAGED — all actions denied (run `kintsugi resume`)");
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

fn cmd_log(number: usize, page: usize, show_redacted: bool, filter: &FilterArgs) -> Result<()> {
    let db = default_db_path();
    if !db.exists() {
        print!("{}", logview::render_log(&[], false));
        return Ok(());
    }
    let log = EventLog::open(&db).with_context(|| format!("open log {}", db.display()))?;
    let number = number.max(1);
    let page = page.max(1);
    let offset = (page - 1) * number;

    let color = logview::use_color(
        std::env::var_os("NO_COLOR").is_some(),
        std::io::stdout().is_terminal(),
    );

    let f = filter.to_filter_paged(show_redacted, Some(number), Some(offset))?;
    let mut events = log.query(&f)?;
    // The query returns the page oldest-first; flip it so the newest command in
    // the page is on top.
    events.reverse();

    // Total matches (counting ignores limit/offset) for the page footer.
    let total = log.count_matching(&filter.to_filter(show_redacted, None)?)? as usize;

    if events.is_empty() {
        if total == 0 {
            // Genuinely empty log → the designed empty state.
            print!("{}", logview::render_log(&events, color));
        } else {
            // Paged past the end.
            println!("  no events on page {page} — {total} total; newest is page 1.");
        }
        return Ok(());
    }

    print!("{}", logview::render_log(&events, color));
    print!(
        "{}",
        logview::render_page_footer(page, offset, events.len(), total, color)
    );
    Ok(())
}

/// `kintsugi report` — the destructive commands on the timeline, for an
/// audit/compliance review. Shows catastrophic (and, by default, ambiguous)
/// events newest-first; honors the same time/agent/session filters as `log`.
fn cmd_report(catastrophic_only: bool, number: usize, filter: &FilterArgs) -> Result<()> {
    let db = default_db_path();
    if !db.exists() {
        println!("No events recorded yet — nothing to report.");
        return Ok(());
    }
    let log = EventLog::open(&db).with_context(|| format!("open log {}", db.display()))?;
    let color = logview::use_color(
        std::env::var_os("NO_COLOR").is_some(),
        std::io::stdout().is_terminal(),
    );

    // The core Filter holds a single class; a report spans two. Query without a
    // class filter and keep the destructive ones in Rust, so one pass covers
    // both bands. Pull a generous window, then trim to `number` after filtering.
    let f = filter.to_filter(false, Some(number.max(1) * 50))?;
    let mut events = log.query(&f)?;
    events.retain(|e| match e.class {
        Class::Catastrophic => true,
        Class::Ambiguous => !catastrophic_only,
        Class::Safe => false,
    });
    events.reverse(); // newest first
    events.truncate(number.max(1));

    if events.is_empty() {
        let scope = if catastrophic_only {
            "catastrophic"
        } else {
            "destructive"
        };
        println!("No {scope} commands in scope. The timeline is clean for this filter.");
        return Ok(());
    }

    let band = if catastrophic_only {
        "catastrophic"
    } else {
        "destructive (catastrophic + ambiguous)"
    };
    println!("Audit report — {band} commands, newest first:\n");
    print!("{}", logview::render_log(&events, color));
    println!(
        "\n{} command(s) shown. Full chain integrity: `kintsugi status`.",
        events.len()
    );
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
        "redacted {n} event(s) — hidden from views; chain intact (use `kintsugi purge` to erase)"
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
    let all = log.query(&kintsugi_core::Filter {
        include_redacted: true,
        ..kintsugi_core::Filter::default()
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
    fn run_in_shell_propagates_exit_code() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(run_in_shell(tmp.path(), "exit 0").unwrap().success());
        let st = run_in_shell(tmp.path(), "exit 7").unwrap();
        assert_eq!(st.code(), Some(7));
    }

    #[cfg(unix)]
    #[test]
    fn tty_code_is_short_and_hex() {
        let c = tty_code();
        assert_eq!(c.len(), 4);
        assert!(c.chars().all(|ch| ch.is_ascii_hexdigit()), "got {c}");
    }

    #[test]
    fn in_band_only_for_shim_and_mcp() {
        // Shim and MCP have a caller waiting → approve runs it there.
        assert!(is_in_band("shim"));
        assert!(is_in_band("mcp"));
        // Hook origins are one-shot → `kintsugi run` is the way to run them.
        assert!(!is_in_band("claude-code"));
        assert!(!is_in_band("cursor"));
        assert!(!is_in_band("codex"));
    }

    #[test]
    fn version_compare_handles_tags_and_suffixes() {
        // Newer wins, with or without the leading `v`.
        assert!(version_is_newer("v0.2.0", "0.1.0"));
        assert!(version_is_newer("0.1.1", "0.1.0"));
        assert!(version_is_newer("v1.0.0", "0.9.9"));
        // Same or older does not trigger an update.
        assert!(!version_is_newer("v0.1.0", "0.1.0"));
        assert!(!version_is_newer("0.1.0", "0.2.0"));
        // Pre-release/build suffixes compare on the numeric core.
        assert_eq!(parse_version("v0.1.0-rc1"), Some((0, 1, 0)));
        assert_eq!(parse_version("0.1"), Some((0, 1, 0)));
        // Unparseable tag: fall back to "differs" so we don't hide a real release.
        assert!(version_is_newer("nightly", "0.1.0"));
        assert!(!version_is_newer("v0.1.0", "0.1.0"));
    }

    #[test]
    fn describe_scorer_distinguishes_model_from_fallback() {
        // The local model loaded: show the model name, marked as such.
        let m = describe_scorer("llama:Qwen3-4B-Instruct-2507-Q4_K_M");
        assert!(m.contains("Qwen3-4B-Instruct-2507-Q4_K_M"));
        assert!(m.contains("local model"));
        assert!(!m.starts_with("llama:"), "the raw backend prefix is hidden");

        // The offline fallback: name it and hint at the fix.
        let h = describe_scorer("heuristic");
        assert!(h.contains("heuristic"));
        assert!(h.contains("KINTSUGI_MODEL_FILE"));

        // An unknown backend id is passed through verbatim, not dropped.
        assert_eq!(describe_scorer("future-backend"), "future-backend");
    }

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
        assert_eq!(core.class, Some(kintsugi_core::Class::Catastrophic));
        assert_eq!(core.limit, Some(10));

        let bad = FilterArgs {
            class: Some("nope".into()),
            ..f
        };
        assert!(bad.to_filter(false, None).is_err());
    }
}
