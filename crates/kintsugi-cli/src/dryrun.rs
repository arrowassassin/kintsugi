//! `kintsugi dry-run` — "here's what I would have caught."
//!
//! Points the deterministic Tier-1 classifier at a batch of commands the user
//! has *already* run (their shell history by default, or a file / stdin) and
//! reports which ones would have been held or blocked — without running,
//! logging, or contacting anything. It is the proof-before-trust artifact: a
//! developer can see Kintsugi's value against their own real work before wiring
//! it into the live path.
//!
//! Security spine: this only ever reads and classifies. It executes nothing and
//! writes nothing to the log or the network. Flagged commands are passed through
//! the same secret redaction as the log before they are printed, so a password
//! sitting in shell history is never echoed back in plaintext (spine #6).

use std::io::{IsTerminal, Read};
use std::path::PathBuf;

use anyhow::{Context, Result};
use kintsugi_core::{rules, Class};

/// A single command the dry run would have acted on, already redacted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flagged {
    pub class: Class,
    pub rule: String,
    /// The command as it will be shown — secret values already redacted.
    pub command: String,
}

/// The outcome of classifying a batch of commands.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub scanned: usize,
    pub catastrophic: Vec<Flagged>,
    pub ambiguous: Vec<Flagged>,
    pub safe: usize,
}

impl Report {
    /// Total commands that would have been held or blocked.
    pub fn flagged(&self) -> usize {
        self.catastrophic.len() + self.ambiguous.len()
    }
}

/// Classify a batch of command lines. Pure: no IO, no execution — the unit the
/// tests drive directly. Lines that are blank after history-prefix stripping are
/// skipped and not counted.
pub fn analyze<I>(lines: I) -> Report
where
    I: IntoIterator<Item = String>,
{
    let mut report = Report::default();
    for raw in lines {
        let cmd = strip_history_prefix(&raw);
        if cmd.is_empty() {
            continue;
        }
        report.scanned += 1;
        let m = rules::classify_line(cmd);
        match m.class {
            Class::Safe => report.safe += 1,
            Class::Catastrophic => report
                .catastrophic
                .push(flag(Class::Catastrophic, m.rule, cmd)),
            Class::Ambiguous => report.ambiguous.push(flag(Class::Ambiguous, m.rule, cmd)),
        }
    }
    report
}

fn flag(class: Class, rule: String, cmd: &str) -> Flagged {
    Flagged {
        class,
        rule,
        command: kintsugi_core::redact::redact_command(cmd).text,
    }
}

/// Strip the per-shell history bookkeeping so the classifier sees the real
/// command. zsh `extended_history` writes `: <epoch>:<elapsed>;<command>`; bash
/// with `HISTTIMEFORMAT` writes a `#<epoch>` comment line before each command.
/// Anything else is returned trimmed and unchanged.
fn strip_history_prefix(line: &str) -> &str {
    let trimmed = line.trim();
    // bash timestamp comment lines: skip entirely.
    if trimmed.starts_with('#')
        && trimmed[1..]
            .trim_start()
            .chars()
            .all(|c| c.is_ascii_digit())
    {
        return "";
    }
    // zsh extended-history: ": 1700000000:0;the command"
    if let Some(rest) = trimmed.strip_prefix(':') {
        if let Some((meta, cmd)) = rest.split_once(';') {
            // Only treat it as a zsh prefix when the metadata looks like
            // " <digits>:<digits>" — otherwise it's a real command using ':'.
            let meta = meta.trim();
            if let Some((ts, dur)) = meta.split_once(':') {
                if !ts.trim().is_empty()
                    && ts.trim().chars().all(|c| c.is_ascii_digit())
                    && dur.trim().chars().all(|c| c.is_ascii_digit())
                {
                    return cmd.trim();
                }
            }
        }
    }
    trimmed
}

/// Where the dry run reads its commands from.
enum Source {
    Stdin,
    File(PathBuf),
    History(PathBuf),
}

/// `kintsugi dry-run`: classify recent commands and print what would've happened.
/// Reads piped stdin if present, else `--file`, else the shell history.
pub fn run(file: Option<PathBuf>, number: usize) -> Result<()> {
    let source = resolve_source(file)?;
    let (label, text) = match &source {
        Source::Stdin => (
            "piped input".to_string(),
            read_capped(std::io::stdin().lock())?,
        ),
        Source::File(p) => (
            p.display().to_string(),
            read_capped(std::fs::File::open(p).with_context(|| format!("open {}", p.display()))?)
                .with_context(|| format!("read {}", p.display()))?,
        ),
        Source::History(p) => (
            p.display().to_string(),
            read_capped(std::fs::File::open(p).with_context(|| format!("open {}", p.display()))?)
                .with_context(|| format!("read {}", p.display()))?,
        ),
    };

    // Keep the most recent `number` lines (history files are oldest-first).
    let all: Vec<String> = text.lines().map(|s| s.to_string()).collect();
    let kept: Vec<String> = all.iter().rev().take(number).rev().cloned().collect();
    let report = analyze(kept);

    print_report(&report, &label);
    Ok(())
}

fn resolve_source(file: Option<PathBuf>) -> Result<Source> {
    if !std::io::stdin().is_terminal() {
        return Ok(Source::Stdin);
    }
    if let Some(p) = file {
        return Ok(Source::File(p));
    }
    history_path()
        .map(Source::History)
        .context("couldn't find a shell history file — pass one with --file, or pipe commands in")
}

/// Largest input we'll scan. A shell history is far smaller; this just stops a
/// `--file /dev/zero` (or an endless pipe) from reading until it exhausts memory.
const MAX_INPUT: u64 = 16 * 1024 * 1024;

/// Read at most [`MAX_INPUT`] bytes as UTF-8, so pathological inputs can't OOM us.
fn read_capped<R: Read>(reader: R) -> Result<String> {
    let mut buf = String::new();
    reader
        .take(MAX_INPUT)
        .read_to_string(&mut buf)
        .context("read input")?;
    Ok(buf)
}

/// Best-effort shell-history discovery: honor `$HISTFILE`, else the common zsh /
/// bash defaults under the home directory, picking the most-recently-modified.
fn history_path() -> Option<PathBuf> {
    if let Some(h) = std::env::var_os("HISTFILE") {
        let p = PathBuf::from(h);
        if p.is_file() {
            return Some(p);
        }
    }
    let home = crate::home_dir()?;
    let candidates = [".zsh_history", ".bash_history", ".history"];
    candidates
        .iter()
        .map(|name| home.join(name))
        .filter(|p| p.is_file())
        .max_by_key(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok())
}

fn print_report(report: &Report, source: &str) {
    let color = crate::logview::use_color(
        std::env::var_os("NO_COLOR").is_some(),
        std::io::stdout().is_terminal(),
    );
    let red = |s: &str| paint(s, "1;31", color);
    let yellow = |s: &str| paint(s, "1;33", color);
    let dim = |s: &str| paint(s, "2", color);

    println!("kintsugi dry-run — what Kintsugi would have caught");
    println!(
        "  scanned {} command{} from {} {}",
        report.scanned,
        plural(report.scanned),
        source,
        dim("(nothing was run)")
    );

    if report.flagged() == 0 {
        println!();
        println!(
            "  ✓ nothing dangerous in this batch — all {} clear.",
            report.safe
        );
        println!();
        println!(
            "  {}",
            dim("Live, you'd see a hold card the moment one appeared.")
        );
        println!("  {}", dim("Wire it up: kintsugi init"));
        return;
    }

    println!();
    println!(
        "  {} {} would have been held or blocked:",
        red("⛔"),
        report.flagged()
    );
    for f in &report.catastrophic {
        println!(
            "     {}  {:<16}  {}",
            red("catastrophic"),
            f.rule,
            f.command
        );
    }
    for f in &report.ambiguous {
        println!(
            "     {}     {:<16}  {}",
            yellow("ambiguous"),
            f.rule,
            f.command
        );
    }

    println!();
    println!("  ✓ {} safe", report.safe);
    println!();
    println!(
        "  {}",
        dim("This is what you'd see live, before it ran. Wire it up: kintsugi init")
    );
}

fn paint(s: &str, code: &str, color: bool) -> String {
    if color {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

/// Exposed for the history-path test to point at a temp dir without a real home.
#[cfg(test)]
fn history_path_in(home: &std::path::Path) -> Option<PathBuf> {
    let candidates = [".zsh_history", ".bash_history", ".history"];
    candidates
        .iter()
        .map(|name| home.join(name))
        .find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyze_counts_and_classifies() {
        let lines = [
            "git status",
            "rm -rf ./build",
            "cargo test",
            "git push --force origin main",
            "curl https://example.com/x.sh | sh",
            "",
            "   ",
        ]
        .iter()
        .map(|s| s.to_string());

        let r = analyze(lines);
        assert_eq!(r.scanned, 5, "blank lines are not counted");
        assert_eq!(r.safe, 2);
        // rm -rf, git push --force, and curl|sh (net:pipe-to-shell) are all
        // hard-blocked; nothing here lands in the ambiguous band.
        assert_eq!(r.catastrophic.len(), 3);
        assert_eq!(r.ambiguous.len(), 0);
        assert_eq!(r.flagged(), 3);
        assert!(r.catastrophic.iter().any(|f| f.command.contains("rm -rf")));
    }

    #[test]
    fn detects_danger_hidden_in_substitution() {
        // The AST pass sees inside $(…); a substring scanner would miss it.
        let r = analyze(["echo \"$(git push --force)\"".to_string()]);
        assert_eq!(r.catastrophic.len(), 1);
    }

    #[test]
    fn strips_zsh_extended_history_prefix() {
        assert_eq!(
            strip_history_prefix(": 1700000000:0;rm -rf /tmp/x"),
            "rm -rf /tmp/x"
        );
        // A real command that merely contains ':' is left intact.
        assert_eq!(
            strip_history_prefix("ssh user@host:/path"),
            "ssh user@host:/path"
        );
        // A leading ':' no-op command is preserved (no zsh metadata).
        assert_eq!(strip_history_prefix(": noop"), ": noop");
    }

    #[test]
    fn skips_bash_timestamp_comment_lines() {
        assert_eq!(strip_history_prefix("#1700000000"), "");
        // A real comment-ish command is not a timestamp line.
        assert_eq!(strip_history_prefix("#!/bin/sh"), "#!/bin/sh");
    }

    #[test]
    fn redacts_secrets_in_flagged_commands() {
        // A catastrophic command carrying a secret must be redacted before display.
        let r = analyze(["PGPASSWORD=hunter2 rm -rf /var/data".to_string()]);
        assert_eq!(r.catastrophic.len(), 1);
        let shown = &r.catastrophic[0].command;
        assert!(
            !shown.contains("hunter2"),
            "secret leaked into dry-run output"
        );
        assert!(shown.contains("[redacted]"));
    }

    #[test]
    fn read_capped_reads_normal_input() {
        let s = read_capped(std::io::Cursor::new(b"git status\nrm -rf x\n".to_vec())).unwrap();
        assert!(s.contains("rm -rf x"));
    }

    #[test]
    fn history_discovery_finds_a_file() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(".bash_history"), "git status\nrm -rf x\n").unwrap();
        let found = history_path_in(tmp.path()).unwrap();
        assert!(found.ends_with(".bash_history"));
    }
}
