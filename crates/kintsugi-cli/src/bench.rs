//! `kintsugi bench` — replay corpora through the deterministic classifier and
//! report class distribution. The measuring stick for every effects-engine
//! change: hold-rate may only go down; catastrophic-as-safe delta must be 0.

use anyhow::{Context, Result};
use kintsugi_core::{classify_line, Class, EventLog, Filter};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchRow {
    pub command: String,
    pub class: Class,
    pub rule: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchReport {
    pub total: usize,
    pub safe: usize,
    pub ambiguous: usize,
    pub catastrophic: usize,
    pub rows: Vec<BenchRow>,
}

pub fn run_corpus(lines: &[String]) -> BenchReport {
    let mut r = BenchReport { total: 0, safe: 0, ambiguous: 0, catastrophic: 0, rows: Vec::new() };
    for line in lines {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let m = classify_line(line);
        r.total += 1;
        match m.class {
            Class::Safe => r.safe += 1,
            Class::Ambiguous => r.ambiguous += 1,
            Class::Catastrophic => r.catastrophic += 1,
        }
        r.rows.push(BenchRow { command: line.to_string(), class: m.class, rule: m.rule });
    }
    r
}

/// Gate check: catastrophic-as-safe delta must be 0 (hard), and the
/// hold-rate (ambiguous+catastrophic share) must not increase.
/// Ok(summary) on pass, Err(reason) on gate failure.
pub fn compare(baseline: &BenchReport, current: &BenchReport) -> Result<String, String> {
    // Any command catastrophic in baseline that is Safe now = I1 violation.
    // For duplicates, keep the SAFEST class seen: Safe > Ambiguous > Catastrophic.
    // This way, a catastrophic command with even one safe occurrence fails the gate.
    let mut cur_by_cmd: std::collections::HashMap<&str, Class> =
        std::collections::HashMap::new();
    for row in &current.rows {
        let cmd = row.command.as_str();
        cur_by_cmd
            .entry(cmd)
            .and_modify(|existing| {
                // Safe > Ambiguous > Catastrophic for gate purposes
                if row.class == Class::Safe {
                    *existing = Class::Safe;
                } else if row.class == Class::Ambiguous && *existing == Class::Catastrophic {
                    *existing = Class::Ambiguous;
                }
            })
            .or_insert(row.class);
    }
    for row in &baseline.rows {
        if row.class == Class::Catastrophic {
            if let Some(Class::Safe) = cur_by_cmd.get(row.command.as_str()) {
                return Err(format!("CATASTROPHIC-AS-SAFE: {:?}", row.command));
            }
        }
    }
    let rate = |r: &BenchReport| {
        if r.total == 0 { 0.0 } else { (r.ambiguous + r.catastrophic) as f64 / r.total as f64 }
    };
    let (b, c) = (rate(baseline), rate(current));
    if c > b + 1e-9 {
        return Err(format!("hold-rate increased: {:.1}% -> {:.1}%", b * 100.0, c * 100.0));
    }
    Ok(format!("hold-rate {:.1}% -> {:.1}% ({} commands)", b * 100.0, c * 100.0, current.total))
}

/// Entry point for the CLI subcommand.
pub fn run(events: bool, corpus: Option<&Path>, json: Option<&Path>, baseline: Option<&Path>, check: bool) -> Result<()> {
    let mut lines: Vec<String> = Vec::new();
    if events {
        let db = kintsugi_daemon::default_db_path();
        let log = EventLog::open(&db).context("open events.db")?;
        let filter = Filter { agent_not: Some("fs-watch".into()), ..Default::default() };
        lines.extend(log.query(&filter)?.into_iter().map(|e| e.command));
    }
    if let Some(p) = corpus {
        lines.extend(std::fs::read_to_string(p).with_context(|| format!("read corpus {}", p.display()))?.lines().map(str::to_string));
    }
    if lines.is_empty() {
        anyhow::bail!("nothing to replay — pass --events and/or --corpus FILE");
    }
    let report = run_corpus(&lines);
    if report.total == 0 {
        anyhow::bail!("corpus contained no commands after filtering comments/blanks — refusing to report a vacuous pass");
    }
    println!(
        "replayed {:>5} commands: {} safe ({:.1}%), {} ambiguous, {} catastrophic",
        report.total,
        report.safe,
        report.safe as f64 * 100.0 / report.total.max(1) as f64,
        report.ambiguous,
        report.catastrophic
    );
    // Top held programs — tells us which manifests to write next.
    let mut held: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for row in report.rows.iter().filter(|r| r.class == Class::Ambiguous) {
        *held.entry(row.rule.clone()).or_default() += 1;
    }
    let mut held: Vec<_> = held.into_iter().collect();
    held.sort_by_key(|b| std::cmp::Reverse(b.1));
    for (rule, n) in held.iter().take(15) {
        println!("  {n:>5}  {rule}");
    }
    if let Some(p) = json {
        std::fs::write(p, serde_json::to_string_pretty(&report)?).with_context(|| format!("write report {}", p.display()))?;
        println!("wrote {}", p.display());
    }
    if let Some(p) = baseline {
        let base: BenchReport = serde_json::from_str(&std::fs::read_to_string(p).with_context(|| format!("read baseline {}", p.display()))?).with_context(|| format!("parse baseline {}", p.display()))?;
        match compare(&base, &report) {
            Ok(s) => println!("gates OK: {s}"),
            Err(e) => {
                eprintln!("GATE FAILED: {e}");
                if check {
                    std::process::exit(1);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kintsugi_core::Class;

    fn report_of(cmds: &[&str]) -> BenchReport {
        run_corpus(&cmds.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn counts_classes() {
        let r = report_of(&["ls", "rm -rf /", "npm install"]);
        assert_eq!((r.total, r.safe, r.catastrophic, r.ambiguous), (3, 1, 1, 1));
        assert_eq!(r.rows[1].class, Class::Catastrophic);
    }

    #[test]
    fn gate_fails_on_cata_as_safe() {
        // Baseline says catastrophic; current says safe → hard failure.
        let base = report_of(&["rm -rf /"]);
        let mut cur = base.clone();
        cur.rows[0].class = Class::Safe;
        cur.safe = 1;
        cur.catastrophic = 0;
        assert!(compare(&base, &cur).is_err());
    }

    #[test]
    fn gate_fails_on_hold_rate_increase() {
        let base = report_of(&["ls", "mkdir x"]);
        let mut cur = base.clone();
        // Pretend `ls` became ambiguous: hold-rate rose.
        cur.rows[0].class = Class::Ambiguous;
        cur.ambiguous += 1;
        cur.safe -= 1;
        assert!(compare(&base, &cur).is_err());
    }

    #[test]
    fn gate_passes_on_improvement() {
        let base = report_of(&["mkdir x"]); // ambiguous today
        let mut cur = base.clone();
        cur.rows[0].class = Class::Safe;
        cur.safe = 1;
        cur.ambiguous = 0;
        assert!(compare(&base, &cur).is_ok());
    }

    #[test]
    fn gate_catches_cata_as_safe_among_duplicates() {
        // Baseline: rm -rf / is catastrophic.
        // Current: two rows for rm -rf / — one Safe, one Catastrophic.
        // Despite the Safe occurrence, the gate should fail because we keep the safest class
        // for duplicate commands, and Safe > Catastrophic means the map holds Safe,
        // triggering the I1 violation.
        let base = BenchReport {
            total: 1,
            safe: 0,
            ambiguous: 0,
            catastrophic: 1,
            rows: vec![BenchRow {
                command: "rm -rf /".to_string(),
                class: Class::Catastrophic,
                rule: "catastrophic".to_string(),
            }],
        };
        let cur = BenchReport {
            total: 2,
            safe: 1,
            ambiguous: 0,
            catastrophic: 1,
            rows: vec![
                BenchRow {
                    command: "rm -rf /".to_string(),
                    class: Class::Safe,
                    rule: "safe".to_string(),
                },
                BenchRow {
                    command: "rm -rf /".to_string(),
                    class: Class::Catastrophic,
                    rule: "catastrophic".to_string(),
                },
            ],
        };
        assert!(compare(&base, &cur).is_err());
    }

    #[test]
    fn empty_corpus_is_an_error_not_a_pass() {
        let r = run_corpus(&["# only a comment".to_string(), "".to_string()]);
        assert_eq!(r.total, 0); // run() refuses this; compare() never sees it
    }
}
