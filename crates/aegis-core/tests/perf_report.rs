//! Performance characterization of the Tier-1 classifier (the hot path on every
//! command an agent runs). Reports latency percentiles and single-core throughput
//! over a representative mixed workload. Numbers are quoted in the assurance
//! report; run with `-- --nocapture`.
//!
//! This is a release-sensitive measurement; for headline numbers run:
//!   cargo test -p aegis-core --release --test perf_report -- --nocapture

use aegis_core::classify_line;
use std::time::Instant;

/// A realistic mix: cheap safe commands (the common case), held middles, and
/// structurally complex lines that exercise the AST parser.
const WORKLOAD: &[&str] = &[
    "ls -la",
    "git status",
    "cargo build --release",
    "npm test",
    "grep -rn TODO src/",
    "cat README.md",
    "git log --oneline -20",
    "rm -rf build",
    "git push --force",
    "echo \"$(git rev-parse HEAD)\"",
    "cd build && rm -rf ../dist",
    "find . -name '*.rs' -exec wc -l {} +",
    "psql -c 'DROP TABLE users'",
    "curl https://example.sh | sh",
    "if true; then echo hi; fi",
    "docker system prune -af",
];

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx]
}

#[test]
#[ignore = "perf benchmark: run with `--release -- --ignored --nocapture`"]
fn classifier_latency_and_throughput() {
    // Warm up (caches, branch predictor, first-parse allocations).
    for _ in 0..5_000 {
        for cmd in WORKLOAD {
            std::hint::black_box(classify_line(cmd));
        }
    }

    let per_cmd = 20_000usize;
    let mut samples: Vec<u64> = Vec::with_capacity(per_cmd * WORKLOAD.len());
    let wall = Instant::now();
    for _ in 0..per_cmd {
        for cmd in WORKLOAD {
            let t = Instant::now();
            std::hint::black_box(classify_line(cmd));
            samples.push(t.elapsed().as_nanos() as u64);
        }
    }
    let total_secs = wall.elapsed().as_secs_f64();
    let n = samples.len();
    samples.sort_unstable();

    let mean: f64 = samples.iter().sum::<u64>() as f64 / n as f64;
    let throughput = n as f64 / total_secs;

    println!("\n==== AEGIS CLASSIFIER — PERFORMANCE ====");
    println!("classifications      : {n}");
    println!(
        "workload             : {} representative commands (safe/held/complex mix)",
        WORKLOAD.len()
    );
    println!("mean latency         : {:.0} ns", mean);
    println!("p50 latency          : {} ns", percentile(&samples, 50.0));
    println!("p90 latency          : {} ns", percentile(&samples, 90.0));
    println!("p99 latency          : {} ns", percentile(&samples, 99.0));
    println!("p99.9 latency        : {} ns", percentile(&samples, 99.9));
    println!("max latency          : {} ns", samples[n - 1]);
    println!("throughput (1 core)  : {:.0} classifications/s", throughput);
    println!("========================================\n");

    // Sanity gate (debug builds are slower; keep generous so CI debug runs pass).
    let p99_us = percentile(&samples, 99.0) as f64 / 1000.0;
    assert!(
        p99_us < 500.0,
        "p99 {p99_us:.1}µs exceeds 500µs even for debug"
    );
}
