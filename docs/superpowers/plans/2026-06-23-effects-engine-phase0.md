# Effects Engine Phase 0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cut Kintsugi's false-positive ambiguous holds by proving safety from command *effects* (deterministic effect manifests + workspace confinement) and by letting human approvals generalize (template memory) — all measured by a replay harness, with zero catastrophic-as-safe regressions.

**Architecture:** A new `effects` module in kintsugi-core reduces a parsed command segment to a typed `EffectSet` via an embedded declarative manifest; a rescue hook in `classify_segment_depth` may upgrade **only** `ambiguous:{prog}` fall-throughs to Safe when the effect set is complete, bounded, and all-benign. Template memory adds a second, generalizing key to the existing per-repo decision-memory table. A `kintsugi bench` replay harness measures every change against the event log and a vendored corpus.

**Tech Stack:** Rust workspace (kintsugi-core, kintsugi-cli, kintsugi-daemon), rusqlite, serde/toml (already deps of kintsugi-core via policy.rs), clap, Dioxus 0.6 (desktop-dx — separate workspace).

**Spec:** `docs/superpowers/specs/2026-06-23-effects-engine-phase0-1-design.md`

## Global Constraints

- **I1:** Zero catastrophic-classified-as-safe. The golden corpus catastrophic rows in `crates/kintsugi-core/tests/classifier_corpus.rs` must never change class.
- **I2:** The hard block decision is deterministic — no model in any new decision path.
- **I3:** Fail toward caution: unknown program / unresolvable path / manifest failure / template ambiguity → the pre-existing verdict (Ambiguous), never Safe.
- **I4:** Memory (exact or template) never rescues Catastrophic; templates only apply when the current verdict is Ambiguous.
- **Rescue rule (spec §3.2):** the effects engine is invoked *only* on the `ambiguous:{prog}` fall-through in `classify_segment_depth` — never before the catastrophic checks, never on any other rule.
- Rescued verdicts carry rule name `safe:effects:{prog}` (auditable).
- Run all Rust checks from the repo root: `cargo test --workspace` (desktop-dx is a detached workspace; build it separately with `cargo build --manifest-path desktop-dx/Cargo.toml` when touched).
- Every commit message ends with `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.
- Milestone boundaries (after Task 2, Task 6, Task 10): STOP and run the 3-lens adversarial panel gate (security / correctness / spec-conformance) before starting the next milestone.

---

## Milestone M0.1 — Replay harness

### Task 1: `kintsugi bench` command (replay + report + gates)

**Files:**
- Create: `crates/kintsugi-cli/src/bench.rs`
- Create: `bench/benign.txt` (repo root — vendored benign corpus)
- Modify: `crates/kintsugi-cli/src/main.rs` (add `Bench` subcommand around line 34 enum + dispatch around line 592)
- Test: inline `#[cfg(test)]` in `crates/kintsugi-cli/src/bench.rs`

**Interfaces:**
- Consumes: `kintsugi_core::{classify_line, Class, EventLog, Filter}` — `EventLog::open(path)`, `log.query(&Filter{ agent_not: Some("fs-watch".into()), limit: None, ..Default::default() }) -> Vec<LoggedEvent>` (field `.command: String` is the raw line).
- Produces: `pub struct BenchReport { pub total: usize, pub safe: usize, pub ambiguous: usize, pub catastrophic: usize, pub rows: Vec<BenchRow> }`, `pub struct BenchRow { pub command: String, pub class: Class, pub rule: String }`, `pub fn run_corpus(lines: &[String]) -> BenchReport`, `pub fn compare(baseline: &BenchReport, current: &BenchReport) -> Result<String, String>` (Err = gate failure text). Task 2 and CI rely on the CLI surface: `kintsugi bench [--events] [--corpus FILE] [--json OUT] [--baseline FILE --check]`.

- [ ] **Step 1: Write the failing tests**

In `crates/kintsugi-cli/src/bench.rs` (new file — write the test module first; the `use super::*` items don't exist yet):

```rust
//! `kintsugi bench` — replay corpora through the deterministic classifier and
//! report class distribution. The measuring stick for every effects-engine
//! change: hold-rate may only go down; catastrophic-as-safe delta must be 0.

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
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p kintsugi bench:: 2>&1 | tail -5`
Expected: compile error — `BenchReport`, `run_corpus`, `compare` not found.

- [ ] **Step 3: Implement bench.rs**

Above the test module in `crates/kintsugi-cli/src/bench.rs`:

```rust
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
    let cur_by_cmd: std::collections::HashMap<&str, Class> =
        current.rows.iter().map(|r| (r.command.as_str(), r.class)).collect();
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
        let db = kintsugi_core::log::default_db_path().context("no data dir")?;
        let log = EventLog::open(&db).context("open events.db")?;
        let filter = Filter { agent_not: Some("fs-watch".into()), ..Default::default() };
        lines.extend(log.query(&filter)?.into_iter().map(|e| e.command));
    }
    if let Some(p) = corpus {
        lines.extend(std::fs::read_to_string(p)?.lines().map(str::to_string));
    }
    if lines.is_empty() {
        anyhow::bail!("nothing to replay — pass --events and/or --corpus FILE");
    }
    let report = run_corpus(&lines);
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
    held.sort_by(|a, b| b.1.cmp(&a.1));
    for (rule, n) in held.iter().take(15) {
        println!("  {n:>5}  {rule}");
    }
    if let Some(p) = json {
        std::fs::write(p, serde_json::to_string_pretty(&report)?)?;
        println!("wrote {}", p.display());
    }
    if let Some(p) = baseline {
        let base: BenchReport = serde_json::from_str(&std::fs::read_to_string(p)?)?;
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
```

Notes for the implementer:
- If `kintsugi_core::log::default_db_path()` does not exist, look in `crates/kintsugi-core/src/log.rs` for how the daemon locates events.db (grep `data_dir\|events.db`) and use that helper; if it is daemon-side, replicate the two-line path construction here rather than adding a dependency.
- `Class` must be `Serialize`/`Deserialize` + `Copy` for the JSON report and the `cur_by_cmd` map; check `crates/kintsugi-core/src/types.rs` — if the derives are missing, add `Serialize, Deserialize` to the existing derive list (it already serializes over IPC, so they are almost certainly present).
- `serde_json` is already a kintsugi-cli dependency (IPC); confirm in `crates/kintsugi-cli/Cargo.toml`, add if missing.

- [ ] **Step 4: Wire the subcommand**

In `crates/kintsugi-cli/src/main.rs`, add to the `Command` enum (after `Log { … }`):

```rust
    /// Replay commands through the deterministic classifier and report the
    /// class distribution (dev tool — the accuracy measuring stick).
    Bench {
        /// Replay the local event-log history.
        #[arg(long)]
        events: bool,
        /// Also replay a newline-delimited command file.
        #[arg(long)]
        corpus: Option<std::path::PathBuf>,
        /// Write the full report as JSON.
        #[arg(long)]
        json: Option<std::path::PathBuf>,
        /// Compare against a baseline JSON report and print gate results.
        #[arg(long)]
        baseline: Option<std::path::PathBuf>,
        /// Exit non-zero if a gate fails (for CI).
        #[arg(long)]
        check: bool,
    },
```

Add `mod bench;` beside the other module declarations, and in `main()`'s match:

```rust
        Some(Command::Bench { events, corpus, json, baseline, check }) => {
            bench::run(events, corpus.as_deref(), json.as_deref(), baseline.as_deref(), check)
        }
```

- [ ] **Step 5: Create the vendored benign corpus**

Create `bench/benign.txt` — ~120 lines of realistic benign dev commands, one per line, drawn from common agent transcripts. Include at minimum (extend to ~120 in the same spirit — file ops, builds, VCS reads, interpreters running project files):

```text
# Vendored benign corpus — commands a coding agent runs constantly.
# Every line here is harmless in a normal workspace. The effects engine
# should eventually classify most of these Safe; none may become Catastrophic.
mkdir -p build/out
mkdir src/components
cp README.md docs/readme-copy.md
cp -r templates/base scaffold
mv notes.txt docs/notes.txt
touch src/lib.rs
touch .gitkeep
chmod +x scripts/run-tests.sh
chmod 644 config.yaml
tar -tzf release.tar.gz
make
make build
make test
python script.py
python -m pytest tests/
python3 -c "print(1+1)"
node index.js
npx tsc --noEmit
awk '{print $1}' access.log
xargs -n1 echo < list.txt
mktemp -d
ln -s ../shared shared
git add src/main.rs
git commit -m "wip"
git checkout -b feature/x
git stash list
rustc --version
docker ps
docker images
kubectl get pods
head -c 100 data.bin
sort -u names.txt
cut -d, -f2 data.csv
diff old.txt new.txt
```

- [ ] **Step 6: Run tests + build, verify pass**

Run: `cargo test -p kintsugi bench:: && cargo build -p kintsugi 2>&1 | tail -3`
Expected: all bench tests PASS; clean build.

- [ ] **Step 7: Commit**

```bash
git add crates/kintsugi-cli/src/bench.rs crates/kintsugi-cli/src/main.rs bench/benign.txt
git commit -m "feat(bench): replay harness — the accuracy measuring stick

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

### Task 2: Record the baseline + CI gate

**Files:**
- Create: `bench/baseline.json` (generated)
- Modify: `.github/workflows/ci.yml` (or the workflow that runs `cargo test` — locate with `ls .github/workflows/`)

**Interfaces:**
- Consumes: Task 1's CLI (`kintsugi bench --corpus bench/benign.txt --json … --baseline … --check`).
- Produces: `bench/baseline.json` — the frozen pre-effects-engine numbers every later milestone is compared against.

- [ ] **Step 1: Generate and inspect the baseline**

```bash
cargo run -p kintsugi -- bench --corpus bench/benign.txt --json bench/baseline.json
cargo run -p kintsugi -- bench --events --json /tmp/events-baseline.json || true
```

Expected: the vendored corpus shows a high ambiguous share (most of `mkdir`/`cp`/`make`/… held today) — record the exact percentages in the commit message. The `--events` run is local-only evidence (do not commit it; events.db content is private) — note its hold-rate for the PR description.

- [ ] **Step 2: Add the CI gate**

In the CI workflow, after the existing `cargo test` step:

```yaml
      - name: Bench regression gates (hold-rate ↓ only, zero cata-as-safe)
        run: cargo run -p kintsugi -- bench --corpus bench/benign.txt --baseline bench/baseline.json --check
```

- [ ] **Step 3: Verify locally, then commit**

Run: `cargo run -p kintsugi -- bench --corpus bench/benign.txt --baseline bench/baseline.json --check`
Expected: `gates OK: hold-rate X% -> X%` (identical, exit 0).

```bash
git add bench/baseline.json .github/workflows/
git commit -m "feat(bench): freeze pre-effects baseline + CI regression gates

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

### ⛔ M0.1 PANEL GATE

Dispatch three parallel review subagents (fresh context each) on the M0.1 diff (`git diff main...HEAD`):
1. **Security lens:** "Try to construct a way this bench harness weakens security: does the CI gate actually fail on a cata-as-safe delta? Can baseline.json drift mask a regression? Does `--events` leak private command text into committed artifacts?"
2. **Correctness lens:** "Edge cases: empty corpus, comment/blank lines, duplicate commands (HashMap keying by command text — verify last-wins is acceptable or flag), report math."
3. **Spec lens:** "Check against spec §M0.1 (docs/superpowers/specs/2026-06-23-effects-engine-phase0-1-design.md): both gates present, JSON output, events+corpus sources."

Fix confirmed findings, re-run the failing lens, record verdicts in the eventual PR description. Only then proceed to M0.2.

---

## Milestone M0.2 — Effect manifests + confinement + rescue

### Task 3: Effect types + embedded manifest

**Files:**
- Create: `crates/kintsugi-core/src/effects.rs`
- Create: `crates/kintsugi-core/src/effects/manifest.toml` (embedded via `include_str!`)
- Modify: `crates/kintsugi-core/src/lib.rs` (add `pub mod effects;`)
- Test: inline `#[cfg(test)]` in effects.rs

**Interfaces:**
- Consumes: nothing from other tasks (pure new module). Uses `toml` + `serde` (already kintsugi-core deps via policy.rs — verify in `crates/kintsugi-core/Cargo.toml`, add `toml` if it turns out policy uses hand-parsing).
- Produces (Task 5 relies on these exact names):
  - `pub enum Scope { Workspace, Outside, Unknown }`
  - `pub enum Effect { FsRead(String), FsWrite(String, Scope), FsDelete(String, Scope), NetEgress, ProcExec, PrivEsc, ShellEval, Unknown }`
  - `pub struct EffectSet { pub effects: Vec<Effect> }` with `pub fn is_benign(&self) -> bool`
  - `pub fn extract(prog: &str, args: &[&str], root_known: bool) -> Option<EffectSet>` — `None` = no manifest for prog.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<&str> {
        v.to_vec()
    }

    #[test]
    fn mkdir_relative_is_benign() {
        let e = extract("mkdir", &args(&["-p", "build/out"]), true).unwrap();
        assert!(e.is_benign(), "{e:?}");
    }

    #[test]
    fn unknown_program_has_no_manifest() {
        assert!(extract("weirdtool", &args(&["x"]), true).is_none());
    }

    #[test]
    fn cp_reads_sources_writes_dest() {
        let e = extract("cp", &args(&["a.txt", "b.txt"]), true).unwrap();
        assert!(e.effects.iter().any(|x| matches!(x, Effect::FsRead(p) if p == "a.txt")));
        assert!(e.effects.iter().any(|x| matches!(x, Effect::FsWrite(p, Scope::Workspace) if p == "b.txt")));
        assert!(e.is_benign());
    }

    #[test]
    fn absolute_path_is_outside() {
        let e = extract("mkdir", &args(&["/etc/foo"]), true).unwrap();
        assert!(!e.is_benign());
    }

    #[test]
    fn traversal_is_not_workspace() {
        let e = extract("cp", &args(&["a", "../../x"]), true).unwrap();
        assert!(!e.is_benign());
    }

    #[test]
    fn unlisted_flag_invalidates_profile() {
        // `cp --no-preserve=mode` fine, but a flag we haven't audited (e.g.
        // hypothetical `--hook=cmd`) must poison the profile -> Unknown.
        let e = extract("chmod", &args(&["--reference=/etc/shadow", "f"]), true).unwrap();
        assert!(!e.is_benign());
    }

    #[test]
    fn tar_list_ok_extract_unknown() {
        assert!(extract("tar", &args(&["-tzf", "a.tgz"]), true).unwrap().is_benign());
        assert!(!extract("tar", &args(&["-xzf", "a.tgz"]), true).unwrap().is_benign());
    }

    #[test]
    fn no_root_known_only_pure_relative_pass() {
        // When the workspace root is unknown (classify_line without cwd),
        // relative traversal-free paths are still Workspace by construction;
        // everything else is Unknown.
        assert!(extract("mkdir", &args(&["sub/dir"]), false).unwrap().is_benign());
        assert!(!extract("mkdir", &args(&["~/dir"]), false).unwrap().is_benign());
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p kintsugi-core effects:: 2>&1 | tail -3`
Expected: compile error (module doesn't exist).

- [ ] **Step 3: Write the manifest**

`crates/kintsugi-core/src/effects/manifest.toml`. Schema: per-program tables. `paths = "<role>"` describes what positional args are; `flags` lists **audited-benign** flags (any other `-`/`--` token → profile invalidated → `Unknown` effect); `value_flags` are audited flags that consume the next token. Initial coverage — the programs that dominate real holds (from the M0.1 `--events` top-held list; the set below is the expected floor):

```toml
# Effect manifests — deterministic per-program effect profiles.
# CONTRACT: listing a program here asserts that, invoked with ONLY the flags
# below, its filesystem/network effects are exactly the declared ones. Any
# unlisted flag poisons the profile (-> Unknown -> no rescue). When unsure,
# leave it out — absence just means "held for review", never a miss.

[mkdir]
writes = "all-args"
flags = ["-p", "--parents", "-v", "--verbose", "-m", "--mode"]
value_flags = ["-m", "--mode"]

[touch]
writes = "all-args"
flags = ["-a", "-m", "-c", "--no-create"]

[cp]
reads = "init-args"     # every positional except the last
writes = "last-arg"
flags = ["-r", "-R", "--recursive", "-p", "--preserve", "-v", "--verbose", "-n", "--no-clobber", "-a", "--archive"]

[mv]
reads = "init-args"
writes = "last-arg"
deletes = "init-args"   # the source stops existing
flags = ["-v", "--verbose", "-n", "--no-clobber"]

[ln]
writes = "last-arg"
flags = ["-s", "--symbolic", "-v"]

[chmod]
writes = "path-args"    # metadata write; positional non-mode args are paths
flags = ["-R", "--recursive", "-v", "--verbose"]
skip_first_positional = true   # the mode (755 / +x) is not a path

[mktemp]
writes = "all-args"
flags = ["-d", "--directory", "-p", "-t"]
allow_zero_args = true         # bare `mktemp` writes only under $TMPDIR

[make]
proc_exec = true               # runs project-declared recipes
reads = "none"
flags = ["-j", "-C", "-f", "-B", "-k", "-s", "--silent", "-n", "--dry-run"]
value_flags = ["-j", "-C", "-f"]

[awk]
reads = "path-args"
skip_first_positional = true   # the program text
flags = ["-F", "-v", "-f"]
value_flags = ["-F", "-v"]

[sort]
reads = "all-args"
flags = ["-u", "-r", "-n", "-k", "-t", "-h"]
value_flags = ["-k", "-t"]
allow_zero_args = true

[tar]
# Only LIST mode is profiled; extraction writes archive-controlled paths.
list_flags = ["-t", "-tf", "-tzf", "-tjf", "-tvf", "-tzvf", "--list"]
reads = "all-args"

[docker]
safe_subcommands = ["ps", "images", "version", "info", "logs", "inspect"]

[kubectl]
safe_subcommands = ["get", "describe", "version", "config"]

[python]
proc_exec = true
runs_workspace_file = true     # `python script.py` — file must be a workspace path
flags = ["-m", "-q", "-u", "-B"]

[python3]
proc_exec = true
runs_workspace_file = true
flags = ["-m", "-q", "-u", "-B"]

[node]
proc_exec = true
runs_workspace_file = true
flags = []

[git]
# git add/commit/checkout/switch/restore(-staged)/stash(push/list/show) are
# workspace-confined by construction. Handled in code, not TOML (needs
# subcommand-aware arg parsing) — this entry is a marker for coverage tests.
handled_in_code = true
```

Implementer notes:
- `python -c` / `node -e` / `awk` program text can contain arbitrary code — but the *effects* of that code are made by the child process at runtime, which the shim/daemon intercepts separately. For Phase 0 be strict anyway: `-c`/`-e`/`--eval` are NOT in the audited flag lists, so their presence invalidates the profile → held (I3). `awk`'s program text is skipped as a positional but a `system()` call inside it is invisible — mitigate by rejecting awk programs containing `system(` or backticks: check the first positional for the substring `system(` and emit `Effect::Unknown` when present.
- `docker`/`kubectl` `safe_subcommands`: first positional must be in the list; anything else → `Unknown`. No path effects (their reads are API calls, not workspace-relevant); model them as an empty benign `EffectSet`.
- `runs_workspace_file`: the first positional must classify as `Scope::Workspace` (it both reads and executes a project file — emit `FsRead(path)` + `ProcExec`). `ProcExec` from a manifest with `proc_exec = true` is benign-eligible **only because** the child's own commands are themselves intercepted at runtime; document this in a comment.

- [ ] **Step 4: Implement effects.rs**

```rust
//! Deterministic effect extraction: reduce (program, args) to the complete
//! set of filesystem/network/process effects, or `None`/`Unknown` when we
//! can't be sure. Spec: docs/superpowers/specs/2026-06-23-effects-engine-phase0-1-design.md §3.
//!
//! SECURITY CONTRACT (spec §3.2): callers may use a fully-benign EffectSet
//! ONLY to upgrade an `ambiguous:{prog}` fall-through to Safe. Nothing here
//! may run before the catastrophic checks or influence any other verdict.

use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Workspace,
    Outside,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    FsRead(String),
    FsWrite(String, Scope),
    FsDelete(String, Scope),
    NetEgress,
    ProcExec,
    PrivEsc,
    ShellEval,
    Unknown,
}

#[derive(Debug, Clone, Default)]
pub struct EffectSet {
    pub effects: Vec<Effect>,
}

impl EffectSet {
    /// The rescue predicate: complete, bounded, all-benign (spec §3.1 rule 4).
    /// Reads are benign only because the caller (classify_segment_depth) has
    /// already run the secret-path and catastrophic checks on this segment.
    pub fn is_benign(&self) -> bool {
        self.effects.iter().all(|e| match e {
            Effect::FsRead(_) => true,
            Effect::FsWrite(_, s) | Effect::FsDelete(_, s) => *s == Scope::Workspace,
            Effect::ProcExec => true, // child commands are themselves intercepted
            Effect::NetEgress | Effect::PrivEsc | Effect::ShellEval | Effect::Unknown => false,
        })
    }
}

/// Classify a path token's write-scope, paranoid (spec §3.4).
/// `root_known=false` means the caller has no cwd (classify_line): only
/// purely-relative, traversal-free paths count as Workspace by construction.
pub fn path_scope(token: &str, root_known: bool) -> Scope {
    let t = token.trim();
    if t.is_empty() {
        return Scope::Unknown;
    }
    // Anything the shell might rewrite or that escapes: not provably confined.
    if t.starts_with('~') || t.starts_with('$') || t.contains("$(") || t.contains('`') {
        return Scope::Unknown;
    }
    if t.starts_with('/') {
        return Scope::Outside; // absolute: judged Outside even with a root —
                               // Phase 0 rescues only relative paths (paranoid).
    }
    // Lexical traversal check: any `..` component can escape.
    if std::path::Path::new(t)
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Scope::Unknown;
    }
    // Relative + traversal-free: stays under the execution cwd. When the
    // root is unknown this is still confinement *to the cwd*, which is the
    // workspace guarantee Phase 0 promises.
    let _ = root_known;
    Scope::Workspace
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Profile {
    #[serde(default)]
    reads: Option<String>,
    #[serde(default)]
    writes: Option<String>,
    #[serde(default)]
    deletes: Option<String>,
    #[serde(default)]
    flags: Vec<String>,
    #[serde(default)]
    value_flags: Vec<String>,
    #[serde(default)]
    list_flags: Vec<String>,
    #[serde(default)]
    safe_subcommands: Vec<String>,
    #[serde(default)]
    proc_exec: bool,
    #[serde(default)]
    runs_workspace_file: bool,
    #[serde(default)]
    skip_first_positional: bool,
    #[serde(default)]
    allow_zero_args: bool,
    #[serde(default)]
    handled_in_code: bool,
}

fn manifests() -> &'static HashMap<String, Profile> {
    static M: OnceLock<HashMap<String, Profile>> = OnceLock::new();
    M.get_or_init(|| {
        // A malformed manifest disables the whole engine (fail closed, I3).
        toml::from_str(include_str!("effects/manifest.toml")).unwrap_or_default()
    })
}

/// Extract the effect set for `prog args…`, or None when no manifest covers
/// the program (→ caller keeps the Ambiguous verdict).
pub fn extract(prog: &str, args: &[&str], root_known: bool) -> Option<EffectSet> {
    let p = manifests().get(prog)?;
    if p.handled_in_code {
        return None; // git etc. — covered by is_safe_git today; no rescue here.
    }
    let mut set = EffectSet::default();

    // docker/kubectl-style: judged purely on the first positional subcommand.
    if !p.safe_subcommands.is_empty() {
        match args.iter().find(|a| !a.starts_with('-')) {
            Some(sub) if p.safe_subcommands.iter().any(|s| s == sub) => return Some(set),
            _ => {
                set.effects.push(Effect::Unknown);
                return Some(set);
            }
        }
    }

    // tar-style list mode: first token must be an audited list flag.
    if !p.list_flags.is_empty() {
        match args.first() {
            Some(f) if p.list_flags.iter().any(|l| l == f) => {
                for a in &args[1..] {
                    set.effects.push(Effect::FsRead((*a).to_string()));
                }
                return Some(set);
            }
            _ => {
                set.effects.push(Effect::Unknown);
                return Some(set);
            }
        }
    }

    // Generic path-role profiles: split flags from positionals, strictly.
    let mut positionals: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        if a.starts_with('-') && a.len() > 1 {
            // Audited flag? (exact match, or --flag=value form of an audited flag)
            let base = a.split('=').next().unwrap_or(a);
            if !p.flags.iter().any(|f| f == base) {
                set.effects.push(Effect::Unknown); // unaudited flag poisons
                return Some(set);
            }
            if p.value_flags.iter().any(|f| f == base) && !a.contains('=') {
                i += 1; // consume the flag's value
            }
        } else {
            positionals.push(a);
        }
        i += 1;
    }
    if p.skip_first_positional && !positionals.is_empty() {
        positionals.remove(0);
    }
    if positionals.is_empty() && !p.allow_zero_args {
        set.effects.push(Effect::Unknown);
        return Some(set);
    }

    if p.runs_workspace_file {
        if let Some(f) = positionals.first() {
            // Reject inline-code sentinels defensively even though the flag
            // audit should have caught them.
            match path_scope(f, root_known) {
                Scope::Workspace => {
                    set.effects.push(Effect::FsRead((*f).to_string()));
                    set.effects.push(Effect::ProcExec);
                }
                _ => set.effects.push(Effect::Unknown),
            }
        }
        return Some(set);
    }
    if p.proc_exec {
        set.effects.push(Effect::ProcExec);
    }

    let mut role = |role: Option<&String>, kind: fn(String, Scope) -> Effect, read: bool| {
        let Some(role) = role else { return };
        let targets: Vec<&str> = match role.as_str() {
            "all-args" | "path-args" => positionals.clone(),
            "init-args" => positionals[..positionals.len().saturating_sub(1)].to_vec(),
            "last-arg" => positionals.last().map(|l| vec![*l]).unwrap_or_default(),
            "none" => Vec::new(),
            _ => {
                set.effects.push(Effect::Unknown);
                return;
            }
        };
        for t in targets {
            if read {
                set.effects.push(Effect::FsRead(t.to_string()));
            } else {
                set.effects.push(kind(t.to_string(), path_scope(t, root_known)));
            }
        }
    };
    role(p.reads.as_ref(), Effect::FsWrite, true);
    role(p.writes.as_ref(), Effect::FsWrite, false);
    role(p.deletes.as_ref(), Effect::FsDelete, false);
    Some(set)
}
```

Implementer notes:
- The closure-borrowing of `set` inside `role` won't compile as written (two mutable borrows) — restructure into a small helper function `fn expand(role: &str, positionals: &[&str]) -> Option<Vec<&str>>` returning the targets, and push effects in the main body. Keep behavior identical to the intent above.
- `awk` `system(` rejection: after the flag loop, if `prog == "awk"`, inspect the skipped first positional (capture it before `remove(0)`) and push `Effect::Unknown` if it contains `system(` or `` ` ``.
- Add `pub mod effects;` to lib.rs and re-export nothing yet (Task 5 uses `crate::effects::…` internally).

- [ ] **Step 5: Run tests until green**

Run: `cargo test -p kintsugi-core effects:: 2>&1 | tail -5`
Expected: all effects tests PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/kintsugi-core/src/effects.rs crates/kintsugi-core/src/effects/manifest.toml crates/kintsugi-core/src/lib.rs
git commit -m "feat(effects): deterministic effect extraction + embedded manifests

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

### Task 4: Confinement hardening tests (property-style)

**Files:**
- Test: `crates/kintsugi-core/tests/effects_confinement.rs` (new)

**Interfaces:**
- Consumes: `kintsugi_core::effects::{path_scope, Scope, extract}` — make `effects` module `pub` (done in Task 3).

- [ ] **Step 1: Write the adversarial test file**

```rust
//! Confinement is the footgun (spec §3.4): every trick that could smuggle a
//! write outside the workspace must land on Outside or Unknown — never
//! Workspace. Paranoia is correct; the worst case must be an unnecessary
//! question, never a miss.

use kintsugi_core::effects::{extract, path_scope, Scope};

#[test]
fn traversal_variants_never_confined() {
    for p in [
        "../x", "a/../../x", "./../x", "a/b/../../../etc", "..", "a/..",
    ] {
        assert_ne!(path_scope(p, true), Scope::Workspace, "escaped: {p}");
    }
}

#[test]
fn absolute_and_home_never_confined() {
    for p in ["/etc/passwd", "/tmp/x", "~/x", "~root/x", "$HOME/x", "${HOME}/x"] {
        assert_ne!(path_scope(p, true), Scope::Workspace, "escaped: {p}");
    }
}

#[test]
fn substitution_and_backticks_never_confined() {
    for p in ["$(pwd)/x", "`pwd`/x", "a$(cmd)b", "$VAR/dir"] {
        assert_ne!(path_scope(p, true), Scope::Workspace, "escaped: {p}");
    }
}

#[test]
fn plain_relative_is_confined() {
    for p in ["x", "a/b/c", "./x", "dir/", "weird name.txt", ".hidden/file"] {
        assert_eq!(path_scope(p, true), Scope::Workspace, "over-held: {p}");
    }
}

#[test]
fn empty_and_whitespace_are_unknown() {
    assert_eq!(path_scope("", true), Scope::Unknown);
    assert_eq!(path_scope("   ", true), Scope::Unknown);
}

#[test]
fn secret_relative_paths_still_blocked_upstream() {
    // .env is relative and traversal-free — path_scope alone calls it
    // Workspace. The SECRET check lives upstream (is_secret_path runs in
    // catastrophic checks / is_safe before any rescue). Prove the composed
    // classifier still holds/blocks it after the rescue lands (Task 5 test);
    // here we just document the division of labor.
    assert_eq!(path_scope(".env", true), Scope::Workspace);
}

#[test]
fn extract_never_panics_on_garbage() {
    for line in [
        vec!["--", "-", "---x"],
        vec![""],
        vec!["\u{0}"],
        vec!["-p"],
        vec!["a", "b", "c", "d", "e", "f", "g"],
    ] {
        let _ = extract("mkdir", &line, true);
        let _ = extract("cp", &line, true);
        let _ = extract("tar", &line, true);
    }
}
```

- [ ] **Step 2: Run, fix any failures in effects.rs (not in the tests)**

Run: `cargo test -p kintsugi-core --test effects_confinement 2>&1 | tail -5`
Expected: PASS. If a case fails, the fix goes in `path_scope`/`extract` — these assertions encode the spec.

- [ ] **Step 3: Commit**

```bash
git add crates/kintsugi-core/tests/effects_confinement.rs
git commit -m "test(effects): adversarial confinement corpus — escapes never confined

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

### Task 5: The rescue hook in the classifier

**Files:**
- Modify: `crates/kintsugi-core/src/rules.rs:497` (the `ambiguous:{prog}` fall-through in `classify_segment_depth`)
- Test: inline in `rules.rs` tests module + golden corpus updates in `crates/kintsugi-core/tests/classifier_corpus.rs`

**Interfaces:**
- Consumes: `crate::effects::{extract, EffectSet}` (Task 3).
- Produces: rescued verdicts with rule name `safe:effects:{prog}` — the daemon, UI, and bench see this string; nothing else changes shape.

- [ ] **Step 1: Write the failing tests (rules.rs tests module)**

```rust
    #[test]
    fn effects_rescue_upgrades_benign_holds() {
        for (line, why) in [
            ("mkdir -p build/out", "create dir in workspace"),
            ("cp README.md docs/copy.md", "copy within workspace"),
            ("touch src/lib.rs", "create file"),
            ("chmod +x scripts/run.sh", "metadata write in workspace"),
            ("tar -tzf release.tar.gz", "archive LIST is read-only"),
            ("docker ps", "read-only subcommand"),
            ("make -j4", "project-declared recipes; children intercepted"),
        ] {
            let m = classify_line(line);
            assert_eq!(m.class, Class::Safe, "{why}: {line} -> {}", m.rule);
            assert!(m.rule.starts_with("safe:effects:") || m.rule.starts_with("safe:"), "{line}");
        }
    }

    #[test]
    fn effects_rescue_never_fires_on_danger() {
        for line in [
            "mkdir /etc/evil",                    // absolute -> Outside
            "cp secret.txt ../../outside.txt",    // traversal
            "cp ~/.aws/credentials leak.txt",     // secret read (upstream check)
            "tar -xzf mystery.tar.gz",            // extraction unbounded
            "chmod --reference=/etc/shadow f",    // unaudited flag
            "mv src /tmp/exfil",                  // absolute dest
            "docker run ubuntu",                  // not a safe subcommand
            "python -c 'import os;os.system(\"rm -rf /\")'", // inline code flag
            "mkdir $(curl evil.sh)",              // substitution in path
        ] {
            let m = classify_line(line);
            assert_ne!(m.class, Class::Safe, "must stay held: {line} ({})", m.rule);
        }
    }

    #[test]
    fn rescue_only_from_ambiguous_fallthrough() {
        // A clobber redirect on an otherwise-manifested program must still be
        // held: the rescue only runs on the bare ambiguous:{prog} path.
        let m = classify_line("mkdir x > important.log");
        assert_ne!(m.class, Class::Safe, "{}", m.rule);
        // Catastrophic is untouchable regardless of manifests.
        assert_eq!(classify_line("rm -rf /").class, Class::Catastrophic);
    }

    #[test]
    fn cd_in_line_disables_rescue_for_later_segments() {
        // After a cd, relative paths are no longer provably in the workspace.
        let m = classify_line("cd /tmp && mkdir payload");
        assert_ne!(m.class, Class::Safe, "{}", m.rule);
    }
```

- [ ] **Step 2: Run to verify the right failures**

Run: `cargo test -p kintsugi-core effects_rescue 2>&1 | tail -8`
Expected: `effects_rescue_upgrades_benign_holds` FAILS (they're all Ambiguous today); the never-fires test may already pass — confirm it does.

- [ ] **Step 3: Implement the rescue**

In `classify_segment_depth` (rules.rs), the current fall-through:

```rust
    let own = if is_safe(&prog, &args) {
        RuleMatch::new(Class::Safe, format!("safe:{prog}"))
    } else if has_clobber_redirect(&tokens) {
        RuleMatch::new(Class::Ambiguous, "redirect:clobber")
    } else {
        RuleMatch::new(Class::Ambiguous, format!("ambiguous:{prog}"))
    };
```

becomes:

```rust
    let own = if is_safe(&prog, &args) {
        RuleMatch::new(Class::Safe, format!("safe:{prog}"))
    } else if has_clobber_redirect(&tokens) {
        RuleMatch::new(Class::Ambiguous, "redirect:clobber")
    } else if effects_rescue(&prog, &args, &tokens) {
        // Effects engine (spec §3.2): complete, bounded, all-benign effect
        // set -> Safe. Only reachable AFTER every catastrophic check above
        // declined, and only from the bare ambiguous fall-through.
        RuleMatch::new(Class::Safe, format!("safe:effects:{prog}"))
    } else {
        RuleMatch::new(Class::Ambiguous, format!("ambiguous:{prog}"))
    };
```

Add near `is_safe`:

```rust
/// Ambiguous->Safe rescue via the deterministic effects engine.
/// Preconditions (enforced by call position): catastrophic checks, secret
/// clobber, block-device and redirect checks have all declined already.
fn effects_rescue(prog: &str, args: &[&str], tokens: &[String]) -> bool {
    // Any redirect at all means effects the manifest didn't declare.
    if tokens.iter().any(|t| t.contains('>') || t.contains('<')) {
        return false;
    }
    // A secret path anywhere disqualifies (mirrors is_safe's deny-by-default).
    if args.iter().any(|a| is_secret_path(a)) {
        return false;
    }
    match crate::effects::extract(prog, args, false) {
        Some(set) => set.is_benign(),
        None => false,
    }
}
```

For the `cd` guard: in `classify_line_depth` (the segment splitter), track whether any earlier segment's program was `cd`; if so, classify later segments with rescue disabled. Implementation: add a boolean threaded through, or simplest — in `classify_line_depth`, after splitting segments, if any segment's `effective_argv` starts with `cd`, post-process: a `safe:effects:*` result from a *later* segment downgrades back to `ambiguous:{prog}`. Look at how segments are iterated (rules.rs:250 onward) and pick the minimal-diff variant; the test in Step 1 is the acceptance bar.

- [ ] **Step 4: Update the golden corpus deliberately**

In `crates/kintsugi-core/tests/classifier_corpus.rs`, these Ambiguous rows are now expected-Safe **by design** (benign, workspace-confined). Move them to the Safe section with a comment:

```rust
    // ---- Safe via effects engine (Phase 0): benign, workspace-confined ----
    ("cp -r a b", Class::Safe),
    ("chmod 755 script.sh", Class::Safe),
    ("mv src dst", Class::Safe),
```

`rm file.txt` stays Ambiguous (no rm manifest — deliberate: deletion stays human-reviewed in Phase 0). `npm install`, `make install`, `./configure`, `python manage.py migrate`, `docker run ubuntu`, `curl -X POST …` stay Ambiguous (`install` targets system dirs / network / unmanifested). **No Catastrophic row changes — if one fails, that is an I1 violation: fix the code, never the row.**

Also append new adversarial catastrophic/ambiguous rows locking the rescue's edges:

```rust
    ("mkdir /etc/evil", Class::Ambiguous),
    ("cp x ../../outside", Class::Ambiguous),
    ("tar -xzf a.tgz", Class::Ambiguous),
    ("cd /tmp && mkdir payload", Class::Ambiguous),
    ("mkdir -p build && cargo build", Class::Safe),
```

- [ ] **Step 5: Run the full core suite**

Run: `cargo test -p kintsugi-core 2>&1 | tail -5`
Expected: all PASS, including golden corpus and the existing proptest/fuzz suites.

- [ ] **Step 6: Commit**

```bash
git add crates/kintsugi-core/src/rules.rs crates/kintsugi-core/tests/classifier_corpus.rs
git commit -m "feat(rules): effects-engine rescue — benign holds become provably Safe

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

### Task 6: Measure + widen coverage to the ≥60% target

**Files:**
- Modify: `crates/kintsugi-core/src/effects/manifest.toml` (add programs the measurement says matter)
- Modify: `bench/baseline.json` → regenerate as `bench/baseline.json` stays frozen; the *comparison* proves the drop.

**Interfaces:**
- Consumes: Task 1's bench, Task 5's rescue.
- Produces: the M0.2 headline number for the PR/panel.

- [ ] **Step 1: Measure**

```bash
cargo run -p kintsugi -- bench --corpus bench/benign.txt --baseline bench/baseline.json
cargo run -p kintsugi -- bench --events --json /tmp/after-m02.json
```

Expected: gates OK, hold-rate on the vendored corpus drops sharply (target: most of benign.txt Safe). On `--events`: the report prints the top remaining `ambiguous:{prog}` rules.

- [ ] **Step 2: Widen the manifest for the top remaining held programs**

For each of the top ~10 remaining `ambiguous:{prog}` entries that is genuinely benign-profileable (judgment call — when unsure, leave held), add a manifest entry following Task 3's contract, plus one rescue test and one never-fires test per added program in rules.rs. Do NOT add: `rm`, `curl`, `wget`, `ssh`, `scp`, package-manager installs, or anything with network/system-dir effects.

- [ ] **Step 3: Verify the target**

Run: `cargo run -p kintsugi -- bench --events` and compute: (benign holds that became Safe) / (total previous benign holds) — the spec target is ≥60% of historical benign holds rescued. Record the real numbers. If short of 60%, iterate Step 2; if the remainder is dominated by genuinely-unprofileable programs (project scripts, rm), record that finding for M0.3 (template memory is the mechanism for those) and proceed.

- [ ] **Step 4: Full workspace test + commit**

Run: `cargo test --workspace 2>&1 | tail -3`
Expected: PASS.

```bash
git add crates/kintsugi-core/src/effects/manifest.toml crates/kintsugi-core/src/rules.rs
git commit -m "feat(effects): widen manifest coverage to measured top-held programs

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

### ⛔ M0.2 PANEL GATE

Three parallel review subagents on `git diff main...HEAD` (focus: Tasks 3–6):
1. **Security lens:** "You are an attacker. Construct a command the effects engine now classifies Safe that damages the user: traversal/symlink/encoding tricks in path_scope, flag-smuggling past the audited lists, manifest role confusion (init-args/last-arg off-by-one), wrapper evasion (`sh -c 'mkdir /etc/x'`), the cd guard, redirect detection inside tokens, unicode/homoglyph paths. Write each candidate as a concrete command line and trace it through the code."
2. **Correctness lens:** "Malformed manifests, empty positionals, value_flags at end-of-args, `--flag=value` splitting, the closure-borrow restructure, OnceLock failure path (must disable rescue, not panic)."
3. **Spec lens:** "Verify I1–I4 + §3.2 against the diff: rescue reachable ONLY from the bare ambiguous fall-through; catastrophic checks untouched; golden catastrophic rows unchanged; rescued rule string `safe:effects:{prog}`; fail-closed on manifest errors."

Fix confirmed findings (each fix gets a regression test), re-panel the failing lens, then proceed.

---

## Milestone M0.3 — Template memory + approve-affordance

### Task 7: Template hashing in kintsugi-core

**Files:**
- Modify: `crates/kintsugi-core/src/memory.rs`
- Modify: `crates/kintsugi-core/src/lib.rs` (export `template_of`, `template_hash`)
- Test: inline in memory.rs

**Interfaces:**
- Consumes: `crate::shell::split`, `crate::effects::path_scope`, `rules::is_secret_path` — make `is_secret_path` `pub(crate)` in rules.rs.
- Produces (Tasks 8–9 rely on): `pub struct Template { pub display: String, pub hash: String }`, `pub fn template_of(raw: &str) -> Option<Template>` — `None` when no safe generalization exists (fall back to exact-only).

- [ ] **Step 1: Write the failing tests**

```rust
    #[test]
    fn template_abstracts_positionals_keeps_program_and_flags() {
        let a = template_of("grep -rn TODO src/").unwrap();
        let b = template_of("grep -rn FIXME lib/").unwrap();
        assert_eq!(a.hash, b.hash);
        assert_eq!(a.display, "grep -rn <str> <path:ws>");
    }

    #[test]
    fn different_flags_are_different_templates() {
        let a = template_of("rm file.txt").unwrap();
        let b = template_of("rm -rf file.txt");
        // -rf makes it catastrophic upstream; template_of must refuse anyway.
        assert!(b.is_none() || b.unwrap().hash != a.hash);
    }

    #[test]
    fn different_programs_never_collide() {
        let a = template_of("grep x y").unwrap();
        let b = template_of("rm x").unwrap();
        assert_ne!(a.hash, b.hash);
    }

    #[test]
    fn secret_paths_never_abstract() {
        // A secret path stays literal -> approving `cat notes.txt` can never
        // teach `cat .env`.
        let a = template_of("cat notes.txt").unwrap();
        let b = template_of("cat .env");
        assert!(b.is_none(), "secret arg must refuse templating: {b:?}");
        assert!(a.display.contains("<path:ws>"));
    }

    #[test]
    fn out_of_workspace_paths_stay_literal() {
        let t = template_of("ls /var/log").unwrap();
        assert!(t.display.contains("/var/log"), "{}", t.display);
    }

    #[test]
    fn urls_and_numbers_get_typed_slots() {
        let a = template_of("sleep 5").unwrap();
        let b = template_of("sleep 30").unwrap();
        assert_eq!(a.hash, b.hash);
        assert_eq!(a.display, "sleep <num>");
    }

    #[test]
    fn shell_metachars_refuse_templating() {
        for raw in ["x && y", "a | b", "cmd $(sub)", "cmd `sub`", "a; b", "a > b"] {
            assert!(template_of(raw).is_none(), "must refuse: {raw}");
        }
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p kintsugi-core memory:: 2>&1 | tail -3`
Expected: compile error — `template_of` not found.

- [ ] **Step 3: Implement**

Append to memory.rs:

```rust
/// A generalized command shape: program + flags literal, positionals
/// abstracted to typed slots. `display` is what the human approves;
/// `hash` is the storage key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    pub display: String,
    pub hash: String,
}

/// Build the template for a raw line, or None when no safe generalization
/// exists (multi-command lines, substitutions, redirects, secret paths).
/// SECURITY: refusal is always correct — the caller falls back to
/// exact-hash memory. Never widen what a slot can match.
pub fn template_of(raw: &str) -> Option<Template> {
    let raw = raw.trim();
    // Only single simple commands generalize. Any shell structure refuses.
    for meta in ["&&", "||", "|", ";", ">", "<", "$(", "`", "\n"] {
        if raw.contains(meta) {
            return None;
        }
    }
    let tokens = crate::shell::split(raw);
    if tokens.is_empty() {
        return None;
    }
    let mut out: Vec<String> = Vec::with_capacity(tokens.len());
    out.push(tokens[0].clone()); // program stays literal
    for tok in &tokens[1..] {
        if tok.starts_with('-') {
            out.push(tok.clone()); // flags stay literal (rm -rf ≠ rm)
        } else if crate::rules::is_secret_path(tok) {
            return None; // never generalize near secrets
        } else if tok.chars().all(|c| c.is_ascii_digit()) {
            out.push("<num>".into());
        } else if tok.starts_with("http://") || tok.starts_with("https://") {
            out.push("<url>".into());
        } else if crate::effects::path_scope(tok, false) == crate::effects::Scope::Workspace
            && (tok.contains('/') || tok.contains('.'))
        {
            out.push("<path:ws>".into());
        } else if crate::effects::path_scope(tok, false) == crate::effects::Scope::Workspace {
            out.push("<str>".into()); // bare word (pattern, name, subcommand-ish)
        } else {
            out.push(tok.clone()); // absolute/~/$: stays literal
        }
    }
    let display = out.join(" ");
    Some(Template { hash: command_hash(&format!("template:{display}")), display })
}
```

Implementer note: the `<str>` vs `<path:ws>` split above means a git-style subcommand (`git status`) abstracts to `git <str>` — too wide. Guard: if the program is in a short list of subcommand-taking programs (`git`, `cargo`, `npm`, `docker`, `kubectl`, `go`, `make`), keep the **first** positional literal. Add a test: `template_of("git status")` and `template_of("git push")` produce different hashes.

- [ ] **Step 4: Run tests until green, commit**

Run: `cargo test -p kintsugi-core memory:: 2>&1 | tail -3` → PASS.

```bash
git add crates/kintsugi-core/src/memory.rs crates/kintsugi-core/src/lib.rs crates/kintsugi-core/src/rules.rs
git commit -m "feat(memory): Drain-style command templates — approvals that generalize

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

### Task 8: Template memory in the store + daemon decision path

**Files:**
- Modify: `crates/kintsugi-core/src/log.rs` (memory table `kind` column + `remember_template` + lookup)
- Modify: `crates/kintsugi-daemon/src/lib.rs` (decide() lookup order ~line 678; resolve_pending remember path ~line 835)
- Modify: `crates/kintsugi-daemon/src/ipc.rs` (Resolution gains `remember_template`)
- Test: `crates/kintsugi-daemon/tests/` (new file `template_memory.rs`)

**Interfaces:**
- Consumes: Task 7's `template_of`.
- Produces: `EventLog::remember_template(repo, template_hash, Decision)`, `EventLog::memory_lookup_template(repo, template_hash) -> Option<Decision>`; IPC `Resolution { …, remember: bool, remember_template: bool }` (serde-default false — old clients keep working).

- [ ] **Step 1: Write the failing daemon test**

`crates/kintsugi-daemon/tests/template_memory.rs` — copy the scaffolding style of `crates/kintsugi-daemon/tests/misc.rs` (in-memory/temp daemon construction; read that file first and mirror its helpers):

```rust
//! Template memory: approving one command teaches its shape — but never
//! across flags, programs, or the catastrophic floor.

// (mirror the daemon-test scaffolding from tests/misc.rs — temp dir,
//  Daemon::open, ProposedCommand::new)

#[test]
fn template_approval_generalizes_within_shape() {
    let d = test_daemon();
    let a = cmd("grep -rn TODO src/");
    assert_eq!(d.decide(&a).decision, Decision::Hold); // ambiguous today? if
    // grep is Safe via allowlist, use a held shape instead:
    let a = cmd("python tools/gen.py alpha");
    assert_eq!(d.decide(&a).decision, Decision::Hold);
    d.remember_template_for(&a, Decision::Allow); // helper: template_of + log.remember_template
    let b = cmd("python tools/gen.py beta");
    let v = d.decide(&b);
    assert_eq!(v.decision, Decision::Allow);
    assert!(v.reason.starts_with("memory:template-allow"), "{}", v.reason);
}

#[test]
fn template_never_crosses_flags_or_programs() {
    let d = test_daemon();
    let a = cmd("python tools/gen.py alpha");
    d.remember_template_for(&a, Decision::Allow);
    assert_eq!(d.decide(&cmd("python -c 'x' tools/gen.py")).decision, Decision::Hold);
    assert_eq!(d.decide(&cmd("node tools/gen.py alpha")).decision, Decision::Hold);
}

#[test]
fn template_never_rescues_catastrophic() {
    let d = test_daemon();
    // Even a poisoned/hand-inserted template row must not lift the floor.
    let boom = cmd("rm -rf node_modules");
    if let Some(t) = kintsugi_core::template_of(&boom.raw) {
        d.log_remember_template("repo", &t.hash, Decision::Allow);
    }
    let v = d.decide(&boom);
    assert_ne!(v.decision, Decision::Allow, "{}", v.reason);
}
```

(Adapt helper names to what tests/misc.rs actually provides; the three behaviors are the acceptance bar.)

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p kintsugi-daemon --test template_memory 2>&1 | tail -5`
Expected: compile errors (missing methods).

- [ ] **Step 3: Implement the store**

In log.rs schema block (line ~263), the memory table is `PRIMARY KEY (repo, command_hash)`. Add a migration: `ALTER TABLE memory ADD COLUMN kind TEXT NOT NULL DEFAULT 'exact'` guarded by a `PRAGMA table_info(memory)` check (mirror however log.rs handles the `summary` column addition — grep `ALTER TABLE` there and copy the idiom). Template rows store the template hash in the same `command_hash` column with `kind='template'`.

```rust
    /// Remember a per-repo decision for a command TEMPLATE (generalized shape).
    pub fn remember_template(
        &self,
        repo: &str,
        template_hash: &str,
        action: crate::types::Decision,
    ) -> Result<(), LogError> {
        use crate::types::Decision;
        if action == Decision::Hold {
            return Err(LogError::Corrupt("cannot remember a Hold decision".to_string()));
        }
        let now = crate::log::now_ts(); // reuse however remember() stamps time
        self.conn.execute(
            "INSERT INTO memory (repo, command_hash, action, updated_at, kind)
             VALUES (?1, ?2, ?3, ?4, 'template')
             ON CONFLICT(repo, command_hash) DO UPDATE SET action = ?3, updated_at = ?4",
            rusqlite::params![repo, template_hash, action.as_str(), now],
        )?;
        Ok(())
    }

    /// Look up a remembered template decision.
    pub fn memory_lookup_template(
        &self,
        repo: &str,
        template_hash: &str,
    ) -> Result<Option<crate::types::Decision>, LogError> {
        // identical to memory_lookup but AND kind='template'
        …
    }
```

(Also add `AND kind='exact'` to the existing `memory_lookup` WHERE clause so the two namespaces can't collide.)

- [ ] **Step 4: Implement the daemon decision + resolve paths**

In `decide()` after the exact-memory match (lib.rs ~line 690), add:

```rust
        // Template memory: a human-taught SHAPE. Same floor as exact memory
        // (never lifts Catastrophic, I4) and only fires while still held.
        if verdict.decision == Decision::Hold {
            if let Some(t) = kintsugi_core::template_of(&cmd.raw) {
                match self.log.memory_lookup_template(&repo, &t.hash) {
                    Ok(Some(Decision::Allow))
                        if verdict.class != kintsugi_core::Class::Catastrophic =>
                    {
                        verdict.decision = Decision::Allow;
                        verdict.reason = format!("memory:template-allow [{}] ({})", t.display, verdict.reason);
                    }
                    Ok(Some(Decision::Deny)) => {
                        verdict.decision = Decision::Deny;
                        verdict.reason = format!("memory:template-deny [{}] ({})", t.display, verdict.reason);
                    }
                    _ => {}
                }
            }
        }
```

In ipc.rs `Resolution` (line ~100):

```rust
    /// Whether to remember this decision for this exact command in this repo.
    pub remember: bool,
    /// Whether to remember the generalized SHAPE (template) of this command.
    #[serde(default)]
    pub remember_template: bool,
```

In `resolve_pending` (lib.rs ~835-866), beside the exact-remember write:

```rust
        if resolution.remember_template
            && resolution.decision != Decision::Hold
            && item_class != kintsugi_core::Class::Catastrophic
        {
            if let Some(t) = kintsugi_core::template_of(&cmd_raw) {
                self.log.remember_template(&repo, &t.hash, resolution.decision)?;
            }
        }
```

(Adapt variable names to the surrounding function; the catastrophic guard mirrors the existing `remember` one at line 846-848.)

- [ ] **Step 5: Run daemon tests**

Run: `cargo test -p kintsugi-daemon 2>&1 | tail -3`
Expected: all PASS including the new template_memory tests and the existing ipc_roundtrip (serde-default keeps old payloads valid).

- [ ] **Step 6: Commit**

```bash
git add crates/kintsugi-core/src/log.rs crates/kintsugi-daemon/src/lib.rs crates/kintsugi-daemon/src/ipc.rs crates/kintsugi-daemon/tests/template_memory.rs
git commit -m "feat(daemon): template memory — human approvals teach command shapes

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

### Task 9: The affordance — CLI flag + desktop card + accessibility

**Files:**
- Modify: `crates/kintsugi-cli/src/main.rs` (Approve command, line ~190: add `--always-like-this`; `cmd_resolve_pending` to pass it)
- Modify: `desktop-dx/src/bindings.rs` (extend `resolve` at line 74)
- Modify: `desktop-dx/src/components/screens.rs` (Held card)
- Test: manual verification script + existing desktop build

**Interfaces:**
- Consumes: Task 8's `remember_template` IPC field; Task 7's `Template.display`.
- Produces: user-visible affordance; no new programmatic interface.

- [ ] **Step 1: CLI flag**

In the `Approve` variant (main.rs ~line 190):

```rust
    /// Approve a held command by id (or unique id prefix).
    Approve {
        id: String,
        /// Also remember this decision for commands LIKE this one (the
        /// generalized shape is shown before it is saved).
        #[arg(long)]
        always_like_this: bool,
    },
```

In `cmd_resolve_pending`, when the flag is set: compute `kintsugi_core::template_of(&raw)`; if `None`, print `no safe generalization for this command — remembered exactly instead` and fall back to `remember: true`; if `Some(t)`, print `will always allow: {t.display}` and send `remember_template: true` in the Resolution payload.

- [ ] **Step 2: Desktop binding**

In bindings.rs, beside `resolve` (line 74):

```rust
/// Resolve a held item and remember its generalized shape ("always allow
/// commands like this"). Falls back to exact-remember when no template exists.
pub fn resolve_remember_template(id: &str, allow: bool) -> bool {
    // same IPC call as resolve() but with remember_template: true
    …
}

/// The template display string for a raw command, for showing the human
/// exactly what they would be teaching. None = no safe generalization.
pub fn template_display(raw: &str) -> Option<String> {
    kintsugi_core::template_of(raw).map(|t| t.display)
}
```

- [ ] **Step 3: Held card UI (screens.rs)**

Read the Held card section of `desktop-dx/src/components/screens.rs` first (find the existing Approve/Deny buttons and the two-step approve-and-run flow). Add beneath the action row:

- A checkbox row: `input { r#type: "checkbox", id: "always-like-this", … }` + `label { r#for: "always-like-this", "Always allow commands like this" }` — the `for`/`id` pairing makes the label clickable and screen-reader-associated.
- When checked, render the template preview in a monospace line under the checkbox: `code { title: "This exact shape will be auto-allowed in this repo", "{template}" }` using `bindings::template_display(&item.command)`; when it returns `None`, disable the checkbox and show "no safe generalization — will remember this exact command".
- Wire the approve handler: checked → `resolve_remember_template(id, true)` else existing `resolve(id, true)`.
- **Accessibility (spec §5, scoped to this card):** the checkbox and both action buttons reachable in DOM order (checkbox before buttons); visible `:focus-visible` outline on the checkbox/buttons (add to the app stylesheet if missing: `outline: 2px solid var(--accent); outline-offset: 2px`); the template preview gets `aria-label`-equivalent via the `title` attribute; badge/summary colors on this card checked ≥4.5:1 contrast against their background (adjust the shade, not the hue, if short).

- [ ] **Step 4: Build + manual verify**

```bash
cargo build --manifest-path desktop-dx/Cargo.toml 2>&1 | tail -3
cargo test --workspace 2>&1 | tail -3
```

Expected: both green. Manual check (document in commit body): trigger a held command (`python /tmp/x.py` style via the shim or `kintsugi record`), open Control Room → Needs review → checkbox shows template → approve → rerun a same-shape command → auto-allowed with `memory:template-allow` in the feed detail.

- [ ] **Step 5: Commit**

```bash
git add crates/kintsugi-cli/src/main.rs desktop-dx/src/bindings.rs desktop-dx/src/components/screens.rs
git commit -m "feat(ui): 'always allow commands like this' — template approvals in CLI + Control Room

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

### Task 10: Phase 0 wrap — measure, document, PR

**Files:**
- Modify: `docs/superpowers/specs/2026-06-23-effects-engine-phase0-1-design.md` (append a "Phase 0 results" addendum)
- Create: PR via `gh`

- [ ] **Step 1: Final numbers**

```bash
cargo run -p kintsugi -- bench --corpus bench/benign.txt --baseline bench/baseline.json
cargo run -p kintsugi -- bench --events
cargo test --workspace 2>&1 | tail -3
```

Record: vendored-corpus hold-rate before/after, events hold-rate before/after, % of historical benign holds rescued (target ≥60%), zero cata-as-safe.

- [ ] **Step 2: Append the results addendum to the spec, commit**

Three lines: measured numbers, manifest coverage count, residual top-held programs (the template-memory tail).

- [ ] **Step 3: Open the PR**

```bash
git push -u origin feat/effects-engine
gh pr create --title "Effects engine Phase 0: prove safety, don't allowlist names" --body "…"
```

PR body: the headline numbers, the three panel-gate verdict summaries (M0.1/M0.2/M0.3), invariant statement (I1–I4 held; golden catastrophic rows untouched), and a note that Phase 1 (engine extraction + widened interception) follows in a separate plan per the spec.

### ⛔ M0.3 PANEL GATE (runs before Step 3's PR)

1. **Security lens:** "Attack template memory: craft an approval whose template later matches a harmful command (slot-widening, `<str>` over-matching, subcommand programs, flag-order tricks, unicode). Trace template_of end-to-end for each."
2. **Correctness lens:** "Migration idempotency (kind column), old-client Resolution payloads (serde default), exact-vs-template namespace separation in SQL, None-template fallbacks in CLI/desktop."
3. **Spec lens:** "I4 in every path (decide + resolve_pending + hand-inserted rows), affordance shows the template before saving, accessibility items from spec §5 present."

---

## Self-review record

- **Spec coverage:** M0.1→Tasks 1–2; M0.2 (§3.1–3.4)→Tasks 3–6; M0.3 (§3.5)→Tasks 7–9; §5 UI/accessibility→Task 9 Step 3; §6 error handling→Task 3 (OnceLock fail-closed), Task 5 (rescue preconditions), Task 7 (refusal semantics); §7 testing→Tasks 1, 4, 5, 8; panel gates→after Tasks 2, 6, 10. Phase 1 (M1.1–M1.2) deliberately deferred to its own plan per scope check.
- **Known adaptation points (not placeholders):** daemon-test scaffolding names (mirror tests/misc.rs), the `role` closure restructure (behavior fully specified by tests), log.rs migration idiom (mirror the summary-column migration), Held-card exact insertion point (read screens.rs first). Each names its source of truth in-repo.
- **Type consistency check:** `template_of`/`Template{display,hash}` used identically in Tasks 7/8/9; `Scope`/`Effect`/`extract(prog,args,root_known)` identical in Tasks 3/4/5; `BenchReport`/`compare` identical in Tasks 1/2/6.
