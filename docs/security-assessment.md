# Aegis — Security Stress & Vulnerability Assessment

**Scope:** the Tier-1 deterministic classifier and its dependencies — the security
spine that decides whether an AI agent's shell command is hard-blocked, held, or
allowed. **Target:** the shipping version on `main`. **Method:** automated
adversarial testing run in-repo; every figure below is reproduced by a command in
this report — nothing is asserted without a measurement.

> **Honesty note (read first).** This is an *internal, automated* assessment, not a
> third-party penetration test or formal audit. Aegis's guarantee is deliberately
> *"nothing is unrecoverable"* (detective + reversible), **not** *"nothing runs
> un-warned."* Hooks can be bypassed by an agent in auto-approve/"yolo" mode or a
> process invoking a binary by absolute path; the filesystem-watcher backstop, not
> interception, is what makes the honest guarantee. Numbers here characterize the
> classifier's correctness, robustness, performance, and supply-chain hygiene —
> they do not claim an unbypassable control.

## Headline results

| Dimension | Result |
|---|---|
| Dangerous commands leaked to **Safe** (zero-tolerance gate) | **0 / 176 (0.00%)** |
| Hard-blocked (Catastrophic) | 155 / 176 (88.1%) |
| Held for review (Ambiguous) | 21 / 176 (11.9%) |
| False positives on strict-safe set | **0 / 37 (0.0%)** |
| Adversarial fuzz inputs, panics/aborts/hangs | **0 / 1,400,000** |
| Pathological DoS inputs bounded (no abort) | 10 / 10 (≤ 10.6 ms) |
| Classifier latency (release) | **p50 2.2 µs · p99 18 µs · ~240k/s/core** |
| Known CVEs in dependency tree (`cargo audit`) | **0 / 436 deps** |
| `unsafe` blocks in first-party crates | **0** |
| Copyleft license obligations | **0** (all effective licenses permissive) |
| Line coverage (CI gate ≥ 88%) | 88.6% |

**One real vulnerability was found and fixed during this campaign** — a heap-
exhaustion denial-of-service in the bundled shell parser (see §3).

---

## 1. Security correctness & evasion resistance

A 176-command adversarial corpus (`crates/aegis-core/tests/security_stress.rs`)
maps attack classes to **MITRE ATT&CK** (T1485 Data Destruction, T1561 Disk Wipe,
T1552 Unsecured Credentials, T1059 Command Execution, T1499 resource exhaustion)
and the **GTFOBins** "benign binary, harmful use" catalog. The one zero-tolerance
metric per the security spine: **a genuinely dangerous command must never be
classified `Safe`.**

```
dangerous commands tested : 176
  hard-blocked (Catastrophic): 155  (88.1%)
  held for review (Ambiguous):  21  (11.9%)
  LEAKED to Safe (FAILURE)   :   0  (0.0%)
safe commands tested      :  37
  false-positive (over-block):   0  (0.0%)
```

Evasion classes exercised, all caught (Catastrophic or held — never Safe):

- **Quoting / escaping:** `r""m -rf /`, `\rm -rf /`, `rm -r''f /`, `"rm" -rf /`
- **Transparent prefixes:** `sudo`, `env VAR=x`, `nohup`, `timeout`, `command`, `exec`
- **Command substitution / backticks:** `echo "$(rm -rf /)"`, `` x=`git push --force` ``
- **Here-docs / here-strings / process substitution:** `bash <<<'rm -rf /'`, `grep x <(rm -rf /)`
- **Compound & function bodies:** `if … then rm -rf / fi`, `f(){ rm -rf /; }; f`
- **Encode-to-shell:** `… | base64 -d | sh`, `openssl enc -d … | bash`
- **Git-flag evasion:** `git -C /repo push --force`, `git -c k=v push --force`
- **Secret exfiltration:** `tar czf x ~/.ssh`, `sort ~/.aws/credentials`, `> ~/.ssh/id_rsa`

The 11.9% held (not hard-blocked) are *opaque payloads* Tier-1 cannot prove
catastrophic — variable indirection (`X=rm; $X -rf /`), `eval`, language
interpreters (`python -c …`). These are **held/denied, never run silently**, and
are exactly the band the Tier-2 model is designed to score.

**Reproduce:** `cargo test -p aegis-core --test security_stress -- --nocapture`

## 2. Robustness fuzzing (1.4M inputs, zero crashes)

No `cargo-fuzz`/libFuzzer on stable Rust, so the campaign uses a deterministic,
seeded, in-process fuzzer (`crates/aegis-core/tests/robustness_fuzz.rs`) across
three generators. A real parser stack-overflow is an *uncatchable abort* that
kills the process, so reaching the end of each run is the proof of survival.

| Generator | Inputs | Result |
|---|---|---|
| Arbitrary Unicode (ASCII + control + multibyte + emoji + NUL) | 600,000 | no panic/abort |
| Shell-metacharacter soup (operators, quotes, subs, here-ops, keywords) | 800,000 | no panic/abort |

**Reproduce:** `cargo test -p aegis-core --release --test robustness_fuzz -- --ignored --nocapture`

## 3. Denial-of-service resistance — one vulnerability found & fixed

The fuzzer drove the classifier into **heap exhaustion**: a single 23-byte input
made the bundled bash parser (`brush-parser`) attempt a **1.75 GB allocation** and
abort the process. Minimal reproducer:

```
)x<< .env$( (.envfiEOF        →  memory allocation of 1879048192 bytes failed
```

Root cause: `brush-parser`'s here-doc / here-string tokenizer over-allocates on
*malformed* here-operator input (operator pileups like `<<<<<`, empty delimiters
like `<< ''`, here-ops mixed with command substitution). **Impact:** an agent — or
a prompt-injected instruction — emitting such a command would OOM-crash the Aegis
daemon, disabling the safety layer (a fail-open DoS).

**Fix (shipped in this branch):** here-operators are *neutralized* before the line
reaches the parser, so it never enters the vulnerable reader. Substitutions and
command structure are preserved, so **no detection is lost and no catastrophe can
hide** (verified: `echo "$(rm -rf /)" <<EOF` still classifies Catastrophic). The
exact reproducer plus nine other pathological inputs are now regression-locked and
bounded:

```
[dos] heredoc DoS      0.02 ms -> Ambiguous     [dos] 2MB word        10.64 ms -> Ambiguous
[dos] deep $()         0.09 ms -> Ambiguous     [dos] 100k quotes      0.29 ms -> Ambiguous
[dos] deep braces      0.24 ms -> Ambiguous     [dos] backtick bomb    0.24 ms -> Ambiguous
[dos] pipe flood       1.30 ms -> Ambiguous     [dos] keyword bomb     0.35 ms -> Ambiguous
[dos] amp flood        0.86 ms -> Ambiguous     [dos] NUL spam         0.45 ms -> Ambiguous
```

Pre-existing guards verified by the same suite: deeply nested `$(…)` (stack-
overflow class, found in the earlier classifier roundtable) and 64 KB+/256-operator
floods are refused before parsing and fail toward caution (never Safe).

**Reproduce:** `cargo test -p aegis-core --release --test robustness_fuzz dos_pathological_inputs_are_bounded_and_never_abort -- --nocapture`

## 4. Performance (hot path on every agent command)

Release build, 320,000 classifications over a representative safe/held/complex mix
(`crates/aegis-core/tests/perf_report.rs`):

```
mean 4.1 µs · p50 2.2 µs · p90 11.6 µs · p99 18.1 µs · p99.9 41.6 µs · max 95.6 µs
throughput: ~239,700 classifications/s (single core)
```

Safe commands — the common case — clear in low microseconds; the cost ceiling is
bounded by the §3 complexity caps. The classifier does no I/O and is deterministic.

**Reproduce:** `cargo test -p aegis-core --release --test perf_report -- --ignored --nocapture`

## 5. Supply-chain & memory safety

- **Known vulnerabilities:** `cargo audit` against the RustSec advisory database
  (1,132 advisories) over **436 dependencies → 0 vulnerabilities, 0 warnings.**
- **Memory safety:** **0 `unsafe` blocks** in any first-party crate (`aegis-core`,
  `-daemon`, `-intercept`, `-cli`, `-model`, `-tui`). Combined with the 1.4M-input
  fuzz (no abort), the trusted computing base is memory-safe Rust.
- **Licensing:** 322 resolved packages, all effective licenses permissive
  (MIT / Apache-2.0 / BSD / Zlib / Unlicense). **No copyleft obligations** — the one
  LGPL mention is an *optional* arm of a tri-licensed UEFI crate (`r-efi`,
  `MIT OR Apache-2.0 OR LGPL`) that is not compiled for the target platforms. The
  bash parser was deliberately chosen (`brush-parser`, MIT) over a GPL alternative
  to keep the distributed binary permissive.
- **Test suite:** 331 test functions; **88.6% line coverage**, enforced at ≥ 88% in
  CI (`cargo llvm-cov --fail-under-lines 88`).

**Reproduce:** `cargo audit` · `cargo llvm-cov --workspace --summary-only`

## 6. What this assessment does *not* cover

To stay honest for an enterprise reviewer:

- **Not a third-party pen-test or formal audit.** Independent review recommended
  before relying on Aegis as a compliance control.
- **Fuzzing is stable-Rust in-process**, not coverage-guided (libFuzzer/AFL++) — a
  longer guided campaign and `cargo-fuzz` targets are recommended follow-ups.
- **Interception is not a sandbox.** The threat model (and §0 note) is explicit:
  Aegis guards mistakes and makes them reversible; it is not an unbypassable
  firewall against a determined same-machine process.
- **Tier-2 model** scoring is out of scope here (it can only *add* caution and never
  unblocks a rule decision; the spine holds regardless of the model).

## Appendix — reproduce the whole campaign

```sh
# correctness + zero-leak gate (fast)
cargo test -p aegis-core --test security_stress -- --nocapture
# robustness fuzz (1.4M inputs) + DoS bounds
cargo test -p aegis-core --release --test robustness_fuzz -- --ignored --nocapture
# performance
cargo test -p aegis-core --release --test perf_report -- --ignored --nocapture
# supply chain + coverage
cargo audit
cargo llvm-cov --workspace --summary-only --fail-under-lines 88
```
