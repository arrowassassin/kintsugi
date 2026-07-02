# Effects Engine — Phase 0 & 1 Design

**Date:** 2026-06-23
**Status:** Approved for implementation
**Scope:** Phase 0 (bash precision fix, measured) + Phase 1 (generic effects engine, widened interception). Phases 2–4 are a north-star appendix, not in scope.

## 1. Problem

Kintsugi's deterministic classifier over-holds. `is_safe()` in `crates/kintsugi-core/src/rules.rs` is a hand-curated allowlist of ~40 program names; everything unlisted falls through to `ambiguous:{prog}` and is held. A single working session produced ~748 ambiguous holds, most of them benign (`mkdir`, `cp`, `touch`, `chmod`, `make`, project scripts). Separately, decision memory (`memory.rs`) keys on the SHA-256 of the exact raw line, so approving `grep foo src/` teaches nothing about `grep bar src/` — holds never decay.

Two root causes, two mechanisms:

1. **The classifier knows danger but not safety.** Fix: prove safety from *effects*, not name membership.
2. **Memory doesn't generalize.** Fix: template-based memory (Drain-style) instead of exact-line hashes.

Research grounding (deep-research run, 2026-06-23, 25/25 claims verified): the deterministic information-flow direction (Google DeepMind **CaMeL**, arXiv:2503.18813; Microsoft **Fides**, arXiv:2505.23643) provably constrains agent actions via capability/taint tracking with bounded utility cost, while model-based guardrails (LlamaFirewall, AGrail, DataSentinel) carry severe over-defense / utility loss (LlamaFirewall best config: ASR 1.75% but utility 42.7%). Kintsugi's invariant — the hard block is never an LLM — is the correct minority position; this design extends it. The end goal: a deterministic, local-first behavioral antivirus for AI agents (a niche the research confirms is empty).

## 2. Core invariants (unchanged, load-bearing)

- **I1 — Zero catastrophic-classified-as-safe.** Golden corpus stays green by construction.
- **I2 — The hard block decision is deterministic.** Never a model. The Tier-2 scorer remains escalation-only.
- **I3 — Fail toward caution.** Unparseable, unknown, or unresolvable → Ambiguous (or worse), never Safe.
- **I4 — Memory/policy never auto-downgrades Catastrophic.** Only an in-the-moment human decision lifts that floor.

## 3. Architecture

### 3.1 The reframe: Safe is a proof, not a membership test

Every action reduces to a typed **EffectSet** — the complete list of things it touches:

```rust
enum Effect {
    FsRead(PathClass),          // path + secret/non-secret tag
    FsWrite(PathClass, Scope),  // Scope: Workspace | Outside | Unknown
    FsDelete(PathClass, Scope),
    NetEgress(Host),
    ProcExec,                   // spawns arbitrary further processes
    PrivEsc,                    // sudo/doas/setuid
    SecretRead(PathBuf),
    ShellEval,                  // eval/source/pipe-to-shell
    Unknown,                    // the conservative escape hatch
}
```

Classification becomes envelope-checking, in strict order (first hit wins):

1. **Hard-danger check** (existing catastrophic rules + trifecta): secret clobber, block-device write, tainted+sensitive egress → **Catastrophic**.
2. **Any `Unknown` effect** (unlisted program, unresolvable write path) → **Ambiguous**.
3. **Any unconfined effect** (write/delete outside workspace, `NetEgress`, `PrivEsc`, `ShellEval` with non-benign payload) → **Ambiguous**.
4. **Residual** — reads (non-secret) + writes/deletes provably confined to the workspace → **Safe**.

### 3.2 Strictly-safe integration

The existing catastrophic rules in `rules.rs` run **first and unchanged**. The effects engine is only permitted to rescue a verdict **from Ambiguous to Safe**, and only when the effect set is *complete* (no `Unknown`), *bounded* (every write scope known), and *all-benign* (rule 4 above). It can never touch a Catastrophic verdict. Therefore the change is a strict precision improvement: it can remove false holds; it cannot create a miss. I1 holds by construction, not by testing alone.

### 3.3 Effect manifests are data, not code

Per-program effect profiles live in an embedded declarative manifest (TOML), compiled into the binary but structured for contribution:

```toml
[mkdir]
writes = ["$args"]            # each positional arg is a created path
[cp]
reads  = ["$args[..-1]"]
writes = ["$args[-1]"]
flags_unsafe = []             # flags that invalidate the profile → Unknown
[tar]
# extraction writes archive-controlled paths → never confinable
subcommand_profiles = { "-t*" = { reads = ["$args"] } }  # list mode only
default = "unknown"
```

Initial coverage: the ~25 programs responsible for the bulk of real holds (measured from events.db, not guessed). A program without a manifest, or invoked with a flag outside its profile, contributes `Unknown` → no rescue. **This manifest format is deliberately the seed of the Phase-2 signature-pack format.**

### 3.4 Workspace confinement (the footgun, handled paranoid)

`Scope::Workspace` requires **proof**: the path, after lexical normalization (no `..` escapes), resolves under the session `cwd`'s workspace root; symlink components that cannot be verified as in-workspace → `Unknown`; redirects (`>`, `>>`) contribute writes; absolute paths outside the root → `Outside`; paths controlled by data we can't see (archive contents, command substitution output) → `Unknown`. When in doubt: not confined. The worst case must always be an unnecessary question, never a miss.

### 3.5 Template memory (generalizing approvals)

Replace exact-line hashing with a two-key lookup: exact hash (kept, backward-compatible) then **template hash**. Template construction (Drain-inspired, deterministic):

- Program name and **all flags stay literal** (`rm -rf` can never be reached from an `rm` approval).
- Positional args abstract to typed slots: `<path:ws>` (in-workspace), `<path:out>`, `<url>`, `<num>`, `<str>`.
- **Risk-bearing tokens are never abstracted**: secret paths, egress hosts, and anything the danger rules key on stay literal in the template.
- Templates are per-repo (same as today's memory) and stored in the same `memory` table with a `kind` column (`exact` | `template`).
- Template memory can never rescue Catastrophic (I4) and only applies when the current verdict is Ambiguous.

UI affordance: the hold prompt (CLI) and Held card (desktop) gain **"Always allow commands like this"** alongside the existing exact-match option, showing the human the exact template being taught (e.g. `grep <str> <path:ws>`), so what generalizes is visible and auditable.

## 4. Milestones

### M0.1 — Replay harness (the measuring stick; ships first)

`kintsugi bench` (dev command, feature-gated or hidden): replays commands through `classify_line`/`classify` and reports hold-rate, class distribution, and per-class deltas vs. a recorded baseline.

Corpora: (a) the local events.db history (real usage, ~750 commands); (b) the golden corpus (hard gate: zero Catastrophic→anything-lower deltas); (c) a vendored public benign set (NL2Bash sample) for breadth. Output is a table + JSON; CI runs the golden + vendored corpora with two gates: **cata-as-safe delta = 0** and **hold-rate must not increase**.

### M0.2 — Effect manifests + confinement + rescue

`effects` module inside kintsugi-core (single file to start): `Effect`, `EffectSet`, manifest loader, confinement checker, and `try_rescue(seg, tokens) -> Option<RuleMatch>` called from `classify_segment_depth` only on the `ambiguous:{prog}` fall-through path. Rule name for rescued verdicts: `safe:effects:{prog}` (auditable in the event log and UI). Measured target: ≥60% of historical benign holds become Safe, zero golden regressions.

### M0.3 — Template memory + approve-affordance

`template_hash()` beside `command_hash()` in memory.rs; daemon `decide()` consults exact then template; `remember` IPC gains a template variant; CLI hold prompt + desktop Held card get "Always allow commands like this" with the template rendered. Tests prove non-generalization across flags and risk tokens.

### M1.1 — Engine extraction + Cedar spike

Extract `effects` into `kintsugi-core/src/effects/` with a clean boundary: `trait EffectExtractor { fn extract(&self, action: &Action) -> EffectSet }` and one `judge(&EffectSet) -> Class` policy core. Bash becomes extractor #1. **Pure refactor: M0.1 replay numbers must be byte-identical before/after.**

Cedar spike (time-boxed, ~1 day): can Cedar (formally-verified Rust policy engine) express rules 1–4 of §3.1 without contortion? Written adopt/reject decision committed to `docs/superpowers/specs/` as an addendum. Rejecting is an acceptable outcome; the `judge` interface makes it swappable later either way.

### M1.2 — Widened interception (file-edit + MCP extractors)

Two new extractors feeding the same daemon `decide()` through the existing hook surface (`kintsugi-hook` on PreToolUse already sees non-bash tool calls):

- **File-edit extractor:** Edit/Write tool calls → `FsWrite(path, scope)` (+ `SecretRead`/secret-clobber when the target is a secret path). An edit inside the workspace is Safe (today it passes unexamined — this is *new coverage*, strictly additive); an edit to `~/.ssh/…` or outside the workspace is held/blocked by the same rules 1–4.
- **MCP extractor:** MCP tool calls → conservative default `Unknown` (held) with a small manifest of known-benign read-only tools (e.g. read/list/search tools) → `FsRead`/none. Same manifest format as §3.3.

The daemon protocol gains an action-type tag; the Control Room feed/queue render non-bash actions with an action-type badge. Same classes, same queue, same undo story where applicable.

### Panel gate (after every milestone)

Three independent adversarial reviewers, distinct lenses, before the next milestone starts:

1. **Security** — actively construct a bypass: a dangerous action the milestone now classifies Safe (traversal, symlinks, encoding, wrapper evasion, flag smuggling, template overreach).
2. **Correctness** — edge cases, error paths, fail-toward-caution behavior under malformed input.
3. **Spec conformance** — verify I1–I4 and the §3.2 rescue-only-from-Ambiguous rule against the diff.

Confirmed findings are fixed and re-panelled. A milestone advances only on a clean panel + green replay gates. Panel verdicts are recorded in the PR description.

## 5. UI & accessibility (folded into M0.3 / M1.2)

- **Held card explanation upgrade:** show the effect set in plain words ("writes `build/` — inside workspace; no network"), so a human can decide in one glance. Rescued-Safe events show `safe:effects:{prog}` provenance in the detail drawer.
- **"Always allow commands like this"** with the template visibly rendered (M0.3).
- **Action-type badges** (shell / edit / MCP) in Feed, History, and Queue (M1.2).
- **Accessibility pass on the touched screens:** full keyboard operability of the Held card (approve/deny/remember reachable and operable without a mouse, visible focus ring), ARIA-equivalent labels on badge/summary elements Dioxus renders, WCAG-AA contrast check on the new badge colors, and `prefers-reduced-motion` respected for any new transitions. Scope: only screens this work touches — not a whole-app audit.

## 6. Error handling

- Manifest missing/unparseable for a program → that program contributes `Unknown` → no rescue (today's behavior).
- Confinement cannot resolve a path → `Scope::Unknown` → no rescue.
- Template construction hits any risk-bearing token ambiguity → fall back to exact-hash-only.
- Any panic-adjacent path in the new code fails closed to the pre-engine verdict. The new code can only ever fail *toward* holding.

## 7. Testing

- Golden corpus: unchanged, hard CI gate (I1).
- Replay regression in CI: cata-as-safe delta = 0; hold-rate monotonically non-increasing across milestones.
- Confinement property tests: `..` traversal, absolute escapes, symlinks, redirect targets, NUL/odd encodings.
- Template tests: approved `grep <str> <path:ws>` must not match `rm`, must not match `grep` with new flags, must not match out-of-workspace paths.
- M1.1 refactor: replay output byte-identical pre/post extraction.
- M1.2: new-extractor corpora (benign edit in workspace → Safe; secret-file edit → Catastrophic; unknown MCP tool → Ambiguous).

## 8. North-star appendix (Phases 2–4, not in scope)

| Phase | Ships | Wheels reused | Invented |
|---|---|---|---|
| 2 | Signature packs: rules-as-data, community repo, signed updates | semgrep/gitleaks pack model, minisign, git distribution | agent-action signature vocabulary |
| 3 | Trajectory conformance: deterministic multi-step patterns ("read N secrets → egress") | Falco/Tetragon rule semantics, existing event log | the deterministic trajectory rules (research white space; paper-worthy) |
| 4 | Quarantine: suspect actions run sandboxed instead of just held | Landlock (Linux), Seatbelt (macOS) | glue only |

Standing commitments: manifests stay data (Phase-2 seed); `judge()` stays swappable (Cedar or successor); AgentDojo remains the external benchmark currency; positioning leans on "the referee can't be the player" (independent, cross-agent, audit-grade — what a vendor's native permission prompt can never be).
