# Phase 6 — changes & hardening to existing features (code-grounded)

Companion to `kintsugi-provenance-design.md` and `kintsugi-phase6-tasklist.md`. This lists the
concrete changes Phase 6 requires in the *existing* codebase, grounded in the current source.
Each is a security-spine-sensitive change → covered by the human-approved design + the review gate.

---

## A. Daemon: add session/agent context + durable taint state  *(biggest change)*
**Finding:** there is **no session concept in the engine.** `rules::classify_and_decide(cmd, mode)`
(`crates/kintsugi-core/src/rules.rs:64`) is stateless per `ProposedCommand`; "session" today exists
only in the CLI shell-recorder (`crates/kintsugi-cli/src/...`), not the decision path.

**Change:**
- Introduce `SessionId` and thread it through `ProposedCommand` (`types.rs`) and the IPC contract
  (`kintsugi-daemon/src/ipc.rs`). Derive it per dialect: prefer the agent's own session id where the
  hook payload carries one (Claude Code's hook JSON includes a session id); fall back to a
  `agent + cwd + ppid` heuristic. Document the fallback's limits.
- Daemon holds `SessionId -> TaintSet` and `AbsPath -> TaintSet` state.
- **Durability / fail-closed:** in-memory taint is lost on daemon restart. Persist taint events to the
  existing SQLite log so taint survives a restart; on cold start, **rebuild taint state from the log**.
  Under `KINTSUGI_FAIL_CLOSED=1`, unknown/lost taint must err toward caution (treat as possibly tainted
  for trifecta), never silently clear.

## B. rules.rs: extract reusable, standalone predicates
**Finding:** secret-read detection already exists — `reads_secret` / `is_secret_path` /
`clobbers_secret` / `seg_mentions_secret` (`rules.rs:795–840`). Egress detection exists but is narrow
and embedded in catastrophic patterns (curl|sh downloader at `rules.rs:330–332`; `curl -X POST` cases).

**Change:**
- **Reuse, don't reinvent** the secret leg: expose `is_sensitive_read(cmd) -> Option<path-id>` built on
  the existing `reads_secret`/`is_secret_path`. (Identifier only — never contents; spine rule 6.)
- **Extract** `is_egress_sink(cmd) -> Option<target>` from the existing curl/wget/fetch/POST logic and
  broaden carefully to scp/ssh/nc/DNS-exfil/`git push`-to-external — as a *dedicated predicate*, not by
  loosening any existing catastrophic rule. Zero-tolerance bar applies: no "catastrophic-as-safe"
  regression in `rules.rs` tests (the roundtable corpus at `rules.rs:1323+`).
- Keep `classify()` pure for *intrinsic* class. Add a separate `evaluate_trifecta(cmd, session_taint)`
  composed in the daemon, so the per-command classifier signature stays stable and the new taint axis
  is additive (monotonic-caution by construction).

## C. types.rs: new taint types + Verdict/ProposedCommand extension
`types.rs` (193 lines) defines `Class` (:65), `Mode` (:113), `Decision` (:138), `Verdict`.
**Change:** add `SourceKind`, `TaintLabel`, `TaintSet`, `ObservedIngest`, `ProvStep` (see task list);
extend `Verdict` with `provenance: Option<Vec<ProvStep>>`; add `session: SessionId` to `ProposedCommand`.
`Class` is unchanged (trifecta maps to `Catastrophic`/`Ambiguous`); only the `reason`/provenance carry
the trifecta detail.

## D. log.rs: new event variants, schema versioned, chain preserved
`log.rs` (1044 lines) is the append-only hash-chained event log.
**Change:** add event variants (`ObservedIngest`, `TaintAssigned`, `TaintPropagated`, `TrifectaVerdict`
with `Vec<ProvStep>`). Bump the log schema version and handle forward/back compat on read. **Invariant:**
append-only + hash chain unbroken; no secret contents in any new field (source_id/path are identifiers).

## E. intercept: the new observation surface (+ no regression to the shell path)
`hook.rs` / `dialect.rs` currently match shell tools only; non-shell "passes through silently"
(`docs/hooks.md`).
**Change:** add per-dialect matchers for content tools (`WebFetch`/`Read`/web-search/file-read) and MCP
tool results → normalize to `ObservedIngest` → daemon. **Observation never blocks** (still allow); it
only labels. **Harden:** ensure the added matchers don't regress the existing shell hold path or the
fail-open behavior for non-dangerous commands; build the cross-agent observer as a **standalone spike
first** (it is the riskiest new primitive, like the `$PATH` shim was — see CLAUDE.md "Start here").

## F. policy.rs: `[provenance]` schema
`policy.rs` (269 lines) parses `.kintsugi.toml` (allow/deny/mode, repo overrides global).
**Change:** add the `[provenance]` table (untrusted, trusted_paths, sensitive, sinks, mode, reset_on —
schema in design doc §5). Repo-overrides-global precedence unchanged. `deny` precedence preserved.

## G. redact.rs: provenance must stay secret-safe
`redact.rs` (847 lines) handles redaction. **Change:** route any new source_id / path field through the
existing redaction so a provenance trail can never capture secret values. Add tests asserting no secret
content appears in `ObservedIngest`/`ProvStep`.

## H. model: advisory dependency hint only (no decision)
`kintsugi-model` (`heuristic.rs`/`llama.rs`). **Change (optional, V1.1-leaning):** an advisory
"likely dependent?" hint / provenance summary for the *ambiguous taint band only*. Must be
escalation-only and never clear a taint or downgrade a trifecta block (spine rules 1–2).

---

## Sequencing note
A (session+taint state) and B (predicates) are prerequisites for the P6.1 model and P6.3 rules.
E (observation surface) is the riskiest and should be spiked standalone before integration.
Everything lands through one-branch-per-segment + the six-role review gate; never to `main`.
