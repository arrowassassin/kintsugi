# Kintsugi — Provenance / taint-aware flow control (design doc)

**Date:** 2026-06-20 · **Status:** Design draft — *needs human go-ahead before code (touches rule classes + security spine; see `CLAUDE.md`)*
**Feature:** Provenance — deterministic, prompt-injection-aware taint tracking ("trifecta guard")
**Relationship to existing spec:** extends `kintsugi-design-doc.md`; this is the next phase after the Phase 0–5 line. Companion roadmap for V2 + the desktop app is in §7–§8.

---

## 0. Summary

Today Kintsugi blocks commands that are *intrinsically* catastrophic (`rm -rf`, force-push, `DROP TABLE`). Provenance adds a second, orthogonal axis: block commands that are **causally influenced by untrusted content** — the "lethal trifecta" (untrusted input + access to secrets/private data + an exfiltration sink). This defends against indirect prompt injection, poisoned links, and malicious file/tool content — the dominant agent attack class of 2025–2026, and one no shipping agent-security product covers deterministically.

The decision stays **100% deterministic** (Tier-1 rules). The local model remains advisory-only. This is fully consistent with the security spine.

## 1. Security-spine compliance (read first)

Mapped to `CLAUDE.md` §"Security spine":
1. **Rules block, model only explains.** The trifecta verdict is a deterministic Tier-1 rule over taint labels. The model may only *advise* (e.g. a dependency hint or a plain-English provenance summary); it never decides.
2. **Monotonic model influence.** Taint can only *add* caution (escalate to hold/deny). The model may never clear a taint or downgrade a trifecta block.
3. **Raw command preserved + shown verbatim.** Unchanged. The provenance trail annotates; it never replaces the command text.
4. **Append-only, hash-chained log.** Taint events (source ingested, label assigned, propagation, trifecta verdict) are new event types in the existing log — appended, never mutated.
5. **No network egress.** Provenance adds no egress. It *observes* egress attempts as sinks; it does not make any.
6. **No secret values in logs.** A "sensitive read" is recorded by *path/identifier only* (`~/.aws/credentials`), never contents — same as today's secret-access detection.
7. **Honest guarantee.** Provenance is *interception-grade*, not an unbypassable firewall. Coarse taint is sound-but-over-approximate (false positives possible); an agent in yolo/auto-approve mode or calling a binary by absolute path can bypass the hooks. The guarantee remains "nothing unrecoverable + everything recorded," not "no exfiltration is ever possible."

## 2. Threat model

- **Indirect prompt injection:** the agent reads attacker-controlled content (web page, GitHub issue, file, tool output) carrying hidden instructions, then runs a command that exfiltrates secrets or damages the system.
- **Poisoned links / supply content:** a malicious URL the agent was told to fetch.
- **Confused-deputy exfiltration:** legitimate-looking command (`curl`, `git push`, `nc`, DNS) that leaks tainted/sensitive data.
- Out of scope for V1: covert channels below the command layer, in-model reasoning attacks that never surface as an observable tool call, and bypasses via disabled hooks (covered only by the filesystem backstop).

## 3. The feature

### 3.1 Trust-boundary model (configured in policy, deterministic)
- **Untrusted sources (taint origins):** web fetches, web-search results, downloaded files, issue/PR/ticket/email bodies, MCP/tool outputs from external services, clipboard, and shell ingestion (`curl`/`wget`/`git clone`/reads of downloaded artifacts). Trusted by default: the repo's own tracked files (configurable).
- **Sensitive reads:** secrets/keys/credentials/env (`.env`, `~/.ssh`, `~/.aws/credentials`, keychains, token stores) — reuses today's secret-access detection.
- **Sinks:** network egress (`curl`/`wget`/`nc`/`scp`/`ssh`/DNS tools/`git push` to external remotes), writes to shared/public/world-readable locations, outbound MCP calls.

### 3.2 Taint state model (coarse, source-level, deterministic)
- **Granularity (V1):** session-level and file-level labels. Fine-grained per-token dataflow is explicitly *out of scope* (unsolved deterministically in real time — see §3.7).
- **Session taint:** when an untrusted source is ingested, the agent session is labelled `tainted{source_id, ts}`. Multiple sources accumulate as a provenance set.
- **File taint:** when a tainted session writes a file, that path is labelled tainted (tracked in a taint store keyed by absolute path). A later read of a tainted file re-taints the reading session.
- **Reset/decay:** taint persists for the session; policy may define explicit trust resets (e.g. a human-reviewed checkpoint). No automatic time decay in V1 (sound over fast).

### 3.3 Taint-source observation — the new interception surface (FULL, per decision 2026-06-20)
Kintsugi today hooks only shell tools. V1 **extends the interception layer to observe content-ingesting tool calls** so taint sources are seen at the moment of ingestion:
- Register pre-tool (and where available, post-tool/result) hooks on content tools per agent: `WebFetch`, `Read`, web-search, file-read tools, and MCP tool results. (Claude Code `PreToolUse` matchers extend beyond `Bash`; equivalent matchers exist per dialect — see `docs/hooks.md`. Where an agent exposes only pre-tool (not the *result*), V1 taints on the *act* of fetching an untrusted URL/path; result-content classification is V1.1.)
- Shell-based ingestion continues to be caught via the existing Bash hook + `$PATH` shim.
- New normalized event: `ObservedIngest { source_kind, source_id, agent, session, ts }`, flowing to the daemon's taint tracker. Non-shell tools previously "passed through silently"; now content tools are observed (still allowed — observation, not blocking, unless a sink rule fires later).

### 3.4 The trifecta rule (Tier-1, deterministic)
```
TRIFECTA-01:  session_or_input_tainted  AND  sensitive_read  AND  egress_sink   → BLOCK (catastrophic-class)
TRIFECTA-02:  session_or_input_tainted  AND  egress_sink (no sensitive read)     → HOLD (ambiguous-class)
TRIFECTA-03:  session_or_input_tainted  AND  sensitive_read (no sink)            → ANNOTATE + HOLD if attended
```
Tunable per scope in policy. A trifecta BLOCK is mapped to deny on hooks (like other catastrophic holds) and routed through the guarded `kintsugi run` path so the snapshot/audit guarantees hold.

### 3.5 Decision-flow integration
Slots into the existing precedence (`docs/policy.md`) as a new Tier-1 input:
1. Tier-1 classifies the command (Safe/Catastrophic/Ambiguous) **and** evaluates taint rules over current session/file labels.
2. Taint verdicts compose monotonically: they may escalate a class, never downgrade. A trifecta BLOCK is a hard floor exactly like an intrinsic catastrophic command.
3. Policy `deny`/`allow` and decision memory apply as today (allow never downgrades a trifecta block, same as it never downgrades catastrophic).
4. The model (Tier-2) may add an advisory dependency hint / provenance summary for the ambiguous taint band only.

### 3.6 Provenance trail (audit + UI)
Every taint verdict records a deterministic, human-readable trail: `untrusted source read → label → sensitive read → egress sink → rule fired`. This powers (a) the audit log (forensic replay: "everything descended from source X") and (b) the UI hero panel. It is the core trust mechanism that makes a coarse, over-approximate gate usable — the human approves in one keystroke *with full context*.

### 3.7 The hard problem + false positives (first-class)
Precise "did this command actually *depend* on the untrusted input?" is unsolved deterministically in real time (offline auditors can't block in time; LLM/white-box screeners reintroduce model dependence). V1 ships **coarse source-level taint (sound, over-approximate)** and treats false positives as a UX problem solved by the provenance trail + one-key approve + per-scope tuning + always-allow memory. The advisory model may *narrow* (hint "likely independent") but never *widen* trust.

### 3.8 Honest caveats
Inherits the hook honest-limit: yolo/auto-approve mode, disabled hooks, or absolute-path binary calls bypass observation (filesystem backstop still applies). Coarse taint over-blocks; tuning is expected. Result-content classification (vs. fetch-act tainting) depends on per-agent post-tool visibility.

## 4. Architecture & crate placement
- `kintsugi-intercept`: add content-tool matchers + the `ObservedIngest` normalization (new dialect entries alongside `hook.rs`/`dialect.rs`).
- `kintsugi-core`: taint state model, taint store, trifecta rules, provenance-trail builder. New deterministic rule module; **zero-tolerance** test bar applies (a trifecta-classified-as-safe is a hard CI failure).
- `kintsugi-daemon`: hold session taint state; persist taint events to the log; expose taint state + provenance over IPC.
- `kintsugi-model`: optional advisory dependency-hint / provenance-summary prompt (never decides).
- `kintsugi-cli` / `kintsugi-tui`: surface taint state, provenance trail, and trifecta holds.

## 5. Policy additions (`.kintsugi.toml`)
```toml
[provenance]
enabled = true
mode = "attended"            # trifecta block always hard; lesser bands respect mode
untrusted = ["web", "downloads", "mcp:*", "issues"]   # source kinds treated as taint origins
trusted_paths = ["src/**", "tests/**"]                # repo-owned content not tainted
sensitive = ["~/.aws/**", "~/.ssh/**", ".env", "**/*token*"]
sinks = ["curl *", "wget *", "nc *", "scp *", "git push *", "* | sh"]
reset_on = ["human_checkpoint"]
```

## 6. Phasing (Phase 6.x — follows your phase + TDD + 90% coverage discipline)
- **P6.1** Taint state model + store + property tests (no I/O). Acceptance: labels propagate per spec; trifecta truth-table proven.
- **P6.2** Content-tool observation in `kintsugi-intercept` (per-dialect matchers + `ObservedIngest`). Acceptance: web/file/MCP ingest observed across the supported agents; adversarial bypass tests.
- **P6.3** Trifecta rules wired into Tier-1 + policy schema + decision-flow composition. Acceptance: zero "trifecta-as-safe"; monotonic-caution invariant tested.
- **P6.4** Provenance trail + new log event types + IPC surface. Acceptance: forensic replay reconstructs the trail; log stays hash-chained/append-only.
- **P6.5** CLI/TUI surfacing of taint + holds. Acceptance: a held trifecta shows its provenance trail; one-key approve/deny.
- Each is one branch + PR through the six-role review gate. Never commit to `main`.

## 7. The desktop app (parallel delivery track)
Decision: ship a **Tauri** desktop app — Rust backend reusing this engine + a web frontend (so the UI can be designed with AI tools and shipped cross-platform). The `ratatui` TUI remains the headless/SSH fallback. GPUI rejected (incompatible with a web-design workflow, immature cross-platform, slow for a solo dev on a UI-heavy app; native-render edge irrelevant for a dashboard).

**UI surface map (design-front handoff):** 1) Control room / dashboard (calm-by-default). 2) Held-command panel with the deterministic **provenance trail** (hero). 3) Live feed. 4) Provenance / trust-zone visualizer (source → tainted data → sink). 5) Audit log (hash-chain verify). 6) Policy editor (rules + taint sources/sinks + capability scopes). 7) Snapshots / undo. 8) Settings / enterprise. *(A control-room + provenance-hero mockup exists; gold-seam accent, "show your work on every block.")*

## 8. V2 roadmap (research-backed, sequence by buyer pull)
1. **Formally-verified gate** — machine-check soundness invariants (deny-by-default, block-overrides-allow) + differential random testing to align spec with Rust (AWS Cedar pattern; Kani/Verus/Creusot). Enterprise trust badge. *Bounded/partial — market accurately.*
2. **Capability-based least-privilege scoping** — symbolic per-tool/per-argument policies, deterministically enforced, LLM only proposes (Progent).
3. **MCP / agent-to-agent authorization + non-human-identity governance** — inventory shadow MCP servers (OWASP MCP), govern A2A/MCP calls.
4. **Transactional sandboxing** — CoW snapshots → provable rollback (overlayfs/btrfs/gVisor/microVM/seccomp). *Headline numbers in arXiv:2512.12806 were refuted — build on the OS primitives, not those figures.*
5. **Advanced dependency detection** — local LM-as-judge advisory screeners; attention-saliency if white-box; cut false positives. Always advisory.
6. **Forensic provenance auditing** — NeuroTaint-style offline provenance reconstruction for incident replay.
7. **E2E-encrypted team/fleet tier** — sync policies + audit across a team; security-team control room; compliance reporting. *The paid tier; the one place a light managed backend appears.*
8. **Community policy packs** — shareable rule/taint packs; seeds the network/data flywheel.

## 9. Risks (carry forward)
- **Absorption** by frontier labs shipping native IFC → defend with cross-agent, local-first, deterministic, audit-grade positioning.
- **False-positive ceiling** of coarse taint → mitigate with provenance UX + tuning.
- **Per-agent observability gaps** (pre- vs post-tool) → tainting on fetch-act in V1; result-classification in V1.1.
- **GTM** (solo, nights/weekends) → open-source dev-led adoption → enterprise monetization.

## 10. Sources
CaMeL arXiv:2503.18813 · "Design Patterns for Securing LLM Agents against Prompt Injections" arXiv:2506.08837 · Fides arXiv:2505.23643 · RTBAS arXiv:2502.08966 · Progent arXiv:2504.11703 · NeuroTaint arXiv:2604.23374 · "Systems Security Foundations for Agentic Computing" arXiv:2512.01295 · "Fault-Tolerant Sandboxing for AI Coding Agents" arXiv:2512.12806 *(rollback numbers unverified)* · AWS Cedar (automated reasoning + differential testing) · Kani / Verus / Creusot · Simon Willison — "lethal trifecta".
