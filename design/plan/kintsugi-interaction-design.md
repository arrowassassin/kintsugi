# Kintsugi — interaction design: auto-mode, in-band, antivirus-style (design doc)

**Date:** 2026-06-20 · **Status:** Design draft (research-backed) · Supersedes the "control room is the approval path" framing in earlier docs.

The goal: **never make the user alt-tab to a separate app to approve things.** Run silent by default like antivirus; auto-handle most flags by *negotiating with the agent*; surface a human decision only rarely, and when we must, **in-band inside the agent CLI the user is already in.** The desktop app is demoted to an after-the-fact dashboard, not the gate.

---

## 1. The tiered interaction model

| Tier | Trigger | Action | Where | Human? |
|------|---------|--------|-------|--------|
| **0 — Silent allow** | Safe / allowlisted / remembered | Runs | — | No |
| **1 — Auto-negotiate** | A block the agent can route around (most prompt-injection) | Deterministic **deny + a crisp, state-grounded reason** fed to the model → agent self-corrects | Inside the agent loop | **No** |
| **2 — In-band human** | Genuinely ambiguous high-stakes, or the agent keeps insisting | The agent's **native `ask` prompt** (Claude/Cursor/OpenCode), or — where unavailable — deny+reason that tells the agent to *ask the user itself* | **In the CLI** | Yes, in place |
| **3 — Dashboard** | Review / tune / audit | Desktop app: provenance trail, history, policy | App, occasional | — |

## 2. Per-agent capability matrix (research-confirmed; protocols are 2025-26, in flux)

| Agent | In-band `ask`? | Reason → model? | Tier-2 strategy |
|-------|----------------|-----------------|-----------------|
| **Claude Code** | ✅ `PreToolUse` `permissionDecision: ask` (same dialog as default mode) | ✅ `permissionDecisionReason` (model-facing) | Native ask |
| **Cursor** | ✅ `beforeShellExecution` allow/deny/ask | ✅ **two fields**: `agent_message` (to model) + `user_message` (to UI) | Native ask |
| **OpenCode** | ✅ allow/ask/deny with once/always/reject | ✅ | Native ask |
| **Gemini CLI** | ❌ deny-only (allow/deny/block) | ✅ deny `reason` sent to agent as a tool error | **Tier-1 only** (deny+reason → agent asks user) |
| **Codex** | ❌ `PreToolUse` hook bash-only & deny-only (bidirectional hook is only a proposed issue) | ✅ (reviewer feedback) | **Tier-1 only** for now |
| **Copilot / Qwen** | partial (PreToolUse) | ✅ | deny+reason; native ask where present |

**Hard takeaway:** a uniform in-band Tier-2 is **not** achievable across all agents today. For Gemini/Codex, Tier-2 collapses into Tier-1 (deny+reason, with the reason instructing the agent to ask the user). Do **not** assume a single message field serves both model and human — Cursor's explicit two-field split is the safe pattern; Claude's reason is **model-facing** (the claim it's shown to the user too was refuted).

## 3. The negotiation protocol (and the asymmetry that keeps it safe)

There's a **deployed reference implementation to copy — Codex's reviewer/approvals**:
- On denial, the agent is instructed: *"Do not pursue the same outcome via workaround, indirect execution, or policy circumvention. Continue only with a materially safer alternative. Otherwise, stop and ask the user."*
- A **circuit breaker** interrupts after **3 consecutive** (or 10/50 rolling) denials, and **fails closed** on parse/timeout.
- The deterministic rule layer enforces **"deny always wins; `*` is valid only for allow rules."**

We adopt exactly this. The asymmetry:
- The agent may **retreat / revise / propose a *different* command** — freely.
- The agent may **never** argue the gate into allowing the blocked command.
- **Only a human (in-band) overrides a hard block.**

**Critical safety invariant (a risk the research flagged):** the re-proposed command is **re-evaluated by the same deterministic rules from scratch.** The negotiation *reason text is never an input to the allow decision.* Otherwise injected content could craft phrasing that talks the gate open — prompt-injecting the negotiation loop itself. Allow must be reachable **only** via pattern/rule match, never via anything the model says.

## 4. Why negotiation reduces interruptions but is NOT the security mechanism

Research (Reflexion, ReflAct, Renze & Guven) confirms agents *can* self-correct from natural-language feedback in-context (no fine-tuning) — so Tier-1 will silently neutralize many injection attempts. **But it is unreliable**: documented failure modes are retrying the same blocked action, ungrounded/hallucinated reasoning, and (in a security setting) **no ground-truth oracle**. AgentDojo shows injection ASR ~57.7% and that model-side defenses are "not foolproof."

Therefore:
- **Security = the deterministic gate**, which holds regardless of whether the agent cooperates. Negotiation only changes *who/whether we interrupt*, never *whether the block holds*.
- Make deny reasons **crisp and state-grounded** (ReflAct: +27.7% over free-form) — name the source, the secret, the sink, the rule.
- **Cap retries** with the circuit breaker; after N denials, stop and escalate (Tier-2) or hard-stop.
- **Tiering/classification must be rule-driven, not a classifier model** — Codex's *model* risk-classifier has been red-team-bypassed; only its deny-**rule** layer is trustworthy. This matches Kintsugi's spine exactly: rules decide, the model never does.

## 5. Antivirus/EDR patterns we adopt (to push Tier-2 toward zero)

- **Allowlist / denylist, deterministic, last-match-wins** (OpenCode-style) → Tier-0 silent allow.
- **Decision memory / "always allow this"** (already in Kintsugi) → never ask twice.
- **Default-action-with-timeout** (unattended): auto-deny-with-reason after N seconds so nothing ever hangs on a human.
- **Silent/protected mode**: only hard blocks ever surface.
- **Graduated/earned autonomy**: the tool earns more silent authority per-repo over time (open question: measure the benefit).

## 6. What this changes in the build
- **New Phase 6 segment — "agent-facing deny reasons + negotiation":** extend the per-dialect verdict serialization (`kintsugi-intercept/src/dialect.rs`) to emit a **model-facing reason** on deny (two-channel where supported), carrying the provenance trail in plain language; add the **consecutive-denial circuit breaker** and the "materially safer alternative / else ask the user" instruction; keep `ask` for agents that support it.
- **Re-evaluate-from-scratch invariant** wired so reason text never reaches the allow path.
- **Desktop app reframed** (update `kintsugi-app-design-brief.md`): it is the **dashboard/audit/config** surface, *not* the approval path. The hero "held-command" screen becomes a *review* artifact, not the daily driver.
- **Secret-safe reasons:** the deny reason fed to the agent must be redacted (hardening item G) — never leak a credential value into the negotiation channel.

## 7. Biggest risks (flagged honestly)
1. **Negotiation-loop injection** — mitigated by the re-evaluate-from-scratch invariant (allow only via rules).
2. **Agent ignores/retries** — mitigated by the circuit breaker + Tier-2 fallback + the gate holding regardless.
3. **No uniform in-band ask** — Gemini/Codex fall back to Tier-1; track protocol evolution.
4. **Version fragility** — e.g. Cursor `ask` executed-without-prompting in some builds; allow-lists can override hook permissions. For high-stakes on agents with known bypasses, **prefer deny over ask.**

## 8. Sources
Claude Code hooks (code.claude.com/docs/en/hooks) · Cursor hooks (cursor.com/docs/hooks.md) · OpenCode permissions (opencode.ai/docs/permissions) · Gemini CLI hooks (geminicli.com/docs/hooks) · Codex agent-approvals + auto-review (developers.openai.com/codex) · Reflexion arXiv:2303.11366 · ReflAct arXiv:2505.15182 · Renze & Guven arXiv:2405.06682 · AgentDojo arXiv:2406.13352 · PromptArmor arXiv:2507.15219 · CaMeL/design-patterns arXiv:2506.08837.
