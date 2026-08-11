# Research: making the command classifier more accurate (fewer "allow once" prompts, no missed catastrophes)

Status: research record + adopted plan. Companion to `crates/kintsugi-core/src/rules.rs`
(the Tier‑1 rule engine) and `parse.rs` (the bash‑AST pass). Nothing here changes the security
spine — every proposal is constrained by it.

## The problem, stated against the real code

In attended mode `decide()` (rules.rs) maps classes to actions like this:

```
Safe         -> Allow
Ambiguous    -> Hold   <- the user sees a prompt
Catastrophic -> Hold
```

`is_safe()` is a **narrow allowlist** (read/build/test programs plus tight `git`/`cargo`/`npm`/
`go` subcommand gates). Everything that isn't provably safe and isn't catastrophic falls into
**Ambiguous → Hold**. That is correct for safety but it is the source of the "I click *allow once*
on every other query" fatigue: a huge, heterogeneous middle band all produces the same prompt.

So the goal is not "detect catastrophes better" (the catastrophic floor is already broad and the
zero‑tolerance rule forbids weakening it). The goal is to **shrink the Ambiguous→Hold band**
without ever letting a catastrophic command reach Allow. The research below says that is mostly
an *engineering and UX* problem, not a *model* problem — and it is dangerous to "solve" with a model.

---

## Findings (evidence + confidence)

Confidence reflects source quality. WebFetch was 403'd across arxiv/vendor hosts during this
research, so most numeric figures come from search‑engine summaries; figures surfaced
independently by two or more search agents are marked accordingly. Two sources were fetched
first‑party (NL2Bash README; Claude Code permissions doc) and are the strongest.

### F1 — A learned model must never be the block, and must never *downgrade*. (HIGH confidence)
The single most consistent result across the security literature: models that gate adversarial input
fail exactly when it matters.
- Up to **100% evasion** of six production guardrails (incl. Azure Prompt Shield, Meta Prompt Guard)
  via character‑injection + adversarial‑ML, *while preserving the malicious payload* — arXiv 2504.11168.
- Guard models are **systematically over‑confident under jailbreak** (ICLR'25, arXiv 2410.10414;
  code at github.com/Waffle-Liu/calibration_guard_model) — their confidence score is not trustworthy
  precisely under attack.
- **Generalization collapse** on unseen attacks: one guard dropped 91.0%→33.8% accuracy (−57 pts) on
  novel inputs; "too permissive" LlamaGuard variants detect only **4.5–21.8%** of harmful inputs;
  guards sometimes **answer the harmful prompt** (11–14% of cases) instead of classifying it
  (arXiv 2511.22047).
- Many‑shot jailbreaking's own recommended mitigation is "**classification/modification of the prompt
  before it reaches the model**" — i.e. a deterministic pre‑filter, not the model
  (anthropic.com/research/many-shot-jailbreaking).

→ Direct, independent validation of Kintsugi's spine rules #1 and #2. A command classifier sees
adversarial input *by definition*, so every one of these failure modes is in scope. The model stays
advisory, additive‑caution, AMBIGUOUS‑band‑only.

### F2 — The catastrophic class is the *rarest* class, so learned recall is worst exactly where we need it best. (HIGH confidence)
- Real malicious‑command corpora are small and ~10:1 imbalanced (a PowerShell CNN study: 6,290
  malicious / 60,098 benign, arXiv 1807.04739). General ML consensus: models "underperform on
  under‑represented classes."
- The canonical benign corpus, **NL2Bash** (~9,305 filtered NL/command pairs, 100+ utilities;
  README fetched first‑party), has **no risk labels at all** — any learned risk model needs a corpus
  we'd have to build ourselves.

→ A learned catastrophic detector would have its worst recall on catastrophes. Rules must own the
floor; this is a hard argument *for* the current architecture.

### F3 — There IS a real, on‑topic learned result — but only as an AMBIGUOUS‑band scorer. (MEDIUM confidence)
"Command‑line Risk Classification using Transformer Neural Architectures" (arXiv 2412.01655,
Huawei Munich / TU Munich, Dec 2024) frames *exactly* our problem ("intercept, assess, and block
dangerous CLI commands before they cause damage") and reports a transformer improving detection of
**rare** dangerous commands by ~+22% F1 via transfer learning — and explicitly pitches ML as a
*complement that can audit* rule‑based systems, not replace them. (Surfaced independently by two
agents; PDF not fetchable, so treat +22% as reported‑not‑verified.)

### F4 — For local CPU latency, a linear model beats a transformer by orders of magnitude. (MEDIUM confidence)
- fastText / logistic‑regression on char n‑grams is **sub‑millisecond on CPU**; a practitioner
  benchmark put BERT/DistilBERT ~400× and MiniLM ~300× slower than fastText on CPU‑only machines.
- Quantized MiniLM/DistilBERT is ~85–350 MB at tens‑of‑ms; DistilBERT keeps ~97% of BERT at ~2× speed.
- Fine‑tuned small models reliably beat zero‑shot big‑LLM prompting on short‑text classification
  (arXiv 2406.08660).

→ If/when the ambiguous band gets a local severity scorer, prefer a tiny linear/char‑n‑gram model.

### F5 — The fatigue fix is a default‑deny **allowlist**, made shell‑AST‑aware — not a denylist, and not a model. (HIGH confidence)
- **Denylists are unsound for the auto‑allow decision.** Cursor's auto‑run denylist was bypassable
  via aliases, encodings, and chained/compound commands; Cursor deprecated it (v1.3) and moved to
  allowlists (backslash.security/blog/cursor-ai-security-flaw-autorun-denylist).
- **Claude Code's permission model is the template** (doc fetched first‑party,
  code.claude.com/docs/en/permissions): rules evaluate **deny → ask → allow** (first match wins, a
  broad deny beats a narrow allow); a **non‑configurable read‑only set** runs with no prompt in any
  mode; "don't ask again" is **tiered by risk**; matching is **shell‑aware** (`safe-cmd && other`
  is not authorized by a `safe-cmd` rule; wrappers stripped; exec‑wrappers never auto‑approved);
  and `rm -rf /` prompts even in bypass mode (hard circuit breakers).
- **Habituation is itself a security failure.** Android field studies (Wijesekera USENIX'15, Felt
  SOUPS'12): prompting on ~90% of benign actions devalues warnings; prompt‑on‑first‑use then
  remember causes prompt frequency to decay without added risk. UAC/MFA practice: never re‑prompt
  to wear the user down (MFA‑fatigue attacks weaponize exactly that).

→ Kintsugi already has the safety floor and the AST awareness. **Stored per‑command "allow always"
memory was considered and REJECTED** (over‑allow drift; a remembered entry can be ridden; exact‑
string matching just moves the fatigue one keystroke away). The adopted direction is **stateless**:
make the classifier itself recognize more truly‑safe commands, so there is nothing to drift and
nothing to match.

### F6 — Reframe the axis from "dangerous?" to "reversible?" (MEDIUM confidence, high fit)
Berkeley's **GoEX** (arXiv 2404.06921) argues for replacing *pre‑facto* approval ("is this
dangerous?") with *post‑facto validation* enabled by (a) **undo** and (b) **bounded blast radius**:
if an action is reversible you can let it run and check the result; only *irreversible* actions must
be gated. The micro‑proof is the `rm` ecosystem: `safe-rm`/`careful_rm` convert the #1 dangerous
command into a reversible one by **trashing instead of deleting**. This is *exactly* Kintsugi's
honest guarantee — "nothing is unrecoverable" via snapshots, **not** "nothing runs un‑warned" — used
as a *classification axis*: an ambiguous action that the snapshot layer can fully and cheaply undo
does not need to interrupt the way an irreversible one does.

### F7 — Context/effect‑relative reasoning removes whole swaths of false ambiguity. (MEDIUM‑HIGH confidence)
- **Destructive Command Guard** (github.com/Dicklesworthstone/destructive_command_guard, fetched
  first‑party): whitelist‑checked‑first; **normalizes variable forms** (`$TMPDIR` ≡ `${TMPDIR}`) and
  whitelists `rm -rf /tmp/*`‑class targets so the *same* command is allowed in temp and blocked
  elsewhere; heredoc/`-c`‑body AST scanning; span classification (dangerous string in a comment or
  quoted data doesn't fire); `--force` vs `--force-with-lease` told apart.
- **seccomp can't dereference the filename pointer** (kernel docs) — it sees *that* an `openat`
  happens, not the path. Path‑aware ("safe in /tmp, fatal at /") decisions must be made by
  **parsing the command pre‑exec** (what we do), not at the syscall layer.
- The masquerade‑detection lineage (Schonlau, Statistical Science 2001; Maxion & Townsend, DSN
  2003) found the risk signal lives in the **arguments and paths** that the classic benchmarks threw
  away — a tool that keeps full command text starts ahead of the ~60–69% benchmark numbers.

### F8 — "Surprise = risk," computed per‑project, is a cheap monotonic escalator. (MEDIUM confidence)
A first‑order Markov / n‑gram model over *this project's own* command history is linear‑cost, online,
explainable ("you've never run `git push --force` in this repo before"), and trains with **one‑class**
data — all we'll ever have. Wang & Stolfo showed one‑class training roughly matches two‑class for
this task. A textbook **additive‑caution** signal: it can escalate (unusual → hold) but never unlock.

---

## Adopted plan (v0.4.0, sequenced; spine‑safe)

**P‑1. Widen the confident‑safe recognizer.** *(this PR)* Add strictly read‑only forms to
`is_safe()`: more `git` read verbs, `kubectl`/`docker`/`helm`/`terraform`/`gh` query verbs,
package‑manager query verbs, pure text filters/checksums. Two hard rules: (a) the global
secret‑path guard applies to every addition; (b) subcommand‑gated tools match the verb at
**position 0 only** — never "first non‑flag token" — because a value‑taking flag would let its
*value* stand in for the verb (`kubectl -n get delete …` reads "get" while the real subcommand is
`delete`), which would be a catastrophic‑as‑safe hole. Position‑0 matching fails toward caution.

**P‑2. Context‑relative targets.** Normalize `$TMPDIR`/`${VAR}`/relative paths against cwd +
git‑root *before* judging; treat repo‑confined and temp‑dir operations as low blast radius.

**P‑3. Reversibility tier — off‑by‑default policy flag.** Ambiguous **+** fully snapshot‑reversible
**+** no egress **+** no secret‑read → snapshot first, then allow (or soft confirm). Irreversible
ambiguous stays Held; Catastrophic untouched. A guardrail change: ships dark, needs explicit human
sign‑off to enable.

**P‑4. Measure with the right metric.** Extend the golden corpus with a benign‑in‑context set
(prompts‑per‑100‑commands, before/after) and an adversarial set (wrapper/compound/encoding
evasions). Evaluate at a **fixed false‑positive budget**, not raw accuracy — the catastrophic class
is rare and imbalanced. Catastrophic‑as‑safe stays a hard CI failure.

### Anti‑patterns (evidence‑backed, adopted as constraints)
- **No** model in the block path, and no model downgrade — ever (F1).
- **No** stored per‑command allow‑memory as the auto‑allow mechanism (F5 + user decision).
- **No** denylist as the permission boundary (F5).
- **No** re‑prompting to wear the user down; no prompting on risk‑free actions (F5).
- **No** syscall‑filter shortcut for path decisions (F7).
- **No** learned catastrophic detector (F2).

## Primary sources
- arXiv 2412.01655 — Command‑line Risk Classification using Transformer Neural Architectures
- arXiv 2504.11168 — bypassing LLM guardrails (≤100% evasion)
- arXiv 2410.10414 (ICLR'25) — guard‑model calibration / over‑confidence under jailbreak
- arXiv 2511.22047 — guardrail generalization collapse
- anthropic.com/research/many-shot-jailbreaking
- code.claude.com/docs/en/permissions — tiered, shell‑aware, deny→ask→allow permission model
- backslash.security/blog/cursor-ai-security-flaw-autorun-denylist — denylist failure
- Wijesekera et al., USENIX Security 2015; Felt et al., SOUPS 2012 — permission habituation
- arXiv 2404.06921 — GoEX (reversibility / post‑facto validation)
- github.com/Dicklesworthstone/destructive_command_guard — context‑relative denylist with span kinds
- github.com/TellinaTool/nl2bash — NL2Bash corpus (benign, unlabeled)
- Schonlau et al., Statistical Science 2001; Maxion & Townsend, DSN 2003 — command‑history anomaly
- arXiv 2406.08660 — fine‑tuned small models > zero‑shot LLM on classification
