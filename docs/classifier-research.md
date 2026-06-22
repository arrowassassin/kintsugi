# Research: making the command classifier more accurate (fewer "allow once" prompts, no missed catastrophes)

Status: research / proposal. Not yet a decision. Companion to `crates/kintsugi-core/src/rules.rs`
(the Tier‑1 rule engine) and `parse.rs` (the bash‑AST pass). Nothing here changes the security
spine — every proposal is constrained by it.

## The problem, stated against the real code

Today `decide()` (rules.rs) maps classes to actions like this in attended mode:

```
Safe         -> Allow
Ambiguous    -> Hold   <- the user sees a prompt
Catastrophic -> Hold
```

`is_safe()` is a **narrow allowlist** (≈40 read/build/test programs plus tight `git`/`cargo`/`npm`/
`go` subcommand gates). Everything that isn't provably safe and isn't catastrophic falls into
**Ambiguous → Hold**. That is correct for safety but it is the source of the "I click *allow once*
on every other query" fatigue: a huge, heterogeneous middle band all produces the same prompt, and
the prompt has **no memory** — the same `mv a b` or `python script.py` is held again next time.

So the goal is not "detect catastrophes better" (the catastrophic floor is already broad and the
zero‑tolerance rule forbids weakening it). The goal is to **shrink and de‑duplicate the Ambiguous→Hold
band** without ever letting a catastrophic command reach Allow. The research below says that is mostly
an *engineering and UX* problem, not a *model* problem — and it is dangerous to "solve" with a model.

---

## Findings (evidence + confidence)

Confidence reflects source quality. WebFetch was 403'd across arxiv/vendor hosts during this research,
so most numeric figures come from search‑engine summaries; figures surfaced independently by two or
more search agents are marked accordingly. Two sources were fetched first‑party (NL2Bash README;
Claude Code permissions doc) and are the strongest.

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

→ This is direct, independent validation of Kintsugi's spine rules #1 and #2. A command classifier
sees adversarial input *by definition*, so every one of these failure modes is in scope. The model
stays advisory, additive‑caution, AMBIGUOUS‑band‑only.

### F2 — The catastrophic class is the *rarest* class, so learned recall is worst exactly where we need it best. (HIGH confidence)
- Real malicious‑command corpora are small and ~10:1 imbalanced (a PowerShell CNN study: 6,290
  malicious / 60,098 benign, arXiv 1807.04739). General ML consensus: models "underperform on
  under‑represented classes."
- The canonical benign corpus, **NL2Bash** (~9,305 filtered NL/command pairs, 100+ utilities;
  README fetched first‑party), has **no risk labels at all** — any learned risk model needs a corpus
  we'd have to build ourselves.

→ A learned catastrophic detector would have its worst recall on catastrophes. Rules must own the
floor; this is a hard argument *for* the current architecture, not against it.

### F3 — There IS a real, on‑topic learned result — but only as an AMBIGUOUS‑band scorer. (MEDIUM confidence)
"Command‑line Risk Classification using Transformer Neural Architectures" (arXiv 2412.01655,
Huawei Munich / TU Munich, Dec 2024) frames *exactly* our problem ("intercept, assess, and block
dangerous CLI commands before they cause damage") and reports a transformer improving detection of
**rare** dangerous commands by ~+22% F1 via transfer learning — and explicitly pitches ML as a
*complement that can audit* rule‑based systems, not replace them. (Surfaced independently by two
agents; PDF not fetchable, so treat +22% as reported‑not‑verified.)

→ If we ever add a Tier‑2 learned scorer, this is the design: transfer‑learn, score the ambiguous
band, only add caution.

### F4 — For local CPU latency, a linear model beats a transformer by orders of magnitude. (MEDIUM confidence)
If/when we score the ambiguous band locally:
- fastText / logistic‑regression on char n‑grams is **sub‑millisecond on CPU**; a practitioner
  benchmark put BERT/DistilBERT ~400× and MiniLM ~300× slower than fastText on CPU‑only machines.
- Quantized MiniLM/DistilBERT is ~85–350 MB at tens‑of‑ms; DistilBERT keeps ~97% of BERT at ~2× speed.
- Fine‑tuned small models reliably beat zero‑shot big‑LLM prompting on short‑text classification
  (arXiv 2406.08660).

→ The warm daemon should prefer a tiny linear/char‑n‑gram model for any advisory severity score;
the transformer is overkill for a one‑sentence severity hint.

### F5 — The fatigue fix is a default‑deny **allowlist with memory**, made shell‑AST‑aware — not a denylist, and not a model. (HIGH confidence)
This is the most directly actionable cluster, and it cross‑corroborates from independent angles:
- **Denylists are unsound for the auto‑allow decision.** Cursor's auto‑run denylist was bypassable
  via aliases, encodings, and chained/compound commands; Cursor deprecated it (v1.3) and moved to
  allowlists (backslash.security/blog/cursor-ai-security-flaw-autorun-denylist).
- **Claude Code's permission model is the template** (doc fetched first‑party,
  code.claude.com/docs/en/permissions):
  - Rules evaluate **deny → ask → allow**, first match wins, specificity does *not* override order —
    a broad deny beats a narrow allow (monotonic block; mirrors our spine).
  - A **non‑configurable read‑only set** (`ls, cat, echo, pwd, head, tail, grep, find, wc, which,
    diff, stat, du, cd`, read‑only `git`) runs with **no prompt in any mode**.
  - "Don't ask again" is **tiered by risk**: bash commands persist per project+command permanently;
    file modifications persist only until session end; read‑only never asks.
  - Matching is **shell‑aware**: `Bash(safe-cmd *)` does **not** authorize `safe-cmd && other-cmd`;
    each subcommand of a compound must match independently; wrappers (`timeout, time, nice, nohup,
    stdbuf`) are stripped before matching; exec‑wrappers (`watch, setsid, flock`, `find -exec`)
    can **never** be prefix‑auto‑approved.
  - Even in `bypassPermissions`, `rm -rf /` and `rm -rf ~` still prompt — hard‑coded circuit breakers.
- **Habituation is itself a security failure.** Android field studies (Wijesekera USENIX'15, Felt
  SOUPS'12): prompting on ~90% of apps devalues warnings; **prompt‑on‑first‑use, then remember**
  causes prompt frequency to decay without added risk; permissions without clear risk should not be
  surfaced. UAC/MFA practice: never re‑prompt to wear the user down (MFA‑fatigue attacks weaponize
  exactly that).

→ Kintsugi already has the safety floor and the AST awareness Claude Code's matcher needs (we even
exceed it: our `effective_argv`/`wrapped_commands`/`classify_ast` already strip wrappers and refuse
to let `safe && evil` pass as safe). **What we lack is the *memory*: a scoped, default‑deny
allowlist that turns the first approval of a command‑shape into future silence.** That is the lever.

### F6 — Reframe the axis from "dangerous?" to "reversible?" — the ingenious, replicable centerpiece. (MEDIUM confidence, high fit)
Berkeley's **GoEX** (arXiv 2404.06921) argues for replacing *pre‑facto* approval ("is this
dangerous?") with *post‑facto validation* enabled by (a) **undo** and (b) **bounded blast radius**:
if an action is reversible you can let it run and check the result; only *irreversible* actions must
be gated. The micro‑proof is the `rm` ecosystem: `safe-rm`/`careful_rm` convert the #1 dangerous
command into a reversible one by **trashing instead of deleting** (~10 lines). This is *exactly*
Kintsugi's honest guarantee — "nothing is unrecoverable" via snapshots, **not** "nothing runs
un‑warned." So the reversibility partition is already our spine; we just don't yet use it as a
*classification axis* to suppress prompts.

→ An action that our snapshot layer can fully and cheaply undo does not need to interrupt the user
the way an irreversible one does. "Reversible" is a third signal alongside Safe/Catastrophic that can
*lower the interruption* (never the block) for the ambiguous middle.

### F7 — Context/effect‑relative reasoning removes whole swaths of false ambiguity. (MEDIUM-HIGH confidence)
- **Destructive Command Guard** (github.com/Dicklesworthstone/destructive_command_guard, fetched
  first‑party): whitelist‑checked‑first, then deny, then default‑allow; it **normalizes variable
  forms** (`$TMPDIR` ≡ `${TMPDIR}`) and whitelists `rm -rf /tmp/*`, `/var/tmp/*`, `$TMPDIR/*` so the
  *same* `rm -rf` is allowed in temp and blocked elsewhere. It also does heredoc/`-c`‑body AST
  scanning, **span classification** (don't fire on a dangerous string inside a comment/quote), and
  negative‑lookahead so `--force` blocks but `--force-with-lease` is judged separately. Cheap,
  explainable wins — several of which we already have, some we don't (temp‑dir context, span kinds).
- **seccomp can't dereference the filename pointer** (kernel docs) — it sees *that* an `openat`
  happens, not the path. That is the structural reason path‑aware ("safe in /tmp, fatal at /")
  decisions must be made by **parsing the command pre‑exec** (what we do) rather than at the syscall
  layer. Validates our approach and rules out a naive syscall‑filter shortcut.
- The masquerade‑detection lineage (Schonlau Statistical Science'01; Maxion & Townsend DSN'03) found
  the risk signal lives in the **arguments and paths** that the classic benchmarks threw away — so a
  tool that keeps full command text (we do) starts ahead of the ~60–69% benchmark numbers.

### F8 — "Surprise = risk," computed per‑project, is a cheap monotonic escalator. (MEDIUM confidence)
A first‑order Markov / n‑gram model over *this project's own* command history is linear‑cost, online,
explainable ("you've never run `git push --force` in this repo before"), and trains with **one‑class**
data — which is all we'll ever have (the user's own history; no labeled "bad" set). Wang & Stolfo
showed one‑class training roughly matches two‑class for this task. This is a textbook **additive‑caution**
signal for the ambiguous band: it can escalate (unusual → hold) but never unlock.

---

## What this means for Kintsugi (proposal, phased, spine‑safe)

Ordered by leverage‑per‑effort. None of these touch the catastrophic floor; all are additive.

**P‑A. Scoped allowlist with memory ("approve → remember", default‑deny).** *Highest leverage.*
After the human approves a held *ambiguous* command, offer to persist a **narrow, per‑project** rule
keyed on the command *shape* (program + sub‑command + a normalized argument skeleton, never the raw
string). Next time that shape recurs in that project, it's Allow without a prompt. Tier the
persistence by class exactly like Claude Code: read‑only never asks; ambiguous‑write persists per
project; catastrophic **never** becomes auto‑approvable (hard circuit breaker — we already have
`removes_kintsugi` and the `rm -rf /` rules; make "never auto‑approvable" an explicit property).
Crucially the persisted rule is an **allowlist entry matched through the existing AST pass**, so
`approved-cmd && rm -rf /` still can't ride in on the approval. This is the direct fatigue fix and it
reuses machinery we already have.

**P‑B. Widen the *confident‑safe* recognizer (carefully).** The Ambiguous band is partly just gaps in
`is_safe()`. Add clearly read‑only tools and read‑only sub‑commands that are currently missing
(e.g. more `git` read verbs, `kubectl get/describe/logs`, `docker ps/images/logs`, `cargo
metadata/tree`, `terraform plan/validate`, package‑manager *query* verbs). Each addition needs a test
and must stay read‑only. This shrinks the band at the source.

**P‑C. Reversibility as a prompt‑suppressing signal (not a block change).** Where the snapshot layer
can *provably and cheaply* undo an action's predicted effects (the Phase‑3 undo machinery), mark the
held item "reversible" and let attended mode present it as a lighter‑weight, one‑keystroke confirm (or
auto‑allow‑with‑undo under a user setting) instead of a full hold — *never* for catastrophic, *never*
when effects can't be bounded. This operationalizes GoEX inside our existing snapshot guarantee.

**P‑D. cwd/var‑normalized, context‑relative targets.** Resolve `.`, `$TMPDIR`, `${VAR}`, and relative
paths against cwd + git‑root **before** judging them, and treat `/tmp`,`/var/tmp`,`$TMPDIR` as a
low‑blast‑radius context (borrowing DCG's normalization). Add span‑kind awareness so a dangerous
pattern inside a quoted/comment span isn't treated as executable (we already do some of this via
`all_programs_are_inert_text`; DCG's SpanKind is a more general version). Net effect: fewer
benign‑in‑context commands land in Ambiguous.

**P‑E. (Optional, later) Per‑project "surprise" escalator + tiny advisory scorer.** A one‑class
n‑gram model of the project's own history that can only *escalate* ambiguous→hold for unusual
commands, and — if we want a severity number for the queue UI — a **fastText/char‑n‑gram** local model
(sub‑ms CPU), transfer‑learning idea from arXiv 2412.01655, strictly additive‑caution. This is the
only place a "model" appears, and it can never unlock or downgrade.

### Anti‑patterns to avoid (evidence‑backed)
- **Don't** let any model block or downgrade (F1) — up to 100% evasion, over‑confidence under attack.
- **Don't** build the auto‑allow decision on a denylist (F5, Cursor) — it's routed around by
  aliases/encodings/compounds.
- **Don't** re‑prompt to wear the user down, and **don't** prompt on risk‑free actions (F5, Android/
  UAC) — both train reflexive approval and are net security regressions.
- **Don't** rely on syscall filtering for path‑aware decisions (F7, seccomp can't deref the path).
- **Don't** ship a learned catastrophic detector (F2) — worst recall on the rarest, highest‑stakes class.

### Evaluation note
When we test any of this, measure **detection‑rate at a fixed false‑positive budget** (the security‑ML
standard), not raw accuracy/F1 — the catastrophic class is rare and imbalanced, so accuracy is
misleading. Keep the existing golden corpus as the floor and add: a benign‑in‑context corpus
(temp‑dir ops, read‑only verbs) to measure fatigue reduction, and an adversarial corpus
(wrapper/compound/encoding evasions) to prove the allowlist‑with‑memory can't be ridden.

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
