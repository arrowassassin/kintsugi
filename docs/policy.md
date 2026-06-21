# Policy (`.kintsugi.toml`)

![The timeline reflects policy decisions](img/log.svg)

Kintsugi reads two policy files and merges them, with the repo file overriding the
global one:

1. **Global defaults** — `config.toml` under your config dir
   (`~/.config/kintsugi/config.toml` on Linux). Override the path with
   `KINTSUGI_CONFIG`.
2. **Per-project** — `.kintsugi.toml` at (or above) the working directory, committed
   to the repo.

## Format

```toml
# Optional operating mode for this scope:
#   "attended"   — hold dangerous/ambiguous commands for a one-key decision (default)
#   "unattended" — no human present: catastrophic auto-denies, ambiguous denies
#   "notify"     — record and warn, never block
mode = "attended"

[rules]
# Commands to auto-allow (tames the ambiguous band). A wildcard `*` is supported.
# NOTE: an allow rule never downgrades a rule-detected *catastrophic* command —
# that hard floor always stands.
allow = ["cargo run", "npm run dev"]

# Commands to force to Hold (attended) / Deny (unattended), whatever their class.
deny = ["git push *", "kubectl * --context=prod"]

[provenance]
# The taint-aware "lethal trifecta" guard (untrusted input + a sensitive read + an
# egress sink). On by default; set false to disable the trifecta escalation.
enabled = true
```

## Matching

- A pattern with `*` is a glob (`rm *` matches `rm file.txt`; `*secret*` matches
  any command containing `secret`).
- A pattern without `*` matches the whole command or a **token prefix** of it, so
  `git push` matches `git push --force origin main` but not `git pushing`.
- `deny` takes precedence over `allow`.

## Precedence (how a decision is reached)

1. The Tier-1 rule engine classifies the command (Safe / Catastrophic / Ambiguous).
2. Policy `deny` escalates; policy `allow` tames the ambiguous band (never a
   catastrophic downgrade).
3. Decision memory (`[r]` always-allow / always-deny for this exact command in
   this repo) has the final say.

The model is never in this path — the block decision is always deterministic.

## Provenance (`[provenance]`)

Independently of the class rules, Kintsugi tracks whether an agent session has
ingested **untrusted content** (a web fetch, a search result, an MCP tool result,
a read of a file outside the repo, a `curl`/`wget`/`git clone`). A command in a
tainted session that **reads a secret** and reaches an **egress sink** is the
lethal trifecta and is escalated deterministically — held (attended) or denied
(unattended), never silently allowed. Taint only ever *adds* caution; it can never
downgrade a block. See [`provenance.md`](provenance.md) for the full model and the
`kintsugi provenance` trail view.
