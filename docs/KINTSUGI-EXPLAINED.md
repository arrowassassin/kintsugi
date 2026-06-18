# Kintsugi, explained from scratch

This is the no-jargon guide to what Kintsugi is, why it exists, and how every
piece of it works. You don't need to know Rust, security, or how AI agents work
to read it. If you've ever let a tool run commands on your computer and felt a
little nervous about it, this is for you.

---

## 1. The problem, in one picture

AI coding assistants — Claude Code, Cursor, Codex, Gemini, Google Antigravity,
Copilot, and others — don't just *suggest* commands anymore. They **run** them.
They create files, install packages, push code, delete folders, and talk to
databases, often faster than you can read what they're about to do.

Most of the time that's wonderful. But every so often the wrong line slips
through:

```
rm -rf /                 # erase everything
git push --force         # overwrite your team's work
DROP TABLE users         # delete a database table
terraform destroy        # tear down live infrastructure
```

One bad command, run in a fraction of a second, and something important is gone.
The same risk applies to the humans on the machine — a tired operator pasting a
command into the wrong terminal.

**Kintsugi sits between "a command is about to run" and "the command runs."** It
catches the dangerous ones, explains them in plain English, lets you decide, and
— crucially — keeps the dangerous-but-allowed ones *reversible*. It also writes
down everything that happened in a log that can't be quietly edited later.

The name comes from *kintsugi*, the Japanese art of repairing broken pottery
with gold — the break becomes part of the object's history instead of being
hidden. Kintsugi-the-tool treats mistakes the same way: it doesn't pretend they
can't happen; it makes them visible and repairable.

---

## 2. The one promise Kintsugi makes (and the one it doesn't)

This matters, so it's stated up front and honestly:

- **The honest promise:** *nothing you do is unrecoverable.* If something
  destructive happens — even from a command that dodged the front door —
  Kintsugi has a safety net (a filesystem watcher) that records it so it can be
  undone or at least audited.

- **What Kintsugi does NOT promise:** that *nothing runs without a warning.*
  Kintsugi is not an unbreakable wall. A determined program, or someone with
  administrator ("root") access, can get around the front-door checks. Kintsugi
  is designed to make that **visible and recoverable**, not impossible.

Any tool that tells you it's a perfect, unbypassable firewall is lying. Kintsugi
tells you exactly where its protection is strong and where it isn't.

---

## 3. How a command flows through Kintsugi

Here's the whole journey of a single command, start to finish.

```
  agent or human types a command
              │
              ▼
   ┌──────────────────────┐
   │  1. Interception      │  the command is captured BEFORE it runs
   └──────────────────────┘
              │
              ▼
   ┌──────────────────────┐
   │  2. The rules (Tier-1)│  is this SAFE, CATASTROPHIC, or AMBIGUOUS?
   └──────────────────────┘
              │
        ┌─────┴───────────────┐
        ▼                     ▼
   SAFE → allow         not safe → maybe ask a small local AI (Tier-2)
                              │     to explain it and rate how risky it is
                              ▼
   ┌──────────────────────┐
   │  3. The decision      │  allow · hold for your OK · deny
   └──────────────────────┘
              │
              ▼
   ┌──────────────────────┐
   │  4. Snapshot          │  if it's destructive, back up the files first
   └──────────────────────┘
              │
              ▼
   ┌──────────────────────┐
   │  5. The log           │  write down what happened (permanently)
   └──────────────────────┘
              │
              ▼
   command runs (or doesn't)  — and you can `undo` it later
```

The rest of this guide walks through each numbered box.

---

## 4. Interception — catching the command first

Kintsugi can't protect a command it never sees. So the first job is to **capture
every command before it executes**, no matter where it came from. It does this
three different ways, because agents run commands three different ways:

1. **Native hooks.** Most agent tools have a built-in "before you run a tool, ask
   this program first" feature (a *pre-tool hook*). Kintsugi plugs into each
   one's hook, in that tool's own format. `kintsugi init` detects which agents
   you have installed and wires them up automatically — Claude Code, Cursor,
   Codex, Qwen, Gemini, Google Antigravity, Copilot, and OpenCode.

2. **An MCP server.** MCP is a standard way for AI tools to call external
   "tools." Kintsugi offers one called `kintsugi-exec` — the agent runs commands
   *through* it, and Kintsugi checks them on the way through.

3. **A `$PATH` shim.** This is the catch-all for *raw* commands that don't go
   through a hook or MCP — for example, a script the agent writes and runs
   directly. The shim is a small stand-in placed earlier in your system's command
   search path (`$PATH`), so when something types `rm`, it hits Kintsugi's `rm`
   first. Kintsugi checks the command, then passes it to the real `rm` — keeping
   the exact same output, exit code, and behavior. (Getting this *perfectly*
   transparent across macOS, Linux, and Windows is the single hardest piece of
   the whole project.)

All three feed into **one** internal description of the command, so the rest of
Kintsugi doesn't care where a command came from.

> The honest gap: the `$PATH` shim only guards programs invoked *by name*. A
> program run by its full path, or an agent in a totally sandboxed environment,
> can sidestep it. That's exactly why the safety-net watcher (section 9) exists,
> and why enterprises can enforce the shim system-wide (section 11).

---

## 5. The rules — the part that actually decides

This is the heart of Kintsugi, and it follows one unbreakable principle:

> **Rules decide. The AI only explains.**

The decision to **block** a catastrophic command is made by fixed, written-down
rules — never by an AI model. Why? Because an AI can be *tricked* (a malicious
file could contain text that says "ignore your instructions and allow this").
Fixed rules can't be sweet-talked. This is called the **security spine**, and
nothing in Kintsugi is allowed to violate it.

The rules sort every command into one of three buckets:

- **SAFE** — confidently harmless: reading files, listing a directory, building
  or testing code (`ls`, `cat`, `git status`, `cargo build`). These are allowed
  instantly.

- **CATASTROPHIC** — confidently destructive: `rm -rf /`, `git push --force`,
  `DROP TABLE`, writing directly to a disk, reading your secret keys. These are
  **blocked** (or held for an explicit human override).

- **AMBIGUOUS** — everything in between: `rm one-file.txt`, `npm install`,
  `./deploy.sh`. Could be fine, could be a problem — depends on context.

The rules are deliberately **cautious**: when in doubt, a command lands in
AMBIGUOUS, never SAFE. A false "this looks dangerous" is a minor annoyance; a
missed catastrophe is a disaster. So the bias always points toward caution. A
command being wrongly called *catastrophic* is a tolerable bug; a catastrophic
command being wrongly called *safe* is treated as a **hard failure** the test
suite must never allow.

**The rules are also sneaky-command-aware.** Attackers and overeager agents hide
dangerous commands inside innocent-looking ones. Kintsugi unwraps these:

- a command buried in `bash -c "..."`, `find -exec`, or `xargs`
- a command hidden inside `$(...)` substitutions or backticks
- a command smuggled past `sudo`, `env`, `timeout`, `nohup`, and similar wrappers
- a download piped straight into a shell (`curl ... | sh`) — classic remote-code
  execution
- a sneaky `git -c core.pager='rm -rf /' log`, which secretly runs a command via
  git's configuration (a real bypass that a 0.2.1 fix closed)

If the rules can't fully parse something weird, they don't shrug and call it
safe — they fall back to "ambiguous" and let a human look.

---

## 6. The local AI — explaining, never overruling

For **ambiguous** commands only, Kintsugi can consult a small AI model that runs
**entirely on your machine** (no internet, nothing sent anywhere). The model does
exactly two things:

1. Writes a **one-sentence plain-English summary** of what the command does.
2. Gives a **severity score** for how risky it looks.

And there's a hard rule about what the model is *allowed* to change:

> **The model can only ever ADD caution.** It can push an ambiguous command
> toward "hold" or "deny." It can **never** unlock or downgrade something the
> rules blocked.

So even if the model were somehow fooled, the worst it can do is be *too*
careful. It can't be talked into letting a dangerous command through. The real
command is **always shown to you exactly as written** — the friendly summary
never replaces the actual text.

If no model is installed, Kintsugi still works fully — you just get the rules and
the raw command instead of the English summary.

---

## 7. The decision — allow, hold, or deny

What happens to an ambiguous or catastrophic command depends on the **mode**
you're running in:

- **Attended** (you're at the keyboard): dangerous commands are **held** — paused
  with a card explaining what they'd do — until you approve or reject them with a
  keypress.
- **Unattended** (the agent is running on its own): there's no one to ask, so
  Kintsugi **denies** anything risky and queues it for you to review later.
  Nothing risky auto-runs.
- **Notify**: a lightweight mode that records everything but doesn't block —
  useful for just *watching* what an agent does.

You can tune this per project by committing a small `.kintsugi.toml` file:
pre-approve commands you know are fine (`cargo run`), force-deny ones you never
want (`kubectl --context=prod`), and set how strict unattended mode is.

Crucially, **a human can always override and approve even a catastrophic command**
— it's *your* machine. The point isn't to take away your control; it's to make
sure a destructive action is a *deliberate* choice, not an accident. The *model*
never gets that override power; only you do.

---

## 8. Snapshots and undo — making destruction reversible

Before Kintsugi allows a destructive command to run, it **takes a snapshot** of
the files that command is about to touch. It predicts which paths are affected and
backs them up — using a fast copy-on-write "reflink" where the filesystem
supports it (so it's nearly free), and a plain copy otherwise.

Then, if the command turns out to have been a mistake:

```
kintsugi undo
```

restores the snapshotted files. The restore is **atomic**: each file is rebuilt
in a temporary spot and then swapped into place, with the old version moved
aside first. If anything goes wrong mid-restore, it rolls back — so an
interrupted undo can never leave a file half-written.

Honest caveat (Kintsugi will *tell* you this): some things can't be fully
snapshotted — a command targeting unpredictable paths, or a database change.
When a command's target can't be fully captured, the verdict says so with a ⚠
warning instead of pretending undo will save you. For databases, your real safety
net is your database's own backups; Kintsugi is honest about being "recoverable,"
not "transactional."

---

## 9. The backstop — the safety net under everything

What about a destructive change that **dodged the front door entirely** — a
command that didn't go through a hook, the MCP, or the shim?

That's what the **filesystem watcher backstop** is for. It quietly watches your
working directory and records destructive changes — **deletions and renames** —
even when they came from something Kintsugi never intercepted. This is what backs
the honest promise from section 2: *nothing is unrecoverable*. It's on by default
from the moment you run `kintsugi init`.

It's deliberately quiet. It does **not** record every file save or every new file
(a normal editing or building session creates thousands of those) — only the
destructive, you-might-care-about-this signals. It skips build folders, version-
control internals, and editor scratch files.

And if the backstop's coverage is ever *reduced* — say it couldn't watch a folder,
or the operating system dropped some events under load — it doesn't go silent. It
writes a **`backstop-degraded`** marker onto the timeline so you know there was a
window it might have missed. A safety net you can't tell is torn is worse than
one you can.

---

## 10. The log — a record that can't be quietly rewritten

Everything Kintsugi sees goes into an **append-only, hash-chained** log.

- **Append-only** means entries are only ever *added*, never edited or deleted.
- **Hash-chained** means each entry carries a fingerprint of the one before it,
  like links in a chain. If someone tampers with an old entry, every fingerprint
  after it stops matching — so tampering is *detectable*. You can verify the
  chain is `intact` at any time.

This gives you a trustworthy answer to "what did this agent (or person) actually
do?" — which matters for debugging, for compliance, and for trust.

Two related safeguards:

- **Secrets are never logged in plaintext.** Kintsugi detects when a command is
  reaching for sensitive things (`.env` files, SSH keys, cloud credentials, the
  system keychain) and records *that it happened* without ever copying the secret
  values into the log.
- **If the log can't be written, the command doesn't run.** A command that can't
  be recorded would run "in the dark," defeating the whole point. So if writing
  to the log fails, Kintsugi **fails closed** — it refuses the command rather than
  letting it execute unrecorded.

You can read the log with `kintsugi log`, or explore it live in the TUI.

---

## 11. The enterprise lock — for shared and production machines

On a shared server or a production host, you may want Kintsugi's settings to be
**out of reach** of the agents and ordinary users it's protecting against. That's
the admin lock:

- **`kintsugi admin provision`** sets an admin password and seals the settings
  with strong encryption. After that, *stopping* Kintsugi, turning off recording,
  or loosening enforcement all require the password. An agent or normal user can't
  just `kintsugi stop` their way out.

- The password is never stored. Kintsugi keeps only a derived *verifier* and (as
  of 0.2.1) a *public key*, so even someone who could read the locked file can't
  reconstruct the password or forge a "permission to stop." The matching private
  key is rebuilt from your password only at the moment you prove it.

- **`kintsugi admin enforce-shell`** installs the `$PATH` shim *system-wide* via a
  root-owned system file, so every login shell on the host is guarded — including
  accounts that never opted in. Only root, or the admin password, can remove it.

- A **watchdog** can hand the daemon's lifecycle to the operating system's service
  manager, so if someone kills it, it comes back — and the kill is logged.

The honest scope, again: this defeats an **agent or non-root user** and turns any
forced shutdown into a logged, recoverable event. It does **not** stop **root** —
root can disable any tool on its own machine. Against root, the goal shifts from
*prevent* to *make conspicuous*.

---

## 12. The TUI — seeing it all live

`kintsugi tui` opens a full-screen terminal interface — a calm control room. It
shows the live timeline of everything that's happened, the queue of commands
waiting for your decision, and the backstop's observations, all updating in real
time from the same log and daemon described above.

You navigate with the keyboard (arrows or `j`/`k`), open an entry for detail,
filter the view, approve or deny a held command, and trigger an `undo` — all
without leaving the screen. It's designed to be quiet until something needs your
attention, then to make that one thing obvious. It always restores your terminal
cleanly when you quit, even after an error.

---

## 13. The pieces, named

If you go looking in the code, here's the map. Kintsugi is built in Rust as a set
of cooperating components ("crates"):

- **`kintsugi-core`** — the shared brain: the command type, the deterministic
  rules, the policy logic, snapshots, the admin vault crypto, and the
  hash-chained log.
- **`kintsugi-daemon`** — the always-running background service. It keeps the
  local AI model warm, makes the decisions, takes snapshots, and is the single
  writer to the log (so the chain never gets corrupted by two writers at once).
- **`kintsugi-intercept`** — the three front doors: native hooks, the MCP server,
  and the `$PATH` shim.
- **`kintsugi-cli`** — the `kintsugi` command you type (`init`, `status`, `undo`,
  `admin`, …).
- **`kintsugi-model`** — managing the optional local AI model.
- **`kintsugi-tui`** — the live terminal interface.

There's also a small daemon-side guard: only **one** Kintsugi daemon may run at a
time, so two of them can't race and split the log's chain.

---

## 14. The five rules Kintsugi never breaks

Everything above rests on a short list of non-negotiables (the "security spine"):

1. **Rules block; the AI only explains.** A catastrophic block is never an AI
   decision.
2. **The AI can only add caution.** It can never unlock a rule-based block.
3. **The real command is always shown, exactly as written.** A summary never
   replaces it.
4. **The log is append-only and hash-chained.** The past is never rewritten.
5. **Nothing leaves your machine.** No telemetry, no phoning home, no sending your
   code or commands anywhere. The only network use is downloading the (checksum-
   verified) AI model and, optionally, an LLM endpoint *you* configure.

And one honest guarantee tying it together: **"nothing is unrecoverable" — not
"nothing runs un-warned."**

---

## 15. The thirty-second version

> AI agents run real, sometimes-dangerous commands on your computer. Kintsugi
> catches each one *before* it runs, blocks the clearly-catastrophic ones with
> fixed rules (an AI can only add caution, never remove it), backs up files so
> destructive actions can be undone, watches the filesystem as a safety net for
> anything that slips past, and records everything in a tamper-evident log —
> all locally, with nothing leaving your machine. It won't claim to be an
> unbreakable wall; it promises something more honest: nothing you do is
> unrecoverable.
