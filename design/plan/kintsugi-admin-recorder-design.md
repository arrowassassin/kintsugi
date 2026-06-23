# Kintsugi — Admin-Locked Settings + Passive Session Recorder (design + market analysis)

> Forward-looking design companion. Folds in a 6-engineer build roundtable (2 infosec,
> 2 DBA, 2 principal system-design) and a ~13-stream market/technology research sweep
> (every external claim below was web-sourced; key URLs inline). Bound by the security
> spine in `CLAUDE.md`. Nothing here ships in one PR — see the phased plan (§8).

## 0. What we're adding & why
1. **Password-locked, encrypted, admin-provisioned settings.** A sysadmin installs
   Kintsugi, sets an admin password, and locks protection so a regular user — or an AI
   agent running as that user — can't trivially weaken it. **Stopping/unhooking/
   disabling Kintsugi itself requires the password** when locked. Secret stored at the
   system level, encrypted.
2. **Passive recording of human shell sessions** (no AI-agent hook) for enterprise
   audit/compliance — aimed at DBAs/ops. Same tamper-evident hash-chained log, same
   rules flagging, same reversible snapshots, same no-secrets guarantee.

---

## 1. Market analysis — is "record + per-command revert + audit" already built?

**Verdict: the *combination* is genuinely unbuilt as a shipping product; every
individual pillar is mature prior art; two AI-agent tools are one feature from
converging; and there is a same-named academic project to deconflict from.**

### 1a. ⚠️ Name + concept collision (decide before any public launch)
- **Academic "AEGIS"** — arXiv 2603.12621 / `github.com/Justin0504/Aegis`: a
  pre-execution firewall + audit layer for AI agents with **SHA-256 hash-chained +
  Ed25519-signed tamper-evident audit**, plain-English risk classification, and
  human-in-the-loop holds. Three of our four pillars, already published. It **lacks
  filesystem snapshot/revert**, and is cloud/SDK-agent focused (monkey-patches LLM
  SDKs / proxies MCP+HTTP), not the raw-local-shell `$PATH`-shim case. This is a real
  trademark/SEO/positioning collision — **rename or differentiate hard.**

### 1b. The closest competitors and exactly what each lacks
- **Claude Code `/rewind` checkpointing** — auto-snapshots files *Claude edits*, restores
  on `/rewind`. Its own docs state verbatim it **"does not track files modified by bash
  commands"** — `rm`/`mv`/`cp` "cannot be undone through rewind." *The exact destructive-
  shell case Kintsugi targets is the documented blind spot of the agent's own undo.* (code.claude.com/docs/en/checkpointing)
- **DiffBack** (`github.com/A386official/diffback`) — "wrap any AI agent command, snapshot
  files before execution, per-file accept/reject." Undo-only: **no danger classification,
  no tamper-evident log.**
- **Nous Research Hermes Agent rollback** — auto-snapshots a project before destructive
  terminal commands (`rm/mv/cp/dd/shred/sed -i/>/git reset`), one-command restore. Single-
  agent/project-scoped, **no classification, no audit chain.**
- **arXiv:2512.12806 (Dec 2025)** — per-command CoW snapshots + safe/unsafe/uncertain
  policy for AI agents. Research prototype: **no tamper-evident log, no human warning, not
  local-first, not shipped.**

### 1c. The wider field (none reverts arbitrary shell commands on the real FS)
- **Session recorders** (auditd, tlog/Cockpit, asciinema, `script`): record, never revert;
  auditd/tlog *leak command-line passwords*.
- **Commercial PAM** (CyberArk, BeyondTrust, StrongDM, ObserveIT, Delinea, Teleport):
  record + alert + **terminate the session** — none reverts FS state; tamper-evident vaults
  validate that *part* of our pitch as sellable. Cost: $100–150K/yr-class.
- **Provenance** (PASS, CamFlow, OPUS, ReproZip): capture the lineage graph, **zero revert.**
- **Snapshot/transactional** (snapper+snap-pac, NixOS/Guix, rpm-ostree, openSUSE
  transactional-update): revert at **package-transaction / whole-system-generation**
  granularity, never per arbitrary command, no warning, no audit chain.
- **Record-replay debuggers** (rr, UndoDB, Pernosco, GDB-reverse, CRIU, docker checkpoint):
  revert **process memory only** — their own docs say filesystem ops are not performed/rolled
  back. VM snapshots revert disk but **whole-machine, all-or-nothing, no command attribution.**
- **Versioning FS** (NILFS2 continuous checkpoints, ext3cow, Wayback): revert by *time*,
  command- and danger-agnostic; NILFS2 is "slow but dependable," ext3cow/Wayback are dead.
- **The reversibility ancestor:** "Undo for Operators" (Brown & Patterson, USENIX ATC 2003) —
  Rewind/Repair/Replay. Whole-timeline, app-specific, post-hoc, no pre-warning, no chain.

### 1d. The defensible wedge
Kintsugi = *"Undo for Operators," generalized to the filesystem, made **per-dangerous-command**,
fused with a **pre-execution plain-English warning**, a **deterministic rules block** (model
only explains), a **tamper-evident hash-chained session log**, **secret redaction**, and
**enterprise/DBA reporting** — local-first, cross-agent, and extended from AI agents to **human**
sessions.* No competitor occupies that seam. Lead with: **"undo for the commands your agent's
own checkpointing documents it can't undo,"** the source-agnostic `$PATH`-shim interception, and
the integrity posture (rules block; model only adds caution; append-only hash chain).

### 1e. The pain is real and recurring (evidence)
GitLab 2017 (`rm -rf` on the primary Postgres dir; 5 backups silently failed), AWS S3 2017
(one mistyped command broke a chunk of the internet — AWS's remediation was literally *"add
safeguards to the tool"*, aws.amazon.com/message/41926), Pixar `rm -rf *` wiped 90% of Toy
Story 2. `UPDATE`/`DELETE` without `WHERE` is ~32% of DBA downtime (postgresql.org/community/survey).

---

## 2. The honest "never reversible" list (do not over-claim — spine #7)
A filesystem snapshot restores **only bytes on the watched filesystem, only where a snapshot
was taken first.** Kintsugi must never claim more:
- **Network egress already sent** — emails (SMTP has no recall; Gmail "Undo Send" only *delays*),
  webhooks/API POSTs, payment charges (Stripe *refunds* = a new compensating action).
- **Anything replicated/pushed/off-machine** — a `DROP TABLE` already replicated to replicas; a
  `git push --force` others pulled; a **leaked secret (rotate, don't revert)**; remote-host actions.
- **In-database mutations** — `UPDATE/DELETE` without `WHERE` lives inside the DB engine; a CoW
  file snapshot won't help mid-transaction. (DB PITR is a separate, harder follow-on.)
- **Below-the-file ops** — `dd`/`shred`, raw devices.
- Frame undo as a **bounded, best-effort filesystem backstop** (a saga "compensating action"),
  exactly as the spine already states: *"nothing is unrecoverable via the filesystem backstop,"
  NOT "nothing runs un-warned."*

---

## 3. Snapshot / revert technical strategy (from the FS research)
The one mechanism available on **all three OSes is file-level reflink/clone**, which Kintsugi
already uses (`reflink-copy`: `FICLONE` on Linux Btrfs/XFS, `clonefile` on APFS, ReFS block
cloning on Windows). Confirmed realities to build around:
- **Use `reflink_or_copy()`**, branch on the return: `Ok(None)` = instant CoW; `Ok(Some(bytes))`
  = full copy fell back (slow + space) → surface/throttle for large files.
- **Same-volume constraint is absolute** (`EXDEV` cross-fs); snapshots must sit on the target's
  filesystem or every snapshot silently becomes a full copy.
- **ext4/NTFS/tmpfs/NFS/default-ZFS → always full-copy fallback** (ZFS block-cloning is *disabled
  by default*; don't assume it).
- **Tiered revert (recommend, later phases):**
  - **Universal:** reflink + copy fallback (today). Keep as the portable default.
  - **Linux fast/strong:** when the tree is on **ZFS** (`zfs snapshot`/`zfs rollback` — the only
    true native rollback verb) or **Btrfs** (subvolume snapshot; live swap for non-root), use
    native snapshots via the CLI/`snapper` DBus (`org.opensuse.Snapper`) for instant, atomic,
    whole-subvolume pre/post pairs and `zfs diff`/`btrfs`-style change attribution.
  - **Root backstop:** **LVM thin** snapshots (whole-volume, root-only, revert via
    `lvconvert --merge`, deferred on root) for hosts on an LVM thin pool.
  - **Linux preview/discard sandbox (optional):** **bubblewrap** `--overlay` (capture+diff) /
    `--tmp-overlay` (discard) to *run a command in a discardable overlay* and commit-or-revert.
    Avoid **firejail** overlays (disabled, CVE-2021-26910). All overlay/LVM/native paths are
    Linux-only → they accelerate, they do not replace the cross-platform reflink+watcher backstop.

---

## 4. Feature 1 — password-locked encrypted settings + "password to stop"

### 4a. Ownership & enforcement (principal-eng consensus)
The **daemon is the sole authority and sole log-writer.** Today `kintsugi stop` just reads a PID
file and `kill`s — zero auth. Privileged ops move **behind IPC** and require an authenticated
session: `stop`, `change-password`, `set-setting`, `unhook`, `disable-recording`, `clear-panic`,
`autostart enable/disable`. The CLI never enforces; it asks the daemon.

### 4b. Storage (layered, headless-first)
Two artifacts, stored separately:
- **Password verifier** — `argon2id(password, salt, tuned-params)`; proves knowledge, never the pw.
- **Config-sealing key** — random 32-byte key, AEAD-encrypting the locked-settings blob
  (XChaCha20-Poly1305 / `age`), wrapped by the OS secret store **or** derived from the password.

Tiers chosen at provision time:
| Tier | macOS | Windows | Linux desktop | Linux headless |
|---|---|---|---|---|
| **A. OS secret store** (preferred) | Keychain | DPAPI / Cred Manager | Secret Service / libsecret / kernel keyring | *usually absent* |
| **B. Root-owned sealed file (`0600`)** | — | — | — | argon2id-derived key, AEAD blob |
Tier B is **first-class, not a hack** — headless/air-gapped servers (a primary enterprise
target) have no D-Bus keyring. Use the `keyring` crate behind a trait so Tier B is a clean path.

### 4c. Auth handshake (challenge–response; password never on the wire)
`AuthBegin` → daemon returns `{nonce, salt, kdf_params}` → CLI computes `k = argon2id(pw,…)`,
`proof = HMAC(k, nonce ‖ op_descriptor)` → `AuthProve{proof, op}` → daemon constant-time
compares, binds proof to the op, issues a short-lived **session token** (sudo-style, ~5 min).
**Rate-limit + lockout** (in-memory, exponential backoff, hard lockout after N fails), and
**every attempt — success or fail — is a hash-chain event** (alertable).

### 4d. "Password to stop" without a trivial `kill` bypass
We cannot stop `kill -9` from the same UID/root — so we make a forced stop **not the easy path,
not silent, not permanent**:
- **Watchdog/supervisor** owns lifecycle: systemd `Restart=always` / launchd `KeepAlive` /
  Windows Service auto-restart → a `kill` triggers relaunch in seconds. To keep it dead the
  attacker must disable the *supervisor* unit (a root/admin op).
- **Detect the gap:** on relaunch the daemon writes `daemon-killed-unexpectedly`; chain/heartbeat
  verification makes an un-logged stop conspicuous.
- **Daemon runs as a dedicated `kintsugi` system user** (locked posture) so the audited user can't
  `kill`/`SIGSTOP` it; the systemd unit is **polkit-gated** against non-wheel users.
- **Optional fail-closed boot state** (opt-in only): if the daemon is down, the shim/hook refuse
  commands until it's back. Default stays fail-open (spine #7 — not a firewall, don't brick people).

### 4e. Honest threat matrix (put in docs verbatim)
| Attacker | Read locked settings | Forge settings | `stop` w/o pw | `kill` daemon |
|---|---|---|---|---|
| **AI agent / script (no pw)** | No (sealed) | No (AEAD tag) | No (IPC auth) | mechanically yes, but watchdog relaunches + logs it |
| **Non-root human** | No | No | No | kill→relaunch+logged |
| **Root / sudoer** | Tier-B needs pw; Tier-A readable | can disable unit | bypasses IPC | **yes, permanently** |
| **Disk thief (offline)** | No (argon2id) | No | n/a | n/a |
> One honest sentence: *"Locked settings stop an AI agent or a normal user from weakening Kintsugi,
> and turn any forced shutdown into a logged, alerting, recoverable event. They do not stop root —
> root can disable any same-machine tool, and Kintsugi is designed to make that visible, not impossible."*

### 4f. Settings & lock tiers
- **Locked (need pw to change):** recording on/off, autostart on/off, stop/uninstall/unhook,
  enforcement mode (attended/unattended/fail-closed), policy/rule-set selection, panic clear,
  retention. **Spine #1/#2: a locked setting may only *tighten* — it can NEVER set "allow rm -rf /."**
- **Free (user-changeable):** TUI theme, `NO_COLOR`, local report formatting, model on/off *on
  their own user-level install*.
- **Recovery:** one-time recovery key at provision (FileVault/BitLocker pattern); lost pw + lost
  key → privileged local teardown only (no Kintsugi-held escrow — spine #5). Secret store unavailable
  at runtime → loud **DEGRADED** state that **keeps the lock** (refuses privileged ops), never
  silently drops to UNLOCKED.

### 4g. Auto-start (cross-platform, from PE #2)
User-level by default (launchd LaunchAgent / `systemctl --user` + `loginctl enable-linger` via an
explicit `--persist` / Windows Task Scheduler); **system-level only in admin-locked posture**
(LaunchDaemon / system unit with a dedicated least-priv account / Windows Service). `autostart
enable|disable` is a daemon-gated, logged op that then installs/removes the unit idempotently
(atomic write, fenced/managed block). Honest: the user-level posture is convenience; the lock is
real only in the system posture.

---

## 5. Feature 2 — passive shell-session recording

### 5a. Capture (dual path; reuse the single-writer log)
- **Primary:** an rc-file **preexec hook** — zsh native `add-zsh-hook preexec`, bash via a
  *vendored, checksum-pinned* `bash-preexec` (spine #5 forbids `curl|source`); `precmd`/`$?` for
  exit codes. **Fire-and-forget**: backgrounds a one-shot `kintsugi ingest` → daemon. Captures
  command (verbatim), cwd, exit code, user, tty, host. Managed **fenced block** in rc files for
  idempotent install/upgrade/removal; append last.
- **Complementary:** the existing **`$PATH` shim** (catches shell-outs / `base64|sh` execs the
  hook can't see — Teleport's lesson that string-capture is defeated by obfuscation). Dedup by
  session+timestamp in reports.
- **Higher-assurance:** **`kintsugi record`** — a PTY-wrapping logged shell (like `script`/tlog) for
  an explicit, auditable session that survives inner-hook tampering (session framing).
- **All are *sources*; the daemon is the sole writer** → new `Request::Record(ShellRecord)` reusing
  the existing single-writer `Observe` path; additive event columns `source/host/tty/exit_code`
  with a **versioned canonical hash** (extend, never reorder — or every prior hash breaks; dedicated
  cross-version verification test). Windows recorder (PowerShell `PSReadLine AddToHistoryHandler`)
  is **v1.x**, not v1.

### 5b. Separation of duties (DBA hard requirement)
A user-sourced rc hook *fails* "the audited user can't disable it" (they own the file). So the
DBA-credible posture is: system-wide hook in `/etc/profile.d` + `/etc/bash.bashrc` pushed by config
management, the daemon as a non-user system account, **and the honest doc that a userspace recorder
is evadable** (`bash --norc`, fresh tty, absolute-path exec). Off-box shipping (roadmap E1) makes
*gaps* detectable; auditd `-e 2`/eBPF is the root-backed floor Kintsugi **integrates with, not
reimplements** (no kernel code — CLAUDE.md).

### 5c. Secret redaction = LAUNCH BLOCKER (both DBA + infosec said so)
auditd writes DB passwords to the audit log; tlog disables input logging *because of it*. Kintsugi
must **redact the secret span before the line is hashed** (the chain is immutable — you can't fix
it later), keeping the rest verbatim (resolve spine #3 vs #6 by value-span redaction + a `‹redacted›`
marker so the log is honest a secret was present). Redact at the **source** (in the hook/shim,
before IPC):
- DB URIs `scheme://user:****@host`; `mysql -p****` / `--password=****`; `redis-cli -a ****`;
  inline `PGPASSWORD=****` / `MYSQL_PWD=****` / `AWS_SECRET_ACCESS_KEY=****`; `--token=`/`--api-key`/
  `Authorization: Bearer ****`; `curl -u user:pass` / `https://user:pass@…`.
- **Conservative + visible:** over-redact rather than leak; always leave the marker (audit value).
  *"Our audit log can't itself become the breach"* is a genuine differentiator over auditd/tlog.

### 5d. Reports & compliance (the deal-closer)
The killer row no incumbent produces: **a *dangerous* command ran — who, when, where, exit, the
verdict, and whether it was reversible/undone.**
- `kintsugi report --since <range> --destructive --by-user --format json|csv`
- `kintsugi log --danger --since 24h` · `kintsugi whoran <pattern>` · `kintsugi verify` (chain
  intact/broken/gapped) · `kintsugi undo coverage`. **All offline/local-first** (DB hosts are segmented).
- Attribution keyed on **`auid`/loginuid** through `sudo`/`su` ("jdoe via `sudo -u postgres` ran
  DROP TABLE", not "postgres did it"). Commands *inside* `psql` (`\! rm`) are invisible to a shell
  recorder — say so; complement pgAudit, don't claim to replace it.
- **Compliance table** (ship in docs — auditors live by it): PCI-DSS 10.2.1.1/10.2.1.2 (log access +
  admin actions), 10.5.1 (≥12-mo retention, 3-mo hot), 10.3.x (protect logs) → hash chain; SOC 2
  CC7.2/7.3 (detect/respond) + CC8.1 (change mgmt); HIPAA §164.312(b); SOX ITGC change.

### 5e. Operational hard-lines (DBA/SRE)
- **Fail-open for availability, never fail-halt** — the *opposite* of auditd's `disk_full_action=halt`.
  If the log fills or the daemon dies: stop recording, alert, write a signed **gap-marker** to the
  chain; **never stall the shell or halt a DB host.**
- **Non-blocking, lossy-but-chained:** daemon-down → spool to `~/.kintsugi/spool/`, daemon folds it
  into the chain on restart (a buffer, never a 2nd writer); if even the spool fails, a gap-marker.
- **Overhead budget:** <2 ms added at the prompt (p99 <10 ms), zero added DB-query latency, model
  **off by default on DB hosts**, async+batched WAL writes. Chain must **survive log rotation**
  (seal a segment, chain the next segment's genesis to the prior final hash).

---

## 6. Security-spine compliance (review gate)
1. Monotonic floor: admin/locked settings plug in **above** local policy like the roadmap's E0
   org-policy and can only tighten — the existing `adjust_for_policy` hard floor must cover them.
   *No password can set "allow catastrophic."*
2. Verbatim vs no-secrets: value-span redaction at source (§5c), never drop the command.
3. Append-only chain: additive versioned columns; cross-version verification test.
4. No egress by default; off-box shipping is opt-in (roadmap E1).
5. Honest framing everywhere — the §4e matrix and §2 list are mandatory copy. No "firewall."

---

## 7. New dependencies (justify; spine/allowlist)
`argon2`, `chacha20poly1305` (RustCrypto — audited, permissive), optional `keyring` (Tier A).
All dev/runtime-justified by "password, encrypted, system-level." Vendored pinned `bash-preexec`
(checksummed, not downloaded). Record in `DECISIONS.md`.

---

## 8. Phased implementation plan (small reviewable PRs)
- **P-A0 (this PR): foundation + redaction.** Command-line **secret redaction** module in
  `kintsugi-core` (launch-blocker, self-contained, reused by recorder + improves today's log) +
  this design doc. Fully unit-tested.
- **P-A1: locked-settings core.** `kintsugi-core::admin` — argon2id verifier + AEAD-sealed settings,
  Tier-B sealed-file storage, recovery key, monotonic-lock model + property test. Unit-tested, no
  IPC yet.
- **P-A2: daemon auth + password-to-stop.** `AuthBegin/Prove`, session token, rate-limit/lockout,
  privileged ops behind IPC, authenticated `kintsugi stop`, watchdog + `daemon-killed` event.
- **P-A3: recorder.** `Request::Record` + additive versioned columns; `kintsugi ingest`; rc preexec
  hook installer (fenced block, bash/zsh); spool + gap-markers; DBA reports.
- **P-A4: autostart + service install** (Linux systemd + macOS launchd first; Windows later).
- **P-A5: native snapshot tier** (ZFS/Btrfs/snapper integration) + bubblewrap preview (Linux).
- **Later/enterprise:** auditd/eBPF ingestion, off-box relay (roadmap E1/E2), Windows recorder,
  `kintsugi record` PTY.

---

## 9. Open decisions for the human
1. **Rename / deconflict** from the academic "AEGIS" (arXiv 2603.12621) before any public launch?
2. Paywall stance for the locked-settings + audit (the design doc's "no paywall planned" line vs
   the enterprise roadmap's paid control plane).
3. Default posture on DB hosts: fail-open (recommended) confirmed as default, fail-closed opt-in.
