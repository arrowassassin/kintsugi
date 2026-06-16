# Snapshot & Undo Techniques — Design and Research Note

**Status:** research note (informational), not a spec change.
**Audience:** Kintsugi maintainers working on the snapshot/undo path and the planned *recoverer*.
**Scope:** low-level snapshot mechanisms, undo/recovery models, command-level undo, and the
preexec timing window — synthesized into concrete recommendations.

**Web sources:** reachable in this environment. Primary mechanism claims are cited to
authoritative pages (man7, kernel.org, btrfs.readthedocs.io, LWN, Berkeley ROC papers, VLDB/ACM).
A few synthesis claims drawn from general systems knowledge are marked
"(from training knowledge — verify before publishing)".

---

## 0. Where Kintsugi already is (grounding)

`crates/kintsugi-core/src/snapshot.rs` already implements the core of the "snapshot before a
destructive action, one-command undo" promise:

- **`predict_paths`** — a dependency-free, shell-segment-aware predictor. It splits the raw line
  on `;`, `&&`, `||`, `|`, and newlines (outside quotes), tokenizes each segment, tracks a leading
  `cd` to update the effective cwd, and collects non-flag args plus redirect targets. Bogus
  candidates are harmless because only existing paths are captured.
- **`is_fully_reversible`** — an honesty gate. It returns `false` for *unbounded* targets: globs
  (`* ? [`), shell expansions (`$`, backtick, `~`), the filesystem root, top-level paths, and
  device nodes (`/dev/...`). For those, `kintsugi undo` is not promised and the filesystem-watcher
  backstop is the real net.
- **`capture` / `restore`** — write a content/path manifest (`Manifest { id, command, entries }`)
  under `store_root/<uuid>/`, copying each predicted-and-existing path. Restore clears the current
  target and copies the stored version back. Handles both overwrite and delete recovery.
- **`copy_file`** uses `reflink_copy::reflink_or_copy` — **reflink-first, plain-copy fallback** —
  exactly the CoW strategy this note recommends doubling down on.

The two design questions this note exists to answer:

1. Can we make `capture` cheaper and more atomic by leaning harder on filesystem-native CoW and
   snapshots, without breaking the cross-filesystem fallback?
2. How do we extend the same engine to a **recoverer** that guards *human* mistakes via a shell
   preexec hook, without hanging the user's shell or losing the race against the command?

There is no `undo.rs` in `crates/kintsugi-core/src/` today (the module list is `shell`, `snapshot`,
`types`, `memory`, `rules`, `parse`, `policy`, `lib`, `log`, `redact`, `admin`); restore logic
lives in `snapshot::restore`.

---

## 1. Copy-on-write & reflinks — the cheap-capture substrate

The single most important performance lever for "snapshot before destructive action" is to avoid
copying bytes. CoW lets a snapshot share the original data extents until one side is written, so
capture is near-instant and near-free on disk until the guarded command actually mutates data.

### 1.1 Linux reflinks: `FICLONE` / `FICLONERANGE` and `copy_file_range`

- **`FICLONE` / `FICLONERANGE` ioctls** make a destination file (or byte range) share the
  source's physical extents via reflink — "faster than making a separate physical copy of the
  data." Supported on **btrfs, XFS, and OCFS2**. Clones are **atomic with respect to concurrent
  writes**, so no lock is needed to obtain a consistent cloned copy. XFS and btrfs do **not**
  support overlapping reflink ranges within the same file.
  Source: <https://www.man7.org/linux/man-pages/man2/ioctl_ficlonerange.2.html>,
  <https://btrfs.readthedocs.io/en/latest/Reflink.html>.
- **`copy_file_range(2)`** is the next-best fallback: it lets the kernel copy between two file
  descriptors without bouncing data through userspace, and on reflink-capable filesystems the
  kernel may satisfy it by sharing extents. Historically it returned `-EXDEV` across different
  filesystems; kernel changes around 5.3–5.12 relaxed cross-fs behavior, which introduced its own
  caveats (e.g. zero-byte returns for some file types), so a robust caller must check the returned
  count and fall back. Source: <https://lkml.iu.edu/hypermail/linux/kernel/2107.0/00910.html>,
  <https://lkml.iu.edu/hypermail/linux/kernel/2103.0/07196.html>.
- **The hard constraint:** reflink requires **both files on the same filesystem**. "Cross-filesystem
  reflink is not possible — there's nothing in common between [them] so the block sharing can't
  work." Source: <https://btrfs.readthedocs.io/en/latest/Reflink.html>. This directly shapes where
  Kintsugi puts its snapshot store (see §1.6).
- **`cp --reflink=auto`** is the userspace expression of reflink-first/copy-fallback; `--reflink=always`
  fails with `EINVAL`/`EOPNOTSUPP` when the fs can't clone. The common cause of
  `cp --reflink: failed to clone: Invalid argument` is that source and dest are on filesystems or
  mounts that can't share extents. Source: <https://www.ctrl.blog/entry/cp-reflink-einval.html>.

The `reflink_copy` crate Kintsugi already uses wraps exactly this ladder
(`FICLONE` → fall back to copy), and on macOS/Windows maps to `clonefile`/ReFS block cloning.
(from training knowledge — verify before publishing: that `reflink_copy` uses `clonefile` on APFS
and `FSCTL_DUPLICATE_EXTENTS_TO_FILE` on ReFS.)

### 1.2 Filesystem-level snapshots (whole-subvolume/dataset)

When the whole working tree lives on a CoW filesystem, a **subvolume/dataset snapshot** is even
cheaper than per-file reflinks and is atomic for the entire tree at an instant:

- **btrfs**: `btrfs subvolume snapshot` — instantaneous, writable or read-only, shares extents.
- **ZFS**: `zfs snapshot pool/ds@name` — atomic, O(1), read-only; `zfs clone`/`zfs rollback` for
  recovery. ZFS gained `copy_file_range`/block-clone support later than btrfs/XFS.
  Source: <https://github.com/openzfs/zfs/discussions/4237>. (from training knowledge — verify:
  ZFS rollback discards snapshots newer than the target, which is destructive in its own right.)
- **APFS** (macOS): `fs_snapshot`/`tmutil localsnapshot` — atomic volume snapshots underpinning
  Time Machine local snapshots. (from training knowledge — verify before publishing.)

These give a true point-in-time tree, but they are **filesystem-global / subvolume-global**, not
"just the paths this command touches," and they require privilege and the right fs. They are best
viewed as an *optional accelerator/backstop* rather than the default path for a per-command tool.

### 1.3 NILFS2 — continuous snapshotting

**NILFS2** is a log-structured CoW filesystem that takes **a checkpoint every few seconds (or per
synchronous write)** automatically; users promote significant checkpoints to retained snapshots,
each mountable read-only concurrently with the live mount. It "enables users to restore files and
namespaces mistakenly overwritten or destroyed just a few seconds ago" and ships an **online
garbage collector** that reclaims space in the background while keeping snapshots.
Source: <https://lwn.net/Articles/294782/>, <https://docs.kernel.org/filesystems/nilfs2.html>,
<https://wiki.archlinux.org/title/NILFS2>.

NILFS2 is the closest existing system to "an always-on recoverer": it makes the *backstop*
continuous rather than per-command. Kintsugi cannot assume users run it, but its model — cheap
continuous checkpoints + background GC + promote-to-keep — is a strong template for the watcher
backstop's retention design (§4, §5).

### 1.4 overlayfs — copy-up as accidental versioning

**overlayfs** unions a read-only `lowerdir` with a writable `upperdir`. On first write to a lower
file it performs **copy-up** into the upper layer, leaving the lower copy pristine. This is the
mechanism behind container layers. It is not a general snapshot tool, but it demonstrates a
*sandbox* technique: run a risky command with the real tree as `lowerdir` and discard or commit the
`upperdir`. (from training knowledge — verify before publishing: overlayfs has surprising semantics
for hardlinks, rename, and metadata-only copy-up; not a drop-in for arbitrary host trees.)

### 1.5 Atomicity, cross-filesystem limits, cost — summary table

| Mechanism | Granularity | Atomic? | Same-fs only? | Capture cost | Privilege |
|---|---|---|---|---|---|
| `FICLONE` reflink | per file/range | yes (vs concurrent writes) | yes | ~free until write | none |
| `copy_file_range` | per file/range | no (may partial) | mostly (post-5.x cross-fs caveats) | low | none |
| btrfs/ZFS snapshot | subvolume/dataset | yes | n/a (in-fs) | O(1) | usually yes |
| APFS snapshot | volume | yes | in-fs | O(1) | yes |
| NILFS2 checkpoint | whole fs, continuous | yes | in-fs | amortized, automatic | mount-time |
| overlayfs copy-up | per file on write | per-file | n/a | deferred to write | mount/CAP |
| plain copy (fallback) | per file/tree | no | works anywhere | full byte copy | none |

### 1.6 Implication for the store location

Because reflink is **same-filesystem only**, the snapshot store must live on the *same filesystem
as the captured paths* to get CoW; a store on a different mount silently degrades every capture to
a full byte copy. Recommendation: derive the store root per-filesystem (e.g. a `.kintsugi/snapshots`
near the target's mount, or a per-mount store keyed by `st_dev`), not a single global directory on
`$HOME` that may be a different device than `/work`. Today's `store_root` is a single path; making
it device-aware is the highest-leverage perf change for capture.

---

## 2. Undo models from the literature

### 2.1 Write-ahead / undo logging and ARIES

The database world's canonical answer to "make destructive operations reversible" is **write-ahead
logging (WAL)**: any change is recorded in a log on stable storage *before* the change is applied
to the object. **ARIES** (Mohan et al., ACM TODS 1992) is the recovery method built on WAL,
supporting fine-granularity locking and **partial rollbacks** via the log; it underpins Db2 and SQL
Server. Recovery is **Analysis → Redo → Undo**: replay to reconstruct state, then undo
still-active transactions. Source: <https://dl.acm.org/doi/10.1145/128765.128770>,
<https://web.stanford.edu/class/cs345d-01/rl/aries.pdf>,
<https://en.wikipedia.org/wiki/Algorithms_for_Recovery_and_Isolation_Exploiting_Semantics>.

**Relevance to Kintsugi:** Kintsugi's manifest *is* a tiny, file-granular undo log — "before image"
of each touched path, written before the command runs. ARIES tells us two useful things:
- **Log-before-apply ordering is the correctness invariant.** The snapshot (before-image) must be
  durably written *before* the guarded command is permitted to run. For the recoverer's bounded
  synchronous path (§4), "durable" should mean at least the manifest is fsynced and the reflinks
  exist; otherwise undo is a lie under a crash.
- **Idempotent, ordered redo/undo.** `restore` should be safe to re-run (idempotent) and apply
  entries in a defined order, matching the CLAUDE.md "append-only, hash-chained log, never mutate
  past events" spine — the snapshot manifest can hang off the same event log.

### 2.2 Versioning file systems

These automatically retain prior versions, turning "undo" into "open an older version":

- **Elephant** (Santry et al., SOSP '99) — "the file system that never forgets": keeps version
  history and applies *retention policies* to decide which versions to keep, recognizing that you
  cannot keep everything forever. (from training knowledge — verify before publishing.)
- **CVFS / Self-Securing Storage** (Strunk, Goodson et al., CMU PDL, OSDI 2000) — the storage
  device itself versions every write and audit-logs requests, so that even after an intruder/admin
  compromise, *prior* data and history survive for a guaranteed detection window. The
  Comprehensive Versioning File System (CVFS) makes per-write versioning space-efficient via
  journal-based metadata and multiversion b-trees. (from training knowledge — verify before
  publishing.) This is the closest prior art to Kintsugi's *tamper-evident* angle: versioning +
  append-only history as a security property, not just convenience.
- **ext3cow** (Peterson & Burns) — adds copy-on-write snapshots and a time-travel interface
  (`file@timestamp`) to ext3, so any past point-in-time is openable. (from training knowledge —
  verify before publishing.)
- **Wayback** (Cornell, USENIX '04) — a user-level *comprehensive versioning* filesystem via FUSE
  that logs an undo record on every write, giving per-write rollback without kernel changes.
  (from training knowledge — verify before publishing.)

**Relevance:** versioning FSes show the design axis Kintsugi must own deliberately — **retention**.
"Never forgets" is impossible in bounded disk; every one of these systems pairs versioning with a
GC/retention policy. Kintsugi must do the same (§5).

### 2.3 Berkeley Recovery-Oriented Computing — "undo for operators"

The UC Berkeley/Stanford **ROC** project (Patterson, Brown et al.) reframes dependability around
*recovering from* inevitable human and software faults rather than preventing all of them — exactly
Kintsugi's honest-guarantee posture. Its **"Three R's: Rewind, Repair, Replay"** undo model:

1. **Rewind** — revert all system state to an earlier point in time (before the error).
2. **Repair** — the operator fixes the latent problem (patch, filter, or just retry differently).
3. **Replay** — re-execute the intervening user interactions against the repaired system.

Built and evaluated as an *undoable e-mail store*. Sources:
<https://people.eecs.berkeley.edu/~pattrsn/papers/ROC_ASPLOS_draft4.pdf>,
<http://roc.cs.berkeley.edu/papers/sigops-undo-extabs2c.pdf>,
<https://www.sigops.org/s/archives/ew-history/2002/program/p70-brown.pdf>, <http://roc.cs.berkeley.edu/>.

**Relevance:** Kintsugi's undo is "Rewind" only, scoped to the filesystem before-images of one
command. That is the honest scope: it cannot Replay (re-run later commands against restored state)
and it cannot undo non-filesystem effects (network calls, pushed commits, dropped remote tables).
The ROC framing is the right vocabulary for the user-facing copy: Kintsugi gives you a **fast,
bounded Rewind**; *you* do Repair and Replay. Don't overclaim transactional all-or-nothing.

---

## 3. Command-level / time-travel undo

### 3.1 Trash-can semantics — `safe-rm`, `trash-cli`, `rip`

The cheapest, most reliable file-recovery primitive is to **not delete** — move to a trash dir:

- **`trash-cli`** implements the **FreeDesktop.org Trash spec**: files move to
  `~/.local/share/Trash`, and it records **original name, original path, deletion date, and
  permissions** in a `.trashinfo` sidecar, enabling exact restore (`trash-restore`). Commands:
  `trash-put`, `trash-list`, `trash-restore`, `trash-rm`, `trash-empty`.
  Source: <https://github.com/andreafrancia/trash-cli>,
  <https://manpages.ubuntu.com/manpages/xenial/man1/trash.1.html>.
- **`shell-safe-rm` / `safe-rm`** — drop-in `rm` replacements that move to `~/.Trash` (safe-rm
  itself has no built-in restore/empty). Source: <https://adamheins.com/blog/a-safer-rm>.

**Relevance:** For deletions specifically, "rename into a trash store" is **atomic on the same
filesystem** (`rename(2)`) and *cheaper than reflink+copy* — no data movement at all. Kintsugi's
recoverer should prefer **intercept-and-divert** for `rm`-class deletes when feasible (move target
aside, let undo move it back) over snapshot-then-let-it-delete. This dovetails with the existing
`is_fully_reversible` gate. The `.trashinfo` metadata model (original path + perms + timestamp) is a
good template for what the manifest stores.

### 3.2 Transactional shells and "predict the paths"

There is no widely-deployed truly transactional Unix shell (filesystem ops aren't transactional at
the syscall layer). The practical substitutes:

- **`overlayfs` / unionfs sandbox** — run the command against an overlay; commit or discard the
  upper layer (a poor-man's transaction). (from training knowledge.)
- **NILFS2 continuous checkpoints** — implicit "everything is in a transaction you can rewind to a
  few seconds ago." (§1.3)
- **Static path prediction** — what Kintsugi already does in `predict_paths`. The limits are
  fundamental and the code is honest about them via `is_fully_reversible`:
  - Globs and shell expansions (`*`, `$VAR`, `~`, command substitution) resolve to paths *unknown
    until the shell expands them* — Kintsugi flags these as not-fully-reversible rather than
    guessing.
  - Tools that compute their own targets (a script that `rm`s paths read from a file; `find ... -delete`)
    are opaque to static parsing.
  - Output redirections, in-place edits (`sed -i`, `>`), and move/rename are handled by treating
    redirect targets and non-flag args as candidates.

**Better prediction options, in increasing cost/accuracy:**
1. **Static (current)** — cheap, deterministic, runs without the daemon. Best for Tier-1.
2. **Dry-run / `--dry-run` where the tool supports it** — e.g. `rsync -n`, `git ... --dry-run`.
   High fidelity but tool-specific and not always available.
3. **Runtime tracing** (the *backstop*) — a filesystem watcher (`fanotify`/`inotify` on Linux,
   `FSEvents` on macOS, `ReadDirectoryChangesW`/USN journal on Windows) observes the *actual*
   paths the command touches and snapshots/journals them as they're about to change. This is the
   ground truth that catches everything static prediction misses, at the cost of racing the writes.
   (from training knowledge — verify before publishing: `fanotify` with `FAN_OPEN_PERM` can block a
   write until permitted, but requires `CAP_SYS_ADMIN`; plain `inotify` only *observes* and cannot
   pre-empt, so it is a backstop, not a gate.)

**Recommendation on prediction:** keep static prediction as the fast path; treat the watcher as the
authoritative backstop; never claim coverage beyond what `is_fully_reversible` returns true for.

---

## 4. The preexec timing window — blocking vs. race

This is the crux of the recoverer design.

### 4.1 What a preexec hook can and can't see

- **zsh** has a built-in `preexec` function (a `DEBUG`-style trap) that runs **after the user hits
  enter but before the command executes**, receiving the command line. **bash** has no native
  preexec; the community **`bash-preexec`** library emulates it via the `DEBUG` trap + `PROMPT_COMMAND`
  for bash 3.1+. Source: <https://zsh.sourceforge.io/Doc/Release/Functions.html>,
  <https://github.com/rcaloras/bash-preexec>,
  <https://jichu4n.com/posts/debug-trap-and-prompt_command-in-bash/>.
- Crucially, **preexec runs in the interactive shell's own process, synchronously**: whatever it
  does, the user's command does not start until the hook returns (unless the hook backgrounds work).
  This is what makes a *just-in-time* snapshot possible at all — but also what can hang the shell.
- A preexec hook **can** cancel/replace a command (e.g. by resetting it or returning non-zero in
  zsh), which is how a recoverer could *divert* an `rm` to trash. Source:
  <https://medium.com/the-cloud-corner/cancel-a-terminal-command-during-preexec-zsh-function-c5b0d27b99fb>.
- It **cannot** see paths produced by runtime expansion that the shell hasn't performed yet in all
  cases, and it cannot perfectly model what the binary will do internally — same limits as §3.2.

### 4.2 The tradeoff

```
  user hits enter
        │
   ┌────┴─────────────────────────────────────────────────┐
   │ preexec hook fires (synchronous, in the shell)        │
   └────┬──────────────────────────────────────────────────┘
        │
   (A) FIRE-AND-FORGET: hook backgrounds the snapshot, returns immediately
        │   → command starts NOW, racing the snapshot. If the snapshot
        │     hasn't captured a path before the command overwrites/deletes
        │     it, the before-image is wrong/missing. Fast; unsafe for
        │     destructive commands.
        │
   (B) SYNCHRONOUS: hook blocks until the snapshot completes
        │   → command cannot touch anything until the before-image is
        │     durable. Correct. BUT if the daemon stalls/crashes, the
        │     user's shell hangs indefinitely. Unacceptable UX.
        ▼
   command executes
```

Neither pure option is acceptable: (A) loses the race for exactly the commands we care about; (B)
risks hanging the shell on daemon failure — a guard tool that freezes your terminal will be
uninstalled within a day.

### 4.3 Recommended preexec design — classify locally, bound the block

A three-step hook that is *fast for safe commands and bounded for dangerous ones*:

1. **Classify locally, in-process, with no daemon round-trip (Tier-1 only).** The hook runs the
   deterministic Tier-1 classifier (a pure function over the command string — the same rules engine
   in `kintsugi-core::rules`, compiled into the shim/hook so it needs *no IPC*). SAFE commands take
   the fire-and-forget path; only CATASTROPHIC/destructive commands pay for a snapshot. This keeps
   the common case (cd, ls, git status, cargo build) at near-zero added latency.
   - Security spine note: the hook must never let the *model* gate execution. Tier-1 is rules-only;
     model scoring (Tier-2) is for the daemon's ambiguous band and must not be on the synchronous
     preexec path.

2. **Fire-and-forget for safe commands.** Return immediately; optionally hand the command to the
   daemon asynchronously for the event log. No blocking, no snapshot.

3. **Bounded synchronous snapshot for destructive commands.** For a destructive command, the hook
   performs a **just-in-time snapshot with a hard timeout** (e.g. 250–750 ms, tunable):
   - **Reflink-first, predicted-paths-only.** Snapshot only `predict_paths`-and-existing targets,
     using `reflink_or_copy`. Reflink makes the common case complete in single-digit ms even for
     large files, because no bytes move. This is why reflink is the enabler for a *bounded*
     synchronous snapshot rather than a multi-second copy.
   - **Durability before release.** Fsync the manifest (and ensure reflinks are persisted) before
     returning, per the ARIES log-before-apply invariant — otherwise undo isn't honest under a crash.
   - **On timeout / daemon stall / error → degrade, never hang.** If the snapshot doesn't finish
     within the budget, the hook **abandons the synchronous attempt, falls back to fire-and-forget,
     lets the command run, and relies on the filesystem-watcher backstop** to journal whatever the
     command actually touches. The user is told, in plain English, that coverage degraded to
     best-effort for this command.
   - **Prefer divert-over-snapshot for deletes.** For `rm`-class commands on the same filesystem, a
     `rename(2)` into the trash store is atomic and instant — strictly better than snapshot+delete.
     Use it where the recoverer can safely rewrite/redirect the command (zsh can; bash via
     `bash-preexec` can with care), otherwise snapshot.

This gives: zero-cost safe path, bounded worst-case latency on the dangerous path, **no
indefinite hang**, and a backstop that catches the race when the bound is exceeded.

### 4.4 Why the watcher backstop is load-bearing

Because (i) static prediction can't see every path, (ii) the synchronous bound can be exceeded, and
(iii) bash's emulated preexec is best-effort, the **filesystem watcher is the thing that makes the
"nothing is unrecoverable" guarantee honest.** It observes actual mutations and journals
before-images even when the just-in-time path missed. It is *recovery-oriented* (ROC §2.3), not
preventive — it cannot stop a write, only ensure a prior version exists to roll back to. The honest
guarantee is therefore "recoverable," not "un-warned" or "transactional."

---

## 5. Retention / GC — bounding disk

Every versioning system in §2.2 pairs capture with retention; Kintsugi must too, or the store grows
without bound. Recommended policy (mirrors NILFS2's promote-and-GC and Elephant's retention):

- **Tiered retention by recency + significance.** Keep all snapshots for the last N hours; thin
  older ones (keep one per command that was actually destructive, drop redundant before-images).
- **Size and age caps with background GC.** A configurable byte budget and max-age; a background
  reclaimer (like NILFS2's online GC) deletes oldest-first once over budget. GC must respect the
  append-only event log: removing a snapshot's *data* is allowed; rewriting *history* is not — log a
  "snapshot expired" event rather than deleting the manifest record.
- **Reflink-aware accounting.** Because reflinked snapshots share extents, on-disk cost ≈ the bytes
  the guarded commands actually changed, not the file sizes. Account real (post-CoW) usage, not
  apparent size, so GC isn't overzealous.
- **Promote-to-keep.** Like NILFS2 checkpoints→snapshots, let the user pin a snapshot so GC never
  reclaims it (e.g. the one right before a known-bad incident).

---

## 6. Recommendations for Kintsugi (concrete)

**Recorder + recoverer architecture:**

1. **One snapshot engine, two front-ends.** Keep `snapshot::{predict_paths, is_fully_reversible,
   capture, restore}` as the single engine. Front-end A is the existing agent-gate path (daemon
   verdict → capture before allowed destructive command). Front-end B is the new **recoverer**: a
   shell preexec hook (zsh native + `bash-preexec` for bash) that calls the *same* engine for
   human-typed commands.

2. **Compile Tier-1 rules into the hook for daemon-free classification.** The preexec hook must
   classify SAFE vs destructive **without IPC** so the common case adds ~no latency and a dead
   daemon can't hang the shell. Reuse `kintsugi-core::rules` as a pure function. Rules block; the
   model never gates on this path (security spine #1/#2).

3. **Reflink-first, predicted-paths-only, bounded-synchronous snapshot for destructive commands.**
   Hard timeout (start ~500 ms, tunable). On timeout/stall/error → fire-and-forget + watcher
   backstop, and tell the user coverage degraded. Fsync the manifest before releasing the command
   (ARIES ordering).

4. **Prefer divert-to-trash for deletes.** `rename(2)` into a same-fs trash store is atomic and
   instant; restore = rename back. Store FreeDesktop-style metadata (original path, perms,
   timestamp). Fall back to snapshot when the command can't be safely rewritten.

5. **Make the store device-aware.** Place the snapshot store on the **same filesystem** as the
   captured paths (key by `st_dev`) so reflink actually engages; a cross-mount store silently
   degrades every capture to a full copy. This is the biggest capture-perf win available.

6. **Keep the watcher backstop authoritative.** It is what makes the guarantee honest when static
   prediction or the bounded snapshot misses. Treat `inotify`/`fanotify`/`FSEvents`/USN as
   observe-and-journal (recovery), not as a pre-emptive gate.

7. **Bound disk with tiered, reflink-aware, background GC** (§5), append-only-log-safe.

8. **Honest guarantee — state it everywhere it matters.** Kintsugi provides a **best-effort
   just-in-time snapshot plus a filesystem-watcher backstop ⇒ destructive *filesystem* actions are
   recoverable (Rewind), not hard-transactional.** It is *not* all-or-nothing, *not* unbypassable,
   and *cannot* undo non-filesystem effects (network calls, already-pushed commits, dropped remote
   tables, `dd` to a device, anything `is_fully_reversible` returns false for). For those, the tool
   *warns* and refuses to promise undo — consistent with CLAUDE.md spine #7 ("nothing is
   unrecoverable via the watcher backstop," NOT "nothing runs un-warned"). Use the ROC vocabulary in
   UX copy: Kintsugi gives you a fast, bounded **Rewind**; you do Repair and Replay.

---

## Sources

Reachable web sources used:

- ioctl_ficlonerange(2) — <https://www.man7.org/linux/man-pages/man2/ioctl_ficlonerange.2.html>
- btrfs Reflink docs — <https://btrfs.readthedocs.io/en/latest/Reflink.html>
- copy_file_range cross-fs regression/patch threads —
  <https://lkml.iu.edu/hypermail/linux/kernel/2107.0/00910.html>,
  <https://lkml.iu.edu/hypermail/linux/kernel/2103.0/07196.html>
- `cp --reflink` EINVAL — <https://www.ctrl.blog/entry/cp-reflink-einval.html>
- ZFS copy_file_range discussion — <https://github.com/openzfs/zfs/discussions/4237>
- NILFS2 — <https://lwn.net/Articles/294782/>, <https://docs.kernel.org/filesystems/nilfs2.html>,
  <https://wiki.archlinux.org/title/NILFS2>
- ARIES — <https://dl.acm.org/doi/10.1145/128765.128770>,
  <https://web.stanford.edu/class/cs345d-01/rl/aries.pdf>,
  <https://en.wikipedia.org/wiki/Algorithms_for_Recovery_and_Isolation_Exploiting_Semantics>
- ROC / Three R's / Undo for Operators —
  <https://people.eecs.berkeley.edu/~pattrsn/papers/ROC_ASPLOS_draft4.pdf>,
  <http://roc.cs.berkeley.edu/papers/sigops-undo-extabs2c.pdf>,
  <https://www.sigops.org/s/archives/ew-history/2002/program/p70-brown.pdf>, <http://roc.cs.berkeley.edu/>
- zsh preexec — <https://zsh.sourceforge.io/Doc/Release/Functions.html>
- bash-preexec — <https://github.com/rcaloras/bash-preexec>;
  DEBUG trap — <https://jichu4n.com/posts/debug-trap-and-prompt_command-in-bash/>
- zsh cancel-in-preexec — <https://medium.com/the-cloud-corner/cancel-a-terminal-command-during-preexec-zsh-function-c5b0d27b99fb>
- trash-cli / FreeDesktop Trash — <https://github.com/andreafrancia/trash-cli>,
  <https://manpages.ubuntu.com/manpages/xenial/man1/trash.1.html>; safer rm —
  <https://adamheins.com/blog/a-safer-rm>

Items marked "(from training knowledge — verify before publishing)" — APFS `clonefile`/Windows ReFS
mapping of `reflink_copy`; ZFS rollback discarding newer snapshots; APFS `fs_snapshot`/`tmutil`;
overlayfs hardlink/rename caveats; `fanotify FAN_OPEN_PERM` capabilities; and the specifics of
Elephant FS, CVFS/Self-Securing Storage, ext3cow, and Wayback — were not re-fetched from primary
sources in this pass and should be confirmed against the cited papers before publication.
