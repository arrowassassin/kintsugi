# Anchoring — a receipt for your log

Your event log is hash-chained, so a casual edit inside it breaks `kintsugi verify`.
But an attacker who can rewrite the database can also rewrite the whole chain:
a rebuilt chain is internally consistent and proves nothing on its own. A
**checkpoint** is the missing piece — a small file with the log's length and head
hash at a moment in time, optionally signed with your admin vault's key. Keep a
copy somewhere the log cannot reach, and later you can prove whether the log you
are looking at is still the log you anchored.

Kintsugi never pushes anything. `kintsugi anchor` talks to the log file, not the
daemon, and makes no network call. The copy is yours to make.

## What a checkpoint proves

- **INTACT** — the chain verifies AND the anchored `(seq, head)` is exactly where
  the chain ends today. Nothing has been appended since, nothing changed.
- **STALE** — the chain verifies and your anchored head is still reachable at its
  own sequence, but N events have been appended since. Normal: export a fresh
  checkpoint.
- **TAMPERED** — the chain diverges before the anchor, or the anchored head is no
  longer at its sequence (a purge or a rewrite rebuilt the log underneath it).
- **INVALID** — the signature does not verify under the `key_id` the checkpoint
  carries. The file was edited, corrupted, or forged.
- **UNVERIFIABLE** — unsigned, missing, unreadable, or no anchor recorded. An
  unsigned checkpoint asserts nothing about who wrote it.

## Use

```sh
# Write a signed checkpoint (prompts for the admin password) to a file.
kintsugi anchor export --out ~/Dropbox/kintsugi-receipt.txt

# Print one to stdout instead (no --out).
kintsugi anchor export

# Check the log against that file — distinct exit codes, see below.
kintsugi anchor verify --checkpoint ~/Dropbox/kintsugi-receipt.txt

# Check against the most recent anchor recorded in this log, no file needed.
kintsugi anchor verify
```

`kintsugi status` grows an `anchored: <ts> (N events ago)` line once anchors exist.

Keep the exported file **outside the log's reach**: a private repo, a second
device, removable media, a password manager's attachment. A copy on the same disk
as the database protects against edits but not against a wipe.

### Exit codes

| Code | Verdict | Meaning |
|---|---|---|
| 0 | `INTACT through anchor N` | chain intact, nothing appended since |
| 1 | `STALE: N events since the anchor` | chain intact, new events appended |
| 2 | `TAMPERED` | chain diverges before the anchor, or the log was purged/rewritten after it |
| 3 | `INVALID` | signature does not verify under its own `key_id` |
| 4 | `UNVERIFIABLE` | unsigned, missing, unreadable, or no anchor recorded |

Anything non-zero means verification did not fully pass; script against the code,
not the prose.

## Signing

Signing adds no new secret at rest. The key is derived per operation from the same
admin-vault inputs the admin proof uses (password, `auth_salt`, KDF params), and
only the verifying public key travels — as the checkpoint's `key_id`, in hex. That
makes a checkpoint **self-certifying**: it verifies against a key it carries, and
the vault file you already trust pins that key.

- No vault, or `--no-sign`, or an unreadable vault ⇒ the checkpoint is **unsigned**
  and `anchor verify` reports `UNVERIFIABLE`. That is deliberate: a signature you
  cannot check is worse than an honest "unsigned".
- A password change re-keys the vault: the next export starts a new `key_id`
  series, and older checkpoints keep verifying under the `key_id` they recorded.
  Rotation appends a series; it never invalidates history.
- Signatures cover a protocol-separation label (`kintsugi.log.anchor.v1`) distinct
  from the admin proof's, so an anchor signature cannot be replayed as a "password
  to stop" proof, or the reverse.
- `--password-file` reads the password from a file for non-interactive use. Treat
  such a file like any other secret; Kintsugi never writes one.

## The no-fork guard

Anchors are append-only and their sequence numbers must strictly increase. An
export whose head is *behind* the last recorded anchor is refused, and nothing is
written: a lower seq can only mean the events table was restored from a backup or
rewritten. After a deliberate purge (which rechains), the next anchor records the
new head — with the `audit:purge` row in the events table preserving the why.

## What anchoring does not buy

- **It is not tamper-proof.** It makes tampering *evident* to whoever holds a
  checkpoint. Delete every copy of your checkpoints and the guarantee is gone.
- **It does not stop a command from running.** See
  [`security-assessment.md`](security-assessment.md) for the honest boundary.
- **It does not prove the log was never rewritten before you first anchored** —
  your first checkpoint is where the guarantee starts.
- **It says nothing about a machine you do not verify on.** Verifying is a
  deliberate act: run it, read the exit code.
