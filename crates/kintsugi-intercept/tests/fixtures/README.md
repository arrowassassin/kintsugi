# V1.1 payload fixtures — post-tool and file-write shapes (pinned 2026-11-22)

Task-1 spike of the Phase 6 V1.1 plan
(`docs/superpowers/plans/2026-11-22-phase6-provenance-v11.md`). These files pin the
**exact wire shapes** that Task 2 (post-tool result observation) and Task 3
(Cursor/OpenCode file-write observation) must parse. This is data + docs only — no
production source changes.

The 0.2.1 lesson ("adapters written to documented shapes, never round-trip-verified",
`DECISIONS.md:518-523`) is the reason this directory exists: every new parse in Tasks
2/3 must trace to a file here, and every file here carries its provenance.

## Provenance flags

- **verified** — every field name traces to a primary, vendor-controlled source fetched
  on 2026-11-22 (official docs example or a machine-generated wire schema).
- **provisional** — at least one field (or its live emission) could not be confirmed
  against a primary source. Provisional fixtures get a **needs live-CLI verification**
  checkbox below; a human resolves them before the shapes back any release claim.

Scalar values (ids, paths, model names, `cursor_version`) are **illustrative
placeholders** — the pinned contract is the field names and their nesting, not the
example values. Workspace paths reuse the repo's existing test convention
(`/work/repo`) so the follow-on tests resolve against a familiar root.

## Index

| Fixture | Agent | Event | Min version | Flag |
| --- | --- | --- | --- | --- |
| `claude-post-tool-use.json` | Claude Code | `PostToolUse` | v2.1.330 (docs current at pin date; event is older) | verified |
| `codex-post-tool-use.json` | OpenAI Codex | `PostToolUse` | hooks stable ~v0.124.0 (Apr 2026, secondary source) | verified |
| `antigravity-post-tool.json` | Google Antigravity | `PostToolUse` | none published (research gap) | provisional |
| `cursor-write.json` | Cursor | `preToolUse` (`Write`) | hooks GA, config schema v1; exact version unconfirmed | provisional |
| `cursor-str-replace.json` | Cursor | `preToolUse` (`StrReplace`) | same | provisional |
| `cursor-after-file-edit.json` | Cursor | `afterFileEdit` | same | provisional |
| `opencode-write-v1.json` | OpenCode | `tool.execute.before` (V1) | V1 object entrypoints in 1.18.29+ | provisional |
| `opencode-write-v2.json` | OpenCode | `ctx.tool.hook("execute.before")` (V2) | V2 GA status unverified (mid-migration) | provisional |

---

## claude-post-tool-use.json — **verified**

- **Agent:** Claude Code. **Date:** 2026-11-22.
- **Source:** [Hooks reference](https://code.claude.com/docs/en/hooks), `PostToolUse`
  input section (fetched 2026-11-22; docs current as of release v2.1.330). Envelope
  fields are the docs example verbatim: `session_id`, `transcript_path`, `cwd`,
  `permission_mode`, `hook_event_name`, `tool_name`, `tool_input`, `tool_response`,
  `tool_use_id`, optional `duration_ms`.
- **Reason for flag:** the envelope is documented verbatim by the vendor. One honest
  caveat: the docs state "the exact schema for [tool_input and tool_response] depends
  on the tool", and no WebFetch success shape is published — so `tool_response` here is
  deliberately a plain **string** (the form the docs themselves define for error text)
  rather than an invented object. Task 2's classifier must treat the response
  **opaquely** (content-bearing vs empty/error) and never depend on response field
  names — which is also spine #6: result bytes are never persisted.
- **Expected normalized assertion:** `parse_post` yields `PostToolCall { tool:
  "WebFetch", input: {url, prompt}, response: <opaque string>, cwd: "/work/repo",
  session_id: "e3f8a1c2-…" }`; `classify_result_ingest` yields `IngestSource { kind:
  Web, id: "https://example.com/advisory" }` — the source id comes from
  `tool_input.url`, never from the response bytes.

## codex-post-tool-use.json — **verified**

- **Agent:** OpenAI Codex. **Date:** 2026-11-22.
- **Source:** machine-generated wire schema
  [`codex-rs/hooks/schema/generated/post-tool-use.command.input.schema.json`](https://github.com/openai/codex/tree/main/codex-rs/hooks/schema/generated)
  (fetched 2026-11-22) — the strongest fixture source of the eight agents. All 11
  required fields present: `cwd`, `hook_event_name` (const `"PostToolUse"`), `model`,
  `permission_mode`, `session_id`, `tool_input`, `tool_name`, `tool_response`,
  `tool_use_id`, `transcript_path` (string|null), `turn_id`; optional `agent_id` /
  `agent_type` omitted (subagent-only). `tool_input` and `tool_response` are
  unconstrained (`true`) in the schema — any JSON value is wire-valid.
- **Reason for flag:** pinned against a generated schema in the vendor repo. Caveat
  (from the docs' own pointer): `main` may include unreleased fields; the version
  stamps (PostToolUse since v0.117.0 Feb 2026, stable v0.124.0 Apr 2026) come from a
  secondary reference, not OpenAI release notes.
- **Tool choice note:** Codex hook coverage excludes hosted tools (`WebSearch` etc.),
  so the fixture uses the sanctioned content surface — an MCP tool
  (`mcp__webdocs__fetch_page`, `mcp__<server>__<tool>` convention). A `WebFetch`-style
  fixture would be dishonest for this dialect.
- **Expected normalized assertion:** `PostToolCall { tool: "mcp__webdocs__fetch_page",
  input: {url}, response: <opaque>, cwd: "/work/repo", session_id: "b1e5d0a2-…" }`;
  `classify_result_ingest` yields `IngestSource { kind: Mcp, id:
  "mcp/webdocs/fetch_page" }` by the existing `is_mcp_tool` name-shape rule.

## antigravity-post-tool.json — **provisional**

- **Agent:** Google Antigravity. **Date:** 2026-11-22.
- **Source:** [Antigravity Hooks docs](https://antigravity.google/docs/hooks),
  `PostToolUse` section (fetched 2026-11-22). Fields verbatim from the documented
  contract: `toolCall {name, args}`, `stepIdx`, `error` (optional; "empty if
  successful"), plus common fields `conversationId`, `workspacePaths`,
  `transcriptPath`, `artifactDirectoryPath`, `modelName`. The example values
  (`conversationId`, `modelName`, `~`-prefixed paths) mirror the docs' own examples.
- **Reason for flag (needs resolution):** the official docs say `toolCall.args`, but
  Kintsugi's in-tree adapter (`crates/kintsugi-intercept/src/dialect.rs:187-200`,
  `parse_antigravity`) reads `toolCall.arguments` — written to an older or wrong
  reading of this dialect. At least one of the two is wrong for the live wire, and
  only a live CLI can say which. Additionally, the research round found plugin
  tool-event hooks publicly questioned in the IDE (Aug 2026 forum) and no version
  stamps for hooks availability.
- **Honest limitation (for Task 2):** Antigravity `PostToolUse` carries **no result
  bytes** — input args plus optional `error` only, and its output is advisory-only
  (`{}`). Result-content classification for this dialect reduces to *act
  confirmation*: the fetch ran and `error` is empty, so any added taint may only use
  `args.Url` as the source id.
- **Expected normalized assertion:** `PostToolCall { tool: "read_url_content", input:
  {Url}, response: null, session: "ec33ebf9-…" }`; an added taint (if Task 2 chooses
  to observe this dialect's post events) is `IngestSource { kind: Web, id:
  "https://example.com/advisory" }` from `toolCall.args.Url`.

- [ ] **Needs live-CLI verification:** confirm live Antigravity payloads carry
      `toolCall.args` (official docs) rather than `toolCall.arguments` (what the
      current adapter reads); fix the adapter accordingly in Task 2/3.

## cursor-write.json — **provisional**

- **Agent:** Cursor. **Date:** 2026-11-22.
- **Source:** [Cursor Hooks docs](https://cursor.com/docs/hooks), common input schema +
  `preToolUse` section (fetched 2026-11-22). Envelope documented: `tool_name`,
  `tool_input`, `tool_use_id`, `cwd`, `agent_message`, plus the common fields
  (`conversation_id`, `generation_id`, `model`, `model_id`, `model_params`,
  `hook_event_name`, `cursor_version`, `workspace_roots`, `user_email`,
  `transcript_path`).
- **Reason for flag:** the **inner `tool_input` shape for the `Write` tool is not
  documented** (the docs' `preToolUse` example is Shell-only) and the exact Cursor
  content-tool name set is the research round's stated gap. `file_path` is anchored to
  Cursor's own documented convention (`afterFileEdit` and `beforeReadFile` both use
  `file_path`); `content` is the Claude-compatible best guess, unverified. `Write` is
  a documented matcher value (the docs say the `afterFileEdit` matcher runs against
  the value `Write`).
- **Expected normalized assertion (Task 3):** write-shape parse yields tool `Write`,
  absolute path `/work/repo/src/notes.rs` from `tool_input.file_path`, session
  `conv-4d2f9a1c` from `conversation_id` → `WriteObserved { session: "conv-4d2f9a1c",
  path: "/work/repo/src/notes.rs" }`. Cursor shell payloads
  (`beforeShellExecution {command, cwd}`) parse unchanged.

- [ ] **Needs live-CLI verification:** pin the exact Cursor `Write` tool_input arg
      names (`content`?) and confirm `Write` fires `preToolUse` on the live CLI.

## cursor-str-replace.json — **provisional**

- **Agent:** Cursor. **Date:** 2026-11-22.
- **Source:** same docs as above for the envelope. `StrReplace` as a live tool name is
  sourced from the wild, not the docs: a community-confirmed matcher
  `Write|StrReplace|Delete` blocked real writes ([Cursor forum, Windows
  thread](https://forum.cursor.com/t/hooks-intermittently-non-functional-on-windows-pretooluse-worked-then-stopped-after-hooks-json-edit/154608)).
  `old_string`/`new_string` are anchored to Cursor's documented `afterFileEdit`
  `edits[]` entries; the `StrReplace` tool_input itself is undocumented.
- **Reason for flag:** both the tool name and its inner args are outside the official
  docs (the docs' matcher list says "Values include Shell, Read, Write, Grep, Delete,
  Task" — non-exhaustive, and `StrReplace` is not listed).
- **Expected normalized assertion (Task 3):** tool `StrReplace`, path
  `/work/repo/src/lib.rs` from `tool_input.file_path`, session `conv-4d2f9a1c` →
  `WriteObserved { session: "conv-4d2f9a1c", path: "/work/repo/src/lib.rs" }`.

- [ ] **Needs live-CLI verification:** enumerate Cursor's exact content-tool name set
      (does `Edit`/`StrReplaceAll` exist? is `StrReplace` the real id?) and pin the
      matcher `Write|StrReplace|Delete|…` accordingly.

## cursor-after-file-edit.json — **provisional**

- **Agent:** Cursor. **Date:** 2026-11-22.
- **Source:** [Cursor Hooks docs](https://cursor.com/docs/hooks), `afterFileEdit`
  section (fetched 2026-11-22). Hook-specific fields documented verbatim:
  `file_path` (absolute) and `edits: [{old_string, new_string}]`, plus the common
  schema fields.
- **Reason for flag:** the shape is documented, but the research round flagged Cursor
  coverage holes that live verification must confirm (cloud-agent backend tools never
  fire hooks; CLI `AskUserQuestion` skips pre/post hooks), and the exact mapping of
  which tool writes fire `afterFileEdit` (Write only? StrReplace too?) is not stated.
- **Expected normalized assertion (Task 3):** post-write confirmation signal —
  `file_path` `/work/repo/src/notes.rs`, session `conv-4d2f9a1c` from
  `conversation_id`, the `edits[]` body never persisted (spine #6). Intended use:
  belt-and-braces confirmation that an edit landed, alongside the pre-tool write
  observation.

- [ ] **Needs live-CLI verification:** confirm which tool writes fire `afterFileEdit`
      on the live CLI, and that the event's own coverage claim holds.

## opencode-write-v1.json — **provisional**

- **Agent:** OpenCode. **Date:** 2026-11-22.
- **Source:** V1 plugin contract per the [plugins
  manual](https://github.com/joshuadavidthomas/opencode-plugins-manual/blob/main/docs/04-hooks-reference.md)
  and [OpenCode plugins docs](https://opencode.ai/docs/plugins/): the
  `tool.execute.before` hook receives two arguments — `input: {tool, sessionID,
  callID}` and a mutable `output: {args}`. The fixture serializes both arguments as
  one document (`input` / `output` keys are the fixture's representation of the two
  callback parameters, not wire fields). `filePath` is documented by the manual's own
  worked examples (`output.args.filePath` for read and write); `content` is
  unverified.
- **Reason for flag:** the research round's stated gap — OpenCode's exact `write`
  argument field names were never verified against OpenCode source (`filePath` vs
  `file_path`, content field names). V1 signatures themselves are documented, and V1
  object entrypoints are supported in OpenCode 1.18.29+ (npm `latest` was still V1
  1.19.4 on 2026-10-25, third-party observed).
- **Expected normalized assertion (Task 3):** the generated dual-entrypoint plugin
  forwards `{tool, args:{filePath}, session, cwd}` to `kintsugi-hook --agent opencode
  --event write` → `WriteObserved { session: "ses_9f2a41", path:
  "/work/repo/src/notes.rs" }`; the taint session key is `input.sessionID`.
  `cwd` is added by the bridge (the plugin's `process.cwd()`) because the daemon
  resolves/validates the path against the writing session's workspace trust
  boundary. The raw two-argument V1 callback shape above is also accepted by
  `Dialect::parse_write` (fixture-driven test), so a direct test can feed this file
  unchanged.

- [ ] **Needs live-CLI verification:** pin the exact `write`/`edit` arg field names
      against OpenCode source (confirm `filePath` + `content`; establish `edit`'s
      shape) before the generated plugin ships.

## opencode-write-v2.json — **provisional**

- **Agent:** OpenCode. **Date:** 2026-11-22.
- **Source:** [OpenCode server plugins
  docs](https://opencode.ai/docs/build/plugins/server/) (fetched 2026-11-22): V2
  registers `await ctx.tool.hook("execute.before", (event) => …)`; the documented
  event fields are `event.tool` and `event.input` (verbatim doc example: `if
  (event.tool === "read") console.log(event.input)`). The `execute.after` variant adds
  `status` (`"completed" | "error"`), `result`, and `error` (with `.message`).
- **Reason for flag (the big one):** **the V2 event's session field is not
  documented** — the docs show only `tool` and `input` on the before event. Taint
  keying needs a session id; V1 has `input.sessionID`, V2's equivalent must be
  established from source or a live run before the V2 write path can ship. V2's GA
  status is itself unverified (V1→V2 migration in flight; "V1 plugin implementations
  do not run in V2").
- **Expected normalized assertion (Task 3):** `{tool: "write", input: {filePath,
  content}}` parses to the same write observation as V1 — path
  `/work/repo/src/notes.rs` from `input.filePath` — **with the session key pending
  the gap above**. `execute.after` (if Task 3 prefers post-write confirmation) adds
  `status`/`result`/`error` per the documented shape.

- [ ] **Needs live-CLI verification:** pin the V2 event's session identifier (or the
      sanctioned way a plugin obtains it), and confirm V2 field names on a live
      OpenCode install.

- **Task 3 decision on the V2 session gap (2026-11-22):** V2 ships the
  `ctx.tool.hook("execute.before")` registration *and* honours the existing
  convention that **sessionless observations are skipped**. The V2 handler forwards
  `{tool, args:{filePath}, cwd}` with no session, so `kintsugi-hook` parses and
  classifies it but sends nothing (exactly like a sessionless PreToolUse content
  call). Consequences, stated honestly: V2 write taint is inert until an honest
  session identifier is pinned; the V1 write path and the V1 shell gate are
  unaffected; and no invented session key (callID, per-call id, or a process-global
  placeholder) is ever used as one — a fabricated key would fragment or merge taint
  silently. The alternative (derive a session from V1-only fields) is not available
  on a V2 host, because V1 plugin implementations do not run under V2.

---

## How Tasks 2 and 3 consume these

- Task 2 (`dialect.rs::parse_post` + `observe.rs::classify_result_ingest`): each
  post-tool fixture parses to the expected `PostToolCall`; malformed or
  missing-response variants must parse to `None` — observation never blocks.
- Task 3 (Cursor/OpenCode write shapes + the generated OpenCode plugin JS): the
  write fixtures parse to `WriteObserved {session, path}`; the dual V1/V2 entrypoint
  registration is unit-tested against the two OpenCode fixtures.
- **Adversarial guidance (for the tester role):** a malformed variant of every
  fixture here (truncated JSON, wrong types, missing `tool_name`/`toolCall`) must
  degrade to pass-through — parse to `None`/`Bad`, never panic, never block the tool
  call, and never write partial identifiers to the taint log.

## Honest-guarantee notes carried from the research round

- Antigravity `PostToolUse` has no result-content field; its output is advisory-only
  (`{}`). Post-tool classification for this dialect is act-confirmation at best.
- Cursor cloud agents redact MCP results: `postToolUse` there receives
  `{"redacted": true}` as `tool_output` — result bytes are unavailable in that
  surface.
- Codex hook coverage excludes hosted tools (`WebSearch` and friends) —
  "a useful guardrail, not a complete enforcement boundary" in Codex's own words.
- Every dialect here is fail-open on hook infra failure except where an explicit
  opt-in exists (Claude `onFailure: "block"`; Cursor `failClosed`). Fixture shape
  says nothing about enforcement grade; docs claims stay per the honest-guarantee
  rule.
