# Aegis — Enterprise / Team Roadmap (companion to the design doc)

> This is a **forward-looking** track, separate from the locked solo design doc
> (`aegis-design-doc.md`). Nothing here ships in v1. It exists so that, when team
> and enterprise demand arrives, we extend Aegis **without betraying the local-first
> tool solo users love, and without weakening the security spine.**

## The thesis

Today Aegis is a dev-first, local-first, single-machine tool. Its adoption engine
is exactly that: nothing leaves your machine, install in one line, works alone.

Enterprises want the *opposite* of local-first in one dimension: a central security
team wants **visibility and control across the fleet**. The whole roadmap is about
resolving that tension — adding opt-in **central visibility + policy** as an additive
layer, while the free local tool stays untouched and trustworthy.

We do **not** chase "unbypassable prevention." Aegis stays a *detective + reversible*
control (spine #7). Enterprise value is **fleet visibility, faster response, and
provable audit**, not a false guarantee.

## Non-negotiable constraints (inherited from the security spine)

Every enterprise feature below must hold these, or it does not ship:

1. **Monotonic policy (spine #2).** An org/team policy may only *tighten* — escalate
   ambiguous → deny, require approval, narrow allows. It can **never unlock or
   downgrade a rule-based catastrophic block.** Central config is one more caution
   layer, never an override of the hard floor.
2. **Local-first stays the default.** Team/enterprise mode is strictly **opt-in,
   per-install, off by default.** A solo user never enrolls, never phones home.
3. **Append-only, verifiable audit (spine #4).** Off-box shipping forwards the
   existing hash chain; the collector **verifies** chains and detects tampering /
   truncation. It never rewrites history.
4. **No secret values egress (spine #5/#6).** Command *text* may be shipped to a
   user/org-configured endpoint; the *contents* of `.env`, keys, and credential
   stores never are. Secret-path detection redacts at the source before transport.
5. **Egress is configured, never phoned home (spine #5).** The only new outbound
   path is an org-configured collector/control-plane endpoint with pinned mTLS,
   off unless enrolled.
6. **Honest framing in all sales/compliance copy (spine #7).** We sell detection +
   reversibility + audit, and we document the bypass surface (yolo mode, absolute
   paths). We do not claim a firewall.

## Tiers

| Tier | Who | What |
|------|-----|------|
| **OSS core** (free, forever) | solo devs | today's local-first tool — gate, undo, local log, all agents |
| **Team** | small teams | signed central policy distribution + aggregated **read-only** audit |
| **Enterprise** | orgs / regulated | SSO/SCIM, RBAC, SIEM export, fleet management, compliance attestations, support SLA, air-gap |

The paid surface is the parts an organization needs and a solo dev does not:
**the control plane, cross-fleet audit, identity, and support.** The core stays free
and local — that is the trust and adoption flywheel, not a loss leader to nerf.

---

## Phases

Sequenced for **fastest credibility first**: "we can see what agents did across the
fleet" (E1+E2) unlocks the most procurement value for the least surface area. E0 is a
cheap prerequisite done alongside E1.

### E0 — Multi-tenant foundations *(prerequisite, small)*
- **Org-policy layer above local policy.** Precedence today is rules → policy →
  memory; insert an **org policy** layer that can only tighten (assert + test the
  merge is monotonic). `aegis policy show --effective` prints rules vs local vs org
  and *why* each verdict won.
- **Stable identity.** Per-install device id + optional org id (no PII; rotatable).
- **Signed, versioned policy bundle** format so a central policy is distributable and
  **verifiable offline** (works air-gapped).
- *Deliverable:* `org-policy.toml` schema + signature verification + `policy show
  --effective`; property test: org policy never downgrades a catastrophic.

### E1 — Off-box tamper-evident audit *(the CISO's #1 ask)*
- **`aegis-relay` log shipper (opt-in).** Forwards append-only event-log rows to a
  collector, **including the hash chain**, so the collector can verify integrity and
  flag a tampered or truncated local log.
- **Redaction at source.** Builds on existing secret-path handling; a configurable
  field policy enforces what may leave (default: no contents, ever).
- **Transport.** User/org-configured endpoint, pinned mTLS, retry/queue offline.
  Off by default.
- **Collector reference contract.** Thin server: stores per-device chains, exposes a
  read API + a per-device **verification status** (intact / broken / gapped).
- *Deliverable:* `aegis-relay` + documented collector contract + cross-device chain
  verification.

### E2 — SIEM / SOC integration
- **Export formats:** OCSF (preferred) + CEF + JSON for Splunk, Elastic, Datadog,
  Sentinel. `aegis export --format ocsf`.
- **Alert signals:** catastrophic-denied, panic-engaged, chain-verification-failed,
  undo-performed → webhook/syslog.
- **Reference dashboards:** agent activity across the fleet, blocked catastrophics
  over time, undo/restore events, policy-drift.
- *Deliverable:* documented field mappings + a sample Splunk/Elastic pipeline.

### E3 — Fleet management & policy distribution
- **Self-hostable control plane (read + policy push first).** Author org policy,
  push signed bundles to devices, see enrollment & health.
- **Enrollment:** `aegis enroll <token>` joins a machine to an org; devices pull the
  signed org policy on a schedule (and verify it offline).
- **Health/drift:** which devices are live, which agents are wired, chain status,
  last-seen, policy version in effect.
- *Deliverable:* self-hostable control plane + `aegis enroll`.

### E4 — Identity, access & approval workflows
- **SSO (OIDC/SAML) + SCIM** provisioning for the control plane.
- **RBAC:** separate who authors policy, who views audit, who may override a hold.
- **Remote approval:** route a held command to a human approver via Slack / Teams /
  PagerDuty — a natural extension of the existing **approval queue** (`aegis queue` /
  `approve` / `run`). Break-glass overrides are themselves logged + alertable.
- *Deliverable:* control-plane authz + remote-approval integration over the queue.

### E5 — Compliance & supply-chain trust
- **Attestations:** SOC 2 Type II for the control plane; a plain data-handling doc
  (exactly what is shipped, what is never shipped).
- **Supply chain:** cosign-signed binaries, SBOM, reproducible builds, and the
  existing pinned-checksum model-download story written up for procurement.
- **Threat model + pen-test** doc that formalizes the honest guarantee (spine #7) so
  security reviewers get a straight answer, not marketing.
- *Deliverable:* a public trust center; signed releases + SBOM in CI.

### E6 — Packaging & deployment
- **MDM-friendly install** (signed pkg/msi; Homebrew/winget already partly there);
  config via env / MDM profiles; zero-touch enrollment.
- **Air-gapped mode:** org policy + model bundle sideloaded, no egress at all — a
  first-class supported posture, not an afterthought (regulated buyers need it).
- *Deliverable:* MDM packages + an air-gap install guide.

---

## Business model notes

- **OSS core is free and local — permanently.** It is the credibility and adoption
  engine; nerfing it to upsell would kill the thing that makes Aegis spread.
- **Paid = control plane + cross-fleet audit + identity + support.** Orgs pay for
  central visibility and governance; solo devs never need it and never pay.
- **Self-host first, SaaS later.** Self-hosting the collector/control plane removes
  the biggest security objection ("your agent's commands go to a third party") and
  fits regulated buyers. A managed SaaS is a later convenience tier.

## What we will NOT do (protect the moat *and* the spine)

- Egress will **never** be default-on, and secret **values** will never leave a machine.
- Central policy will **never** unlock a catastrophic block (monotonic only).
- We will **not** claim prevention / "unbypassable firewall." Detective + reversible +
  auditable is the honest, defensible story — and it is what survives a security review.
- We will not fork the codebase into "open core that's deliberately broken." The paid
  surface is genuinely *additional* (the plane + audit), not crippleware.

## Suggested first slice (if/when we start)

E0 (monotonic org-policy layer + `policy show --effective`) **+** E1 (`aegis-relay`
shipper + a reference collector that verifies chains). That pair is the smallest thing
that turns "a great solo tool" into "a tool a security team can stand behind," and
both are pure additions that respect every spine rule above.
