# AgentGuard Cloud — MVP Design

Status: **M0 built** (agent-side redaction pipeline + local sink); M1+ planning.
Owner: TBD. Last updated: 2026-06-18.

This document sketches the smallest **sellable** cloud layer on top of the local
AgentGuard agent, and the agent-side changes required to feed it — without ever
weakening the local privacy or enforcement guarantees.

---

## 1. Positioning (open-core)

Three layers, deliberately separated:

| Layer | Role | Pricing |
|---|---|---|
| **Local enforcement** (this repo) | Hooks + policy engine + secret scanners. Fail-closed, offline, standalone. | Free / open — the distribution wedge |
| **Control plane** (this doc) | Fleet visibility, central policy, compliance evidence, retained audit | **Paid** — the product |
| **Integrations** | MDM, SIEM, Slack/Jira, SSO/SCIM | **Paid** — the lock-in |

Pitch: *"Deploy AgentGuard across your dev fleet; see every secret your AI agents
tried to leak, set policy once, get alerted — and secrets never leave the machine."*

**Non-negotiable invariants:**
1. Enforcement **never** depends on the cloud. If the cloud is down, the agent
   still blocks (it already fails closed locally).
2. The cloud is a **redacted, additive read + policy layer**. Raw secrets,
   prompts, commands, and file contents never leave the machine.
3. Cross-agent & vendor-neutral: one policy/audit plane across Claude Code,
   Cursor, and whatever comes next.

---

## 2. Architecture

```
┌─────────────────────── developer machine ───────────────────────┐
│  Claude Code / Cursor ── hooks ──> agentguard daemon             │
│                                      │                           │
│                          Evaluate() / Scan()                     │
│                                      │                           │
│                          audit.Evaluate / audit.Scan  ──> audit.log (local, full)
│                                      │                           │
│                          redact()  ── allowlist only ──┐         │
│                                      │                  │         │
│                          event shipper (offline buffer)│         │
└──────────────────────────────────────────────────────│─────────┘
                                                         │ HTTPS + device token
                                                         ▼
                                      ┌──────── AgentGuard Cloud ────────┐
                                      │  ingest API ──> Postgres (Supabase)│
                                      │  dashboard (Next.js)              │
                                      │  policy push  ──────────┐         │
                                      │  Slack alerts           │         │
                                      └─────────────────────────│─────────┘
                                                                ▲
                            agent polls for policy/suppressions │
```

Key point: the **local audit log stays complete**; only the `redact()` output is
shipped. The shipper is on a side path — it can fail, lag, or be disabled with
zero effect on enforcement.

---

## 3. Redacted event schema (the contract)

This is the **only** shape that leaves the machine. Anything not on this list is
a bug (see §5 redaction test).

```jsonc
{
  "schema": 1,
  "event_id": "uuid",            // client-generated, idempotency key
  "ts": "2026-06-17T15:07:58Z",
  "device_id": "uuid",           // from enrollment, not PII
  "org_id": "uuid",              // from enrollment token
  "agent": "cursor",             // claude-code | cursor | codex
  "tool": "Prompt",              // Prompt | Bash | Read | mcp__<server>__<tool>
  "decision": "deny",            // allow | deny | ask
  "reason": "2 secrets detected in prompt (AWS access key id, GitLab Private Token)",
  "source": "builtin",           // first finding's backend
  "rule": "AWS access key id",   // first finding's rule
  "findings": [
    { "source": "builtin",    "rule": "AWS access key id",     "hash": "sha256:<salted>" },
    { "source": "kingfisher", "rule": "GitLab Private Token",  "hash": "sha256:<salted>" }
  ],
  "cwd_base": "fagent",          // basename ONLY — never the full path
  "agent_version": "0.1.0"
}
```

**Never shipped:** raw secret values, raw prompt text, full file paths, file
contents, command strings, `session_id` (or only a salted hash of it).

**`hash`** = `sha256(org_salt || secret_value)`, truncated. Lets the cloud answer
"same secret seen on N machines / still leaking after rotation" **without ever
transmitting or storing the value**. `org_salt` is per-org and server-held so
hashes aren't brute-forceable across tenants. (Computing the hash means the agent
must briefly hold the matched substring — acceptable, it already does during
scanning — but it is discarded immediately and never logged.)

---

## 4. Agent-side work (Go, this repo)

Small, self-contained additions. Maps onto existing code. **Items 1–3 are built
(M0)**; the file/queue/enrollment details below note where M0 reality and the
forward-looking design differ.

1. **`RedactEvaluate` / `RedactScan` → `CloudEvent`** (`internal/cloud/redact.go`,
   built) — the single redaction boundary. Builds the §3 struct from the same data
   `audit.Evaluate` / `audit.Scan` (`internal/audit/audit.go`) already record. The
   local audit log is unchanged; redaction is a *second*, stricter projection.
2. **Event shipper** (`internal/cloud/shipper.go`, built): a `Shipper` fed by a
   bounded **in-memory** queue (`queueDepth`, drop-*newest* on overflow with a
   counter) drained by a background goroutine, fanning each event out to one or
   more `Sink`s. Never blocks the hook path. Two sink types implement the `Sink`
   interface: `FileSink` (M0 — NDJSON at `~/.agentguard/events.ndjson`) and
   `HTTPSink` (`internal/cloud/httpsink.go` — POSTs each event to an ingest
   endpoint with an optional bearer token; bounded timeout + a few quick retries).
   *Still deferred:* a durable on-disk replay queue (`~/.agentguard/queue/`) with
   long per-sink backoff so events survive the daemon being offline.
3. **Config** (`CloudConfig`/`CloudSink` in `internal/types/types.go` + `config.json`,
   built; off by default): add
   ```jsonc
   "cloud": {
     "enabled": false,
     "sinks": [
       {
         "name": "local",          // M0 (built): local NDJSON, zero infra
         "type": "file",
         "path": ""                // defaults to ~/.agentguard/events.ndjson
       },
       {
         "name": "agentguard",     // HTTPSink (built): POSTs events to an ingest API
         "type": "https",
         "endpoint": "https://ingest.agentguard.dev",
         "enrollment_token": "",   // sent as Bearer; future: exchanged for a device token
         "org_salt": ""            // provisioned at enrollment, per sink (not yet used)
       }
       // add a second sink here for a customer's self-hosted plane / SIEM
     ]
   }
   ```
   Defaults off (`enabled:false` / empty `sinks`) → the OSS agent is cloud-free
   unless enrolled. Unknown sink types are skipped with a warning rather than
   failing the daemon. For local end-to-end testing of the HTTPS sink, point
   `endpoint` at the preview server in `tools/cloud-preview/`.
4. **Enrollment**: `agentguard enroll --token <org-token> [--sink <name>]` → calls
   that sink's endpoint, stores `device_id` + device token + `org_salt` against the
   named sink locally. One-time per sink.
5. **Policy pull**: periodic GET of org policy (allowlists + **suppressions**),
   merged into the local `Config` and hot-reloaded. This is the false-positive
   escape hatch flowing back from the dashboard.

> Suppression model to add locally: a `suppressed_rules` list (by `rule` /
> `rule_id`) checked in the merge step of `handleScan` before a finding blocks.

### 4a. Multi-sink fan-out

A single agent can ship to **more than one destination** — e.g. AgentGuard SaaS
*and* a customer's self-hosted control plane or their SIEM. The design rule:

- **One `redact()` boundary, fan out after.** The redaction happens exactly once
  (§5); the resulting allowlisted event is then delivered to every configured
  sink. Never redact per-sink — that would fork the privacy guarantee and the
  redaction test would no longer cover every egress path.
- **Per-sink credentials.** Each sink carries its own `enrollment_token` (→ device
  token) and `org_salt`. A customer key is therefore scoped to one sink; rotating
  or revoking one never affects another.
- **Per-sink delivery state.** Each sink gets its own retry/backoff cursor over the
  shared on-disk queue, so a slow or down sink never blocks the others. An event is
  only evicted from the queue once **all** sinks have acked it (or it ages out).
- **Per-sink hashes.** Because `org_salt` is per sink, the finding `hash` (§3) is
  computed per sink — the same secret produces different hashes for different
  planes, so no sink can correlate across tenants.

```
                         ┌─> sink: agentguard SaaS   (token A, salt A)
hook ─> daemon ─> redact ┤
                         └─> sink: customer SIEM     (token B, salt B)
```

The dashboard (§6) shows the sink `name` on each device so operators can see where
a given device is reporting.

---

## 5. Privacy / redaction guarantee (the security story)

This is the differentiator vs. cloud-proxy DLP. Make it **provable**:

- A single `redact()` boundary — nothing else may construct an outbound payload.
  This is what makes multi-sink fan-out (§4a) safe: every sink receives the output
  of the *same* redaction, so the guarantee covers all egress paths at once.
- A **redaction test** (`cloud_test.go`): feed events containing known secret
  values, raw prompts, and full paths through `redact()` + the serializer, then
  assert the output bytes contain **none** of those substrings. Fail the build
  otherwise. Ship this test result/coverage as a trust artifact.
- Document the field allowlist (§3) publicly.
- Optional: **tamper-evidence** — hash-chain local audit records (`prev_hash`),
  verify server-side; detects gaps/edits.

---

## 6. Cloud MVP (Next.js + Supabase)

Stack chosen for speed-to-sellable. Supabase gives Postgres + auth + RLS.

### Data model (Postgres)
- `orgs(id, name, salt, created_at)`
- `users(id, org_id, email, role)` — via Supabase auth
- `devices(id, org_id, sink_name, hostname_hash, last_seen, agent_version, token_hash)`
- `events(id, org_id, device_id, ts, agent, tool, decision, source, rule, reason, cwd_base, schema)`
- `finding(id, event_id, source, rule, hash)`
- `policies(org_id, json, version, updated_at)` — allowlists + suppressions
- Row-Level Security keyed on `org_id` everywhere.

### Ingest API
- `POST /api/ingest` — device-token auth, validates against §3 schema, dedupes on
  `event_id`, bulk-insert. Rejects any unknown field (defense in depth).
- `GET /api/policy?version=` — returns org policy if newer (the agent's pull).
- `POST /api/enroll` — exchanges org enrollment token for `device_id` + token + `org_salt`.

### Dashboard (Next.js)
- **Overview**: blocks over time, total secrets prevented, active devices.
- **Events table**: filter by agent / source / rule / decision / device / time.
- **Insights**: top rules firing, builtin-vs-kingfisher split, claude-vs-cursor
  split, **noisiest rules** (false-positive candidates → one-click suppress).
- **Devices**: roster, last-seen, version (stale-agent visibility).
- **Policy editor**: allowlists + suppressions; publishes a new `policies.version`
  that agents pull.

### First integration
- **Slack**: webhook alert when `decision=deny` and a finding looks like a *real*
  leak (e.g. high-confidence rule). One integration is enough to prove value.

---

## 7. Security & ops considerations

- TLS only; device tokens are bearer creds — store hashed, support revoke.
- Per-org salt for finding hashes; never expose salt to clients beyond their org.
- Rate-limit ingest per device; cap payload size.
- Data retention policy + per-org export (compliance ask).
- Offline-first: agent buffers and replays; ingest is idempotent on `event_id`.
- Backpressure: bounded local queue, drop-oldest, surface a "dropped N" counter.

---

## 8. Phased roadmap

- **M0 — Agent pipeline (no cloud): ✅ built.** `RedactEvaluate`/`RedactScan`
  (`internal/cloud/redact.go`), `Shipper` + `FileSink` writing local NDJSON
  (`internal/cloud/shipper.go`), `cloud` config (off by default), and the
  **redaction trust test** (`internal/cloud/redact_test.go`). Validates the
  contract with zero infra.
- **M1 — Ingest + store:** *in progress.* Agent ships over HTTPS via `HTTPSink`
  (`internal/cloud/httpsink.go`, built) and a local preview ingest + dashboard
  exists (`tools/cloud-preview/`). *Remaining:* real Supabase schema + persistent
  `POST /api/ingest`, enrollment → device tokens, idempotency on `event_id`.
- **M2 — Dashboard read views:** overview, events table, insights.
- **M3 — Policy push + suppressions:** dashboard editor → agent pull → local
  suppression enforcement.
- **M4 — Slack alerting.**
- **Post-MVP (deferred):** SSO/SCIM, MDM (Jamf/Intune) packaging, SIEM exports
  (Splunk/Datadog/Sentry), Jira/Linear, tamper-evidence verification UI.

---

## 9. Open decisions

- Hosting for ingest/dashboard (Vercel + Supabase cloud vs. self-host option for
  security-sensitive buyers — some will *require* self-host). Multi-sink (§4a)
  makes "SaaS **and** self-hosted at once" a first-class config, not a fork.
- Do we offer a **self-hosted control plane** tier? (Likely yes for enterprise.)
- Multi-sink limits: cap the number of sinks per device? Per-sink event filtering
  (e.g. only ship `deny` events to a customer's SIEM)?
- Finding-hash scheme: per-org salt only, or per-org + rotation?
- Pricing unit: per-device, per-seat, or per-org tier.
- How much of the agent↔cloud protocol to open-source (spec it so the OSS agent
  can talk to a self-hosted plane).
