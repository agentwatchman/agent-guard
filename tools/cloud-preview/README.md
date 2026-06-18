# Cloud Preview — local control-plane stand-in

A tiny ingest endpoint + live dashboard for watching the agent's **HTTPSink**
ship redacted events in real time. It's a **dev/test harness** — events live in
memory only, there's no auth or persistence — used to exercise the data-plane
path (`internal/cloud/httpsink.go`) before the real cloud exists.

```
agentguard daemon ──HTTP POST /api/ingest──> this server ──SSE──> browser dashboard
```

## 1. Start the preview server

```bash
cd tools/cloud-preview
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn server:app --port 8000
```

Open <http://localhost:8000> — it'll say "connecting…" until events arrive.

## 2. Point the agent at it

Add an `https` sink to the config the daemon runs with (`config.json` for
`make run`, or `~/.agentguard/config.json` for the installed service). You can
keep the local `file` sink too — the shipper fans out to both:

```json
{
  "allowed_egress": ["github.com", "api.github.com", "registry.npmjs.org", "pypi.org", "files.pythonhosted.org"],
  "approved_mcp": ["github", "linear"],
  "cloud": {
    "enabled": true,
    "sinks": [
      { "name": "local",   "type": "file" },
      { "name": "preview", "type": "https", "endpoint": "http://localhost:8000/api/ingest" }
    ]
  }
}
```

> The shipper is built once at daemon start, so set the sink **before** running.

## 3. Run the daemon and generate events

```bash
make run          # terminal 1 — look for: msg="cloud shipping enabled"
./test.sh         # terminal 2 — fires sample tool calls
```

You can also fire a secret-scan event directly:

```bash
curl -s --unix-socket ~/.agentguard/agentguard.sock http://unix/v1/scan \
  -H 'Content-Type: application/json' \
  -d '{"text":"my key is AKIAIOSFODNN7EXAMPLE","agent":"cursor"}'
```

Watch rows stream into the dashboard. Note what's there — tool, decision, rule,
severity, finding source/rule — and what's **not**: no raw secret value, command
string, full path, or prompt text. That's the redaction boundary doing its job.

## Endpoints

| Method | Path           | Purpose                                  |
|--------|----------------|------------------------------------------|
| POST   | `/api/ingest`  | receives a `CloudEvent` (or array) from the agent |
| GET    | `/api/events`  | buffered events as JSON (initial load)   |
| GET    | `/api/stream`  | Server-Sent Events feed (live updates)   |
| GET    | `/`            | the dashboard                            |

## Not included (on purpose)

This is a harness, not the product. Real M1 adds: enrollment → device tokens,
schema validation that rejects unknown fields, Postgres/RLS persistence, and
per-org finding-hash salting. See [`docs/cloud-mvp.md`](../../docs/cloud-mvp.md).
