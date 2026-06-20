"""AgentGuard Cloud Preview — a local stand-in for the M1 control plane.

A tiny ingest endpoint + live dashboard used to watch the agent's HTTPSink ship
redacted events in real time. This is a DEV/TEST harness, not the shipped agent:
it stores events in memory only and does no auth/persistence.

Run:
    pip install -r requirements.txt
    uvicorn server:app --port 8000

Then point an agent "https" sink at http://localhost:8000/api/ingest, restart
the daemon, generate events (./test.sh), and open http://localhost:8000.
"""

from __future__ import annotations

import asyncio
import json
from collections import deque
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

MAX_EVENTS = 1000

app = FastAPI(title="AgentGuard Cloud Preview")

# In-memory store, newest first. This is intentionally ephemeral — restart to clear.
events: deque[dict] = deque(maxlen=MAX_EVENTS)
# Live subscribers (one asyncio.Queue per open SSE connection).
subscribers: set[asyncio.Queue] = set()


@app.post("/api/ingest")
async def ingest(request: Request):
    """Receive one CloudEvent (or a JSON array of them) from the agent's HTTPSink."""
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid json"}, status_code=400)

    items = payload if isinstance(payload, list) else [payload]
    accepted = 0
    for ev in items:
        if not isinstance(ev, dict):
            continue
        ev["_received_at"] = datetime.now(timezone.utc).isoformat()
        events.appendleft(ev)
        accepted += 1
        for q in list(subscribers):
            q.put_nowait(ev)
    return {"accepted": accepted}


@app.get("/api/events")
async def list_events():
    """Return all buffered events (newest first) for the initial page load."""
    return JSONResponse(list(events))


@app.get("/api/stream")
async def stream():
    """Server-Sent Events feed: pushes each new event as it arrives."""
    q: asyncio.Queue = asyncio.Queue()
    subscribers.add(q)

    async def gen():
        try:
            yield ": connected\n\n"  # open the stream immediately
            while True:
                ev = await q.get()
                yield f"data: {json.dumps(ev)}\n\n"
        finally:
            subscribers.discard(q)

    return StreamingResponse(gen(), media_type="text/event-stream")


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(INDEX_HTML)


INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>AgentGuard · Cloud Preview</title>
<style>
  :root {
    --bg:#0b0f17; --panel:#131a26; --line:#1f2a3a; --txt:#e6edf5; --muted:#8aa0bd;
    --allow:#2ea043; --ask:#d29922; --deny:#f85149; --crit:#f85149; --accent:#3b82f6;
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--txt);
         font:14px/1.5 ui-sans-serif,-apple-system,Segoe UI,Roboto,sans-serif; }
  header { padding:18px 24px; border-bottom:1px solid var(--line);
           display:flex; align-items:center; gap:12px; }
  header h1 { font-size:16px; margin:0; font-weight:650; letter-spacing:.2px; }
  header .dot { width:9px; height:9px; border-radius:50%; background:var(--deny); }
  header .dot.live { background:var(--allow); box-shadow:0 0 0 4px rgba(46,160,67,.15); }
  header .sub { color:var(--muted); font-size:12px; }
  .cards { display:grid; grid-template-columns:repeat(6,1fr); gap:12px; padding:20px 24px; }
  .card { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:14px 16px; }
  .card .n { font-size:24px; font-weight:700; }
  .card .l { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.6px; margin-top:2px; }
  .card.deny .n { color:var(--deny); } .card.allow .n { color:var(--allow); }
  .card.ask .n { color:var(--ask); } .card.secrets .n { color:var(--crit); }
  .wrap { padding:0 24px 40px; }
  table { width:100%; border-collapse:collapse; background:var(--panel);
          border:1px solid var(--line); border-radius:12px; overflow:hidden; }
  th,td { text-align:left; padding:10px 14px; border-bottom:1px solid var(--line); vertical-align:top; }
  th { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.6px; }
  tr:last-child td { border-bottom:none; }
  td.mono { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12.5px; }
  .badge { display:inline-block; padding:2px 8px; border-radius:999px; font-size:11px; font-weight:650; }
  .b-allow { background:rgba(46,160,67,.15); color:var(--allow); }
  .b-ask   { background:rgba(210,153,34,.15); color:var(--ask); }
  .b-deny  { background:rgba(248,81,73,.15); color:var(--deny); }
  .b-bi    { background:rgba(59,130,246,.15); color:var(--accent); }
  .b-kf    { background:rgba(168,85,247,.18); color:#c084fc; }
  .muted   { color:var(--muted); }
  .sev { font-size:10.5px; padding:1px 7px; border-radius:999px; background:rgba(248,81,73,.12); color:var(--crit); }
  .agent { color:var(--accent); }
  .empty { padding:40px; text-align:center; color:var(--muted); }
  .findings { color:var(--muted); font-size:12px; }
  .flash { animation:flash 1s ease-out; }
  @keyframes flash { from { background:rgba(59,130,246,.18);} to { background:transparent;} }
</style>
</head>
<body>
<header>
  <span class="dot" id="dot"></span>
  <h1>AgentGuard <span class="sub">· Cloud Preview</span></h1>
  <span class="sub" id="status">connecting…</span>
</header>

<div class="cards">
  <div class="card"><div class="n" id="c-total">0</div><div class="l">Events</div></div>
  <div class="card allow"><div class="n" id="c-allow">0</div><div class="l">Allow</div></div>
  <div class="card ask"><div class="n" id="c-ask">0</div><div class="l">Ask</div></div>
  <div class="card deny"><div class="n" id="c-deny">0</div><div class="l">Deny</div></div>
  <div class="card secrets"><div class="n" id="c-secrets">0</div><div class="l">Secrets</div></div>
  <div class="card"><div class="n" id="c-devices">0</div><div class="l">Agents</div></div>
</div>

<div class="wrap">
  <table>
    <thead>
      <tr><th>Time</th><th>Agent</th><th>Tool</th><th>Decision</th><th>Source</th><th>Rule</th><th>Reason</th></tr>
    </thead>
    <tbody id="rows">
      <tr><td colspan="7" class="empty">No events yet — run <span class="mono">./test.sh</span> against the daemon.</td></tr>
    </tbody>
  </table>
</div>

<script>
const counts = { total:0, allow:0, ask:0, deny:0, secrets:0 };
const agents = new Set();
const rows = document.getElementById('rows');
let emptyShown = true;

function esc(s){ return (s==null?'':String(s)).replace(/[&<>]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
function fmtTime(ts){ try { return new Date(ts).toLocaleTimeString(); } catch { return ts||''; } }

function badge(d){
  const cls = d==='allow'?'b-allow':d==='ask'?'b-ask':'b-deny';
  return `<span class="badge ${cls}">${esc(d||'?')}</span>`;
}

function srcBadge(s){
  if (!s) return '<span class="muted">—</span>';
  const cls = s==='kingfisher' ? 'b-kf' : 'b-bi';
  return `<span class="badge ${cls}">${esc(s)}</span>`;
}

function render(ev, isNew){
  if (emptyShown){ rows.innerHTML=''; emptyShown=false; }

  counts.total++;
  if (ev.decision in counts) counts[ev.decision]++;
  const findingCount = Array.isArray(ev.findings) ? ev.findings.length : 0;
  if (findingCount > 0) counts.secrets += findingCount;
  else if (ev.severity === 'critical') counts.secrets += 1;
  if (ev.agent) agents.add(ev.agent);

  document.getElementById('c-total').textContent   = counts.total;
  document.getElementById('c-allow').textContent   = counts.allow;
  document.getElementById('c-ask').textContent     = counts.ask;
  document.getElementById('c-deny').textContent    = counts.deny;
  document.getElementById('c-secrets').textContent = counts.secrets;
  document.getElementById('c-devices').textContent = agents.size;

  const sev = ev.severity ? ` <span class="sev">${esc(ev.severity)}</span>` : '';
  const rule = ev.rule ? `<span class="mono">${esc(ev.rule)}</span>${sev}` : sev;
  const find = findingCount ? `<div class="findings">${findingCount} finding(s): ` +
      ev.findings.map(f=>esc(f.rule)+' ('+esc(f.source)+')').join(', ') + '</div>' : '';

  const tr = document.createElement('tr');
  if (isNew) tr.className = 'flash';
  tr.innerHTML =
    `<td class="mono">${fmtTime(ev.ts || ev._received_at)}</td>`+
    `<td class="agent">${esc(ev.agent||'—')}</td>`+
    `<td class="mono">${esc(ev.tool||'—')}</td>`+
    `<td>${badge(ev.decision)}</td>`+
    `<td>${srcBadge(ev.source)}</td>`+
    `<td>${rule||'—'}</td>`+
    `<td>${esc(ev.reason||'')}${find}</td>`;
  rows.insertBefore(tr, rows.firstChild);
}

// Initial load (newest first → render oldest first so newest ends up on top).
fetch('/api/events').then(r=>r.json()).then(list=>{
  list.slice().reverse().forEach(ev=>render(ev,false));
});

// Live stream.
const es = new EventSource('/api/stream');
es.onopen  = ()=>{ document.getElementById('dot').classList.add('live');
                   document.getElementById('status').textContent='live'; };
es.onerror = ()=>{ document.getElementById('dot').classList.remove('live');
                   document.getElementById('status').textContent='disconnected — retrying…'; };
es.onmessage = e=>{ try { render(JSON.parse(e.data), true); } catch {} };
</script>
</body>
</html>
"""
