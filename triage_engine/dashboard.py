"""Embedded zero-dependency AI-NOC Triage Web Console (HTTP + JSON API)."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
from typing import Any

from .storage import IncidentStore

CONSOLE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AI-Powered NOC Incident Triage Console</title>
  <style>
    :root { --bg:#070b14; --panel:#111827; --border:#1f2937; --text:#e5e7eb; --muted:#9ca3af; --sev1:#ef4444; --sev2:#f59e0b; --sev3:#38bdf8; --ok:#22c55e; }
    * { box-sizing:border-box; margin:0; padding:0; }
    body { font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,monospace; background:var(--bg); color:var(--text); padding:24px; line-height:1.5; }
    header { display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px; padding-bottom:16px; margin-bottom:20px; border-bottom:1px solid var(--border); }
    h1 { font-size:1.35rem; color:#f8fafc; }
    .sub { color:var(--muted); font-size:0.85rem; }
    .kpis { display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:14px; margin-bottom:22px; }
    .kpi { background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:16px; }
    .kpi-l { color:var(--muted); font-size:0.75rem; text-transform:uppercase; letter-spacing:0.06em; }
    .kpi-v { font-size:1.7rem; font-weight:700; margin-top:6px; }
    .card { background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:18px; margin-bottom:16px; }
    .card-top { display:flex; justify-content:space-between; align-items:center; gap:10px; flex-wrap:wrap; margin-bottom:10px; }
    .badge { padding:3px 9px; border-radius:999px; font-size:0.74rem; font-weight:700; margin-right:6px; }
    .SEV-1 { background:rgba(239,68,68,.16); color:var(--sev1); border:1px solid rgba(239,68,68,.4); }
    .SEV-2 { background:rgba(245,158,11,.16); color:var(--sev2); border:1px solid rgba(245,158,11,.4); }
    .SEV-3 { background:rgba(56,189,248,.16); color:var(--sev3); border:1px solid rgba(56,189,248,.4); }
    .pill { background:rgba(34,197,94,.12); color:var(--ok); border:1px solid rgba(34,197,94,.35); padding:2px 8px; border-radius:6px; font-size:0.74rem; }
    h3 { font-size:1rem; color:#f8fafc; }
    .lbl { color:#93c5fd; font-size:0.78rem; text-transform:uppercase; margin-top:12px; margin-bottom:4px; font-weight:700; }
    ul, ol { margin-left:20px; font-size:0.87rem; color:#d1d5db; }
    pre { background:#0b1120; border:1px solid var(--border); padding:10px; border-radius:8px; overflow-x:auto; color:#7dd3fc; font-size:0.82rem; margin-top:6px; }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>AI-POWERED NOC INCIDENT TRIAGE CONSOLE</h1>
      <div class="sub">Tier-1 Deterministic Telemetry &amp; PCAP Forensics &rarr; Tier-2 Multi-Provider LLM RCA Synthesis</div>
    </div>
    <span class="pill" id="sync">Live &middot; Syncing</span>
  </header>
  <div class="kpis" id="kpis"></div>
  <div id="feed"></div>
  <script>
    const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
    async function load() {
      const res = await fetch("/api/incidents");
      const data = await res.json();
      const m = data.metrics || {};
      document.getElementById("kpis").innerHTML = `
        <div class="kpi"><div class="kpi-l">Triaged Incidents</div><div class="kpi-v">${m.total_incidents ?? 0}</div></div>
        <div class="kpi"><div class="kpi-l">Critical (SEV-1)</div><div class="kpi-v" style="color:var(--sev1)">${m.sev1_count ?? 0}</div></div>
        <div class="kpi"><div class="kpi-l">High (SEV-2)</div><div class="kpi-v" style="color:var(--sev2)">${m.sev2_count ?? 0}</div></div>
        <div class="kpi"><div class="kpi-l">Tier-1 Token Savings</div><div class="kpi-v" style="color:var(--ok)">${m.token_savings_pct ?? 0}%</div></div>
      `;
      const items = data.incidents || [];
      document.getElementById("feed").innerHTML = items.length ? items.map(i => `
        <div class="card">
          <div class="card-top">
            <div><span class="badge ${esc(i.severity)}">${esc(i.severity)}</span><span class="pill">${esc(i.osi_layer)} · ${esc(i.category)}</span> <strong>${esc(i.title)}</strong></div>
            <div class="sub">${esc(i.incident_id)} · Engine: ${esc(i.engine_used)} (${Math.round((i.confidence||0)*100)}%)</div>
          </div>
          <div class="lbl">Root Cause Analysis</div>
          <p style="font-size:0.9rem">${esc(i.root_cause)}</p>
          <div class="lbl">Wire / Telemetry Evidence</div>
          <ul>${(i.evidence||[]).map(e => `<li>${esc(e)}</li>`).join("")}</ul>
          <div class="lbl">Remediation Runbook</div>
          <ol>${(i.remediation_steps||[]).map(s => `<li>${esc(s)}</li>`).join("")}</ol>
          <div class="lbl">Verification Commands</div>
          <pre>${(i.verification_commands||[]).map(esc).join("\\n")}</pre>
        </div>
      `).join("") : '<div class="card sub">No incidents triaged yet. Run `python triage_bot.py --demo`.</div>';
      document.getElementById("sync").textContent = "Live · " + new Date().toISOString().slice(11,19) + "Z";
    }
    load();
    setInterval(load, 5000);
  </script>
</body>
</html>
"""


def start_console_server(store: IncidentStore, host: str = "127.0.0.1", port: int = 8085) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, _fmt: str, *_args: Any) -> None:
            return

        def _send(self, code: int, ctype: str, body: bytes) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path in ("/", "/index.html"):
                self._send(200, "text/html; charset=utf-8", CONSOLE_HTML.encode("utf-8"))
            elif self.path == "/api/incidents":
                payload = {"metrics": store.get_metrics(), "incidents": store.list_incidents(limit=30)}
                self._send(200, "application/json; charset=utf-8", json.dumps(payload).encode("utf-8"))
            elif self.path == "/healthz":
                self._send(200, "application/json; charset=utf-8", b'{"status":"ok"}')
            else:
                self._send(404, "application/json; charset=utf-8", b'{"error":"Not Found"}')

    srv = ThreadingHTTPServer((host, port), Handler)
    threading.Thread(target=srv.serve_forever, name="ai-noc-console", daemon=True).start()
    return srv
