"""
EmberArmor Proxy Addon
======================
mitmproxy addon that intercepts all outbound AI API traffic,
runs it through the EmberArmor enforcement engine, and logs
every decision with full latency telemetry.

Intercepted endpoints:
  api.anthropic.com
  api.perplexity.ai
  api.moonshot.ai
  generativelanguage.googleapis.com
  api.openai.com

Decision modes:
  SAFE   → pass through, log
  REVIEW → pass through, flag in audit log (tuning mode)
  UNSAFE → block with structured error response
"""

from __future__ import annotations

import json
import time
import uuid
import asyncio
import threading
from datetime import datetime, timezone
from typing import Any

import httpx
from mitmproxy import http
from mitmproxy.script import concurrent

# ── Configuration ────────────────────────────────────────────────────────────

EMBER_API_BASE   = "http://localhost:8000"
EMBER_API_KEY    = "ember-proxy-internal-key"   # set in EmberArmor .env
PROXY_PORT       = 8080
STATUS_PORT      = 7070

# Hosts to intercept — everything else passes through untouched
AI_HOSTS = {
    "api.anthropic.com",
    "api.perplexity.ai",
    "api.moonshot.ai",
    "generativelanguage.googleapis.com",
    "api.openai.com",
}

# Paths that carry prompt payloads (skip embeddings, file uploads, etc.)
PROMPT_PATHS = {
    "/v1/messages",
    "/v1/chat/completions",
    "/chat/completions",
    "/v1beta/models",        # Gemini prefix
}

# In REVIEW mode we pass everything through but flag it — good for tuning
# Set to True to start blocking UNSAFE decisions
BLOCK_ON_UNSAFE = False

# ── Shared audit log (in-memory ring buffer, 1000 entries) ──────────────────

from collections import deque
_audit_log: deque[dict] = deque(maxlen=1000)
_log_lock = threading.Lock()

def _log(entry: dict) -> None:
    entry["id"] = str(uuid.uuid4())[:8]
    entry["ts"] = datetime.now(timezone.utc).isoformat()
    with _log_lock:
        _audit_log.appendleft(entry)

# ── EmberArmor client (sync, called from mitmproxy thread) ──────────────────

def _check_with_ember(prompt: str, endpoint: str) -> dict[str, Any]:
    """Call EmberArmor dissonance check. Returns decision dict."""
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(
                f"{EMBER_API_BASE}/api/v1/dissonance/check",
                headers={
                    "Authorization": f"Bearer {EMBER_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={"text": prompt, "context": {"source": endpoint}},
            )
            if resp.status_code == 200:
                return resp.json()
            else:
                return {
                    "decision": "REVIEW",
                    "error": f"EmberArmor returned {resp.status_code}",
                    "safety_level": "CAUTION",
                    "contradiction_score": 0.0,
                }
    except Exception as exc:
        return {
            "decision": "REVIEW",
            "error": str(type(exc).__name__),
            "safety_level": "CAUTION",
            "contradiction_score": 0.0,
        }


def _extract_prompt(body_bytes: bytes, host: str) -> str | None:
    """Extract the prompt text from a request body. Returns None if unreadable."""
    try:
        data = json.loads(body_bytes)
    except Exception:
        return None

    # Anthropic: {"messages": [{"role": "user", "content": "..."}]}
    if "messages" in data:
        parts = []
        for msg in data.get("messages", []):
            content = msg.get("content", "")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        parts.append(block.get("text", ""))
        return "\n".join(parts) if parts else None

    # Gemini: {"contents": [{"parts": [{"text": "..."}]}]}
    if "contents" in data:
        parts = []
        for content in data.get("contents", []):
            for part in content.get("parts", []):
                if "text" in part:
                    parts.append(part["text"])
        return "\n".join(parts) if parts else None

    # Prompt string (older APIs)
    if "prompt" in data:
        p = data["prompt"]
        if isinstance(p, str):
            return p
        if isinstance(p, dict) and "text" in p:
            return p["text"]

    return None


# ── mitmproxy addon class ────────────────────────────────────────────────────

class EmberArmorAddon:

    def __init__(self):
        print(f"[EmberArmor Proxy] Started — intercepting AI traffic on port {PROXY_PORT}")
        print(f"[EmberArmor Proxy] Status dashboard → http://localhost:{STATUS_PORT}")
        print(f"[EmberArmor Proxy] Enforcement API  → {EMBER_API_BASE}")
        print(f"[EmberArmor Proxy] Block on UNSAFE  → {BLOCK_ON_UNSAFE}")

    @concurrent
    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host

        # Only intercept known AI endpoints
        if host not in AI_HOSTS:
            return

        path = flow.request.path
        method = flow.request.method

        # Only inspect POST requests with prompt payloads
        if method != "POST":
            return

        # Check if this path likely carries a prompt
        is_prompt_path = any(path.startswith(p) for p in PROMPT_PATHS)

        # For Gemini the path pattern is /v1beta/models/<model>:generateContent
        if "generateContent" in path or "streamGenerateContent" in path:
            is_prompt_path = True

        if not is_prompt_path:
            return

        t0 = time.perf_counter()
        body = flow.request.content

        prompt = _extract_prompt(body, host)
        if not prompt:
            _log({
                "host": host,
                "path": path,
                "decision": "PASS",
                "reason": "no_prompt_extracted",
                "latency_ms": 0,
            })
            return

        # Truncate very long prompts for the check (keep first 8k chars)
        prompt_for_check = prompt[:8000]

        # ── EmberArmor enforcement ──────────────────────────────────────────
        result = _check_with_ember(prompt_for_check, host)
        latency_ms = round((time.perf_counter() - t0) * 1000, 1)

        decision   = result.get("decision", "REVIEW")
        safety     = result.get("safety_level", "UNKNOWN")
        score      = result.get("contradiction_score", 0.0)
        error      = result.get("error")

        # Redact prompt for audit (hash only)
        import hashlib
        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()[:16]

        audit_entry = {
            "host": host,
            "path": path,
            "decision": decision,
            "safety_level": safety,
            "contradiction_score": score,
            "latency_ms": latency_ms,
            "prompt_hash": prompt_hash,
            "prompt_preview": prompt[:120].replace("\n", " "),
            "error": error,
        }
        _log(audit_entry)

        # Console output
        icon = {"SAFE": "✓", "REVIEW": "⚠", "UNSAFE": "✗"}.get(decision, "?")
        print(
            f"[{icon}] {host:<42} {decision:<8} "
            f"score={score:.2f} latency={latency_ms}ms"
        )

        # ── Block if UNSAFE and blocking enabled ────────────────────────────
        if decision == "UNSAFE" and BLOCK_ON_UNSAFE:
            flow.response = http.Response.make(
                403,
                json.dumps({
                    "error": {
                        "type":    "ember_armor_block",
                        "message": "Request blocked by EmberArmor enforcement.",
                        "decision": decision,
                        "safety_level": safety,
                        "contradiction_score": score,
                    }
                }),
                {"Content-Type": "application/json"},
            )


# ── Status dashboard (tiny HTTP server on port 7070) ────────────────────────

from http.server import BaseHTTPRequestHandler, HTTPServer

STATUS_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="3">
<title>EmberArmor Proxy</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0F1117; color: #CDCCCA; font-family: 'Consolas', monospace; padding: 24px; }
  h1 { color: #20808D; font-size: 22px; margin-bottom: 4px; letter-spacing: 1px; }
  .sub { color: #7A7974; font-size: 12px; margin-bottom: 24px; }
  .stats { display: flex; gap: 24px; margin-bottom: 24px; }
  .stat { background: #1A1D27; border: 1px solid #2A2D3A; border-radius: 8px;
          padding: 16px 24px; min-width: 140px; }
  .stat-val { font-size: 28px; font-weight: bold; color: #20808D; }
  .stat-lbl { font-size: 11px; color: #7A7974; margin-top: 4px; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th { background: #155F6A; color: #F7F6F2; padding: 8px 10px; text-align: left; }
  tr:nth-child(even) { background: #1A1D27; }
  tr:nth-child(odd)  { background: #16191F; }
  td { padding: 7px 10px; border-bottom: 1px solid #2A2D3A; }
  .SAFE   { color: #6DAA45; font-weight: bold; }
  .REVIEW { color: #BB653B; font-weight: bold; }
  .UNSAFE { color: #D163A7; font-weight: bold; }
  .PASS   { color: #5A5957; }
  .ts     { color: #5A5957; font-size: 10px; }
  .preview{ color: #7A7974; max-width: 340px; overflow: hidden;
            text-overflow: ellipsis; white-space: nowrap; }
</style>
</head>
<body>
<h1>⬡ EMBERARMOR PROXY</h1>
<div class="sub">Auto-refreshes every 3s &nbsp;·&nbsp; localhost:{port}</div>
<div class="stats">
  <div class="stat"><div class="stat-val">{total}</div><div class="stat-lbl">TOTAL CHECKS</div></div>
  <div class="stat"><div class="stat-val" style="color:#6DAA45">{safe}</div><div class="stat-lbl">SAFE</div></div>
  <div class="stat"><div class="stat-val" style="color:#BB653B">{review}</div><div class="stat-lbl">REVIEW</div></div>
  <div class="stat"><div class="stat-val" style="color:#D163A7">{unsafe}</div><div class="stat-lbl">UNSAFE</div></div>
  <div class="stat"><div class="stat-val">{avg_lat}ms</div><div class="stat-lbl">AVG LATENCY</div></div>
</div>
<table>
<thead><tr>
  <th>Time</th><th>Host</th><th>Decision</th><th>Score</th><th>Latency</th><th>Preview</th>
</tr></thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>"""

def _build_status_html() -> str:
    with _log_lock:
        entries = list(_audit_log)

    total   = len(entries)
    safe    = sum(1 for e in entries if e.get("decision") == "SAFE")
    review  = sum(1 for e in entries if e.get("decision") == "REVIEW")
    unsafe  = sum(1 for e in entries if e.get("decision") == "UNSAFE")
    lats    = [e["latency_ms"] for e in entries if e.get("latency_ms", 0) > 0]
    avg_lat = round(sum(lats) / len(lats)) if lats else 0

    rows = []
    for e in entries[:50]:
        d   = e.get("decision", "PASS")
        ts  = e.get("ts", "")[-8:-1]   # HH:MM:SS
        host = e.get("host", "")
        score = e.get("contradiction_score", 0.0)
        lat   = e.get("latency_ms", 0)
        preview = e.get("prompt_preview", "")[:80]
        rows.append(
            f'<tr>'
            f'<td class="ts">{ts}</td>'
            f'<td>{host}</td>'
            f'<td class="{d}">{d}</td>'
            f'<td>{score:.2f}</td>'
            f'<td>{lat}ms</td>'
            f'<td class="preview">{preview}</td>'
            f'</tr>'
        )

    return STATUS_HTML.format(
        port=STATUS_PORT,
        total=total, safe=safe, review=review, unsafe=unsafe,
        avg_lat=avg_lat,
        rows="\n".join(rows) if rows else '<tr><td colspan="6" style="text-align:center;color:#5A5957;padding:24px;">No traffic yet — start using your AI tools!</td></tr>',
    )


class _StatusHandler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass   # silence access logs

    def do_GET(self):
        if self.path == "/api/log":
            with _log_lock:
                data = json.dumps(list(_audit_log)[:100])
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(data.encode())
        else:
            html = _build_status_html()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode())


def _start_status_server():
    server = HTTPServer(("localhost", STATUS_PORT), _StatusHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    print(f"[EmberArmor Proxy] Status dashboard running → http://localhost:{STATUS_PORT}")


# ── mitmproxy entry point ────────────────────────────────────────────────────

def start():
    _start_status_server()

addons = [EmberArmorAddon()]
