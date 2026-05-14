"""FastAPI application entry point.

Phase 1 wires the minimum middleware stack: CORS + structured request logging.
Phases 4 and 5 will layer on WAF, rate limiter, audit, and Prometheus.
"""
from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from uuid import uuid4

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from agentforge import __version__
from agentforge.api import auth as auth_router
from agentforge.api import campaigns, findings, health, observability, regression
from agentforge.config import get_settings
from agentforge.db.database import dispose_engine
from agentforge.errors import register_exception_handlers
from agentforge.observability.metrics import MetricsMiddleware, metrics_response
from agentforge.observability.structured_log import configure_logging
from agentforge.observability.tracing import flush_traces
from agentforge.security.audit_log import AuditMiddleware
from agentforge.security.rate_limiter import RateLimitMiddleware
from agentforge.security.waf import WAFMiddleware

logger = logging.getLogger("agentforge")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    # Structured logging is set up here (not at import) so test runs that
    # don't import main keep their stdlib basicConfig.
    configure_logging(level=settings.log_level, json_output=settings.is_production)
    logger.info("agentforge starting environment=%s version=%s", settings.environment, __version__)
    try:
        yield
    finally:
        logger.info("agentforge shutting down — disposing DB pool")
        flush_traces()
        await dispose_engine()


class RequestLogMiddleware(BaseHTTPMiddleware):
    """Structured per-request log line + correlation ID.

    Why placeholder: Phase 5 will replace this with structlog + JSON output and
    add Prometheus timing histograms. For Phase 1 we just need a request ID
    plumbed through so health-check failures can be traced.
    """

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        request_id = request.headers.get("X-Request-ID") or uuid4().hex
        request.state.request_id = request_id
        start = time.perf_counter()
        try:
            response: Response = await call_next(request)
        except Exception:
            logger.exception("request_failed request_id=%s path=%s", request_id, request.url.path)
            raise
        elapsed_ms = (time.perf_counter() - start) * 1000
        response.headers["X-Request-ID"] = request_id
        logger.info(
            "http_request method=%s path=%s status=%s duration_ms=%.1f request_id=%s",
            request.method,
            request.url.path,
            response.status_code,
            elapsed_ms,
            request_id,
        )
        return response


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="AgentForge",
        version=__version__,
        description="Multi-agent adversarial evaluation platform for the OpenEMR Clinical Co-Pilot.",
        lifespan=lifespan,
    )

    register_exception_handlers(app)

    # FastAPI applies middleware in reverse order of `add_middleware()` calls,
    # so the LAST add is the OUTERMOST layer (runs first on request, last on
    # response). Layer order we want, outer to inner:
    #   CORS -> WAF -> RateLimit -> RequestLog -> Audit -> router
    # So we add them in reverse: Audit, RequestLog, RateLimit, WAF, CORS.
    app.add_middleware(MetricsMiddleware)
    app.add_middleware(AuditMiddleware)
    app.add_middleware(RequestLogMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(WAFMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "X-API-Key", "X-Admin-Confirm", "X-Request-ID", "Content-Type"],
        expose_headers=["X-Request-ID"],
    )

    app.include_router(health.router, prefix="/api/v1")
    app.include_router(auth_router.router, prefix="/api/v1")
    app.include_router(campaigns.router, prefix="/api/v1")
    app.include_router(findings.router, prefix="/api/v1")
    app.include_router(regression.router, prefix="/api/v1")
    app.include_router(observability.router, prefix="/api/v1")

    # /metrics — content-negotiated. Prometheus scrapers (any client without
    # text/html in Accept, or that explicitly asks for text/plain) get the
    # standard exposition format. Browsers get a styled HTML view that polls
    # the same data and renders grouped tables.
    from agentforge.templates import METRICS_HTML

    @app.get("/metrics", include_in_schema=False)
    async def _prometheus_scrape(request: Request, format: str | None = None):
        accept = request.headers.get("accept", "")
        wants_html = format != "text" and "text/html" in accept
        if wants_html:
            return HTMLResponse(content=METRICS_HTML)
        return metrics_response()

    @app.get("/dashboard", include_in_schema=False)
    async def _dashboard():
        return HTMLResponse(content=_DASHBOARD_HTML)

    # /health is now just a redirect to /api/v1/health, which content-negotiates
    # HTML for browsers and JSON for monitors.
    from fastapi.responses import RedirectResponse

    @app.get("/health", include_in_schema=False)
    async def _health_redirect(request: Request):
        target = "/api/v1/health"
        if request.url.query:
            target += "?" + request.url.query
        return RedirectResponse(url=target, status_code=307)

    @app.get("/", include_in_schema=False)
    async def _landing(request: Request):
        """Content-negotiating landing: HTML for browsers, JSON for API clients."""
        accept = request.headers.get("accept", "")
        if "text/html" in accept:
            return HTMLResponse(content=_LANDING_HTML.format(version=__version__, env=get_settings().environment))
        return JSONResponse({
            "name": "AgentForge",
            "description": "Multi-agent adversarial evaluation platform for the OpenEMR Clinical Co-Pilot.",
            "version": __version__,
            "environment": get_settings().environment,
            "docs": "/docs",
            "health": "/api/v1/health",
            "metrics": "/metrics",
            "endpoints": {
                "campaigns": "/api/v1/campaigns",
                "findings": "/api/v1/findings",
                "regression": "/api/v1/regression",
                "coverage": "/api/v1/coverage",
                "cost": "/api/v1/cost",
                "auth_token": "/api/v1/auth/token",
            },
        })

    return app


_LANDING_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>AgentForge — Adversarial AI Security Platform</title>
<style>
  :root {{
    --bg: #0b1020;
    --panel: #131a2e;
    --panel-2: #1a233c;
    --text: #e7ecf3;
    --muted: #8b95ab;
    --accent: #5b9dff;
    --critical: #ff5e6b;
    --high: #ffb547;
    --ok: #2bd17e;
  }}
  * {{ box-sizing: border-box; }}
  html, body {{ margin: 0; padding: 0; background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
  .container {{ max-width: 980px; margin: 0 auto; padding: 48px 24px 80px; }}
  header {{ display: flex; align-items: baseline; justify-content: space-between; flex-wrap: wrap; gap: 12px; }}
  h1 {{ font-size: 32px; margin: 0; font-weight: 700; letter-spacing: -0.01em; }}
  h1 .brand {{ color: var(--accent); }}
  .badge {{ display: inline-block; padding: 4px 10px; border-radius: 999px; font-size: 12px;
    background: rgba(43, 209, 126, 0.15); color: var(--ok); font-weight: 600; }}
  .subtitle {{ color: var(--muted); margin-top: 8px; font-size: 16px; line-height: 1.5; max-width: 720px; }}
  .meta {{ color: var(--muted); font-size: 13px; margin-top: 4px; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-top: 32px; }}
  .card {{ background: var(--panel); border: 1px solid #232b48; border-radius: 12px; padding: 20px; }}
  .card h2 {{ font-size: 14px; text-transform: uppercase; letter-spacing: 0.08em;
    color: var(--muted); margin: 0 0 12px; font-weight: 600; }}
  .card a {{ display: block; color: var(--text); text-decoration: none; padding: 8px 0;
    border-bottom: 1px solid rgba(255,255,255,0.04); font-size: 14px; }}
  .card a:hover {{ color: var(--accent); }}
  .card a:last-child {{ border-bottom: none; }}
  .card a code {{ background: var(--panel-2); padding: 2px 6px; border-radius: 4px; font-size: 12px; color: var(--accent); }}
  #findings-list {{ margin-top: 8px; }}
  #findings-list .vuln {{ padding: 10px 0; border-bottom: 1px solid rgba(255,255,255,0.04); font-size: 14px; }}
  #findings-list .vuln:last-child {{ border-bottom: none; }}
  #findings-list .sev {{ display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 11px; font-weight: 700; margin-right: 8px; vertical-align: middle; }}
  #findings-list .sev-CRITICAL {{ background: rgba(255, 94, 107, 0.15); color: var(--critical); }}
  #findings-list .sev-HIGH {{ background: rgba(255, 181, 71, 0.15); color: var(--high); }}
  #findings-list .sev-MEDIUM {{ background: rgba(91, 157, 255, 0.15); color: var(--accent); }}
  #findings-list .vid {{ color: var(--muted); font-family: ui-monospace, SFMono-Regular, monospace; font-size: 12px; margin-right: 6px; }}
  #findings-list .status {{ float: right; font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }}
  .loading, .empty {{ color: var(--muted); font-style: italic; font-size: 14px; padding: 8px 0; }}
  footer {{ margin-top: 48px; color: var(--muted); font-size: 12px; text-align: center; line-height: 1.7; }}
  pre {{ background: var(--panel-2); padding: 12px 16px; border-radius: 8px; font-size: 13px;
    overflow-x: auto; color: #c4d3eb; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1><span class="brand">Agent</span>Forge</h1>
    <span class="badge" id="health-badge">● online</span>
  </header>
  <p class="subtitle">Multi-agent adversarial evaluation platform for AI-assisted healthcare. Continuously hunts, evaluates, documents, and regression-tests vulnerabilities in the OpenEMR Clinical Co-Pilot.</p>
  <p class="meta">v{version} · {env} · target: <a href="https://web-production-6259a.up.railway.app" style="color: var(--accent);">web-production-6259a.up.railway.app</a></p>

  <div class="grid">
    <div class="card">
      <h2>Explore the API</h2>
      <a href="/dashboard">Operator dashboard <code>/dashboard</code></a>
      <a href="/docs">Interactive API docs <code>/docs</code></a>
      <a href="/health">Health status <code>/health</code></a>
      <a href="/metrics">Prometheus metrics <code>/metrics</code></a>
      <a href="https://github.com/your-org/agentforge">Source · GitHub</a>
    </div>

    <div class="card">
      <h2>Latest findings</h2>
      <div id="findings-list"><div class="loading">Loading findings…</div></div>
    </div>
  </div>

  <div class="card" style="margin-top: 24px;">
    <h2>Quick start</h2>
<pre># 1. Get a JWT (admin key)
curl -X POST $BASE_URL/api/v1/auth/token \\
  -H "X-API-Key: dev-admin-key-change-me"

# 2. List findings
curl $BASE_URL/api/v1/findings \\
  -H "Authorization: Bearer $TOKEN"

# 3. Trigger a new campaign
curl -X POST $BASE_URL/api/v1/campaigns \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{{"config":{{"attack_category":"prompt_injection","max_attacks":3}}}}'</pre>
  </div>

  <footer>
    Built for Gauntlet AI · Week 3 · Adversarial AI Security Platform<br>
    5-agent LangGraph · Claude Sonnet 4.6 · Groq Llama 3.3 70B · OpenAI gpt-4o fallback
  </footer>
</div>

<script>
(async () => {{
  // Quick anonymous attempt to fetch findings via the admin API key for the
  // demo. In real deployments this card would gate on session auth.
  try {{
    const tokenResp = await fetch('/api/v1/auth/token', {{
      method: 'POST',
      headers: {{ 'X-API-Key': 'dev-admin-key-change-me' }}
    }});
    if (!tokenResp.ok) throw new Error('token denied');
    const {{ access_token }} = await tokenResp.json();
    const fResp = await fetch('/api/v1/findings', {{
      headers: {{ 'Authorization': 'Bearer ' + access_token }}
    }});
    if (!fResp.ok) throw new Error('findings denied');
    const findings = await fResp.json();
    const list = document.getElementById('findings-list');
    if (!findings.length) {{
      list.innerHTML = '<div class="empty">No findings yet — Co-Pilot is robust against tested attacks.</div>';
      return;
    }}
    list.innerHTML = findings.slice(0, 5).map(f => `
      <div class="vuln">
        <span class="sev sev-${{f.severity}}">${{f.severity}}</span>
        <span class="vid">${{f.vuln_id}}</span>
        ${{escapeHtml(f.title)}}
        <span class="status">${{f.status}}</span>
      </div>
    `).join('');
  }} catch (e) {{
    document.getElementById('findings-list').innerHTML =
      '<div class="empty">Sign in with an API key to see findings. <a href="/docs" style="color: var(--accent);">Open the API docs</a>.</div>';
  }}
  // Update host info
  document.getElementById('quick-origin')?.replaceWith(document.createTextNode(window.location.origin));
}})();
function escapeHtml(s) {{
  return String(s).replace(/[&<>"]/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}})[c]);
}}
</script>
</body>
</html>
"""


_DASHBOARD_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>AgentForge Dashboard</title>
<style>
  :root {
    --bg: #0b1020;
    --panel: #131a2e;
    --panel-2: #1a233c;
    --panel-3: #232d4b;
    --text: #e7ecf3;
    --muted: #8b95ab;
    --dim: #5b6478;
    --accent: #5b9dff;
    --accent-2: #7ed4ff;
    --critical: #ff5e6b;
    --high: #ffb547;
    --medium: #5b9dff;
    --low: #2bd17e;
    --ok: #2bd17e;
    --warn: #ffb547;
    --err: #ff5e6b;
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
    font-size: 14px; line-height: 1.5; }
  a { color: var(--accent); text-decoration: none; }
  a:hover { color: var(--accent-2); }
  code, pre { font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, monospace; }

  .topbar { background: var(--panel); border-bottom: 1px solid #1f2842;
    padding: 16px 24px; display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap; }
  .topbar h1 { margin: 0; font-size: 18px; font-weight: 700; letter-spacing: -0.01em; }
  .topbar h1 .brand { color: var(--accent); }
  .topbar .meta { color: var(--muted); font-size: 12px; }
  .topbar .right { display: flex; gap: 12px; align-items: center; }
  .topbar a.btn { background: var(--panel-2); padding: 6px 12px; border-radius: 6px;
    font-size: 12px; color: var(--text); border: 1px solid #2a3553; }
  .topbar a.btn:hover { border-color: var(--accent); }

  .container { max-width: 1280px; margin: 0 auto; padding: 24px; }

  .kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 12px; margin-bottom: 24px; }
  .kpi { background: var(--panel); border: 1px solid #1f2842; border-radius: 10px; padding: 16px; }
  .kpi .label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; }
  .kpi .value { font-size: 24px; font-weight: 700; margin-top: 4px; }
  .kpi .value.critical { color: var(--critical); }
  .kpi .value.accent { color: var(--accent); }

  .agent-tabs { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
  .agent-tab { background: var(--panel); border: 1px solid #1f2842; border-radius: 10px;
    padding: 14px 18px; cursor: pointer; transition: border-color 0.15s, transform 0.15s;
    min-width: 160px; flex: 1; }
  .agent-tab:hover { border-color: var(--accent); }
  .agent-tab.active { border-color: var(--accent); background: var(--panel-2);
    box-shadow: 0 0 0 1px var(--accent) inset; }
  .agent-tab .name { font-weight: 700; font-size: 14px; }
  .agent-tab .role { color: var(--muted); font-size: 11px; margin-top: 2px; text-transform: uppercase; letter-spacing: 0.05em; }
  .agent-tab .calls { color: var(--accent); font-size: 11px; margin-top: 6px; }

  .agent-panel { background: var(--panel); border: 1px solid #1f2842; border-radius: 10px;
    padding: 20px; margin-bottom: 20px; }
  .agent-panel .header { display: flex; justify-content: space-between; align-items: baseline; flex-wrap: wrap; gap: 12px; }
  .agent-panel .header h2 { margin: 0; font-size: 20px; }
  .agent-panel .pill { display: inline-block; padding: 3px 10px; border-radius: 999px;
    font-size: 11px; background: var(--panel-3); color: var(--accent-2); font-weight: 600; }
  .agent-panel .purpose { color: var(--muted); margin-top: 8px; }

  .agent-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 20px; }
  @media (max-width: 800px) { .agent-grid { grid-template-columns: 1fr; } }
  .agent-grid .col h3 { font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em;
    color: var(--muted); margin: 0 0 8px; font-weight: 600; }
  .kv { display: grid; grid-template-columns: 110px 1fr; gap: 6px 12px; font-size: 13px; }
  .kv .k { color: var(--muted); }
  .kv .v { color: var(--text); word-break: break-word; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
  .badge.trust-high { background: rgba(43, 209, 126, 0.15); color: var(--ok); }
  .badge.trust-low { background: rgba(255, 94, 107, 0.15); color: var(--critical); }
  .badge.trust-deterministic { background: rgba(91, 157, 255, 0.15); color: var(--accent); }

  table { width: 100%; border-collapse: collapse; }
  table th { text-align: left; color: var(--muted); font-size: 11px;
    text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600;
    padding: 8px 10px; border-bottom: 1px solid #1f2842; }
  table td { padding: 8px 10px; border-bottom: 1px solid #161e34; font-size: 13px; }
  table tbody tr:hover { background: #151c33; }
  .severity { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; }
  .severity-CRITICAL { background: rgba(255, 94, 107, 0.15); color: var(--critical); }
  .severity-HIGH { background: rgba(255, 181, 71, 0.15); color: var(--high); }
  .severity-MEDIUM { background: rgba(91, 157, 255, 0.15); color: var(--medium); }
  .severity-LOW { background: rgba(43, 209, 126, 0.15); color: var(--low); }
  .verdict { font-weight: 600; font-size: 11px; }
  .verdict-SUCCESS { color: var(--critical); }
  .verdict-FAILURE { color: var(--ok); }
  .verdict-PARTIAL { color: var(--high); }
  .verdict-UNCERTAIN { color: var(--muted); }

  .panels-row { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  @media (max-width: 1000px) { .panels-row { grid-template-columns: 1fr; } }
  .panel { background: var(--panel); border: 1px solid #1f2842; border-radius: 10px; padding: 20px; margin-bottom: 20px; }
  .panel h2 { font-size: 14px; text-transform: uppercase; letter-spacing: 0.08em;
    color: var(--muted); margin: 0 0 14px; font-weight: 600; }

  .coverage-bar { background: #1a2238; height: 8px; border-radius: 4px; overflow: hidden; margin-top: 4px; }
  .coverage-bar > div { height: 100%; background: var(--accent); transition: width 0.3s; }

  .empty { color: var(--dim); font-style: italic; padding: 12px 0; }
  .stale { color: var(--warn); font-size: 12px; }
  .last-update { color: var(--dim); font-size: 11px; }
</style>
</head>
<body>
<div class="topbar">
  <h1><span class="brand">Agent</span>Forge — Security Dashboard</h1>
  <div class="right">
    <span class="last-update" id="last-update">connecting…</span>
    <a class="btn" href="/docs">API docs</a>
    <a class="btn" href="/api/v1/health">Health</a>
    <a class="btn" href="/metrics">Metrics</a>
  </div>
</div>

<div class="container">
  <div class="kpis" id="kpis">
    <div class="kpi"><div class="label">Total cost USD</div><div class="value accent" id="kpi-cost">—</div></div>
    <div class="kpi"><div class="label">Findings open</div><div class="value" id="kpi-open">—</div></div>
    <div class="kpi"><div class="label">Pending approval</div><div class="value critical" id="kpi-pending">—</div></div>
    <div class="kpi"><div class="label">Attacks (recent)</div><div class="value" id="kpi-attacks">—</div></div>
    <div class="kpi"><div class="label">Campaigns (recent)</div><div class="value" id="kpi-campaigns">—</div></div>
  </div>

  <h2 style="margin: 8px 0 12px; color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em;">Agents</h2>
  <div class="agent-tabs" id="agent-tabs"></div>

  <div class="agent-panel" id="agent-panel">
    <div class="header"><h2>Loading…</h2></div>
  </div>

  <div class="panel">
    <h2 style="display: flex; justify-content: space-between; align-items: center;">
      <span>Status summary</span>
      <span>
        <button id="refresh-summary" style="background: var(--panel-2); color: var(--text); border: 1px solid #2a3553; padding: 4px 10px; border-radius: 4px; font-size: 11px; cursor: pointer;">Refresh</button>
        <button id="copy-summary" style="background: var(--panel-2); color: var(--text); border: 1px solid #2a3553; padding: 4px 10px; border-radius: 4px; font-size: 11px; cursor: pointer; margin-left: 4px;">Copy markdown</button>
      </span>
    </h2>
    <pre id="summary-text" style="white-space: pre-wrap; word-wrap: break-word; max-height: 360px; overflow-y: auto; margin: 0; padding: 16px; background: var(--panel-2); border-radius: 8px; font-size: 12px; line-height: 1.6;">Loading…</pre>
  </div>

  <div class="panels-row">
    <div class="panel">
      <h2>Recent findings <span style="text-transform:none;letter-spacing:0;color:var(--dim);font-weight:400;">— CRITICAL findings need admin approval</span></h2>
      <table id="findings-table">
        <thead><tr><th>VULN</th><th>Severity</th><th>Title</th><th>Status</th><th>Action</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>
    <div class="panel">
      <h2>Recent attacks</h2>
      <table id="attacks-table">
        <thead><tr><th>Time</th><th>Category</th><th>Verdict</th><th>Conf.</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>
  </div>

  <div class="panels-row">
    <div class="panel">
      <h2>Attack surface coverage</h2>
      <table id="coverage-table">
        <thead><tr><th>Category</th><th>Cases run</th><th>Coverage</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>
    <div class="panel">
      <h2>Recent campaigns</h2>
      <table id="campaigns-table">
        <thead><tr><th>Started</th><th>Category</th><th>Status</th><th>Cost</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>
  </div>

  <div class="panels-row">
    <div class="panel">
      <h2>Judge drift monitor</h2>
      <div id="drift-panel"><div class="empty">Loading…</div></div>
    </div>
    <div class="panel">
      <h2>Audit log <span style="text-transform:none;letter-spacing:0;color:var(--dim);font-weight:400;">— immutable, append-only</span></h2>
      <table id="audit-table">
        <thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Resource</th></tr></thead>
        <tbody><tr><td colspan="4" class="empty">Loading…</td></tr></tbody>
      </table>
    </div>
  </div>
</div>

<script>
const $ = sel => document.querySelector(sel);
const escapeHtml = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'})[c]);

let state = { data: null, activeAgent: 'orchestrator', token: null };

async function getToken() {
  if (state.token) return state.token;
  const r = await fetch('/api/v1/auth/token', { method: 'POST', headers: { 'X-API-Key': 'dev-admin-key-change-me' } });
  if (!r.ok) throw new Error('auth failed');
  const j = await r.json();
  state.token = j.access_token;
  return state.token;
}

async function fetchDashboard() {
  const token = await getToken();
  const r = await fetch('/api/v1/dashboard', { headers: { 'Authorization': 'Bearer ' + token } });
  if (r.status === 401) { state.token = null; throw new Error('token expired'); }
  if (!r.ok) throw new Error('dashboard fetch failed: ' + r.status);
  return r.json();
}

function renderKpis(d) {
  $('#kpi-cost').textContent = '$' + (d.totals.cost_usd_grand_total ?? 0).toFixed(4);
  $('#kpi-open').textContent = d.totals.findings_open;
  $('#kpi-pending').textContent = d.totals.findings_pending_approval;
  $('#kpi-attacks').textContent = d.totals.attacks_recent;
  $('#kpi-campaigns').textContent = d.totals.campaigns;
}

function renderTabs(d) {
  const html = d.agent_order.map(k => {
    const a = d.agents[k];
    const active = k === state.activeAgent ? 'active' : '';
    return `<div class="agent-tab ${active}" data-agent="${k}">
      <div class="name">${escapeHtml(a.display_name)}</div>
      <div class="role">${escapeHtml(a.role)}</div>
      <div class="calls">${a.calls} LLM calls</div>
    </div>`;
  }).join('');
  $('#agent-tabs').innerHTML = html;
  document.querySelectorAll('.agent-tab').forEach(el => {
    el.addEventListener('click', () => {
      state.activeAgent = el.dataset.agent;
      renderTabs(state.data);
      renderAgentPanel(state.data);
    });
  });
}

function renderAgentPanel(d) {
  const a = d.agents[state.activeAgent];
  if (!a) return;
  const trustBadge = `<span class="badge trust-${a.trust_level.split(' ')[0]}">${escapeHtml(a.trust_level)}</span>`;
  const modelsList = Object.entries(a.models || {}).map(([m, n]) => `<code>${escapeHtml(m)}</code> × ${n}`).join('<br>') || '<span class="empty">no calls yet</span>';
  const recentForAgent = recentAttacksForAgent(d, state.activeAgent);
  $('#agent-panel').innerHTML = `
    <div class="header">
      <h2>${escapeHtml(a.display_name)} Agent</h2>
      <span class="pill">${escapeHtml(a.provider)} · ${escapeHtml(a.model)}</span>
    </div>
    <div class="purpose">${escapeHtml(a.purpose)}</div>
    <div class="agent-grid">
      <div class="col">
        <h3>Configuration</h3>
        <div class="kv">
          <div class="k">role</div><div class="v">${escapeHtml(a.role)}</div>
          <div class="k">model</div><div class="v"><code>${escapeHtml(a.model)}</code></div>
          <div class="k">provider</div><div class="v">${escapeHtml(a.provider)}</div>
          <div class="k">temperature</div><div class="v">${a.temperature}</div>
          <div class="k">trust level</div><div class="v">${trustBadge}</div>
          <div class="k">reads</div><div class="v">${a.reads.map(escapeHtml).join(', ')}</div>
          <div class="k">writes</div><div class="v">${a.writes.map(escapeHtml).join(', ')}</div>
        </div>
      </div>
      <div class="col">
        <h3>Live activity</h3>
        <div class="kv">
          <div class="k">total calls</div><div class="v">${a.calls}</div>
          <div class="k">models hit</div><div class="v">${modelsList}</div>
        </div>
        <h3 style="margin-top: 16px;">Recent attacks attributed</h3>
        ${recentForAgent}
      </div>
    </div>
  `;
}

function recentAttacksForAgent(d, agent) {
  // RedTeam owns attack rows; Judge owns verdicts; others have no direct DB rows.
  if (agent === 'red_team') {
    if (!d.recent_attacks.length) return '<div class="empty">No attacks executed yet.</div>';
    return `<table><thead><tr><th>Attack</th><th>Cat.</th><th>Mut.</th></tr></thead><tbody>` +
      d.recent_attacks.slice(0, 5).map(r => `<tr>
        <td><code>${escapeHtml(r.attack_case_id ?? '-')}</code></td>
        <td>${escapeHtml(r.category)}</td>
        <td>${r.mutation_generation}</td>
      </tr>`).join('') + '</tbody></table>';
  }
  if (agent === 'judge') {
    const judged = d.recent_attacks.filter(r => r.verdict);
    if (!judged.length) return '<div class="empty">No verdicts recorded yet.</div>';
    return `<table><thead><tr><th>Attack</th><th>Verdict</th><th>Conf.</th></tr></thead><tbody>` +
      judged.slice(0, 5).map(r => `<tr>
        <td><code>${escapeHtml(r.attack_case_id ?? '-')}</code></td>
        <td><span class="verdict verdict-${r.verdict}">${r.verdict}</span></td>
        <td>${r.confidence?.toFixed(2) ?? '-'}</td>
      </tr>`).join('') + '</tbody></table>';
  }
  if (agent === 'documentation') {
    if (!d.recent_findings.length) return '<div class="empty">No reports filed yet.</div>';
    return `<table><thead><tr><th>VULN</th><th>Severity</th><th>Status</th></tr></thead><tbody>` +
      d.recent_findings.slice(0, 5).map(r => `<tr>
        <td><code>${escapeHtml(r.vuln_id)}</code></td>
        <td><span class="severity severity-${r.severity}">${r.severity}</span></td>
        <td>${escapeHtml(r.status)}</td>
      </tr>`).join('') + '</tbody></table>';
  }
  if (agent === 'orchestrator') {
    if (!d.recent_campaigns.length) return '<div class="empty">No campaigns yet.</div>';
    return `<table><thead><tr><th>Started</th><th>Category</th><th>Status</th></tr></thead><tbody>` +
      d.recent_campaigns.slice(0, 5).map(r => `<tr>
        <td>${r.started_at ? new Date(r.started_at).toLocaleTimeString() : '-'}</td>
        <td>${escapeHtml(r.attack_category)}</td>
        <td>${escapeHtml(r.status)}</td>
      </tr>`).join('') + '</tbody></table>';
  }
  return '<div class="empty">No direct activity rows for this agent — check Regression API for run history.</div>';
}

function renderFindingsTable(d) {
  const tbody = $('#findings-table tbody');
  if (!d.recent_findings.length) { tbody.innerHTML = '<tr><td colspan="5" class="empty">No findings.</td></tr>'; return; }
  tbody.innerHTML = d.recent_findings.map(r => {
    const canApprove = r.status === 'PENDING_APPROVAL';
    const action = canApprove
      ? `<button class="approve-btn" data-id="${r.id}" data-vuln="${escapeHtml(r.vuln_id)}"
           style="background:rgba(43,209,126,0.15);color:var(--ok);border:1px solid var(--ok);
                  padding:3px 10px;border-radius:4px;font-size:11px;cursor:pointer;font-weight:600;">
           Approve</button>`
      : '<span style="color:var(--dim);font-size:11px;">—</span>';
    return `<tr>
      <td><code>${escapeHtml(r.vuln_id)}</code></td>
      <td><span class="severity severity-${r.severity}">${r.severity}</span></td>
      <td>${escapeHtml(r.title)}</td>
      <td>${escapeHtml(r.status)}</td>
      <td>${action}</td>
    </tr>`;
  }).join('');
  // Wire approval buttons.
  document.querySelectorAll('.approve-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const id = btn.dataset.id, vuln = btn.dataset.vuln;
      btn.disabled = true; btn.textContent = 'Approving…';
      try {
        const token = await getToken();
        const r = await fetch(`/api/v1/findings/${id}/approve`, {
          method: 'POST',
          headers: { 'Authorization': 'Bearer ' + token, 'X-Admin-Confirm': 'true' },
        });
        if (!r.ok) throw new Error('HTTP ' + r.status);
        btn.textContent = 'Approved ✓';
        setTimeout(tick, 800);  // refresh dashboard to show new OPEN status
      } catch (e) {
        btn.disabled = false; btn.textContent = 'Approve';
        alert(`Approve ${vuln} failed: ${e.message}\n(Need admin role + X-Admin-Confirm.)`);
      }
    });
  });
}

function renderAttacksTable(d) {
  const tbody = $('#attacks-table tbody');
  if (!d.recent_attacks.length) { tbody.innerHTML = '<tr><td colspan="4" class="empty">No attacks yet.</td></tr>'; return; }
  tbody.innerHTML = d.recent_attacks.map(r => `<tr>
    <td>${r.created_at ? new Date(r.created_at).toLocaleTimeString() : '-'}</td>
    <td>${escapeHtml(r.category)}</td>
    <td>${r.verdict ? `<span class="verdict verdict-${r.verdict}">${r.verdict}</span>` : '-'}</td>
    <td>${r.confidence != null ? r.confidence.toFixed(2) : '-'}</td>
  </tr>`).join('');
}

function renderCoverage(d) {
  const tbody = $('#coverage-table tbody');
  if (!d.coverage.length) { tbody.innerHTML = '<tr><td colspan="3" class="empty">No coverage data.</td></tr>'; return; }
  tbody.innerHTML = d.coverage.map(c => `<tr>
    <td>${escapeHtml(c.category)}</td>
    <td>${c.cases_run} / ${c.total_seed_cases}</td>
    <td><div>${c.coverage_pct.toFixed(0)}%</div><div class="coverage-bar"><div style="width:${c.coverage_pct}%"></div></div></td>
  </tr>`).join('');
}

function renderCampaigns(d) {
  const tbody = $('#campaigns-table tbody');
  if (!d.recent_campaigns.length) { tbody.innerHTML = '<tr><td colspan="4" class="empty">No campaigns.</td></tr>'; return; }
  tbody.innerHTML = d.recent_campaigns.map(r => `<tr>
    <td>${r.started_at ? new Date(r.started_at).toLocaleTimeString() : '-'}</td>
    <td>${escapeHtml(r.attack_category ?? '-')}</td>
    <td>${escapeHtml(r.status)}</td>
    <td>${r.total_cost_usd != null ? '$' + r.total_cost_usd.toFixed(4) : '-'}</td>
  </tr>`).join('');
}

async function renderAuditAndDrift() {
  const token = await getToken();
  // Audit log (admin-only — will 403 for non-admin tokens, handled gracefully).
  try {
    const r = await fetch('/api/v1/audit?limit=12', { headers: { 'Authorization': 'Bearer ' + token } });
    const tbody = $('#audit-table tbody');
    if (r.status === 403) {
      tbody.innerHTML = '<tr><td colspan="4" class="empty">Admin role required to view the audit trail.</td></tr>';
    } else if (r.ok) {
      const rows = await r.json();
      tbody.innerHTML = rows.length
        ? rows.map(a => `<tr>
            <td>${a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : '-'}</td>
            <td><code>${escapeHtml(a.actor)}</code></td>
            <td>${escapeHtml(a.action)}</td>
            <td>${escapeHtml(a.resource_type ?? '-')}</td>
          </tr>`).join('')
        : '<tr><td colspan="4" class="empty">No audit entries yet.</td></tr>';
    }
  } catch (e) { /* leave loading state */ }

  // Judge drift monitor.
  try {
    const r = await fetch('/api/v1/judge-drift', { headers: { 'Authorization': 'Bearer ' + token } });
    if (r.ok) {
      const dft = await r.json();
      const flag = dft.drift_suspected
        ? '<span class="severity severity-HIGH">DRIFT SUSPECTED</span>'
        : '<span class="severity severity-LOW">HEALTHY</span>';
      const dist = Object.entries(dft.verdict_distribution || {})
        .map(([k, v]) => `<code>${k}</code> ${v}`).join(' &nbsp; ') || '<span class="empty">no verdicts yet</span>';
      $('#drift-panel').innerHTML = `
        <div style="margin-bottom:10px;">${flag}</div>
        <div class="kv">
          <div class="k">total scored</div><div class="v">${dft.total_scored}</div>
          <div class="k">verdict mix</div><div class="v">${dist}</div>
          <div class="k">mean conf (all)</div><div class="v">${dft.mean_confidence_all}</div>
          <div class="k">mean conf (recent 20)</div><div class="v">${dft.mean_confidence_recent20}</div>
          <div class="k">dominant share</div><div class="v">${(dft.dominant_verdict_share * 100).toFixed(0)}%</div>
        </div>
        <div style="margin-top:10px;color:var(--muted);font-size:12px;font-style:italic;">${escapeHtml(dft.interpretation)}</div>`;
    }
  } catch (e) { /* leave loading state */ }
}

async function fetchSummary() {
  const token = await getToken();
  const r = await fetch('/api/v1/summary', {
    headers: { 'Authorization': 'Bearer ' + token, 'Accept': 'text/markdown' }
  });
  if (r.status === 401) { state.token = null; throw new Error('token expired'); }
  if (!r.ok) throw new Error('summary fetch failed: ' + r.status);
  return r.text();
}

async function refreshSummary() {
  const el = document.getElementById('summary-text');
  el.textContent = 'Refreshing…';
  try {
    el.textContent = await fetchSummary();
  } catch (e) {
    el.textContent = 'error: ' + e.message;
  }
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('refresh-summary')?.addEventListener('click', refreshSummary);
  document.getElementById('copy-summary')?.addEventListener('click', () => {
    const text = document.getElementById('summary-text').textContent;
    navigator.clipboard?.writeText(text);
    const btn = document.getElementById('copy-summary');
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = orig; }, 1200);
  });
});

async function tick() {
  try {
    const d = await fetchDashboard();
    state.data = d;
    renderKpis(d);
    renderTabs(d);
    renderAgentPanel(d);
    renderFindingsTable(d);
    renderAttacksTable(d);
    renderCoverage(d);
    renderCampaigns(d);
    $('#last-update').textContent = 'updated ' + new Date().toLocaleTimeString();
  } catch (e) {
    $('#last-update').innerHTML = '<span class="stale">' + escapeHtml(e.message) + '</span>';
    console.error(e);
  }
}

tick();
refreshSummary();
renderAuditAndDrift();
setInterval(tick, 5000);
// Summary + audit/drift are heavier — refresh every 30s rather than every poll.
setInterval(refreshSummary, 30000);
setInterval(renderAuditAndDrift, 30000);
</script>
</body>
</html>
"""




app = create_app()
