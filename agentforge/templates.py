"""HTML templates served to browsers.

We extract these from `main.py` so other modules (e.g. `api/health.py`) can
content-negotiate the same templates without creating a circular import
through `main`.

The shared `_TOP_NAV` block is a fragment included in every page so the
Dashboard / Health / Metrics views have consistent navigation — never
makes the user reach for the back button.
"""

from __future__ import annotations


_TOP_NAV_STYLES = r"""
  .topnav { background: var(--panel); border-bottom: 1px solid #1f2842;
    padding: 14px 24px; display: flex; align-items: center; gap: 24px;
    position: sticky; top: 0; z-index: 100; }
  .topnav .logo { font-size: 16px; font-weight: 700; letter-spacing: -0.01em;
    color: var(--text); text-decoration: none; }
  .topnav .logo .brand { color: var(--accent); }
  .topnav .nav-links { display: flex; gap: 4px; flex: 1; }
  .topnav .nav-links a { padding: 6px 12px; border-radius: 6px;
    color: var(--muted); text-decoration: none; font-size: 13px; font-weight: 500; }
  .topnav .nav-links a:hover { color: var(--text); background: var(--panel-2); }
  .topnav .nav-links a.active { color: var(--accent); background: var(--panel-2); }
  .topnav .right { display: flex; gap: 12px; align-items: center; }
  .topnav .right a { color: var(--muted); font-size: 12px; text-decoration: none; }
  .topnav .right a:hover { color: var(--text); }
"""

_TOP_NAV_HTML = r"""<nav class="topnav">
  <a class="logo" href="/dashboard"><span class="brand">Agent</span>Forge</a>
  <div class="nav-links">
    <a href="/dashboard" data-nav="dashboard">Security Dashboard</a>
    <a href="/api/v1/health" data-nav="health">Health</a>
    <a href="/metrics" data-nav="metrics">Metrics</a>
  </div>
  <div class="right">
    <a href="/docs">API docs</a>
    <a href="/api/v1/findings">Findings</a>
  </div>
</nav>
<script>
(() => {
  const path = window.location.pathname;
  let active = null;
  if (path === '/dashboard' || path === '/' ) active = 'dashboard';
  else if (path.includes('/health')) active = 'health';
  else if (path.includes('/metrics')) active = 'metrics';
  if (active) document.querySelectorAll(`[data-nav="${active}"]`).forEach(el => el.classList.add('active'));
})();
</script>"""


METRICS_HTML = (r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>AgentForge Metrics</title>
<style>
  :root { --bg:#0b1020; --panel:#131a2e; --panel-2:#1a233c; --panel-3:#232d4b;
    --text:#e7ecf3; --muted:#8b95ab; --dim:#5b6478;
    --ok:#2bd17e; --err:#ff5e6b; --accent:#5b9dff; --accent-2:#7ed4ff; }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    font-size: 14px; line-height: 1.5; }
""" + _TOP_NAV_STYLES + r"""
  .container { max-width: 1280px; margin: 0 auto; padding: 24px; }
  h1 { font-size: 22px; margin: 0 0 4px; letter-spacing: -0.01em; }
  .subtitle { color: var(--muted); font-size: 13px; margin-bottom: 24px; }
  .panel { background: var(--panel); border: 1px solid #1f2842; border-radius: 10px;
    padding: 20px; margin-bottom: 16px; }
  .panel h2 { font-size: 13px; text-transform: uppercase; letter-spacing: 0.08em;
    color: var(--accent); margin: 0 0 4px; font-weight: 700; }
  .panel .help { color: var(--muted); font-size: 12px; margin-bottom: 12px; font-style: italic; }
  .panel .type { display: inline-block; background: var(--panel-3); color: var(--accent-2);
    padding: 2px 8px; border-radius: 4px; font-size: 10px; text-transform: uppercase;
    letter-spacing: 0.05em; font-weight: 700; margin-bottom: 8px; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; color: var(--muted); font-size: 11px; padding: 8px 10px;
    text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600;
    border-bottom: 1px solid #1f2842; }
  td { padding: 8px 10px; border-bottom: 1px solid #161e34; font-size: 13px;
    font-family: ui-monospace, SFMono-Regular, monospace; }
  tr:hover td { background: #151c33; }
  td.value { color: var(--accent-2); font-weight: 600; text-align: right; width: 120px; }
  .empty { color: var(--dim); font-style: italic; padding: 8px 0; font-family: inherit; }
  .last-update { color: var(--dim); font-size: 11px; }
  pre.raw { background: var(--panel-2); padding: 16px; border-radius: 8px;
    overflow-x: auto; font-size: 11px; color: #c4d3eb; max-height: 320px; }
  .toggle { background: var(--panel-2); color: var(--text); border: 1px solid #2a3553;
    padding: 6px 12px; border-radius: 6px; font-size: 12px; cursor: pointer; }
  .toggle:hover { border-color: var(--accent); }
</style>
</head>
<body>
""" + _TOP_NAV_HTML + r"""

<div class="container">
  <h1>Metrics</h1>
  <div class="subtitle">
    Live Prometheus counters and histograms from the AgentForge platform.
    <span class="last-update" id="last-update">— connecting…</span>
    <button class="toggle" id="toggle-raw" style="margin-left: 12px;">Show raw text</button>
  </div>

  <div id="metrics-container"></div>

  <div class="panel" id="raw-panel" style="display: none;">
    <h2>Raw Prometheus exposition</h2>
    <div class="help">Curl-friendly text format consumed by Prometheus / Grafana scrapers.</div>
    <pre class="raw" id="raw-text">…</pre>
  </div>
</div>

<script>
const $ = sel => document.querySelector(sel);
const escapeHtml = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'})[c]);

function parseProm(text) {
  // Group samples by metric family. Skip lines starting with # except HELP/TYPE.
  const families = {};
  let lastHelp = '', lastType = '';
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    if (line.startsWith('# HELP')) { lastHelp = line.replace(/^# HELP \S+\s*/, ''); continue; }
    if (line.startsWith('# TYPE')) {
      const m = line.match(/^# TYPE (\S+) (\S+)/);
      if (m) {
        lastType = m[2];
        families[m[1]] = { name: m[1], help: lastHelp, type: m[2], samples: [] };
      }
      continue;
    }
    if (line.startsWith('#')) continue;
    // sample: name{labels} value [timestamp]
    const m = line.match(/^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+(\S+)/);
    if (!m) continue;
    const [, name, labelStr, value] = m;
    // Find the family this sample belongs to.
    let fam = families[name];
    if (!fam) {
      // Could be a _bucket / _count / _sum suffix on a histogram.
      for (const baseName of Object.keys(families)) {
        if (name.startsWith(baseName + '_')) { fam = families[baseName]; break; }
      }
    }
    if (!fam) {
      fam = families[name] = { name, help: '', type: 'unknown', samples: [] };
    }
    fam.samples.push({ name, labels: labelStr || '', value });
  }
  return Object.values(families);
}

function renderFamily(f) {
  if (!f.samples.length) {
    return `<div class="panel">
      <h2>${escapeHtml(f.name)}</h2>
      ${f.type ? `<span class="type">${f.type}</span>` : ''}
      <div class="help">${escapeHtml(f.help) || '—'}</div>
      <div class="empty">no samples</div>
    </div>`;
  }
  // For histograms, only show a compact summary.
  const isHist = f.type === 'histogram';
  let rows;
  if (isHist) {
    // Aggregate: total count, total sum, last few buckets
    const count = f.samples.find(s => s.name === f.name + '_count');
    const sum = f.samples.find(s => s.name === f.name + '_sum');
    const buckets = f.samples.filter(s => s.name === f.name + '_bucket').slice(0, 6);
    rows = '';
    if (count) rows += `<tr><td>count <span style="color: var(--dim);">${count.labels}</span></td><td class="value">${count.value}</td></tr>`;
    if (sum) rows += `<tr><td>sum <span style="color: var(--dim);">${sum.labels}</span></td><td class="value">${parseFloat(sum.value).toFixed(4)}</td></tr>`;
    rows += buckets.map(b => `<tr><td><span style="color: var(--dim);">${escapeHtml(b.labels)}</span></td><td class="value">${b.value}</td></tr>`).join('');
    if (f.samples.filter(s => s.name === f.name + '_bucket').length > 6) {
      rows += `<tr><td colspan="2" class="empty">…+${f.samples.filter(s => s.name === f.name + '_bucket').length - 6} more buckets</td></tr>`;
    }
  } else {
    rows = f.samples.slice(0, 20).map(s => `<tr>
      <td><span style="color: var(--dim);">${escapeHtml(s.labels)}</span></td>
      <td class="value">${escapeHtml(s.value)}</td>
    </tr>`).join('');
    if (f.samples.length > 20) {
      rows += `<tr><td colspan="2" class="empty">…+${f.samples.length - 20} more samples</td></tr>`;
    }
  }
  return `<div class="panel">
    <h2>${escapeHtml(f.name)}</h2>
    ${f.type ? `<span class="type">${f.type}</span>` : ''}
    <div class="help">${escapeHtml(f.help) || '—'}</div>
    <table><thead><tr><th>Labels</th><th style="text-align: right;">Value</th></tr></thead>
    <tbody>${rows}</tbody></table>
  </div>`;
}

async function tick() {
  try {
    const r = await fetch('/metrics?format=text', { headers: { 'Accept': 'text/plain' } });
    const text = await r.text();
    document.getElementById('raw-text').textContent = text;
    const families = parseProm(text)
      .filter(f => f.name.startsWith('agentforge_'))
      .sort((a, b) => a.name.localeCompare(b.name));
    document.getElementById('metrics-container').innerHTML =
      families.length
        ? families.map(renderFamily).join('')
        : '<div class="panel"><div class="empty">No agentforge_* metrics yet — run a campaign to generate samples.</div></div>';
    document.getElementById('last-update').textContent = '— updated ' + new Date().toLocaleTimeString();
  } catch (e) {
    document.getElementById('last-update').textContent = '— ' + e.message;
  }
}

document.getElementById('toggle-raw').addEventListener('click', () => {
  const p = document.getElementById('raw-panel');
  const btn = document.getElementById('toggle-raw');
  if (p.style.display === 'none') { p.style.display = 'block'; btn.textContent = 'Hide raw text'; }
  else { p.style.display = 'none'; btn.textContent = 'Show raw text'; }
});

tick();
setInterval(tick, 5000);
</script>
</body>
</html>
""")


HEALTH_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>AgentForge Health</title>
<style>
  :root { --bg:#0b1020; --panel:#131a2e; --panel-2:#1a233c; --text:#e7ecf3;
    --muted:#8b95ab; --ok:#2bd17e; --err:#ff5e6b; --accent:#5b9dff; }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
""" + _TOP_NAV_STYLES + r"""
  .center-wrap { min-height: calc(100vh - 56px); display: flex; align-items: center; justify-content: center; padding: 20px; }
  .card { background: var(--panel); border: 1px solid #1f2842; border-radius: 16px;
    padding: 40px 48px; min-width: 480px; max-width: 600px; width: 100%;
    box-shadow: 0 20px 60px rgba(0,0,0,0.4); }
  h1 { margin: 0 0 4px; font-size: 24px; letter-spacing: -0.01em; display: flex;
    align-items: center; gap: 12px; flex-wrap: wrap; }
  h1 .brand { color: var(--accent); }
  .status-pill { display: inline-flex; align-items: center; gap: 6px; padding: 6px 14px;
    border-radius: 999px; font-size: 13px; font-weight: 600; margin-left: auto; }
  .status-pill.healthy { background: rgba(43, 209, 126, 0.15); color: var(--ok); }
  .status-pill.degraded { background: rgba(255, 94, 107, 0.15); color: var(--err); }
  .status-pill .dot { width: 8px; height: 8px; border-radius: 50%; background: currentColor; }
  .meta { color: var(--muted); font-size: 13px; margin-top: 4px; }
  .deps { margin-top: 28px; }
  .dep { display: flex; align-items: center; gap: 14px; padding: 16px;
    background: var(--panel-2); border-radius: 10px; margin-bottom: 10px; }
  .dep .icon { width: 12px; height: 12px; border-radius: 50%; flex-shrink: 0; }
  .dep.up .icon { background: var(--ok); box-shadow: 0 0 12px var(--ok); }
  .dep.down .icon { background: var(--err); box-shadow: 0 0 12px var(--err); }
  .dep .name { font-weight: 600; flex: 1; text-transform: capitalize; }
  .dep .status { color: var(--muted); font-size: 13px; text-transform: uppercase;
    letter-spacing: 0.05em; font-weight: 600; }
  .dep.up .status { color: var(--ok); }
  .dep.down .status { color: var(--err); }
  .dep .detail { color: var(--err); font-size: 12px; margin-top: 4px;
    font-family: ui-monospace, monospace; }
  .footer { margin-top: 24px; display: flex; justify-content: space-between;
    align-items: center; font-size: 12px; color: var(--muted); flex-wrap: wrap; gap: 12px; }
  .footer a { color: var(--accent); text-decoration: none; }
  .footer a:hover { text-decoration: underline; }
  .last-update { font-size: 11px; }
  .links { display: flex; gap: 12px; flex-wrap: wrap; }
</style>
</head>
<body>
""" + _TOP_NAV_HTML + r"""
<div class="center-wrap">
<div class="card">
  <h1>
    <span class="brand">Agent</span>Forge
    <span class="status-pill" id="status-pill"><span class="dot"></span><span id="status-label">checking...</span></span>
  </h1>
  <div class="meta">v<span id="version">--</span> &middot; <span id="env">--</span></div>

  <div class="deps" id="deps"></div>

  <div class="footer">
    <span class="last-update" id="last-update">--</span>
    <span class="links">
      <a href="/dashboard">&larr; Security Dashboard</a>
      <a href="/api/v1/health?format=json">Raw JSON</a>
    </span>
  </div>
</div>
</div>

<script>
async function tick() {
  try {
    const r = await fetch('/api/v1/health?format=json', { headers: { 'Accept': 'application/json' } });
    const d = await r.json();
    const pill = document.getElementById('status-pill');
    const label = document.getElementById('status-label');
    pill.className = 'status-pill ' + d.status;
    label.textContent = d.status.toUpperCase();
    document.getElementById('version').textContent = d.version;
    document.getElementById('env').textContent = d.environment;

    const depsEl = document.getElementById('deps');
    depsEl.innerHTML = d.dependencies.map(dep => `
      <div class="dep ${dep.status}">
        <div class="icon"></div>
        <div class="name">${escapeHtml(dep.name)}${dep.detail ? `<div class="detail">${escapeHtml(dep.detail)}</div>` : ''}</div>
        <div class="status">${escapeHtml(dep.status)}</div>
      </div>
    `).join('');

    document.getElementById('last-update').textContent = 'updated ' + new Date().toLocaleTimeString();
  } catch (e) {
    document.getElementById('status-pill').className = 'status-pill degraded';
    document.getElementById('status-label').textContent = 'UNREACHABLE';
    document.getElementById('deps').innerHTML = '<div class="dep down"><div class="icon"></div><div class="name">api</div><div class="status">unreachable</div></div>';
  }
}
function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'})[c]);
}
tick();
setInterval(tick, 5000);
</script>
</body>
</html>
"""

