# Clinical Co-Pilot WAF — Deployment Guide

A Cloudflare Worker that fronts the deployed Clinical Co-Pilot as a
filtering reverse proxy. $0 (Workers free tier: 100k requests/day), no
custom domain required.

---

## Prerequisites

- A Cloudflare account (free) — <https://dash.cloudflare.com/sign-up>
- Node.js installed (for the `wrangler` CLI)

---

## Step 1 — Install wrangler + log in

```bash
npm install -g wrangler
wrangler login          # opens a browser, authorizes the CLI
```

## Step 2 — Deploy the Worker (no KV yet)

From this directory:

```bash
cd clinical-copilot-waf
npx wrangler deploy
```

Wrangler prints the live URL, e.g.:

```
https://clinical-copilot-waf.<your-subdomain>.workers.dev
```

That URL is now a WAF in front of the Co-Pilot. Test it:

```bash
# clean request — proxied through to the Co-Pilot
curl https://clinical-copilot-waf.<your-subdomain>.workers.dev/health

# SQLi in the query string — blocked by the WAF, never reaches the Co-Pilot
curl "https://clinical-copilot-waf.<your-subdomain>.workers.dev/health?q=union+select+*+from+users"
# -> 400 {"detail":"Request blocked: sqli_pattern in query","blocked_by":"clinical-copilot-waf"}

# scanner user-agent — blocked
curl -H "User-Agent: sqlmap/1.7" https://clinical-copilot-waf.<your-subdomain>.workers.dev/health
# -> 403 {"detail":"Scanner user-agent rejected", ...}
```

## Step 3 — (Optional) Enable per-IP rate limiting via KV

```bash
npx wrangler kv namespace create RATE_LIMIT_KV
```

Wrangler prints an `id`. Uncomment the `[[kv_namespaces]]` block in
`wrangler.toml` and paste the id, then redeploy:

```bash
npx wrangler deploy
```

Rate limits are then enforced: 60 req/min general, 30/min on `/chat`,
10/min on `/auth/login`. (The Worker runs fine without this — it just
skips rate limiting until the binding exists.)

## Step 4 — (Optional) Geo-blocking

Set `BLOCKED_COUNTRIES` in `wrangler.toml` to a comma-separated list of
ISO country codes, e.g. `BLOCKED_COUNTRIES = "KP,RU"`, then redeploy.

## Step 5 — Point AgentForge at the WAF and re-validate

This is the closed loop — AgentForge proves the WAF works:

```bash
# In AgentForge's .env, change BACKEND_URL to the Worker URL:
BACKEND_URL=https://clinical-copilot-waf.<your-subdomain>.workers.dev

# Re-sync to Railway and re-run the eval suite:
uv run python scripts/sync_env_to_railway.py
uv run python -m scripts.waf_validation        # before/after attack-surface report
```

`scripts/waf_validation.py` runs the same attack set against the Co-Pilot
*directly* and *through the WAF*, then prints how many attacks the WAF
blocked at the edge — the measurable attack-surface reduction.

---

## What the WAF does and does NOT stop

| Stops at the edge | Does NOT stop (needs the Co-Pilot's own RBAC fix) |
| --- | --- |
| SQL injection patterns | VULN-001 — cross-tenant PHI via `/patients/{id}/identity` |
| XSS / script injection | VULN-002 — cross-patient `/chat` disclosure |
| Path traversal | VULN-003 — patient enumeration via `/documents/list` |
| Scanner user-agents | (these are syntactically perfect, authenticated requests) |
| Oversized payloads (DoS) | |
| High Cloudflare threat-score IPs | |
| Per-IP request floods | |
| Traffic from blocked countries | |

The WAF is a **compensating control**: it shrinks the attack surface and
buys time, but broken object-level authorization must still be fixed in
the Co-Pilot's application code. AgentForge measures both — what the WAF
caught, and what still gets through.

---

## Rollback

The Worker is a pure proxy — deleting it (`npx wrangler delete`) or
pointing `BACKEND_URL` back at the raw Railway URL fully reverts. The
Co-Pilot itself is never modified.
