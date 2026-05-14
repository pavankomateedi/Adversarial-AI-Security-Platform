# Clinical Co-Pilot WAF

A **Cloudflare Worker** that fronts the deployed OpenEMR Clinical Co-Pilot
as a filtering reverse proxy — the "traditional security tooling" layer
the AgentForge PRD calls for, distinct from the LLM-driven adversarial
platform.

```
Internet ──▶ clinical-copilot-waf.<subdomain>.workers.dev  (Cloudflare edge)
                      │  geo / scanner / threat-score / size /
                      │  injection / rate-limit  ── reject here ──▶ 4xx
                      ▼  clean requests only
             web-production-6259a.up.railway.app  (the real Co-Pilot)
```

## Why a Worker (not Cloudflare's managed WAF)

Cloudflare's *managed* WAF ruleset needs a **zone** — a domain you own
with nameservers on Cloudflare. The Co-Pilot lives on a Railway-owned
`*.up.railway.app` subdomain, so there's no zone to attach. A Worker
gives the same Cloudflare edge network and the same protection classes
for **$0 and no custom domain** — we just author the rules instead of
toggling Cloudflare's managed ones.

## Protection layers

See [src/index.js](src/index.js) — 7 layers, request rejected at the first trip:

1. **Geo-blocking** — configurable country denylist
2. **Scanner user-agents** — sqlmap / nikto / nuclei / metasploit / …
3. **Cloudflare threat score** — built-in abuse signal, free per request
4. **Body-size cap** — 50 KB default, blocks payload-amplification DoS
5. **Injection patterns** — SQLi / XSS / path traversal in URL + body
6. **Per-IP rate limiting** — sliding window via Workers KV (60/min general, 30 on `/chat`, 10 on `/auth/login`)
7. **Response hardening** — adds HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy

## Honest scope

This WAF is a **compensating control**. It cannot stop the broken
object-level authorization bugs AgentForge found (VULN-001/002/003) —
those are authenticated, syntactically perfect requests. It *does* shrink
the attack surface (injection, scanners, DoS, enumeration floods) and
buys time while the Co-Pilot's RBAC is fixed.

## Deploy

See [WAF_DEPLOYMENT.md](WAF_DEPLOYMENT.md). Short version:

```bash
npm install -g wrangler && wrangler login
cd clinical-copilot-waf && npx wrangler deploy
```

## The closed loop

After deploying, point AgentForge's `BACKEND_URL` at the Worker URL and
run `scripts/waf_validation.py` — it attacks the Co-Pilot directly *and*
through the WAF and reports the measurable attack-surface reduction.
That's the PRD's "traditional tooling + adversarial platform" synthesis:
the firewall defends, AgentForge proves it works.
