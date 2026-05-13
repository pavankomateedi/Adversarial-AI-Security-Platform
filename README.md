# AgentForge

**Multi-agent adversarial evaluation platform for AI-assisted healthcare.** Continuously hunts, evaluates, documents, and regression-tests vulnerabilities in the OpenEMR Clinical Co-Pilot — autonomously, with cost guardrails and human approval gates for critical findings.

🚀 **Deployed:** `https://agentforge-production-f5a1.up.railway.app` *(URL filled in once deploy is healthy)*

📋 **Target system:** `https://web-production-6259a.up.railway.app` (Clinical Co-Pilot running Claude Opus 4.7)

---

## What it does

1. **OrchestratorAgent** (Claude Haiku 4.5) — Picks the next attack category based on coverage gaps and cost budget.
2. **RedTeamAgent** (Groq Llama 3.3 70B) — Loads a seed adversarial prompt, mutates it if needed, sends it to the Co-Pilot.
3. **JudgeAgent** (Claude Sonnet 4.6, temp=0) — Independently scores the Co-Pilot's response against a per-category rubric. Cross-checks 10% of verdicts.
4. **DocumentationAgent** (Claude Sonnet 4.6) — Writes a CVE-style report (Markdown + structured JSON in DB) when an exploit is confirmed.
5. **RegressionAgent** — Deterministically replays confirmed exploits on every Co-Pilot deploy and detects re-introductions.

All five agents coordinate through a **LangGraph state machine** with hard cost ceilings, mutation caps, and conditional routing (see [ARCHITECTURE.md](ARCHITECTURE.md)).

## Five-layer security moat protecting AgentForge itself

| Layer | File |
| --- | --- |
| WAF (SQLi, SSRF, path traversal, scanner UA, payload size) | [agentforge/security/waf.py](agentforge/security/waf.py) |
| Per-IP rate limiter (Redis or in-memory fallback) | [agentforge/security/rate_limiter.py](agentforge/security/rate_limiter.py) |
| JWT + bcrypt-hashed API keys + RBAC | [agentforge/security/auth.py](agentforge/security/auth.py) |
| Input guard (control char strip, SSRF check, prompt-injection heuristic) | [agentforge/security/input_guard.py](agentforge/security/input_guard.py) |
| Immutable audit log (Postgres trigger-enforced) | [agentforge/security/audit_log.py](agentforge/security/audit_log.py) |

---

## Local development

```powershell
# 1. Install deps (uv)
uv sync

# 2. Configure env
Copy-Item .env.example .env
# Edit .env with your ANTHROPIC_API_KEY, GROQ_API_KEY, BACKEND_URL, BACKEND_USERNAME, etc.

# 3. Start local Postgres + Redis
docker compose up -d

# 4. Run migrations
uv run alembic upgrade head

# 5. Start the API
uv run uvicorn agentforge.main:app --reload --port 8000

# 6. Smoke
curl http://localhost:8000/api/v1/health
```

Issue a JWT once you've set `ADMIN_API_KEY`:

```bash
curl -X POST http://localhost:8000/api/v1/auth/token -H "X-API-Key: $ADMIN_API_KEY"
```

Start a real campaign against the live Co-Pilot:

```bash
curl -X POST http://localhost:8000/api/v1/campaigns \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"config": {"attack_category": "prompt_injection", "max_attacks": 3, "max_mutations_per_attack": 2}}'
```

---

## Test suite

```bash
uv run pytest tests/unit/ -v          # 44 unit tests
uv run python -m evals.runners.eval_runner --smoke    # harness self-test (no LLM calls)
uv run python -m evals.runners.eval_runner --target $BACKEND_URL --category prompt_injection
uv run python -m evals.runners.regression_runner --target $BACKEND_URL --fail-on-regression
```

---

## Deploy to Railway

```bash
railway login
railway init -n agentforge
railway add -d postgres -d redis -s agentforge
uv run python scripts/sync_env_to_railway.py    # pushes .env values to the agentforge service
railway up
```

---

## Documentation

| File | Purpose |
| --- | --- |
| [CLAUDE.md](CLAUDE.md) | Master build spec — single source of truth |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Multi-agent architecture, state flow, DB schema |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Full attack surface map, threat actors |
| [ACTION_PLAN.md](ACTION_PLAN.md) | Phased build roadmap (Days 1–6) |
| [USERS.md](USERS.md) | Three personas + RBAC permissions matrix |
| [COST_ANALYSIS.md](COST_ANALYSIS.md) | Measured cost per attack + projections to 100K/day |
| [vulnerability_reports/](vulnerability_reports/) | Auto-generated CVE-style findings |

---

## Tech stack

- **Python 3.11+**, FastAPI, async SQLAlchemy 2.0, Alembic, PostgreSQL 15, Redis 7
- **LangGraph 1.x** for stateful multi-agent orchestration
- **Anthropic Claude 4.x** (Sonnet 4.6 for Judge/Documentation, Haiku 4.5 for Orchestrator)
- **Groq Llama 3.3 70B** for RedTeam (permissive model needed for offensive prompt generation)
- **Langfuse** for LLM trace dashboards, **Prometheus** for metrics, **structlog** for JSON logs
- **uv** for dependency management; deploys via Dockerfile to Railway

## CI

- [`.github/workflows/ci.yml`](.github/workflows/ci.yml) — lint, bandit, detect-secrets, pip-audit, trivy, pytest, eval smoke, docker build + scan
- [`.github/workflows/regression.yml`](.github/workflows/regression.yml) — nightly regression at 02:00 UTC; fails CI on REGRESSION
- [`.github/workflows/security_scan.yml`](.github/workflows/security_scan.yml) — weekly: semgrep + hadolint + trivy SARIF

---

*Owner: <pavan.kom@gmail.com> · Version 1.0.0 · 2026-05-12*
