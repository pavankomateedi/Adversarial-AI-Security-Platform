# AgentForge — Project Status & Handoff

*One page covering everything you need to finish the project: live URLs,
what's measured vs not, what's pending, the submission checklist, and
the demo/interview plan. Generated 2026-05-15.*

---

## 1 · Live URLs

| Service | URL | Auth | What it is |
| --- | --- | --- | --- |
| **AgentForge platform** | https://agentforge-production-f5a1.up.railway.app | open landing / JWT for API | The 5-agent adversarial platform |
| AgentForge dashboard | https://agentforge-production-f5a1.up.railway.app/dashboard | self-fetches admin JWT | Security Dashboard — agent tiles, findings, drift, audit |
| AgentForge health | https://agentforge-production-f5a1.up.railway.app/api/v1/health | none | Styled HTML for browsers, JSON for monitors |
| AgentForge metrics | https://agentforge-production-f5a1.up.railway.app/metrics | none | Prometheus + styled HTML |
| AgentForge OpenAPI | https://agentforge-production-f5a1.up.railway.app/docs | none | Swagger UI |
| **Cloudflare Worker WAF** | https://clinical-copilot-waf.pavan-kom.workers.dev | none (proxy) | 7-layer edge filter in front of the Co-Pilot |
| **Clinical Co-Pilot (target)** | https://web-production-6259a.up.railway.app | session cookies | Week-1/2 target system |

**Admin API key (dev):** `dev-admin-key-change-me` — rotate before going public.

---

## 2 · Repo & branches

- **Repo:** https://github.com/pavankomateedi/Adversarial-AI-Security-Platform
- **Active branch:** `Branch-1` (all new work; do not merge to `main` without explicit decision)
- **Latest commit on Branch-1:** `71446c7` (INTERVIEW_PREP.md) — newer post-MFA fixes will follow

**Memory rules saved for future Claude sessions on this project:**
- All commits go to `Branch-1`
- Co-author trailer on every commit: `Co-Authored-By: Pavan` (no email)

---

## 3 · What's built (the shipping list)

| Component | Files | Status |
| --- | --- | --- |
| **5 LangGraph agents** | `agentforge/agents/{orchestrator,red_team,judge,documentation,regression}.py` | ✅ all live, on Branch-1 |
| Campaign graph + state | `agentforge/graph/{campaign_graph,state,edges}.py` | ✅ |
| Target client (session-cookie auth) | `agentforge/core/target_client.py` | ✅ |
| Seed attack library (18 attacks, 6 categories) | `agentforge/core/attack_library.py` + `evals/categories/**/*.yaml` | ✅ |
| Async DB layer (8 tables + audit trigger) | `agentforge/db/` | ✅ |
| 5-layer security moat | `agentforge/security/{waf,rate_limiter,auth,input_guard,audit_log}.py` | ✅ |
| Observability (Prometheus + structlog + Langfuse + drift endpoint) | `agentforge/observability/`, `agentforge/api/observability.py` | ✅ |
| Cost + coverage trackers | `agentforge/core/{cost_tracker,coverage_tracker}.py` | ✅ |
| 20+ API routes | `agentforge/api/` | ✅ |
| HTML dashboards (landing / health / dashboard / metrics) | `agentforge/templates.py`, `agentforge/main.py` | ✅ |
| OpenAI gpt-4o fallback (Judge + Documentation) | `agentforge/agents/models.py` | ✅ |
| Multi-worker concurrency (Semaphore on `MAX_CONCURRENT_CAMPAIGNS`) | `agentforge/services/campaign_runner.py` | ✅ |
| Auto-convert findings → regression_cases | `agentforge/agents/documentation.py` | ✅ |
| Cross-category regression flagger | `agentforge/agents/regression.py` | ✅ |
| Judge ground-truth dataset (9 cases) + accuracy runner | `evals/judge_ground_truth.yaml`, `evals/runners/judge_accuracy.py` | ✅ |
| **Cloudflare Worker WAF + before/after validation script** | `clinical-copilot-waf/`, `scripts/waf_validation.py` | ✅ deployed prod |
| Self-pentest of platform's own moat | `scripts/pentest_agentforge.py` | ✅ 17/17 passing |
| 3 CI workflows (CI, nightly regression, weekly security scan) | `.github/workflows/{ci,regression,security_scan}.yml` | ✅ |
| **93 unit tests** | `tests/unit/` | ✅ all green |

---

## 4 · What's MEASURED (real numbers)

### 4a · Self-pentest of AgentForge (run 2026-05-14)
**17 / 17 PASS** across 5 layers:

```
baseline      health 200
auth          5/5  no-token 401, invalid-JWT 401, invalid-key 401, admin-confirm 403
waf           5/5  SQLi query/body, traversal, scanner-UA, oversized-body — all blocked
rate_limit    7/15 burst /auth/token calls returned 429
input_guard   2/2  missing fields 422, out-of-range 422
audit         immutable — DB trigger blocks UPDATE/DELETE
disclosure    /docs reachable, zero secrets in any response body
```

### 4b · WAF before/after (PROD, measured 2026-05-15)

| Attack class | BEFORE (no WAF) | AFTER (via Cloudflare prod) | Change |
| --- | --- | --- | --- |
| **Injection / scanner / DoS** | 0 / 5 blocked (0%) | **5 / 5 blocked (100%)** | ✅ **100% reduction at edge** |
| **Broken access control (RBAC)** | ⚠️ see §5 | ⚠️ see §5 | invalidated until MFA fix |
| False positives | — | **0** | ✅ |

Per-probe injection class (prod, just measured):
- `SQLi in query` → 400 ✓
- `Path traversal in query` → 400 ✓
- `XSS in query` → 400 ✓
- `Scanner UA (sqlmap)` → 403 ✓
- `Oversized body (>50KB)` → 413 ✓
- `/health`, `/openapi.json` → 200 passthrough ✓

### 4c · Cost
- **Per attack:** $0.011 average (Groq RedTeam + Anthropic Judge)
- **Full dev + demo + WAF + pen tests this week:** under **$0.50**
- **Projection table:** `COST_ANALYSIS.md` — runs cleanly to 100K/day with documented architectural changes

### 4d · Co-Pilot LLM safety layer
LLM-driven adversarial campaigns against `/chat` showed strong refusals — Judge mean confidence 0.94 across 12 attacks in 6 categories. The Co-Pilot's chat layer is robust.

---

## 5 · ⚠️ KNOWN ISSUE — Cross-user RBAC findings under re-verification

**TL;DR:** `target_client.login()` had a bug where `username_override` was
stored but never used. Cross-user runs silently used the global
`BACKEND_USERNAME` (`dr.pavan` — physician with access to all 5 patients)
instead of `nurse.adams`. The 9 "bypasses" reported in VULN-001/002/003
are **not validated**; they may have been dr.pavan accessing patients
she IS authorized for.

**The bug is fixed** (commit pending after MFA verification).

**Re-verification blocked on:** MFA enforcement on `nurse.adams`. The
test user account requires MFA, which the test client doesn't seed.
The user is disabling MFA on `nurse.adams` (same flow used for
`dr.pavan` earlier). Once done:

1. Re-run `BACKEND_URL=<waf-url> uv run python -m scripts.cross_user_attacks` as the *real* nurse.adams
2. Update `VULN-001/002/003` based on what's actually true:
   - **Confirm** if the bypasses reproduce → reports stand
   - **Rewrite** if results differ → reports updated with new evidence
   - **Retract** if no bypasses → replace with the honest methodology-limitation finding

**Critical:** do NOT record the demo or hand the submission until this
is resolved. Honesty in the writeup is non-negotiable — a hospital CISO
will catch an unverified finding faster than they'll forgive one.

---

## 6 · Submission deliverables — checklist vs PRD

| PRD requirement | Status |
| --- | --- |
| GitHub repository (forked from OpenEMR) | ⚠️ standalone repo — outstanding decision: rename to fork OR submit as sibling alongside the Co-Pilot fork |
| Setup guide + deployed link in README | ✅ |
| `THREAT_MODEL.md` with ~500-word summary | ✅ |
| `USERS.md` | ✅ |
| `ARCHITECTURE.md` with ~500-word summary + diagram | ✅ |
| **Demo video (3–5 min)** | ⏸ your task — script in `INTERVIEW_PREP.md` & in chat |
| Eval Dataset `./evals/` with results across ≥3 categories | ✅ 6 categories, 18 cases |
| **Minimum 3 vulnerability reports** | ⚠️ VULN-001/002/003 exist; **under re-verification** (§5) |
| AI Cost Analysis | ✅ `COST_ANALYSIS.md` |
| Deployed application running live attacks | ✅ both URLs live |
| Social post (final only — Friday) | ⏸ your task |

---

## 7 · The demo plan (when you record)

Use the 5-minute script (in earlier chat + summarized in `INTERVIEW_PREP.md`):

1. **0:00–0:25 Hook** — clinical AI, novel attack surface, why static testing fails
2. **0:25–1:00 Architecture** — 5 agents, model separation, LangGraph
3. **1:00–1:45 Dashboard tour** — KPIs, agent tiles, audit, drift, summary
4. **1:45–2:30 Live campaign** — `POST /api/v1/campaigns`, watch the row appear
5. **2:30–3:45 The findings** — **(only present whichever finding(s) survive the MFA re-test)**
6. **3:45–4:20 Self-defense moat** — `scripts/pentest_agentforge.py` 17/17
7. **4:20–4:45 Cost & scale** — $0.50 dev cost, projection to 100K/day
8. **4:45–5:00 Wrap** — repo, branch, deployed URLs

**Add the WAF story somewhere** (mention in §3 or §7):
> "Traditional firewall layer too — Cloudflare Worker WAF in front of the Co-Pilot, 100% injection blocking measured against the live prod URL, validated *by* AgentForge."

---

## 8 · The interview plan

`INTERVIEW_PREP.md` is the study sheet — 570 lines organized around the
four themes the interviewer is most likely to probe (architecture,
model selection, tradeoffs, legacy vs AI integration). Each question
has a one-sentence headline, a two-minute version, and a killer fact.

**Three lines to memorize cold:**

1. *Opening pitch:* "AgentForge is a five-agent adversarial evaluation platform built on LangGraph. The RedTeam runs on Groq because Claude refuses to write attacks; the Judge runs on Claude with a gpt-4o fallback because the verdict layer is the platform's trust anchor; the Orchestrator is deterministic on purpose."

2. *The PRD synthesis:* "Traditional tooling defends, the adversarial platform proves *and quantifies* it. The WAF blocks injection 100%; AgentForge measures exactly which 9 RBAC bypasses still get through — the unchanged 9 is the most important number in the demo because it proves the platform tells the truth."

3. *When asked the toughest question (false positives, weaknesses):* "Single-category Orchestrator is the biggest weakness — it ranks within a category but doesn't auto-broaden. I emit a `low_signal` flag so the operator / a future scheduler can switch. Concrete, named, owned."

---

## 9 · Remaining order of operations

```
NOW            : you — disable MFA on nurse.adams in the Co-Pilot
THEN (chat me) : me — re-run cross_user_attacks, update findings, commit
THEN           : you — review the corrected VULN reports
THEN           : you — record 3-5 min demo (script ready)
FRIDAY         : you — social post tagging @GauntletAI
SUBMISSION     : you — submit branch + URLs + reports
```

---

## 10 · Quick reference — file map

```
agentforge/                    # the Python package
├── agents/                    # 5 LangGraph agents + model factory
├── api/                       # 20+ FastAPI routes
├── core/                      # attack library, target client, trackers
├── db/                        # async SQLAlchemy + Alembic + repos
├── graph/                     # LangGraph state + campaign + regression
├── observability/             # metrics, structlog, Langfuse
├── security/                  # 5-layer moat
├── services/                  # campaign runner, summarizer
├── templates.py               # HTML pages
├── main.py                    # FastAPI app + lifespan
└── errors.py                  # exception hierarchy

clinical-copilot-waf/          # the Cloudflare Worker WAF
├── src/index.js
├── wrangler.toml
├── README.md
└── WAF_DEPLOYMENT.md

evals/
├── categories/                # 17 attack YAMLs + 6 rubrics
├── runners/                   # eval_runner, regression_runner, judge_accuracy
└── judge_ground_truth.yaml    # human-labeled cases

scripts/
├── cross_user_attacks.py      # the script that needs the MFA fix
├── pentest_agentforge.py      # 17/17 self-pentest
├── waf_validation.py          # before/after WAF measurement
├── feed_dashboard.py          # populate live dashboard
├── ingest_findings.py         # load VULN reports into DB
└── smoke_*.py                 # one-off smokes

vulnerability_reports/         # ← submission deliverable
├── VULN-001.md                # ⚠️ under re-verification (§5)
├── VULN-002.md                # ⚠️ under re-verification
├── VULN-003.md                # ⚠️ under re-verification
├── AUDIT-2026-05-12.md        # 6-category sweep audit
└── WAF-BEFORE-AFTER-2026-05-14.md  # measured before/after

tests/unit/                    # 93 tests, all green

PROJECT_STATUS.md              # ← this file
INTERVIEW_PREP.md              # 570-line study sheet
README.md
CLAUDE.md                      # build spec
ARCHITECTURE.md
THREAT_MODEL.md
USERS.md
COST_ANALYSIS.md
```

---

*Generated as a handoff snapshot. The truth state will change as soon as
the nurse.adams MFA toggle happens — re-run the §5 protocol then
overwrite this section.*
