# AgentForge — Users & Workflows

Three operator personas use AgentForge day-to-day. They map directly to the
three RBAC roles enforced in [agentforge/security/auth.py](agentforge/security/auth.py).

---

## 1. Security Engineer (`operator` role)

**Goal:** Discover vulnerabilities in the Clinical Co-Pilot, validate fixes, and prevent
regressions.

**Primary workflow:**

```
1. Pick a category to probe
   POST /api/v1/campaigns
     { "config": { "attack_category": "prompt_injection",
                   "priority": "HIGH",
                   "max_attacks": 10,
                   "max_mutations_per_attack": 3,
                   "patient_id": "demo-001" } }
   -> 202 Accepted, returns campaign_id

2. Watch progress
   GET /api/v1/campaigns/{id}              # status + attacks_run + findings_count
   GET /api/v1/findings?category=...       # what got filed

3. Review and triage
   GET /api/v1/findings/{id}               # full markdown + JSON
   PATCH /api/v1/findings/{id} { "status": "IN_PROGRESS" }

4. Validate a fix the Co-Pilot team shipped
   POST /api/v1/regression/run             # replays all confirmed exploits
   GET  /api/v1/regression/results         # PASS / FAIL / REGRESSION
```

**What they should NOT do:**
- Approve CRITICAL findings — that requires admin.
- Delete audit log entries — physically impossible (DB trigger).

**Tools they care about:**
- `GET /api/v1/coverage` — which categories are under-tested
- `GET /api/v1/cost` — campaign cost breakdown
- Langfuse dashboard — agent traces for debugging weird verdicts

---

## 2. Clinical IT Admin (`admin` role)

**Goal:** Authorize critical findings before they leave the platform, manage
operator API keys, audit the trail.

**Primary workflow:**

```
1. Get notified when a CRITICAL finding lands (status=PENDING_APPROVAL)
   GET /api/v1/findings?status=PENDING_APPROVAL

2. Read the report and decide
   GET /api/v1/findings/{id}

3. Approve (or update status to WONT_FIX)
   POST /api/v1/findings/{id}/approve
     Headers:
       Authorization: Bearer <admin-jwt>
       X-Admin-Confirm: true
   -> 200, status -> OPEN, approved_by recorded

4. Periodically audit
   (Direct DB read on audit_log table — append-only, immutable)
```

**Why the X-Admin-Confirm header:** prevents accidental approval via stale tokens
or replayed requests. See [auth.py:require_admin_with_confirm](agentforge/security/auth.py).

---

## 3. Platform Engineer (no role — operates infrastructure)

**Goal:** Keep AgentForge running, monitor cost, manage Co-Pilot deployment webhooks.

**Primary workflow:**

```
1. Watch Prometheus metrics
   GET /metrics                            # unauthenticated, internal-only
   GET /api/v1/metrics                     # JSON snapshot for dashboards

2. Cost monitoring
   GET /api/v1/cost                        # by-campaign breakdown
   COST_ALERT_THRESHOLD_USD env caps a single campaign

3. Wire deployment webhooks (Co-Pilot side)
   Co-Pilot's Railway dashboard -> deploy hook -> POST $AGENTFORGE_URL/api/v1/regression/run
   AgentForge runs the full regression suite on every Co-Pilot deploy.

4. Manage operator API keys (DB-level for MVP; admin UI in v1.1)
   Insert hashed key into api_keys table:
     INSERT INTO api_keys (name, key_hash, role)
     VALUES ('alice-securitydev', '$2b$12$...', 'operator');
```

**Day-2 ops:**
- Rotate `SECRET_KEY` quarterly via Railway dashboard.
- Review nightly regression artifacts in GitHub Actions.
- Increase `MAX_TOKENS_PER_CAMPAIGN` only with explicit budget approval.

---

## Permissions matrix (CLAUDE.md §8.1)

| Action | viewer | operator | admin |
|---|---|---|---|
| Read findings / coverage / metrics | ✅ | ✅ | ✅ |
| Start / cancel campaigns | ❌ | ✅ | ✅ |
| Trigger regression | ❌ | ✅ | ✅ |
| Update finding status | ❌ | ✅ | ✅ |
| Approve CRITICAL finding | ❌ | ❌ | ✅ + `X-Admin-Confirm: true` |
| View cost API | ❌ | ✅ | ✅ |
| View Prometheus `/metrics` | (internal scraper only) | | |

---

## How users authenticate

```
1. Receive an API key from the platform engineer.

2. Exchange it for a JWT (60-min lifetime by default):
     POST /api/v1/auth/token
       Headers: X-API-Key: <your-key>
     -> { "access_token": "...", "expires_at": "...", "role": "operator" }

3. All subsequent requests:
     Authorization: Bearer <access_token>

4. For ad-hoc CI / deployment hooks, send the API key directly:
     X-API-Key: <key>
     (skips token issuance — useful for short scripts)
```
