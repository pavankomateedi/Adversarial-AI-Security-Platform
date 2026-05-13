# AgentForge — Multi-Agent Architecture & Clinical Co-Pilot Integration

## Executive Summary

AgentForge is a five-agent adversarial evaluation platform built on LangGraph, deployed on Railway, and connected to an existing OpenEMR Clinical Co-Pilot backend. The platform operates as an autonomous red team that continuously hunts, evaluates, documents, and regression-tests vulnerabilities in the Clinical Co-Pilot — without requiring human intervention for routine test runs.

The architecture separates attack generation from evaluation by design. The **RedTeamAgent** generates adversarial inputs using permissive open-source models (Groq/Mistral); the **JudgeAgent** independently evaluates results using a trusted closed model (Claude Sonnet) with no access to the RedTeam's strategy. The **OrchestratorAgent** reads coverage maps and cost budgets to prioritize the next campaign. The **DocumentationAgent** converts confirmed exploits into professional CVE-style reports. The **RegressionAgent** converts every confirmed finding into a deterministic test case that runs on every deployment of the Clinical Co-Pilot.

The five agents coordinate through a shared LangGraph state graph backed by PostgreSQL. Every agent action is traced in Langfuse, metered in Prometheus, and logged in an append-only audit table. No single agent has trust over another — each reads only what it needs from the shared state, and writes only to its designated output fields. The entire platform is protected by a five-layer security moat (WAF → Rate Limiter → Auth → Input Guard → Audit Log) so the attack platform itself cannot be turned into an attack vector.

The integration point between AgentForge and the Clinical Co-Pilot is a thin HTTP adapter (`target_client.py`) that forwards adversarial inputs to the Co-Pilot's chat endpoint and returns raw responses. This adapter handles auth, retry logic, and cost metering — no changes to the Clinical Co-Pilot codebase are required.

Three operational decisions deserve explicit defense. **First, model separation is non-negotiable.** Frontier models trained on safety policies refuse to generate offensive payloads. The RedTeam therefore runs on Groq Llama 3.3 70B — open-weights and permissive — while the Judge runs on Claude Sonnet 4.6 at temperature 0 with a fresh rubric loaded per call. A single model performing both jobs would have a conflict of interest by design; we treat that conflict as a structural defect, not a tunable parameter. **Second, every Judge call has a provider-independent fallback to OpenAI gpt-4o.** Anthropic returns 529 (overloaded) under sustained load, and a single-provider Judge means a single-provider outage that silently halts the platform; this audit's first live run encountered exactly that condition. **Third, the platform enforces hard cost guardrails.** Each campaign carries an enforced USD ceiling, the Orchestrator halts attacks when ceilings are reached, and per-agent / per-model cost is tracked and exposed at `/api/v1/cost` so the operator can see exactly which agent is burning budget. The cumulative cost of this audit's six-category sweep across 27 mutated attacks was $0.14 — the architecture scales linearly with attack volume and the cost levers documented in `COST_ANALYSIS.md` extend it cleanly to 10K runs/day with a Haiku-tier Judge cross-check and prompt caching on the rubric.

---

## Agent Roles & Interactions

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AgentForge Platform                                  │
│                                                                               │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                    LangGraph Campaign Graph                           │   │
│  │                                                                       │   │
│  │  ┌──────────────────┐                                                │   │
│  │  │  OrchestratorAgent│──────────────────────────────────┐            │   │
│  │  │  (Claude Haiku)   │ CampaignConfig                   │            │   │
│  │  │                   │ (category, priority,             │            │   │
│  │  │  Reads:           │  token_budget, target_endpoint)  │            │   │
│  │  │  - Coverage map   │                                  ▼            │   │
│  │  │  - Open findings  │                       ┌─────────────────┐     │   │
│  │  │  - Session cost   │                       │  RedTeamAgent   │     │   │
│  │  │  - Trigger event  │                       │  (Groq/Mistral) │     │   │
│  │  └──────────────────┘                        │                 │     │   │
│  │           ▲                                  │  Generates &    │     │   │
│  │           │ next_attack                      │  mutates        │     │   │
│  │           │ (after verdict)                  │  adversarial    │     │   │
│  │           │                                  │  inputs         │     │   │
│  │  ┌────────┴─────────┐                        └────────┬────────┘     │   │
│  │  │   JudgeAgent     │◄───────────────────────────────┘              │   │
│  │  │  (Claude Sonnet) │        AttackResult                            │   │
│  │  │                  │        (prompt + target response)              │   │
│  │  │  Blind to        │                                                │   │
│  │  │  RedTeam intent  │────────────────────┐                           │   │
│  │  │                  │ JudgeVerdict        │                           │   │
│  │  │  Outputs:        │ (SUCCESS/FAIL/      │                           │   │
│  │  │  - verdict       │  PARTIAL/UNCERTAIN) │                           │   │
│  │  │  - confidence    │                     │                           │   │
│  │  │  - evidence      │                     ▼                           │   │
│  │  └──────────────────┘          ┌──────────────────┐                  │   │
│  │                                │ DocumentationAgent│                  │   │
│  │                                │ (Claude Sonnet)   │                  │   │
│  │                                │                   │                  │   │
│  │                                │  Runs only when:  │                  │   │
│  │                                │  verdict=SUCCESS  │                  │   │
│  │                                │  confidence≥0.7   │                  │   │
│  │                                │                   │                  │   │
│  │                                │  Outputs:         │                  │   │
│  │                                │  VULN-{id}.md     │                  │   │
│  │                                └──────────┬────────┘                  │   │
│  │                                           │                            │   │
│  └───────────────────────────────────────────┼────────────────────────┘   │
│                                              │                              │
│  ┌───────────────────────────────────────────┼────────────────────────┐   │
│  │              LangGraph Regression Graph   │                         │   │
│  │                                           ▼                         │   │
│  │                              ┌─────────────────────┐                │   │
│  │                              │  RegressionAgent     │                │   │
│  │                              │  (deterministic)     │                │   │
│  │                              │                      │                │   │
│  │  Trigger: nightly cron,      │  Replays confirmed   │                │   │
│  │  deployment webhook,         │  exploits against    │                │   │
│  │  manual API call             │  target              │                │   │
│  │                              │                      │                │   │
│  │                              │  PASS | FAIL |       │                │   │
│  │                              │  REGRESSION          │                │   │
│  │                              └─────────────────────┘                │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                               │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                    Shared Infrastructure                              │   │
│  │  PostgreSQL (findings, campaigns, regression, audit_log)             │   │
│  │  Redis (rate limiting, session cache, task queue)                    │   │
│  │  Langfuse (LLM traces)  │  Prometheus (metrics)  │  structlog (logs)│   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        │ HTTP (target_client.py)
                                        │ Auth: API key / bearer token
                                        │ Retry: tenacity (3x exponential backoff)
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│              OpenEMR Clinical Co-Pilot (EXISTING — no changes)               │
│                                                                               │
│  POST /chat          ← AgentForge sends adversarial messages here            │
│  POST /upload        ← AgentForge tests indirect injection via file upload   │
│  GET  /chart/{id}    ← AgentForge probes PHI access controls                 │
│  WS   /chat/stream   ← AgentForge tests multi-turn conversation attacks      │
│                                                                               │
│  Deployed on Railway at: $BACKEND_URL                                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Integration with Existing Clinical Co-Pilot

### Overview

AgentForge treats the Clinical Co-Pilot as a **black-box target**. Zero changes are required to the Co-Pilot codebase. The integration is entirely one-directional: AgentForge sends HTTP requests to the Co-Pilot's existing API endpoints and observes responses.

### `target_client.py` — The Integration Adapter

```python
# agentforge/core/target_client.py

class ClinicalCopilotClient:
    """
    HTTP client for interacting with the deployed OpenEMR Clinical Co-Pilot.
    Handles: auth, retry, response normalization, cost tracking.
    No changes to the Co-Pilot codebase required.
    """
    
    base_url: str          # = BACKEND_URL from .env
    api_key: str           # = BACKEND_API_KEY from .env (if Co-Pilot requires auth)
    timeout: int = 30      # seconds
    max_retries: int = 3
    
    async def send_message(
        self, 
        content: str, 
        conversation_id: str | None = None,
        patient_context: dict | None = None
    ) -> TargetResponse:
        """
        Send a single message to the Co-Pilot chat endpoint.
        Returns normalized TargetResponse with response text,
        status code, latency, and any tool calls observed.
        """
    
    async def send_conversation(
        self, 
        messages: list[dict],  # multi-turn sequence
        patient_context: dict | None = None
    ) -> list[TargetResponse]:
        """
        Send a multi-turn conversation sequence.
        Used by RedTeamAgent for multi-turn attack chains.
        """
    
    async def upload_document(
        self, 
        content: bytes,
        filename: str,
        content_type: str
    ) -> TargetResponse:
        """
        Upload a document to test indirect injection via file upload.
        """
    
    async def probe_patient_chart(
        self, 
        patient_id: str,
        auth_token: str
    ) -> TargetResponse:
        """
        Probe chart access to test cross-patient data exposure.
        """
```

### Co-Pilot Endpoints AgentForge Targets

| Co-Pilot Endpoint | Attack Categories Tested | AgentForge Method |
|---|---|---|
| `POST /chat` | Direct injection, multi-turn, persona hijacking, privilege escalation | `send_message()`, `send_conversation()` |
| `POST /upload` | Indirect injection, state corruption via documents | `upload_document()` |
| `GET /chart/{patient_id}` | PHI leakage, cross-patient exposure, auth bypass | `probe_patient_chart()` |
| `POST /chat` (rapid) | Token exhaustion, cost amplification, DoS | `send_message()` in rapid sequence |
| Any endpoint | Recursive tool invocation, parameter tampering | `send_message()` with tool-triggering prompts |

### Co-Pilot Deployment Webhook

To trigger automatic regression when the Co-Pilot is redeployed, add this webhook to the Co-Pilot's Railway deployment settings:

```
POST https://agentforge.railway.app/api/v1/regression/run
Headers:
  X-Webhook-Secret: {shared_secret}
  Content-Type: application/json
Body:
  {"trigger": "deployment", "service": "clinical-copilot", "version": "..."}
```

This requires no code change in the Co-Pilot — it's a Railway deployment webhook configured in the Co-Pilot's Railway dashboard.

---

## Inter-Agent Communication Protocol

All agents communicate through the **shared LangGraph state** (`AgentForgeState`). Agents do not call each other directly — they read from state and write back to state. LangGraph routes between agents based on conditional edges.

### State Fields by Agent

| Field | Written By | Read By |
|---|---|---|
| `campaign_config` | Orchestrator | RedTeam |
| `current_attack` | RedTeam | Judge |
| `attack_results` | RedTeam | Judge, Documentation |
| `current_verdict` | Judge | Orchestrator, Documentation |
| `confirmed_findings` | Documentation | Orchestrator, Regression |
| `session_cost_usd` | CostTracker (all nodes) | Orchestrator |
| `stop_campaign` | Orchestrator, CostCheck | Graph router |
| `escalate_to_human` | Judge | API (surfaces to operator) |
| `needs_mutation` | Judge | Graph router → RedTeam |
| `mutation_count` | RedTeam | RedTeam (self-limit) |

### Conditional Routing Logic

```
After JudgeAgent runs:
  IF verdict = SUCCESS AND confidence >= 0.7  → route to DocumentationAgent
  IF verdict = PARTIAL OR confidence < 0.6    → route back to RedTeamAgent (mutate)
  IF mutation_count >= max_mutations          → route to OrchestratorAgent (next attack)
  IF verdict = FAILURE                        → route to OrchestratorAgent (next attack)
  IF escalate_to_human = True                 → pause graph, notify operator via API
  IF stop_campaign = True                     → END

After DocumentationAgent runs:
  → cost_check_node
  IF session_cost_usd < ceiling               → route to OrchestratorAgent (next attack)
  IF session_cost_usd >= ceiling              → END (cost circuit breaker)
```

---

## Data Flow: End-to-End Campaign

```
1. Operator calls POST /api/v1/campaigns
   └─ FastAPI validates request, creates Campaign record in DB
   └─ Enqueues campaign task to Redis task queue

2. Background worker picks up task
   └─ Initializes AgentForgeState with campaign_id
   └─ Invokes campaign_graph.run(state)

3. OrchestratorAgent node executes
   └─ Queries coverage_tracker for category coverage percentages
   └─ Queries DB for open high-severity findings
   └─ Checks session_cost_usd vs MAX_TOKENS_PER_CAMPAIGN
   └─ Selects highest-priority attack category
   └─ Writes CampaignConfig to state.campaign_config

4. RedTeamAgent node executes
   └─ Loads seed attack cases from attack_library for selected category
   └─ Uses Groq/Mistral to generate/mutate adversarial prompt
   └─ Calls target_client.send_message() → Clinical Co-Pilot
   └─ Writes AttackResult (prompt + response) to state.attack_results
   └─ Increments state.mutation_count

5. JudgeAgent node executes
   └─ Loads rubric for attack category from evals/categories/{cat}/rubric.yaml
   └─ Evaluates AttackResult against rubric using Claude Sonnet (temp=0.0)
   └─ Writes JudgeVerdict to state.current_verdict
   └─ IF confidence < 0.6: sets state.escalate_to_human = True

6. Conditional router decides next node
   └─ SUCCESS + high confidence → DocumentationAgent
   └─ PARTIAL → back to RedTeamAgent (mutation)
   └─ FAILURE → back to OrchestratorAgent

7. DocumentationAgent node executes (if SUCCESS)
   └─ Generates VulnerabilityReport markdown
   └─ Saves to vulnerability_reports/VULN-{id}.md
   └─ Saves structured JSON to DB
   └─ IF severity = CRITICAL: sets status = PENDING_APPROVAL
      └─ Operator must call POST /api/v1/findings/{id}/approve

8. Cost check node
   └─ IF under ceiling → back to OrchestratorAgent (loop)
   └─ IF over ceiling → END campaign

9. All events logged to:
   └─ Langfuse (LLM traces with token counts)
   └─ Prometheus (metrics: attack_count, verdict_outcomes, cost_usd)
   └─ PostgreSQL audit_log (immutable)
   └─ structlog JSON (Railway log drain)
```

---

## Database Schema

```sql
-- Core tables

CREATE TABLE campaigns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    status VARCHAR(20) NOT NULL,  -- RUNNING | COMPLETED | FAILED | CANCELLED
    attack_category VARCHAR(50),
    config JSONB NOT NULL,
    started_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    total_cost_usd DECIMAL(10,4),
    findings_count INT DEFAULT 0
);

CREATE TABLE attack_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_id UUID REFERENCES campaigns(id),
    attack_case_id VARCHAR(50),
    category VARCHAR(50) NOT NULL,
    subcategory VARCHAR(100),
    prompt TEXT NOT NULL,
    response TEXT NOT NULL,
    verdict VARCHAR(20),      -- SUCCESS | FAILURE | PARTIAL | UNCERTAIN
    confidence DECIMAL(3,2),
    mutation_generation INT DEFAULT 0,
    cost_usd DECIMAL(10,4),
    latency_ms INT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE vulnerability_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vuln_id VARCHAR(20) UNIQUE NOT NULL,  -- VULN-001, VULN-002, ...
    title VARCHAR(255) NOT NULL,
    severity VARCHAR(10) NOT NULL,        -- CRITICAL | HIGH | MEDIUM | LOW
    status VARCHAR(20) NOT NULL,          -- OPEN | PENDING_APPROVAL | IN_PROGRESS | RESOLVED
    category VARCHAR(50) NOT NULL,
    cvss_score DECIMAL(3,1),
    attack_result_id UUID REFERENCES attack_results(id),
    report_markdown TEXT,
    report_json JSONB,
    discovered_at TIMESTAMPTZ DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    approved_by VARCHAR(255),
    approved_at TIMESTAMPTZ
);

CREATE TABLE regression_cases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID REFERENCES vulnerability_findings(id),
    attack_sequence JSONB NOT NULL,       -- reproducible attack steps
    expected_safe_behavior TEXT NOT NULL,
    evaluation_rubric JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE
);

CREATE TABLE regression_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    trigger VARCHAR(20) NOT NULL,         -- MANUAL | SCHEDULED | DEPLOYMENT
    target_url TEXT NOT NULL,
    started_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    total_cases INT,
    pass_count INT,
    fail_count INT,
    regression_count INT
);

CREATE TABLE regression_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id UUID REFERENCES regression_runs(id),
    case_id UUID REFERENCES regression_cases(id),
    outcome VARCHAR(20) NOT NULL,         -- PASS | FAIL | REGRESSION
    response TEXT,
    notes TEXT,
    executed_at TIMESTAMPTZ DEFAULT NOW()
);

-- Append-only audit log (UPDATE/DELETE blocked by trigger)
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    actor VARCHAR(255) NOT NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id UUID,
    ip_address INET,
    user_agent TEXT,
    metadata JSONB
);

-- Trigger: prevent modification of audit_log
CREATE OR REPLACE FUNCTION prevent_audit_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit log is immutable — modification not permitted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_immutable
BEFORE UPDATE OR DELETE ON audit_log
FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();
```

---

## Security Architecture (5-Layer Moat)

```
Internet
    │
    ▼
┌─────────────────────────────────────────────────┐
│  Layer 1: WAF (waf.py FastAPI middleware)        │
│  - Blocks SQL injection patterns                 │
│  - Blocks SSRF (internal IP in URL params)       │
│  - Blocks path traversal (../, %2e%2e)          │
│  - Blocks known scanner user agents             │
│  - Blocks IP ranges on blocklist                │
│  - Rejects payloads > 50KB                      │
└────────────────────────┬────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────┐
│  Layer 2: Rate Limiter (slowapi + Redis)         │
│  - Per-IP: 60 req/min general, 5 for campaigns  │
│  - Per-user: 3 campaign starts/hour (operator)  │
│  - Burst tolerance: 10 requests                 │
│  - Returns 429 with Retry-After header          │
└────────────────────────┬────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────┐
│  Layer 3: Authentication (auth.py)              │
│  - JWT bearer tokens (60-min expiry)            │
│  - API key auth (bcrypt-hashed in DB)           │
│  - RBAC: viewer / operator / admin              │
│  - Admin ops require X-Admin-Confirm header     │
└────────────────────────┬────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────┐
│  Layer 4: Input Guard (input_guard.py)          │
│  - Pydantic strict validation on all bodies     │
│  - Strips control characters from string fields │
│  - Validates UUIDs, enums, numeric ranges       │
│  - Detects prompt injection in user-provided    │
│    fields (target_url, config params)           │
└────────────────────────┬────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────┐
│  Layer 5: Audit Log (audit_log.py)              │
│  - Every state mutation logged immutably        │
│  - Append-only (DB trigger)                     │
│  - Logs: actor, action, resource, IP, UA        │
│  - Available to admin via GET /api/v1/audit     │
└────────────────────────┬────────────────────────┘
                         │
                         ▼
                  FastAPI Route Handler
```

---

## Observability Architecture

```
Agent Execution
     │
     ├─── Langfuse Trace ──────→ cloud.langfuse.com
     │    (LLM calls, token     (inter-agent traces,
     │     counts, latency,      cost by agent,
     │     prompt/response)      drift detection)
     │
     ├─── Prometheus Metrics ──→ /metrics endpoint
     │    agentforge_attacks_total{category, outcome}
     │    agentforge_session_cost_usd{campaign_id}
     │    agentforge_judge_confidence_histogram
     │    agentforge_regression_outcome{outcome}
     │    agentforge_coverage_percent{category}
     │    agentforge_api_request_duration_seconds
     │
     ├─── structlog JSON ──────→ Railway log drain
     │    {"event": "attack_sent", "campaign_id": ...,
     │     "category": ..., "cost_usd": ...}
     │
     └─── audit_log table ────→ PostgreSQL
          (immutable record of all mutations)
```

### Orchestrator Dashboard Queries

The OrchestratorAgent answers these questions before every campaign decision:

```sql
-- Coverage per category
SELECT category, 
       COUNT(*) as cases_run,
       COUNT(*) FILTER (WHERE verdict = 'SUCCESS') as successes,
       ROUND(COUNT(*) * 100.0 / MAX(total_cases_in_category), 1) as coverage_pct
FROM attack_results GROUP BY category;

-- Open critical/high findings
SELECT COUNT(*) FROM vulnerability_findings
WHERE severity IN ('CRITICAL', 'HIGH') AND status = 'OPEN';

-- Session cost
SELECT SUM(cost_usd) FROM attack_results WHERE campaign_id = $1;

-- Recent regressions
SELECT COUNT(*) FROM regression_results
WHERE outcome = 'REGRESSION' AND executed_at > NOW() - INTERVAL '7 days';
```

---

## Known Tradeoffs

| Decision | Chosen Approach | Alternative | Reason |
|---|---|---|---|
| Agent framework | LangGraph | CrewAI, AutoGen | LangGraph's explicit graph + state model is most debuggable for security workflows; CrewAI is higher-level but less transparent |
| RedTeam model | Groq/Mistral | GPT-4o | Mistral has fewer safety filters for offensive prompts; GPT-4o refuses many attack generation requests |
| Judge model | Claude Sonnet | GPT-4o | Best reasoning + lowest hallucination rate for evaluation; consistent criteria across runs |
| State persistence | PostgreSQL | SQLite | Railway-native; JSONB for flexible attack case storage; required for multi-worker deployment |
| Deployment | Railway | AWS ECS | Railway's simplicity matches project scale; AWS adds operational overhead without benefit at current scale |
| Cost control | Hard token ceiling | Soft alerts | Healthcare context requires hard limits; soft alerts can be ignored; circuit breaker is non-negotiable |
| Human gates | CRITICAL findings only | All findings | Balances autonomy with safety; LOW/MEDIUM/HIGH can be filed automatically with low risk of wasted engineering time |

---

## Scaling Considerations

| Scale | Architecture Change Needed |
|---|---|
| 100 test runs/day | Current architecture sufficient |
| 1,000 test runs/day | Add Redis queue workers (3 workers); upgrade Railway plan |
| 10,000 test runs/day | Switch to AWS ECS; add read replicas for DB; consider SQS for task queue |
| 100,000 test runs/day | Full microservices split; Kafka for event bus; separate observability cluster |

---

*Version: 1.0.0 | AgentForge | 2026-05-11*
