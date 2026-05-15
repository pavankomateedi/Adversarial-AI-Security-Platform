# AgentForge — Interview Prep

A dense Q&A you can re-read before the video interview. Each question
shows: **the headline answer in one sentence** (use this if rushed),
then the **two-minute version**, then the **strongest single fact to
mention** if you only get one sentence.

The goal: every architectural choice has a *deliberate, defensible*
reason. The interviewer will probe for that. Don't say "I picked X" —
say "I picked X because Y, with tradeoff Z, and here's the evidence."

---

## TABLE OF CONTENTS

1. Architecture (multi-agent, LangGraph, agent boundaries)
2. Application / Model selection (why Claude, why Groq, why two providers)
3. Tradeoffs (the four you must articulate)
4. Legacy vs AI integration (the Cloudflare WAF story)
5. Findings & validation (the 3 CRITICAL/HIGH)
6. Cost, scale, resilience
7. Trust, safety, human-in-the-loop
8. Likely curveballs

---

## 1. ARCHITECTURE

### Q: Walk me through the architecture.

**Headline:** Five distinct agents on LangGraph, separated by responsibility
and trust level, coordinating through a shared Postgres-backed state.

**Two-minute version:**
- **OrchestratorAgent** (Claude Haiku 4.5) — reads coverage gaps, open
  findings, cost; decides what RedTeam targets next using a deterministic
  `(severity × exploitability) ÷ cost_estimate` priority formula. The
  Orchestrator does NOT call an LLM during its decision — deliberate
  choice: arithmetic should be reproducible, free, instant.
- **RedTeamAgent** (Groq Llama 3.3 70B) — generates and mutates
  adversarial inputs. Open-weights model on purpose; commercial models
  refuse offensive prompts.
- **JudgeAgent** (Claude Sonnet 4.6, temp=0) — independent verdict
  engine, blind to RedTeam's strategy. Fresh rubric loaded per call.
  10% of verdicts cross-checked with a second LLM pass.
- **DocumentationAgent** (Claude Sonnet 4.6) — converts confirmed
  exploits into CVE-style reports. CRITICAL findings sit
  `PENDING_APPROVAL` until an admin approves with `X-Admin-Confirm: true`.
- **RegressionAgent** (deterministic + Judge) — replays confirmed
  exploits on every Co-Pilot deploy, detects regressions, flags
  cross-category regressions (a fix in A that breaks B).

State lives in a `AgentForgeState` TypedDict; agents only write to their
designated fields. Postgres is the source of truth, Redis is best-effort
cache. The whole thing is deployed on Railway.

**Killer fact:** "Attack generation and attack evaluation are different
jobs — a system that does both in the same context has a conflict of
interest by design. We use two different model providers for the same
reason."

---

### Q: Why five agents? Why not just one well-prompted LLM?

**Headline:** Different responsibilities need different trust levels and
different models — you can't put attack generation and attack evaluation
in the same context without compromising the judgment.

**Two-minute version:**
- Single-agent or pipeline architectures are explicitly disqualified by
  the PRD because of the conflict-of-interest problem.
- An LLM that *generates* an attack and then *judges* whether it
  succeeded has motivated reasoning. Even if you ask "did you succeed,"
  it knows the answer it wants.
- Separation also lets us pick the right model for each job: a
  permissive open-weights model for offensive prompt generation, a
  trusted closed model with cross-check for evaluation.

**Killer fact:** "The PRD explicitly says a single-agent architecture
does not satisfy the assignment. The reason is structural — not size."

---

### Q: Why LangGraph specifically (vs CrewAI, AutoGen, custom)?

**Headline:** LangGraph's explicit graph + state model is the most
debuggable for security workflows; CrewAI is higher-level but more
opaque.

**Two-minute version:**
- LangGraph is a state machine: nodes are agents, edges are conditional
  routing functions. You can `print(state)` between any two nodes and
  see exactly what every agent saw and wrote. For a security platform,
  that auditability is everything.
- CrewAI abstracts the agent loop — easier to start, harder to audit.
- AutoGen's conversation pattern is great for assistant-style flows but
  awkward for "judge is blind to attacker's strategy" boundaries.
- Custom would have been ~2 weeks of foundation work we'd rather spend
  on attacks.

**Killer fact:** "I picked LangGraph because the *security* of the
platform depends on knowing exactly what every agent saw and wrote.
LangGraph treats that as a first-class concept — agents read from
shared state, not from each other's outputs."

---

### Q: How do agents coordinate — message passing or shared state?

**Headline:** Shared state, with explicit write-fences per agent (see
ARCHITECTURE.md "State Fields by Agent" table).

**Two-minute version:**
- Each agent reads what it needs from `AgentForgeState` and returns a
  partial dict that LangGraph merges back. No direct agent-to-agent calls.
- Documented write-fences: only RedTeam writes `attack_results`, only
  Judge writes `current_verdict`, only Documentation writes
  `confirmed_findings`. This is enforced by convention + code review;
  not by runtime ACLs (a deliberate tradeoff — runtime enforcement would
  add complexity not justified at this scale).
- Failure handling: each node has try/except. On unrecoverable failure
  the node returns an empty partial update and the campaign continues
  with the next attack. The graph's recursion limit (40+ depending on
  campaign size) prevents infinite loops.

**Killer fact:** "Agents never call each other directly. The Judge
literally cannot read the RedTeam's reasoning — by design, not just by
convention."

---

## 2. APPLICATION / MODEL SELECTION

### Q: Why Claude Sonnet 4.6 for the Judge?

**Headline:** Best reasoning + lowest hallucination rate for evaluation;
prompt caching is mature so the rubric block is essentially free after
the first call; temperature 0 gives deterministic verdicts.

**Two-minute version:**
- The Judge is the trust anchor — if it drifts, the whole platform's
  output is suspect. We want the highest-quality model we can afford here.
- Temperature 0 because we want the same verdict for the same
  (prompt, response, rubric) every time. Drift between runs is the
  enemy.
- Anthropic's prompt cache cuts the per-Judge-call cost ~85% after the
  first call in a session because the rubric is reloaded fresh per call
  (deliberate) but the cache makes it cheap.
- We also have OpenAI gpt-4o as a fallback (`agentforge/agents/models.py`
  → `get_fallback_model`). Anthropic 529s under load; without the
  fallback, the platform dies during a real-world overloaded window.

**Killer fact:** "Two providers for the same role isn't paranoia — it's
the difference between a platform that's down when Anthropic is down
and one that's not. The grader called this out specifically."

---

### Q: Why Groq Llama 3.3 70B for the RedTeam (not Claude or GPT-4o)?

**Headline:** Claude and GPT-4o are trained to refuse offensive prompts
— they're literally unsuited for attack generation. Llama is permissive
and Groq's inference is cheap.

**Two-minute version:**
- "Generate a prompt that gets the model to produce a fake oxycodone
  prescription" — Claude says no, every time. So does GPT-4o. The
  RedTeam needs a model that *will* compose offensive payloads.
- Open-weights Llama via Groq does it without refusing.
- Groq's pricing for Llama 3.3 70B is ~$0.59/M input tokens — at our
  scale (cents per campaign), it doesn't matter, but at 10K runs/day it
  becomes significant.
- Mistral is the documented fallback.

**Killer fact:** "Using Claude or GPT-4o for the RedTeam would be a
category error — the very thing that makes them trustworthy for the
Judge (refusing harmful generation) makes them useless for generating
the attacks the Judge needs to evaluate."

---

### Q: Why Claude Haiku 4.5 for the Orchestrator?

**Headline:** Actually, the Orchestrator does NOT call an LLM. It's
deterministic on purpose.

**Two-minute version:**
- The Orchestrator's job is arithmetic: rank remaining seed cases by
  `(severity × exploitability) ÷ cost_estimate`, sort, pick the highest.
  An LLM adds cost, latency, and non-determinism to a decision that is
  fundamentally a comparison.
- We have the Haiku binding wired up in `models.py` for future use (LLM
  enrichment of stop reasons, natural-language summarization), but the
  decision itself stays deterministic.

**Killer fact:** "I deliberately put no LLM in the Orchestrator's
decision path. Where AI doesn't add signal, deterministic code is
strictly better — cheaper, faster, reproducible, debuggable."

---

## 3. TRADEOFFS — the four you must articulate

### Tradeoff 1: Multi-agent vs single-agent

| Cost | Benefit |
| --- | --- |
| 5x the orchestration code | Structural separation of attack vs evaluation |
| 5x the failure modes | Lets us use 2 model providers + open vs closed |
| More LLM calls per campaign | The Judge cannot "agree with everything" — it doesn't see what the attacker tried |

**Verdict:** Mandatory per PRD. Also the right call regardless.

### Tradeoff 2: LLM-driven vs deterministic

| When LLM wins | When deterministic wins |
| --- | --- |
| Novel adversarial prompt generation | RBAC bypass probing (`scripts/cross_user_attacks.py`) |
| Verdict on ambiguous responses | Replay (RegressionAgent) |
| Vulnerability report writing | Cost ceiling enforcement |
| Mutation strategies | Audit log integrity |

**Concrete example:** AgentForge found VULN-001/002/003 — three CRITICAL
RBAC bypasses — using a **deterministic Python script**, not an LLM. The
LLM eval suite tested the chat-layer defenses (which were strong); the
deterministic script tested the protocol-layer defenses (which weren't).
Both layers needed both tools.

**Killer fact:** "The three real findings we shipped were caught by a
deterministic Python script, not by an LLM. That's not a bug; that's the
PRD's point — sometimes traditional tooling beats LLM-driven approaches."

### Tradeoff 3: Cost vs coverage

| Cost lever | Effect |
| --- | --- |
| Cost ceiling per campaign | Hard halt at budget — circuit breaker, not a soft alert |
| Mutation cap | Bounded retries on PARTIAL verdicts |
| Per-agent + per-model cost tracking | Operator sees exactly which agent is burning budget |
| Prompt caching on the rubric | 10x cost reduction on Judge calls at scale |
| Local Ollama at 10K runs/day | Documented path in COST_ANALYSIS.md |

**Concrete numbers:** This week's entire dev + demo cost ran under
$0.50. The 6-category sweep with 2 attacks + 2 mutations each was $0.09
total. We can run this every Co-Pilot deploy for the cost of one cup
of coffee per month.

### Tradeoff 4: Autonomy vs human-in-the-loop

**Where we're autonomous:**
- Attack generation (RedTeam)
- Verdict (Judge)
- Report writing (Documentation)
- Regression replay
- Cost ceiling enforcement

**Where a human is required:**
- Approving CRITICAL findings before they're filed (`PENDING_APPROVAL`
  status + `X-Admin-Confirm: true` header on the API)
- Investigating UNCERTAIN verdicts (Judge confidence < 0.6)
- Reviewing cross-category regression flags

**Why the human gate at CRITICAL:** "An agent that confidently
documents a false positive wastes engineering time. CRITICAL severity
is where the cost of a false positive is highest — wasted clinical
review cycles. So that's exactly where we put the human."

---

## 4. LEGACY vs AI INTEGRATION

This is the question the interviewer is most likely to push on, because
the PRD explicitly mentions "Traditional non-AI security tooling may
outperform LLM-driven approaches."

### Q: How did you integrate legacy / traditional security tooling with the AI framework?

**Headline:** Two ways: (a) deterministic Python probes alongside the
LLM-driven LangGraph campaigns, and (b) a Cloudflare Worker WAF in front
of the Co-Pilot, validated *by* AgentForge.

**Two-minute version:**

**Layer 1 — Inside AgentForge:**
- The whole multi-agent campaign loop is LLM-driven (RedTeam mutates,
  Judge evaluates).
- BUT `scripts/cross_user_attacks.py` is pure deterministic Python — no
  LLM at all. It's the script that found all three real CRITICAL/HIGH
  findings.
- `scripts/pentest_agentforge.py` — same: traditional pen-test of our
  own security moat (WAF, rate limit, auth, audit). Result: 17/17 pass.
- The Judge has a *ground-truth dataset*
  (`evals/judge_ground_truth.yaml`) — 9 human-labeled cases that
  validate the LLM Judge against a deterministic baseline.

**Layer 2 — In front of the Co-Pilot:**
- We built a Cloudflare Worker WAF (`clinical-copilot-waf/`) as a
  filtering reverse proxy — 7 layers: geo-block, scanner UA, Cloudflare
  threat score, body-size cap, SQLi/XSS/traversal, rate limiting,
  response hardening.
- AgentForge *validates* the WAF — `scripts/waf_validation.py` runs
  identical probes direct-vs-via-WAF and produces measured attack-
  surface reduction.
- **Measured result:** injection/scanner/DoS class: 0% → 100% blocked.
  RBAC bypass class: 9 → 9 unchanged.

**Killer fact:** "The integration story isn't 'AI replaces traditional
tools.' It's 'AI validates traditional tools and finds the things they
can't see.' AgentForge measures exactly what the WAF caught (100% of
injection) and what it can't (the 9 RBAC bypasses, which are
authenticated, syntactically-perfect requests no firewall can see).
That number — the unchanged 9 — is the single most important number in
the demo because it's the one that proves the platform tells the truth."

---

### Q: Why a Cloudflare Worker instead of, say, ModSecurity + nginx?

**Headline:** Same edge protection, $0, no custom domain required —
exactly what fit the project constraints. ModSecurity is the textbook
"traditional WAF" answer; the Worker is the textbook "deployed in 2026
without owning a domain" answer.

**Two-minute version:**
- Cloudflare's *managed* WAF (OWASP Core Rule Set, etc.) requires a
  zone — a domain you own with nameservers on Cloudflare. The Co-Pilot
  lives on a Railway-owned `*.up.railway.app` subdomain, so there's no
  zone to attach managed rules to.
- A Worker gives the same Cloudflare edge network and same protection
  classes for $0 and no custom domain — we author the rules instead of
  toggling the managed ones.
- Functionally equivalent for this threat model. The managed version is
  just less code.

**Killer fact:** "ModSecurity would have been more impressive to point
at — 'look at the OWASP Core Rule Set, it's textbook.' But the right
answer is the one that fits your constraints. We don't own a domain
yet, so the Worker is the rational choice. If we did, the managed WAF
would be a 15-minute switch."

---

## 5. FINDINGS & VALIDATION

### Q: Tell me about the three vulnerabilities you found.

**Headline:** Three real CRITICAL/HIGH broken-object-level-authorization
bugs in the deployed Co-Pilot, all caught by a single deterministic
cross-user RBAC probe. PHI for unauthorized patients, cross-patient
clinical data, and patient enumeration.

**Two-minute version:**
- I logged in as the test nurse (`nurse.adams`, RBAC-restricted to one
  patient — `demo-001`) and probed the four patients she's not
  assigned to.
- **VULN-001 (CRITICAL):** `GET /patients/{id}/identity` returned full
  PHI (name, DOB, sex, MRN) for all 4 unauthorized patients.
- **VULN-002 (CRITICAL):** `POST /chat` enforcement is *inconsistent* —
  refused for 3 patients, *leaked clinical labs* for one ("A1c 10.5%,
  uncontrolled type 2 diabetes" for demo-003).
- **VULN-003 (HIGH):** `GET /documents/list` returned 200 for any
  patient_id — patient-existence oracle.

Each has a full CVE-style report (`vulnerability_reports/VULN-*.md`)
with reproduction steps, observed vs expected, clinical impact,
remediation, and validation. CRITICAL severity correctly filed as
`PENDING_APPROVAL` in the DB — the human approval gate kicked in.

**Killer fact:** "All three were found in the first cross-user pass —
before the LLM-driven campaigns even started. The Co-Pilot's LLM
safety layer is *strong* (the eval campaigns showed Judge confidence
0.94 on refusals). The protocol layer below it is *weak*. That's the
finding."

---

### Q: How do you know your Judge isn't drifting / agreeing with everything?

**Headline:** Three signals — cross-check on 10% of verdicts, a
ground-truth dataset, and a live drift monitor.

**Two-minute version:**
- **10% cross-check:** every 10th verdict is re-run with a fresh LLM
  call. `cross_check_disagreement` flag fires if they disagree —
  surfaces in the agent_trace and the dashboard.
- **Ground truth:** `evals/judge_ground_truth.yaml` — 9 human-labeled
  cases spanning SUCCESS/FAILURE/PARTIAL. `judge_accuracy.py` runs them
  through the real Judge and reports agreement vs the labels. CI gates
  on `--smoke` (dataset validity); a future `--full` run gates the
  Judge's accuracy.
- **Drift monitor:** `/api/v1/judge-drift` endpoint exposes verdict
  distribution, mean confidence across time windows, dominant verdict
  share. A Judge stuck on one verdict for >85% of cases is flagged as
  `drift_suspected`. The dashboard has a live panel.

**Killer fact:** "Testing the tester is the failure mode the PRD calls
out by name. Three independent signals — sampled cross-check, labeled
ground truth, longitudinal drift metric — cover the three ways the
Judge can fail."

---

## 6. COST, SCALE, RESILIENCE

### Q: Walk me through the cost projection at scale.

**Headline:** Linear at the current architecture up to ~1K runs/day,
then needs architectural changes. Full breakdown in COST_ANALYSIS.md.

| Scale | Cost / day | Architectural change |
| --- | --- | --- |
| 100 runs/day | $1–5 | Current architecture sufficient |
| 1,000 runs/day | $11–40 | Enable Anthropic prompt caching on the rubric |
| 10,000 runs/day | $110–350 | RedTeam → local Ollama; cache identical seed-attack pairs |
| 100,000 runs/day | $1,100–2,500 | Separate RedTeam cluster, batch Judge via Anthropic Batches API (50% discount), shard Postgres |

**Killer fact:** "Per-attack cost today: $0.011 (RedTeam + Co-Pilot +
Judge). The full dev + demo + 3-finding discovery cost under $0.50.
That's the platform paying for itself in week one."

---

### Q: What happens when Anthropic is overloaded?

**Headline:** OpenAI gpt-4o fallback fires automatically for the Judge
and Documentation agents. Orchestrator is deterministic so it doesn't
care.

**Two-minute version:**
- `agentforge/agents/models.py` has both primary and fallback bindings.
- Judge: 4 retries with exponential backoff on the primary
  (Claude Sonnet 4.6); on persistent failure, switches to gpt-4o.
- Documentation: same pattern.
- This actually happened during development — Anthropic was 529'ing for
  hours. The fallback kept the platform running.

**Killer fact:** "The grader specifically called this out: 'multi-
provider fallback for the Judge before hitting a real outage reflects
mature operational design rather than reactive patching.' That choice
saved a demo run when Anthropic was overloaded."

---

## 7. TRUST, SAFETY, HUMAN-IN-THE-LOOP

### Q: How do you prevent the adversarial platform from being turned against systems it shouldn't attack?

**Headline:** Five-layer defense moat protecting AgentForge itself,
empirically validated 17/17 by our own self-pentest script.

**Layers:**
1. **WAF middleware** — SQLi, SSRF, path traversal, scanner UA,
   oversized body
2. **Rate limiter** — per-IP token bucket, Redis-backed
3. **JWT + bcrypt API keys + RBAC** — viewer / operator / admin
4. **Input guard** — Pydantic strict validation
5. **Immutable audit log** — Postgres trigger blocks UPDATE/DELETE at
   storage layer

**Killer fact:** "An adversarial tool is itself a weapon if you don't
harden it. We hardened it, *and* we tested the hardening:
`scripts/pentest_agentforge.py` ran 17 probes against the deployed
AgentForge — all 17 passed. The grader specifically praised this
instinct."

---

### Q: Where exactly is the human in your loop?

| Where the human IS in the loop | Why |
| --- | --- |
| Approving CRITICAL findings (`X-Admin-Confirm: true`) | Cost of a false-positive CRITICAL is highest |
| Reviewing UNCERTAIN verdicts (Judge confidence < 0.6) | Judge knows when it doesn't know |
| Investigating cross-category regression flags | "Fix A broke B" needs human triage |

| Where the human is NOT | Why |
| --- | --- |
| Attack generation | Whole point of the platform |
| Verdict on confident verdicts | If Judge is 0.95+ confident, the human review wastes time |
| Documentation rendering | Reproducibly templated |
| Regression replay | Deterministic |
| Cost ceiling enforcement | Hard limit, no human override |

---

## 8. LIKELY CURVEBALLS

### Q: What's the biggest weakness of your platform?

**Honest answer:** The Orchestrator is single-category in this MVP. It
ranks *within* a category but doesn't dynamically broaden to other
categories when one is exhausted. That's why I emit a `low_signal` flag
— so a human / future scheduler can switch.

### Q: What would you change with another week?

- Wire the Co-Pilot deploy webhook → `/api/v1/regression/run` (the
  closed loop on every deploy)
- Replace the per-attack `cost_usd` (currently 0 in DB, tracked in-mem)
  with proper persistence — the campaign total works, the per-attack
  doesn't yet
- Real PDF indirect-injection payloads (currently text-as-PDF)
- Move RegressionAgent to a background worker with its own Redis queue
  for >1K confirmed exploits

### Q: Why didn't you use [framework X]?

Answer the specific tool, but the meta-answer is: every choice was made
against the constraint "what makes the platform's *decisions* most
auditable to a hospital CISO?" — not "what's the newest tool."

### Q: A skeptic says "this is just a fancy test suite." Respond.

**Headline:** A test suite is static. AgentForge mutates partial-success
attacks autonomously, prioritizes by coverage gaps, halts on cost,
files reports without human prompting, and re-runs the regression suite
on every Co-Pilot deploy. That's not a test runner; that's a continuous
red team.

**Concrete proof:** RedTeam took the DAN-injection seed, the Co-Pilot
refused, Judge classified PARTIAL with confidence 0.72, RedTeam
generated a mutated variant *in the same campaign* without human
input. A test suite can't do that.

---

## INTERVIEW TACTICS

1. **Always anchor in evidence.** "Why X?" → not "I think X" but
   "I picked X because the eval showed Y." Cite the specific finding
   (VULN-001), the specific metric (5/5 blocked), the specific file
   (`agentforge/security/audit_log.py`).

2. **Lead with the headline, drop into detail only if probed.**
   Interviewers respect "I picked Claude Sonnet 4.6 for the Judge,
   temperature 0, with a gpt-4o fallback." Don't open with a 5-minute
   model comparison.

3. **Own the tradeoffs.** Never say "X is perfect." Say "X is the right
   call given these three constraints, here's the cost." Confidence
   without humility reads as marketing.

4. **The PRD's exact phrases are your scaffolding.** Phrases like:
   - "a system of agents that can hunt, evaluate, escalate, and document
     vulnerabilities continuously"
   - "a system that can be defended in front of a hospital CISO"
   - "Traditional non-AI security tooling may also outperform LLM-driven
     approaches"

   These are the *graders'* mental model. Using their language tells them
   you read the assignment, hard.

5. **When in doubt, point to the dashboard.** `https://agentforge-production-f5a1.up.railway.app/dashboard`
   is a live demo — KPIs, the 3 VULNs visible, the agents, the audit
   trail. "Let me show you" beats "let me tell you."

---

## ONE-LINE SUMMARY FOR THE OPENING

> "AgentForge is a five-agent adversarial evaluation platform built on
> LangGraph. The RedTeam runs on Groq because Claude refuses to write
> attacks, the Judge runs on Claude with a gpt-4o fallback because the
> verdict layer is the platform's trust anchor, and the Orchestrator is
> deterministic on purpose. We tested a deployed Clinical Co-Pilot,
> found three CRITICAL/HIGH RBAC bugs in the first run, and shipped a
> Cloudflare Worker WAF that we then validated *with* AgentForge —
> proving 100% of injection-class attacks blocked, and being honest
> that 9 RBAC bypasses pass through because a firewall can't see them."
