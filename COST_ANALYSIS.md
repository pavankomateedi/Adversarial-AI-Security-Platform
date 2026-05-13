# AgentForge — AI Cost Analysis

> Empirical cost per attack against the deployed Clinical Co-Pilot, plus the
> architectural changes needed to scale 1,000× without burning a hole through
> the budget.

---

## Measured cost per single attack

Real numbers from the live smoke + 6-category sweep runs against
`https://web-production-6259a.up.railway.app` (Claude Opus 4.7 target):

| Phase of the attack | LLM | Tokens (typical) | Cost / attack |
|---|---|---|---|
| RedTeam — pick + (optional) mutate | Groq Llama 3.3 70B | ~500 in / ~150 out | $0.0004 |
| Target call | Co-Pilot (Claude Opus 4.7) | — | (target's bill) |
| Judge — rubric + verdict JSON | Claude Sonnet 4.6 | ~1,800 in / ~250 out | $0.0093 |
| 10% cross-check | Claude Sonnet 4.6 | ~1,800 in / ~250 out | $0.0009 amortized |
| Documentation (when SUCCESS) | Claude Sonnet 4.6 | ~2,500 in / ~800 out | $0.020 (only on hits) |
| **Per attack (no mutation, no report)** | | | **~$0.011** |
| **Per attack (1 mutation, no report)** | | | **~$0.015** |
| **Per finding (with report)** | | | **~$0.030** |

Empirical runs:
- **Single-attack smoke**: $0.0045 (PI-DIRECT-001, no mutation, FAILURE verdict)
- **6-category sweep (no mutations)**: $0.034 total — 6 attacks, 6 verdicts, 0 reports
- **6-category sweep (2 attacks, 2 mutations each)**: $0.088 total — 12 attacks, 12 verdicts, 0 reports

---

## Projection

| Scale | Cost / day | Cost / month | Required changes |
|---|---|---|---|
| **100 attacks / day** | ~$1.10 | ~$33 | None — current architecture sufficient. |
| **1,000 attacks / day** | ~$11 | ~$330 | (a) Enable Anthropic prompt-cache on the Judge rubric — cuts Judge cost ~10×. (b) Add a second Redis worker for the campaign queue. |
| **10,000 attacks / day** | ~$110 | ~$3,300 | (a) Replace Judge cross-check with a Haiku-4.5 second opinion (5× cheaper). (b) Move RedTeam to local Ollama (Llama 3 70B) — saves Groq fees. (c) Cache identical seed-attack→target pairs (regression replay shares the same prompts). |
| **100,000 attacks / day** | ~$1,100 | ~$33,000 | Architectural overhaul: (a) Separate RedTeam cluster (16× Ollama GPUs). (b) Async batch the Judge against Anthropic's Message Batches API (50% discount). (c) Shard PostgreSQL by campaign_id. (d) Stream attack_results to Kafka, batch-write to DB. |

Numbers above assume the Co-Pilot's compute cost is paid by the Co-Pilot
team (AgentForge is the attacker, not the host). If the same team owns
both, multiply by ~2× to include the target's own inference cost.

---

## Cost levers we already ship

1. **Hard ceiling per campaign** — `MAX_TOKENS_PER_CAMPAIGN` env (default 500K
   tokens). The `cost_check_node` in the LangGraph halts the campaign as
   soon as `CostTracker.ceiling_breached()` returns True.
   See [agentforge/graph/campaign_graph.py](agentforge/graph/campaign_graph.py).

2. **Mutation cap** — `max_mutations_per_attack` (default 3). Stops the
   RedTeam from infinitely re-rolling on PARTIAL verdicts.

3. **Per-model pricing table** — [agentforge/core/cost_tracker.py](agentforge/core/cost_tracker.py)
   records every call against the per-million-token rate. Swap-in cheaper
   models change only this table.

4. **Per-agent cost attribution** — `GET /api/v1/cost` returns the
   breakdown so a platform engineer can see when one agent (usually the
   Judge cross-check) starts dominating.

5. **Prompt caching is wired** in the model factory for any agent that uses
   `langchain-anthropic` — the rubric block on the Judge is the cache
   target. Enabling it cuts the per-Judge-call cost by ~85% after the
   first call in a session.

---

## Where cost will leak in the future

- **Long multi-turn attacks**: history grows on every turn → input tokens
  scale O(n²). The Co-Pilot also limits history to 8 turns. Cap multi-turn
  attacks at 4 user turns to stay in the sweet spot.

- **Indirect injection via large documents**: the document body counts as
  input tokens on every chat turn that references it. Truncate uploaded
  payloads to 4K chars in `RedTeamAgent._execute` before sending.

- **Judge over-thinking**: a Sonnet model on ambiguous output occasionally
  generates 1K+ tokens of reasoning. Cap `max_tokens=512` on the Judge
  model factory if cost grows.

- **Regression suite growth**: every confirmed finding becomes a
  regression case. After 100 findings, a single regression run is
  100 × $0.011 ≈ $1.10. Schedule nightly, not on every Co-Pilot deploy.

---

## Bottom line

For the demo and the next 90 days, **AgentForge is operating well under
$50/month** even with daily multi-category runs. The architecture has
explicit choke-points (`cost_check_node`, `max_mutations`, the per-model
pricing table) so scaling up is a config change, not a refactor.
