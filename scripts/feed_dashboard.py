"""Feed the deployed Security Dashboard with real campaign data.

Triggers one campaign per attack category through the *deployed* AgentForge
API so that the campaigns land in Railway's Postgres and the dashboard's
KPIs / agent counters / coverage map fill in.

    uv run python -m scripts.feed_dashboard
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

AGENTFORGE_URL = "https://agentforge-production-f5a1.up.railway.app"
ADMIN_API_KEY = "dev-admin-key-change-me"

CATEGORIES = [
    "prompt_injection",
    "data_exfiltration",
    "state_corruption",
    "tool_misuse",
    "denial_of_service",
    "identity_exploitation",
]


async def get_token(client: httpx.AsyncClient) -> str:
    r = await client.post("/api/v1/auth/token", headers={"X-API-Key": ADMIN_API_KEY})
    r.raise_for_status()
    return r.json()["access_token"]


async def start_campaign(client: httpx.AsyncClient, token: str, category: str) -> str:
    r = await client.post(
        "/api/v1/campaigns",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={
            "config": {
                "attack_category": category,
                "priority": "HIGH",
                "max_attacks": 2,
                "max_mutations_per_attack": 1,
                "cost_budget_usd": "2.0",
                "patient_id": "demo-001",
            }
        },
    )
    r.raise_for_status()
    return r.json()["campaign_id"]


async def wait_for(client: httpx.AsyncClient, token: str, campaign_id: str, max_seconds: int = 120) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {token}"}
    started = time.time()
    while time.time() - started < max_seconds:
        r = await client.get(f"/api/v1/campaigns/{campaign_id}", headers=headers)
        r.raise_for_status()
        body = r.json()
        if body["status"] in ("COMPLETED", "FAILED", "CANCELLED"):
            return body
        await asyncio.sleep(3)
    return {"status": "TIMEOUT", "id": campaign_id}


async def main() -> None:
    async with httpx.AsyncClient(base_url=AGENTFORGE_URL, timeout=180) as client:
        token = await get_token(client)
        print(f"token issued (len={len(token)})\n")

        for category in CATEGORIES:
            try:
                cid = await start_campaign(client, token, category)
                print(f"  {category:26s}  started {cid}")
                result = await wait_for(client, token, cid)
                print(
                    f"    -> {result['status']}  "
                    f"cost=${result.get('total_cost_usd', 0)}  "
                    f"findings={result.get('findings_count', 0)}"
                )
            except httpx.HTTPStatusError as e:
                print(f"  {category}: HTTP {e.response.status_code} {e.response.text[:200]}")
            except Exception as e:  # noqa: BLE001
                print(f"  {category}: {e}")

        print("\nfetching dashboard totals...")
        r = await client.get("/api/v1/dashboard", headers={"Authorization": f"Bearer {token}"})
        r.raise_for_status()
        d = r.json()
        t = d["totals"]
        print(f"  campaigns_recent:        {t['campaigns']}")
        print(f"  attacks_recent:          {t['attacks_recent']}")
        print(f"  findings_open:           {t['findings_open']}")
        print(f"  pending_approval:        {t['findings_pending_approval']}")
        print(f"  cost_usd_grand_total:    ${t['cost_usd_grand_total']:.4f}")
        for agent_key in d["agent_order"]:
            print(f"  {agent_key:18s} llm_calls = {d['agents'][agent_key]['calls']}")


if __name__ == "__main__":
    asyncio.run(main())
