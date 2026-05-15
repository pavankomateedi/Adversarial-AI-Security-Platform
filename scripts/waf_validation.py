"""Measure the attack-surface reduction the Clinical Co-Pilot WAF provides.

Runs an identical probe set against the Co-Pilot two ways:
  - DIRECT  : straight at the Railway URL (no WAF)
  - VIA WAF : through the Cloudflare Worker reverse proxy

then prints a before/after table: which probes the WAF blocked at the
edge, and which still got through (the RBAC class the WAF can't see).

This is the PRD's "traditional tooling + adversarial platform" synthesis:
the firewall defends, AgentForge proves — and quantifies — that it works.

    uv run python -m scripts.waf_validation \
        --direct https://web-production-6259a.up.railway.app \
        --waf    https://clinical-copilot-waf.<subdomain>.workers.dev
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from dataclasses import dataclass

import httpx

# Probe set spanning what a WAF *should* catch and what it *can't*.
# `waf_should_block` is the expectation we're validating.
_PROBES: list[dict] = [
    # --- injection / scanner classes: the WAF SHOULD block these ---
    {"name": "SQLi in query", "method": "GET",
     "path": "/health?q=union+select+*+from+users", "waf_should_block": True},
    {"name": "Path traversal in query", "method": "GET",
     "path": "/health?f=..%2f..%2fetc%2fpasswd", "waf_should_block": True},
    {"name": "XSS in query", "method": "GET",
     "path": "/health?x=<script>alert(1)</script>", "waf_should_block": True},
    {"name": "Scanner user-agent", "method": "GET", "path": "/health",
     "headers": {"User-Agent": "sqlmap/1.7"}, "waf_should_block": True},
    {"name": "Oversized body", "method": "POST", "path": "/auth/login",
     "body": "x" * (60 * 1024), "waf_should_block": True},
    # --- broken-auth class: the WAF CANNOT see these (authenticated,
    #     syntactically perfect) — expected to pass through both ways ---
    {"name": "Health check (baseline)", "method": "GET", "path": "/health",
     "waf_should_block": False},
    {"name": "OpenAPI spec (baseline)", "method": "GET", "path": "/openapi.json",
     "waf_should_block": False},
]


@dataclass
class ProbeResult:
    name: str
    direct_status: int
    waf_status: int
    waf_should_block: bool
    waf_blocked: bool

    @property
    def verdict(self) -> str:
        if self.waf_should_block:
            return "WAF BLOCKED ✓" if self.waf_blocked else "WAF MISSED ✗"
        return "passthrough ✓" if not self.waf_blocked else "false-positive ✗"


async def _send(client: httpx.AsyncClient, base: str, probe: dict) -> int:
    url = base.rstrip("/") + probe["path"]
    kwargs: dict = {"headers": probe.get("headers", {})}
    try:
        if probe["method"] == "GET":
            r = await client.get(url, **kwargs)
        else:
            r = await client.post(url, content=probe.get("body", ""), **kwargs)
        return r.status_code
    except Exception:  # noqa: BLE001 — network error counts as "unknown"
        return 0


async def run(direct: str, waf: str) -> list[ProbeResult]:
    results: list[ProbeResult] = []
    async with httpx.AsyncClient(timeout=20, follow_redirects=False) as client:
        for probe in _PROBES:
            direct_status = await _send(client, direct, probe)
            waf_status = await _send(client, waf, probe)
            # A "block" is any 4xx the WAF returns that the direct path did not.
            waf_blocked = waf_status in (400, 403, 413, 429) and waf_status != direct_status
            results.append(ProbeResult(
                name=probe["name"],
                direct_status=direct_status,
                waf_status=waf_status,
                waf_should_block=probe["waf_should_block"],
                waf_blocked=waf_blocked,
            ))
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="WAF attack-surface validation")
    parser.add_argument("--direct", required=True, help="Co-Pilot URL with NO WAF")
    parser.add_argument("--waf", required=True, help="Cloudflare Worker WAF URL")
    args = parser.parse_args()

    print(f"DIRECT : {args.direct}")
    print(f"VIA WAF: {args.waf}\n")
    results = asyncio.run(run(args.direct, args.waf))

    print(f"{'PROBE':<32}{'DIRECT':<10}{'VIA WAF':<10}{'VERDICT'}")
    print("-" * 78)
    for r in results:
        print(f"{r.name:<32}{r.direct_status:<10}{r.waf_status:<10}{r.verdict}")
    print("-" * 78)

    should_block = [r for r in results if r.waf_should_block]
    blocked = [r for r in should_block if r.waf_blocked]
    false_positives = [r for r in results if not r.waf_should_block and r.waf_blocked]

    reduction = (len(blocked) / len(should_block) * 100) if should_block else 0
    print(f"Attack-surface reduction: {len(blocked)}/{len(should_block)} "
          f"injection/scanner/DoS probes blocked at the edge ({reduction:.0f}%)")
    print(f"False positives (legit traffic blocked): {len(false_positives)}")
    print()
    print("Note: broken-object-level-authorization (VULN-001/002/003) is NOT in")
    print("this probe set — a WAF cannot see it. Those need the Co-Pilot's RBAC fix.")

    # Non-zero exit if the WAF missed something it should have caught, or
    # blocked legitimate traffic — so this can gate CI on the WAF config.
    if len(blocked) < len(should_block) or false_positives:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
