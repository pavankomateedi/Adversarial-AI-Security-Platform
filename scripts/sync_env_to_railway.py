"""Sync .env values to Railway variables for the linked service.

Skips Railway-managed values (DATABASE_URL, REDIS_URL — set as references)
and dev-only values that should differ in production.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV_PATH = ROOT / ".env"

# Keys we DO NOT push to Railway (managed or dev-only).
SKIP_KEYS = {
    "DATABASE_URL",        # Railway: reference to ${{Postgres.DATABASE_URL}} (handled below)
    "REDIS_URL",           # Railway: reference to ${{Redis.REDIS_URL}}
    "ENVIRONMENT",         # Override to production
    "CORS_ALLOWED_ORIGINS",  # Override
    "SECRET_KEY",          # Generate fresh prod key (handled below)
    "PROMETHEUS_PORT",     # Not relevant on Railway single-container
}

# Variables we always set explicitly for production.
OVERRIDES = {
    "ENVIRONMENT": "production",
    "CORS_ALLOWED_ORIGINS": "*",
    # Use the public Railway DB url to allow asyncpg driver via prefix swap
    "DATABASE_URL": "postgresql+asyncpg://${{Postgres.PGUSER}}:${{Postgres.PGPASSWORD}}@${{Postgres.RAILWAY_PRIVATE_DOMAIN}}:${{Postgres.PGPORT}}/${{Postgres.PGDATABASE}}",
    "REDIS_URL": "${{Redis.REDIS_URL}}",
    # Generated with `python -c "import secrets; print(secrets.token_hex(32))"`
    # for this Railway deploy. Rotate via the Railway dashboard if exposed.
    "SECRET_KEY": "71a1ac234fb2d07b63ca81ec3965ec27241dc73b3a3b16303c229e16c65565a5",
}


def parse_env(path: Path) -> list[tuple[str, str]]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "=" not in s:
            continue
        key, _, val = s.partition("=")
        key = key.strip()
        val = val.strip()
        if not val:
            continue
        out.append((key, val))
    return out


def set_var(key: str, value: str) -> bool:
    """Call `railway variable set KEY=VALUE --skip-deploys`."""
    cmd = ["railway", "variable", "set", f"{key}={value}", "--skip-deploys"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, shell=True)
    except subprocess.TimeoutExpired:
        print(f"  TIMEOUT: {key}")
        return False
    ok = r.returncode == 0
    if ok:
        print(f"  set {key}  (len={len(value)})")
    else:
        print(f"  FAIL {key}: {r.stderr.strip()[:200]}")
    return ok


def main() -> None:
    env = dict(parse_env(ENV_PATH))
    # Apply overrides on top.
    env_for_railway = {**env, **OVERRIDES}
    # Drop skipped keys.
    for k in list(env_for_railway):
        if k in SKIP_KEYS:
            if k in OVERRIDES:
                continue
            del env_for_railway[k]

    print(f"Syncing {len(env_for_railway)} variables to Railway (linked service)")
    failed = 0
    for key, value in env_for_railway.items():
        if not set_var(key, value):
            failed += 1
    print(f"\nDone. {len(env_for_railway) - failed} ok, {failed} failed.")


if __name__ == "__main__":
    main()
