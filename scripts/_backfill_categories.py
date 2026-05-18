"""One-shot: normalize category strings stored as `AttackCategory.X` to `x`.

Background: `str(StrEnum_member)` on Python 3.11+ returns `"AttackCategory.X"`
instead of the enum value. Several repository writes used `str(...)` and
poisoned the column. The coverage tracker joins on the lowercase `.value`,
so coverage read 0% across the board.

This script lowercases + strips the `AttackCategory.` prefix in place. Safe
to re-run; it only updates rows that still match the bad pattern.
"""

from __future__ import annotations

import asyncio

from sqlalchemy import text

from agentforge.db.database import session_scope


UPDATES = [
    # table, column
    ("attack_results", "category"),
    ("vulnerability_findings", "category"),
    ("campaigns", "attack_category"),
]


async def main() -> None:
    async with session_scope() as s:
        for table, col in UPDATES:
            result = await s.execute(
                text(
                    f"UPDATE {table} SET {col} = lower(replace({col}, 'AttackCategory.', '')) "
                    f"WHERE {col} LIKE 'AttackCategory.%'"
                )
            )
            print(f"  {table}.{col}: {result.rowcount} rows normalized")
        print("done")


asyncio.run(main())
