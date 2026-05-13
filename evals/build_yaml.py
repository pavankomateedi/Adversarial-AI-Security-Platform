"""Regenerate per-category YAML attack files from SEED_ATTACKS.

Run when SEED_ATTACKS changes:

    uv run python -m evals.build_yaml

The YAML files become the on-disk eval dataset that the eval_runner and the
JudgeAgent's rubrics reference.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from agentforge.core.attack_library import SEED_ATTACKS

OUT_ROOT = Path(__file__).parent / "categories"


def _case_to_dict(case) -> dict:  # type: ignore[no-untyped-def]
    payload = {
        "attack_id": case.attack_id,
        "category": str(case.category),
        "subcategory": case.subcategory,
        "severity": str(case.severity),
        "exploitability": str(case.exploitability),
        "add_to_regression": case.add_to_regression,
        "description": case.description,
        "attack_sequence": [{"role": t.role, "content": t.content} for t in case.attack_sequence],
        "expected_safe_behavior": case.expected_safe_behavior,
        "evaluation_rubric": {
            "success_indicators": case.success_indicators,
            "failure_indicators": case.failure_indicators,
            "partial_indicators": case.partial_indicators,
        },
        "tags": case.tags,
        "references": case.references,
    }
    if case.requires_document_upload:
        payload["document_upload"] = {
            "filename": case.document_filename,
            "doc_type": case.document_doc_type,
            "payload": case.document_payload,
        }
    return payload


def main() -> None:
    OUT_ROOT.mkdir(parents=True, exist_ok=True)
    grouped: dict[tuple[str, str], list[dict]] = {}
    for case in SEED_ATTACKS:
        key = (str(case.category), case.subcategory)
        grouped.setdefault(key, []).append(_case_to_dict(case))

    written = []
    for (category, subcategory), cases in grouped.items():
        category_dir = OUT_ROOT / category
        category_dir.mkdir(parents=True, exist_ok=True)
        path = category_dir / f"{subcategory}.yaml"
        path.write_text(
            yaml.safe_dump({"cases": cases}, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
        written.append(str(path.relative_to(OUT_ROOT.parent)))
    for p in written:
        print(f"wrote {p}")
    print(f"\ntotal: {len(written)} files, {len(SEED_ATTACKS)} cases")


if __name__ == "__main__":
    main()
