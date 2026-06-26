from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


def summarize_robustness_cards(
    cards_dir: str | Path,
    *,
    expected_count: int | None = None,
) -> dict[str, Any]:
    root = Path(cards_dir)
    card_paths = sorted(path for path in root.rglob("*.md") if path.is_file())
    rows = [{"card_path": str(path), "sample_id": path.stem} for path in card_paths]
    return {
        "cards_dir": str(root),
        "card_count": len(card_paths),
        "expected_count": expected_count,
        "card_generation_rate": len(card_paths) / expected_count if expected_count and expected_count > 0 else None,
        "cards": rows,
        "claim_boundary": (
            "Robustness Card coverage proves reporting completeness only. "
            "It does not prove malware behavior preservation or detector robustness."
        ),
    }


def write_card_summary(summary: dict[str, Any], output_dir: str | Path) -> None:
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    (root / "robustness_card_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (root / "robustness_card_summary.md").write_text(to_markdown(summary), encoding="utf-8")
    with (root / "robustness_card_rows.csv").open("w", encoding="utf-8", newline="") as handle:
        rows = list(summary.get("cards", []))
        fieldnames = sorted({key for row in rows for key in row}) if rows else ["sample_id", "card_path"]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def to_markdown(summary: dict[str, Any]) -> str:
    return (
        "# BinaryShield Robustness Card Coverage Summary\n\n"
        f"**Cards directory:** {summary.get('cards_dir')}\n\n"
        f"**Card count:** {summary.get('card_count')}\n\n"
        f"**Expected count:** {summary.get('expected_count')}\n\n"
        f"**Card generation rate:** {summary.get('card_generation_rate')}\n\n"
        "## Claim Boundary\n\n"
        f"{summary.get('claim_boundary')}\n"
    )
