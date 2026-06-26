from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any


def build_card_deck(
    cards_root: str | Path,
    *,
    title: str = "BinaryShield Malware Robustness Card Deck",
    max_cards: int = 25,
) -> dict[str, Any]:
    root = Path(cards_root)
    card_paths = sorted(path for path in root.rglob("*.md") if _looks_like_card(path))
    rows = [_parse_card(path, root) for path in card_paths]
    verdict_counts = Counter(str(row.get("verdict", "unknown")) for row in rows)
    detector_counts = Counter(str(row.get("detector", "unknown")) for row in rows)
    transformation_counts = Counter(str(row.get("transformation", "unknown")) for row in rows)
    level_counts = Counter(str(row.get("validation_level", "unknown")) for row in rows)
    deck = {
        "title": title,
        "cards_root": str(root),
        "card_count": len(rows),
        "max_cards_in_markdown": max_cards,
        "verdict_counts": dict(sorted(verdict_counts.items())),
        "detector_counts": dict(sorted(detector_counts.items())),
        "transformation_counts": dict(sorted(transformation_counts.items())),
        "validation_level_counts": dict(sorted(level_counts.items())),
        "cards": rows,
        "claim_boundary": (
            "This deck summarizes generated Malware Robustness Cards. It proves reporting coverage "
            "and structural validation evidence only. It does not prove full malware behavior "
            "preservation without Level 3 sandbox validation."
        ),
    }
    return deck


def write_card_deck(deck: dict[str, Any], output_dir: str | Path) -> None:
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    (root / "robustness_card_deck.json").write_text(json.dumps(deck, indent=2), encoding="utf-8")
    (root / "robustness_card_deck.md").write_text(to_markdown(deck), encoding="utf-8")
    rows = list(deck.get("cards", []))
    with (root / "robustness_card_deck_rows.csv").open("w", encoding="utf-8", newline="") as handle:
        fieldnames = sorted({key for row in rows for key in row}) if rows else ["card_path", "sample_id"]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def to_markdown(deck: dict[str, Any]) -> str:
    max_cards = int(deck.get("max_cards_in_markdown", 25))
    cards = list(deck.get("cards", []))
    header = (
        f"# {deck.get('title', 'BinaryShield Malware Robustness Card Deck')}\n\n"
        f"**Cards root:** `{deck.get('cards_root')}`\n\n"
        f"**Card count:** {deck.get('card_count')}\n\n"
    )
    sections = [
        _counts_section("Verdict Counts", deck.get("verdict_counts", {})),
        _counts_section("Detector Counts", deck.get("detector_counts", {})),
        _counts_section("Transformation Counts", deck.get("transformation_counts", {})),
        _counts_section("Validation Level Counts", deck.get("validation_level_counts", {})),
        _card_table(cards[:max_cards]),
        "## Claim Boundary\n\n" + str(deck.get("claim_boundary")) + "\n",
    ]
    if len(cards) > max_cards:
        sections.insert(
            -1,
            f"## Truncation Note\n\nMarkdown table shows {max_cards} of {len(cards)} cards. "
            "See `robustness_card_deck_rows.csv` for the full deck.\n",
        )
    return header + "\n".join(sections)


def _counts_section(title: str, counts: Any) -> str:
    if not isinstance(counts, dict) or not counts:
        return f"## {title}\n\nNo entries.\n"
    rows = "\n".join(f"| {key} | {value} |" for key, value in counts.items())
    return f"## {title}\n\n| Value | Count |\n|---|---:|\n{rows}\n"


def _card_table(cards: list[dict[str, Any]]) -> str:
    if not cards:
        return "## Cards\n\nNo cards found.\n"
    rows = "\n".join(
        "| {sample_id} | {detector} | {transformation} | {validation_level} | {verdict} | {card_path} |".format(
            sample_id=_cell(card.get("sample_id")),
            detector=_cell(card.get("detector")),
            transformation=_cell(card.get("transformation")),
            validation_level=_cell(card.get("validation_level")),
            verdict=_cell(card.get("verdict")),
            card_path=_cell(card.get("card_path")),
        )
        for card in cards
    )
    return (
        "## Cards\n\n"
        "| Sample | Detector | Transformation | Validation Level | Verdict | Card |\n"
        "|---|---|---|---:|---|---|\n"
        f"{rows}\n"
    )


def _cell(value: Any) -> str:
    return str(value if value is not None else "").replace("|", "\\|")


def _looks_like_card(path: Path) -> bool:
    try:
        first = path.read_text(encoding="utf-8", errors="replace").splitlines()[0]
    except IndexError:
        return False
    return first.startswith("# Malware Robustness Card:")


def _parse_card(path: Path, root: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    fields = _parse_field_table(text)
    return {
        "card_path": path.relative_to(root).as_posix(),
        "sample_id": fields.get("sample", path.stem),
        "detector": fields.get("detector", "unknown"),
        "transformation": fields.get("transformation", "unknown"),
        "validation_level": _int_or_text(fields.get("validation level", "unknown")),
        "allowed_for_evaluation": fields.get("allowed for evaluation", "unknown"),
        "clean_prediction": fields.get("clean prediction", "unknown"),
        "transformed_prediction": fields.get("transformed prediction", "unknown"),
        "verdict": fields.get("verdict", "unknown"),
        "claim_boundary": _extract_claim_boundary(text),
    }


def _parse_field_table(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 2 or cells[0].lower() in {"field", "---"}:
            continue
        fields[cells[0].lower()] = cells[1]
    return fields


def _extract_claim_boundary(text: str) -> str:
    marker = "## Claim Boundary"
    if marker not in text:
        return ""
    after = text.split(marker, 1)[1].strip()
    if "## " in after:
        after = after.split("## ", 1)[0].strip()
    return " ".join(after.split())


def _int_or_text(value: str) -> int | str:
    try:
        return int(value)
    except (TypeError, ValueError):
        return value
