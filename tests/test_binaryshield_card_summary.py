from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from binaryshield.evaluation.card_summary import summarize_robustness_cards, to_markdown


class BinaryShieldCardSummaryTests(unittest.TestCase):
    def test_card_summary_computes_generation_rate(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            cards = root / "cards"
            cards.mkdir()
            (cards / "sample_a.md").write_text("# card a\n", encoding="utf-8")
            (cards / "sample_b.md").write_text("# card b\n", encoding="utf-8")
            summary = summarize_robustness_cards(cards, expected_count=2)
        self.assertEqual(summary["card_count"], 2)
        self.assertEqual(summary["card_generation_rate"], 1.0)
        self.assertIn("Robustness Card Coverage", to_markdown(summary))

    def test_card_summary_can_use_existing_cards_for_optional_transforms(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            cards = root / "cards"
            cards.mkdir()
            (cards / "sample_a.md").write_text("# card a\n", encoding="utf-8")
            expected_count = len(list(cards.rglob("*.md")))
            summary = summarize_robustness_cards(cards, expected_count=expected_count)
        self.assertEqual(summary["expected_count"], 1)
        self.assertEqual(summary["card_generation_rate"], 1.0)


if __name__ == "__main__":
    unittest.main()
