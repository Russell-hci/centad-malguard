from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from binaryshield.evaluation.card_deck import build_card_deck, to_markdown, write_card_deck


CARD = """# Malware Robustness Card: sample_a

| Field | Value |
|---|---|
| Sample | sample_a |
| Detector | hybrid_centroid |
| Transformation | append_overlay |
| Validation level | 2 |
| Allowed for evaluation | True |
| Original SHA-256 | abc |
| Transformed SHA-256 | def |
| Clean prediction | malware |
| Transformed prediction | malware |
| Clean confidence | not evaluated |
| Transformed confidence | not evaluated |
| Verdict | detector_stable |

## Claim Boundary

Validated PE-preserving transformation; full behavior preservation is not claimed unless sandbox_execution_status is passed.
"""


class BinaryShieldCardDeckTests(unittest.TestCase):
    def test_card_deck_summarizes_cards(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            cards = root / "cards" / "append_overlay"
            cards.mkdir(parents=True)
            (cards / "sample_a.md").write_text(CARD, encoding="utf-8")
            (root / "not_a_card.md").write_text("# Other\n", encoding="utf-8")
            deck = build_card_deck(root, max_cards=10)
            output = root / "deck"
            write_card_deck(deck, output)
            self.assertEqual(deck["card_count"], 1)
            self.assertEqual(deck["verdict_counts"], {"detector_stable": 1})
            self.assertEqual(deck["detector_counts"], {"hybrid_centroid": 1})
            self.assertEqual(deck["transformation_counts"], {"append_overlay": 1})
            self.assertIn("sample_a", to_markdown(deck))
            self.assertTrue((output / "robustness_card_deck.json").exists())


if __name__ == "__main__":
    unittest.main()
