from __future__ import annotations

import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import amend_grok_review as amendment


class GalatiansReviewAmendmentTests(unittest.TestCase):
    def test_exactly_four_local_handles_change(self) -> None:
        self.assertEqual(sum(old != new for *_, old, new in amendment.ITEMS), 4)

    def test_all_eight_items_are_unique(self) -> None:
        self.assertEqual(len(amendment.ITEMS), 8)
        self.assertEqual(len({item[0] for item in amendment.ITEMS}), 8)
        self.assertEqual(len({item[1] for item in amendment.ITEMS}), 8)

    def test_corrected_semantic_distribution_is_four_four(self) -> None:
        primaries = [item[3] for item in amendment.ITEMS]
        self.assertEqual(primaries.count("believers-faith-in-christ"), 4)
        self.assertEqual(primaries.count("christs-own-faithfulness"), 4)

    def test_corrected_threshold_fails_only_representation(self) -> None:
        result = amendment.threshold([item[3] for item in amendment.ITEMS])
        self.assertEqual(
            result,
            {
                "evidence_complete": True,
                "author_review_complete": True,
                "qualifies": False,
                "non_null_primary_count": 8,
                "represented_position_count": 2,
                "maximum_position_primary_count": 4,
                "failure_reasons": ["fewer-than-three-represented-positions"],
            },
        )

    def test_threshold_rejects_concentration(self) -> None:
        result = amendment.threshold(["a"] * 5 + ["b"] * 2 + ["c"])
        self.assertIn(
            "one-position-has-more-than-four-primary-endorsements",
            result["failure_reasons"],
        )

    def test_rule2_exception_is_the_prior_approved_amendment(self) -> None:
        self.assertEqual(
            amendment.RULE2_RESOLVED_BLIND_ID,
            "blind-ac30c39602d53eaa198433fe611f57e0",
        )

    def test_output_inventory_is_fixed(self) -> None:
        self.assertEqual(
            amendment.EXPECTED_FILES,
            tuple(sorted(amendment.EXPECTED_FILES)),
        )


if __name__ == "__main__":
    unittest.main()
