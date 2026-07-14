from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HARNESS = ROOT / "harness"
if str(HARNESS) not in sys.path:
    sys.path.insert(0, str(HARNESS))

import quantum_fallback_review  # noqa: E402
import run_quantum_fallback  # noqa: E402
from rule3 import review  # noqa: E402


class QuantumFallbackReviewTests(unittest.TestCase):
    def test_exact_eight_response_bundle_validates(self) -> None:
        bundle = quantum_fallback_review.load_quantum_responses(
            ROOT, run_quantum_fallback.CANDIDATE_ID
        )
        self.assertEqual(len(bundle.responses), 8)
        self.assertEqual(
            tuple(record.model_key for record in bundle.responses),
            run_quantum_fallback.MODEL_ORDER,
        )
        self.assertTrue(all(record.attempt_number == 1 for record in bundle.responses))

    def test_review_context_restores_globals(self) -> None:
        original_root = review.PRIVATE_RELATIVE_ROOT
        original_loader = review._review_response_bundle
        with quantum_fallback_review.quantum_review_context():
            self.assertEqual(
                review.PRIVATE_RELATIVE_ROOT,
                quantum_fallback_review.REVIEW_ROOT,
            )
            self.assertIs(
                review._review_response_bundle,
                quantum_fallback_review.load_quantum_responses,
            )
        self.assertEqual(review.PRIVATE_RELATIVE_ROOT, original_root)
        self.assertIs(review._review_response_bundle, original_loader)


if __name__ == "__main__":
    unittest.main()
