from __future__ import annotations

import json
import stat
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import evaluate_rule3
from rule3 import contract, evaluate, review
from test_rule3_review import Rule3FixtureMixin


class Rule3ThresholdTests(unittest.TestCase):
    def setUp(self) -> None:
        self.positions = ["a", "b", "c", "d"]

    def test_exact_six_non_null_three_positions_boundary_qualifies(self) -> None:
        result = evaluate.evaluate_divergence(
            ["a", "a", "b", "b", "c", "c", None, None], self.positions
        )
        self.assertTrue(result["qualifies"])
        self.assertEqual(result["non_null_primary_count"], 6)
        self.assertEqual(result["represented_position_count"], 3)

    def test_exact_four_per_position_boundary_qualifies(self) -> None:
        result = evaluate.evaluate_divergence(
            ["a", "a", "a", "a", "b", "b", "c", "c"], self.positions
        )
        self.assertTrue(result["qualifies"])
        self.assertEqual(result["maximum_position_primary_count"], 4)

    def test_every_threshold_failure_boundary_is_separate(self) -> None:
        fewer_non_null = evaluate.evaluate_divergence(
            ["a", "a", "b", "b", "c", None, None, None], self.positions
        )
        self.assertEqual(
            fewer_non_null["failure_reasons"],
            ["fewer-than-six-non-null-primary-endorsements"],
        )
        fewer_positions = evaluate.evaluate_divergence(
            ["a", "a", "a", "a", "b", "b", "b", "b"], self.positions
        )
        self.assertIn(
            "fewer-than-three-represented-positions", fewer_positions["failure_reasons"]
        )
        too_concentrated = evaluate.evaluate_divergence(
            ["a", "a", "a", "a", "a", "b", "b", "c"], self.positions
        )
        self.assertEqual(
            too_concentrated["failure_reasons"],
            ["one-position-has-more-than-four-primary-endorsements"],
        )

    def test_incomplete_evidence_can_never_produce_a_threshold_result(self) -> None:
        with self.assertRaises(evaluate.Rule3EvaluationError):
            evaluate.evaluate_divergence(["a"] * 7, self.positions)


class Rule3EvaluationLaneTests(Rule3FixtureMixin, unittest.TestCase):
    def _positions(self, candidate_id: str) -> list[str]:
        question, _ = review._load_question(self.root, candidate_id)
        return [position["id"] for position in question["position_map"]]

    def test_qualifying_priority_is_terminal_and_never_fallback_eligible(self) -> None:
        candidate = evaluate.PRIORITY_ID
        positions = self._positions(candidate)
        self.build_chain(
            candidate,
            [
                positions[0],
                positions[0],
                positions[0],
                positions[1],
                positions[1],
                positions[1],
                positions[2],
                positions[2],
            ],
        )
        terminal = evaluate.publish_candidate_evaluation(self.root, candidate)
        self.assertEqual(terminal["value"]["status"], "terminal-selected")
        self.assertEqual(terminal["value"]["selected_candidate_id"], candidate)
        pool = self.root / review.PRIVATE_RELATIVE_ROOT
        self.assertFalse((pool / "fallback-eligibility.json").exists())
        self.assertEqual(stat.S_IMODE((pool / "terminal.json").stat().st_mode), 0o600)
        with self.assertRaisesRegex(evaluate.Rule3EvaluationError, "ineligible"):
            evaluate.publish_candidate_evaluation(self.root, evaluate.FALLBACK_ID)

    def test_complete_reviewed_priority_failure_alone_writes_eligibility(self) -> None:
        candidate = evaluate.PRIORITY_ID
        position = self._positions(candidate)[0]
        self.build_chain(candidate, [position] * 8)
        eligibility = evaluate.publish_candidate_evaluation(self.root, candidate)
        self.assertEqual(
            eligibility["value"]["status"],
            "fallback-eligible-after-complete-reviewed-priority-failure",
        )
        self.assertFalse(eligibility["value"]["threshold_result"]["qualifies"])
        self.assertTrue(eligibility["value"]["threshold_result"]["failure_reasons"])
        self.assertEqual(stat.S_IMODE(eligibility["path"].stat().st_mode), 0o600)
        self.assertFalse(
            (self.root / review.PRIVATE_RELATIVE_ROOT / "terminal.json").exists()
        )

    def test_fallback_cannot_be_evaluated_without_exact_eligibility(self) -> None:
        candidate = evaluate.FALLBACK_ID
        positions = self._positions(candidate)
        self.build_chain(
            candidate,
            [
                positions[0],
                positions[0],
                positions[1],
                positions[1],
                positions[2],
                positions[2],
                None,
                None,
            ],
        )
        with self.assertRaises(
            (review.Rule3ReviewError, evaluate.Rule3EvaluationError)
        ):
            evaluate.compute_candidate_evaluation(self.root, candidate)
        self.assertFalse(
            (
                review.review_paths(self.root, candidate).candidate_root / "evaluation"
            ).exists()
        )

    def test_incomplete_or_unreviewed_priority_cannot_create_false_eligibility(
        self,
    ) -> None:
        candidate = evaluate.PRIORITY_ID
        self.bundle(candidate)
        review.publish_blind_materials(self.root, candidate)
        with self.assertRaises(review.Rule3ReviewError):
            evaluate.compute_candidate_evaluation(self.root, candidate)
        pool = self.root / review.PRIVATE_RELATIVE_ROOT
        self.assertFalse((pool / "fallback-eligibility.json").exists())
        self.assertFalse(
            (
                review.review_paths(self.root, candidate).candidate_root / "evaluation"
            ).exists()
        )

    def test_eligible_fallback_can_select_and_closes_the_pool(self) -> None:
        priority = evaluate.PRIORITY_ID
        fallback = evaluate.FALLBACK_ID
        priority_position = self._positions(priority)[0]
        self.build_chain(priority, [priority_position] * 8)
        evaluate.publish_candidate_evaluation(self.root, priority)
        fallback_positions = self._positions(fallback)
        self.build_chain(
            fallback,
            [
                fallback_positions[0],
                fallback_positions[0],
                fallback_positions[1],
                fallback_positions[1],
                fallback_positions[2],
                fallback_positions[2],
                None,
                None,
            ],
        )
        terminal = evaluate.publish_candidate_evaluation(self.root, fallback)
        self.assertEqual(terminal["value"]["status"], "terminal-selected")
        self.assertEqual(terminal["value"]["selected_candidate_id"], fallback)
        self.assertFalse(terminal["value"]["third_candidate_allowed"])

    def test_two_complete_failures_write_terminal_no_selection(self) -> None:
        priority = evaluate.PRIORITY_ID
        fallback = evaluate.FALLBACK_ID
        self.build_chain(priority, [self._positions(priority)[0]] * 8)
        evaluate.publish_candidate_evaluation(self.root, priority)
        self.build_chain(fallback, [self._positions(fallback)[0]] * 8)
        terminal = evaluate.publish_candidate_evaluation(self.root, fallback)
        self.assertEqual(
            terminal["value"]["status"],
            "terminal-two-completed-failures-no-selection",
        )
        self.assertIsNone(terminal["value"]["selected_candidate_id"])
        self.assertFalse(terminal["value"]["third_candidate_allowed"])

    def test_evaluation_tamper_is_rejected(self) -> None:
        candidate = evaluate.PRIORITY_ID
        positions = self._positions(candidate)
        self.build_chain(
            candidate,
            [
                positions[0],
                positions[0],
                positions[1],
                positions[1],
                positions[2],
                positions[2],
                None,
                None,
            ],
        )
        evaluate.publish_candidate_evaluation(self.root, candidate)
        receipt = (
            review.review_paths(self.root, candidate).candidate_root
            / "evaluation"
            / "receipt.json"
        )
        value = json.loads(receipt.read_bytes())
        value["threshold_result"]["qualifies"] = False
        receipt.write_bytes(contract.canonical_json_bytes(value))
        with self.assertRaises(evaluate.Rule3EvaluationError):
            evaluate.verify_candidate_evaluation(self.root, candidate)

    def test_cli_evaluator_modes_are_mutually_exclusive(self) -> None:
        parsed = evaluate_rule3.parser().parse_args(
            ["--candidate", evaluate.PRIORITY_ID, "--verify"]
        )
        self.assertTrue(parsed.verify)
        with self.assertRaises(SystemExit):
            evaluate_rule3.parser().parse_args(
                ["--candidate", evaluate.PRIORITY_ID, "--check", "--write"]
            )

    def test_atomic_single_file_publication_recovers_prelink_and_rejects_rewrite(
        self,
    ) -> None:
        pool = self.root / review.PRIVATE_RELATIVE_ROOT
        self._private_directory(pool)
        target = pool / "fixture-receipt.json"
        value = {
            "schema_version": "fixture-1.0.0",
            "created_at": "2026-07-13T10:00:00Z",
        }
        preparation = pool / ".fixture-receipt.json.prepare"
        preparation.write_bytes(contract.canonical_json_bytes(value))
        preparation.chmod(0o600)
        evaluate._write_once_private_json(target, value)
        self.assertTrue(target.is_file())
        self.assertFalse(preparation.exists())
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        with self.assertRaisesRegex(evaluate.Rule3EvaluationError, "write-once"):
            evaluate._write_once_private_json(target, value)

    def test_single_file_publication_clones_the_open_inode_during_path_swap(
        self,
    ) -> None:
        pool = self.root / review.PRIVATE_RELATIVE_ROOT
        self._private_directory(pool)
        target = pool / "pinned-receipt.json"
        preparation = pool / ".pinned-receipt.json.prepare"
        value = {"schema_version": "fixture-1.0.0", "value": "approved"}
        approved = contract.canonical_json_bytes(value)
        preparation.write_bytes(approved)
        preparation.chmod(0o600)
        original = evaluate._clone_pinned_no_replace

        def swap_then_publish(
            source_descriptor: int,
            parent_descriptor: int,
            target_name: str,
            payload: bytes,
        ) -> None:
            preparation.unlink()
            preparation.write_bytes(b'{"foreign":true}\n')
            preparation.chmod(0o600)
            original(source_descriptor, parent_descriptor, target_name, payload)

        with mock.patch.object(
            evaluate, "_clone_pinned_no_replace", side_effect=swap_then_publish
        ):
            with self.assertRaisesRegex(
                evaluate.Rule3EvaluationError, "preparation path changed"
            ):
                evaluate._write_once_private_json(target, value)
        self.assertEqual(target.read_bytes(), approved)
        self.assertEqual(preparation.read_bytes(), b'{"foreign":true}\n')


if __name__ == "__main__":
    unittest.main()
