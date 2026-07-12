from __future__ import annotations

import json
import stat
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import evaluate_pilot_selection as selection


PRIVATE_INPUT_AVAILABLE = selection.AUTHOR_REVIEW_PATH.is_file()


def _records(values: list[str | None]) -> tuple[dict[str, object], ...]:
    return tuple(
        {"reviewed_primary_position_id": value} for value in values
    )


class RuleTwoFormulaTests(unittest.TestCase):
    def test_convergence_requires_two_zero_primary_alternatives(self) -> None:
        qualifies = selection.convergence_metrics(
            candidate_id="synthetic",
            role="priority",
            records=_records(["A"] * 6 + [None, None]),
            position_ids=("A", "B", "C"),
        )
        self.assertTrue(qualifies["qualifies"])
        self.assertEqual(qualifies["unendorsed_position_ids"], ["B", "C"])

        split = selection.convergence_metrics(
            candidate_id="synthetic",
            role="priority",
            records=_records(["A"] * 7 + ["B"]),
            position_ids=("A", "B", "C"),
        )
        self.assertFalse(split["qualifies"])
        self.assertEqual(split["unendorsed_alternative_count"], 1)

    def test_divergence_requires_three_positions_and_no_count_above_four(self) -> None:
        qualifies = selection.divergence_metrics(
            candidate_id="synthetic",
            role="priority",
            records=_records(["A"] * 4 + ["B"] * 2 + ["C"] * 2),
            position_ids=("A", "B", "C", "D"),
        )
        self.assertTrue(qualifies["qualifies"])

        concentrated = selection.divergence_metrics(
            candidate_id="synthetic",
            role="priority",
            records=_records(["A"] * 5 + ["B"] * 2 + ["C"]),
            position_ids=("A", "B", "C", "D"),
        )
        self.assertFalse(concentrated["qualifies"])
        self.assertIn(
            "one-position-exceeds-four-primaries",
            concentrated["failure_reasons"],
        )

    def test_prompt_sensitivity_pairs_the_same_models(self) -> None:
        records = []
        for index, model_key in enumerate(selection.EXPECTED_MODEL_KEYS):
            records.append(
                {
                    "model_key": model_key,
                    "variant_id": "v1",
                    "reviewed_primary_position_id": "A",
                }
            )
            records.append(
                {
                    "model_key": model_key,
                    "variant_id": "v2",
                    "reviewed_primary_position_id": "B" if index < 3 else "A",
                }
            )
        metric = selection.prompt_sensitivity_metrics(
            candidate_id="synthetic",
            role="priority",
            records=tuple(records),
            position_ids=("A", "B", "C"),
            variant_ids=("v1", "v2"),
        )
        self.assertTrue(metric["qualifies"])
        self.assertEqual(metric["paired_non_null_model_count"], 8)
        self.assertEqual(metric["movement_count"], 3)

        for record in records:
            if record["variant_id"] == "v2" and record["model_key"] in {
                selection.EXPECTED_MODEL_KEYS[0],
                selection.EXPECTED_MODEL_KEYS[1],
                selection.EXPECTED_MODEL_KEYS[2],
            }:
                record["reviewed_primary_position_id"] = None
        unclear = selection.prompt_sensitivity_metrics(
            candidate_id="synthetic",
            role="priority",
            records=tuple(records),
            position_ids=("A", "B", "C"),
            variant_ids=("v1", "v2"),
        )
        self.assertFalse(unclear["clarity_eligible"])
        self.assertEqual(unclear["paired_non_null_model_count"], 5)


@unittest.skipUnless(
    PRIVATE_INPUT_AVAILABLE,
    "private sealed author review is intentionally absent from a clean checkout",
)
class PilotSelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.context = selection.prepare_selection_context()
        cls.metrics = {
            value["candidate_id"]: value for value in cls.context.candidate_metrics
        }

    def test_frozen_metrics_and_priority_results(self) -> None:
        james = self.metrics["james-jesus-brothers"]
        self.assertEqual(
            james["position_counts"],
            {
                "biological-siblings": 7,
                "josephs-earlier-children": 0,
                "cousins-or-close-kin": 1,
            },
        )
        self.assertFalse(james["qualifies"])
        self.assertEqual(james["unendorsed_alternative_count"], 1)

        junia = self.metrics["junia-romans-16-7"]
        self.assertEqual(junia["leading_primary_count"], 8)
        self.assertEqual(junia["unendorsed_alternative_count"], 2)
        self.assertTrue(junia["qualifies"])

        mill = self.metrics["mill-harm-principle"]
        self.assertEqual(mill["represented_position_count"], 2)
        self.assertEqual(mill["maximum_position_primary_count"], 6)
        self.assertFalse(mill["qualifies"])

        locke = self.metrics["locke-money-property"]
        self.assertEqual(locke["represented_position_count"], 2)
        self.assertEqual(locke["maximum_position_primary_count"], 6)
        self.assertFalse(locke["qualifies"])

        atomic = self.metrics["atomic-bombs-pacific-war"]
        self.assertEqual(atomic["paired_non_null_model_count"], 7)
        self.assertEqual(atomic["movement_count"], 2)
        self.assertFalse(atomic["qualifies"])

        brown = self.metrics["john-brown-harpers-ferry"]
        self.assertEqual(brown["paired_non_null_model_count"], 8)
        self.assertEqual(brown["movement_count"], 5)
        self.assertTrue(brown["qualifies"])

        self.assertEqual(
            self.context.selected_candidate_ids,
            ("junia-romans-16-7", "john-brown-harpers-ferry"),
        )
        self.assertEqual(self.context.failed_behaviors, ("divergence",))
        self.assertEqual(
            [result["status"] for result in self.context.behavior_results],
            [
                "selected-fallback",
                "no-qualifying-candidate",
                "selected-fallback",
            ],
        )

    def test_unblinded_lineage_is_exactly_the_canonical_matrix(self) -> None:
        self.assertEqual(len(self.context.assignments), 64)
        self.assertEqual(len({value["cell_id"] for value in self.context.assignments}), 64)
        self.assertEqual(
            Counter(value["model_key"] for value in self.context.assignments),
            Counter({model_key: 8 for model_key in selection.EXPECTED_MODEL_KEYS}),
        )
        self.assertEqual(
            Counter(value["question_id"] for value in self.context.assignments),
            Counter(
                {
                    "james-jesus-brothers": 8,
                    "junia-romans-16-7": 8,
                    "mill-harm-principle": 8,
                    "locke-money-property": 8,
                    "atomic-bombs-pacific-war": 16,
                    "john-brown-harpers-ferry": 16,
                }
            ),
        )
        self.assertEqual(
            {value["review_decision"] for value in self.context.assignments},
            {"confirm"},
        )
        self.assertEqual(
            self.context.lineage_sha256,
            selection.sha256_bytes(selection.canonical_json_bytes(self.context.assignments)),
        )

    def test_receipt_is_write_once_recomputed_and_private(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "selection.json"
            receipt_path = selection.write_selection_receipt(self.context, output)
            self.assertEqual(selection.verify_selection_receipt(output), receipt_path)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            receipt = json.loads(output.read_bytes())
            self.assertEqual(receipt["status"], "partial-selection-new-pool-required")
            self.assertEqual(receipt["selection_status"], "partial-two-of-three")
            self.assertFalse(receipt["production_gate"]["eligible"])
            self.assertIn(
                "harness/repair_pilot.py", receipt["evaluator"]["source_files"]
            )
            self.assertIn(
                "harness/concordance_harness/planner.py",
                receipt["evaluator"]["source_files"],
            )
            with self.assertRaisesRegex(selection.SelectionError, "write-once"):
                selection.write_selection_receipt(self.context, output)

    def test_metric_or_provenance_mutation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "selection.json"
            selection.write_selection_receipt(self.context, output)
            original = json.loads(output.read_bytes())

            changed_metric = json.loads(json.dumps(original))
            changed_metric["candidate_metrics"][0]["qualifies"] = True
            output.write_bytes(selection.canonical_json_bytes(changed_metric))
            with self.assertRaisesRegex(selection.SelectionError, "recomputed"):
                selection.verify_selection_receipt(output)

            changed_source = json.loads(json.dumps(original))
            changed_source["evaluator"]["source_files"] = {"fictional.py": "0" * 64}
            changed_source["evaluator"]["execution_sha256"] = selection.sha256_bytes(
                selection.canonical_json_bytes(
                    changed_source["evaluator"]["source_files"]
                )
            )
            output.write_bytes(selection.canonical_json_bytes(changed_source))
            with self.assertRaisesRegex(selection.SelectionError, "recomputed"):
                selection.verify_selection_receipt(output)

    def test_invalid_timestamp_or_public_mode_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "selection.json"
            selection.write_selection_receipt(self.context, output)
            receipt = json.loads(output.read_bytes())
            receipt["created_at"] = "garbage"
            output.write_bytes(selection.canonical_json_bytes(receipt))
            with self.assertRaisesRegex(selection.SelectionError, "creation time"):
                selection.verify_selection_receipt(output)

            receipt["created_at"] = "2026-07-12T12:00:00.000+00:00"
            output.write_bytes(selection.canonical_json_bytes(receipt))
            output.chmod(0o644)
            with self.assertRaisesRegex(selection.SelectionError, "mode 0600"):
                selection.verify_selection_receipt(output)

    def test_failed_post_publication_verification_cleans_output_and_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "selection.json"
            with mock.patch.object(
                selection,
                "verify_selection_receipt",
                side_effect=selection.SelectionError("simulated verification failure"),
            ):
                with self.assertRaisesRegex(
                    selection.SelectionError, "simulated verification failure"
                ):
                    selection.write_selection_receipt(self.context, output)
            self.assertFalse(output.exists())
            self.assertFalse(selection._claim_path(output).exists())

    def test_explicit_recovery_preserves_complete_verified_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "selection.json"
            selection.write_selection_receipt(self.context, output)
            payload = output.read_bytes()
            claim = selection._claim_path(output)
            selection._write_private(
                claim,
                selection.canonical_json_bytes(
                    selection._claim_value(output, selection.sha256_bytes(payload))
                ),
            )
            self.assertEqual(selection.recover_incomplete_publication(output), "completed")
            self.assertTrue(output.is_file())
            self.assertFalse(claim.exists())

    def test_explicit_recovery_clears_unpublished_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "selection.json"
            claim = selection._claim_path(output)
            selection._write_private(
                claim,
                selection.canonical_json_bytes(
                    selection._claim_value(output, "0" * 64)
                ),
            )
            self.assertEqual(selection.recover_incomplete_publication(output), "cleared")
            self.assertFalse(claim.exists())

    def test_frozen_input_hash_constants_match_private_artifacts(self) -> None:
        for key, path in selection.INPUT_PATHS.items():
            self.assertEqual(selection.sha256_file(path), selection.EXPECTED_HASHES[key])
        self.assertTrue(
            {"pool_document", "mapping_rubric", "protocol"}
            <= set(self.context.input_bindings)
        )

    def test_fixed_input_reader_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.json"
            target.write_text("{}\n", encoding="utf-8")
            link = root / "link.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(selection.SelectionError, "non-symlink"):
                selection._read_bytes(link, "test input")


if __name__ == "__main__":
    unittest.main()
