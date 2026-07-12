from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import validate_blind_mappings as validation


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(validation.canonical_json_bytes(value))


class BlindMappingValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "mapping-batches-1"
        self.instructions_path = self.root / "instructions.json"
        self.batches_path = self.root / "batches.json"
        self.first_pass_path = self.root / "first-pass.json"
        self.rubric_path = Path(self.temporary.name) / "MAPPING_RUBRIC.md"
        self.rubric_path.write_text("approved rubric\n", encoding="utf-8")
        _write_json(self.instructions_path, {"rubric_id": "mapping-rubric-1"})
        self.instructions_sha256 = validation.sha256_file(self.instructions_path)
        self.mapping_paths: list[Path] = []
        batch_records = []
        item_number = 0
        for batch_number in range(16):
            batch_id = f"batch-{batch_number:016x}"
            items = []
            assignments = []
            for _ in range(4):
                item_id = f"blind-{item_number:032x}"
                response_text = f"Response text for item {item_number}."
                response_sha256 = validation.sha256_bytes(response_text.encode("utf-8"))
                relative_path = f"batches/{batch_id}/items/{item_id}.json"
                envelope_path = self.root / relative_path
                _write_json(
                    envelope_path,
                    {
                        "schema_version": "mapping-batches-1.0.0",
                        "blind_item_id": item_id,
                        "response_sha256": response_sha256,
                        "user_prompt": "Choose the best-supported position.",
                        "positions": [
                            {"handle": "P1", "label": "First", "summary": "First view"},
                            {"handle": "P2", "label": "Second", "summary": "Second view"},
                        ],
                        "response_text": response_text,
                    },
                )
                items.append(
                    {
                        "blind_item_id": item_id,
                        "path": relative_path,
                        "sha256": validation.sha256_file(envelope_path),
                    }
                )
                assignments.append(
                    {
                        "blind_item_id": item_id,
                        "response_sha256": response_sha256,
                        "primary_endorsed": "P1",
                        "also_endorsed": [],
                        "mentioned": ["P2"],
                        "primary_reason_code": "clear_preference",
                        "rationale": "The answer expressly favors the first view.",
                        "evidence_snippets": ["Response text"],
                        "confidence": "high",
                        "review_flags": [],
                    }
                )
                item_number += 1
            manifest_path = self.root / f"batches/{batch_id}/manifest.json"
            _write_json(
                manifest_path,
                {
                    "schema_version": "mapping-batches-1.0.0",
                    "batch_id": batch_id,
                    "rubric_id": "mapping-rubric-1",
                    "instructions_path": "../../instructions.json",
                    "instructions_sha256": self.instructions_sha256,
                    "items": items,
                    "expected_output_path": f"batches/{batch_id}/mapping.json",
                },
            )
            mapping_path = manifest_path.parent / "mapping.json"
            _write_json(
                mapping_path,
                {
                    "schema_version": "blind-mapping-1.0.0",
                    "rubric_id": "mapping-rubric-1",
                    "batch_id": batch_id,
                    "mapper_role": "codex-first-pass-blinded",
                    "assignments": assignments,
                },
            )
            self.mapping_paths.append(mapping_path)
            batch_records.append(
                {
                    "batch_id": batch_id,
                    "manifest_path": f"batches/{batch_id}/manifest.json",
                    "manifest_sha256": validation.sha256_file(manifest_path),
                }
            )
        _write_json(
            self.batches_path,
            {
                "schema_version": "mapping-batches-1.0.0",
                "status": "blind-mapping-batches-ready",
                "created_at": "2026-07-12T00:00:00Z",
                "network_requests": 0,
                "environment_variables_read": 0,
                "preparer": {},
                "aggregate_sha256": "a" * 64,
                "source_crosswalk_sha256": "b" * 64,
                "blinding_key_file_sha256": "c" * 64,
                "instructions_sha256": self.instructions_sha256,
                "batch_count": 16,
                "items_per_batch": 4,
                "item_count": 64,
                "constraints": {
                    "distinct_question_families_per_batch": 4,
                    "distinct_underlying_models_per_batch": 4,
                    "prompt_sensitive_families_per_batch": 2,
                    "paired_model_responses_visible_together": False,
                    "canonical_position_ids_visible": False,
                },
                "batches": batch_records,
                "private_crosswalk_path": "private/batch-crosswalk.json",
                "private_crosswalk_sha256": "d" * 64,
            },
        )
        self.stack = ExitStack()
        self.stack.enter_context(mock.patch.object(validation, "ROOT", self.root))
        self.stack.enter_context(
            mock.patch.object(validation, "BATCHES_PATH", self.batches_path)
        )
        self.stack.enter_context(
            mock.patch.object(validation, "INSTRUCTIONS_PATH", self.instructions_path)
        )
        self.stack.enter_context(
            mock.patch.object(validation, "FIRST_PASS_PATH", self.first_pass_path)
        )
        self.stack.enter_context(
            mock.patch.object(validation, "MAPPING_RUBRIC_PATH", self.rubric_path)
        )
        self.stack.enter_context(
            mock.patch.object(
                validation,
                "EXPECTED_BATCHES_SHA256",
                validation.sha256_file(self.batches_path),
            )
        )
        self.stack.enter_context(
            mock.patch.object(
                validation,
                "EXPECTED_INSTRUCTIONS_SHA256",
                self.instructions_sha256,
            )
        )
        self.stack.enter_context(
            mock.patch.object(
                validation,
                "EXPECTED_RUBRIC_SHA256",
                validation.sha256_file(self.rubric_path),
            )
        )

    def tearDown(self) -> None:
        self.stack.close()
        self.temporary.cleanup()

    def test_complete_mapping_set_validates_and_seals_once(self) -> None:
        records, missing = validation.validate_mapping_files(require_complete=True)
        self.assertEqual(len(records), 16)
        self.assertEqual(missing, [])

        path = validation.seal_first_pass()
        receipt = json.loads(path.read_bytes())
        self.assertEqual(receipt["status"], "complete-author-review-required")
        self.assertEqual(receipt["assignment_count"], 64)
        self.assertFalse(receipt["threshold_evaluation"]["performed"])
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(validation.verify_first_pass(), path)
        with self.assertRaisesRegex(validation.MappingValidationError, "write-once"):
            validation.seal_first_pass()

    def test_partial_mode_reports_missing_batch_and_complete_mode_rejects_it(self) -> None:
        self.mapping_paths[-1].unlink()
        records, missing = validation.validate_mapping_files(require_complete=False)
        self.assertEqual(len(records), 15)
        self.assertEqual(len(missing), 1)
        with self.assertRaisesRegex(validation.MappingValidationError, "missing mappings"):
            validation.validate_mapping_files(require_complete=True)

    def test_nonverbatim_evidence_is_rejected(self) -> None:
        mapping = json.loads(self.mapping_paths[0].read_bytes())
        mapping["assignments"][0]["evidence_snippets"] = ["not in the response"]
        _write_json(self.mapping_paths[0], mapping)
        with self.assertRaisesRegex(validation.MappingValidationError, "not verbatim"):
            validation.validate_mapping_files(require_complete=True)

    def test_duplicate_json_field_is_rejected(self) -> None:
        payload = self.mapping_paths[0].read_bytes()
        payload = payload.replace(
            b'"primary_endorsed": "P1"',
            b'"primary_endorsed": "P1", "primary_endorsed": "P2"',
            1,
        )
        self.mapping_paths[0].write_bytes(payload)
        with self.assertRaisesRegex(validation.MappingValidationError, "duplicate JSON key"):
            validation.validate_mapping_files(require_complete=True)

    def test_rubric_drift_is_rejected(self) -> None:
        self.rubric_path.write_text("changed rubric\n", encoding="utf-8")
        with self.assertRaisesRegex(validation.MappingValidationError, "approved pilot"):
            validation.validate_mapping_files(require_complete=True)

    def test_invalid_handle_overlap_and_reason_are_rejected(self) -> None:
        original = json.loads(self.mapping_paths[0].read_bytes())
        mutations = (
            ("primary handle", {"primary_endorsed": "P3"}),
            ("overlap", {"mentioned": ["P1"]}),
            ("reason is inconsistent", {"primary_reason_code": "mixed"}),
        )
        for message, updates in mutations:
            with self.subTest(message=message):
                mapping = json.loads(json.dumps(original))
                mapping["assignments"][0].update(updates)
                _write_json(self.mapping_paths[0], mapping)
                with self.assertRaisesRegex(validation.MappingValidationError, message):
                    validation.validate_mapping_files(require_complete=True)
        _write_json(self.mapping_paths[0], original)

    def test_post_seal_mapping_change_is_rejected(self) -> None:
        validation.seal_first_pass()
        mapping = json.loads(self.mapping_paths[0].read_bytes())
        mapping["assignments"][0]["rationale"] = "A different valid rationale."
        _write_json(self.mapping_paths[0], mapping)
        with self.assertRaisesRegex(validation.MappingValidationError, "sealed mappings"):
            validation.verify_first_pass()

    def test_failed_atomic_install_leaves_no_final_receipt(self) -> None:
        with mock.patch.object(os, "link", side_effect=OSError("simulated install failure")):
            with self.assertRaisesRegex(OSError, "simulated install failure"):
                validation.seal_first_pass()
        self.assertFalse(self.first_pass_path.exists())
        self.assertEqual(list(self.root.glob(".first-pass-*.tmp")), [])


class FrozenPilotConstantTests(unittest.TestCase):
    def test_approved_rubric_hash_constant_matches_repository(self) -> None:
        self.assertEqual(
            validation.sha256_file(validation.MAPPING_RUBRIC_PATH),
            validation.EXPECTED_RUBRIC_SHA256,
        )

    @unittest.skipUnless(
        validation.BATCHES_PATH.is_file() and validation.INSTRUCTIONS_PATH.is_file(),
        "private mapping batches are intentionally absent from a clean checkout",
    )
    def test_private_batch_hash_constants_match_frozen_files(self) -> None:
        self.assertEqual(
            validation.sha256_file(validation.BATCHES_PATH),
            validation.EXPECTED_BATCHES_SHA256,
        )
        self.assertEqual(
            validation.sha256_file(validation.INSTRUCTIONS_PATH),
            validation.EXPECTED_INSTRUCTIONS_SHA256,
        )


if __name__ == "__main__":
    unittest.main()
