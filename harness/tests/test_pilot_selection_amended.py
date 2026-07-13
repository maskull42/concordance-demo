from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import evaluate_pilot_selection_amended as selection


PRIVATE_INPUT_AVAILABLE = selection.amendment.BASE_REVIEW_PATH.is_file()


class AmendedPilotSelectionFilesystemTests(unittest.TestCase):
    def test_superseding_receipt_delta_runs_without_private_fixtures(self) -> None:
        before = {
            "candidate_id": "john-brown-harpers-ferry",
            "paired_non_null_model_count": 8,
            "movement_count": 5,
        }
        after = {
            "candidate_id": "john-brown-harpers-ferry",
            "paired_non_null_model_count": 7,
            "movement_count": 4,
        }
        base_context = selection.base.SelectionContext(
            input_bindings={},
            run_input_artifacts=(),
            mapping_files=(),
            candidate_files=(),
            assignments=(),
            lineage_sha256="1" * 64,
            candidate_metrics=(before,),
            behavior_results=(),
            selected_candidate_ids=(
                "junia-romans-16-7",
                "john-brown-harpers-ferry",
            ),
            failed_behaviors=("divergence",),
        )
        context = selection.AmendedSelectionContext(
            base_context=base_context,
            active_input_bindings={},
            amendment_sha256="2" * 64,
            amended_review_sha256="3" * 64,
            amended_draft_sha256="4" * 64,
            assignments=(),
            lineage_sha256="5" * 64,
            candidate_metrics=(after,),
            behavior_results=(),
            selected_candidate_ids=base_context.selected_candidate_ids,
            failed_behaviors=base_context.failed_behaviors,
        )
        with tempfile.TemporaryDirectory() as temporary:
            receipt = selection._receipt(
                context,
                output_path=Path(temporary) / "selection-rule2-2.json",
                created_at="2026-07-12T20:00:00+00:00",
                source_files={"fixture": "6" * 64},
            )

        self.assertEqual(
            receipt["correction_effect"]["paired_non_null_model_count"],
            {"before": 8, "after": 7},
        )
        self.assertEqual(
            receipt["correction_effect"]["movement_count"],
            {"before": 5, "after": 4},
        )
        self.assertFalse(receipt["correction_effect"]["selection_changed"])
        self.assertEqual(receipt["failed_behaviors"], ["divergence"])

    def test_replaced_claim_is_quarantined_not_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            claim = Path(temporary) / ".selection.publish-claim"
            owned_payload = b'{"owned":true}\n'
            selection._write_private(claim, owned_payload)
            _, _, owned_identity = selection._read_claim(claim, "owned claim")
            claim.unlink()
            foreign_payload = b'{"foreign":true}\n'
            selection._write_private(claim, foreign_payload)

            with self.assertRaisesRegex(selection.AmendedSelectionError, "quarantine"):
                selection._unlink_owned_claim(
                    claim,
                    expected_payload=owned_payload,
                    expected_identity=owned_identity,
                )

            self.assertEqual(claim.read_bytes(), foreign_payload)
            quarantines = list(
                claim.parent.glob(f"{claim.name}{selection.CLAIM_QUARANTINE_INFIX}*")
            )
            self.assertEqual(len(quarantines), 1)
            self.assertEqual(quarantines[0].read_bytes(), foreign_payload)

    def test_foreign_private_staging_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "selection.json"
            staging = Path(temporary) / ".selection.fixture.tmp"
            staging.mkdir(mode=0o700)
            owner_payload = selection._staging_owner_payload(output, "d" * 64)
            selection._write_private(
                staging / selection.STAGING_OWNER_NAME,
                selection._staging_owner_payload(output, "e" * 64),
            )
            with self.assertRaisesRegex(
                selection.AmendedSelectionError, "owner changed"
            ):
                selection._remove_private_staging(staging, owner_payload)
            self.assertFalse(staging.exists())
            quarantines = list(
                staging.parent.glob(f"{staging.name}{selection.STAGING_CLEANUP_INFIX}*")
            )
            self.assertEqual(len(quarantines), 1)
            self.assertTrue(quarantines[0].is_dir())

    def test_quarantined_claim_and_staging_cleanup_are_recoverable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "selection.json"
            operation_token = "f" * 64
            staging_name = f".{output.name}.fixture.tmp"
            staging = output.parent / staging_name
            staging.mkdir(mode=0o700)
            selection._write_private(
                staging / selection.STAGING_OWNER_NAME,
                selection._staging_owner_payload(output, operation_token),
            )
            selection._write_private(
                staging / selection.STAGING_PAYLOAD_NAME, b"partial"
            )
            staging_quarantine = staging.parent / (
                f"{staging.name}{selection.STAGING_CLEANUP_INFIX}fixture"
            )
            os.rename(staging, staging_quarantine)
            claim = selection._claim_path(output)
            selection._write_private(
                claim,
                selection.canonical_json_bytes(
                    selection._claim_value(
                        output, "0" * 64, staging_name, operation_token
                    )
                ),
            )
            claim_quarantine = claim.parent / (
                f"{claim.name}{selection.CLAIM_QUARANTINE_INFIX}fixture"
            )
            os.rename(claim, claim_quarantine)

            self.assertEqual(
                selection.recover_incomplete_publication(output), "cleared"
            )
            self.assertFalse(staging_quarantine.exists())
            self.assertFalse(claim_quarantine.exists())


@unittest.skipUnless(
    PRIVATE_INPUT_AVAILABLE,
    "private sealed author review is intentionally absent from a clean checkout",
)
class AmendedPilotSelectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.review_root = self.root / "author-review-2"
        selection.amendment.write_amended_review(self.review_root)
        self.original_verify_amended_review = selection.amendment.verify_amended_review
        self.patchers = [
            mock.patch.object(
                selection.amendment,
                "AMENDMENT_PATH",
                self.review_root / "amendment.json",
            ),
            mock.patch.object(
                selection.amendment,
                "OUTPUT_SEALED_ROOT",
                self.review_root / "sealed-primary-review",
            ),
            mock.patch.object(
                selection.amendment,
                "verify_amended_review",
                side_effect=lambda: self.original_verify_amended_review(
                    self.review_root
                ),
            ),
        ]
        for patcher in self.patchers:
            patcher.start()

    def tearDown(self) -> None:
        for patcher in reversed(self.patchers):
            patcher.stop()
        self.temporary.cleanup()

    def test_expected_metric_delta_and_unchanged_selection(self) -> None:
        context = selection.prepare_amended_context()
        brown = selection._metric_by_id(
            context.candidate_metrics, "john-brown-harpers-ferry"
        )
        self.assertEqual(brown["paired_non_null_model_count"], 7)
        self.assertEqual(brown["movement_count"], 4)
        methods = next(
            value
            for value in brown["variant_metrics"]
            if value["variant_id"] == "methods-and-violence-frame"
        )
        self.assertEqual(methods["non_null_primary_count"], 7)
        self.assertEqual(methods["position_counts"]["criminal-fanatical-violence"], 0)
        self.assertTrue(brown["qualifies"])
        self.assertEqual(
            context.selected_candidate_ids,
            ("junia-romans-16-7", "john-brown-harpers-ferry"),
        )
        self.assertEqual(context.failed_behaviors, ("divergence",))
        changed = [
            value
            for value in context.assignments
            if value["review_decision"] == "correct"
        ]
        self.assertEqual(len(changed), 1)
        self.assertEqual(changed[0]["cell_id"], selection.amendment.TARGET_CELL_ID)
        self.assertIsNone(changed[0]["reviewed_primary_position_id"])
        active = context.active_input_bindings
        self.assertEqual(
            active["author_review"]["sha256"], context.amended_review_sha256
        )
        self.assertEqual(active["review_draft"]["sha256"], context.amended_draft_sha256)
        self.assertEqual(active["review_amendment"]["sha256"], context.amendment_sha256)
        self.assertIn("author-review-2", active["author_review"]["path"])
        self.assertNotEqual(
            active["author_review"]["sha256"], selection.amendment.BASE_REVIEW_SHA256
        )
        for record in active.values():
            path = Path(record["path"])
            if not path.is_absolute():
                path = selection.REPOSITORY_ROOT / path
            self.assertTrue(path.is_file())
            self.assertEqual(selection.sha256_file(path), record["sha256"])

    def test_receipt_is_private_recomputed_and_write_once(self) -> None:
        context = selection.prepare_amended_context()
        output = self.root / "selection-rule2-2.json"
        receipt_path = selection.write_selection_receipt(context, output)
        self.assertEqual(selection.verify_selection_receipt(output), receipt_path)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(list(output.parent.glob(f".{output.name}.*.tmp")), [])
        receipt = json.loads(output.read_bytes())
        self.assertEqual(receipt["selection_id"], "rule2-selection-2")
        self.assertEqual(
            receipt["correction_effect"]["movement_count"], {"before": 5, "after": 4}
        )
        self.assertFalse(receipt["correction_effect"]["selection_changed"])
        with self.assertRaisesRegex(selection.AmendedSelectionError, "write-once"):
            selection.write_selection_receipt(context, output)

    def test_changed_metric_is_rejected(self) -> None:
        context = selection.prepare_amended_context()
        output = self.root / "selection-rule2-2.json"
        selection.write_selection_receipt(context, output)
        receipt = json.loads(output.read_bytes())
        receipt["candidate_metrics"][-1]["movement_count"] = 3
        output.write_bytes(selection.canonical_json_bytes(receipt))
        output.chmod(0o600)
        with self.assertRaisesRegex(selection.AmendedSelectionError, "recomputed"):
            selection.verify_selection_receipt(output)

    def test_completed_claim_is_recoverable(self) -> None:
        context = selection.prepare_amended_context()
        output = self.root / "selection-rule2-2.json"
        selection.write_selection_receipt(context, output)
        payload = output.read_bytes()
        claim = selection._claim_path(output)
        selection._write_private(
            claim,
            selection.canonical_json_bytes(
                selection._claim_value(
                    output,
                    selection.sha256_bytes(payload),
                    f".{output.name}.recovery.tmp",
                    "a" * 64,
                )
            ),
        )
        self.assertEqual(selection.recover_incomplete_publication(output), "completed")
        self.assertFalse(claim.exists())

    def test_completed_output_quarantine_is_recoverable(self) -> None:
        context = selection.prepare_amended_context()
        output = self.root / "selection-rule2-2.json"
        selection.write_selection_receipt(context, output)
        payload = output.read_bytes()
        claim = selection._claim_path(output)
        selection._write_private(
            claim,
            selection.canonical_json_bytes(
                selection._claim_value(
                    output,
                    selection.sha256_bytes(payload),
                    f".{output.name}.recovery.tmp",
                    "9" * 64,
                )
            ),
        )
        quarantine = output.parent / (
            f"{output.name}{selection.OUTPUT_CLEANUP_INFIX}fixture"
        )
        os.rename(output, quarantine)

        self.assertEqual(selection.recover_incomplete_publication(output), "completed")
        self.assertTrue(output.is_file())
        self.assertFalse(quarantine.exists())
        self.assertFalse(claim.exists())

    def test_unpublished_private_staging_is_recoverable(self) -> None:
        output = self.root / "selection-rule2-2.json"
        staging_name = f".{output.name}.fixture.tmp"
        operation_token = "b" * 64
        staging = output.parent / staging_name
        staging.mkdir(mode=0o700)
        selection._write_private(
            staging / selection.STAGING_OWNER_NAME,
            selection._staging_owner_payload(output, operation_token),
        )
        selection._write_private(staging / selection.STAGING_PAYLOAD_NAME, b"partial")
        claim = selection._claim_path(output)
        selection._write_private(
            claim,
            selection.canonical_json_bytes(
                selection._claim_value(output, "0" * 64, staging_name, operation_token)
            ),
        )
        self.assertEqual(selection.recover_incomplete_publication(output), "cleared")
        self.assertFalse(staging.exists())
        self.assertFalse(claim.exists())

    def test_foreign_claim_is_not_deleted_after_claim_race(self) -> None:
        context = selection.prepare_amended_context()
        output = self.root / "selection-rule2-2.json"
        claim = selection._claim_path(output)
        foreign_payload = b'{"foreign":true}\n'
        original_write = selection._write_private

        def install_foreign(path: Path, payload: bytes) -> None:
            if path == claim:
                original_write(path, foreign_payload)
                raise selection.AmendedSelectionError("simulated claim race")
            original_write(path, payload)

        with mock.patch.object(
            selection, "_write_private", side_effect=install_foreign
        ):
            with self.assertRaisesRegex(selection.AmendedSelectionError, "claim race"):
                selection.write_selection_receipt(context, output)
        self.assertEqual(claim.read_bytes(), foreign_payload)
        self.assertFalse(output.exists())

    def test_dangling_destination_is_not_cleared_by_recovery(self) -> None:
        output = self.root / "selection-rule2-2.json"
        output.symlink_to(self.root / "missing")
        claim = selection._claim_path(output)
        selection._write_private(
            claim,
            selection.canonical_json_bytes(
                selection._claim_value(
                    output,
                    "0" * 64,
                    f".{output.name}.recovery.tmp",
                    "c" * 64,
                )
            ),
        )
        with self.assertRaises(selection.base.SelectionError):
            selection.recover_incomplete_publication(output)
        self.assertTrue(output.is_symlink())
        self.assertTrue(claim.is_file())


if __name__ == "__main__":
    unittest.main()
