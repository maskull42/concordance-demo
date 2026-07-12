from __future__ import annotations

import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import finalize_author_review as finalizer
import prepare_author_review as packet_builder


PRIVATE_INPUT_AVAILABLE = packet_builder.FIRST_PASS_PATH.is_file()
TIMESTAMP = "2026-07-12T12:00:00.000Z"


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(packet_builder.canonical_json_bytes(value))


@unittest.skipUnless(
    PRIVATE_INPUT_AVAILABLE,
    "private first-pass mappings are intentionally absent from a clean checkout",
)
class AuthorReviewValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.context = packet_builder.prepare_review_context()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.packet_root = Path(self.temporary.name) / "author-review-1"
        packet_builder.write_review_packet(self.context, self.packet_root)
        self.packet_receipt = json.loads(
            (self.packet_root / "packet.json").read_bytes()
        )
        self.draft_path = Path(self.temporary.name) / "review-complete.json"
        self.draft = self._complete_draft()
        _write_json(self.draft_path, self.draft)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _decisions(self) -> list[dict[str, object]]:
        result = []
        for item in self.context.items:
            assignment = item["first_pass_assignment"]
            result.append(
                {
                    "review_index": item["review_index"],
                    "blind_item_id": item["blind_item_id"],
                    "response_sha256": item["response_sha256"],
                    "review_item_sha256": item["review_item_sha256"],
                    "first_pass_assignment_sha256": item[
                        "first_pass_assignment_sha256"
                    ],
                    "first_pass_primary_endorsed": assignment["primary_endorsed"],
                    "first_pass_primary_reason_code": assignment[
                        "primary_reason_code"
                    ],
                    "decision": "confirm",
                    "reviewed_primary_endorsed": assignment["primary_endorsed"],
                    "reviewed_primary_reason_code": assignment[
                        "primary_reason_code"
                    ],
                    "review_note": None,
                    "reviewed_at": TIMESTAMP,
                }
            )
        return result

    def _complete_draft(self) -> dict[str, object]:
        return {
            "schema_version": finalizer.DRAFT_SCHEMA_VERSION,
            "status": "complete-primary-review",
            "rubric_id": "mapping-rubric-1",
            "rubric_sha256": packet_builder.EXPECTED_RUBRIC_SHA256,
            "exported_at": TIMESTAMP,
            "network_requests": 0,
            "environment_variables_read": 0,
            "review_id": self.packet_receipt["review_id"],
            "first_pass_receipt_sha256": packet_builder.EXPECTED_FIRST_PASS_SHA256,
            "ordered_items_sha256": self.context.ordered_items_sha256,
            "reviewer": {"id": "ag-elrod", "display_name": "A.G. Elrod"},
            "review_scope": "primary-and-reason-only",
            "item_count": 64,
            "cursor": 63,
            "decisions": self._decisions(),
            "author_attestation": True,
            "threshold_evaluation": {
                "performed": False,
                "reason": "Primary review is complete; threshold calculation has not run",
            },
            "selection_status": "not-evaluated",
        }

    def _set_first_correction(self, draft: dict[str, object]) -> None:
        decision = draft["decisions"][0]  # type: ignore[index]
        item = self.context.items[0]
        original = decision["first_pass_primary_endorsed"]
        handles = [position["handle"] for position in item["positions"]]
        replacement = next(handle for handle in handles if handle != original)
        decision["decision"] = "correct"
        decision["reviewed_primary_endorsed"] = replacement
        decision["reviewed_primary_reason_code"] = "clear_preference"
        decision["review_note"] = "The response gives the replacement position priority."

    def test_complete_review_validates_seals_and_verifies(self) -> None:
        value = finalizer.validate_review_input(
            self.draft_path,
            require_complete=True,
            packet_root=self.packet_root,
        )
        self.assertEqual((value.confirmed, value.corrected, value.pending), (64, 0, 0))
        sealed_root = self.packet_root / "sealed-primary-review"
        receipt_path = finalizer.seal_review(
            self.draft_path,
            packet_root=self.packet_root,
            sealed_root=sealed_root,
        )
        self.assertEqual(
            finalizer.verify_sealed_review(
                packet_root=self.packet_root, sealed_root=sealed_root
            ),
            receipt_path,
        )
        self.assertEqual(stat.S_IMODE(sealed_root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(receipt_path.stat().st_mode), 0o600)
        self.assertEqual(
            stat.S_IMODE((sealed_root / "review-draft.json").stat().st_mode), 0o600
        )
        with self.assertRaisesRegex(
            finalizer.AuthorReviewValidationError, "write-once"
        ):
            finalizer.seal_review(
                self.draft_path,
                packet_root=self.packet_root,
                sealed_root=sealed_root,
            )

    def test_valid_correction_is_counted_and_preserved(self) -> None:
        self._set_first_correction(self.draft)
        _write_json(self.draft_path, self.draft)
        value = finalizer.validate_review_input(
            self.draft_path,
            require_complete=True,
            packet_root=self.packet_root,
        )
        self.assertEqual((value.confirmed, value.corrected, value.pending), (63, 1, 0))
        self.assertEqual(value.decisions[0]["decision"], "correct")

    def test_correction_note_is_optional(self) -> None:
        self._set_first_correction(self.draft)
        self.draft["decisions"][0]["review_note"] = None  # type: ignore[index]
        _write_json(self.draft_path, self.draft)
        value = finalizer.validate_review_input(
            self.draft_path,
            require_complete=True,
            packet_root=self.packet_root,
        )
        self.assertEqual(value.corrected, 1)
        self.assertIsNone(value.decisions[0]["review_note"])

    def test_in_progress_export_is_checkable_but_not_sealable(self) -> None:
        first = self.draft["decisions"][0]  # type: ignore[index]
        first["decision"] = "pending"
        first["reviewed_at"] = None
        self.draft["status"] = "author-review-in-progress"
        self.draft["author_attestation"] = False
        self.draft["threshold_evaluation"] = {
            "performed": False,
            "reason": "Author review is in progress",
        }
        _write_json(self.draft_path, self.draft)
        value = finalizer.validate_review_input(
            self.draft_path,
            require_complete=False,
            packet_root=self.packet_root,
        )
        self.assertEqual(value.pending, 1)
        with self.assertRaisesRegex(
            finalizer.AuthorReviewValidationError, "not complete"
        ):
            finalizer.validate_review_input(
                self.draft_path,
                require_complete=True,
                packet_root=self.packet_root,
            )

    def test_inconsistent_decisions_are_rejected(self) -> None:
        original = json.loads(json.dumps(self.draft))
        cases = []

        changed_confirmation = json.loads(json.dumps(original))
        self._set_first_correction(changed_confirmation)
        changed_confirmation["decisions"][0]["decision"] = "confirm"
        cases.append(("confirmation changes", changed_confirmation))

        unchanged_correction = json.loads(json.dumps(original))
        unchanged_correction["decisions"][0]["decision"] = "correct"
        unchanged_correction["decisions"][0]["review_note"] = "A note."
        cases.append(("correction does not change", unchanged_correction))

        wrong_binding = json.loads(json.dumps(original))
        wrong_binding["decisions"][0]["response_sha256"] = "0" * 64
        cases.append(("binding differs", wrong_binding))

        invalid_reason = json.loads(json.dumps(original))
        invalid_reason["decisions"][0]["reviewed_primary_reason_code"] = "mixed"
        cases.append(("are inconsistent", invalid_reason))

        for message, candidate in cases:
            with self.subTest(message=message):
                _write_json(self.draft_path, candidate)
                with self.assertRaisesRegex(
                    finalizer.AuthorReviewValidationError, message
                ):
                    finalizer.validate_review_input(
                        self.draft_path,
                        require_complete=True,
                        packet_root=self.packet_root,
                    )

    def test_duplicate_json_key_is_rejected(self) -> None:
        payload = packet_builder.canonical_json_bytes(self.draft)
        payload = payload.replace(
            b'"status": "complete-primary-review"',
            b'"status": "complete-primary-review", "status": "author-review-in-progress"',
            1,
        )
        self.draft_path.write_bytes(payload)
        with self.assertRaisesRegex(
            finalizer.AuthorReviewValidationError, "duplicate JSON key"
        ):
            finalizer.validate_review_input(
                self.draft_path,
                require_complete=True,
                packet_root=self.packet_root,
            )

    def test_post_seal_draft_mutation_is_rejected(self) -> None:
        sealed_root = self.packet_root / "sealed-primary-review"
        finalizer.seal_review(
            self.draft_path,
            packet_root=self.packet_root,
            sealed_root=sealed_root,
        )
        stored = json.loads((sealed_root / "review-draft.json").read_bytes())
        stored["decisions"][0]["review_note"] = "Later mutation."
        _write_json(sealed_root / "review-draft.json", stored)
        with self.assertRaisesRegex(
            finalizer.AuthorReviewValidationError, "differs from contract"
        ):
            finalizer.verify_sealed_review(
                packet_root=self.packet_root, sealed_root=sealed_root
            )

    def test_validator_provenance_mutation_is_rejected(self) -> None:
        sealed_root = self.packet_root / "sealed-primary-review"
        receipt_path = finalizer.seal_review(
            self.draft_path,
            packet_root=self.packet_root,
            sealed_root=sealed_root,
        )
        receipt = json.loads(receipt_path.read_bytes())
        receipt["validator"]["source_files"] = {"fictional.py": "0" * 64}
        receipt["validator"]["execution_sha256"] = finalizer.sha256_bytes(
            finalizer.canonical_json_bytes(receipt["validator"]["source_files"])
        )
        _write_json(receipt_path, receipt)
        with self.assertRaisesRegex(
            finalizer.AuthorReviewValidationError, "differs from contract"
        ):
            finalizer.verify_sealed_review(
                packet_root=self.packet_root, sealed_root=sealed_root
            )

    def test_sealing_never_replaces_racing_destination(self) -> None:
        sealed_root = self.packet_root / "sealed-primary-review"
        original = finalizer.tempfile.mkdtemp

        def race(*args: object, **kwargs: object) -> str:
            created = original(*args, **kwargs)
            sealed_root.mkdir()
            return created

        with mock.patch.object(finalizer.tempfile, "mkdtemp", race):
            with self.assertRaisesRegex(
                finalizer.AuthorReviewValidationError, "write-once"
            ):
                finalizer.seal_review(
                    self.draft_path,
                    packet_root=self.packet_root,
                    sealed_root=sealed_root,
                )
        self.assertTrue(sealed_root.is_dir())
        self.assertEqual(list(sealed_root.iterdir()), [])

    def test_failed_seal_cleans_claimed_partial_output(self) -> None:
        sealed_root = self.packet_root / "sealed-primary-review"
        original = finalizer.os.link
        calls = 0

        def fail_second(source: object, destination: object) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("simulated second-link failure")
            original(source, destination)

        with mock.patch.object(finalizer.os, "link", fail_second):
            with self.assertRaisesRegex(OSError, "second-link failure"):
                finalizer.seal_review(
                    self.draft_path,
                    packet_root=self.packet_root,
                    sealed_root=sealed_root,
                )
        self.assertFalse(sealed_root.exists())
        self.assertFalse(finalizer._claim_path(sealed_root).exists())

    def test_explicit_recovery_clears_crash_left_partial_seal(self) -> None:
        sealed_root = self.packet_root / "sealed-primary-review"
        claim = finalizer._claim_path(sealed_root)
        finalizer._write_private(
            claim, finalizer.canonical_json_bytes(finalizer._claim_value(sealed_root))
        )
        sealed_root.mkdir(mode=0o700)
        finalizer._write_private(sealed_root / "review-draft.json", b"partial")
        self.assertEqual(
            finalizer.recover_incomplete_seal(
                packet_root=self.packet_root, sealed_root=sealed_root
            ),
            "cleared",
        )
        self.assertFalse(sealed_root.exists())
        self.assertFalse(claim.exists())

    def test_explicit_recovery_preserves_complete_verified_seal(self) -> None:
        sealed_root = self.packet_root / "sealed-primary-review"
        finalizer.seal_review(
            self.draft_path,
            packet_root=self.packet_root,
            sealed_root=sealed_root,
        )
        claim = finalizer._claim_path(sealed_root)
        finalizer._write_private(
            claim, finalizer.canonical_json_bytes(finalizer._claim_value(sealed_root))
        )
        self.assertEqual(
            finalizer.recover_incomplete_seal(
                packet_root=self.packet_root, sealed_root=sealed_root
            ),
            "completed",
        )
        self.assertTrue((sealed_root / "review.json").is_file())
        self.assertFalse(claim.exists())


if __name__ == "__main__":
    unittest.main()
