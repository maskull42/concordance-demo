from __future__ import annotations

import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import finalize_selected_content_review as finalize
import prepare_selected_content_review as packet


PRIVATE_INPUT_AVAILABLE = (
    packet.SELECTION_PATH.is_file() and packet.SUCCESSOR_MANIFEST_PATH.is_file()
)


@unittest.skipUnless(
    PRIVATE_INPUT_AVAILABLE,
    "private Rule 2 selection is intentionally absent from a clean checkout",
)
class SelectedContentReviewValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.packet_root = self.root / "selected-content-review-1"
        self.context = packet.prepare_review_context()
        packet.write_review_packet(self.context, self.packet_root)
        receipt = json.loads((self.packet_root / "packet.json").read_bytes())
        self.reviewed_at = "2026-07-13T08:00:00.000+00:00"
        self.draft = {
            "schema_version": "selected-content-review-draft-1.0.0",
            "status": "complete-selected-content-review",
            "exported_at": self.reviewed_at,
            "network_requests": 0,
            "environment_variables_read": 0,
            "review_id": receipt["review_id"],
            "reviewer": {"id": "ag-elrod", "display_name": "A.G. Elrod"},
            "bindings": self.context.bindings,
            "content_decisions": [
                {
                    "question_id": record["question"]["id"],
                    "question_sha256": record["sha256"],
                    "decision": "author-verify",
                    "reviewed_at": self.reviewed_at,
                }
                for record in self.context.questions
            ],
            "mapping_attestations": [
                {
                    **group,
                    "decision": "approve-pilot-lineage",
                    "reviewed_at": self.reviewed_at,
                }
                for group in self.context.mapping_groups
            ],
            "author_attestation": {
                "exact_content_reviewed": True,
                "selected_pilot_mappings_reviewed": True,
                "final_run_requires_fresh_mappings": True,
            },
        }
        self.draft_path = self.root / "review-export.json"
        self._write_draft()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_draft(self) -> None:
        self.draft_path.write_text(
            json.dumps(self.draft, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def test_complete_export_validates(self) -> None:
        validation = finalize.validate_review_input(
            self.draft_path, packet_root=self.packet_root
        )
        self.assertEqual(validation.question_ids, packet.SELECTED_IDS)
        self.assertEqual(
            validation.value["author_attestation"]["exact_content_reviewed"], True
        )

    def test_changed_question_binding_is_rejected(self) -> None:
        self.draft["content_decisions"][0]["question_sha256"] = "0" * 64
        self._write_draft()
        with self.assertRaisesRegex(
            finalize.SelectedContentReviewValidationError, "content decision differs"
        ):
            finalize.validate_review_input(
                self.draft_path, packet_root=self.packet_root
            )

    def test_seal_is_private_verified_and_write_once(self) -> None:
        sealed_root = self.packet_root / "sealed-review"
        receipt_path = finalize.seal_review(
            self.draft_path,
            packet_root=self.packet_root,
            sealed_root=sealed_root,
        )
        self.assertEqual(
            finalize.verify_sealed_review(
                packet_root=self.packet_root, sealed_root=sealed_root
            ),
            receipt_path,
        )
        self.assertEqual(stat.S_IMODE(sealed_root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(receipt_path.stat().st_mode), 0o600)
        with self.assertRaisesRegex(
            finalize.SelectedContentReviewValidationError, "write-once"
        ):
            finalize.seal_review(
                self.draft_path,
                packet_root=self.packet_root,
                sealed_root=sealed_root,
            )


if __name__ == "__main__":
    unittest.main()
