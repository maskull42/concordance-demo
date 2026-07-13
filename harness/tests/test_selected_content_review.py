from __future__ import annotations

import json
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import prepare_selected_content_review as review
import finalize_selected_content_review as finalize


PRIVATE_INPUT_AVAILABLE = (
    review.SELECTION_PATH.is_file() and review.SUCCESSOR_MANIFEST_PATH.is_file()
)
BROWSER_CHECK_PATH = Path(__file__).with_name(
    "check_selected_content_review_browser.mjs"
)


class SelectedContentReviewAssetTests(unittest.TestCase):
    def test_browser_script_has_valid_javascript_syntax(self) -> None:
        result = subprocess.run(
            ["node", "--check", str(review.SCRIPT_PATH)],
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_browser_script_exposes_all_bound_question_fields_and_decisions(
        self,
    ) -> None:
        script = review.SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertIn("JSON.stringify(question, null, 2)", script)
        self.assertIn("fullRecord.open = true", script)
        self.assertIn('"Bound question SHA-256"', script)
        self.assertIn('"Review decision", mapping.review_decision', script)
        self.assertNotIn("innerHTML", script)

    def test_render_keeps_untrusted_text_inside_base64_payload(self) -> None:
        context = review.SelectedContentReviewContext(
            bindings={"fixture": {"sha256": "0" * 64}},
            questions=(),
            mappings=(
                {
                    "cell_id": "fixture:model:default:answer",
                    "response_text": "</script><script>alert('unsafe')</script>",
                },
            ),
            mapping_groups=(),
        )
        payload, _ = review.render_packet(context, "selected-review-fixture")
        self.assertNotIn(b"alert('unsafe')", payload)
        self.assertEqual(payload.count(b"<script>"), 1)


@unittest.skipUnless(
    PRIVATE_INPUT_AVAILABLE,
    "private Rule 2 selection is intentionally absent from a clean checkout",
)
class SelectedContentReviewTests(unittest.TestCase):
    def test_context_enforces_pinned_successor_manifest(self) -> None:
        with patch.object(review, "SUCCESSOR_MANIFEST_SHA256", "0" * 64):
            with self.assertRaisesRegex(
                review.SelectedContentReviewError, "successor manifest hash differs"
            ):
                review.prepare_review_context()

    def test_context_binds_two_questions_and_twenty_four_mappings(self) -> None:
        context = review.prepare_review_context()
        self.assertEqual(
            [record["question"]["id"] for record in context.questions],
            list(review.SELECTED_IDS),
        )
        self.assertEqual(len(context.mappings), 24)
        self.assertEqual(
            [group["mapping_count"] for group in context.mapping_groups], [8, 16]
        )
        corrected = [
            mapping
            for mapping in context.mappings
            if mapping["review_decision"] == "correct"
        ]
        self.assertEqual(len(corrected), 1)
        self.assertEqual(corrected[0]["cell_id"], review.TARGET_CELL_ID)
        self.assertIsNone(corrected[0]["reviewed_primary_position_id"])
        self.assertEqual(corrected[0]["reviewed_primary_reason_code"], "outside_map")
        for record in context.questions:
            question = record["question"]
            self.assertEqual(question["verification"]["status"], "proposed")
            for position in question["position_map"]:
                self.assertEqual(position["verification"]["status"], "proposed")
                for source in position["sources"]:
                    self.assertEqual(source["verification"]["status"], "proposed")

    def test_write_verify_privacy_and_write_once(self) -> None:
        context = review.prepare_review_context()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "selected-content-review-1"
            packet_path = review.write_review_packet(context, output)
            self.assertEqual(review.verify_review_packet(output), packet_path)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(packet_path.stat().st_mode), 0o600)
            receipt_path = output / "packet.json"
            self.assertEqual(stat.S_IMODE(receipt_path.stat().st_mode), 0o600)
            receipt = json.loads(receipt_path.read_bytes())
            self.assertEqual(receipt["question_count"], 2)
            self.assertEqual(receipt["mapping_count"], 24)
            self.assertNotIn(
                context.mappings[0]["response_text"],
                receipt_path.read_text(encoding="utf-8"),
            )
            with self.assertRaisesRegex(
                review.SelectedContentReviewError, "write-once"
            ):
                review.write_review_packet(context, output)

    def test_browser_export_validates_end_to_end(self) -> None:
        context = review.prepare_review_context()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "selected-content-review-1"
            packet_path = review.write_review_packet(context, output)
            export_path = root / "browser-export.json"
            result = subprocess.run(
                [
                    "node",
                    str(BROWSER_CHECK_PATH),
                    str(packet_path),
                    str(export_path),
                ],
                capture_output=True,
                check=False,
                text=True,
                timeout=60,
            )
            if result.returncode != 0 and "Executable doesn't exist" in result.stderr:
                self.skipTest("Playwright Chromium is not installed")
            self.assertEqual(result.returncode, 0, result.stderr)
            validation = finalize.validate_review_input(export_path, packet_root=output)
            self.assertEqual(validation.question_ids, review.SELECTED_IDS)


if __name__ == "__main__":
    unittest.main()
