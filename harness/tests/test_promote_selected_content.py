from __future__ import annotations

import copy
import json
import os
import shutil
import stat
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import promote_selected_content as promotion
from concordance_harness.util import canonical_json_bytes, sha256_bytes


PRIVATE_REVIEW_AVAILABLE = (
    promotion.SEALED_DRAFT_PATH.is_file() and promotion.SEALED_RECEIPT_PATH.is_file()
)


def _read_json(path: Path) -> dict:
    return json.loads(path.read_bytes())


def _fixture_context() -> promotion.PromotionContext:
    predecessor_manifest = _read_json(promotion.PREDECESSOR_MANIFEST_PATH)
    predecessor_questions = tuple(
        _read_json(promotion.PREDECESSOR_ROOT / "questions" / f"{question_id}.json")
        for question_id in promotion.SELECTED_IDS
    )
    return promotion.PromotionContext(
        predecessor_manifest=predecessor_manifest,
        predecessor_questions=predecessor_questions,
        sealed_draft={
            "content_decisions": [],
            "mapping_attestations": [],
        },
        sealed_receipt={},
        review_id="selected-review-fixture",
        reviewed_at=promotion.AUTHOR_REVIEWED_AT,
        sealed_at=promotion.SEALED_AT,
    )


def _strip_promotion(question: dict) -> dict:
    stripped = copy.deepcopy(question)
    stripped["content_version"] = promotion.PREDECESSOR_CONTENT_VERSION
    proposed = {"status": "proposed", "verified_by": None, "verified_at": None}
    stripped["verification"] = copy.deepcopy(proposed)
    for position in stripped["position_map"]:
        position["verification"] = copy.deepcopy(proposed)
        for source in position["sources"]:
            source["verification"] = copy.deepcopy(proposed)
    return stripped


class SelectedContentPromotionPureTests(unittest.TestCase):
    def test_pinned_reader_hashes_and_parses_one_open_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "record.json"
            replacement = root / "replacement.json"
            pinned = canonical_json_bytes({"record": "pinned"})
            changed = canonical_json_bytes({"record": "changed"})
            path.write_bytes(pinned)
            replacement.write_bytes(changed)
            real_open = promotion.os.open
            real_replace = promotion.os.replace
            swapped = False

            def open_then_swap(*args, **kwargs):
                nonlocal swapped
                descriptor = real_open(*args, **kwargs)
                if Path(args[0]) == path and not swapped:
                    real_replace(replacement, path)
                    swapped = True
                return descriptor

            with patch.object(promotion.os, "open", side_effect=open_then_swap):
                value, payload = promotion._read_pinned_json(
                    path,
                    sha256_bytes(pinned),
                    "pinned fixture",
                )

            self.assertTrue(swapped)
            self.assertEqual(value, {"record": "pinned"})
            self.assertEqual(payload, pinned)
            self.assertEqual(path.read_bytes(), changed)

    def test_payloads_change_only_content_version_and_verification(self) -> None:
        context = _fixture_context()
        first = promotion.promotion_payloads(context)
        second = promotion.promotion_payloads(context)

        self.assertEqual(first, second)
        for predecessor in context.predecessor_questions:
            question_id = predecessor["id"]
            promoted = json.loads(first[f"questions/{question_id}.json"])
            self.assertEqual(_strip_promotion(promoted), predecessor)
            self.assertEqual(promoted["content_version"], promotion.CONTENT_VERSION)
            records = [
                promoted["verification"],
                *(position["verification"] for position in promoted["position_map"]),
                *(
                    source["verification"]
                    for position in promoted["position_map"]
                    for source in position["sources"]
                ),
            ]
            self.assertTrue(records)
            self.assertTrue(
                all(
                    record
                    == {
                        "status": "author-verified",
                        "verified_by": "A.G. Elrod",
                        "verified_at": promotion.AUTHOR_REVIEWED_AT,
                    }
                    for record in records
                )
            )

    def test_public_manifest_preserves_gates_without_private_payloads(self) -> None:
        payloads = promotion.promotion_payloads(_fixture_context())
        manifest = json.loads(payloads["manifest.json"])
        combined = b"\n".join(payloads.values()).decode("utf-8")

        self.assertEqual(manifest["content_version"], promotion.CONTENT_VERSION)
        self.assertEqual(
            manifest["selection_result"]["failed_behaviors"], ["divergence"]
        )
        self.assertFalse(manifest["selection_result"]["production_eligible"])
        self.assertEqual(
            manifest["selection_result"]["scholarship_verification"],
            "author-verified",
        )
        self.assertEqual(
            manifest["production_gate"],
            {
                "eligible": False,
                "blockers": [
                    "divergence has no qualifying selected candidate",
                    "the linked-challenge final model run has not been executed",
                ],
            },
        )
        self.assertNotIn('"response_text"', combined)
        self.assertNotIn("/Users/", combined)
        self.assertNotIn("/Volumes/", combined)
        self.assertNotIn(str(promotion.REPOSITORY_ROOT), combined)

    def test_public_write_is_verified_and_write_once(self) -> None:
        context = _fixture_context()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / promotion.CONTENT_VERSION
            manifest_path = promotion.write_promotion(context, output)

            self.assertEqual(
                promotion.verify_promotion(output, context=context), manifest_path
            )
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(manifest_path.stat().st_mode), 0o644)
            with self.assertRaisesRegex(
                promotion.SelectedContentPromotionError, "immutable"
            ):
                promotion.write_promotion(context, output)

    def test_concurrent_public_writers_publish_exactly_once(self) -> None:
        context = _fixture_context()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / promotion.CONTENT_VERSION
            barrier = threading.Barrier(2)

            def attempt_write() -> Path | Exception:
                barrier.wait()
                try:
                    return promotion.write_promotion(context, output)
                except Exception as error:  # capture both contenders for assertion
                    return error

            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(lambda _: attempt_write(), range(2)))

            paths = [result for result in results if isinstance(result, Path)]
            errors = [result for result in results if isinstance(result, Exception)]
            self.assertEqual(paths, [output / "manifest.json"])
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], promotion.SelectedContentPromotionError)
            self.assertIn("cooperatively immutable", str(errors[0]))
            self.assertEqual(
                promotion.verify_promotion(output, context=context),
                output / "manifest.json",
            )
            self.assertEqual(
                [entry.name for entry in output.parent.iterdir()],
                [promotion.CONTENT_VERSION],
            )

    def test_changed_promoted_question_is_rejected(self) -> None:
        context = _fixture_context()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / promotion.CONTENT_VERSION
            promotion.write_promotion(context, output)
            question_path = output / "questions/junia-romans-16-7.json"
            question = _read_json(question_path)
            question["premise"] += " Altered."
            question_path.write_bytes(canonical_json_bytes(question))
            os.chmod(question_path, 0o644)

            with self.assertRaisesRegex(
                promotion.SelectedContentPromotionError,
                "promoted successor bytes differ",
            ):
                promotion.verify_promotion(output, context=context)


class SelectedContentPromotionSyntheticSealTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.predecessor_root = self.root / promotion.PREDECESSOR_CONTENT_VERSION
        shutil.copytree(promotion.PREDECESSOR_ROOT, self.predecessor_root)
        self.packet_root = self.root / "packet"
        self.sealed_root = self.packet_root / "sealed-review"
        self.sealed_root.mkdir(parents=True, mode=0o700)
        os.chmod(self.packet_root, 0o700)
        os.chmod(self.sealed_root, 0o700)
        self.draft = {
            "schema_version": promotion.finalizer.REVIEW_SCHEMA_VERSION,
            "status": "complete-selected-content-review",
            "exported_at": promotion.AUTHOR_REVIEWED_AT,
            "review_id": "selected-review-fixture",
            "reviewer": copy.deepcopy(promotion.REVIEWER),
            "content_decisions": [
                {
                    "question_id": question_id,
                    "question_sha256": promotion.PREDECESSOR_QUESTION_SHA256[
                        question_id
                    ],
                    "decision": "author-verify",
                    "reviewed_at": promotion.AUTHOR_REVIEWED_AT,
                }
                for question_id in promotion.SELECTED_IDS
            ],
            "mapping_attestations": [
                {
                    "question_id": question_id,
                    "mapping_count": promotion.EXPECTED_MAPPING_COUNTS[question_id],
                    "mappings_sha256": str(index + 1) * 64,
                    "decision": "approve-pilot-lineage",
                    "reviewed_at": promotion.AUTHOR_REVIEWED_AT,
                }
                for index, question_id in enumerate(promotion.SELECTED_IDS)
            ],
            "author_attestation": {
                "exact_content_reviewed": True,
                "selected_pilot_mappings_reviewed": True,
                "final_run_requires_fresh_mappings": True,
            },
        }
        self.draft_payload = canonical_json_bytes(self.draft)
        self.draft_sha256 = sha256_bytes(self.draft_payload)
        self.receipt = {
            "schema_version": promotion.finalizer.RECEIPT_SCHEMA_VERSION,
            "status": "complete-selected-content-review-sealed",
            "created_at": promotion.SEALED_AT,
            "reviewer": copy.deepcopy(promotion.REVIEWER),
            "verified_question_ids": list(promotion.SELECTED_IDS),
            "question_count": 2,
            "mapping_count": 24,
            "content_verification_status": "authorized-for-author-verified-promotion",
            "input_draft": {
                "path": "review-draft.json",
                "sha256": self.draft_sha256,
            },
            "packet_receipt": {
                "path": "../packet.json",
                "sha256": promotion.PACKET_RECEIPT_SHA256,
            },
            "production_gate": {
                "eligible": False,
                "reason": "The divergence case and fresh final run remain incomplete.",
            },
            "author_attestation": copy.deepcopy(self.draft["author_attestation"]),
        }
        self.receipt_payload = canonical_json_bytes(self.receipt)
        (self.sealed_root / "review-draft.json").write_bytes(self.draft_payload)
        (self.sealed_root / "review.json").write_bytes(self.receipt_payload)
        os.chmod(self.sealed_root / "review-draft.json", 0o600)
        os.chmod(self.sealed_root / "review.json", 0o600)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _prepare(self) -> promotion.PromotionContext:
        with (
            patch.object(promotion.finalizer, "verify_sealed_review"),
            patch.object(promotion, "SEALED_DRAFT_SHA256", self.draft_sha256),
            patch.object(
                promotion,
                "SEALED_RECEIPT_SHA256",
                sha256_bytes(self.receipt_payload),
            ),
        ):
            return promotion.prepare_promotion(
                predecessor_root=self.predecessor_root,
                packet_root=self.packet_root,
                sealed_root=self.sealed_root,
            )

    def test_synthetic_exact_seal_authorizes_promotion(self) -> None:
        context = self._prepare()

        self.assertEqual(context.review_id, "selected-review-fixture")
        self.assertEqual(context.reviewed_at, promotion.AUTHOR_REVIEWED_AT)
        self.assertEqual(context.sealed_at, promotion.SEALED_AT)

    def test_changed_sealed_receipt_hash_is_rejected(self) -> None:
        receipt_path = self.sealed_root / "review.json"
        receipt_path.write_bytes(self.receipt_payload + b" ")
        os.chmod(receipt_path, 0o600)

        with (
            patch.object(promotion.finalizer, "verify_sealed_review"),
            patch.object(promotion, "SEALED_DRAFT_SHA256", self.draft_sha256),
            patch.object(
                promotion,
                "SEALED_RECEIPT_SHA256",
                sha256_bytes(self.receipt_payload),
            ),
        ):
            with self.assertRaisesRegex(
                promotion.SelectedContentPromotionError,
                "sealed selected-content review receipt hash differs",
            ):
                promotion.prepare_promotion(
                    predecessor_root=self.predecessor_root,
                    packet_root=self.packet_root,
                    sealed_root=self.sealed_root,
                )


@unittest.skipUnless(
    PRIVATE_REVIEW_AVAILABLE,
    "private selected-content seal is intentionally absent from a clean checkout",
)
class SelectedContentPromotionPrivateTests(unittest.TestCase):
    def test_exact_private_seal_and_predecessor_authorize_promotion(self) -> None:
        context = promotion.prepare_promotion()

        self.assertEqual(
            context.review_id, "selected-review-57e22e96d69998198d061b87d76b3923"
        )
        self.assertEqual(context.reviewed_at, promotion.AUTHOR_REVIEWED_AT)
        self.assertEqual(context.sealed_at, promotion.SEALED_AT)
        self.assertEqual(
            [question["id"] for question in context.predecessor_questions],
            list(promotion.SELECTED_IDS),
        )


if __name__ == "__main__":
    unittest.main()
