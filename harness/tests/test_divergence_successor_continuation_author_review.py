from __future__ import annotations

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import jsonschema

from concordance_harness.util import canonical_json_bytes, sha256_bytes
from divergence_successor_continuation import review as base_review
from divergence_successor_continuation_author_review import anchor, contract, lock, review


SOURCE_ROOT = Path(__file__).resolve().parents[2]
FIXED_TIME = "2026-07-14T18:00:00Z"


class ContinuationAuthorReviewV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.packet, _, cls.verified_anchor = review._load_blind_packet(SOURCE_ROOT)

    def _draft(self) -> dict[str, object]:
        assignments = []
        for item in self.packet["items"]:
            assignments.append(
                {
                    "blind_id": item["blind_id"],
                    "response_sha256": item["response_sha256"],
                    "primary_position_handle": item["position_map"][0]["handle"],
                    "primary_reason_code": "clear_preference",
                    "rationale": "The response states a direct primary preference.",
                    "evidence_snippets": [item["response_text"][:80]],
                    "confidence": "high",
                }
            )
        return {
            "schema_version": contract.FIRST_PASS_SCHEMA,
            "status": contract.FIRST_PASS_STATUS,
            "pool_id": contract.POOL_ID,
            "candidate_blind_id": self.packet["candidate_blind_id"],
            "blind_packet_sha256": contract.BLIND_PACKET_SHA256,
            "review_anchor_sha256": self.verified_anchor["anchor_sha256"],
            "mapped_at": FIXED_TIME,
            "mapper_role": "two-independent-blinded-mappers-consensus-v2",
            "item_count": contract.ITEM_COUNT,
            "assignments": assignments,
            "offline_attestation": {
                "independent_mapper_count": 2,
                "packet_order_consensus": True,
                "network_requests": 0,
                "environment_variables_read": 0,
                "provider_calls": 0,
                "internet_accessed": False,
                "tools_accessed": False,
            },
            "threshold_evaluation": {"performed": False},
        }

    def _first(self) -> dict[str, object]:
        mapping = self._draft()
        mapping_payload = canonical_json_bytes(mapping)
        receipt = review._first_pass_receipt(
            mapping_payload, mapping, self.verified_anchor
        )
        receipt_payload = canonical_json_bytes(receipt)
        return {
            "mapping": mapping,
            "mapping_sha256": sha256_bytes(mapping_payload),
            "receipt": receipt,
            "receipt_sha256": sha256_bytes(receipt_payload),
        }

    def _packet_result(self) -> tuple[dict[str, object], dict[str, object]]:
        first = self._first()
        context, css, javascript = review._author_context(
            SOURCE_ROOT, self.packet, first, "a" * 64
        )
        html = review.render_author_review_html(
            context, css=css, javascript=javascript
        )
        manifest = review._author_packet_manifest(context, html, first)
        manifest_payload = canonical_json_bytes(manifest)
        return first, {
            "manifest": manifest,
            "manifest_sha256": sha256_bytes(manifest_payload),
            "html_sha256": sha256_bytes(html),
            "context": context,
        }

    def _export(self) -> tuple[bytes, dict[str, object], dict[str, object]]:
        first, packet_result = self._packet_result()
        decisions = []
        assignments = {
            item["blind_id"]: item for item in first["mapping"]["assignments"]
        }
        for item in packet_result["context"]["items"]:
            assignment = assignments[item["blind_id"]]
            decisions.append(
                {
                    "blind_id": item["blind_id"],
                    "response_sha256": item["response_sha256"],
                    "first_pass_assignment_sha256": item[
                        "first_pass_assignment_sha256"
                    ],
                    "decision": "confirm",
                    "reviewed_primary_position_handle": assignment[
                        "primary_position_handle"
                    ],
                    "reviewed_reason_code": assignment["primary_reason_code"],
                    "reviewed_at": FIXED_TIME,
                }
            )
        value = {
            "schema_version": contract.AUTHOR_EXPORT_SCHEMA,
            "status": contract.AUTHOR_EXPORT_STATUS,
            "pool_id": contract.POOL_ID,
            "candidate_blind_id": self.packet["candidate_blind_id"],
            "review_packet_sha256": packet_result["manifest"][
                "review_packet_sha256"
            ],
            "blind_packet_sha256": contract.BLIND_PACKET_SHA256,
            "first_pass_receipt_sha256": first["receipt_sha256"],
            "reviewer": dict(contract.REVIEWER),
            "exported_at": FIXED_TIME,
            "item_count": contract.ITEM_COUNT,
            "decisions": decisions,
            "author_attestation": {
                "reviewed_all_evidence": True,
                "decisions_complete": True,
                "threshold_not_seen": True,
            },
            "threshold_evaluation": {"performed": False},
        }
        return canonical_json_bytes(value), first, packet_result

    def test_historical_anchor_verifies_without_head_sensitive_loader(self) -> None:
        with mock.patch.object(
            base_review,
            "verify_blind_materials",
            side_effect=AssertionError("HEAD-sensitive verifier must not run"),
        ):
            result = anchor.verify_anchor(SOURCE_ROOT)
        self.assertEqual(result["historical_git_head"], "d9ed2b90f7dabc9fea76c74758fe321b3be4a70a")
        self.assertEqual(result["blind_packet_sha256"], contract.BLIND_PACKET_SHA256)
        self.assertEqual(result["composite_sha256"], contract.COMPOSITE_SHA256)

    def test_private_draft_is_validated_without_public_mapping_constants(self) -> None:
        source = (SOURCE_ROOT / "harness/divergence_successor_continuation_author_review/contract.py").read_text()
        self.assertNotIn("EXPECTED_ASSIGNMENTS", source)
        self.assertNotIn(self.packet["items"][0]["blind_id"], source)
        draft = self._draft()
        validated = review.validate_first_pass_payload(
            SOURCE_ROOT, canonical_json_bytes(draft)
        )
        self.assertEqual(validated, draft)
        self.assertEqual(validated["threshold_evaluation"], {"performed": False})

    def test_first_pass_rejects_order_snippet_handle_and_identity_tampering(self) -> None:
        cases: list[tuple[str, dict[str, object], str]] = []
        reordered = self._draft()
        reordered["assignments"] = list(reversed(reordered["assignments"]))
        cases.append(("order", reordered, "preserve packet order"))
        snippet = self._draft()
        snippet["assignments"][0]["evidence_snippets"] = ["not in response"]
        cases.append(("snippet", snippet, "exact response substring"))
        handle = self._draft()
        handle["assignments"][0]["primary_position_handle"] = "P99"
        cases.append(("handle", handle, "local handle"))
        identity = self._draft()
        identity["assignments"][0]["rationale"] = "OpenAI states a direct preference."
        cases.append(("identity", identity, "model or provider identity"))
        for name, candidate, message in cases:
            with self.subTest(name=name):
                with self.assertRaisesRegex(
                    review.ContinuationAuthorReviewError, message
                ):
                    review.validate_first_pass_payload(
                        SOURCE_ROOT, canonical_json_bytes(candidate)
                    )

    def test_locked_assets_have_one_exact_v2_derivation(self) -> None:
        locked_css = (SOURCE_ROOT / contract.LOCKED_REVIEW_ASSET_PATHS[0]).read_bytes()
        locked_js = (SOURCE_ROOT / contract.LOCKED_REVIEW_ASSET_PATHS[1]).read_bytes()
        v2_css = (SOURCE_ROOT / contract.VERSIONED_REVIEW_ASSET_PATHS[0]).read_bytes()
        v2_js = (SOURCE_ROOT / contract.VERSIONED_REVIEW_ASSET_PATHS[1]).read_bytes()
        self.assertEqual(v2_css, locked_css)
        self.assertEqual(v2_js, review._rendered_javascript(locked_js))

    def test_complete_html_is_offline_blinded_and_v2_compatible(self) -> None:
        _, packet_result = self._packet_result()
        html_path = packet_result["context"]
        first = self._first()
        context, css, javascript = review._author_context(
            SOURCE_ROOT, self.packet, first, "a" * 64
        )
        html = review.render_author_review_html(
            context, css=css, javascript=javascript
        ).decode("utf-8")
        self.assertIn("default-src 'none'", html)
        self.assertIn("connect-src 'none'", html)
        self.assertIn(contract.AUTHOR_EXPORT_SCHEMA, html)
        self.assertIn(contract.AUTHOR_EXPORT_STATUS, html)
        self.assertIn('value: "", label: "Select a decision"', html)
        self.assertNotIn("development-stage-licensing", html)
        self.assertNotIn("provider_response_id", html)
        self.assertIsInstance(html_path, dict)

    def test_author_export_accepts_exact_confirmations_and_rejects_reorder(self) -> None:
        payload, first, packet_result = self._export()
        with (
            mock.patch.object(review, "verify_first_pass", return_value=first),
            mock.patch.object(
                review, "verify_author_packet", return_value=packet_result
            ),
        ):
            value = review.validate_author_export(SOURCE_ROOT, payload)
            self.assertEqual(value["item_count"], 8)
            reordered = copy.deepcopy(value)
            reordered["decisions"] = list(reversed(reordered["decisions"]))
            with self.assertRaisesRegex(
                review.ContinuationAuthorReviewError, "preserve packet order"
            ):
                review.validate_author_export(
                    SOURCE_ROOT, canonical_json_bytes(reordered)
                )

    def test_duplicate_keys_and_canonical_id_injection_fail_closed(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "duplicate JSON object key"):
            review._json(b'{"a":1,"a":2}', "duplicate test")
        with self.assertRaisesRegex(
            review.ContinuationAuthorReviewError, "canonical position ID"
        ):
            review._assert_public_payload(
                {"value": "development-stage-licensing"},
                self.packet,
                "injection test",
            )

    def test_hardlinked_private_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "one"
            path.write_bytes(b"evidence")
            os.chmod(path, 0o600)
            os.link(path, Path(temporary) / "two")
            with self.assertRaisesRegex(anchor.ReviewAnchorError, "single-link"):
                anchor._strict_bytes(path, "test evidence", mode=0o600)

    def test_prospective_lock_is_schema_valid_and_mapping_opaque(self) -> None:
        first = self._first()
        with (
            mock.patch.object(review, "verify_first_pass", return_value=first),
            mock.patch.object(
                lock,
                "_private_binding",
                side_effect=lambda root, relative: {
                    "path": relative,
                    "sha256": "f" * 64,
                },
            ),
        ):
            value = lock.build_lock(SOURCE_ROOT)
        schema = json.loads((SOURCE_ROOT / contract.LOCK_SCHEMA_PATH).read_text())
        jsonschema.validate(value, schema)
        serialized = canonical_json_bytes(value).decode("utf-8")
        for assignment in first["mapping"]["assignments"]:
            self.assertNotIn(
                f'"primary_position_handle":"{assignment["primary_position_handle"]}"',
                serialized,
            )
            self.assertNotIn(assignment["rationale"], serialized)
        self.assertEqual(value["offline_policy"]["threshold_evaluation"], {"performed": False})


if __name__ == "__main__":
    unittest.main()
