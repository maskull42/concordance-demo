from __future__ import annotations

import hashlib
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from divergence_successor import contract, review


SOURCE_ROOT = Path(__file__).resolve().parents[2]
FIXED_TIME = "2026-07-14T12:00:00Z"
RULE3_SEALED_HASHES = {
    "harness/rule3/__init__.py": (
        "61700c646ab70275e8845beba22baf60af5c24d508fc89f3ff8e683a7548d253"
    ),
    "harness/rule3/review.py": (
        "0aed54f76c1a99ec6a10311415c0e45ecb1f9acfa9ddc1b1b86b13cf8b208a01"
    ),
    "harness/rule3/review_assets/review.css": (
        "728f25df5e61d7708a0f85b7e6accbc42304f9e9904976e0099ea3b2bdc5600b"
    ),
    "harness/rule3/review_assets/review.js": (
        "f0bbed8d7438a6b47c79a02ef1fb6105b4e2b3ff739a716aef6d81c07a531c59"
    ),
}


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class DivergenceSuccessorReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        os.chmod(self.root, 0o700)
        question_path = self.root / contract.QUESTION_PATH
        question_path.parent.mkdir(parents=True)
        question = {
            "id": contract.CANDIDATE_ID,
            "prompt_variants": [
                {"id": "default", "user_prompt": contract.CANDIDATE_PROMPT}
            ],
            "position_map": [
                {
                    "id": "development-stage-licensing",
                    "label": "License before a covered training run",
                    "summary": "Prior permission begins before covered training.",
                    "attestation": "The label and summary are source-bound.",
                    "sources": [],
                },
                {
                    "id": "deployment-release-licensing",
                    "label": "License only before broad deployment or release",
                    "summary": "Training remains ungated; deployment requires permission.",
                    "attestation": "The label and summary are source-bound.",
                    "sources": [],
                },
                {
                    "id": "binding-frontier-supervision",
                    "label": "Binding developer supervision without licensing",
                    "summary": "Duties bind frontier developers without prior permission.",
                    "attestation": "The label and summary are source-bound.",
                    "sources": [],
                },
                {
                    "id": "use-centered-general-law",
                    "label": "Downstream high-risk-use and general-law regulation",
                    "summary": "Regulation centers on uses, liability, and general law.",
                    "attestation": "The label and summary are source-bound.",
                    "sources": [],
                },
            ],
        }
        question_path.write_bytes(contract.canonical_json_bytes(question))
        for relative in review.REVIEW_ASSET_PATHS:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(SOURCE_ROOT / relative, destination)

        assets = [
            {"path": relative, "sha256": digest((self.root / relative).read_bytes())}
            for relative in review.REVIEW_ASSET_PATHS
        ]
        question_sha = digest(question_path.read_bytes())
        self.lock_facts = {
            "git_head": "a" * 40,
            "lock_sha256": "b" * 64,
            "question_sha256": question_sha,
            "plan_sha256": "c" * 64,
            "review_assets_sha256": digest(contract.canonical_json_bytes(assets)),
        }
        bindings = {
            **self.lock_facts,
            "authorization_receipt_sha256": "d" * 64,
            "pricing_recheck_receipt_sha256": "e" * 64,
            "model_manifest_sha256": "f" * 64,
            "run_receipt_sha256": "1" * 64,
        }
        prompt_sha = review._expected_prompt_sha(contract.CANDIDATE_ID)
        responses = []
        for index, model_key in enumerate(contract.MODEL_KEYS, 1):
            requested_model, provider, _ = contract.EXPECTED_MODELS[model_key]
            responses.append(
                review.ResponseRecord(
                    candidate_id=contract.CANDIDATE_ID,
                    cell_id=f"successor-cell-{index}",
                    model_key=model_key,
                    provider=provider,
                    requested_model_id=requested_model,
                    response_id=f"private-provider-response-{index}",
                    response_text=(
                        f"Response {index} selects one primary legal architecture "
                        "and gives a concrete public-law rationale."
                    ),
                    prompt_sha256=prompt_sha,
                    outcome_path=f"outcomes/{model_key}/attempt-1.json",
                    outcome_sha256=digest(f"outcome-{index}".encode()),
                    attempt_number=1,
                )
            )
        self.bundle = review.ResponseBundle(
            candidate_id=contract.CANDIDATE_ID,
            bindings=bindings,
            responses=tuple(responses),
        )
        self.fact_patch = mock.patch.object(
            review, "_review_lock_facts", return_value=self.lock_facts
        )
        self.bundle_patch = mock.patch.object(
            review, "_review_response_bundle", return_value=self.bundle
        )
        self.fact_patch.start()
        self.bundle_patch.start()

    def tearDown(self) -> None:
        self.bundle_patch.stop()
        self.fact_patch.stop()
        self.temporary.cleanup()

    def _publish_first_pass(self) -> dict[str, object]:
        review.publish_blind_materials(self.root, contract.CANDIDATE_ID)
        blind = review.verify_blind_materials(self.root, contract.CANDIDATE_ID)
        assignments = []
        for item in blind["packet"]["items"]:
            primary = item["position_map"][1]["handle"]
            assignments.append(
                {
                    "blind_id": item["blind_id"],
                    "response_sha256": item["response_sha256"],
                    "primary_position_handle": primary,
                    "primary_reason_code": "clear_preference",
                    "rationale": "The response selects this local position directly.",
                    "evidence_snippets": [item["response_text"]],
                    "confidence": "high",
                }
            )
        first_pass = {
            "schema_version": review.FIRST_PASS_SCHEMA,
            "status": "complete-first-pass",
            "pool_id": contract.POOL_ID,
            "candidate_blind_id": blind["packet"]["candidate_blind_id"],
            "blind_packet_sha256": blind["packet_sha256"],
            "mapper_role": "codex-first-pass-blinded",
            "item_count": contract.REQUIRED_COMPLETED_RESPONSES,
            "assignments": assignments,
            "offline_attestation": {
                "network_requests": 0,
                "environment_variables_read": 0,
                "model_calls": 0,
            },
            "threshold_evaluation": {"performed": False},
        }
        draft = self.root / "first-pass.json"
        draft.write_bytes(contract.canonical_json_bytes(first_pass))
        review.seal_first_pass(self.root, contract.CANDIDATE_ID, draft)
        return blind

    def _author_export(self, packet: dict[str, object]) -> bytes:
        first = review.verify_first_pass(self.root, contract.CANDIDATE_ID)
        context = packet["context"]
        assignments = {
            item["blind_id"]: item for item in first["mapping"]["assignments"]
        }
        decisions = []
        for item in context["items"]:
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
            "schema_version": review.AUTHOR_REVIEW_SCHEMA,
            "status": "complete-author-review",
            "pool_id": contract.POOL_ID,
            "candidate_blind_id": packet["manifest"]["candidate_blind_id"],
            "review_packet_sha256": packet["manifest"]["review_packet_sha256"],
            "blind_packet_sha256": packet["manifest"]["blind_packet_sha256"],
            "first_pass_receipt_sha256": first["receipt_sha256"],
            "reviewer": dict(review.AUTHOR_REVIEWER),
            "exported_at": FIXED_TIME,
            "item_count": contract.REQUIRED_COMPLETED_RESPONSES,
            "decisions": decisions,
            "author_attestation": {
                "reviewed_all_evidence": True,
                "decisions_complete": True,
                "threshold_not_seen": True,
            },
            "threshold_evaluation": {"performed": False},
        }
        return contract.canonical_json_bytes(value)

    def test_full_successor_review_lifecycle_is_private_and_handle_only(self) -> None:
        blind = self._publish_first_pass()
        review.publish_author_packet(self.root, contract.CANDIDATE_ID)
        packet = review.verify_author_packet(self.root, contract.CANDIDATE_ID)
        html = (
            review.review_paths(self.root, contract.CANDIDATE_ID)
            .author_packet_root.joinpath("review.html")
            .read_text()
        )
        self.assertIn("default-src 'none'", html)
        self.assertIn("connect-src 'none'", html)
        self.assertIn('id="divergence-successor-evidence"', html)
        self.assertNotIn("private-provider-response", html)

        export_payload = self._author_export(packet)
        exported = review.validate_author_export(
            self.root, contract.CANDIDATE_ID, export_payload
        )
        serialized = export_payload.decode()
        for decision in exported["decisions"]:
            handle = decision["reviewed_primary_position_handle"]
            self.assertRegex(handle, r"^P[1-9][0-9]*$")
        for canonical_id in (
            "development-stage-licensing",
            "deployment-release-licensing",
            "binding-frontier-supervision",
            "use-centered-general-law",
        ):
            self.assertNotIn(canonical_id, serialized)
        for item in blind["packet"]["items"]:
            self.assertTrue(all("id" not in position for position in item["position_map"]))

        draft = self.root / "author-review.json"
        draft.write_bytes(export_payload)
        review.seal_author_review(self.root, contract.CANDIDATE_ID, draft)
        sealed = review.verify_author_review(self.root, contract.CANDIDATE_ID)
        self.assertEqual(sealed["review"], exported)

    def test_successor_module_preserves_the_sealed_rule3_reviewer_bytes(self) -> None:
        for relative, expected in RULE3_SEALED_HASHES.items():
            with self.subTest(relative=relative):
                self.assertEqual(digest((SOURCE_ROOT / relative).read_bytes()), expected)

    def test_public_surface_matches_the_review_lifecycle(self) -> None:
        for name in (
            "build_blind_materials",
            "publish_blind_materials",
            "verify_blind_materials",
            "seal_first_pass",
            "verify_first_pass",
            "render_author_review_html",
            "publish_author_packet",
            "verify_author_packet",
            "validate_author_export",
            "seal_author_review",
            "verify_author_review",
        ):
            with self.subTest(name=name):
                self.assertTrue(callable(getattr(review, name)))


if __name__ == "__main__":
    unittest.main()
