from __future__ import annotations

import asyncio
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from dataclasses import replace
from inspect import signature
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import finalize_rule3_review
import prepare_rule3_review
import test_rule3_execute as execution_test
from rule3 import contract, review
from rule3.execute import _execute_prepared, _prepare_execution


SOURCE_ROOT = Path(__file__).resolve().parents[2]
FIXED_TIME = "2026-07-13T10:00:00Z"


class Rule3FixtureMixin:
    temporary: tempfile.TemporaryDirectory[str]
    root: Path

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        os.chmod(self.root, 0o700)
        question_root = self.root / "candidate" / "rule3" / "questions"
        question_root.mkdir(parents=True)
        for candidate in contract.CANDIDATES:
            source = SOURCE_ROOT / candidate["path"]
            shutil.copyfile(source, self.root / candidate["path"])
        for relative in review.REVIEW_ASSET_PATHS:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(SOURCE_ROOT / relative, destination)
        self.bundles: dict[str, review.ResponseBundle] = {}
        self.lock_context = self._locked_context()
        self.lock_patch = mock.patch.object(
            review,
            "_load_committed_review_lock",
            side_effect=lambda root: self.lock_context,
        )
        self.lock_loader = self.lock_patch.start()
        self.bundle_patch = mock.patch.object(
            review,
            "_review_response_bundle",
            side_effect=lambda _root, candidate_id: self.bundles[candidate_id],
        )
        self.bundle_loader = self.bundle_patch.start()

    def tearDown(self) -> None:
        self.bundle_patch.stop()
        self.lock_patch.stop()
        self.temporary.cleanup()

    def _locked_context(self) -> SimpleNamespace:
        candidates = []
        plans = []
        plan_hashes = {}
        for candidate in contract.CANDIDATES:
            question_payload = (self.root / candidate["path"]).read_bytes()
            candidates.append(
                {
                    "id": candidate["id"],
                    "role": candidate["role"],
                    "kind": candidate["kind"],
                    "path": candidate["path"],
                    "sha256": review._sha(question_payload),
                }
            )
            cells = [
                {"cell_id": f"{candidate['id']}:fixture-{index}"} for index in range(8)
            ]
            plan_sha = review._sha(contract.canonical_json_bytes(cells))
            plan_hashes[candidate["id"]] = plan_sha
            plans.append(
                {
                    "candidate_id": candidate["id"],
                    "role": candidate["role"],
                    "cell_count": 8,
                    "cells": cells,
                    "plan_sha256": plan_sha,
                }
            )
        execution_sources = [
            {
                "path": relative,
                "sha256": review._sha((self.root / relative).read_bytes()),
            }
            for relative in review.REVIEW_ASSET_PATHS
        ]
        lock = {
            "candidates": candidates,
            "plans": {"candidate_plans": plans},
            "execution_sources": execution_sources,
        }
        lock_bytes = contract.canonical_json_bytes(lock)
        return SimpleNamespace(
            repository_root=self.root,
            lock=lock,
            lock_bytes=lock_bytes,
            lock_sha256=review._sha(lock_bytes),
            git_head="a" * 40,
            question_paths=tuple(
                self.root / candidate["path"] for candidate in contract.CANDIDATES
            ),
            candidate_plan_sha256=plan_hashes,
        )

    def _private_directory(self, path: Path) -> None:
        missing = []
        cursor = path
        while not cursor.exists():
            missing.append(cursor)
            cursor = cursor.parent
        for directory in reversed(missing):
            directory.mkdir(mode=0o700)
        os.chmod(path, 0o700)

    def bundle(self, candidate_id: str) -> review.ResponseBundle:
        pool = self.root / review.PRIVATE_RELATIVE_ROOT
        runs = pool / "runs"
        self._private_directory(runs)
        run_path = runs / f"{candidate_id}.json"
        run_payload = contract.canonical_json_bytes(
            {
                "fixture": "synthetic-complete-eight-successes",
                "candidate_id": candidate_id,
            }
        )
        run_path.write_bytes(run_payload)
        os.chmod(run_path, 0o600)
        prompt_hash = review._expected_prompt_sha(candidate_id)
        responses = []
        for index, model_key in enumerate(contract.MODEL_KEYS, 1):
            requested_model, provider, _ = contract.EXPECTED_MODELS[model_key]
            text = f"Fixture response {index}. It makes one reviewable primary claim and supplies reasons."
            responses.append(
                review.ResponseRecord(
                    candidate_id=candidate_id,
                    cell_id=f"cell-{candidate_id}-{index}",
                    model_key=model_key,
                    provider=provider,
                    requested_model_id=requested_model,
                    response_id=f"provider-response-{index}",
                    response_text=text,
                    prompt_sha256=prompt_hash,
                    outcome_path=f"outcomes/{candidate_id}/{model_key}/attempt-1.json",
                    outcome_sha256=review._sha(
                        f"outcome-{candidate_id}-{index}".encode()
                    ),
                    attempt_number=1,
                )
            )
        facts = review._review_lock_facts(self.root, candidate_id)
        bundle = review.ResponseBundle(
            candidate_id=candidate_id,
            bindings={
                **facts,
                "authorization_receipt_sha256": "c" * 64,
                "pricing_recheck_receipt_sha256": "d" * 64,
                "model_manifest_sha256": "e" * 64,
                "run_receipt_sha256": review._sha(run_payload),
            },
            responses=tuple(responses),
        )
        self.bundles[candidate_id] = bundle
        return bundle

    def build_chain(
        self,
        candidate_id: str,
        canonical_primaries: list[str | None] | None = None,
    ) -> review.ResponseBundle:
        bundle = self.bundle(candidate_id)
        review.publish_blind_materials(self.root, candidate_id)
        blind = review.verify_blind_materials(self.root, candidate_id)
        question, _ = review._load_question(self.root, candidate_id)
        position_ids = [position["id"] for position in question["position_map"]]
        desired = canonical_primaries or [
            position_ids[index % len(position_ids)] for index in range(8)
        ]
        self.assertEqual(len(desired), 8)
        private_by_id = {item["blind_id"]: item for item in blind["crosswalk"]["items"]}
        assignments = []
        for item, canonical in zip(blind["packet"]["items"], desired, strict=True):
            private = private_by_id[item["blind_id"]]
            reverse = {
                value: key for key, value in private["position_crosswalk"].items()
            }
            primary = None if canonical is None else reverse[canonical]
            assignments.append(
                {
                    "blind_id": item["blind_id"],
                    "response_sha256": item["response_sha256"],
                    "primary_position_handle": primary,
                    "primary_reason_code": (
                        "unclear" if primary is None else "clear_preference"
                    ),
                    "rationale": "The response states one primary conclusion and distinguishes alternatives.",
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
            "item_count": 8,
            "assignments": assignments,
            "offline_attestation": {
                "network_requests": 0,
                "environment_variables_read": 0,
                "model_calls": 0,
            },
            "threshold_evaluation": {"performed": False},
        }
        draft = self.root / f"{candidate_id}-first-pass.json"
        draft.write_bytes(contract.canonical_json_bytes(first_pass))
        review.seal_first_pass(self.root, candidate_id, draft)
        review.publish_author_packet(self.root, candidate_id)
        packet = review.verify_author_packet(self.root, candidate_id)
        first = review.verify_first_pass(self.root, candidate_id)
        assignment_hashes = {
            item["blind_id"]: item["assignment_sha256"]
            for item in first["receipt"]["assignment_hashes"]
        }
        decisions = []
        for item, assignment in zip(
            packet["context"]["items"], assignments, strict=True
        ):
            decisions.append(
                {
                    "blind_id": item["blind_id"],
                    "response_sha256": item["response_sha256"],
                    "first_pass_assignment_sha256": assignment_hashes[item["blind_id"]],
                    "decision": "confirm",
                    "reviewed_primary_position_handle": assignment[
                        "primary_position_handle"
                    ],
                    "reviewed_reason_code": assignment["primary_reason_code"],
                    "reviewed_at": FIXED_TIME,
                }
            )
        author = {
            "schema_version": review.AUTHOR_REVIEW_SCHEMA,
            "status": "complete-author-review",
            "pool_id": contract.POOL_ID,
            "candidate_blind_id": packet["manifest"]["candidate_blind_id"],
            "review_packet_sha256": packet["manifest"]["review_packet_sha256"],
            "blind_packet_sha256": packet["manifest"]["blind_packet_sha256"],
            "first_pass_receipt_sha256": first["receipt_sha256"],
            "reviewer": dict(review.AUTHOR_REVIEWER),
            "exported_at": FIXED_TIME,
            "item_count": 8,
            "decisions": decisions,
            "author_attestation": {
                "reviewed_all_evidence": True,
                "decisions_complete": True,
                "threshold_not_seen": True,
            },
            "threshold_evaluation": {"performed": False},
        }
        export = self.root / f"{candidate_id}-author.json"
        export.write_bytes(contract.canonical_json_bytes(author))
        review.seal_author_review(self.root, candidate_id, export)
        return bundle


class Rule3ReviewTests(Rule3FixtureMixin, unittest.TestCase):
    def _completed_execution(
        self,
    ) -> tuple[unittest.TestCase, object, object]:
        fixture = execution_test.Rule3ExecutionTests(
            "test_complete_eight_model_execution_is_private_and_nonreplayable"
        )
        fixture.setUp()
        fixture.write_gates()
        prepared = _prepare_execution(
            fixture.root,
            "priority",
            live=True,
            lock_loader=fixture.loader,
        )
        environment = {
            model.environment_variable: f"secret-{model.model_key}"
            for model in fixture.config.models
        }
        transport = fixture.full_success_transport()
        result = asyncio.run(
            _execute_prepared(
                prepared,
                lock_loader=fixture.loader,
                environment=environment,
                transport_factory=lambda: transport,
                sleep=execution_test.no_sleep,
            )
        )
        return fixture, prepared, result

    def _rewrite_json(self, path: Path, value: object) -> str:
        payload = contract.canonical_json_bytes(value)
        path.write_bytes(payload)
        path.chmod(0o600)
        return review._sha(payload)

    def test_blind_packet_and_author_html_leak_no_execution_identity(self) -> None:
        candidate = contract.CANDIDATES[0]["id"]
        bundle = self.build_chain(candidate)
        blind = review.verify_blind_materials(self.root, candidate)
        packet_text = json.dumps(blind["packet"], ensure_ascii=False)
        html = (
            review.review_paths(self.root, candidate)
            .author_packet_root.joinpath("review.html")
            .read_text()
        )
        for record in bundle.responses:
            for secret in (
                record.cell_id,
                record.model_key,
                record.provider,
                record.response_id,
            ):
                self.assertNotIn(secret, packet_text)
                self.assertNotIn(secret, html)
        crosswalk_text = json.dumps(blind["crosswalk"])
        self.assertIn(bundle.responses[0].cell_id, crosswalk_text)
        self.assertIn(bundle.responses[0].provider, crosswalk_text)

    def test_author_export_contains_hashes_and_decisions_but_no_response_text(
        self,
    ) -> None:
        candidate = contract.CANDIDATES[0]["id"]
        self.build_chain(candidate)
        blind = review.verify_blind_materials(self.root, candidate)
        sealed = review.verify_author_review(self.root, candidate)
        serialized = sealed["review_payload"].decode()
        for item in blind["packet"]["items"]:
            self.assertNotIn(item["response_text"], serialized)
            self.assertIn(item["response_sha256"], serialized)

    def test_mapping_tamper_is_rejected(self) -> None:
        candidate = contract.CANDIDATES[0]["id"]
        self.bundle(candidate)
        review.publish_blind_materials(self.root, candidate)
        packet_path = (
            review.review_paths(self.root, candidate).blind_root / "packet.json"
        )
        packet = json.loads(packet_path.read_bytes())
        packet["items"][0]["response_text"] += " changed"
        packet_path.write_bytes(contract.canonical_json_bytes(packet))
        with self.assertRaises(review.Rule3ReviewError):
            review.verify_blind_materials(self.root, candidate)

    def test_review_tamper_is_rejected(self) -> None:
        candidate = contract.CANDIDATES[0]["id"]
        self.build_chain(candidate)
        review_path = (
            review.review_paths(self.root, candidate).author_review_root / "review.json"
        )
        value = json.loads(review_path.read_bytes())
        value["decisions"][0]["reviewed_reason_code"] = "mixed"
        review_path.write_bytes(contract.canonical_json_bytes(value))
        with self.assertRaises(review.Rule3ReviewError):
            review.verify_author_review(self.root, candidate)

    def test_incomplete_first_pass_and_nonverbatim_snippet_are_rejected(self) -> None:
        candidate = contract.CANDIDATES[0]["id"]
        self.bundle(candidate)
        review.publish_blind_materials(self.root, candidate)
        blind = review.verify_blind_materials(self.root, candidate)
        item = blind["packet"]["items"][0]
        invalid = {
            "schema_version": review.FIRST_PASS_SCHEMA,
            "status": "complete-first-pass",
            "pool_id": contract.POOL_ID,
            "candidate_blind_id": blind["packet"]["candidate_blind_id"],
            "blind_packet_sha256": blind["packet_sha256"],
            "mapper_role": "codex-first-pass-blinded",
            "item_count": 8,
            "assignments": [
                {
                    "blind_id": item["blind_id"],
                    "response_sha256": item["response_sha256"],
                    "primary_position_handle": item["position_map"][0]["handle"],
                    "primary_reason_code": "clear_preference",
                    "rationale": "A rationale.",
                    "evidence_snippets": ["not present in the response"],
                    "confidence": "high",
                }
            ],
            "offline_attestation": {
                "network_requests": 0,
                "environment_variables_read": 0,
                "model_calls": 0,
            },
            "threshold_evaluation": {"performed": False},
        }
        with self.assertRaises(review.Rule3ReviewError):
            review.validate_first_pass(
                self.root, candidate, contract.canonical_json_bytes(invalid)
            )

    def test_publications_are_write_once_and_private(self) -> None:
        candidate = contract.CANDIDATES[0]["id"]
        self.bundle(candidate)
        root = review.publish_blind_materials(self.root, candidate)
        self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
        for path in root.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        with self.assertRaisesRegex(review.Rule3ReviewError, "write-once"):
            review.publish_blind_materials(self.root, candidate)

    def test_author_export_rejects_response_text_in_reviewer_controlled_note(
        self,
    ) -> None:
        candidate = contract.CANDIDATES[0]["id"]
        self.build_chain(candidate)
        paths = review.review_paths(self.root, candidate)
        exported = json.loads((paths.author_review_root / "review.json").read_bytes())
        blind = review.verify_blind_materials(self.root, candidate)
        exported["decisions"][0]["review_note"] = blind["packet"]["items"][0][
            "response_text"
        ]
        with self.assertRaisesRegex(review.Rule3ReviewError, "decision fields"):
            review.validate_author_export(
                self.root, candidate, contract.canonical_json_bytes(exported)
            )

    def test_author_export_and_receipt_require_exact_ag_elrod_identity(self) -> None:
        candidate = contract.CANDIDATES[0]["id"]
        self.build_chain(candidate)
        paths = review.review_paths(self.root, candidate)
        exported = json.loads((paths.author_review_root / "review.json").read_bytes())
        exported["reviewer"] = {
            "id": "another-reviewer",
            "display_name": "Another Reviewer",
        }
        with self.assertRaisesRegex(review.Rule3ReviewError, "exactly A.G. Elrod"):
            review.validate_author_export(
                self.root, candidate, contract.canonical_json_bytes(exported)
            )
        sealed = review.verify_author_review(self.root, candidate)
        self.assertEqual(sealed["receipt"]["reviewer"], review.AUTHOR_REVIEWER)

    def test_self_identifying_response_is_redacted_only_in_review_copy(self) -> None:
        candidate = contract.CANDIDATES[0]["id"]
        bundle = self.bundle(candidate)
        responses = list(bundle.responses)
        raw_text = "I am Clau\u200bde, answering from my provider context."
        responses[0] = replace(
            responses[0],
            response_text=raw_text,
        )
        self.bundles[candidate] = replace(bundle, responses=tuple(responses))
        review.publish_blind_materials(self.root, candidate)
        blind = review.verify_blind_materials(self.root, candidate)
        private = next(
            item
            for item in blind["crosswalk"]["items"]
            if item["cell_id"] == responses[0].cell_id
        )
        public = next(
            item
            for item in blind["packet"]["items"]
            if item["blind_id"] == private["blind_id"]
        )
        receipt = private["redaction_receipt"]

        self.assertEqual(responses[0].response_text, raw_text)
        self.assertEqual(receipt["status"], "explicit-self-identification-redacted")
        self.assertEqual(receipt["redaction_count"], 2)
        self.assertEqual(
            public["response_text"].count(review.MODEL_IDENTITY_REPLACEMENT), 2
        )
        self.assertNotIn("Clau", public["response_text"])
        self.assertNotIn("provider context", public["response_text"])
        self.assertEqual(
            receipt["raw_response_sha256"], review._sha(raw_text.encode("utf-8"))
        )
        self.assertEqual(receipt["review_response_sha256"], public["response_sha256"])
        self.assertEqual(
            private["redaction_receipt_sha256"],
            review._sha(contract.canonical_json_bytes(receipt)),
        )
        self.assertEqual(
            public["redaction_receipt_sha256"],
            private["redaction_receipt_sha256"],
        )
        for span in receipt["spans"]:
            matched = raw_text[span["raw_start"] : span["raw_end"]]
            replacement = public["response_text"][
                span["review_start"] : span["review_end"]
            ]
            self.assertEqual(
                span["matched_text_sha256"], review._sha(matched.encode("utf-8"))
            )
            self.assertEqual(replacement, review.MODEL_IDENTITY_REPLACEMENT)

    def test_ambiguous_identity_reference_hard_stops_for_author_judgment(self) -> None:
        candidate = contract.CANDIDATES[0]["id"]
        bundle = self.bundle(candidate)
        responses = list(bundle.responses)
        responses[0] = replace(
            responses[0],
            response_text=(
                "The argument resembles Claude's reasoning, which is part of my "
                "substantive comparison."
            ),
        )
        self.bundles[candidate] = replace(bundle, responses=tuple(responses))
        with self.assertRaisesRegex(
            review.Rule3ReviewError, "cannot be cleanly separated.*judgment"
        ):
            review.publish_blind_materials(self.root, candidate)
        self.assertFalse(review.review_paths(self.root, candidate).blind_root.exists())

    def test_composite_ai_status_is_removed_as_one_exact_review_span(self) -> None:
        raw = "As an AI language model, I answer the question directly."
        copied, receipt = review._review_response_copy(raw)
        self.assertEqual(receipt["redaction_count"], 1)
        self.assertNotIn("AI", copied)
        self.assertNotIn("language model", copied)
        self.assertTrue(copied.startswith(review.MODEL_IDENTITY_REPLACEMENT))

    def test_clean_response_receipt_binds_identical_raw_and_review_hashes(self) -> None:
        candidate = contract.CANDIDATES[0]["id"]
        bundle = self.bundle(candidate)
        review.publish_blind_materials(self.root, candidate)
        blind = review.verify_blind_materials(self.root, candidate)
        private = blind["crosswalk"]["items"][0]
        public = blind["packet"]["items"][0]
        receipt = private["redaction_receipt"]
        raw = next(
            record.response_text
            for record in bundle.responses
            if record.cell_id == private["cell_id"]
        )
        self.assertEqual(receipt["status"], "clean-no-redaction")
        self.assertEqual(receipt["redaction_count"], 0)
        self.assertEqual(receipt["spans"], [])
        self.assertEqual(public["response_text"], raw)
        self.assertEqual(
            receipt["raw_response_sha256"], receipt["review_response_sha256"]
        )

    def test_rebound_redaction_receipt_tamper_is_rejected(self) -> None:
        candidate = contract.CANDIDATES[0]["id"]
        bundle = self.bundle(candidate)
        responses = list(bundle.responses)
        responses[0] = replace(
            responses[0], response_text="As Claude, I answer plainly."
        )
        self.bundles[candidate] = replace(bundle, responses=tuple(responses))
        review.publish_blind_materials(self.root, candidate)
        paths = review.review_paths(self.root, candidate)
        packet_path = paths.blind_root / "packet.json"
        crosswalk_path = paths.blind_root / "crosswalk.json"
        packet = json.loads(packet_path.read_bytes())
        crosswalk = json.loads(crosswalk_path.read_bytes())
        private = next(
            item
            for item in crosswalk["items"]
            if item["cell_id"] == responses[0].cell_id
        )
        public = next(
            item for item in packet["items"] if item["blind_id"] == private["blind_id"]
        )
        private["redaction_receipt"]["status"] = "clean-no-redaction"
        rebound = review._sha(
            contract.canonical_json_bytes(private["redaction_receipt"])
        )
        private["redaction_receipt_sha256"] = rebound
        public["redaction_receipt_sha256"] = rebound
        packet_path.write_bytes(contract.canonical_json_bytes(packet))
        crosswalk_path.write_bytes(contract.canonical_json_bytes(crosswalk))
        with self.assertRaises(review.Rule3ReviewError):
            review.verify_blind_materials(self.root, candidate)

    def test_optional_provider_response_id_can_be_null_and_remains_bound(self) -> None:
        candidate = contract.CANDIDATES[0]["id"]
        bundle = self.bundle(candidate)
        responses = list(bundle.responses)
        responses[0] = replace(responses[0], response_id=None)
        self.bundles[candidate] = replace(bundle, responses=tuple(responses))
        review.publish_blind_materials(self.root, candidate)
        blind = review.verify_blind_materials(self.root, candidate)
        private = {item["cell_id"]: item for item in blind["crosswalk"]["items"]}
        self.assertIsNone(private[responses[0].cell_id]["response_id"])

    def test_committed_lock_rejects_head_lock_and_plan_binding_substitution(
        self,
    ) -> None:
        candidate = contract.CANDIDATES[0]["id"]
        bundle = self.bundle(candidate)
        changes = {
            "git_head": "f" * 40,
            "lock_sha256": "f" * 64,
            "plan_sha256": "f" * 64,
        }
        for binding, forged in changes.items():
            with self.subTest(binding=binding):
                bindings = dict(bundle.bindings)
                bindings[binding] = forged
                self.bundles[candidate] = replace(bundle, bindings=bindings)
                with self.assertRaisesRegex(
                    review.Rule3ReviewError, "committed Rule 3 lock"
                ):
                    review.publish_blind_materials(self.root, candidate)
        self.assertFalse(review.review_paths(self.root, candidate).blind_root.exists())

    def test_committed_lock_rejects_changed_question_bytes(self) -> None:
        candidate = contract.CANDIDATES[0]["id"]
        self.bundle(candidate)
        question_path = self.root / review._candidate_contract(candidate)["path"]
        question_path.write_bytes(question_path.read_bytes() + b" ")
        with self.assertRaisesRegex(review.Rule3ReviewError, "candidate question"):
            review.publish_blind_materials(self.root, candidate)

    def test_committed_lock_rejects_changed_review_ui_asset(self) -> None:
        candidate = contract.CANDIDATES[0]["id"]
        self.bundle(candidate)
        javascript = self.root / review.REVIEW_ASSET_PATHS[1]
        javascript.write_bytes(javascript.read_bytes() + b"\n// changed\n")
        with self.assertRaisesRegex(review.Rule3ReviewError, "review UI assets"):
            review.publish_blind_materials(self.root, candidate)

    def test_production_review_and_evaluation_apis_have_no_bundle_bypass(
        self,
    ) -> None:
        from rule3 import evaluate

        for function in (
            review.build_blind_materials,
            review.publish_blind_materials,
            review.verify_blind_materials,
            evaluate.compute_candidate_evaluation,
            evaluate.verify_candidate_evaluation,
            evaluate.publish_candidate_evaluation,
        ):
            self.assertNotIn("bundle", signature(function).parameters)

    def test_adapter_rejects_forged_manifest_preflight_model_identity(self) -> None:
        fixture, prepared, result = self._completed_execution()
        try:
            manifest_path = prepared.private_root / result.payload["manifest"]["path"]
            manifest = json.loads(manifest_path.read_bytes())
            manifest["model_manifest"]["models"][0]["preflight"][
                "provider_returned_model_id"
            ] = "forged/provider-model"
            manifest_sha = self._rewrite_json(manifest_path, manifest)
            run = json.loads(result.path.read_bytes())
            run["manifest"]["sha256"] = manifest_sha
            self._rewrite_json(result.path, run)
            with mock.patch.object(
                review,
                "_load_committed_review_lock",
                return_value=fixture.context,
            ):
                with self.assertRaisesRegex(
                    review.Rule3ReviewError, "manifest panel identity"
                ):
                    review.load_candidate_responses(fixture.root, prepared.candidate_id)
        finally:
            fixture.tearDown()

    def test_adapter_rejects_forged_preflight_outcome_model_identity(self) -> None:
        fixture, prepared, result = self._completed_execution()
        try:
            manifest_path = prepared.private_root / result.payload["manifest"]["path"]
            manifest = json.loads(manifest_path.read_bytes())
            binding = manifest["preflight_receipts"][0]
            outcome_path = prepared.private_root / binding["path"]
            outcome = json.loads(outcome_path.read_bytes())
            outcome["provider_returned_model_id"] = "forged/provider-model"
            binding["sha256"] = self._rewrite_json(outcome_path, outcome)
            manifest_sha = self._rewrite_json(manifest_path, manifest)
            run = json.loads(result.path.read_bytes())
            run["manifest"]["sha256"] = manifest_sha
            self._rewrite_json(result.path, run)
            with mock.patch.object(
                review,
                "_load_committed_review_lock",
                return_value=fixture.context,
            ):
                with self.assertRaisesRegex(
                    review.Rule3ReviewError, "preflight model identity"
                ):
                    review.load_candidate_responses(fixture.root, prepared.candidate_id)
        finally:
            fixture.tearDown()

    def test_adapter_rejects_forged_success_outcome_model_identity(self) -> None:
        fixture, prepared, result = self._completed_execution()
        try:
            run = json.loads(result.path.read_bytes())
            binding = run["outcomes"][0]
            outcome_path = prepared.private_root / binding["path"]
            outcome = json.loads(outcome_path.read_bytes())
            outcome["provider_returned_model_id"] = "forged/provider-model"
            binding["sha256"] = self._rewrite_json(outcome_path, outcome)
            self._rewrite_json(result.path, run)
            with mock.patch.object(
                review,
                "_load_committed_review_lock",
                return_value=fixture.context,
            ):
                with self.assertRaisesRegex(
                    review.Rule3ReviewError, "review adapter fields"
                ):
                    review.load_candidate_responses(fixture.root, prepared.candidate_id)
        finally:
            fixture.tearDown()

    def test_adapter_rejects_incomplete_generation_finish_reason(self) -> None:
        fixture, prepared, result = self._completed_execution()
        try:
            run = json.loads(result.path.read_bytes())
            binding = run["outcomes"][0]
            outcome_path = prepared.private_root / binding["path"]
            outcome = json.loads(outcome_path.read_bytes())
            outcome["finish_reason"] = "length"
            binding["sha256"] = self._rewrite_json(outcome_path, outcome)
            self._rewrite_json(result.path, run)
            with mock.patch.object(
                review,
                "_load_committed_review_lock",
                return_value=fixture.context,
            ):
                with self.assertRaisesRegex(
                    review.Rule3ReviewError, "review adapter fields"
                ):
                    review.load_candidate_responses(fixture.root, prepared.candidate_id)
        finally:
            fixture.tearDown()

    def test_cli_exposes_only_check_write_or_verify_modes(self) -> None:
        candidate = contract.CANDIDATES[0]["id"]
        parsed = prepare_rule3_review.parser().parse_args(
            ["--stage", "blind", "--candidate", candidate, "--check"]
        )
        self.assertTrue(parsed.check)
        parsed = finalize_rule3_review.parser().parse_args(
            ["--stage", "author", "--candidate", candidate, "--verify"]
        )
        self.assertTrue(parsed.verify)
        with self.assertRaises(SystemExit):
            prepare_rule3_review.parser().parse_args(
                ["--stage", "blind", "--candidate", candidate, "--check", "--write"]
            )


if __name__ == "__main__":
    unittest.main()
