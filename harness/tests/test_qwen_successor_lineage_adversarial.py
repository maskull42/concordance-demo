from __future__ import annotations

import asyncio
import copy
import json
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from concordance_harness.providers import ProviderAdapter, ProviderError  # noqa: E402
from concordance_harness.util import (  # noqa: E402
    canonical_json_bytes,
    prompt_sha256,
    sha256_bytes,
)
from concordance_recovery import execute as first_execute  # noqa: E402
from concordance_recovery.journal import (  # noqa: E402
    JournalRecord,
    RecoveryJournalError,
    write_record,
)
from qwen_successor import contract, execute  # noqa: E402
from qwen_successor import parent as parent_module  # noqa: E402
from qwen_successor.authorization import ReceiptBinding  # noqa: E402
from qwen_successor.parent import ParentEvidence  # noqa: E402
from rule3.execute import reserved_microdollars  # noqa: E402


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
HEAD = "a" * 40
LOCK_SHA = "b" * 64
AUTH_SHA = "c" * 64
PRICING_SHA = "d" * 64
T0 = "2026-07-13T10:00:00+00:00"
T1 = "2026-07-13T11:00:00+00:00"
QWEN_ATTEMPT_ONE_REQUEST_BODY_SHA256 = (
    "ecd765d853cbb6a02c61d1c2c36de15afcdfd1d183d1bb05e83b37ebe5919db2"
)


def record(path: Path, payload: dict, seed: int) -> JournalRecord:
    return JournalRecord(path=path, payload=payload, sha256=f"{seed:064x}")


def make_exact_private_tree(root: Path, relative_files: set[str]) -> None:
    root.mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    directories: set[str] = set()
    for relative in relative_files:
        parent = PurePosixPath(relative).parent
        while parent != PurePosixPath("."):
            directories.add(parent.as_posix())
            parent = parent.parent
    for relative in contract.FIRST_EXTRA_EMPTY_DIRECTORIES:
        parent_module._add_directory_with_parents(directories, relative)
    for relative in sorted(directories, key=lambda value: (value.count("/"), value)):
        path = root / relative
        path.mkdir(exist_ok=True)
        path.chmod(0o700)
    for relative in relative_files:
        path = root / relative
        path.write_bytes(b"{}\n")
        path.chmod(0o600)


class QwenSuccessorLineageFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # This reads only committed public configuration, locks, prompts, and source
        # bindings. It does not read either private response lane.
        cls.first = first_execute.prepare_recovery(
            REPOSITORY_ROOT, require_committed=False
        )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        target = tuple(
            call
            for call in self.first.full_plan
            if call.model.model_key in contract.TARGET_MODEL_KEYS
        )
        cells = [
            {
                "model_key": call.model.model_key,
                "cell_id": call.cell_id,
                "requested_model_id": call.model.requested_model_id,
                "provider": call.model.provider,
                "route": call.model.route,
                "environment_variable": call.model.environment_variable,
                "fallback_allowed": False,
                "reserved_cost_microdollars_per_post": reserved_microdollars(call),
            }
            for call in target
        ]
        context = SimpleNamespace(
            repository_root=self.root,
            lock={
                "target_plan": {
                    "cells": cells,
                    "plan_sha256": "e" * 64,
                    "qwen_openrouter_fallback": copy.deepcopy(contract.QWEN_OPENROUTER),
                }
            },
            lock_sha256=LOCK_SHA,
            git_head=HEAD,
        )
        with (
            mock.patch.object(execute, "load_lock", return_value=context),
            mock.patch.object(
                execute.first_execute,
                "prepare_recovery",
                return_value=self.first,
            ),
        ):
            self.prepared = execute.prepare_successor(
                self.root, require_committed=False
            )
        self.authority = execute.Authority(
            authorization=ReceiptBinding(
                self.prepared.paths.private_root / "paid-authorization.json",
                {},
                AUTH_SHA,
            ),
            pricing=ReceiptBinding(
                self.prepared.paths.private_root / "pricing-recheck.json",
                {},
                PRICING_SHA,
            ),
        )
        self.qwen = self.prepared.target_by_key["qwen"]
        self.openrouter_route_key = execute._route_key(self.prepared.fallback_call)
        self.parent = self._parent()
        self.manifest = record(
            self.prepared.paths.manifest,
            {"status": "synthetic-successor-manifest"},
            20,
        )
        self.deepinfra_preflight = record(
            self.prepared.paths.preflight_outcome("qwen", 1),
            {"status": "success", "route_key": "qwen", "model_key": "qwen"},
            21,
        )
        self.openrouter_preflight = record(
            self.prepared.paths.preflight_outcome(self.openrouter_route_key, 1),
            {
                "status": "success",
                "route_key": self.openrouter_route_key,
                "model_key": "qwen",
            },
            22,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _parent(self) -> ParentEvidence:
        rule3_root = self.root / "synthetic-rule3-parent"
        first_root = self.root / "synthetic-first-parent"
        messages = self.qwen.answer_messages()
        request = ProviderAdapter(
            self.qwen.model, execute._NeverTransport()
        ).build_generation_request("redacted-offline-secret", messages)
        stranded_payload = {
            "model_key": "qwen",
            "semantic_attempt_number": 1,
            "prompt_sha256": prompt_sha256(messages),
            "messages_sha256": sha256_bytes(canonical_json_bytes(messages)),
            "requested_params_sha256": sha256_bytes(
                canonical_json_bytes(self.qwen.model.requested_params_receipt())
            ),
            "request_json_body_sha256": sha256_bytes(
                json.dumps(request.json_body, ensure_ascii=False).encode("utf-8")
            ),
            "reserved_cost_microdollars": contract.RESERVED_PER_POST["qwen"],
        }
        rule3 = SimpleNamespace(
            private_root=rule3_root,
            preserved_outcomes=(
                record(
                    rule3_root / "generation/outcomes/gemini/attempt-1.json",
                    {"status": "success", "model_key": "gemini"},
                    1,
                ),
                record(
                    rule3_root / "generation/outcomes/claude/attempt-1.json",
                    {"status": "success", "model_key": "claude"},
                    2,
                ),
            ),
        )
        return ParentEvidence(
            rule3=rule3,
            cohere_outcome=record(
                first_root / contract.COHERE_OUTCOME_PATH,
                {"status": "success", "model_key": "cohere"},
                3,
            ),
            stranded_qwen_intent=record(
                first_root / contract.QWEN_STRANDED_INTENT_PATH,
                stranded_payload,
                4,
            ),
            first_manifest=record(
                first_root / contract.FIRST_MANIFEST_PATH,
                {"status": "complete"},
                5,
            ),
            first_claim=record(
                self.root / contract.FIRST_CLAIM_PATH,
                {"status": "claimed"},
                6,
            ),
            reserved_microdollars=contract.INHERITED_RESERVED_MICRODOLLARS,
        )

    def attempt_two_payload(self) -> dict:
        return execute._generation_intent_payload(
            self.prepared,
            self.authority,
            self.parent,
            self.manifest,
            self.deepinfra_preflight,
            self.qwen,
            2,
            created_at=T0,
        )

    def write_attempt_two_intent(self) -> JournalRecord:
        return write_record(
            self.prepared.paths.generation_intent("qwen", 2),
            self.attempt_two_payload(),
        )

    def preflights(self) -> dict[str, JournalRecord]:
        return {
            "qwen": self.deepinfra_preflight,
            self.openrouter_route_key: self.openrouter_preflight,
        }

    def successor_outcomes(self, *, qwen_attempt: int) -> list[JournalRecord]:
        outcomes = []
        for index, call in enumerate(self.prepared.target_plan):
            key = call.model.model_key
            attempt = qwen_attempt if key == "qwen" else 1
            actual = self.prepared.fallback_call if attempt == 3 else call
            outcomes.append(
                record(
                    self.prepared.paths.generation_outcome(key, attempt),
                    {
                        "status": "success",
                        "model_key": key,
                        "provider": actual.model.provider,
                        "route": actual.model.route,
                        "requested_model_id": actual.model.requested_model_id,
                        "semantic_attempt_number": attempt,
                        "intent": {
                            "path": f"generation/intents/{key}/attempt-{attempt}.json",
                            "sha256": f"{100 + index:064x}",
                        },
                        "raw_response": {
                            "path": (
                                f"generation/raw-responses/{key}/attempt-{attempt}.json"
                            ),
                            "sha256": f"{110 + index:064x}",
                        },
                    },
                    120 + index + attempt,
                )
            )
        return outcomes


class ParentImmutabilityAndClaimTests(QwenSuccessorLineageFixture):
    def test_parent_contract_binds_all_files_absences_and_empty_capture_dir(
        self,
    ) -> None:
        expected = parent_module._expected_parent_contract()
        self.assertEqual(expected["first_private_binding_count"], 26)
        self.assertEqual(
            expected["first_private_bindings"],
            [
                {"path": path, "sha256": digest}
                for path, digest in sorted(contract.FIRST_PRIVATE_SHA256.items())
            ],
        )
        self.assertEqual(
            expected["required_absent"], list(contract.FIRST_REQUIRED_ABSENT)
        )
        self.assertEqual(
            expected["first_extra_empty_directories"],
            ["generation/raw-responses/qwen"],
        )

        first_root = self.root / "exact-parent-tree"
        expected_files = set(contract.FIRST_PRIVATE_SHA256)
        make_exact_private_tree(first_root, expected_files)
        parent_module._inspect_exact_private_tree(first_root, expected_files)
        parent_module._validate_required_absences(first_root)

        forbidden = first_root / "generation/raw-responses/qwen/attempt-1.json"
        forbidden.write_bytes(b"{}\n")
        forbidden.chmod(0o600)
        with self.assertRaisesRegex(RecoveryJournalError, "inventory changed"):
            parent_module._inspect_exact_private_tree(first_root, expected_files)
        with self.assertRaisesRegex(RecoveryJournalError, "absence changed"):
            parent_module._validate_required_absences(first_root)

        forbidden.unlink()
        missing = first_root / contract.QWEN_STRANDED_INTENT_PATH
        missing.unlink()
        with self.assertRaisesRegex(RecoveryJournalError, "inventory changed"):
            parent_module._inspect_exact_private_tree(first_root, expected_files)

    def test_exact_parent_intent_is_claimed_once_and_cannot_be_rebound(self) -> None:
        first = execute._ensure_claim(self.prepared, self.authority, self.parent)
        second = execute._ensure_claim(self.prepared, self.authority, self.parent)
        self.assertEqual(first.sha256, second.sha256)
        self.assertEqual(
            first.path,
            self.root
            / contract.CLAIM_ROOT_RELATIVE
            / f"{contract.QWEN_STRANDED_INTENT_SHA256}.json",
        )
        self.assertEqual(
            first.payload["stranded_qwen_intent"],
            {
                "path": contract.QWEN_STRANDED_INTENT_PATH,
                "sha256": self.parent.stranded_qwen_intent.sha256,
                "disposition": (
                    "consumed-possibly-delivered-possibly-billed-one-replacement"
                ),
            },
        )
        self.assertEqual(first.payload["replacement_semantic_attempt_number"], 2)
        self.assertEqual(
            list(first.path.parent.glob("*.json")),
            [first.path],
        )

        changed_parent = replace(
            self.parent,
            stranded_qwen_intent=record(
                self.parent.stranded_qwen_intent.path,
                self.parent.stranded_qwen_intent.payload,
                999,
            ),
        )
        with self.assertRaisesRegex(execute.SuccessorExecutionError, "claim changed"):
            execute._ensure_claim(self.prepared, self.authority, changed_parent)


class RequestIdentityAndFallbackTests(QwenSuccessorLineageFixture):
    def test_deepinfra_attempt_two_is_byte_identical_to_attempt_one_request(
        self,
    ) -> None:
        payload = self.attempt_two_payload()
        request = ProviderAdapter(
            self.qwen.model, execute._NeverTransport()
        ).build_generation_request(
            "redacted-offline-secret", self.qwen.answer_messages()
        )
        request_hash = sha256_bytes(
            json.dumps(request.json_body, ensure_ascii=False).encode("utf-8")
        )
        self.assertEqual(request_hash, QWEN_ATTEMPT_ONE_REQUEST_BODY_SHA256)
        self.assertEqual(payload["request_json_body_sha256"], request_hash)
        self.assertEqual(payload["semantic_attempt_number"], 2)
        self.assertEqual(payload["provider"], "deepinfra")
        self.assertEqual(payload["route"], "deepinfra")
        self.assertEqual(payload["requested_model_id"], "Qwen/Qwen3.5-397B-A17B")
        self.assertEqual(payload["reserved_cost_microdollars"], 49_243)
        self.assertEqual(payload["messages"], self.qwen.answer_messages())
        self.assertIs(payload["requested_params"]["tools_enabled"], False)
        self.assertIs(payload["requested_params"]["web_search_enabled"], False)
        self.assertIs(payload["requested_params"]["retrieval_enabled"], False)
        self.assertFalse({"tools", "web_search", "retrieval"} & set(request.json_body))

        forged = copy.deepcopy(self.parent.stranded_qwen_intent.payload)
        forged["request_json_body_sha256"] = "0" * 64
        changed_parent = replace(
            self.parent,
            stranded_qwen_intent=record(
                self.parent.stranded_qwen_intent.path, forged, 998
            ),
        )
        with self.assertRaisesRegex(
            execute.SuccessorExecutionError, "differs from the stranded request"
        ):
            execute._generation_intent_payload(
                self.prepared,
                self.authority,
                changed_parent,
                self.manifest,
                self.deepinfra_preflight,
                self.qwen,
                2,
                created_at=T0,
            )

    def test_openrouter_is_an_upfront_preflight_and_excludes_deepinfra_exactly(
        self,
    ) -> None:
        self.assertEqual(
            tuple(execute._route_key(call) for call in self.prepared.preflight_plan),
            contract.PREFLIGHT_ROUTE_KEYS,
        )
        fallback = self.prepared.fallback_call
        request = ProviderAdapter(
            fallback.model, execute._NeverTransport()
        ).build_generation_request(
            "redacted-offline-secret", fallback.answer_messages()
        )
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.url, "https://openrouter.ai/api/v1/chat/completions")
        self.assertEqual(request.json_body["model"], "qwen/qwen3.5-397b-a17b")
        self.assertEqual(
            request.json_body["provider"],
            {
                "ignore": ["deepinfra"],
                "sort": "throughput",
                "allow_fallbacks": True,
                "require_parameters": True,
                "max_price": {"prompt": 0.45, "completion": 3.0},
            },
        )
        self.assertNotIn("only", request.json_body["provider"])
        self.assertFalse({"tools", "web_search", "retrieval"} & set(request.json_body))
        self.assertEqual(
            contract.QWEN_OPENROUTER["accepted_returned_model_ids"],
            [
                "qwen/qwen3.5-397b-a17b",
                "qwen/qwen3.5-397b-a17b-20260216",
            ],
        )
        adapter = execute._SuccessorAdapter(fallback.model, execute._NeverTransport())
        for model_id in contract.QWEN_OPENROUTER["accepted_returned_model_ids"]:
            adapter.assert_model_identity(model_id)
        with self.assertRaises(ProviderError):
            adapter.assert_model_identity("Qwen/Qwen3.5-397B-A17B")

        environment = {
            call.model.environment_variable: f"synthetic-{index}"
            for index, call in enumerate(self.prepared.preflight_plan)
        }
        without_openrouter = dict(environment)
        without_openrouter.pop("OPENROUTER_API_KEY")
        with self.assertRaisesRegex(
            execute.SuccessorExecutionError, "OPENROUTER_API_KEY"
        ):
            execute._collect_secrets(self.prepared, without_openrouter)
        self.assertEqual(
            set(execute._collect_secrets(self.prepared, environment)),
            {call.model.environment_variable for call in self.prepared.preflight_plan},
        )

    def test_attempt_three_requires_attempt_two_nonsuccess_and_is_last(self) -> None:
        fallback = self.prepared.fallback_call
        with self.assertRaises(RecoveryJournalError):
            execute._generation_intent_payload(
                self.prepared,
                self.authority,
                self.parent,
                self.manifest,
                self.openrouter_preflight,
                fallback,
                3,
                created_at=T1,
            )

        attempt_two = self.write_attempt_two_intent()
        success = write_record(
            self.prepared.paths.generation_outcome("qwen", 2),
            {
                "status": "success",
                "model_key": "qwen",
                "semantic_attempt_number": 2,
            },
        )
        with self.assertRaisesRegex(
            execute.SuccessorExecutionError, "success|fallback|attempt 2"
        ):
            execute._generation_intent_payload(
                self.prepared,
                self.authority,
                self.parent,
                self.manifest,
                self.openrouter_preflight,
                fallback,
                3,
                created_at=T1,
            )

        success.path.unlink()
        consumed = write_record(
            self.prepared.paths.generation_outcome("qwen", 2),
            execute._consumed_without_capture_payload(
                self.prepared,
                self.authority,
                self.qwen,
                attempt_two,
                completed_at=T1,
            ),
        )
        payload = execute._generation_intent_payload(
            self.prepared,
            self.authority,
            self.parent,
            self.manifest,
            self.openrouter_preflight,
            fallback,
            3,
            created_at=T1,
        )
        self.assertEqual(payload["semantic_attempt_number"], 3)
        self.assertEqual(payload["provider"], "openrouter")
        self.assertEqual(
            payload["replacement_of_parent_intent"]["sha256"], attempt_two.sha256
        )
        self.assertEqual(
            payload["replacement_of_parent_intent"]["outcome"]["sha256"],
            consumed.sha256,
        )
        self.assertEqual(execute._attempt_range("qwen"), (2, 3))
        with self.assertRaisesRegex(
            execute.SuccessorExecutionError, "only DeepInfra Qwen attempt 2"
        ):
            execute._consumed_without_capture_payload(
                self.prepared,
                self.authority,
                fallback,
                SimpleNamespace(payload=payload),
                completed_at=T1,
            )

    def test_deepinfra_no_capture_advances_once_but_openrouter_no_capture_stops(
        self,
    ) -> None:
        attempt_two = self.write_attempt_two_intent()
        success, needs, reason = asyncio.run(
            execute._reconcile_generation(
                self.prepared,
                self.authority,
                self.parent,
                self.manifest,
                self.preflights(),
                self.qwen,
            )
        )
        self.assertIsNone(success)
        self.assertIs(needs, True)
        self.assertIsNone(reason)
        disposition = json.loads(
            self.prepared.paths.generation_outcome("qwen", 2).read_bytes()
        )
        self.assertEqual(disposition["status"], "consumed-without-capture")
        self.assertEqual(
            disposition["disposition"],
            {
                "category": "ambiguous-no-capture",
                "possibly_delivered": True,
                "possibly_billed": True,
                "deepinfra_replay_allowed": False,
                "openrouter_fallback_allowed_once": True,
            },
        )
        self.assertEqual(disposition["intent"]["sha256"], attempt_two.sha256)

        fallback_payload = execute._generation_intent_payload(
            self.prepared,
            self.authority,
            self.parent,
            self.manifest,
            self.openrouter_preflight,
            self.prepared.fallback_call,
            3,
            created_at=T1,
        )
        write_record(self.prepared.paths.generation_intent("qwen", 3), fallback_payload)
        success, needs, reason = asyncio.run(
            execute._reconcile_generation(
                self.prepared,
                self.authority,
                self.parent,
                self.manifest,
                self.preflights(),
                self.qwen,
            )
        )
        self.assertIsNone(success)
        self.assertIs(needs, False)
        self.assertIn("terminal", reason)
        self.assertFalse(self.prepared.paths.generation_outcome("qwen", 3).exists())

    def test_captured_deepinfra_error_also_authorizes_only_attempt_three(self) -> None:
        attempt_two = self.write_attempt_two_intent()
        raw = write_record(
            self.prepared.paths.generation_raw("qwen", 2),
            {"status": "synthetic-sanitized-http-error"},
        )
        error = execute._error(
            ProviderError(
                "synthetic provider failure",
                category="provider-error",
                retryable=True,
            ),
            preflight=False,
        )
        outcome = write_record(
            self.prepared.paths.generation_outcome("qwen", 2),
            execute._generation_outcome_payload(
                self.prepared,
                self.authority,
                self.qwen,
                attempt_two,
                raw,
                result=None,
                error=error,
                latency_ms=1,
                completed_at=T1,
            ),
        )
        payload = execute._generation_intent_payload(
            self.prepared,
            self.authority,
            self.parent,
            self.manifest,
            self.openrouter_preflight,
            self.prepared.fallback_call,
            3,
            created_at=T1,
        )
        self.assertEqual(payload["semantic_attempt_number"], 3)
        self.assertEqual(
            payload["replacement_of_parent_intent"]["outcome"]["sha256"],
            outcome.sha256,
        )
        self.assertEqual(execute._attempt_range("qwen"), (2, 3))


class BudgetAndCompositeTests(QwenSuccessorLineageFixture):
    def test_budget_lineage_counts_both_qwen_routes_and_every_safe_attempt(
        self,
    ) -> None:
        reservations = {
            ("qwen", 2): contract.RESERVED_PER_POST["qwen"],
            ("qwen", 3): contract.QWEN_OPENROUTER_RESERVED_MICRODOLLARS,
        }
        for key in contract.UNTOUCHED_MODEL_KEYS:
            for attempt in (1, 2, 3):
                reservations[(key, attempt)] = contract.RESERVED_PER_POST[key]
        for index, ((key, attempt), reserve) in enumerate(reservations.items()):
            write_record(
                self.prepared.paths.generation_intent(key, attempt),
                {"reserved_cost_microdollars": reserve, "seed": index},
            )
        self.assertEqual(execute._reserved_total(self.prepared), 1_989_257)
        self.assertEqual(
            self.parent.reserved_microdollars + execute._reserved_total(self.prepared),
            3_056_732,
        )
        self.assertEqual(contract.INHERITED_RESERVED_MICRODOLLARS, 1_067_475)
        self.assertLess(
            contract.COMBINED_RESERVED_CAP_MICRODOLLARS,
            contract.CANDIDATE_CAP_MICRODOLLARS,
        )

        malformed = self.prepared.paths.generation_intent("qwen", 4)
        write_record(malformed, {"reserved_cost_microdollars": True})
        with self.assertRaisesRegex(
            execute.SuccessorExecutionError, "reservation is malformed"
        ):
            execute._reserved_total(self.prepared)

    def test_budget_rejects_an_undercounted_or_over_cap_intent(self) -> None:
        write_record(
            self.prepared.paths.generation_intent("qwen", 2),
            {"reserved_cost_microdollars": 1},
        )
        with self.assertRaisesRegex(
            execute.SuccessorExecutionError, "reservation|cost|changed"
        ):
            execute._reserved_total(self.prepared)

        self.prepared.paths.generation_intent("qwen", 2).unlink()
        write_record(
            self.prepared.paths.generation_intent("qwen", 2),
            {
                "reserved_cost_microdollars": (
                    contract.NEW_RESERVED_CAP_MICRODOLLARS + 1
                )
            },
        )
        with self.assertRaisesRegex(execute.SuccessorExecutionError, "cap exceeded"):
            execute._reserved_total(self.prepared)

    def test_three_source_composite_has_exactly_one_qwen_winner(self) -> None:
        for qwen_attempt in (2, 3):
            with (
                self.subTest(qwen_attempt=qwen_attempt),
                mock.patch.object(
                    execute,
                    "_reserved_total",
                    return_value=contract.NEW_RESERVED_CAP_MICRODOLLARS,
                ),
            ):
                payload = execute._composite_payload(
                    self.prepared,
                    self.authority,
                    self.parent,
                    self.manifest,
                    self.successor_outcomes(qwen_attempt=qwen_attempt),
                    sealed_at=T1,
                )
                self.assertEqual(payload["successful_outcome_count"], 8)
                self.assertEqual(
                    [item["model_key"] for item in payload["outcomes"]],
                    list(contract.MODEL_ORDER),
                )
                self.assertEqual(
                    [item["source_lane"] for item in payload["outcomes"]],
                    [
                        "immutable-rule3-parent",
                        "immutable-rule3-parent",
                        "immutable-cohere-recovery",
                        "qwen-successor",
                        "qwen-successor",
                        "qwen-successor",
                        "qwen-successor",
                        "qwen-successor",
                    ],
                )
                qwen_cells = [
                    item for item in payload["outcomes"] if item["model_key"] == "qwen"
                ]
                self.assertEqual(len(qwen_cells), 1)
                self.assertEqual(qwen_cells[0]["semantic_attempt_number"], qwen_attempt)
                self.assertEqual(
                    payload["parent_stranded_qwen_intent"]["sha256"],
                    self.parent.stranded_qwen_intent.sha256,
                )
                self.assertEqual(
                    payload["budget"],
                    {
                        "inherited_reserved_microdollars": 1_067_475,
                        "new_reserved_microdollars": 1_989_257,
                        "combined_reserved_microdollars": 3_056_732,
                        "new_reserved_cap_microdollars": 1_989_257,
                        "combined_reserved_cap_microdollars": 3_056_732,
                    },
                )
                self.assertNotIn("response_text", json.dumps(payload))

    def test_composite_rejects_both_qwen_routes_or_a_missing_source(self) -> None:
        outcomes = self.successor_outcomes(qwen_attempt=2)
        outcomes.append(
            record(
                self.prepared.paths.generation_outcome("qwen", 3),
                {
                    "status": "success",
                    "model_key": "qwen",
                    "provider": "openrouter",
                    "route": contract.QWEN_OPENROUTER["route"],
                    "requested_model_id": contract.QWEN_OPENROUTER[
                        "requested_model_id"
                    ],
                    "semantic_attempt_number": 3,
                    "intent": {"path": "qwen-3-intent", "sha256": "7" * 64},
                    "raw_response": {"path": "qwen-3-raw", "sha256": "8" * 64},
                },
                900,
            )
        )
        with (
            mock.patch.object(execute, "_reserved_total", return_value=0),
            self.assertRaisesRegex(
                execute.SuccessorExecutionError, "duplicate|Qwen|outcome"
            ),
        ):
            execute._composite_payload(
                self.prepared,
                self.authority,
                self.parent,
                self.manifest,
                outcomes,
                sealed_at=T1,
            )

        missing = self.successor_outcomes(qwen_attempt=2)[:-1]
        with (
            mock.patch.object(execute, "_reserved_total", return_value=0),
            self.assertRaisesRegex(
                execute.SuccessorExecutionError, "missing|count|outcome"
            ),
        ):
            execute._composite_payload(
                self.prepared,
                self.authority,
                self.parent,
                self.manifest,
                missing,
                sealed_at=T1,
            )


if __name__ == "__main__":
    unittest.main()
