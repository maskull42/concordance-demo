from __future__ import annotations

import asyncio
import inspect
import json
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from concordance_harness.config import load_harness_config
from concordance_harness.planner import build_plan, load_questions
from concordance_harness.providers import PreflightResult
from concordance_harness.util import canonical_json_bytes, prompt_sha256, sha256_bytes
from rule3 import contract as rule3_contract
from rule3 import review as rule3_review
from rule3.authorization import (
    OFFICIAL_PRICING_HOSTS,
    PAID_AUTHORIZATION_STATEMENT,
    write_paid_authorization,
    write_pricing_recheck,
)
from rule3.budget import CANDIDATE_ORDER, JournalRecord, write_once_private_json
from rule3.evaluate import Rule3EvaluationError
from rule3.review import Rule3ReviewError
from rule3.execute import (
    FALLBACK_ELIGIBILITY_SCHEMA_VERSION,
    MODEL_KEYS,
    RUN_SCHEMA_VERSION,
    Rule3ExecutionError,
    _execute_prepared,
    _load_manifest,
    _prepare_execution,
    _preflight_intent_path,
    _preflight_intent_payload,
    _preflight_outcome_path,
    _preflight_outcome_payload,
    dry_run_summary,
    execute_prepared,
    plan_contract_sha256,
    prepare_execution,
)

from support import FakeTransport, repository_root, response


async def no_sleep(_: float) -> None:
    return None


class Rule3ExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        source = repository_root()
        for relative in (
            "harness/config/models.json",
            "config/rule3-protocol.json",
            "candidate/rule3/questions/galatians-pistis-christou.json",
            "candidate/rule3/questions/quantum-measurement-realist-strategies.json",
            *rule3_review.REVIEW_ASSET_PATHS,
        ):
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source / relative, destination)

        config_path = self.root / "harness/config/models.json"
        protocol_path = self.root / "config/rule3-protocol.json"
        question_root = self.root / "candidate/rule3/questions"
        config = load_harness_config(config_path)
        protocol = json.loads(protocol_path.read_bytes())
        questions = load_questions(question_root)
        by_id = {question.question_id: question for question in questions}
        plan_hashes = {}
        locked_plans = []
        for candidate_id in CANDIDATE_ORDER:
            plan = build_plan(
                (by_id[candidate_id],),
                config.models,
                protocol["system_prompt"],
                protocol["standard_challenge_prompt"],
                answer_only=True,
            )
            plan_hashes[candidate_id] = plan_contract_sha256(plan)
            cells = [
                {
                    "cell_id": call.cell_id,
                    "prompt_sha256": prompt_sha256(call.answer_messages()),
                    "requested_model_id": call.model.requested_model_id,
                    "route": call.model.route,
                    "requested_params": call.model.requested_params_receipt(),
                }
                for call in plan
            ]
            candidate_contract = next(
                item for item in rule3_contract.CANDIDATES if item["id"] == candidate_id
            )
            locked_plans.append(
                {
                    "candidate_id": candidate_id,
                    "role": candidate_contract["role"],
                    "cell_count": 8,
                    "cells": cells,
                    "plan_sha256": plan_hashes[candidate_id],
                }
            )
        locked_candidates = []
        for candidate in rule3_contract.CANDIDATES:
            payload = (self.root / candidate["path"]).read_bytes()
            locked_candidates.append(
                {
                    "id": candidate["id"],
                    "role": candidate["role"],
                    "kind": candidate["kind"],
                    "path": candidate["path"],
                    "sha256": sha256_bytes(payload),
                }
            )
        locked_sources = [
            {
                "path": relative,
                "sha256": sha256_bytes((self.root / relative).read_bytes()),
            }
            for relative in rule3_review.REVIEW_ASSET_PATHS
        ]
        lock = {
            "candidates": locked_candidates,
            "plans": {"candidate_plans": locked_plans},
            "execution_sources": locked_sources,
        }
        lock_bytes = canonical_json_bytes(lock)
        self.context = SimpleNamespace(
            repository_root=self.root,
            lock=lock,
            lock_bytes=lock_bytes,
            lock_sha256=sha256_bytes(lock_bytes),
            git_head="b" * 40,
            candidates=tuple(locked_candidates),
            models_config_path=config_path,
            protocol_path=protocol_path,
            question_paths=tuple(
                question_root / f"{candidate_id}.json"
                for candidate_id in CANDIDATE_ORDER
            ),
            candidate_plan_sha256=plan_hashes,
            candidate_cost_cap_microdollars=6_000_000,
            total_cost_cap_microdollars=12_000_000,
            attempts_per_cell=3,
            output_token_cap=16_384,
        )
        self.config = config

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def evidence(self) -> list[dict[str, object]]:
        return [
            {
                "model_key": model.model_key,
                "requested_model_id": model.requested_model_id,
                "input_per_million": model.planning_pricing["input_per_million"],
                "output_per_million": model.planning_pricing["output_per_million"],
                "official_source_url": (
                    f"https://{OFFICIAL_PRICING_HOSTS[model.model_key][0]}/"
                    f"pricing/{model.model_key}"
                ),
            }
            for model in self.config.models
        ]

    def write_gates(self):
        authorization = write_paid_authorization(
            self.context, statement=PAID_AUTHORIZATION_STATEMENT
        )
        pricing = write_pricing_recheck(
            self.context, self.evidence(), reviewed_by="A.G. Elrod"
        )
        return authorization, pricing

    def write_fallback_eligibility(self):
        authorization, pricing = self.write_gates()
        private = self.root / ".pilot/rule3/concordance-divergence-supplement-1"
        priority_id, fallback_id = CANDIDATE_ORDER
        run_path = private / "runs" / f"{priority_id}.json"
        run_sha256 = write_once_private_json(
            run_path,
            {
                "schema_version": RUN_SCHEMA_VERSION,
                "status": "complete-eight-successes",
                "candidate_id": priority_id,
                "successful_outcome_count": 8,
            },
        )
        author_path = (
            private / "candidates" / priority_id / "author-review" / "receipt.json"
        )
        author_sha256 = write_once_private_json(
            author_path,
            {
                "schema_version": "rule3-author-review-receipt-1.0.0",
                "status": "sealed-complete-author-review",
                "item_count": 8,
            },
        )
        threshold = {
            "evidence_complete": True,
            "author_review_complete": True,
            "qualifies": False,
            "non_null_primary_count": 5,
            "represented_position_count": 3,
            "maximum_position_primary_count": 3,
            "failure_reasons": ["fewer-than-six-non-null-primary-endorsements"],
        }
        evaluation_path = (
            private / "candidates" / priority_id / "evaluation" / "receipt.json"
        )
        evaluation_sha256 = write_once_private_json(
            evaluation_path,
            {
                "schema_version": "rule3-evaluation-receipt-1.0.0",
                "status": "complete-offline-reviewed-threshold-evaluation",
                "threshold_result": threshold,
            },
        )
        eligibility = {
            "schema_version": FALLBACK_ELIGIBILITY_SCHEMA_VERSION,
            "status": ("fallback-eligible-after-complete-reviewed-priority-failure"),
            "pool_id": "concordance-divergence-supplement-1",
            "rule_version": "pilot-rule-3",
            "created_at": "2026-07-13T10:00:00Z",
            "git_head": self.context.git_head,
            "lock_sha256": self.context.lock_sha256,
            "authorization_receipt_sha256": authorization.sha256,
            "pricing_recheck_receipt_sha256": pricing.sha256,
            "priority_candidate_id": priority_id,
            "fallback_candidate_id": fallback_id,
            "priority_run_receipt": {
                "path": str(run_path.relative_to(private)),
                "sha256": run_sha256,
            },
            "author_review_receipt": {
                "path": str(author_path.relative_to(private)),
                "sha256": author_sha256,
            },
            "evaluation_receipt": {
                "path": str(evaluation_path.relative_to(private)),
                "sha256": evaluation_sha256,
            },
            "threshold_result": threshold,
        }
        path = private / "fallback-eligibility.json"
        digest = write_once_private_json(path, eligibility)
        return path, eligibility, digest

    def loader(self, _: Path) -> SimpleNamespace:
        return self.context

    def metadata_response(self, model: object):
        if model.metadata_mode == "list":
            return response(200, {"data": [{"id": model.requested_model_id}]})
        if model.metadata_mode == "openrouter-endpoints":
            return response(
                200,
                {
                    "data": {
                        "id": "openai/gpt-5.6-sol-20260709",
                        "endpoints": [{"provider_name": "OpenAI"}],
                    }
                },
            )
        if model.api_style == "google":
            return response(200, {"name": f"models/{model.requested_model_id}"})
        return response(200, {"id": model.requested_model_id})

    def generation_response(self, model: object):
        text = "A complete scholarly answer to the frozen question."
        if model.api_style == "google":
            return response(
                200,
                {
                    "modelVersion": model.requested_model_id,
                    "responseId": f"response-{model.model_key}",
                    "candidates": [
                        {
                            "content": {"parts": [{"text": text}]},
                            "finishReason": "STOP",
                        }
                    ],
                    "usageMetadata": {
                        "promptTokenCount": 20,
                        "candidatesTokenCount": 10,
                        "thoughtsTokenCount": 3,
                        "totalTokenCount": 33,
                    },
                },
            )
        if model.api_style == "anthropic":
            return response(
                200,
                {
                    "id": f"response-{model.model_key}",
                    "model": model.requested_model_id,
                    "content": [{"type": "text", "text": text}],
                    "stop_reason": "end_turn",
                    "usage": {"input_tokens": 20, "output_tokens": 10},
                },
            )
        if model.api_style == "cohere":
            return response(
                200,
                {
                    "id": f"response-{model.model_key}",
                    "model": model.requested_model_id,
                    "message": {"content": [{"type": "text", "text": text}]},
                    "finish_reason": "COMPLETE",
                    "usage": {"tokens": {"input_tokens": 20, "output_tokens": 10}},
                },
            )
        if model.api_style == "xai-responses":
            return response(
                200,
                {
                    "id": f"response-{model.model_key}",
                    "model": model.requested_model_id,
                    "status": "completed",
                    "output": [
                        {
                            "type": "message",
                            "role": "assistant",
                            "content": [{"type": "output_text", "text": text}],
                        }
                    ],
                    "usage": {
                        "input_tokens": 20,
                        "output_tokens": 10,
                        "total_tokens": 30,
                    },
                },
            )
        returned = (
            "openai/gpt-5.6-sol-20260709"
            if model.model_key == "gpt"
            else model.requested_model_id
        )
        return response(
            200,
            {
                "id": f"response-{model.model_key}",
                "model": returned,
                "provider": "OpenAI" if model.model_key == "gpt" else model.provider,
                "choices": [{"message": {"content": text}, "finish_reason": "stop"}],
                "usage": {
                    "prompt_tokens": 20,
                    "completion_tokens": 10,
                    "total_tokens": 30,
                },
            },
        )

    def full_success_transport(self) -> FakeTransport:
        return FakeTransport(
            [self.metadata_response(model) for model in self.config.models]
            + [self.generation_response(model) for model in self.config.models]
        )

    def test_dry_run_is_exact_and_does_not_read_environment(self) -> None:
        class ForbiddenEnvironment(dict):
            def get(self, key: str, default: str = "") -> str:
                raise AssertionError(f"environment read: {key}")

        with mock.patch("rule3.execute.os.environ", ForbiddenEnvironment()):
            prepared = _prepare_execution(
                self.root, "priority", live=False, lock_loader=self.loader
            )
            summary = dry_run_summary(prepared)
        self.assertEqual(summary["logical_cells"], 8)
        self.assertEqual(summary["model_keys"], list(MODEL_KEYS))
        self.assertEqual(summary["call_type"], "answer")
        self.assertEqual(summary["network_requests"], 0)
        self.assertEqual(summary["environment_variables_read"], 0)
        self.assertLess(summary["three_attempt_reserved_microdollars"], 6_000_000)

    def test_structural_dry_run_does_not_claim_an_unproved_git_head(self) -> None:
        structural = SimpleNamespace(**{**self.context.__dict__, "git_head": None})
        prepared = _prepare_execution(
            self.root,
            "priority",
            live=False,
            lock_loader=lambda _: structural,
        )
        self.assertIsNone(prepared.binding.git_head)
        with self.assertRaisesRegex(Rule3ExecutionError, "approved contract"):
            _prepare_execution(
                self.root,
                "priority",
                live=True,
                lock_loader=lambda _: structural,
            )

    def test_every_live_gate_precedes_environment_or_network(self) -> None:
        class ForbiddenEnvironment(dict):
            def get(self, key: str, default: str = "") -> str:
                raise AssertionError(f"environment read: {key}")

        transport = FakeTransport([])
        with mock.patch("rule3.execute.os.environ", ForbiddenEnvironment()):
            with self.assertRaisesRegex(Rule3ExecutionError, "authorization"):
                _prepare_execution(
                    self.root, "priority", live=True, lock_loader=self.loader
                )
        self.assertEqual(transport.requests, [])

    def test_priority_refuses_any_fallback_state(self) -> None:
        self.write_gates()
        root = self.root / ".pilot/rule3/concordance-divergence-supplement-1"
        write_once_private_json(root / "fallback-eligibility.json", {"state": "exists"})
        with self.assertRaisesRegex(Rule3ExecutionError, "fallback state"):
            _prepare_execution(
                self.root, "priority", live=True, lock_loader=self.loader
            )

    def test_live_gates_are_rechecked_immediately_before_environment_access(
        self,
    ) -> None:
        class ForbiddenEnvironment(dict):
            def get(self, key: str, default: str = "") -> str:
                raise AssertionError(f"environment read: {key}")

        self.write_gates()
        prepared = _prepare_execution(
            self.root, "priority", live=True, lock_loader=self.loader
        )
        write_once_private_json(
            prepared.private_root / "fallback-eligibility.json",
            {"state": "appeared-after-prepare"},
        )
        transport = FakeTransport([])
        with self.assertRaisesRegex(Rule3ExecutionError, "fallback state"):
            asyncio.run(
                _execute_prepared(
                    prepared,
                    lock_loader=self.loader,
                    environment=ForbiddenEnvironment(),
                    transport_factory=lambda: transport,
                    sleep=no_sleep,
                )
            )
        self.assertEqual(transport.requests, [])

    def test_fallback_requires_exact_eligibility(self) -> None:
        self.write_gates()
        with self.assertRaisesRegex(Rule3ExecutionError, "fallback eligibility"):
            _prepare_execution(
                self.root, "fallback", live=True, lock_loader=self.loader
            )

    def test_fallback_accepts_only_the_canonical_verified_review_chain(self) -> None:
        path, eligibility, digest = self.write_fallback_eligibility()
        verified = {"path": path, "value": eligibility, "sha256": digest}
        with mock.patch(
            "rule3.evaluate.verify_fallback_eligibility",
            return_value=verified,
        ):
            prepared = _prepare_execution(
                self.root, "fallback", live=True, lock_loader=self.loader
            )
        self.assertEqual(prepared.candidate_id, CANDIDATE_ORDER[1])

        with mock.patch(
            "rule3.evaluate.verify_fallback_eligibility",
            side_effect=Rule3EvaluationError("review chain changed"),
        ):
            with self.assertRaisesRegex(
                Rule3ExecutionError, "complete offline review verification"
            ):
                _prepare_execution(
                    self.root, "fallback", live=True, lock_loader=self.loader
                )
        with mock.patch(
            "rule3.evaluate.verify_fallback_eligibility",
            side_effect=Rule3ReviewError("deep review artifact changed"),
        ):
            with self.assertRaisesRegex(
                Rule3ExecutionError, "complete offline review verification"
            ):
                _prepare_execution(
                    self.root, "fallback", live=True, lock_loader=self.loader
                )

    def test_complete_eight_model_execution_is_private_and_nonreplayable(self) -> None:
        self.write_gates()
        prepared = _prepare_execution(
            self.root, "priority", live=True, lock_loader=self.loader
        )
        environment = {
            model.environment_variable: f"secret-{model.model_key}"
            for model in self.config.models
        }
        transport = self.full_success_transport()
        result = asyncio.run(
            _execute_prepared(
                prepared,
                lock_loader=self.loader,
                environment=environment,
                transport_factory=lambda: transport,
                sleep=no_sleep,
            )
        )
        self.assertEqual(result.payload["status"], "complete-eight-successes")
        self.assertEqual(result.payload["successful_outcome_count"], 8)
        self.assertEqual(result.network_requests, 16)
        self.assertEqual(len(transport.requests), 16)
        self.assertEqual(stat.S_IMODE(result.path.stat().st_mode), 0o600)
        for record in result.payload["outcomes"]:
            outcome_path = prepared.private_root / record["path"]
            outcome = json.loads(outcome_path.read_bytes())
            self.assertEqual(stat.S_IMODE(outcome_path.stat().st_mode), 0o600)
            self.assertEqual(outcome["status"], "success")
            self.assertEqual(len(outcome["response_sha256"]), 64)
            self.assertEqual(
                outcome["manifest_sha256"], result.payload["manifest"]["sha256"]
            )
            self.assertIn("response_text", outcome)
        from rule3.review import load_candidate_responses

        with mock.patch(
            "rule3.review._load_committed_review_lock",
            return_value=self.context,
        ):
            review_bundle = load_candidate_responses(self.root, prepared.candidate_id)
        self.assertEqual(len(review_bundle.responses), 8)
        self.assertEqual(
            tuple(item.model_key for item in review_bundle.responses), MODEL_KEYS
        )
        with self.assertRaisesRegex(Rule3ExecutionError, "no replay"):
            _prepare_execution(
                self.root, "priority", live=True, lock_loader=self.loader
            )

    def test_retry_ceiling_stops_before_other_models(self) -> None:
        self.write_gates()
        prepared = _prepare_execution(
            self.root, "priority", live=True, lock_loader=self.loader
        )
        environment = {
            model.environment_variable: f"secret-{model.model_key}"
            for model in self.config.models
        }
        transport = FakeTransport(
            [self.metadata_response(model) for model in self.config.models]
            + [response(500, {"error": "retry"}) for _ in range(3)]
        )
        result = asyncio.run(
            _execute_prepared(
                prepared,
                lock_loader=self.loader,
                environment=environment,
                transport_factory=lambda: transport,
                sleep=no_sleep,
            )
        )
        self.assertEqual(result.payload["status"], "incomplete-terminal-stop")
        self.assertIn("three-attempt ceiling", result.payload["stopped_reason"])
        self.assertEqual(result.network_requests, 11)
        self.assertEqual(len(transport.requests), 11)
        attempts = list(
            (
                prepared.private_root / "outcomes" / prepared.candidate_id / "gemini"
            ).glob("attempt-*.json")
        )
        self.assertEqual(len(attempts), 3)

    def test_nonretryable_response_stops_immediately(self) -> None:
        self.write_gates()
        prepared = _prepare_execution(
            self.root, "priority", live=True, lock_loader=self.loader
        )
        environment = {
            model.environment_variable: f"secret-{model.model_key}"
            for model in self.config.models
        }
        transport = FakeTransport(
            [self.metadata_response(model) for model in self.config.models]
            + [response(400, {"error": "invalid"})]
        )
        result = asyncio.run(
            _execute_prepared(
                prepared,
                lock_loader=self.loader,
                environment=environment,
                transport_factory=lambda: transport,
                sleep=no_sleep,
            )
        )
        self.assertEqual(result.payload["status"], "incomplete-terminal-stop")
        self.assertIn("nonretryable", result.payload["stopped_reason"])
        self.assertEqual(result.network_requests, 9)
        self.assertEqual(len(transport.requests), 9)

    def test_manifest_without_bound_preflight_files_fails_closed(self) -> None:
        self.write_gates()
        prepared = _prepare_execution(
            self.root, "priority", live=True, lock_loader=self.loader
        )
        environment = {
            model.environment_variable: f"secret-{model.model_key}"
            for model in self.config.models
        }
        transport = self.full_success_transport()
        asyncio.run(
            _execute_prepared(
                prepared,
                lock_loader=self.loader,
                environment=environment,
                transport_factory=lambda: transport,
                sleep=no_sleep,
            )
        )
        shutil.rmtree(prepared.private_root / "preflight")
        with self.assertRaisesRegex(Rule3ExecutionError, "preflight"):
            _load_manifest(prepared)

    def test_forged_manifest_preflight_identity_is_rejected(self) -> None:
        self.write_gates()
        prepared = _prepare_execution(
            self.root, "priority", live=True, lock_loader=self.loader
        )
        environment = {
            model.environment_variable: f"secret-{model.model_key}"
            for model in self.config.models
        }
        transport = self.full_success_transport()
        asyncio.run(
            _execute_prepared(
                prepared,
                lock_loader=self.loader,
                environment=environment,
                transport_factory=lambda: transport,
                sleep=no_sleep,
            )
        )
        manifest_path = (
            prepared.private_root / "manifests" / f"{prepared.candidate_id}.json"
        )
        value = json.loads(manifest_path.read_bytes())
        value["model_manifest"]["models"][0]["preflight"][
            "provider_returned_model_id"
        ] = "forged-model"
        manifest_path.write_bytes(canonical_json_bytes(value))
        with self.assertRaisesRegex(Rule3ExecutionError, "identity"):
            _load_manifest(prepared)

    def test_stranded_preflight_intent_is_never_replayed(self) -> None:
        class ForbiddenEnvironment(dict):
            def get(self, key: str, default: str = "") -> str:
                raise AssertionError(f"environment read: {key}")

        self.write_gates()
        prepared = _prepare_execution(
            self.root, "priority", live=True, lock_loader=self.loader
        )
        model = self.config.models[0]
        payload = _preflight_intent_payload(prepared, model, 1)
        write_once_private_json(
            _preflight_intent_path(
                prepared.private_root,
                prepared.candidate_id,
                model.model_key,
                1,
            ),
            payload,
        )

        def forbidden_transport() -> FakeTransport:
            raise AssertionError("transport constructed")

        with self.assertRaisesRegex(Rule3ExecutionError, "stranded preflight"):
            asyncio.run(
                _execute_prepared(
                    prepared,
                    lock_loader=self.loader,
                    environment=ForbiddenEnvironment(),
                    transport_factory=forbidden_transport,
                    sleep=no_sleep,
                )
            )

    def test_unknown_preflight_status_cannot_unlock_a_retry(self) -> None:
        self.write_gates()
        prepared = _prepare_execution(
            self.root, "priority", live=True, lock_loader=self.loader
        )
        model = self.config.models[0]
        intent_payload = _preflight_intent_payload(prepared, model, 1)
        intent_path = _preflight_intent_path(
            prepared.private_root,
            prepared.candidate_id,
            model.model_key,
            1,
        )
        intent_sha = write_once_private_json(intent_path, intent_payload)
        intent = JournalRecord(intent_path, intent_payload, intent_sha)
        outcome_payload = {
            **intent_payload,
            "schema_version": "rule3-preflight-outcome-1.0.0",
            "status": "banana",
            "intent_path": str(intent.path.relative_to(prepared.private_root)),
            "intent_sha256": intent.sha256,
            "completed_at": "2026-07-13T10:00:01Z",
            "error": {
                "category": "provider-error",
                "retryable": True,
                "sanitized_summary": "forged retry state",
            },
        }
        write_once_private_json(
            _preflight_outcome_path(
                prepared.private_root,
                prepared.candidate_id,
                model.model_key,
                1,
            ),
            outcome_payload,
        )
        with self.assertRaisesRegex(Rule3ExecutionError, "status is invalid"):
            _prepare_execution(
                self.root, "priority", live=True, lock_loader=self.loader
            )

    def test_preflight_completion_cannot_predate_its_intent(self) -> None:
        self.write_gates()
        prepared = _prepare_execution(
            self.root, "priority", live=True, lock_loader=self.loader
        )
        model = self.config.models[0]
        intent_payload = _preflight_intent_payload(prepared, model, 1)
        intent_payload["created_at"] = "2026-07-13T10:00:00Z"
        intent_path = _preflight_intent_path(
            prepared.private_root,
            prepared.candidate_id,
            model.model_key,
            1,
        )
        intent_sha = write_once_private_json(intent_path, intent_payload)
        intent = JournalRecord(intent_path, intent_payload, intent_sha)
        outcome_payload = _preflight_outcome_payload(
            prepared,
            intent,
            result=PreflightResult(model.requested_model_id, None, None),
        )
        outcome_payload["completed_at"] = "2026-07-13T09:59:59Z"
        write_once_private_json(
            _preflight_outcome_path(
                prepared.private_root,
                prepared.candidate_id,
                model.model_key,
                1,
            ),
            outcome_payload,
        )
        with self.assertRaisesRegex(Rule3ExecutionError, "durable intent"):
            _prepare_execution(
                self.root, "priority", live=True, lock_loader=self.loader
            )

    def test_phase_lock_prevents_competing_run_from_sealing_false_terminal_state(
        self,
    ) -> None:
        self.write_gates()
        prepared = _prepare_execution(
            self.root, "priority", live=True, lock_loader=self.loader
        )
        environment = {
            model.environment_variable: f"secret-{model.model_key}"
            for model in self.config.models
        }

        async def scenario() -> tuple[object, str, bool]:
            started = asyncio.Event()
            release = asyncio.Event()

            class BlockingTransport(FakeTransport):
                async def send(self, request):
                    if not self.requests:
                        started.set()
                        await release.wait()
                    return await super().send(request)

            winner_transport = BlockingTransport(
                [self.metadata_response(model) for model in self.config.models]
                + [self.generation_response(model) for model in self.config.models]
            )
            loser_transport_constructed = False

            def loser_transport_factory() -> FakeTransport:
                nonlocal loser_transport_constructed
                loser_transport_constructed = True
                return FakeTransport([])

            winner = asyncio.create_task(
                _execute_prepared(
                    prepared,
                    lock_loader=self.loader,
                    environment=environment,
                    transport_factory=lambda: winner_transport,
                    sleep=no_sleep,
                )
            )
            await started.wait()
            loser = asyncio.create_task(
                _execute_prepared(
                    prepared,
                    lock_loader=self.loader,
                    environment=environment,
                    transport_factory=loser_transport_factory,
                    sleep=no_sleep,
                )
            )
            await asyncio.sleep(0.1)
            self.assertFalse(loser.done())
            release.set()
            winner_result = await winner
            try:
                await loser
            except Rule3ExecutionError as error:
                loser_error = str(error)
            else:
                self.fail("competing execution unexpectedly completed")
            return winner_result, loser_error, loser_transport_constructed

        winner_result, loser_error, loser_transport_constructed = asyncio.run(
            scenario()
        )
        self.assertEqual(winner_result.payload["status"], "complete-eight-successes")
        self.assertIn("no replay", loser_error)
        self.assertFalse(loser_transport_constructed)
        run_path = prepared.private_root / "runs" / f"{prepared.candidate_id}.json"
        self.assertEqual(
            json.loads(run_path.read_bytes())["status"], "complete-eight-successes"
        )

    def test_public_live_boundaries_expose_no_injection_seams(self) -> None:
        prepare_parameters = inspect.signature(prepare_execution).parameters
        execute_parameters = inspect.signature(execute_prepared).parameters
        self.assertNotIn("lock_loader", prepare_parameters)
        self.assertNotIn("environment", execute_parameters)
        self.assertNotIn("transport", execute_parameters)
        self.assertNotIn("transport_factory", execute_parameters)

    def test_nested_prepared_mutation_fails_before_credentials_or_transport(
        self,
    ) -> None:
        class ForbiddenEnvironment(dict):
            def get(self, key: str, default: str = "") -> str:
                raise AssertionError(f"environment read: {key}")

        self.write_gates()
        prepared = _prepare_execution(
            self.root, "priority", live=True, lock_loader=self.loader
        )
        prepared.protocol["system_prompt"] = "mutated after validation"

        def forbidden_transport() -> FakeTransport:
            raise AssertionError("transport constructed")

        with self.assertRaisesRegex(Rule3ExecutionError, "changed"):
            asyncio.run(
                _execute_prepared(
                    prepared,
                    lock_loader=self.loader,
                    environment=ForbiddenEnvironment(),
                    transport_factory=forbidden_transport,
                    sleep=no_sleep,
                )
            )

    def test_no_third_phase_or_force_override(self) -> None:
        with self.assertRaisesRegex(Rule3ExecutionError, "no third"):
            _prepare_execution(self.root, "third", live=False, lock_loader=self.loader)
        from run_rule3 import parser

        with self.assertRaises(SystemExit):
            parser().parse_args(["--live", "--phase", "priority", "--force"])


if __name__ == "__main__":
    unittest.main()
