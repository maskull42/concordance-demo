from __future__ import annotations

import asyncio
import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from concordance_harness.config import load_harness_config  # noqa: E402
from concordance_harness.planner import QuestionInput, build_plan  # noqa: E402
from concordance_harness.providers import (  # noqa: E402
    HttpRequest,
    HttpResponse,
    ProviderAdapter,
)
from concordance_harness.util import (  # noqa: E402
    canonical_json_bytes,
    prompt_sha256,
    sha256_bytes,
)
from concordance_recovery.journal import read_record, write_record  # noqa: E402
from divergence_successor import (  # noqa: E402
    authorization,
    composite,
    contract,
    engine,
    execute,
    review,
)
from divergence_successor.lock import LockContext  # noqa: E402
from divergence_successor.state import SuccessorPaths  # noqa: E402
from rule3.budget import JournalRecord  # noqa: E402


SOURCE_ROOT = Path(__file__).resolve().parents[2]
APPROVAL = (
    "I approve exactly one fresh answer from each of the eight locked models for "
    "frontier-ai-lifecycle-licensing, after eight successful metadata preflights, "
    "with no retry, fallback, tools, web search, retrieval, or external context, "
    "under the locked six-dollar candidate and pool caps."
)
SOURCE_URLS = {
    "gemini": "https://ai.google.dev/gemini-api/docs/pricing",
    "claude": "https://docs.anthropic.com/en/docs/about-claude/pricing",
    "cohere": "https://cohere.com/pricing",
    "qwen": "https://deepinfra.com/pricing",
    "deepseek": "https://api-docs.deepseek.com/quick_start/pricing",
    "mistral": "https://mistral.ai/pricing",
    "grok": "https://docs.x.ai/docs/models",
    "gpt": "https://openrouter.ai/models/openai/gpt-5.6-sol",
}


def http(value: dict[str, object]) -> HttpResponse:
    return HttpResponse(200, {"Set-Cookie": "must-not-survive"}, json.dumps(value).encode())


class RecordingEnvironment(dict[str, str]):
    def __init__(self, values: dict[str, str]) -> None:
        super().__init__(values)
        self.reads: list[str] = []

    def get(self, key: str, default: str = "") -> str:
        self.reads.append(key)
        return super().get(key, default)


class ParallelPanelTransport:
    def __init__(
        self,
        prepared: execute.PreparedSuccessor,
        secrets: dict[str, str],
        *,
        generation_mutation: tuple[str, dict[str, object]] | None = None,
    ) -> None:
        self.prepared = prepared
        self.requests: list[HttpRequest] = []
        self.get_count = 0
        self.post_count = 0
        self.maximum_parallel_posts = 0
        self._active_posts = 0
        self._post_gate = asyncio.Event()
        self._metadata_urls: dict[str, str] = {}
        self._generation_urls: dict[str, str] = {}
        self.generation_mutation = generation_mutation
        for call in prepared.plan:
            secret = secrets[call.model.environment_variable]
            adapter = ProviderAdapter(call.model, self)
            self._metadata_urls[
                adapter.build_metadata_request(secret).url
            ] = call.model.model_key
            self._generation_urls[
                adapter.build_generation_request(secret, call.answer_messages()).url
            ] = call.model.model_key

    def metadata_response(self, key: str) -> HttpResponse:
        model = self.prepared.call_by_key[key].model
        if model.metadata_mode == "list":
            return http({"data": [{"id": model.requested_model_id}]})
        if model.metadata_mode == "openrouter-endpoints":
            return http(
                {
                    "data": {
                        "id": "openai/gpt-5.6-sol-20260709",
                        "endpoints": [{"provider_name": "OpenAI"}],
                    }
                }
            )
        if model.api_style == "google":
            return http({"name": f"models/{model.requested_model_id}"})
        return http({"id": model.requested_model_id})

    def generation_response(self, key: str) -> HttpResponse:
        model = self.prepared.call_by_key[key].model
        text = "One primary architecture is best for concrete public-law reasons."
        if model.api_style == "google":
            value: dict[str, object] = {
                "modelVersion": f"models/{model.requested_model_id}",
                "responseId": f"response-{key}",
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
            }
        elif model.api_style == "anthropic":
            value = {
                "id": f"response-{key}",
                "model": model.requested_model_id,
                "content": [{"type": "text", "text": text}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 20, "output_tokens": 10},
            }
        elif model.api_style == "cohere":
            value = {
                "id": f"response-{key}",
                "message": {"content": [{"type": "text", "text": text}]},
                "finish_reason": "COMPLETE",
                "usage": {"tokens": {"input_tokens": 20, "output_tokens": 10}},
            }
        elif model.api_style == "xai-responses":
            value = {
                "id": f"response-{key}",
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
            }
        else:
            returned = (
                "openai/gpt-5.6-sol-20260709"
                if key == "gpt"
                else model.requested_model_id
            )
            value = {
                "id": f"response-{key}",
                "model": returned,
                "provider": "OpenAI" if key == "gpt" else model.provider,
                "choices": [
                    {"message": {"content": text}, "finish_reason": "stop"}
                ],
                "usage": {
                    "prompt_tokens": 20,
                    "completion_tokens": 10,
                    "total_tokens": 30,
                },
            }
        if self.generation_mutation and self.generation_mutation[0] == key:
            value.update(self.generation_mutation[1])
        return http(value)

    async def send(self, request: HttpRequest) -> HttpResponse:
        self.requests.append(request)
        if request.method == "GET":
            if self.post_count:
                raise AssertionError("generation began before all preflights")
            self.get_count += 1
            return self.metadata_response(self._metadata_urls[request.url])
        if self.get_count != 8:
            raise AssertionError("generation began before eight metadata calls")
        self.post_count += 1
        self._active_posts += 1
        self.maximum_parallel_posts = max(
            self.maximum_parallel_posts, self._active_posts
        )
        if self.post_count == 8:
            self._post_gate.set()
        await asyncio.wait_for(self._post_gate.wait(), timeout=2)
        self._active_posts -= 1
        return self.generation_response(self._generation_urls[request.url])


class DivergenceSuccessorLiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        os.chmod(self.root, 0o700)
        self.patchers = [
            mock.patch.object(
                contract, "PAID_CALLS_AUTHORIZATION_ENABLED", True, create=True
            ),
            mock.patch.object(
                contract,
                "PAID_CALLS_AUTHORIZATION_STATEMENT",
                APPROVAL,
                create=True,
            ),
            mock.patch.object(
                contract,
                "PAID_CALLS_AUTHORIZATION_STATEMENT_SHA256",
                sha256_bytes(APPROVAL.encode()),
                create=True,
            ),
        ]
        for patcher in self.patchers:
            patcher.start()
        config = load_harness_config(SOURCE_ROOT / contract.MODELS_CONFIG_PATH)
        question_raw = json.loads((SOURCE_ROOT / contract.QUESTION_PATH).read_bytes())
        question_payload = (SOURCE_ROOT / contract.QUESTION_PATH).read_bytes()
        question = QuestionInput(
            SOURCE_ROOT / contract.QUESTION_PATH,
            question_raw,
            sha256_bytes(question_payload),
        )
        plan = build_plan(
            (question,),
            config.models,
            contract.SYSTEM_PROMPT,
            contract.STANDARD_CHALLENGE_PROMPT,
            answer_only=True,
        )
        cells = [
            {
                "cell_id": call.cell_id,
                "model_key": call.model.model_key,
                "prompt_sha256": prompt_sha256(call.answer_messages()),
                "requested_model_id": call.model.requested_model_id,
                "route": call.model.route,
                "requested_params": call.model.requested_params_receipt(),
                "semantic_attempt_number": 1,
                "maximum_generation_posts": 1,
            }
            for call in plan
        ]
        plan_sha = sha256_bytes(canonical_json_bytes(cells))
        lock_value = {
            "parent": {"quantum_disposition": {"sha256": "6" * 64}},
            "bindings": {
                "question": {"sha256": question.sha256},
                "models_config": {"sha256": config.sha256},
            },
            "plans": {
                "candidate_plans": [
                    {
                        "candidate_id": contract.CANDIDATE_ID,
                        "plan_sha256": plan_sha,
                        "cells": cells,
                    }
                ]
            },
            "paid_authorization": {"lock_authorizes_spending": False},
        }
        lock_bytes = canonical_json_bytes(lock_value)
        context = LockContext(
            repository_root=self.root,
            lock=lock_value,
            lock_bytes=lock_bytes,
            lock_sha256=sha256_bytes(lock_bytes),
            git_head="a" * 40,
            question_paths=(question.path,),
            candidate_plan_sha256={contract.CANDIDATE_ID: plan_sha},
        )
        self.prepared = execute.PreparedSuccessor(
            self.root,
            context,
            SimpleNamespace(value=lambda: lock_value["parent"]),
            SuccessorPaths.for_repository(self.root),
            config,
            question,
            plan,
            {call.model.model_key: call for call in plan},
        )
        authorization.write_authorization(
            context,
            statement=APPROVAL,
            authorized_at="2026-07-14T10:00:00Z",
        )
        evidence = []
        for call in plan:
            pricing = call.model.planning_pricing
            evidence.append(
                {
                    "model_key": call.model.model_key,
                    "requested_model_id": call.model.requested_model_id,
                    "provider": call.model.provider,
                    "route": call.model.route,
                    "input_per_million": pricing["input_per_million"],
                    "output_per_million": pricing["output_per_million"],
                    "source_url": SOURCE_URLS[call.model.model_key],
                }
            )
        authorization.write_pricing_recheck(
            context, evidence, checked_at="2026-07-14T10:01:00Z"
        )
        self.secrets = {
            call.model.environment_variable: f"secret-{call.model.model_key}"
            for call in plan
        }

    def tearDown(self) -> None:
        for patcher in reversed(self.patchers):
            patcher.stop()
        self.temporary.cleanup()

    def run_panel(
        self, *, mutation: tuple[str, dict[str, object]] | None = None
    ) -> tuple[engine.SuccessorExecutionResult, ParallelPanelTransport, RecordingEnvironment]:
        environment = RecordingEnvironment(self.secrets)
        transport = ParallelPanelTransport(
            self.prepared, self.secrets, generation_mutation=mutation
        )
        with mock.patch.object(
            execute, "prepare_successor", return_value=self.prepared
        ), mock.patch.object(
            execute, "verify_parent_snapshot", return_value=self.prepared.parent
        ):
            result = asyncio.run(
                engine._execute_prepared(
                    self.prepared,
                    environment=environment,
                    transport_factory=lambda: transport,
                )
            )
        return result, transport, environment

    def test_exact_live_fake_panel_parallel_generation_and_offline_review(self) -> None:
        result, transport, environment = self.run_panel()
        self.assertEqual(result.network_requests, 16)
        self.assertEqual([item.method for item in transport.requests], ["GET"] * 8 + ["POST"] * 8)
        self.assertEqual(transport.maximum_parallel_posts, 8)
        self.assertEqual(environment.reads, list(self.secrets))
        self.assertEqual(result.payload["successful_outcome_count"], 8)
        self.assertNotIn("response_text", json.dumps(result.payload))
        self.assertFalse(result.payload["network_contract"]["tools_enabled"])

        for call in self.prepared.plan:
            secret = self.secrets[call.model.environment_variable]
            adapter = ProviderAdapter(call.model, transport)
            expected_get = adapter.build_metadata_request(secret)
            expected_post = adapter.build_generation_request(
                secret, call.answer_messages()
            )
            self.assertIn(expected_get, transport.requests)
            self.assertIn(expected_post, transport.requests)

        private = self.prepared.paths.private_root
        self.assertEqual(len(list((private / "preflight/intents").rglob("*.json"))), 8)
        self.assertEqual(len(list((private / "preflight/raw-responses").rglob("*.json"))), 8)
        self.assertEqual(len(list((private / "preflight/outcomes").rglob("*.json"))), 8)
        self.assertEqual(len(list((private / "generation/intents").rglob("*.json"))), 8)
        self.assertEqual(len(list((private / "generation/raw-responses").rglob("*.json"))), 8)
        self.assertEqual(len(list((private / "generation/outcomes").rglob("*.json"))), 8)
        artifact_text = "\n".join(
            path.read_text("utf-8") for path in private.rglob("*.json")
        )
        self.assertNotIn("must-not-survive", artifact_text)
        for secret in self.secrets.values():
            self.assertNotIn(secret, artifact_text)

        facts = {
            "git_head": self.prepared.lock_context.git_head,
            "lock_sha256": self.prepared.lock_context.lock_sha256,
            "question_sha256": self.prepared.question.sha256,
            "plan_sha256": self.prepared.lock_context.candidate_plan_sha256[
                contract.CANDIDATE_ID
            ],
            "review_assets_sha256": "f" * 64,
        }
        with mock.patch.object(
            execute, "prepare_successor", return_value=self.prepared
        ), mock.patch.object(review, "_review_lock_facts", return_value=facts):
            bundle = review.load_candidate_responses(
                self.root, contract.CANDIDATE_ID
            )
        self.assertEqual(
            tuple(item.model_key for item in bundle.responses), contract.MODEL_KEYS
        )
        self.assertTrue(all(item.response_text.strip() for item in bundle.responses))

        empty_environment = RecordingEnvironment({})
        forbidden_transport = mock.Mock(side_effect=AssertionError("network"))
        with mock.patch.object(
            execute, "prepare_successor", return_value=self.prepared
        ), mock.patch.object(
            execute, "verify_parent_snapshot", return_value=self.prepared.parent
        ):
            resumed = asyncio.run(
                engine._execute_prepared(
                    self.prepared,
                    environment=empty_environment,
                    transport_factory=forbidden_transport,
                )
            )
        self.assertEqual(resumed.sha256, result.sha256)
        self.assertEqual(resumed.network_requests, 0)
        self.assertEqual(empty_environment.reads, [])
        forbidden_transport.assert_not_called()

    def test_camel_case_grounding_artifact_is_durable_then_terminal(self) -> None:
        with self.assertRaisesRegex(
            execute.DivergenceSuccessorExecutionError, "no retry allowed"
        ):
            self.run_panel(
                mutation=(
                    "gemini",
                    {
                        "groundingMetadata": {
                            "webSearchQueries": ["frontier AI licensing"]
                        }
                    },
                )
            )
        self.assertFalse(self.prepared.paths.composite.exists())
        raw = self.prepared.paths.generation_raw("gemini")
        outcome = self.prepared.paths.generation_outcome("gemini")
        self.assertTrue(raw.exists())
        self.assertTrue(outcome.exists())
        self.assertEqual(json.loads(outcome.read_bytes())["status"], "error")
        empty_environment = RecordingEnvironment({})
        forbidden_transport = mock.Mock(side_effect=AssertionError("network"))
        with mock.patch.object(
            execute, "prepare_successor", return_value=self.prepared
        ), mock.patch.object(
            execute, "verify_parent_snapshot", return_value=self.prepared.parent
        ), self.assertRaisesRegex(
            execute.DivergenceSuccessorExecutionError, "no retry allowed"
        ):
            asyncio.run(
                engine._execute_prepared(
                    self.prepared,
                    environment=empty_environment,
                    transport_factory=forbidden_transport,
                )
            )
        self.assertEqual(empty_environment.reads, [])
        forbidden_transport.assert_not_called()

    def test_one_failed_preflight_blocks_every_generation(self) -> None:
        environment = RecordingEnvironment(self.secrets)
        transport = ParallelPanelTransport(self.prepared, self.secrets)
        original = transport.metadata_response

        def substituted(key: str) -> HttpResponse:
            if key == "gemini":
                return http({"name": "models/gemini-substitute"})
            return original(key)

        transport.metadata_response = substituted  # type: ignore[method-assign]
        with mock.patch.object(
            execute, "prepare_successor", return_value=self.prepared
        ), mock.patch.object(
            execute, "verify_parent_snapshot", return_value=self.prepared.parent
        ), self.assertRaisesRegex(
            execute.DivergenceSuccessorExecutionError, "preflight"
        ):
            asyncio.run(
                engine._execute_prepared(
                    self.prepared,
                    environment=environment,
                    transport_factory=lambda: transport,
                )
            )
        self.assertEqual(transport.get_count, 8)
        self.assertEqual(transport.post_count, 0)
        self.assertFalse(self.prepared.paths.manifest.exists())
        self.assertFalse(self.prepared.paths.composite.exists())

    def test_later_stranded_preflight_stops_before_secret_lookup(self) -> None:
        paid = authorization.validate_authorization(self.prepared.lock_context)
        pricing = authorization.validate_pricing_recheck(
            self.prepared.lock_context, paid, fresh=False
        )
        authority_value = engine.Authority(paid, pricing)
        call = self.prepared.call_by_key["claude"]
        write_record(
            self.prepared.paths.preflight_intent("claude"),
            engine._preflight_intent_payload(
                self.prepared,
                authority_value,
                call,
                created_at="2026-07-14T10:02:00Z",
            ),
        )
        environment = RecordingEnvironment(self.secrets)
        forbidden_transport = mock.Mock(side_effect=AssertionError("network"))
        with mock.patch.object(
            execute, "prepare_successor", return_value=self.prepared
        ), mock.patch.object(
            execute, "verify_parent_snapshot", return_value=self.prepared.parent
        ), self.assertRaisesRegex(
            execute.DivergenceSuccessorExecutionError, "stranded preflight"
        ):
            asyncio.run(
                engine._execute_prepared(
                    self.prepared,
                    environment=environment,
                    transport_factory=forbidden_transport,
                )
            )
        self.assertEqual(environment.reads, [])
        forbidden_transport.assert_not_called()

    def test_composite_rejects_extra_answers_field(self) -> None:
        result, _, _ = self.run_panel()
        injected = copy.deepcopy(result.payload)
        injected["answers"] = ["private response text"]
        with self.assertRaisesRegex(
            composite.DivergenceSuccessorCompositeError, "top-level fields"
        ):
            composite.validate_composite_value(self.prepared, injected)

    def test_exact_outcome_and_manifest_bindings_reject_tampering(self) -> None:
        self.run_panel()
        paid = authorization.validate_authorization(self.prepared.lock_context)
        pricing = authorization.validate_pricing_recheck(
            self.prepared.lock_context, paid, fresh=False
        )
        authority_value = engine.Authority(paid, pricing)
        manifest = read_record(self.prepared.paths.manifest, "manifest")
        preflights = asyncio.run(
            engine.validate_manifest_record(
                self.prepared, authority_value, manifest
            )
        )
        key = "grok"
        outcome = read_record(
            self.prepared.paths.generation_outcome(key), "outcome"
        )
        intent = read_record(
            self.prepared.paths.generation_intent(key), "intent"
        )
        raw = read_record(self.prepared.paths.generation_raw(key), "raw")
        changed = copy.deepcopy(outcome.payload)
        changed["request_json_body_sha256"] = "0" * 64
        forged = JournalRecord(outcome.path, changed, outcome.sha256)
        with self.assertRaisesRegex(
            execute.DivergenceSuccessorExecutionError,
            "request, raw response, or response hash",
        ):
            asyncio.run(
                engine.validate_generation_record(
                    self.prepared,
                    authority_value,
                    manifest,
                    preflights[key],
                    self.prepared.call_by_key[key],
                    intent,
                    raw,
                    forged,
                )
            )

        changed_intent = copy.deepcopy(intent.payload)
        changed_intent["request_origin"] = "https://attacker.invalid"
        forged_intent = JournalRecord(intent.path, changed_intent, intent.sha256)
        with self.assertRaisesRegex(
            execute.DivergenceSuccessorExecutionError,
            "exact locked request",
        ):
            asyncio.run(
                engine.validate_generation_record(
                    self.prepared,
                    authority_value,
                    manifest,
                    preflights[key],
                    self.prepared.call_by_key[key],
                    forged_intent,
                    raw,
                    outcome,
                )
            )

        changed_manifest = copy.deepcopy(manifest.payload)
        changed_manifest["plan_sha256"] = "0" * 64
        forged_manifest = JournalRecord(
            manifest.path, changed_manifest, manifest.sha256
        )
        with self.assertRaisesRegex(
            execute.DivergenceSuccessorExecutionError, "manifest differs"
        ):
            asyncio.run(
                engine.validate_manifest_record(
                    self.prepared, authority_value, forged_manifest
                )
            )

    def test_composite_semantically_reconciles_authority_and_pricing(self) -> None:
        self.run_panel()
        paid = authorization.validate_authorization(self.prepared.lock_context)
        pricing = authorization.validate_pricing_recheck(
            self.prepared.lock_context, paid, fresh=False
        )
        record = read_record(self.prepared.paths.composite, "composite")
        altered_payload = copy.deepcopy(paid.payload)
        altered_payload["status"] = "forged"
        altered = authorization.AuthorizationBinding(
            paid.path, altered_payload, paid.sha256
        )
        with self.assertRaisesRegex(
            composite.DivergenceSuccessorCompositeError, "authority or pricing"
        ):
            asyncio.run(
                composite.validate_composite_record(
                    self.prepared,
                    engine.Authority(altered, pricing),
                    record,
                )
            )


if __name__ == "__main__":
    unittest.main()
