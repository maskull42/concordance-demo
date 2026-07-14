from __future__ import annotations

import asyncio
import copy
import io
import json
import os
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from concordance_harness.providers import (
    HttpRequest,
    HttpResponse,
    ProviderAdapter,
    ProviderError,
)
from concordance_harness.util import canonical_json_bytes, sha256_bytes
from concordance_recovery.journal import write_record
from divergence_successor import review as parent_review
from divergence_successor_continuation import (
    authorization,
    contract,
    correction,
    execute,
    review,
)
from divergence_successor_continuation.lock import LockContext
from divergence_successor_continuation import lock as continuation_lock
from divergence_successor_continuation.state import ContinuationPaths
from divergence_successor_continuation.transport import (
    NoRedirectHttpsTransport,
    _NoRedirect,
)
from rule3.budget import JournalRecord


SOURCE_ROOT = Path(__file__).resolve().parents[2]


def http(value: dict[str, object]) -> HttpResponse:
    return HttpResponse(200, {}, json.dumps(value).encode("utf-8"))


class ParallelGenerationTransport:
    def __init__(
        self, prepared: execute.PreparedContinuation, secrets: dict[str, str]
    ) -> None:
        self.prepared = prepared
        self.requests: list[HttpRequest] = []
        self.active = 0
        self.maximum_parallel = 0
        self.gate = asyncio.Event()
        self.by_url: dict[str, str] = {}
        for call in prepared.plan:
            secret = secrets[call.model.environment_variable]
            request = ProviderAdapter(call.model, self).build_generation_request(
                secret, call.answer_messages()
            )
            self.by_url[request.url] = call.model.model_key

    def response(self, key: str) -> HttpResponse:
        call = next(item for item in self.prepared.plan if item.model.model_key == key)
        model = call.model
        text = "Binding frontier supervision is the best primary legal architecture."
        if model.api_style == "google":
            return http(
                {
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
                        "totalTokenCount": 30,
                    },
                }
            )
        if model.api_style == "anthropic":
            return http(
                {
                    "id": f"response-{key}",
                    "model": model.requested_model_id,
                    "content": [{"type": "text", "text": text}],
                    "stop_reason": "end_turn",
                    "usage": {"input_tokens": 20, "output_tokens": 10},
                }
            )
        if model.api_style == "cohere":
            return http(
                {
                    "id": f"response-{key}",
                    "message": {"content": [{"type": "text", "text": text}]},
                    "finish_reason": "COMPLETE",
                    "usage": {"tokens": {"input_tokens": 20, "output_tokens": 10}},
                }
            )
        if model.api_style == "xai-responses":
            return http(
                {
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
            )
        returned = (
            "openai/gpt-5.6-sol-20260709" if key == "gpt" else model.requested_model_id
        )
        return http(
            {
                "id": f"response-{key}",
                "model": returned,
                "provider": "OpenAI" if key == "gpt" else model.provider,
                "choices": [{"message": {"content": text}, "finish_reason": "stop"}],
                "usage": {
                    "prompt_tokens": 20,
                    "completion_tokens": 10,
                    "total_tokens": 30,
                },
            }
        )

    async def send(self, request: HttpRequest) -> HttpResponse:
        if request.method != "POST":
            raise AssertionError("continuation issued a metadata request")
        self.requests.append(request)
        self.active += 1
        self.maximum_parallel = max(self.maximum_parallel, self.active)
        if len(self.requests) == 8:
            self.gate.set()
        await asyncio.wait_for(self.gate.wait(), timeout=2)
        self.active -= 1
        return self.response(self.by_url[request.url])


class OfflineCorrectionTests(unittest.TestCase):
    def test_exact_sealed_evidence_corrects_six_successes_and_two_false_negatives(
        self,
    ) -> None:
        value = asyncio.run(
            correction.build_correction_payload(
                SOURCE_ROOT, corrected_at="2026-07-14T15:00:00Z"
            )
        )
        self.assertEqual(value["false_negative_model_keys"], ["claude", "gpt"])
        self.assertEqual(value["method"]["network_requests"], 0)
        self.assertEqual(value["method"]["environment_variables_read"], 0)
        self.assertEqual(
            [
                (item["model_key"], item["original_status"], item["corrected_status"])
                for item in value["model_records"]
            ],
            [
                ("gemini", "success", "success"),
                ("claude", "error", "success"),
                ("cohere", "success", "success"),
                ("qwen", "success", "success"),
                ("deepseek", "success", "success"),
                ("mistral", "success", "success"),
                ("grok", "success", "success"),
                ("gpt", "error", "success"),
            ],
        )
        for item in value["model_records"]:
            self.assertFalse(item["request_body_present"])
            self.assertFalse(item["runtime_tool_artifact_present"])

    def test_hardcoded_preflight_hash_mismatch_fails_closed(self) -> None:
        altered = copy.deepcopy(contract.ORIGINAL_PREFLIGHT_SHA256)
        altered["claude"]["raw_response"] = "0" * 64
        with mock.patch.object(contract, "ORIGINAL_PREFLIGHT_SHA256", altered):
            with self.assertRaisesRegex(
                correction.OfflineCorrectionError, "approved preflight bytes changed"
            ):
                asyncio.run(
                    correction.build_correction_payload(
                        SOURCE_ROOT, corrected_at="2026-07-14T15:00:00Z"
                    )
                )

    def test_approval_hash_and_public_schema_are_exact(self) -> None:
        self.assertEqual(
            sha256_bytes(contract.APPROVAL_STATEMENT.encode("utf-8")),
            contract.APPROVAL_STATEMENT_SHA256,
        )
        schema = json.loads(
            (SOURCE_ROOT / contract.LOCK_SCHEMA_PATH).read_text("utf-8")
        )
        self.assertEqual(
            schema["properties"]["network_policy"]["properties"][
                "maximum_metadata_gets"
            ]["const"],
            0,
        )

    def test_redirect_is_terminal_and_never_follows_location(self) -> None:
        handler = _NoRedirect()
        original = urllib.request.Request("https://api.deepseek.com/chat/completions")
        self.assertIsNone(
            handler.redirect_request(
                original,
                None,
                302,
                "Found",
                {"Location": "https://attacker.invalid/collect"},
                "https://attacker.invalid/collect",
            )
        )
        with mock.patch.dict(
            os.environ,
            {"HTTPS_PROXY": "http://attacker.invalid:8080"},
            clear=False,
        ):
            transport = NoRedirectHttpsTransport()
        self.assertEqual(transport.proxy_handler.proxies, {})
        self.assertFalse(
            any(
                isinstance(item, urllib.request.ProxyHandler)
                for item in transport.opener.handlers
            )
        )
        opener = mock.Mock()
        opener.open.side_effect = urllib.error.HTTPError(
            original.full_url,
            302,
            "Found",
            {"Location": "https://attacker.invalid/collect"},
            io.BytesIO(b'{"redirect":true}'),
        )
        transport.opener = opener
        response = transport._send_sync(
            HttpRequest(
                "POST",
                original.full_url,
                {"Content-Type": "application/json"},
                {"model": "deepseek-v4-pro"},
            )
        )
        self.assertEqual(response.status, 302)
        opener.open.assert_called_once()
        with self.assertRaisesRegex(ProviderError, "POSTs only"):
            transport._send_sync(HttpRequest("GET", original.full_url, {}, None))

    def test_prospective_public_lock_validates_against_versioned_schema(self) -> None:
        import jsonschema

        fake = JournalRecord(
            SOURCE_ROOT / ".pilot/nonexistent-correction.json",
            {"status": "test-only"},
            "f" * 64,
        )
        real_private_binding = continuation_lock._private_binding

        def private_binding(root: Path, path: Path, label: str) -> dict[str, str]:
            if label == "offline correction receipt":
                return {
                    "path": contract.CORRECTION_RECEIPT_RELATIVE,
                    "sha256": "f" * 64,
                }
            return real_private_binding(root, path, label)

        with (
            mock.patch.object(
                correction, "verify_correction_record", return_value=fake
            ),
            mock.patch.object(
                continuation_lock, "_private_binding", side_effect=private_binding
            ),
        ):
            value = continuation_lock.build_lock(SOURCE_ROOT)
        schema = json.loads(
            (SOURCE_ROOT / contract.LOCK_SCHEMA_PATH).read_text("utf-8")
        )
        jsonschema.Draft202012Validator(schema).validate(value)
        self.assertEqual(len(value["parent"]["preflight_records"]), 8)
        self.assertEqual(
            sum(
                len(
                    {
                        item["intent"]["sha256"],
                        item["raw_response"]["sha256"],
                        item["outcome"]["sha256"],
                    }
                )
                for item in value["parent"]["preflight_records"]
            ),
            24,
        )


class ContinuationGenerationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        os.chmod(self.root, 0o700)
        parent, authority_value = correction.load_historical_parent(
            SOURCE_ROOT, fresh_pricing=False
        )
        self.parent = parent
        self.parent_authority = authority_value
        self.paths = ContinuationPaths.for_repository(self.root)
        self.correction_record = write_record(
            self.paths.correction,
            {"corrected_at": "2026-07-14T15:00:00Z"},
        )
        plan = parent.lock_context.lock["plans"]
        models = parent.lock_context.lock["models"]
        lock_value = {
            "plans": plan,
            "models": models,
            "parent": {
                "lock": {"sha256": parent.lock_context.lock_sha256},
                "authorization": {"sha256": authority_value.authorization.sha256},
                "pricing_recheck": {"sha256": authority_value.pricing.sha256},
            },
            "offline_correction": {"sha256": self.correction_record.sha256},
        }
        lock_bytes = canonical_json_bytes(lock_value)
        context = LockContext(
            self.root,
            lock_value,
            lock_bytes,
            sha256_bytes(lock_bytes),
            "b" * 40,
        )
        self.prepared = execute.PreparedContinuation(
            self.root,
            context,
            parent,
            authority_value,
            self.correction_record,
            self.paths,
            parent.plan,
        )
        self.paid = write_record(
            self.paths.authorization,
            {"authorized_at": "2026-07-14T15:01:00Z"},
        )
        self.secrets = {
            call.model.environment_variable: f"secret-{call.model.model_key}"
            for call in self.prepared.plan
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_zero_preflights_eight_parallel_one_shot_posts_and_offline_resume(
        self,
    ) -> None:
        transport = ParallelGenerationTransport(self.prepared, self.secrets)
        with (
            mock.patch.object(
                execute, "prepare_continuation", return_value=self.prepared
            ),
            mock.patch.object(
                authorization, "validate_authorization", return_value=self.paid
            ),
            mock.patch.object(
                authorization,
                "validate_fresh_historical_pricing",
                return_value=(self.parent, self.parent_authority),
            ),
        ):
            result = asyncio.run(
                execute._under_lock(
                    self.prepared,
                    environment=self.secrets,
                    transport_factory=lambda: transport,
                )
            )
        self.assertEqual(result.network_requests, 8)
        self.assertEqual(len(transport.requests), 8)
        self.assertEqual({item.method for item in transport.requests}, {"POST"})
        self.assertEqual(transport.maximum_parallel, 8)
        self.assertEqual(result.payload["network_contract"]["new_metadata_requests"], 0)
        self.assertNotIn("response_text", json.dumps(result.payload))
        for kind in ("intents", "raw-responses", "outcomes"):
            self.assertEqual(
                len(
                    list(
                        (self.paths.private_root / "generation" / kind).rglob("*.json")
                    )
                ),
                8,
            )

        forbidden = mock.Mock(side_effect=AssertionError("network reopened"))
        with (
            mock.patch.object(
                execute, "prepare_continuation", return_value=self.prepared
            ),
            mock.patch.object(
                authorization, "validate_authorization", return_value=self.paid
            ),
        ):
            resumed = asyncio.run(
                execute._under_lock(
                    self.prepared,
                    environment={},
                    transport_factory=forbidden,
                )
            )
        self.assertEqual(resumed.network_requests, 0)
        self.assertEqual(resumed.sha256, result.sha256)
        forbidden.assert_not_called()

        records: list[parent_review.ResponseRecord] = []
        cells = self.prepared.lock_context.lock["plans"]["candidate_plans"][0]["cells"]
        for cell in cells:
            outcome = json.loads(
                self.paths.generation_outcome(cell["model_key"]).read_text("utf-8")
            )
            records.append(
                parent_review.ResponseRecord(
                    candidate_id=contract.CANDIDATE_ID,
                    cell_id=cell["cell_id"],
                    model_key=cell["model_key"],
                    provider=outcome["provider"],
                    requested_model_id=outcome["requested_model_id"],
                    response_id=outcome["result"]["provider_response_id"],
                    response_text=outcome["result"]["response_text"],
                    prompt_sha256=cell["prompt_sha256"],
                    outcome_path=self.paths.generation_outcome(cell["model_key"])
                    .relative_to(self.root)
                    .as_posix(),
                    outcome_sha256=sha256_bytes(
                        self.paths.generation_outcome(cell["model_key"]).read_bytes()
                    ),
                    attempt_number=1,
                )
            )
        bundle = parent_review.ResponseBundle(
            contract.CANDIDATE_ID,
            {"run_receipt_sha256": result.sha256},
            tuple(records),
        )
        question_payload = (
            SOURCE_ROOT / contract.parent_contract.QUESTION_PATH
        ).read_bytes()
        question = json.loads(question_payload)
        with (
            mock.patch.object(review, "load_candidate_responses", return_value=bundle),
            mock.patch.object(
                parent_review,
                "_load_question",
                return_value=(question, question_payload),
            ),
        ):
            blind_path = review.publish_blind_materials(self.root)
            verified = review.verify_blind_materials(self.root)
        self.assertTrue(
            blind_path.is_relative_to(self.root / contract.REVIEW_ROOT_RELATIVE)
        )
        self.assertEqual(verified["packet"]["item_count"], 8)
        public = json.dumps(verified["packet"])
        self.assertNotIn("model_key", public)
        self.assertNotIn("requested_model_id", public)

    def test_provider_specific_generation_tool_artifacts_fail(self) -> None:
        with self.assertRaisesRegex(
            execute.ContinuationExecutionError, "tool artifact"
        ):
            execute._reject_generation_artifacts(
                "claude", {"content": [{"type": "tool_use", "name": "search"}]}
            )
        with self.assertRaisesRegex(
            execute.ContinuationExecutionError, "tool or citation"
        ):
            execute._reject_generation_artifacts(
                "gpt",
                {
                    "choices": [
                        {
                            "message": {
                                "content": "answer",
                                "tool_calls": [{"id": "1"}],
                            },
                            "finish_reason": "stop",
                        }
                    ]
                },
            )

    def test_partial_state_never_reopens_unstarted_cells(self) -> None:
        call = self.prepared.plan[0]
        write_record(
            self.paths.generation_intent(call.model.model_key),
            {"created_at": "2026-07-14T15:02:00Z"},
        )
        with (
            mock.patch.object(
                execute, "prepare_continuation", return_value=self.prepared
            ),
            mock.patch.object(
                authorization, "validate_authorization", return_value=self.paid
            ),
            self.assertRaisesRegex(execute.ContinuationExecutionError, "cannot reopen"),
        ):
            asyncio.run(
                execute._under_lock(
                    self.prepared,
                    environment=self.secrets,
                    transport_factory=mock.Mock(),
                )
            )


if __name__ == "__main__":
    unittest.main()
