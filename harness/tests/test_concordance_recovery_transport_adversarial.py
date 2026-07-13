from __future__ import annotations

import asyncio
import base64
import json
import stat
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from concordance_harness.config import load_harness_config
from concordance_harness.providers import (
    HttpRequest,
    HttpResponse,
    ProviderAdapter,
    ProviderError,
)
from concordance_recovery.authorization import ReceiptBinding
from concordance_recovery.execute import (
    Authority,
    RecoveryExecutionError,
    _ensure_claim,
    _parse_generation_capture,
    _raw_common,
    _validate_recovery_inventory,
)
from concordance_recovery.journal import (
    RecoveryJournalError,
    raw_response_payload,
    read_record,
    validate_raw_response,
    write_record,
)
from concordance_recovery.transport import (
    CapturedReplayTransport,
    DurableCaptureTransport,
)
from concordance_recovery.state import RecoveryPaths

from support import repository_root


class RecordingTransport:
    def __init__(self, response: HttpResponse) -> None:
        self.response = response
        self.requests: list[HttpRequest] = []

    async def send(self, request: HttpRequest) -> HttpResponse:
        self.requests.append(request)
        return self.response


class ConcordanceRecoveryTransportAdversarialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.private = self.root / "private-recovery"
        self.config = load_harness_config(
            repository_root() / "harness/config/models.json"
        )
        self.models = self.config.by_key()
        self.common = {
            "recovery_id": "synthetic-recovery",
            "git_head": "a" * 40,
            "recovery_lock_sha256": "b" * 64,
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def intent(self, *, attempt: int = 1, name: str = "intent"):
        return write_record(
            self.private / "intents" / f"{name}.json",
            {
                "schema_version": "synthetic-intent-1.0.0",
                "semantic_attempt_number": attempt,
                "created_at": "2026-07-13T11:00:00+00:00",
            },
        )

    @staticmethod
    def messages() -> list[dict[str, str]]:
        return [
            {"role": "system", "content": "Synthetic system prompt."},
            {"role": "user", "content": "Synthetic recovery question."},
        ]

    def prepared_and_authority(self):
        prepared = SimpleNamespace(
            paths=SimpleNamespace(private_root=self.private),
            lock_context=SimpleNamespace(
                git_head="a" * 40,
                lock_sha256="b" * 64,
            ),
        )
        authority = Authority(
            authorization=ReceiptBinding(
                self.private / "paid-authorization.json", {}, "c" * 64
            ),
            pricing=ReceiptBinding(self.private / "pricing-recheck.json", {}, "d" * 64),
        )
        return prepared, authority

    def capture_for_generation(
        self,
        model_key: str,
        body: dict,
        *,
        preflight_id: str | None,
        request_override: HttpRequest | None = None,
    ):
        prepared, authority = self.prepared_and_authority()
        model = self.models[model_key]
        call = SimpleNamespace(model=model, answer_messages=self.messages)
        attempt = 2 if model_key == "cohere" else 1
        intent = self.intent(attempt=attempt, name=f"{model_key}-{attempt}")
        expected_request = ProviderAdapter(
            model, RecordingTransport(HttpResponse(500, {}, b""))
        ).build_generation_request("redacted-offline-secret", self.messages())
        captured_request = request_override or expected_request
        raw = write_record(
            self.private / "raw" / f"{model_key}-{attempt}.json",
            raw_response_payload(
                common=_raw_common(
                    prepared,
                    authority,
                    model_key=model_key,
                    attempt=attempt,
                ),
                intent=intent,
                private_root=self.private,
                request_kind="generation",
                request=captured_request,
                response=HttpResponse(
                    status=200,
                    headers={"Set-Cookie": "must-not-survive"},
                    body=json.dumps(body).encode("utf-8"),
                ),
                received_at="2026-07-13T12:00:00+00:00",
            ),
        )
        preflight = SimpleNamespace(
            payload={"provider_returned_model_id": preflight_id}
        )
        return prepared, authority, call, intent, raw, preflight, expected_request

    @staticmethod
    def generation_body(model_key: str, *, include_model: bool) -> dict:
        if model_key == "cohere":
            value = {
                "id": "synthetic-cohere-response",
                "message": {"content": [{"type": "text", "text": "Synthetic answer."}]},
                "finish_reason": "COMPLETE",
                "usage": {"tokens": {"input_tokens": 10, "output_tokens": 5}},
            }
        elif model_key == "grok":
            value = {
                "id": "synthetic-grok-response",
                "status": "completed",
                "output": [
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [
                            {"type": "output_text", "text": "Synthetic answer."}
                        ],
                    }
                ],
                "usage": {
                    "input_tokens": 10,
                    "output_tokens": 5,
                    "total_tokens": 15,
                },
            }
        else:
            value = {
                "id": f"synthetic-{model_key}-response",
                "choices": [
                    {
                        "message": {"content": "Synthetic answer."},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 5,
                    "total_tokens": 15,
                },
            }
        if include_model:
            value["model"] = model_key
        return value

    def test_raw_response_is_saved_before_provider_validation_and_omits_headers(
        self,
    ) -> None:
        model = self.models["cohere"]
        secret = "sentinel-cohere-secret"
        messages = self.messages()
        intent = self.intent(attempt=2)
        expected_request = ProviderAdapter(
            model, RecordingTransport(HttpResponse(500, {}, b""))
        ).build_generation_request(secret, messages)
        malformed = b"{this-is-not-json"
        delegate = RecordingTransport(
            HttpResponse(
                status=200,
                headers={
                    "Set-Cookie": "sentinel-cookie-secret",
                    "X-Reflected-Authorization": secret,
                },
                body=malformed,
            )
        )
        capture_path = self.private / "raw" / "cohere-attempt-2.json"
        capture = DurableCaptureTransport(
            delegate,
            capture_path=capture_path,
            private_root=self.private,
            common=self.common,
            intent=intent,
            request_kind="generation",
            expected_request=expected_request,
        )

        with self.assertRaisesRegex(ProviderError, "malformed JSON"):
            asyncio.run(ProviderAdapter(model, capture).generate(secret, messages))

        self.assertEqual(len(delegate.requests), 1)
        self.assertIsNotNone(capture.capture)
        self.assertTrue(capture_path.is_file())
        record = read_record(capture_path, "synthetic raw capture")
        self.assertEqual(record.payload["response"]["status"], 200)
        self.assertEqual(
            base64.b64decode(record.payload["response"]["body_base64"]), malformed
        )
        self.assertEqual(
            set(record.payload["response"]),
            {"status", "body_base64", "body_sha256"},
        )
        serialized = json.dumps(record.payload)
        self.assertNotIn("Set-Cookie", serialized)
        self.assertNotIn("sentinel-cookie-secret", serialized)
        self.assertNotIn(secret, serialized)
        self.assertEqual(stat.S_IMODE(capture_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(capture_path.parent.stat().st_mode), 0o700)

    def test_captured_replay_has_zero_network_and_is_single_use(self) -> None:
        model = self.models["cohere"]
        messages = self.messages()
        request = ProviderAdapter(
            model, RecordingTransport(HttpResponse(500, {}, b""))
        ).build_generation_request("redacted-offline-secret", messages)
        intent = self.intent(attempt=2)
        response = HttpResponse(
            status=200,
            headers={"Set-Cookie": "omitted"},
            body=json.dumps(self.generation_body("cohere", include_model=False)).encode(
                "utf-8"
            ),
        )
        raw = write_record(
            self.private / "raw" / "replay.json",
            raw_response_payload(
                common=self.common,
                intent=intent,
                private_root=self.private,
                request_kind="generation",
                request=request,
                response=response,
                received_at="2026-07-13T12:00:00+00:00",
            ),
        )
        replay = CapturedReplayTransport(
            raw,
            private_root=self.private,
            common=self.common,
            intent=intent,
            request_kind="generation",
            expected_request=request,
        )

        with mock.patch.object(
            urllib.request,
            "urlopen",
            side_effect=AssertionError("network access during captured replay"),
        ):
            result = asyncio.run(
                ProviderAdapter(model, replay).generate(
                    "redacted-offline-secret", messages
                )
            )
        self.assertIsNone(result.returned_model_id)
        self.assertTrue(replay.used)
        with self.assertRaisesRegex(RecoveryJournalError, "more than once"):
            asyncio.run(replay.send(request))

    def test_capture_rejects_request_mismatch_before_delegate_or_artifact(self) -> None:
        expected = HttpRequest(
            "POST",
            "https://api.example.test/v1/generate",
            {"Authorization": "Bearer expected-secret"},
            {"model": "expected", "input": "same"},
            30.0,
        )
        changed = HttpRequest(
            "POST",
            expected.url,
            {"Authorization": "Bearer expected-secret"},
            {"model": "changed", "input": "same"},
            30.0,
        )
        intent = self.intent()
        delegate = RecordingTransport(HttpResponse(200, {}, b"{}"))
        capture_path = self.private / "raw" / "mismatch.json"
        capture = DurableCaptureTransport(
            delegate,
            capture_path=capture_path,
            private_root=self.private,
            common=self.common,
            intent=intent,
            request_kind="generation",
            expected_request=expected,
        )

        with self.assertRaisesRegex(RecoveryJournalError, "unlocked request"):
            asyncio.run(capture.send(changed))
        self.assertEqual(delegate.requests, [])
        self.assertFalse(capture_path.exists())

    def test_capture_rejects_changed_auth_header_or_query_before_delegate(self) -> None:
        expected = HttpRequest(
            "POST",
            "https://api.example.test/v1/generate",
            {"Authorization": "Bearer expected-secret"},
            {"model": "fixed", "input": "same"},
            30.0,
        )
        changed_requests = (
            HttpRequest(
                expected.method,
                expected.url,
                {"Authorization": "Bearer substituted-secret"},
                expected.json_body,
                expected.timeout_seconds,
            ),
            HttpRequest(
                expected.method,
                expected.url + "?unlocked=true",
                expected.headers,
                expected.json_body,
                expected.timeout_seconds,
            ),
        )
        for index, changed in enumerate(changed_requests, start=1):
            with self.subTest(index=index):
                intent = self.intent(name=f"request-contract-{index}")
                delegate = RecordingTransport(HttpResponse(200, {}, b"{}"))
                capture_path = self.private / "raw" / f"request-contract-{index}.json"
                capture = DurableCaptureTransport(
                    delegate,
                    capture_path=capture_path,
                    private_root=self.private,
                    common=self.common,
                    intent=intent,
                    request_kind="generation",
                    expected_request=expected,
                )
                with self.assertRaisesRegex(RecoveryJournalError, "unlocked request"):
                    asyncio.run(capture.send(changed))
                self.assertEqual(delegate.requests, [])
                self.assertFalse(capture_path.exists())

    def test_preexisting_capture_blocks_delegate_and_cannot_be_replaced(self) -> None:
        request = HttpRequest(
            "POST",
            "https://api.example.test/v1/generate",
            {},
            {"model": "fixed"},
            30.0,
        )
        intent = self.intent()
        capture_path = self.private / "raw" / "existing.json"
        original = write_record(capture_path, {"evidence": "already durable"})
        delegate = RecordingTransport(HttpResponse(200, {}, b"{}"))
        capture = DurableCaptureTransport(
            delegate,
            capture_path=capture_path,
            private_root=self.private,
            common=self.common,
            intent=intent,
            request_kind="generation",
            expected_request=request,
        )

        with self.assertRaisesRegex(RecoveryJournalError, "cannot replace"):
            asyncio.run(capture.send(request))
        self.assertEqual(delegate.requests, [])
        self.assertEqual(
            read_record(capture_path, "existing capture").sha256, original.sha256
        )

    def test_dangling_capture_symlink_is_rejected_before_network(self) -> None:
        request = HttpRequest(
            "POST",
            "https://api.example.test/v1/generate",
            {},
            {"model": "fixed"},
            30.0,
        )
        intent = self.intent()
        capture_path = self.private / "raw" / "dangling.json"
        capture_path.parent.mkdir(mode=0o700)
        capture_path.symlink_to(self.root / "outside-does-not-exist.json")
        delegate = RecordingTransport(HttpResponse(200, {}, b"{}"))
        capture = DurableCaptureTransport(
            delegate,
            capture_path=capture_path,
            private_root=self.private,
            common=self.common,
            intent=intent,
            request_kind="generation",
            expected_request=request,
        )

        with self.assertRaises(RecoveryJournalError):
            asyncio.run(capture.send(request))
        self.assertEqual(
            delegate.requests,
            [],
            "a hostile capture target must be rejected before a paid POST",
        )
        self.assertTrue(capture_path.is_symlink())

    def test_private_records_enforce_modes_and_reject_symlink_components(self) -> None:
        record = write_record(
            self.private / "deep" / "record.json", {"status": "synthetic"}
        )
        self.assertEqual(stat.S_IMODE(record.path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(record.path.parent.stat().st_mode), 0o700)
        record.path.chmod(0o644)
        with self.assertRaisesRegex(RecoveryJournalError, "0600"):
            read_record(record.path, "public recovery record")

        redirect = self.root / "redirect"
        redirect.mkdir(mode=0o700)
        symlink_root = self.root / "symlink-private"
        symlink_root.symlink_to(redirect, target_is_directory=True)
        with self.assertRaisesRegex(RecoveryJournalError, "symlink"):
            write_record(symlink_root / "escaped.json", {"status": "forbidden"})
        self.assertFalse((redirect / "escaped.json").exists())

    def test_public_private_root_mode_is_rejected_before_capture_network(self) -> None:
        request = HttpRequest(
            "POST",
            "https://api.example.test/v1/generate",
            {},
            {"model": "fixed"},
            30.0,
        )
        intent = self.intent(name="private-root-mode")
        self.private.chmod(0o755)
        delegate = RecordingTransport(HttpResponse(200, {}, b"{}"))
        capture_path = self.private / "raw" / "public-root.json"
        capture = DurableCaptureTransport(
            delegate,
            capture_path=capture_path,
            private_root=self.private,
            common=self.common,
            intent=intent,
            request_kind="generation",
            expected_request=request,
        )

        with self.assertRaisesRegex(RecoveryJournalError, "0700"):
            asyncio.run(capture.send(request))
        self.assertEqual(delegate.requests, [])
        self.assertFalse(capture_path.exists())

    def test_raw_tampering_is_rejected_offline(self) -> None:
        request = HttpRequest(
            "POST",
            "https://api.example.test/v1/generate",
            {},
            {"model": "fixed"},
            30.0,
        )
        intent = self.intent()
        payload = raw_response_payload(
            common=self.common,
            intent=intent,
            private_root=self.private,
            request_kind="generation",
            request=request,
            response=HttpResponse(200, {}, b'{"ok":true}'),
            received_at="2026-07-13T12:00:00+00:00",
        )
        payload["response"]["body_sha256"] = "0" * 64
        raw = write_record(self.private / "raw" / "tampered.json", payload)

        with self.assertRaisesRegex(RecoveryJournalError, "body changed"):
            validate_raw_response(
                raw,
                expected_common=self.common,
                expected_intent=intent,
                private_root=self.private,
                request_kind="generation",
                expected_request=request,
            )

    def test_raw_capture_is_bound_to_the_exact_intent(self) -> None:
        request = HttpRequest(
            "POST",
            "https://api.example.test/v1/generate",
            {},
            {"model": "fixed"},
            30.0,
        )
        original_intent = self.intent(name="original-binding")
        different_intent = self.intent(name="different-binding")
        raw = write_record(
            self.private / "raw" / "intent-bound.json",
            raw_response_payload(
                common=self.common,
                intent=original_intent,
                private_root=self.private,
                request_kind="generation",
                request=request,
                response=HttpResponse(200, {}, b'{"ok":true}'),
                received_at="2026-07-13T12:00:00+00:00",
            ),
        )

        with self.assertRaisesRegex(RecoveryJournalError, "lineage differs"):
            validate_raw_response(
                raw,
                expected_common=self.common,
                expected_intent=different_intent,
                private_root=self.private,
                request_kind="generation",
                expected_request=request,
            )

    def test_raw_capture_cannot_predate_its_intent(self) -> None:
        request = HttpRequest(
            "POST",
            "https://api.example.test/v1/generate",
            {},
            {"model": "fixed"},
            30.0,
        )
        intent = write_record(
            self.private / "intents" / "chronology.json",
            {
                "schema_version": "synthetic-intent-1.0.0",
                "created_at": "2026-07-13T13:00:00+00:00",
            },
        )

        with self.assertRaisesRegex(RecoveryJournalError, "predates.*intent"):
            raw_response_payload(
                common=self.common,
                intent=intent,
                private_root=self.private,
                request_kind="generation",
                request=request,
                response=HttpResponse(200, {}, b'{"ok":true}'),
                received_at="2026-07-13T12:00:00+00:00",
            )

    def test_generation_state_before_manifest_is_rejected_offline(self) -> None:
        paths = RecoveryPaths.for_repository(self.root)
        write_record(
            paths.generation_intent("cohere", 2),
            {
                "schema_version": "synthetic-premature-generation-intent",
                "status": "reserved-before-generation-post",
            },
        )
        prepared = SimpleNamespace(paths=paths)

        with self.assertRaisesRegex(
            RecoveryExecutionError, "generation state.*preflight manifest"
        ):
            _validate_recovery_inventory(prepared)

    def test_composite_state_before_manifest_and_outcomes_is_rejected_offline(
        self,
    ) -> None:
        paths = RecoveryPaths.for_repository(self.root)
        write_record(
            paths.composite,
            {
                "schema_version": "synthetic-premature-composite",
                "status": "complete",
            },
        )
        prepared = SimpleNamespace(paths=paths)

        with self.assertRaisesRegex(
            RecoveryExecutionError, "composite state.*preflight manifest"
        ):
            _validate_recovery_inventory(prepared)

    def test_recovery_inventory_rejects_unknown_empty_directory(self) -> None:
        paths = RecoveryPaths.for_repository(self.root)
        paths.private_root.mkdir(parents=True, mode=0o700)
        (paths.private_root / "unknown-empty-directory").mkdir(mode=0o700)

        with self.assertRaisesRegex(RecoveryExecutionError, "unexpected directory"):
            _validate_recovery_inventory(SimpleNamespace(paths=paths))

    def test_recovery_inventory_rejects_public_directory_modes(self) -> None:
        for relative in (Path("."), Path("preflight"), Path("preflight/intents")):
            with self.subTest(relative=relative):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    paths = RecoveryPaths.for_repository(root)
                    target = paths.private_root / relative
                    target.mkdir(parents=True, mode=0o700)
                    target.chmod(0o755)
                    with self.assertRaisesRegex(
                        RecoveryExecutionError,
                        "directories must remain mode 0700",
                    ):
                        _validate_recovery_inventory(SimpleNamespace(paths=paths))

    def test_downstream_state_cannot_backfill_a_missing_parent_claim(self) -> None:
        paths = RecoveryPaths.for_repository(self.root)
        write_record(
            paths.preflight_intent("cohere", 1),
            {
                "schema_version": "synthetic-existing-preflight-intent",
                "status": "reserved-before-metadata-get",
            },
        )
        stranded = write_record(
            self.root / "synthetic-parent" / "cohere-intent.json",
            {"status": "parent-stranded"},
        )
        prepared = SimpleNamespace(
            paths=paths,
            lock_context=SimpleNamespace(
                git_head="a" * 40,
                lock_sha256="b" * 64,
            ),
        )
        _, authority = self.prepared_and_authority()
        parent = SimpleNamespace(stranded_intent=stranded)

        with self.assertRaisesRegex(
            RecoveryExecutionError, "parent claim.*downstream state"
        ):
            _ensure_claim(prepared, authority, parent)
        self.assertFalse(paths.claim.exists())

    def test_cohere_null_generation_id_requires_exact_preflight_and_request_model(
        self,
    ) -> None:
        model = self.models["cohere"]
        body = self.generation_body("cohere", include_model=False)
        prepared, authority, call, intent, raw, preflight, expected_request = (
            self.capture_for_generation(
                "cohere",
                body,
                preflight_id=model.requested_model_id,
            )
        )
        result = asyncio.run(
            _parse_generation_capture(prepared, authority, call, intent, raw, preflight)
        )
        self.assertIsNone(result.returned_model_id)
        self.assertEqual(expected_request.json_body["model"], model.requested_model_id)

        wrong_preflight = SimpleNamespace(
            payload={"provider_returned_model_id": "another-cohere-model"}
        )
        with self.assertRaisesRegex(ProviderError, "exact request and fresh preflight"):
            asyncio.run(
                _parse_generation_capture(
                    prepared, authority, call, intent, raw, wrong_preflight
                )
            )

    def test_cohere_null_generation_id_rejects_a_changed_request_model(self) -> None:
        model = self.models["cohere"]
        normal = ProviderAdapter(
            model, RecordingTransport(HttpResponse(500, {}, b""))
        ).build_generation_request("redacted-offline-secret", self.messages())
        changed_body = dict(normal.json_body or {})
        changed_body["model"] = "another-cohere-model"
        changed_request = HttpRequest(
            normal.method,
            normal.url,
            normal.headers,
            changed_body,
            normal.timeout_seconds,
        )
        prepared, authority, call, intent, raw, preflight, _ = (
            self.capture_for_generation(
                "cohere",
                self.generation_body("cohere", include_model=False),
                preflight_id=model.requested_model_id,
                request_override=changed_request,
            )
        )

        with self.assertRaisesRegex(
            RecoveryJournalError, "request differs from the locked request"
        ):
            asyncio.run(
                _parse_generation_capture(
                    prepared, authority, call, intent, raw, preflight
                )
            )

    def test_null_generation_id_is_rejected_for_every_non_cohere_target(self) -> None:
        for model_key in ("qwen", "deepseek", "mistral", "grok", "gpt"):
            with self.subTest(model_key=model_key):
                model = self.models[model_key]
                prepared, authority, call, intent, raw, preflight, _ = (
                    self.capture_for_generation(
                        model_key,
                        self.generation_body(model_key, include_model=False),
                        preflight_id=model.requested_model_id,
                    )
                )
                with self.assertRaisesRegex(
                    ProviderError, "lacks the exact returned model identifier"
                ):
                    asyncio.run(
                        _parse_generation_capture(
                            prepared, authority, call, intent, raw, preflight
                        )
                    )


if __name__ == "__main__":
    unittest.main()
