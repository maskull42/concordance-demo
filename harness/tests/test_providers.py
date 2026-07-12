from __future__ import annotations

import asyncio
import http.client
import ssl
import sys
import unittest
import urllib.error
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from concordance_harness.config import load_harness_config
from concordance_harness.providers import (
    HttpRequest,
    ProviderAdapter,
    ProviderError,
    ProviderSubstitutionError,
    UrllibTransport,
)

from support import FakeTransport, repository_root, response


class ProviderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        root = repository_root()
        cls.models = load_harness_config(root / "harness/config/models.json").by_key()
        cls.messages = [
            {"role": "system", "content": "System"},
            {"role": "user", "content": "Question"},
        ]

    def test_model_specific_request_parameters(self) -> None:
        gemini = ProviderAdapter(self.models["gemini"], FakeTransport([]))
        gemini_body = gemini.build_generation_request("secret", self.messages).json_body
        self.assertNotIn("temperature", gemini_body["generationConfig"])
        self.assertEqual(gemini_body["generationConfig"]["maxOutputTokens"], 16_384)

        claude = ProviderAdapter(self.models["claude"], FakeTransport([]))
        claude_body = claude.build_generation_request("secret", self.messages).json_body
        self.assertNotIn("temperature", claude_body)
        self.assertEqual(claude_body["max_tokens"], 16_384)

        cohere = ProviderAdapter(self.models["cohere"], FakeTransport([]))
        cohere_body = cohere.build_generation_request("secret", self.messages).json_body
        self.assertEqual(cohere_body["temperature"], 0.2)
        self.assertEqual(cohere_body["max_tokens"], 16_384)

        for key in ("qwen", "deepseek", "mistral"):
            body = ProviderAdapter(
                self.models[key], FakeTransport([])
            ).build_generation_request("secret", self.messages).json_body
            self.assertEqual(body["max_tokens"], 16_384)

        grok = ProviderAdapter(self.models["grok"], FakeTransport([]))
        grok_request = grok.build_generation_request("secret", self.messages)
        self.assertEqual(grok_request.url, "https://api.x.ai/v1/responses")
        self.assertEqual(grok_request.timeout_seconds, 3600.0)
        self.assertEqual(
            grok_request.json_body,
            {
                "model": "grok-4.5",
                "input": self.messages,
                "max_output_tokens": 16_384,
                "temperature": 0.2,
                "tools": [],
                "store": False,
                "service_tier": "default",
            },
        )
        receipt = self.models["grok"].requested_params_receipt()
        self.assertFalse(receipt["tools_enabled"])
        self.assertEqual(
            receipt["provider_options"],
            {"store": False, "service_tier": "default"},
        )

        gpt = ProviderAdapter(self.models["gpt"], FakeTransport([]))
        gpt_request = gpt.build_generation_request("secret", self.messages)
        gpt_body = gpt_request.json_body
        self.assertEqual(gpt_request.timeout_seconds, 3600.0)
        self.assertNotIn("temperature", gpt_body)
        self.assertEqual(gpt_body["model"], "openai/gpt-5.6-sol")
        self.assertEqual(gpt_body["max_tokens"], 16_384)
        self.assertEqual(gpt_body["service_tier"], "default")
        self.assertEqual(
            gpt_body["provider"],
            {"only": ["openai"], "allow_fallbacks": False, "require_parameters": True},
        )

    def test_openrouter_accepts_approved_canonical_id_in_preflight(self) -> None:
        transport = FakeTransport(
            [
                response(
                    200,
                    {
                        "data": {
                            "id": "openai/gpt-5.6-sol-20260709",
                            "endpoints": [{"provider_name": "OpenAI"}],
                        }
                    },
                )
            ]
        )
        result = asyncio.run(
            ProviderAdapter(self.models["gpt"], transport).preflight("secret")
        )
        self.assertEqual(result.returned_model_id, "openai/gpt-5.6-sol-20260709")
        self.assertEqual(result.provider_name, "OpenAI")
        self.assertIn(
            "/models/openai/gpt-5.6-sol/endpoints", transport.requests[0].url
        )

    def test_openrouter_accepts_approved_canonical_id_in_generation(self) -> None:
        transport = FakeTransport(
            [
                response(
                    200,
                    {
                        "id": "response-1",
                        "model": "openai/gpt-5.6-sol-20260709",
                        "provider": "OpenAI",
                        "choices": [
                            {
                                "message": {"content": "Complete answer"},
                                "finish_reason": "stop",
                            }
                        ],
                        "usage": {},
                    },
                )
            ]
        )
        adapter = ProviderAdapter(self.models["gpt"], transport)
        result = asyncio.run(adapter.generate("secret", self.messages))
        self.assertEqual(result.returned_model_id, "openai/gpt-5.6-sol-20260709")
        self.assertEqual(
            transport.requests[0].json_body["model"], "openai/gpt-5.6-sol"
        )
        self.assertEqual(
            transport.requests[0].json_body["provider"],
            {
                "only": ["openai"],
                "allow_fallbacks": False,
                "require_parameters": True,
            },
        )

    def test_openrouter_canonical_identity_policy_is_closed_and_exact(self) -> None:
        adapter = ProviderAdapter(self.models["gpt"], FakeTransport([]))
        for returned in (
            "openai/gpt-5.6-sol-20260708",
            "openai/GPT-5.6-sol-20260709",
            "openai/gpt-5.6-sol-20260709-extra",
            "models/openai/gpt-5.6-sol-20260709",
        ):
            with self.subTest(returned=returned):
                with self.assertRaises(ProviderSubstitutionError):
                    adapter.assert_model_identity(returned)
        for altered_config in (
            replace(self.models["gpt"], provider="azure"),
            replace(self.models["gpt"], route="openrouter-unpinned"),
        ):
            with self.subTest(
                provider=altered_config.provider, route=altered_config.route
            ):
                with self.assertRaises(ProviderSubstitutionError):
                    ProviderAdapter(
                        altered_config, FakeTransport([])
                    ).assert_model_identity("openai/gpt-5.6-sol-20260709")

    def test_models_prefix_is_accepted_only_for_google(self) -> None:
        ProviderAdapter(
            self.models["gemini"], FakeTransport([])
        ).assert_model_identity("models/gemini-3.1-pro-preview")
        with self.assertRaises(ProviderSubstitutionError):
            ProviderAdapter(
                self.models["grok"], FakeTransport([])
            ).assert_model_identity("models/grok-4.5")

    def test_openrouter_generation_rejects_azure_provider(self) -> None:
        transport = FakeTransport(
            [
                response(
                    200,
                    {
                        "id": "response-1",
                        "model": "openai/gpt-5.6-sol-20260709",
                        "provider": "Azure",
                        "choices": [
                            {
                                "message": {"content": "Complete answer"},
                                "finish_reason": "stop",
                            }
                        ],
                        "usage": {},
                    },
                )
            ]
        )
        with self.assertRaises(ProviderSubstitutionError):
            asyncio.run(
                ProviderAdapter(self.models["gpt"], transport).generate(
                    "secret", self.messages
                )
            )

    def test_generation_transport_failure_is_not_blindly_retryable(self) -> None:
        class FailingTransport:
            async def send(self, request):
                raise ProviderError(
                    "provider request timed out",
                    category="timeout",
                    retryable=True,
                )

        adapter = ProviderAdapter(self.models["grok"], FailingTransport())
        with self.assertRaises(ProviderError) as context:
            asyncio.run(adapter.generate("secret", self.messages))
        self.assertEqual(context.exception.category, "timeout")
        self.assertFalse(context.exception.retryable)

    def test_response_read_failures_are_normalized_as_network_errors(self) -> None:
        request = HttpRequest(
            "POST", "https://example.invalid/v1/generate", {}, {}, 1.0
        )
        failures = (
            http.client.IncompleteRead(b"partial", 20),
            http.client.RemoteDisconnected("disconnected"),
            ConnectionResetError("reset"),
            ssl.SSLError("TLS ended"),
        )
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                with patch("urllib.request.urlopen", side_effect=failure):
                    with self.assertRaises(ProviderError) as context:
                        UrllibTransport()._send_sync(request)
                self.assertEqual(context.exception.category, "network")
                self.assertTrue(context.exception.retryable)

    def test_http_error_body_read_failure_is_normalized(self) -> None:
        request = HttpRequest(
            "POST", "https://example.invalid/v1/generate", {}, {}, 1.0
        )
        error = urllib.error.HTTPError(
            request.url, 500, "provider error", {}, None
        )
        error.read = Mock(
            side_effect=http.client.IncompleteRead(b"partial", 20)
        )
        with patch("urllib.request.urlopen", side_effect=error):
            with self.assertRaises(ProviderError) as context:
                UrllibTransport()._send_sync(request)
        self.assertEqual(context.exception.category, "network")
        self.assertTrue(context.exception.retryable)

    def test_request_repr_never_exposes_headers_body_or_query_key(self) -> None:
        adapter = ProviderAdapter(self.models["gemini"], FakeTransport([]))
        request = adapter.build_generation_request("very-secret-value", self.messages)
        rendered = repr(request)
        self.assertNotIn("very-secret-value", rendered)
        self.assertIn("headers=<redacted>", rendered)
        self.assertIn("json_body=<redacted>", rendered)

    def test_returned_model_substitution_is_rejected(self) -> None:
        transport = FakeTransport(
            [
                response(
                    200,
                    {
                        "id": "response-1",
                        "model": "another-model",
                        "output": [
                            {
                                "type": "message",
                                "role": "assistant",
                                "content": [{"type": "output_text", "text": "Text"}],
                            }
                        ],
                        "status": "completed",
                        "usage": {},
                    },
                )
            ]
        )
        adapter = ProviderAdapter(self.models["grok"], transport)
        with self.assertRaises(ProviderSubstitutionError):
            asyncio.run(adapter.generate("secret", self.messages))

    def test_xai_responses_output_and_inclusive_reasoning_usage_are_parsed(self) -> None:
        transport = FakeTransport(
            [
                response(
                    200,
                    {
                        "id": "response-1",
                        "model": "grok-4.5",
                        "output": [
                            {"type": "reasoning", "status": "completed"},
                            {
                                "type": "message",
                                "role": "assistant",
                                "status": "completed",
                                "content": [
                                    {"type": "output_text", "text": "First. "},
                                    {"type": "output_text", "text": "Second."},
                                ],
                            },
                        ],
                        "status": "completed",
                        "usage": {
                            "input_tokens": 120,
                            "input_tokens_details": {"cached_tokens": 40},
                            "output_tokens": 900,
                            "output_tokens_details": {"reasoning_tokens": 700},
                            "total_tokens": 1020,
                        },
                    },
                )
            ]
        )
        result = asyncio.run(
            ProviderAdapter(self.models["grok"], transport).generate(
                "secret", self.messages
            )
        )
        self.assertEqual(result.response_text, "First. Second.")
        self.assertEqual(result.returned_model_id, "grok-4.5")
        self.assertEqual(result.provider_response_id, "response-1")
        self.assertEqual(result.finish_reason, "completed")
        self.assertEqual(
            result.usage,
            {
                "input_tokens": 120,
                "output_tokens": 900,
                "reasoning_tokens": 700,
                "cache_read_tokens": 40,
                "cache_write_tokens": None,
                "total_tokens": 1020,
            },
        )
        self.assertEqual(
            result.effective_params["max_output_tokens"],
            {"state": "known", "value": 16_384, "source": "request"},
        )

    def test_incomplete_finish_state_is_never_a_successful_checkpoint(self) -> None:
        fixtures = {
            "gemini": {
                "modelVersion": "gemini-3.1-pro-preview",
                "candidates": [
                    {
                        "content": {"parts": [{"text": "Partial"}]},
                        "finishReason": "MAX_TOKENS",
                    }
                ],
                "usageMetadata": {},
            },
            "claude": {
                "id": "response-1",
                "model": "claude-fable-5",
                "content": [{"type": "text", "text": "Partial"}],
                "stop_reason": "max_tokens",
                "usage": {},
            },
            "cohere": {
                "id": "response-1",
                "message": {"content": [{"type": "text", "text": "Partial"}]},
                "finish_reason": "MAX_TOKENS",
                "usage": {},
            },
            "qwen": {
                "id": "response-1",
                "model": "Qwen/Qwen3.5-397B-A17B",
                "choices": [
                    {"message": {"content": "Partial"}, "finish_reason": "length"}
                ],
                "usage": {},
            },
            "deepseek": {
                "id": "response-1",
                "model": "deepseek-v4-pro",
                "choices": [
                    {"message": {"content": "Partial"}, "finish_reason": "length"}
                ],
                "usage": {},
            },
            "mistral": {
                "id": "response-1",
                "model": "mistral-large-2512",
                "choices": [
                    {"message": {"content": "Partial"}, "finish_reason": "length"}
                ],
                "usage": {},
            },
            "grok": {
                "id": "response-1",
                "model": "grok-4.5",
                "output": [
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": "Partial"}],
                    }
                ],
                "status": "incomplete",
                "incomplete_details": {"reason": "max_output_tokens"},
                "usage": {},
            },
            "gpt": {
                "id": "response-1",
                "model": "openai/gpt-5.6-sol",
                "provider": "OpenAI",
                "choices": [
                    {"message": {"content": "Partial"}, "finish_reason": "length"}
                ],
                "usage": {},
            },
        }
        for model_key, fixture in fixtures.items():
            with self.subTest(model_key=model_key):
                adapter = ProviderAdapter(
                    self.models[model_key], FakeTransport([response(200, fixture)])
                )
                with self.assertRaises(ProviderError) as context:
                    asyncio.run(adapter.generate("secret", self.messages))
                self.assertEqual(context.exception.category, "incomplete-output")
                self.assertFalse(context.exception.retryable)

    def test_xai_unavailability_stops_without_fallback(self) -> None:
        transport = FakeTransport([response(404, {"error": "not available in region"})])
        adapter = ProviderAdapter(self.models["grok"], transport)
        with self.assertRaises(ProviderError) as context:
            asyncio.run(adapter.preflight("secret"))
        self.assertEqual(context.exception.category, "unavailable")
        self.assertFalse(context.exception.retryable)
        self.assertEqual(len(transport.requests), 1)
        self.assertEqual(self.models["grok"].route, "xai-direct")

    def test_openrouter_metadata_requires_openai_endpoint(self) -> None:
        transport = FakeTransport(
            [
                response(
                    200,
                    {
                        "data": {
                            "id": "openai/gpt-5.6-sol",
                            "endpoints": [{"provider_name": "Azure"}],
                        }
                    },
                )
            ]
        )
        adapter = ProviderAdapter(self.models["gpt"], transport)
        with self.assertRaises(ProviderError) as context:
            asyncio.run(adapter.preflight("secret"))
        self.assertEqual(context.exception.category, "unavailable")


if __name__ == "__main__":
    unittest.main()
