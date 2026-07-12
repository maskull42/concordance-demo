from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from concordance_harness.config import load_harness_config
from concordance_harness.providers import (
    ProviderAdapter,
    ProviderError,
    ProviderSubstitutionError,
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
        gpt_body = gpt.build_generation_request("secret", self.messages).json_body
        self.assertNotIn("temperature", gpt_body)
        self.assertEqual(gpt_body["max_tokens"], 16_384)
        self.assertEqual(gpt_body["service_tier"], "default")
        self.assertEqual(
            gpt_body["provider"],
            {"only": ["openai"], "allow_fallbacks": False, "require_parameters": True},
        )

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
                                "status": "incomplete",
                                "content": [
                                    {"type": "output_text", "text": "First. "},
                                    {"type": "output_text", "text": "Second."},
                                ],
                            },
                        ],
                        "status": "incomplete",
                        "incomplete_details": {"reason": "max_output_tokens"},
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
        self.assertEqual(result.finish_reason, "max_output_tokens")
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
