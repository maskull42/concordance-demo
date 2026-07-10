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
        self.assertEqual(gemini_body["generationConfig"]["maxOutputTokens"], 900)

        claude = ProviderAdapter(self.models["claude"], FakeTransport([]))
        claude_body = claude.build_generation_request("secret", self.messages).json_body
        self.assertNotIn("temperature", claude_body)
        self.assertEqual(claude_body["max_tokens"], 900)

        cohere = ProviderAdapter(self.models["cohere"], FakeTransport([]))
        cohere_body = cohere.build_generation_request("secret", self.messages).json_body
        self.assertEqual(cohere_body["temperature"], 0.2)

        gpt = ProviderAdapter(self.models["gpt"], FakeTransport([]))
        gpt_body = gpt.build_generation_request("secret", self.messages).json_body
        self.assertNotIn("temperature", gpt_body)
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
                        "choices": [
                            {"message": {"content": "Text"}, "finish_reason": "stop"}
                        ],
                        "usage": {},
                    },
                )
            ]
        )
        adapter = ProviderAdapter(self.models["grok"], transport)
        with self.assertRaises(ProviderSubstitutionError):
            asyncio.run(adapter.generate("secret", self.messages))

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
