from __future__ import annotations

import importlib.util
import asyncio
import dataclasses
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]


def load_module():
    path = ROOT / "harness/run_quantum_fallback.py"
    spec = importlib.util.spec_from_file_location("run_quantum_fallback_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class QuantumFallbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()
        cls.module.committed_source_bindings = lambda: ("f" * 40, {})
        cls.context = cls.module.load_context()

    def test_exact_panel_and_plan_are_preserved(self) -> None:
        self.assertEqual(tuple(self.context.call_by_key), self.module.MODEL_ORDER)
        self.assertEqual(len(self.context.call_by_key), 8)
        self.assertEqual(
            self.module.PLAN_SHA256,
            "a553e6ea4c0447cc9ab7bf8772d564279bc7370bf7b0500f2fcc23790c2cf456",
        )

    def test_authorization_binds_the_user_approval_and_continuation(self) -> None:
        value = self.module.authorization_value(self.context, "2026-07-14T00:00:00Z")
        self.assertEqual(value["user_approval_verbatim"], "I approve")
        self.assertEqual(value["user_continuation_verbatim"], "Please continue")
        self.assertEqual(value["scope"]["maximum_generation_posts"], 8)
        self.assertEqual(value["scope"]["automatic_generation_retries"], 0)
        self.assertTrue(value["scope"]["parallel_generation_allowed"])

    def test_corrected_failure_is_the_only_fallback_authority(self) -> None:
        lineage = self.module.validate_private_lineage()
        threshold = lineage["fallback_eligibility"]["threshold_result"]
        self.assertFalse(threshold["qualifies"])
        self.assertEqual(threshold["represented_position_count"], 2)
        self.assertEqual(
            threshold["failure_reasons"],
            ["fewer-than-three-represented-positions"],
        )

    def test_budget_counts_priority_history_and_all_fallback_reservations(self) -> None:
        self.assertEqual(self.context.new_reserved_microdollars, 1_697_814)
        self.assertLessEqual(
            self.context.new_reserved_microdollars,
            self.module.CANDIDATE_CAP_MICRODOLLARS,
        )
        self.assertLessEqual(
            self.module.INHERITED_RESERVED_MICRODOLLARS
            + self.context.new_reserved_microdollars,
            self.module.POOL_CAP_MICRODOLLARS,
        )

    def test_every_receipt_declares_tools_and_external_context_disabled(self) -> None:
        value = self.module.authorization_value(self.context, "2026-07-14T00:00:00Z")[
            "scope"
        ]
        for key in (
            "tools_enabled",
            "web_search_enabled",
            "retrieval_enabled",
            "external_context_enabled",
            "third_candidate_allowed",
        ):
            self.assertFalse(value[key])
        for call in self.context.call_by_key.values():
            params = call.model.requested_params_receipt()
            self.assertFalse(params["tools_enabled"])
            self.assertFalse(params["web_search_enabled"])
            self.assertFalse(params["retrieval_enabled"])

    def test_generation_bodies_contain_no_tool_or_retrieval_route(self) -> None:
        provider_adapter = self.context.runtime["ProviderAdapter"]

        def keys(value):
            if isinstance(value, dict):
                return {str(key).casefold() for key in value} | {
                    item for child in value.values() for item in keys(child)
                }
            if isinstance(value, list):
                return {item for child in value for item in keys(child)}
            return set()

        for key, call in self.context.call_by_key.items():
            adapter = provider_adapter(call.model, object())
            request = adapter.build_generation_request(
                "synthetic-secret", call.answer_messages()
            )
            body = request.json_body
            self.assertIsInstance(body, dict)
            self.assertIn(body.get("tools"), (None, []), key)
            body_keys = keys(body)
            for forbidden in (
                "web_search",
                "x_search",
                "retrieval",
                "plugin",
                "file_search",
                "code_execution",
            ):
                self.assertNotIn(forbidden, body_keys, key)

    def test_gpt_route_remains_pinned_to_openai_without_fallback(self) -> None:
        call = self.context.call_by_key["gpt"]
        self.assertEqual(
            call.model.provider_options["provider"],
            {
                "only": ["openai"],
                "allow_fallbacks": False,
                "require_parameters": True,
            },
        )

    def test_fake_live_run_is_append_only_and_resumes_without_replay(self) -> None:
        from concordance_harness.providers import (
            HttpRequest,
            HttpResponse,
            PreflightResult,
            ProviderResult,
        )

        calls = []

        class FakeTransport:
            async def send(self, request):
                calls.append(request.method)
                return HttpResponse(200, {}, b"{}")

        class FakeAdapter:
            def __init__(self, config, transport):
                self.config = config
                self.transport = transport

            def build_metadata_request(self, secret):
                return HttpRequest(
                    "GET",
                    f"https://example.test/{self.config.model_key}/metadata",
                    {},
                    None,
                )

            def build_generation_request(self, secret, messages):
                return HttpRequest(
                    "POST",
                    f"https://example.test/{self.config.model_key}/generate",
                    {},
                    {"model": self.config.requested_model_id, "messages": messages},
                )

            async def preflight(self, secret):
                await self.transport.send(self.build_metadata_request(secret))
                return PreflightResult(
                    self.config.requested_model_id, self.config.provider, None
                )

            async def generate(self, secret, messages):
                await self.transport.send(
                    self.build_generation_request(secret, messages)
                )
                return ProviderResult(
                    response_text=f"answer from {self.config.model_key}",
                    returned_model_id=self.config.requested_model_id,
                    provider_response_id=f"response-{self.config.model_key}",
                    provider_name=self.config.provider,
                    finish_reason="complete",
                    usage={
                        "input_tokens": 10,
                        "output_tokens": 10,
                        "reasoning_tokens": 0,
                        "total_tokens": 20,
                    },
                    effective_params={},
                )

        runtime = dict(self.context.runtime)
        runtime["ProviderAdapter"] = FakeAdapter
        runtime["UrllibTransport"] = FakeTransport
        context = dataclasses.replace(self.context, runtime=runtime)
        environment = {
            model.environment_variable: f"secret-{model.model_key}"
            for model in context.config.models
        }
        saved_root = self.module.PRIVATE_ROOT
        try:
            with tempfile.TemporaryDirectory(
                dir=ROOT / ".pilot"
            ) as directory, mock.patch.dict("os.environ", environment, clear=True):
                self.module.PRIVATE_ROOT = Path(directory) / "private"
                first = asyncio.run(self.module.run_live(context))
                self.assertEqual(first["status"], "complete-eight-successes")
                self.assertEqual(first["successful_outcome_count"], 8)
                self.assertEqual(calls.count("GET"), 8)
                self.assertEqual(calls.count("POST"), 8)
                second = asyncio.run(self.module.run_live(context))
                self.assertEqual(second["run_sha256"], first["run_sha256"])
                self.assertEqual(len(calls), 16)
        finally:
            self.module.PRIVATE_ROOT = saved_root


if __name__ == "__main__":
    unittest.main()
