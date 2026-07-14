from __future__ import annotations

import asyncio
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from divergence_successor import (  # noqa: E402
    authorization,
    contract,
    engine,
    execute,
    lock,
    parent,
)
from divergence_successor.state import (  # noqa: E402
    DivergenceSuccessorStateError,
    SuccessorPaths,
    phase_lock,
)


class DivergenceSuccessorAdversarialTests(unittest.TestCase):
    def test_single_flight_cannot_create_a_file_before_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            contract,
            "PRIVATE_ROOT_RELATIVE",
            f".pilot/divergence-successor/{contract.POOL_ID}",
            create=True,
        ), mock.patch.object(
            authorization,
            "validate_authorization",
            side_effect=authorization.DivergenceSuccessorAuthorizationError(
                "disabled"
            ),
        ):
            paths = SuccessorPaths.for_repository(temporary)

            async def enter() -> None:
                async with phase_lock(paths.phase_lock, context=mock.Mock()):
                    self.fail("the disabled lock body ran")

            with self.assertRaises(
                authorization.DivergenceSuccessorAuthorizationError
            ):
                asyncio.run(enter())
            self.assertFalse(paths.phase_lock.exists())
            self.assertFalse(paths.private_root.exists())

    def test_boolean_attempt_is_not_an_integer_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            contract,
            "PRIVATE_ROOT_RELATIVE",
            f".pilot/divergence-successor/{contract.POOL_ID}",
            create=True,
        ):
            paths = SuccessorPaths.for_repository(temporary)
            with self.assertRaises(DivergenceSuccessorStateError):
                paths.preflight_intent("grok", True)

    def test_unknown_model_cannot_allocate_a_journal_lane(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            contract,
            "PRIVATE_ROOT_RELATIVE",
            f".pilot/divergence-successor/{contract.POOL_ID}",
            create=True,
        ):
            paths = SuccessorPaths.for_repository(temporary)
            with self.assertRaisesRegex(
                DivergenceSuccessorStateError, "outside the locked panel"
            ):
                paths.generation_outcome("attacker")

    def test_parent_contract_pins_disposition_and_old_lock(self) -> None:
        value = parent.expected_parent_contract()
        self.assertEqual(
            value["quantum_disposition"]["sha256"],
            "6a2b1e071b218ccb7a4bb1d94ce7b8ad4b681aebb5c5277a520588b0236833cc",
        )
        self.assertEqual(
            value["rule3_lock"]["sha256"],
            "8f4daf2ae53d07c7c53fc3f38d3ccd11aa18420185db632467fc9c280be523cc",
        )
        self.assertIs(value["old_pool_extended"], False)
        self.assertIs(value["old_responses_reused"], False)

    def test_tool_key_is_case_insensitive_and_nested(self) -> None:
        with self.assertRaisesRegex(
            execute.DivergenceSuccessorExecutionError, "forbidden"
        ):
            execute.reject_tool_artifacts(
                {"choices": [{"message": {"Tool_Calls": [{"id": "x"}]}}]}
            )

    def test_camel_case_web_queries_and_sources_are_forbidden(self) -> None:
        for artifact in (
            {"groundingMetadata": {"webSearchQueries": ["query"]}},
            {"answer": {"sources": [{"url": "https://example.invalid"}]}},
            {"output": [{"type": "web_search_call", "query": "query"}]},
            {"output": [{"type": "server-tool-use"}]},
            {"output": [{"type": "url-citation"}]},
            {"annotations": [{"type": "url_citation"}]},
            {"output": [{"type": "code_interpreter_call"}]},
            {"output": [{"type": "mcp_call"}]},
            {"output": [{"type": "mcp_list_tools"}]},
            {"output": [{"type": "mcp_approval_request"}]},
            {"output": [{"type": "local_shell_call"}]},
            {"output": [{"type": "custom_tool_call"}]},
            {"output": [{"type": "image_generation_call"}]},
        ):
            with self.subTest(artifact=artifact), self.assertRaisesRegex(
                execute.DivergenceSuccessorExecutionError, "forbidden"
            ):
                execute.reject_tool_artifacts(artifact)

    def test_preflight_requires_explicit_attempt_one(self) -> None:
        value = {
            "status": "success",
            "model_key": "grok",
            "requested_model_id": "grok-4.5",
            "provider_returned_model_id": "grok-4.5",
            "provider": "xai",
            "route": "xai-direct",
        }
        with self.assertRaisesRegex(
            execute.DivergenceSuccessorExecutionError, "differs"
        ):
            execute.validate_preflight_outcome(value, model_key="grok")

    def test_google_and_openrouter_canonical_aliases_are_approved(self) -> None:
        google = {
            "status": "success",
            "model_key": "gemini",
            "requested_model_id": "gemini-3.1-pro-preview",
            "provider_returned_model_id": "models/gemini-3.1-pro-preview",
            "provider": "google",
            "route": "google-direct",
            "attempt_number": 1,
        }
        gpt = {
            "status": "success",
            "model_key": "gpt",
            "requested_model_id": "openai/gpt-5.6-sol",
            "provider_returned_model_id": "openai/gpt-5.6-sol-20260709",
            "provider": "openrouter",
            "route": "openrouter-openai-pinned",
            "attempt_number": 1,
        }
        self.assertIs(
            execute.validate_preflight_outcome(google, model_key="gemini"), google
        )
        self.assertIs(execute.validate_preflight_outcome(gpt, model_key="gpt"), gpt)

    def test_generation_requires_the_exact_cell_id(self) -> None:
        value = {
            "status": "success",
            "candidate_id": contract.CANDIDATE_ID,
            "cell_id": "wrong-cell",
            "model_key": "grok",
            "requested_model_id": "grok-4.5",
            "provider_returned_model_id": "grok-4.5",
            "provider": "xai",
            "route": "xai-direct",
            "attempt_number": 1,
            "prompt_sha256": "a" * 64,
            "result": {"response_text": "A substantive answer."},
        }
        with self.assertRaisesRegex(
            execute.DivergenceSuccessorExecutionError, "differs"
        ):
            execute.validate_generation_outcome(
                value, model_key="grok", prompt_sha256="a" * 64
            )

    def test_internal_live_seam_gates_before_environment_or_transport(self) -> None:
        environment = mock.Mock()
        transport_factory = mock.Mock()
        prepared = mock.Mock()
        with mock.patch.object(
            authorization,
            "require_approval_enabled",
            side_effect=authorization.DivergenceSuccessorAuthorizationError(
                "disabled"
            ),
        ), self.assertRaises(
            authorization.DivergenceSuccessorAuthorizationError
        ):
            asyncio.run(
                engine._execute_prepared(
                    prepared,
                    environment=environment,
                    transport_factory=transport_factory,
                )
            )
        environment.get.assert_not_called()
        transport_factory.assert_not_called()

    def test_public_lock_write_requires_bound_sources_committed_first(self) -> None:
        prospective = {
            "bindings": {"question": {"path": "candidate/question.json"}},
            "execution_sources": [
                {"path": "harness/divergence_successor/contract.py"}
            ],
        }
        git_results = (
            subprocess.CompletedProcess([], 0, stdout=b"a" * 40 + b"\n"),
            subprocess.CompletedProcess(
                [],
                0,
                stdout=b" M harness/divergence_successor/contract.py\n",
            ),
        )
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            authorization, "require_approval_enabled"
        ), mock.patch.object(
            lock, "build_divergence_successor_lock", return_value=prospective
        ), mock.patch.object(
            lock, "_git", side_effect=git_results
        ), mock.patch.object(
            lock.os, "open"
        ) as open_file, self.assertRaisesRegex(
            contract.DivergenceSuccessorLockError,
            "committed and clean before lock creation",
        ):
            lock.write_divergence_successor_lock(temporary)
        open_file.assert_not_called()


if __name__ == "__main__":
    unittest.main()
