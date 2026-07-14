from __future__ import annotations

import asyncio
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rule3.budget import JournalRecord  # noqa: E402

from divergence_successor import authorization, composite, contract, execute, lock  # noqa: E402
from divergence_successor.state import (  # noqa: E402
    DivergenceSuccessorStateError,
    SuccessorPaths,
    inspect_inventory,
)


SOURCE_ROOT = Path(__file__).resolve().parents[2]


def preflight(model_key: str) -> dict[str, object]:
    requested, provider, route = contract.EXPECTED_MODELS[model_key]
    return {
        "status": "success",
        "model_key": model_key,
        "requested_model_id": requested,
        "provider_returned_model_id": requested,
        "provider": provider,
        "route": route,
        "attempt_number": 1,
        "tool_calls": [],
    }


class DivergenceSuccessorPublicSkeletonTests(unittest.TestCase):
    def test_lock_constants_freeze_exact_one_attempt_policy(self) -> None:
        self.assertEqual(lock.EXPECTED_CONTRACT_VALUES["POOL_SIZE"], 1)
        self.assertEqual(lock.EXPECTED_CONTRACT_VALUES["ATTEMPTS_PER_CELL"], 1)
        self.assertEqual(lock.EXPECTED_CONTRACT_VALUES["OUTPUT_TOKEN_CAP"], 16_384)
        self.assertEqual(
            lock.EXPECTED_CONTRACT_VALUES["CANDIDATE_COST_CAP_MICRODOLLARS"],
            6_000_000,
        )
        self.assertEqual(
            lock.EXPECTED_CONTRACT_VALUES["POOL_COST_CAP_MICRODOLLARS"],
            6_000_000,
        )
        self.assertEqual(lock.EXPECTED_CONTRACT_VALUES["AUTOMATIC_RETRIES"], 0)
        self.assertIs(lock.EXPECTED_CONTRACT_VALUES["AUTHORIZATION_ENABLED"], False)

    def test_lock_is_eight_exact_routes_with_no_fallback(self) -> None:
        self.assertEqual(len(contract.MODEL_KEYS), 8)
        self.assertEqual(tuple(contract.EXPECTED_MODELS), contract.MODEL_KEYS)
        self.assertEqual(
            lock.EXPECTED_AUTHORIZED_HOSTS,
            (
                "generativelanguage.googleapis.com",
                "api.anthropic.com",
                "api.cohere.com",
                "api.deepinfra.com",
                "api.deepseek.com",
                "api.mistral.ai",
                "api.x.ai",
                "openrouter.ai",
            ),
        )

    def test_paid_authority_is_a_deliberate_later_gate(self) -> None:
        with mock.patch.object(
            authorization, "write_record"
        ) as write_record, self.assertRaises(
            authorization.DivergenceSuccessorAuthorizationError
        ):
            authorization.write_authorization(
                object(), statement="not approved", authorized_at="2026-07-14T00:00:00Z"
            )
        write_record.assert_not_called()
        readiness = authorization.approval_readiness()
        self.assertEqual(readiness["private_writes"], 0)
        self.assertEqual(readiness["network_requests"], 0)
        self.assertEqual(readiness["environment_variables_read"], 0)

    def test_live_entry_stops_before_every_external_side_effect(self) -> None:
        with mock.patch.object(
            authorization,
            "require_approval_enabled",
            side_effect=authorization.DivergenceSuccessorAuthorizationError(
                "disabled"
            ),
        ) as authority, mock.patch.object(
            execute, "prepare_successor"
        ) as prepare, self.assertRaises(
            authorization.DivergenceSuccessorAuthorizationError
        ):
            asyncio.run(execute.execute_live(SOURCE_ROOT))
        authority.assert_called_once_with()
        prepare.assert_not_called()

    def test_schema_parses_and_pins_nonspending_boundary(self) -> None:
        value = json.loads(
            (SOURCE_ROOT / "candidate/rule3-successor-lock.schema.json").read_text()
        )
        paid = value["properties"]["paid_authorization"]["properties"]
        policy = value["properties"]["execution_policy"]["properties"]
        self.assertEqual(paid["enabled"], {"const": False})
        self.assertEqual(paid["provider_calls_allowed"], {"const": False})
        self.assertEqual(policy["attempts_per_cell"], {"const": 1})
        self.assertEqual(policy["automatic_retries"], {"const": 0})

    def test_fresh_pricing_covers_exact_panel_and_respects_six_dollar_cap(self) -> None:
        source_urls = {
            "gemini": "https://ai.google.dev/gemini-api/docs/pricing",
            "claude": "https://docs.anthropic.com/en/docs/about-claude/pricing",
            "cohere": "https://cohere.com/pricing",
            "qwen": "https://deepinfra.com/pricing",
            "deepseek": "https://api-docs.deepseek.com/quick_start/pricing",
            "mistral": "https://mistral.ai/pricing",
            "grok": "https://docs.x.ai/docs/models",
            "gpt": "https://openrouter.ai/models/openai/gpt-5.6-sol",
        }
        evidence = []
        for key in contract.MODEL_KEYS:
            requested, provider, route = contract.EXPECTED_MODELS[key]
            evidence.append(
                {
                    "model_key": key,
                    "requested_model_id": requested,
                    "provider": provider,
                    "route": route,
                    "input_per_million": 2.0,
                    "output_per_million": 10.0,
                    "source_url": source_urls[key],
                }
            )
        with mock.patch.object(
            contract, "OUTPUT_TOKEN_CAP", 16_384, create=True
        ), mock.patch.object(
            contract, "CANDIDATE_COST_CAP_MICRODOLLARS", 6_000_000, create=True
        ), mock.patch.object(
            contract, "POOL_COST_CAP_MICRODOLLARS", 6_000_000, create=True
        ):
            normalized, reservation = authorization.normalize_pricing_evidence(
                evidence
            )
        self.assertEqual(tuple(item["model_key"] for item in normalized), contract.MODEL_KEYS)
        self.assertLess(reservation, 6_000_000)
        poisoned = copy.deepcopy(evidence)
        poisoned[6]["source_url"] = "https://example.org/xai-pricing"
        with mock.patch.object(
            contract, "OUTPUT_TOKEN_CAP", 16_384, create=True
        ), mock.patch.object(
            contract, "CANDIDATE_COST_CAP_MICRODOLLARS", 6_000_000, create=True
        ), mock.patch.object(
            contract, "POOL_COST_CAP_MICRODOLLARS", 6_000_000, create=True
        ), self.assertRaisesRegex(
            authorization.DivergenceSuccessorAuthorizationError, "not approved"
        ):
            authorization.normalize_pricing_evidence(poisoned)


class DivergenceSuccessorGateTests(unittest.TestCase):
    def test_all_eight_preflights_unlock_the_pure_gate(self) -> None:
        values = [preflight(key) for key in contract.MODEL_KEYS]
        result = execute.preflight_gate(values)
        self.assertEqual(tuple(result), contract.MODEL_KEYS)

    def test_seven_preflights_never_unlock_generation(self) -> None:
        with self.assertRaisesRegex(
            execute.DivergenceSuccessorExecutionError, "exactly eight"
        ):
            execute.preflight_gate(
                [preflight(key) for key in contract.MODEL_KEYS[:-1]]
            )

    def test_reordered_or_substituted_preflight_is_rejected(self) -> None:
        values = [preflight(key) for key in contract.MODEL_KEYS]
        values[0], values[1] = values[1], values[0]
        with self.assertRaisesRegex(
            execute.DivergenceSuccessorExecutionError, "differs"
        ):
            execute.preflight_gate(values)
        value = preflight("grok")
        value["provider_returned_model_id"] = "grok-substitute"
        with self.assertRaisesRegex(
            execute.DivergenceSuccessorExecutionError, "differs"
        ):
            execute.validate_preflight_outcome(value, model_key="grok")

    def test_tool_or_web_artifacts_are_rejected(self) -> None:
        value = preflight("grok")
        value["tool_calls"] = [{"name": "search"}]
        with self.assertRaisesRegex(
            execute.DivergenceSuccessorExecutionError, "forbidden"
        ):
            execute.validate_preflight_outcome(value, model_key="grok")
        with self.assertRaisesRegex(
            execute.DivergenceSuccessorExecutionError, "forbidden"
        ):
            execute.reject_tool_artifacts(
                {"nested": {"web_search": {"query": "outside context"}}}
            )

    def test_attempt_two_has_no_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            contract,
            "PRIVATE_ROOT_RELATIVE",
            f".pilot/divergence-successor/{contract.POOL_ID}",
            create=True,
        ):
            paths = SuccessorPaths.for_repository(temporary)
            with self.assertRaisesRegex(
                DivergenceSuccessorStateError, "exactly semantic attempt 1"
            ):
                paths.generation_intent("grok", 2)

    def test_stranded_intent_is_consumed_without_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            contract,
            "PRIVATE_ROOT_RELATIVE",
            f".pilot/divergence-successor/{contract.POOL_ID}",
            create=True,
        ):
            paths = SuccessorPaths.for_repository(temporary)
            intent = paths.generation_intent("grok")
            intent.parent.mkdir(parents=True)
            intent.write_text("{}\n")
            state = execute.cell_state(paths, "generation", "grok")
            self.assertEqual(state["status"], "consumed-stranded-no-replay")
            self.assertIs(state["network_replay_allowed"], False)

    def test_unknown_private_artifact_fails_exact_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            contract,
            "PRIVATE_ROOT_RELATIVE",
            f".pilot/divergence-successor/{contract.POOL_ID}",
            create=True,
        ):
            paths = SuccessorPaths.for_repository(temporary)
            paths.private_root.mkdir(parents=True)
            paths.private_root.chmod(0o700)
            unknown = paths.private_root / "attempt-2.json"
            unknown.write_text("{}\n")
            unknown.chmod(0o600)
            with self.assertRaisesRegex(
                DivergenceSuccessorStateError, "unexpected file"
            ):
                inspect_inventory(paths)


class DivergenceSuccessorCompositeTests(unittest.TestCase):
    def _fixture(self, root: Path) -> tuple[execute.PreparedSuccessor, list[JournalRecord]]:
        paths = SuccessorPaths.for_repository(root)
        cells = []
        records = []
        for index, key in enumerate(contract.MODEL_KEYS, 1):
            requested, provider, route = contract.EXPECTED_MODELS[key]
            prompt_sha = f"{index:064x}"
            cell = {
                "cell_id": f"{contract.CANDIDATE_ID}:{key}:default:answer",
                "model_key": key,
                "prompt_sha256": prompt_sha,
            }
            cells.append(cell)
            records.append(
                JournalRecord(
                    path=paths.generation_outcome(key),
                    payload={
                        "status": "success",
                        "candidate_id": contract.CANDIDATE_ID,
                        "cell_id": cell["cell_id"],
                        "model_key": key,
                        "provider": provider,
                        "route": route,
                        "requested_model_id": requested,
                        "provider_returned_model_id": requested,
                        "attempt_number": 1,
                        "prompt_sha256": prompt_sha,
                        "completed_at": "2026-07-14T11:59:00Z",
                        "result": {
                            "response_text": f"Fresh answer {index}",
                            "response_sha256": contract.sha256_bytes(
                                f"Fresh answer {index}".encode("utf-8")
                            ),
                            "provider_response_id": f"response-{index}",
                            "tool_calls": [],
                        },
                    },
                    sha256=f"{index:064x}",
                )
            )
        context = SimpleNamespace(
            lock={
                "bindings": {
                    "question": {"sha256": "a" * 64},
                    "models_config": {"sha256": "9" * 64},
                },
                "plans": {
                    "candidate_plans": [
                        {
                            "candidate_id": contract.CANDIDATE_ID,
                            "plan_sha256": "b" * 64,
                            "cells": cells,
                        }
                    ]
                },
            },
            lock_sha256="c" * 64,
            git_head="d" * 40,
        )
        prepared = execute.PreparedSuccessor(root, context, mock.sentinel.parent, paths)
        return prepared, records

    def test_composite_is_exact_and_response_free(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            contract,
            "PRIVATE_ROOT_RELATIVE",
            f".pilot/divergence-successor/{contract.POOL_ID}",
            create=True,
        ):
            root = Path(temporary).resolve()
            prepared, outcomes = self._fixture(root)
            value = composite.composite_payload(
                prepared,
                authorization_record=JournalRecord(
                    prepared.paths.authorization, {}, "e" * 64
                ),
                pricing_recheck_record=JournalRecord(
                    prepared.paths.pricing_recheck, {}, "f" * 64
                ),
                manifest_record=JournalRecord(
                    prepared.paths.manifest,
                    {"sealed_at": "2026-07-14T11:58:00Z"},
                    "1" * 64,
                ),
                outcomes=outcomes,
                sealed_at="2026-07-14T12:00:00Z",
            )
            self.assertNotIn("response_text", json.dumps(value))
            self.assertEqual(
                tuple(item["model_key"] for item in value["outcomes"]),
                contract.MODEL_KEYS,
            )
            self.assertEqual(value["successful_outcome_count"], 8)

    def test_composite_rejects_injected_response_or_tool_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            contract,
            "PRIVATE_ROOT_RELATIVE",
            f".pilot/divergence-successor/{contract.POOL_ID}",
            create=True,
        ):
            root = Path(temporary).resolve()
            prepared, outcomes = self._fixture(root)
            value = composite.composite_payload(
                prepared,
                authorization_record=JournalRecord(
                    prepared.paths.authorization, {}, "e" * 64
                ),
                pricing_recheck_record=JournalRecord(
                    prepared.paths.pricing_recheck, {}, "f" * 64
                ),
                manifest_record=JournalRecord(
                    prepared.paths.manifest,
                    {"sealed_at": "2026-07-14T11:58:00Z"},
                    "1" * 64,
                ),
                outcomes=outcomes,
                sealed_at="2026-07-14T12:00:00Z",
            )
            injected = copy.deepcopy(value)
            injected["response_text"] = "leak"
            with self.assertRaisesRegex(
                composite.DivergenceSuccessorCompositeError, "top-level fields"
            ):
                composite.validate_composite_value(prepared, injected)
            poisoned = copy.deepcopy(outcomes[0].payload)
            poisoned["result"]["tool_calls"] = [{"name": "browser"}]
            with self.assertRaisesRegex(
                execute.DivergenceSuccessorExecutionError, "forbidden"
            ):
                execute.validate_generation_outcome(
                    poisoned,
                    model_key="gemini",
                    prompt_sha256=outcomes[0].payload["prompt_sha256"],
                )


if __name__ == "__main__":
    unittest.main()
