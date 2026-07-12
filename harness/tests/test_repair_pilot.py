from __future__ import annotations

import asyncio
import json
import shutil
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from concordance_harness import HARNESS_VERSION
from concordance_harness.config import load_harness_config
from concordance_harness.execution import create_model_manifest, write_model_manifest
from concordance_harness.planner import build_plan, load_questions
from concordance_harness.providers import HttpResponse, PreflightResult, ProviderError
from concordance_harness.util import atomic_write_json, prompt_sha256, sha256_file

from repair_pilot import (
    DEEPSEEK_PRIOR_ERROR,
    DEEPSEEK_TARGET_CELL,
    GPT_PRIOR_ERROR,
    GPT_RETURNED_CANONICAL_ID,
    MAX_COST_USD,
    PARENT_SELECTED_MODELS,
    RepairError,
    _plan_contract_sha256,
    execute_repair,
    prepare_repair,
)

from support import repository_root, response


class ObservingTransport:
    def __init__(self, responses, repair_root: Path) -> None:
        self.responses = list(responses)
        self.repair_root = repair_root
        self.requests = []
        self.intent_counts_at_post = []

    async def send(self, request):
        self.requests.append(request)
        if request.method == "POST":
            self.intent_counts_at_post.append(
                len(list((self.repair_root / "intents").glob("*.json")))
            )
        if not self.responses:
            raise AssertionError("fixture transport has no response")
        item = self.responses.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


class PilotRepairTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self._copy_inputs()
        self._write_parent_stage()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _copy_inputs(self) -> None:
        source = repository_root()
        paths = (
            "harness/config/models.json",
            "config/protocol.json",
            "candidate/pilot-lock.json",
            "candidate/PILOT_POOL.md",
            "candidate/MAPPING_RUBRIC.md",
        )
        for relative in paths:
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source / relative, target)
        shutil.copytree(
            source / "candidate/questions", self.root / "candidate/questions"
        )

    def _write_parent_stage(self) -> None:
        config = load_harness_config(self.root / "harness/config/models.json")
        questions = load_questions(self.root / "candidate/questions")
        protocol = json.loads((self.root / "config/protocol.json").read_bytes())
        full_plan = build_plan(
            questions,
            config.models,
            protocol["system_prompt"],
            protocol["standard_challenge_prompt"],
            answer_only=True,
        )
        selected = tuple(
            model
            for model in config.models
            if model.model_key in PARENT_SELECTED_MODELS
        )
        stage_config = replace(config, models=selected)
        preflight = {
            model.model_key: PreflightResult(
                returned_model_id=(
                    f"models/{model.requested_model_id}"
                    if model.model_key == "gemini"
                    else model.requested_model_id
                ),
                provider_name="OpenAI" if model.model_key == "gpt" else None,
                note=None,
            )
            for model in selected
        }
        manifest = create_model_manifest(stage_config, preflight, "research")
        stage_root = self.root / ".pilot/stages/without-mistral"
        _, manifest_hash = write_model_manifest(stage_root, manifest)
        parent_plan = tuple(
            call
            for call in full_plan
            if call.model.model_key in PARENT_SELECTED_MODELS
        )
        atomic_write_json(
            stage_root / "stage.json",
            {
                "schema_version": "pilot-stage-1.0.0",
                "stage_id": "without-mistral",
                "evidence_status": "partial-nonqualifying",
                "selected_model_keys": list(PARENT_SELECTED_MODELS),
                "deferred_model_keys": ["mistral"],
                "expected_logical_cell_count": 56,
                "required_aggregate_logical_cell_count": 64,
                "pilot_lock_sha256": sha256_file(
                    self.root / "candidate/pilot-lock.json"
                ),
                "config_sha256": config.sha256,
                "harness_version": HARNESS_VERSION,
                "execution_contract_sha256": "a" * 64,
                "full_plan_sha256": _plan_contract_sha256(full_plan),
                "stage_plan_sha256": _plan_contract_sha256(parent_plan),
                "model_manifest_file_sha256": manifest_hash,
                "created_at": "2026-07-12T00:00:00.000+00:00",
            },
        )
        calls_by_question = {}
        for call in parent_plan:
            calls_by_question.setdefault(call.question.question_id, []).append(call)
        for question in questions:
            cells = [self._parent_cell(call) for call in calls_by_question[question.question_id]]
            atomic_write_json(
                stage_root / "runs" / f"{question.question_id}.json",
                {
                    "schema_version": "1.0.0",
                    "run_id": f"fixture-{question.question_id}",
                    "run_purpose": "pilot",
                    "question_id": question.question_id,
                    "question_content_version": question.content_version,
                    "question_file_sha256": question.sha256,
                    "generated_at": "2026-07-12T00:00:00.000+00:00",
                    "updated_at": "2026-07-12T00:00:00.000+00:00",
                    "harness_version": HARNESS_VERSION,
                    "harness_config_sha256": config.sha256,
                    "model_manifest_file_sha256": manifest_hash,
                    "model_manifest_snapshot": manifest,
                    "cells": sorted(cells, key=lambda cell: cell["cell_id"]),
                },
            )

    @staticmethod
    def _parent_cell(call):
        messages = call.answer_messages()
        common = {
            "cell_id": call.cell_id,
            "question_id": call.question.question_id,
            "model_key": call.model.model_key,
            "model_family": call.model.family,
            "provider": call.model.provider,
            "requested_model_id": call.model.requested_model_id,
            "variant_id": call.variant_id,
            "call_type": "answer",
            "parent_response_id": None,
            "messages": messages,
            "prompt_sha256": prompt_sha256(messages),
            "requested_params": call.model.requested_params_receipt(),
            "attempted_at": "2026-07-12T00:00:00.000+00:00",
            "attempt_count": 1,
        }
        if call.model.model_key == "gpt" or call.cell_id == DEEPSEEK_TARGET_CELL:
            return {
                "status": "error",
                **common,
                "error": (
                    GPT_PRIOR_ERROR
                    if call.model.model_key == "gpt"
                    else DEEPSEEK_PRIOR_ERROR
                ),
                "failed_at": "2026-07-12T00:00:01.000+00:00",
            }
        return {
            "status": "success",
            **common,
            "response_id": f"fixture-{call.cell_id}",
            "response_text": "Fixture response",
        }

    def context(self, repair_id="approved-repair"):
        context = prepare_repair(
            self.root,
            repair_id,
            require_committed_inputs=False,
            require_live_parent_fingerprints=False,
        )
        fast_models = {
            model.model_key: replace(model, requests_per_second=100_000.0)
            for model in context.target_models
        }
        return replace(
            context,
            target_models=tuple(
                fast_models[model.model_key] for model in context.target_models
            ),
            target_calls=tuple(
                replace(call, model=fast_models[call.model.model_key])
                for call in context.target_calls
            ),
        )

    @staticmethod
    def _secrets():
        return {
            "DEEPSEEK_API_KEY": "deepseek-test-secret",
            "OPENROUTER_API_KEY": "openrouter-test-secret",
        }

    @staticmethod
    def _responses():
        responses = [
            response(200, {"data": [{"id": "deepseek-v4-pro"}]}),
            response(
                200,
                {
                    "data": {
                        "id": "openai/gpt-5.6-sol",
                        "endpoints": [{"provider_name": "OpenAI"}],
                    }
                },
            ),
        ]
        # The canonical target order contains one DeepSeek POST and eight GPT POSTs.
        responses.append(
            response(
                200,
                {
                    "id": "deepseek-generation",
                    "model": "deepseek-v4-pro",
                    "choices": [
                        {"message": {"content": "DeepSeek repair"}, "finish_reason": "stop"}
                    ],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
                },
            )
        )
        responses.extend(
            response(
                200,
                {
                    "id": f"gpt-generation-{index}",
                    "model": GPT_RETURNED_CANONICAL_ID,
                    "provider": "OpenAI",
                    "choices": [
                        {"message": {"content": f"GPT repair {index}"}, "finish_reason": "stop"}
                    ],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
                },
            )
            for index in range(8)
        )
        return responses

    def test_parent_is_bound_and_exact_targets_are_derived_from_64(self) -> None:
        context = self.context()
        self.assertEqual(len(context.full_plan), 64)
        self.assertEqual(len(context.target_calls), 9)
        self.assertEqual(
            sum(call.model.model_key == "gpt" for call in context.target_calls), 8
        )
        self.assertEqual(context.target_calls[0].cell_id, DEEPSEEK_TARGET_CELL)
        self.assertEqual(context.receipt["parent"]["success_count"], 47)
        self.assertEqual(context.receipt["parent"]["error_count"], 9)
        self.assertEqual(len(context.receipt["parent"]["run_files"]), 6)
        self.assertEqual(
            context.receipt["network_scope"]["max_outbound_calls"], 11
        )
        self.assertLess(
            context.receipt["network_scope"]["one_attempt_cost_ceiling_usd"],
            MAX_COST_USD,
        )

    def test_parent_tampering_is_rejected_before_a_repair_is_created(self) -> None:
        run_path = (
            self.root
            / ".pilot/stages/without-mistral/runs/atomic-bombs-pacific-war.json"
        )
        run = json.loads(run_path.read_bytes())
        target = next(
            cell for cell in run["cells"] if cell["cell_id"] == DEEPSEEK_TARGET_CELL
        )
        target["error"]["category"] = "timeout"
        atomic_write_json(run_path, run)
        with self.assertRaisesRegex(RepairError, "prior error changed"):
            self.context()
        self.assertFalse((self.root / ".pilot/repairs/approved-repair").exists())

    def test_manifest_hash_mismatch_is_rejected(self) -> None:
        manifest_path = self.root / ".pilot/stages/without-mistral/manifests/models.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest["manifest_id"] = "tampered"
        atomic_write_json(manifest_path, manifest)
        with self.assertRaisesRegex(RepairError, "model_manifest_file_sha256"):
            self.context()

    def test_execution_writes_intent_before_each_post_and_exactly_11_calls(self) -> None:
        context = self.context()
        transport = ObservingTransport(self._responses(), context.repair_root)
        result = asyncio.run(execute_repair(context, self._secrets(), transport))
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["success_count"], 9)
        self.assertEqual(result["error_count"], 0)
        self.assertEqual(result["outbound_attempt_count"], 11)
        self.assertEqual(len(transport.requests), 11)
        self.assertEqual([request.method for request in transport.requests[:2]], ["GET", "GET"])
        self.assertTrue(all(request.method == "POST" for request in transport.requests[2:]))
        self.assertEqual(transport.intent_counts_at_post, list(range(1, 10)))
        self.assertEqual(len(list((context.repair_root / "intents").glob("*.json"))), 9)
        self.assertEqual(len(list((context.repair_root / "outcomes").glob("*.json"))), 9)
        self.assertTrue((context.repair_root / "repair.json").is_file())
        self.assertTrue((context.repair_root / "result.json").is_file())
        returned = {
            cell["provider_returned_model_id"]
            for cell in result["cells"]
            if cell["model_key"] == "gpt"
        }
        self.assertEqual(returned, {GPT_RETURNED_CANONICAL_ID})

    def test_provider_error_is_terminal_and_never_retried(self) -> None:
        context = self.context("terminal-error")
        responses = self._responses()
        responses[2] = ProviderError(
            "ambiguous network failure", category="network", retryable=True
        )
        transport = ObservingTransport(responses, context.repair_root)
        result = asyncio.run(execute_repair(context, self._secrets(), transport))
        self.assertEqual(len(transport.requests), 11)
        self.assertEqual(result["success_count"], 8)
        self.assertEqual(result["error_count"], 1)
        failed = next(cell for cell in result["cells"] if cell["status"] == "error")
        self.assertEqual(failed["attempt_count"], 1)
        self.assertFalse(failed["error"]["retryable"])

    def test_repair_id_reuse_never_resends_terminal_intents(self) -> None:
        context = self.context("single-use")
        first = ObservingTransport(self._responses(), context.repair_root)
        asyncio.run(execute_repair(context, self._secrets(), first))
        second = ObservingTransport(self._responses(), context.repair_root)
        with self.assertRaisesRegex(RepairError, "terminal or stranded"):
            asyncio.run(execute_repair(context, self._secrets(), second))
        self.assertEqual(second.requests, [])

    def test_stranded_intent_is_never_resent_under_same_id(self) -> None:
        context = self.context("stranded")
        responses = self._responses()
        responses[2] = RuntimeError("simulated process death after intent")
        first = ObservingTransport(responses, context.repair_root)
        with self.assertRaisesRegex(RuntimeError, "simulated process death"):
            asyncio.run(execute_repair(context, self._secrets(), first))
        self.assertEqual(len(first.requests), 3)
        self.assertEqual(len(list((context.repair_root / "intents").glob("*.json"))), 1)
        self.assertEqual(len(list((context.repair_root / "outcomes").glob("*.json"))), 0)
        second = ObservingTransport(self._responses(), context.repair_root)
        with self.assertRaisesRegex(RepairError, "terminal or stranded"):
            asyncio.run(execute_repair(context, self._secrets(), second))
        self.assertEqual(second.requests, [])

    def test_only_two_exact_secrets_are_accepted(self) -> None:
        context = self.context("secret-scope")
        transport = ObservingTransport(self._responses(), context.repair_root)
        with self.assertRaisesRegex(RepairError, "exactly DeepSeek and OpenRouter"):
            asyncio.run(
                execute_repair(
                    context,
                    {**self._secrets(), "MISTRAL_API_KEY": "must-not-be-read"},
                    transport,
                )
            )
        self.assertEqual(transport.requests, [])
        self.assertFalse(context.repair_root.exists())


if __name__ == "__main__":
    unittest.main()
