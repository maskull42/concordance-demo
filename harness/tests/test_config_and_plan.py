from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from concordance_harness.config import ConfigError, load_harness_config
from concordance_harness.execution import (
    ResumeError,
    create_model_manifest,
    write_model_manifest,
)
from concordance_harness.planner import PlanError, build_plan, load_questions
from concordance_harness.providers import PreflightResult

from generate import (
    build_pilot_stage_scope,
    config_for_run,
    load_existing_manifest,
    load_pilot_stage_receipt,
    write_pilot_stage_receipt,
)

from support import repository_root


class ConfigAndPlanTests(unittest.TestCase):
    STAGED_MODEL_KEYS = (
        "gemini",
        "claude",
        "cohere",
        "qwen",
        "deepseek",
        "grok",
        "gpt",
    )

    @classmethod
    def setUpClass(cls) -> None:
        root = repository_root()
        cls.config = load_harness_config(root / "harness/config/models.json")
        cls.questions = load_questions(root / "sample/questions")
        cls.candidate_questions = load_questions(root / "candidate/questions")
        cls.protocol = json.loads((root / "config/protocol.json").read_bytes())
        cls.system = cls.protocol["system_prompt"]
        cls.challenge = cls.protocol["standard_challenge_prompt"]

    def test_approved_panel_and_parameter_policies_are_frozen(self) -> None:
        self.assertEqual(len(self.config.models), 8)
        by_key = self.config.by_key()
        for key in ("gemini", "claude", "gpt"):
            self.assertEqual(by_key[key].temperature["mode"], "provider-default")
        for key in ("cohere", "qwen", "deepseek", "mistral", "grok"):
            self.assertEqual(by_key[key].temperature, {"mode": "fixed", "value": 0.2})
        self.assertFalse(by_key["grok"].fallback_allowed)
        self.assertEqual(by_key["grok"].route, "xai-direct")
        self.assertEqual(by_key["qwen"].metadata_path, "/v1/models")
        self.assertEqual(by_key["qwen"].metadata_mode, "list")
        self.assertEqual(by_key["grok"].api_style, "xai-responses")
        self.assertEqual(by_key["grok"].generation_path, "/v1/responses")
        self.assertEqual(
            by_key["grok"].output_limit,
            {"parameter": "max_output_tokens", "value": 16_384},
        )
        for key, model in by_key.items():
            expected_parameter = (
                "max_output_tokens" if key in {"gemini", "grok"} else "max_tokens"
            )
            self.assertEqual(
                model.output_limit,
                {"parameter": expected_parameter, "value": 16_384},
            )
        self.assertEqual(
            by_key["grok"].provider_options,
            {"store": False, "service_tier": "default"},
        )
        self.assertEqual(
            by_key["gpt"].provider_options,
            {
                "service_tier": "default",
                "provider": {
                    "only": ["openai"],
                    "allow_fallbacks": False,
                    "require_parameters": True,
                }
            },
        )

    def test_visible_answer_target_is_separate_from_total_output_ceiling(self) -> None:
        self.assertIn("Keep the visible answer under 900 tokens.", self.system)
        self.assertTrue(
            all(model.output_cap == 16_384 for model in self.config.models)
        )

    def test_changed_total_output_ceiling_is_rejected(self) -> None:
        root = repository_root()
        raw = json.loads((root / "harness/config/models.json").read_bytes())
        raw["models"][3]["output_limit"]["value"] = 900
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "models.json"
            path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaisesRegex(
                ConfigError, "total reasoning-and-answer output ceiling"
            ):
                load_harness_config(path)

    def test_final_shape_is_exactly_64_cells(self) -> None:
        plan = build_plan(
            self.questions,
            self.config.models,
            self.system,
            self.challenge,
        )
        self.assertEqual(len(plan), 64)
        self.assertTrue(all(call.call_type == "answer" for call in plan[:32]))
        self.assertTrue(all(call.call_type == "challenge" for call in plan[32:]))
        self.assertEqual(len({call.cell_id for call in plan}), 64)

    def test_rule_two_pilot_dry_shape_is_exactly_64_answer_cells(self) -> None:
        plan = build_plan(
            self.candidate_questions,
            self.config.models,
            self.system,
            self.challenge,
            answer_only=True,
        )
        self.assertEqual(len(plan), 64)
        self.assertTrue(all(call.call_type == "answer" for call in plan))
        self.assertEqual(len({call.cell_id for call in plan}), 64)

        root = repository_root()
        result = subprocess.run(
            [
                sys.executable,
                "harness/generate.py",
                "--dry-run",
                "--run-purpose",
                "pilot",
                "--questions",
                "candidate/questions",
                "--output",
                ".pilot",
                "--answer-only",
            ],
            cwd=root,
            env={"PATH": os.environ.get("PATH", "")},
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Planned logical cells: 64 of 64", result.stdout)
        self.assertIn("environment variables read: 0", result.stdout)

    def test_seven_model_pilot_stage_has_56_exact_private_cells(self) -> None:
        root = repository_root()
        result = subprocess.run(
            [
                sys.executable,
                "harness/generate.py",
                "--dry-run",
                "--run-purpose",
                "pilot",
                "--questions",
                "candidate/questions",
                "--answer-only",
                "--pilot-stage",
                "credential-scope-test",
                "--output",
                ".pilot/stages/credential-scope-test",
                *(
                    argument
                    for model_key in self.STAGED_MODEL_KEYS
                    for argument in ("--model", model_key)
                ),
            ],
            cwd=root,
            env={"PATH": os.environ.get("PATH", "")},
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Planned logical cells: 56 of 56", result.stdout)
        self.assertIn("private, partial, and nonqualifying", result.stdout)
        self.assertIn("aggregate 64 exact model-variant cells", result.stdout)
        self.assertIn("environment variables read: 0", result.stdout)

    def test_pilot_stage_refuses_missing_stage_wrong_path_and_unknown_model(
        self,
    ) -> None:
        root = repository_root()
        base = [
            sys.executable,
            "harness/generate.py",
            "--dry-run",
            "--run-purpose",
            "pilot",
            "--questions",
            "candidate/questions",
            "--answer-only",
            "--model",
            "gemini",
        ]
        cases = [
            ([], "require an explicit --pilot-stage"),
            (
                [
                    "--pilot-stage",
                    "first-stage",
                    "--output",
                    ".pilot/stages/wrong-stage",
                ],
                "must write exactly to .pilot/stages/first-stage",
            ),
            (
                [
                    "--pilot-stage",
                    "first-stage",
                    "--output",
                    ".pilot/stages/first-stage",
                    "--model",
                    "not-a-model",
                ],
                "unknown model filter(s): not-a-model",
            ),
        ]
        for extra, expected in cases:
            with self.subTest(expected=expected):
                result = subprocess.run(
                    [*base, *extra],
                    cwd=root,
                    env={"PATH": os.environ.get("PATH", "")},
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn(expected, result.stderr)

    def test_live_seven_model_stage_requires_only_selected_credentials(self) -> None:
        root = repository_root()
        result = subprocess.run(
            [
                sys.executable,
                "harness/generate.py",
                "--live",
                "--run-purpose",
                "pilot",
                "--credentials-rotated",
                "--pilot-content-approved",
                "--questions",
                "candidate/questions",
                "--answer-only",
                "--pilot-stage",
                "credential-scope-test",
                "--output",
                ".pilot/stages/credential-scope-test",
                *(
                    argument
                    for model_key in self.STAGED_MODEL_KEYS
                    for argument in ("--model", model_key)
                ),
            ],
            cwd=root,
            env={
                "PATH": os.environ.get("PATH", ""),
                "HOME": os.environ.get("HOME", ""),
            },
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("missing required environment variables", result.stderr)
        self.assertNotIn("MISTRAL_API_KEY", result.stderr)
        for environment_variable in (
            "GOOGLE_API_KEY",
            "ANTHROPIC_API_KEY",
            "COHERE_API_KEY",
            "DEEPINFRA_API_KEY",
            "DEEPSEEK_API_KEY",
            "XAI_API_KEY",
            "OPENROUTER_API_KEY",
        ):
            self.assertIn(environment_variable, result.stderr)

    def test_stage_receipt_and_manifest_cover_only_selected_models(self) -> None:
        arguments = Namespace(
            run_purpose="pilot",
            pilot_stage="without-mistral",
            model=list(self.STAGED_MODEL_KEYS),
        )
        scoped = config_for_run(self.config, arguments)
        self.assertEqual(
            tuple(model.model_key for model in scoped.models), self.STAGED_MODEL_KEYS
        )
        preflight = {
            model.model_key: PreflightResult(
                (
                    "openai/gpt-5.6-sol-20260709"
                    if model.model_key == "gpt"
                    else model.requested_model_id
                ),
                "OpenAI" if model.model_key == "gpt" else model.provider,
                None,
            )
            for model in scoped.models
        }
        manifest = create_model_manifest(scoped, preflight, "research")
        self.assertEqual(
            [model["model_key"] for model in manifest["models"]],
            list(self.STAGED_MODEL_KEYS),
        )

        plan = build_plan(
            self.candidate_questions,
            scoped.models,
            self.system,
            self.challenge,
            answer_only=True,
        )
        scope = build_pilot_stage_scope(
            "without-mistral",
            self.config,
            scoped,
            self.protocol,
            self.candidate_questions,
            plan,
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            _, manifest_hash = write_model_manifest(output, manifest)
            path = write_pilot_stage_receipt(
                output,
                scope,
                manifest_hash,
            )
            receipt = json.loads(path.read_bytes())
            self.assertEqual(receipt["selected_model_keys"], list(self.STAGED_MODEL_KEYS))
            self.assertEqual(receipt["deferred_model_keys"], ["mistral"])
            self.assertEqual(receipt["expected_logical_cell_count"], 56)
            self.assertEqual(receipt["required_aggregate_logical_cell_count"], 64)
            self.assertEqual(receipt["evidence_status"], "partial-nonqualifying")
            self.assertEqual(receipt["config_sha256"], self.config.sha256)
            self.assertEqual(len(receipt["pilot_lock_sha256"]), 64)
            self.assertEqual(receipt["model_manifest_file_sha256"], manifest_hash)
            self.assertEqual(len(receipt["execution_contract_sha256"]), 64)
            self.assertEqual(len(receipt["full_plan_sha256"]), 64)
            self.assertEqual(len(receipt["stage_plan_sha256"]), 64)
            self.assertIsInstance(receipt["created_at"], str)
            self.assertEqual(
                load_pilot_stage_receipt(output, scope), manifest_hash
            )
            loaded = load_existing_manifest(output, scoped)
            self.assertIsNotNone(loaded)
            assert loaded is not None
            loaded_manifest, loaded_hash = loaded
            self.assertEqual(loaded_manifest, manifest)
            self.assertEqual(loaded_hash, manifest_hash)
            self.assertEqual(
                loaded_manifest["models"][-1]["preflight"][
                    "provider_returned_model_id"
                ],
                "openai/gpt-5.6-sol-20260709",
            )

            manifest["models"][0]["route"] = "substituted-route"
            (output / "manifests/models.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )
            with self.assertRaises(ResumeError):
                load_existing_manifest(output, scoped)

    def test_case_model_and_answer_only_filters_are_deterministic(self) -> None:
        plan = build_plan(
            self.questions,
            self.config.models,
            self.system,
            self.challenge,
            {"case-a"},
            {"gemini"},
            answer_only=True,
        )
        self.assertEqual(
            [call.cell_id for call in plan], ["case-a:gemini:default:answer"]
        )
        with self.assertRaises(PlanError):
            build_plan(
                self.questions,
                self.config.models,
                self.system,
                self.challenge,
                {"not-a-case"},
            )

    def test_dry_run_honors_max_calls_without_reading_or_printing_secrets(self) -> None:
        root = repository_root()
        environment = dict(os.environ)
        environment["OPENROUTER_API_KEY"] = "secret-value-that-must-not-appear"
        result = subprocess.run(
            [sys.executable, "harness/generate.py", "--dry-run", "--max-calls", "5"],
            cwd=root,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Planned logical cells: 5 of 64", result.stdout)
        self.assertIn("environment variables read: 0", result.stdout)
        self.assertNotIn(
            environment["OPENROUTER_API_KEY"], result.stdout + result.stderr
        )

    def test_live_path_refuses_sample_before_environment_access(self) -> None:
        root = repository_root()
        result = subprocess.run(
            [
                sys.executable,
                "harness/generate.py",
                "--live",
                "--credentials-rotated",
            ],
            cwd=root,
            env={"PATH": os.environ.get("PATH", "")},
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("refuses the illustrative sample dataset", result.stderr)
        self.assertNotIn("GOOGLE_API_KEY", result.stderr)

    def test_live_pilot_refuses_missing_approval_answer_only_and_private_output(
        self,
    ) -> None:
        root = repository_root()
        base = [
            sys.executable,
            "harness/generate.py",
            "--live",
            "--run-purpose",
            "pilot",
            "--credentials-rotated",
            "--questions",
            "candidate/questions",
        ]
        cases = [
            (
                ["--answer-only", "--output", ".pilot"],
                "requires --pilot-content-approved",
            ),
            (
                ["--pilot-content-approved", "--output", ".pilot"],
                "requires --answer-only",
            ),
            (
                [
                    "--pilot-content-approved",
                    "--answer-only",
                    "--output",
                    "data",
                ],
                "must write under the ignored repository .pilot/ directory",
            ),
        ]
        for extra, expected in cases:
            with self.subTest(expected=expected):
                result = subprocess.run(
                    [*base, *extra],
                    cwd=root,
                    env={"PATH": os.environ.get("PATH", "")},
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn(expected, result.stderr)
                self.assertNotIn("GOOGLE_API_KEY", result.stderr)

    def test_final_refuses_candidate_and_proposed_content_before_environment_access(
        self,
    ) -> None:
        root = repository_root()
        selected_by_kind = {
            kind: next(
                question.raw
                for question in self.candidate_questions
                if question.raw["kind"] == kind
            )
            for kind in ("convergent", "divergent", "prompt-sensitive")
        }
        with tempfile.TemporaryDirectory() as temporary:
            question_root = Path(temporary)
            for raw in selected_by_kind.values():
                (question_root / f"{raw['id']}.json").write_text(
                    json.dumps(raw), encoding="utf-8"
                )

            command = [
                sys.executable,
                "harness/generate.py",
                "--live",
                "--credentials-rotated",
                "--questions",
                str(question_root),
            ]
            candidate_result = subprocess.run(
                command,
                cwd=root,
                env={"PATH": os.environ.get("PATH", "")},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(candidate_result.returncode, 2)
            self.assertIn("refuses candidate content", candidate_result.stderr)
            self.assertNotIn("GOOGLE_API_KEY", candidate_result.stderr)

            for raw in selected_by_kind.values():
                selected = json.loads(json.dumps(raw))
                selected["selection"]["status"] = "selected"
                (question_root / f"{selected['id']}.json").write_text(
                    json.dumps(selected), encoding="utf-8"
                )
            proposed_result = subprocess.run(
                command,
                cwd=root,
                env={"PATH": os.environ.get("PATH", "")},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proposed_result.returncode, 2)
            self.assertIn("refuses unverified scholarly content", proposed_result.stderr)
            self.assertNotIn("GOOGLE_API_KEY", proposed_result.stderr)


if __name__ == "__main__":
    unittest.main()
