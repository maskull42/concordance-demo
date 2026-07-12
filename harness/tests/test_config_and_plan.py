from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from concordance_harness.config import ConfigError, load_harness_config
from concordance_harness.planner import PlanError, build_plan, load_questions

from support import repository_root


class ConfigAndPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        root = repository_root()
        cls.config = load_harness_config(root / "harness/config/models.json")
        cls.questions = load_questions(root / "sample/questions")
        cls.candidate_questions = load_questions(root / "candidate/questions")
        protocol = json.loads((root / "config/protocol.json").read_bytes())
        cls.system = protocol["system_prompt"]
        cls.challenge = protocol["standard_challenge_prompt"]

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
