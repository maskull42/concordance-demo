from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from concordance_harness.config import load_harness_config
from concordance_harness.planner import PlanError, build_plan, load_questions

from support import repository_root


class ConfigAndPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        root = repository_root()
        cls.config = load_harness_config(root / "harness/config/models.json")
        cls.questions = load_questions(root / "sample/questions")
        protocol = __import__("json").loads(
            (root / "config/protocol.json").read_bytes()
        )
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
        self.assertEqual(
            by_key["gpt"].provider_options,
            {
                "provider": {
                    "only": ["openai"],
                    "allow_fallbacks": False,
                    "require_parameters": True,
                }
            },
        )

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


if __name__ == "__main__":
    unittest.main()
