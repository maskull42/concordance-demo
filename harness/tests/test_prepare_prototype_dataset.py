from __future__ import annotations

import json
import os
import socket
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import prepare_prototype_dataset as prototype


ROOT = Path(__file__).resolve().parents[2]


class PrototypeDatasetTests(unittest.TestCase):
    def test_real_sources_project_to_answer_only_candidate_dataset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "dataset"
            with (
                mock.patch.object(
                    socket, "socket", side_effect=AssertionError("network")
                ),
                mock.patch.object(
                    os, "getenv", side_effect=AssertionError("environment")
                ),
            ):
                result = prototype.assemble(ROOT, output)
            self.assertEqual(
                result["response_counts"],
                {
                    "junia-romans-16-7": 8,
                    "john-brown-harpers-ferry": 16,
                    "frontier-ai-lifecycle-licensing": 8,
                },
            )
            index = json.loads((output / "index.json").read_bytes())
            manifest = json.loads((output / "manifests/models.json").read_bytes())
            self.assertEqual(index["mode"], "candidate")
            self.assertEqual(
                [record["question"] for record in index["questions"]],
                [
                    f"questions/{question_id}.json"
                    for question_id in prototype.DISPLAY_IDS
                ],
            )
            self.assertEqual(
                [model["model_key"] for model in manifest["models"]],
                list(prototype.MODEL_ORDER),
            )
            for record in index["questions"]:
                run = json.loads((output / record["run"]).read_bytes())
                mapping = json.loads((output / record["mapping"]).read_bytes())
                self.assertTrue(
                    all(cell["call_type"] == "answer" for cell in run["cells"])
                )
                self.assertTrue(
                    all(
                        assignment["also_endorsed"] == []
                        and assignment["mentioned"] == []
                        for assignment in mapping["assignments"]
                    )
                )

    def test_refuses_to_replace_an_unrelated_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "unrelated"
            output.mkdir()
            sentinel = output / "keep.txt"
            sentinel.write_text("keep", encoding="utf-8")

            with self.assertRaises(prototype.PrototypeDatasetError):
                prototype.assemble(ROOT, output)

            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")


if __name__ == "__main__":
    unittest.main()
