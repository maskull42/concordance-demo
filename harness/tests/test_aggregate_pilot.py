from __future__ import annotations

import json
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aggregate_pilot import (
    AGGREGATE_SCHEMA_VERSION,
    AggregateError,
    BLIND_ITEM_SCHEMA_KEYS,
    _blind_payloads,
    _validate_static_cell,
    prepare_aggregate,
    write_aggregate,
)

from support import repository_root


ROOT = repository_root()
LIVE_EVIDENCE_AVAILABLE = all(
    (ROOT / path).is_file()
    for path in (
        ".pilot/stages/without-mistral/stage.json",
        ".pilot/repairs/gpt-alias-deepseek-network-1/result.json",
        ".pilot/stages/mistral-completion/stage.json",
    )
)


@unittest.skipUnless(
    LIVE_EVIDENCE_AVAILABLE,
    "private pilot evidence is intentionally absent from a clean checkout",
)
class AggregatePilotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.context = prepare_aggregate(ROOT)

    def test_exact_overlay_is_complete_and_balanced(self) -> None:
        self.assertEqual(len(self.context.cells), 64)
        self.assertTrue(
            all(evidence.cell["status"] == "success" for evidence in self.context.cells)
        )
        counts = {
            key: sum(
                evidence.call.model.model_key == key for evidence in self.context.cells
            )
            for key in (
                "gemini",
                "claude",
                "cohere",
                "qwen",
                "deepseek",
                "mistral",
                "grok",
                "gpt",
            )
        }
        self.assertEqual(set(counts.values()), {8})
        self.assertEqual(
            self.context.source_counts,
            {
                "parent": {"preserved_success": 47, "overlaid_error": 9},
                "repair": {"success": 9, "error": 0},
                "mistral": {"success": 8, "error": 0},
                "aggregate": {"success": 64, "error": 0},
            },
        )

    def test_blind_items_have_only_mapper_safe_fields(self) -> None:
        items, crosswalk = _blind_payloads(self.context, b"b" * 32)
        self.assertEqual(len(items), 64)
        self.assertEqual(len(crosswalk["entries"]), 64)
        self.assertEqual(len(set(items)), 64)
        for blind_id, item in items.items():
            self.assertEqual(set(item), BLIND_ITEM_SCHEMA_KEYS)
            self.assertEqual(item["blind_id"], blind_id)
            self.assertTrue(item["user_prompt"])
            self.assertTrue(item["response_text"])
            self.assertTrue(item["position_map"])
            for position in item["position_map"]:
                self.assertEqual(set(position), {"id", "label", "summary"})
        self.assertTrue(
            all("model_key" in entry and "cell_id" in entry for entry in crosswalk["entries"])
        )

    def test_static_contract_tampering_is_rejected(self) -> None:
        evidence = self.context.cells[0]
        changed = dict(evidence.cell)
        changed["prompt_sha256"] = "0" * 64
        with self.assertRaisesRegex(AggregateError, "prompt_sha256"):
            _validate_static_cell(changed, evidence.call, allow_error=False)

    def test_write_is_single_use_and_records_no_threshold_evaluation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "aggregate"
            context = replace(self.context, output_root=output)
            path = write_aggregate(context, blinding_key=b"k" * 32)
            receipt = json.loads(path.read_bytes())
            self.assertEqual(receipt["schema_version"], AGGREGATE_SCHEMA_VERSION)
            self.assertEqual(receipt["status"], "complete-mapping-eligible")
            self.assertFalse(receipt["threshold_evaluation"]["performed"])
            self.assertEqual(receipt["blind_export"]["item_count"], 64)
            self.assertEqual(len(list((output / "blind/items").glob("*.json"))), 64)
            with self.assertRaisesRegex(AggregateError, "single-use"):
                write_aggregate(context, blinding_key=b"k" * 32)


if __name__ == "__main__":
    unittest.main()
