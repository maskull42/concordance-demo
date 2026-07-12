from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prepare_mapping_batches import BatchError, prepare_batches, write_batches

from support import repository_root


ROOT = repository_root()
AGGREGATE_AVAILABLE = (
    ROOT / ".pilot/aggregates/rule2-pilot-1/aggregate.json"
).is_file()


@unittest.skipUnless(
    AGGREGATE_AVAILABLE,
    "private aggregate is intentionally absent from a clean checkout",
)
class MappingBatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.context = prepare_batches()

    def test_schedule_has_sixteen_identity_isolated_batches(self) -> None:
        self.assertEqual(len(self.context.slots), 16)
        seen = set()
        for slot in self.context.slots:
            self.assertEqual(len(slot), 4)
            self.assertEqual(len({item.question_id for item in slot}), 4)
            self.assertEqual(len({item.model_key for item in slot}), 4)
            self.assertEqual(
                {
                    item.question_id
                    for item in slot
                    if item.question_id
                    in {"atomic-bombs-pacific-war", "john-brown-harpers-ferry"}
                },
                {"atomic-bombs-pacific-war", "john-brown-harpers-ferry"},
            )
            for item in slot:
                self.assertNotIn(item.blind_id, seen)
                seen.add(item.blind_id)
        self.assertEqual(len(seen), 64)

    def test_public_envelopes_exclude_identity_and_canonical_position_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "batches"
            receipt_path = write_batches(self.context, output)
            receipt = json.loads(receipt_path.read_bytes())
            self.assertEqual(receipt["batch_count"], 16)
            self.assertEqual(receipt["item_count"], 64)
            envelopes = list((output / "batches").glob("*/items/*.json"))
            self.assertEqual(len(envelopes), 64)
            forbidden = {
                "cell_id",
                "question_id",
                "model_key",
                "provider",
                "variant_id",
                "position_id",
                "canonical_position_id",
            }
            for path in envelopes:
                envelope = json.loads(path.read_bytes())
                self.assertEqual(
                    set(envelope),
                    {
                        "schema_version",
                        "blind_item_id",
                        "response_sha256",
                        "user_prompt",
                        "positions",
                        "response_text",
                    },
                )
                self.assertFalse(forbidden & set(envelope))
                self.assertTrue(
                    all(
                        set(position) == {"handle", "label", "summary"}
                        and position["handle"].startswith("P")
                        for position in envelope["positions"]
                    )
                )
            with self.assertRaisesRegex(BatchError, "single-use"):
                write_batches(self.context, output)


if __name__ == "__main__":
    unittest.main()
