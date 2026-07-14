from __future__ import annotations

import copy
import json
import os
import socket
import unittest
from pathlib import Path
from unittest import mock

import validate_frontier_ai_prototype_inclusion as inclusion


ROOT = Path(__file__).resolve().parents[2]


class PrototypeInclusionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = json.loads((ROOT / inclusion.POLICY_PATH).read_bytes())
        cls.receipt = json.loads((ROOT / inclusion.RECEIPT_PATH).read_bytes())

    def test_sealed_policy_verifies_offline(self) -> None:
        with (
            mock.patch.object(socket, "socket", side_effect=AssertionError("network")),
            mock.patch.object(os, "getenv", side_effect=AssertionError("environment")),
        ):
            result = inclusion.verify(ROOT)
        self.assertEqual(result["classification"], "bimodal_divergence")
        self.assertFalse(result["original_rule3_qualifies"])
        self.assertTrue(result["prototype_inclusion_selected"])
        self.assertEqual(result["provider_calls"], 0)

    def test_original_failure_cannot_be_recast_as_rule3_qualification(self) -> None:
        for section, field, replacement in (
            ("decision_sequence", "original_result", "qualified"),
            ("claim_limits", "rule3_qualification", True),
            ("claim_limits", "precommitted_rule3_qualification", True),
        ):
            policy = copy.deepcopy(self.policy)
            policy[section][field] = replacement
            with (
                self.subTest(section=section, field=field),
                self.assertRaises(inclusion.PrototypeInclusionError),
            ):
                inclusion.validate_semantics(policy, self.receipt)

    def test_prototype_scope_cannot_expand(self) -> None:
        for field, replacement in (
            ("scope", "production"),
            ("provider_calls_authorized", 1),
            ("new_generation_authorized", True),
            ("production_release_authorized", True),
        ):
            policy = copy.deepcopy(self.policy)
            policy["authorization"][field] = replacement
            with (
                self.subTest(field=field),
                self.assertRaises(inclusion.PrototypeInclusionError),
            ):
                inclusion.validate_semantics(policy, self.receipt)

    def test_classification_must_match_the_sealed_5_3_receipt(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["classification"]["nonzero_primary_split_descending"] = [4, 4]
        with self.assertRaises(inclusion.PrototypeInclusionError):
            inclusion.validate_semantics(policy, self.receipt)

        receipt = copy.deepcopy(self.receipt)
        receipt["threshold_result"]["qualifies"] = True
        with self.assertRaises(inclusion.PrototypeInclusionError):
            inclusion.validate_semantics(self.policy, receipt)

    def test_lineage_is_exact_and_append_only(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["lineage"][0]["sha256"] = "0" * 64
        with self.assertRaises(inclusion.PrototypeInclusionError):
            inclusion.validate_semantics(policy, self.receipt)


if __name__ == "__main__":
    unittest.main()
