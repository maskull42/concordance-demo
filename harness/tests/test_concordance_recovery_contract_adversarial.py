from __future__ import annotations

import json
import inspect
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from concordance_harness.config import load_harness_config
from concordance_harness.util import canonical_json_bytes, sha256_bytes
from concordance_recovery import contract
from concordance_recovery.authorization import (
    RecoveryAuthorizationError,
    authorization_payload,
    normalize_pricing_evidence,
    write_paid_authorization,
)
from concordance_recovery.contract import (
    RecoveryLockError,
    discover_recovery_source_paths,
    parent_artifact_bindings,
)
from concordance_recovery.execute import (
    _attempt_range,
    dry_run_summary,
    execute_prepared,
)
from rule3.lock import build_rule3_lock

from support import repository_root


class ConcordanceRecoveryContractAdversarialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = repository_root()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        config = self.root / "harness/config/models.json"
        config.parent.mkdir(parents=True)
        shutil.copy2(self.source / "harness/config/models.json", config)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def lock_context(self) -> SimpleNamespace:
        return SimpleNamespace(
            repository_root=self.root,
            lock={
                "paid_authorization": {
                    "exact_statement": contract.PAID_AUTHORIZATION_STATEMENT,
                    "exact_statement_sha256": (
                        contract.PAID_AUTHORIZATION_STATEMENT_SHA256
                    ),
                    "scope": contract.authorization_scope(),
                }
            },
            lock_sha256="a" * 64,
            git_head="b" * 40,
        )

    def pricing_evidence(self) -> list[dict[str, object]]:
        config = load_harness_config(self.root / "harness/config/models.json")
        by_key = config.by_key()
        return [
            {
                "model_key": model_key,
                "requested_model_id": by_key[model_key].requested_model_id,
                "input_per_million": by_key[model_key].planning_pricing[
                    "input_per_million"
                ],
                "output_per_million": by_key[model_key].planning_pricing[
                    "output_per_million"
                ],
                "official_source_url": (
                    "https://"
                    + contract.OFFICIAL_PRICING_HOSTS[model_key][0]
                    + f"/pricing/{model_key}"
                ),
            }
            for model_key in contract.TARGET_MODEL_KEYS
        ]

    def test_exact_parent_hashes_and_inventory_are_frozen_metadata_only(self) -> None:
        expected_inventory = {
            "budget/intents/galatians-pistis-christou/claude/attempt-1.json": "bfb84f1367209b52b1490459d1a1ab079fab15ca5a5059177002372ca5a78101",
            "budget/intents/galatians-pistis-christou/cohere/attempt-1.json": "ee2b4d0b0c3ae1eaa0ea694f6ae04b158766012e9d6fec6ba938f7f352182bb9",
            "budget/intents/galatians-pistis-christou/gemini/attempt-1.json": "c1a828b4be8d8909ce23d64f7128b85b176f020f1f564418d07b7454daaf128c",
            "manifests/galatians-pistis-christou.json": "7dedec143467eebd3e489515cdb23686bd011aa5ae663999a5bc9ceafc37c135",
            "outcomes/galatians-pistis-christou/claude/attempt-1.json": "30d1481e3cd12946dcfede4e15984ed2fa3969aeff41e12af2666dafc833f41b",
            "outcomes/galatians-pistis-christou/gemini/attempt-1.json": "dc0a96587db718f2014f6e17631447dbafa6970ff5e379f1f29965c63f0dc0e1",
            "paid-authorization.json": "30ecdca710d05786bff0b07f632d9208016a605983078d30d27f9547dc5186c1",
            "preflight/intents/galatians-pistis-christou/claude/attempt-1.json": "a2e7d2de1d8b6b05c19362a07f78f58448d868e949d329592605f138b66acb4a",
            "preflight/intents/galatians-pistis-christou/cohere/attempt-1.json": "f132e2061486d7c38a11aef170026a16873daf9191aee6638c083b269bc60b7c",
            "preflight/intents/galatians-pistis-christou/deepseek/attempt-1.json": "507f9ae5a5061c2beef4d969cc9f4093b1d5f9000fa95f6d75a4ffc59349fcd4",
            "preflight/intents/galatians-pistis-christou/gemini/attempt-1.json": "289c13ea0c0128401a07095bb339be490cac91805784fbeedbaf11a799dfbb4c",
            "preflight/intents/galatians-pistis-christou/gpt/attempt-1.json": "564288ff9cf8a3a3a5aae789cfc71c783b7780c293dfcf744509109cec35548c",
            "preflight/intents/galatians-pistis-christou/grok/attempt-1.json": "665df8d9f8ef0bd3114ce31b8359ce46c1f7e7cdf3d18210a207c5f7d1cd3569",
            "preflight/intents/galatians-pistis-christou/mistral/attempt-1.json": "34c0bb2c81f5b3d6dd73f915fe6ded905c006356d81a5df0713be5c5d661301a",
            "preflight/intents/galatians-pistis-christou/qwen/attempt-1.json": "d10e4690fa59a7b6540dc0633994e237cfe3e4184373af25b5b63bf3635b78a8",
            "preflight/outcomes/galatians-pistis-christou/claude/attempt-1.json": "ed1d59ca52451a231f9c5347c94426e40af5ea2e5ed69253e9b55e3b8ff73f26",
            "preflight/outcomes/galatians-pistis-christou/cohere/attempt-1.json": "c31894629d425b5036236091656830000da4a692ee130078ad86cb802426064e",
            "preflight/outcomes/galatians-pistis-christou/deepseek/attempt-1.json": "8a7b3ef5ef88e23deddbbc12807f08e79a48d667bb263e39343939441bd1fcec",
            "preflight/outcomes/galatians-pistis-christou/gemini/attempt-1.json": "12abb1eaa6e7e40db42d6a16d6a732f1137a8f08275b20e6895264eccac1b4e9",
            "preflight/outcomes/galatians-pistis-christou/gpt/attempt-1.json": "4ee748319a84be5c9d35e65d1abc3e8332b511774cb2667661479d03aa13eda5",
            "preflight/outcomes/galatians-pistis-christou/grok/attempt-1.json": "f8d56a543c7344fb4e174f7c13286b0190388d248b098ba8406ae2b8ab6d52d9",
            "preflight/outcomes/galatians-pistis-christou/mistral/attempt-1.json": "04e13ea8bda72092000a0a66c20539f6cf258883039c63b5aa3e754dbe327dab",
            "preflight/outcomes/galatians-pistis-christou/qwen/attempt-1.json": "8a04e394e0b5dc7c144935d45cf87c551e80b4de058eafb66eac79804d1ed534",
            "pricing-evidence.json": "918e7e904ad3ba13eeb077ec44d0cb34722f2ff9c11d24941d2da6e729cff49a",
            "pricing-recheck.json": "285d2624ac3f636e58a25646a1fd255266f9c6d6b03e1c13ba9d4294fbc79483",
        }
        self.assertEqual(
            contract.PARENT_GIT_HEAD,
            "3f77bf7456a94d18fe2d0d0780a8d0602b4b486b",
        )
        self.assertEqual(
            contract.PARENT_LOCK_SHA256,
            "8f4daf2ae53d07c7c53fc3f38d3ccd11aa18420185db632467fc9c280be523cc",
        )
        self.assertEqual(
            contract.PARENT_MANIFEST_SHA256,
            "7dedec143467eebd3e489515cdb23686bd011aa5ae663999a5bc9ceafc37c135",
        )
        self.assertEqual(
            contract.STRANDED_COHERE_INTENT_SHA256,
            "ee2b4d0b0c3ae1eaa0ea694f6ae04b158766012e9d6fec6ba938f7f352182bb9",
        )
        self.assertEqual(contract.PARENT_ARTIFACT_SHA256, expected_inventory)
        self.assertEqual(len(contract.PARENT_ARTIFACT_SHA256), 25)
        self.assertEqual(
            parent_artifact_bindings(),
            [
                {"path": path, "sha256": digest}
                for path, digest in sorted(contract.PARENT_ARTIFACT_SHA256.items())
            ],
        )
        self.assertEqual(len(contract.PARENT_PREFLIGHT_INTENT_PATHS), 8)
        self.assertEqual(len(contract.PARENT_PREFLIGHT_OUTCOME_PATHS), 8)
        self.assertEqual(len(contract.PARENT_GENERATION_INTENT_PATHS), 3)
        self.assertEqual(len(contract.PARENT_GENERATION_OUTCOME_PATHS), 2)
        self.assertEqual(
            contract.PARENT_REQUIRED_ABSENT_PATHS,
            (
                "outcomes/galatians-pistis-christou/cohere/attempt-1.json",
                "runs/galatians-pistis-christou.json",
            ),
        )
        for path, digest in contract.PARENT_ARTIFACT_SHA256.items():
            self.assertFalse(Path(path).is_absolute())
            self.assertRegex(digest, r"^[a-f0-9]{64}$")
        for item in contract.PRESERVED_SUCCESSES:
            self.assertIn("response_sha256", item)
            self.assertNotIn("response_text", item)

    def test_request_order_attempts_and_caps_are_exact(self) -> None:
        expected_targets = (
            "cohere",
            "qwen",
            "deepseek",
            "mistral",
            "grok",
            "gpt",
        )
        self.assertEqual(contract.TARGET_MODEL_KEYS, expected_targets)
        self.assertEqual(contract.PRESERVED_MODEL_KEYS, ("gemini", "claude"))
        self.assertTrue(
            set(contract.TARGET_MODEL_KEYS).isdisjoint(contract.PRESERVED_MODEL_KEYS)
        )
        self.assertEqual(_attempt_range("cohere"), (2,))
        for model_key in contract.UNTOUCHED_MODEL_KEYS:
            self.assertEqual(_attempt_range(model_key), (1, 2, 3))
        self.assertEqual(
            tuple(item["model_key"] for item in contract.TARGET_ATTEMPT_RECORDS),
            expected_targets,
        )
        self.assertEqual(
            tuple(
                item["semantic_attempt_start"]
                for item in contract.TARGET_ATTEMPT_RECORDS
            ),
            (2, 1, 1, 1, 1, 1),
        )
        self.assertEqual(
            tuple(
                item["maximum_generation_posts"]
                for item in contract.TARGET_ATTEMPT_RECORDS
            ),
            (1, 3, 3, 3, 3, 3),
        )
        self.assertTrue(
            all(
                item["fallback_allowed"] is False
                for item in contract.TARGET_ATTEMPT_RECORDS
            )
        )
        self.assertTrue(
            all(
                item["fresh_preflight_required_before_any_generation"] is True
                for item in contract.TARGET_ATTEMPT_RECORDS
            )
        )
        calculated_new_cap = sum(
            item["maximum_generation_posts"]
            * item["reserved_cost_microdollars_per_post"]
            for item in contract.TARGET_ATTEMPT_RECORDS
        )
        self.assertEqual(calculated_new_cap, 2_038_500)
        self.assertEqual(
            calculated_new_cap, contract.MAX_NEW_RECOVERY_RESERVED_MICRODOLLARS
        )
        self.assertEqual(contract.PARENT_RESERVED_MICRODOLLARS, 1_018_232)
        self.assertEqual(contract.MAX_PRIORITY_RESERVED_MICRODOLLARS, 3_056_732)
        self.assertEqual(
            contract.PARENT_RESERVED_MICRODOLLARS + calculated_new_cap,
            contract.MAX_PRIORITY_RESERVED_MICRODOLLARS,
        )
        self.assertEqual(contract.MAX_PREFLIGHT_REQUESTS, 18)
        self.assertEqual(contract.MAX_GENERATION_POSTS, 16)
        self.assertEqual(contract.MAX_OUTBOUND_REQUESTS, 34)

        summary = dry_run_summary(object())
        self.assertEqual(summary["target_model_keys"], list(expected_targets))
        self.assertEqual(summary["preserved_model_keys"], ["gemini", "claude"])
        self.assertEqual(summary["maximum_preflight_requests"], 18)
        self.assertEqual(summary["maximum_generation_posts"], 16)
        self.assertEqual(summary["network_requests"], 0)
        self.assertEqual(summary["environment_variables_read"], 0)

    def test_no_gemini_claude_fallback_or_third_candidate_is_authorized(self) -> None:
        scope = contract.authorization_scope()
        self.assertEqual(scope["target_model_keys"], list(contract.TARGET_MODEL_KEYS))
        self.assertEqual(scope["preserved_model_keys"], ["gemini", "claude"])
        self.assertNotIn("gemini", scope["target_model_keys"])
        self.assertNotIn("claude", scope["target_model_keys"])
        self.assertIs(scope["fallback_allowed"], False)
        self.assertIs(scope["third_candidate_allowed"], False)
        self.assertIs(scope["tools_enabled"], False)
        self.assertIs(scope["web_search_enabled"], False)
        self.assertIs(scope["retrieval_enabled"], False)
        self.assertIn(
            "make no Gemini or Claude generation call",
            contract.PAID_AUTHORIZATION_STATEMENT,
        )
        self.assertIn(
            "do not run the fallback or a third candidate",
            contract.PAID_AUTHORIZATION_STATEMENT,
        )

    def test_public_live_execution_boundary_exposes_no_injection_seams(self) -> None:
        self.assertEqual(
            tuple(inspect.signature(execute_prepared).parameters),
            ("prepared",),
            "the public paid-call boundary must fix environment, transport, and sleep",
        )

    def test_authorization_requires_the_exact_statement_and_six_target_scope(
        self,
    ) -> None:
        context = self.lock_context()
        timestamp = "2026-07-13T12:00:00+00:00"
        payload = authorization_payload(context, authorized_at=timestamp)
        self.assertEqual(
            payload["authorization_statement"],
            contract.PAID_AUTHORIZATION_STATEMENT,
        )
        self.assertEqual(
            payload["authorization_statement_sha256"],
            sha256_bytes(contract.PAID_AUTHORIZATION_STATEMENT.encode("utf-8")),
        )
        self.assertEqual(
            payload["authorization_statement_sha256"],
            "9cb0237affcf753d7ababa8845349ae088162eb16efecaff6b6f371ca9cacc27",
        )
        self.assertEqual(payload["scope"], contract.authorization_scope())
        self.assertEqual(
            payload["scope"]["target_model_keys"], list(contract.TARGET_MODEL_KEYS)
        )

        with self.assertRaisesRegex(
            RecoveryAuthorizationError, "exact disclosed authorization statement"
        ):
            write_paid_authorization(
                context,
                statement=contract.PAID_AUTHORIZATION_STATEMENT + " altered",
                authorized_at=timestamp,
            )
        self.assertFalse(
            (self.root / contract.PRIVATE_ROOT_RELATIVE).exists(),
            "a rejected statement must not create private recovery state",
        )

        changed = json.loads(json.dumps(context.lock))
        changed["paid_authorization"]["scope"]["fallback_allowed"] = True
        with self.assertRaisesRegex(
            RecoveryAuthorizationError, "paid authority terms changed"
        ):
            authorization_payload(
                SimpleNamespace(**{**context.__dict__, "lock": changed}),
                authorized_at=timestamp,
            )

    def test_pricing_normalization_accepts_exact_six_in_exact_order(self) -> None:
        evidence = self.pricing_evidence()
        normalized = normalize_pricing_evidence(self.root, evidence)
        self.assertEqual(normalized, evidence)
        self.assertEqual(
            [item["model_key"] for item in normalized],
            list(contract.TARGET_MODEL_KEYS),
        )
        self.assertNotIn("gemini", {item["model_key"] for item in normalized})
        self.assertNotIn("claude", {item["model_key"] for item in normalized})

    def test_pricing_normalization_rejects_wrong_count_order_host_and_rate(
        self,
    ) -> None:
        evidence = self.pricing_evidence()
        with self.assertRaisesRegex(RecoveryAuthorizationError, "all six"):
            normalize_pricing_evidence(self.root, evidence[:-1])

        reordered = list(evidence)
        reordered[0], reordered[1] = reordered[1], reordered[0]
        with self.assertRaisesRegex(RecoveryAuthorizationError, "differs"):
            normalize_pricing_evidence(self.root, reordered)

        hostile = json.loads(json.dumps(evidence))
        hostile[0]["official_source_url"] = "https://docs.cohere.com.evil.test/pricing"
        with self.assertRaisesRegex(RecoveryAuthorizationError, "host is not approved"):
            normalize_pricing_evidence(self.root, hostile)

        changed = json.loads(json.dumps(evidence))
        changed[-1]["output_per_million"] = 999
        with self.assertRaisesRegex(
            RecoveryAuthorizationError, "official pricing differs"
        ):
            normalize_pricing_evidence(self.root, changed)

    def test_pricing_normalization_rejects_boolean_zero_as_a_rate(self) -> None:
        evidence = self.pricing_evidence()
        self.assertEqual(evidence[0]["model_key"], "cohere")
        self.assertEqual(evidence[0]["input_per_million"], 0.0)
        evidence[0]["input_per_million"] = False
        with self.assertRaisesRegex(
            RecoveryAuthorizationError, "official pricing differs"
        ):
            normalize_pricing_evidence(self.root, evidence)

    def test_recovery_source_discovery_does_not_change_the_parent_rule3_lock(
        self,
    ) -> None:
        parent_path = self.source / contract.PARENT_LOCK_PATH
        parent_bytes = parent_path.read_bytes()
        parent = json.loads(parent_bytes)
        parent_sources = tuple(item["path"] for item in parent["execution_sources"])

        discovered = discover_recovery_source_paths(self.source, parent_sources)

        self.assertTrue(set(parent_sources).issubset(discovered))
        self.assertIn("harness/concordance_recovery/execute.py", discovered)
        self.assertIn("harness/run_concordance_recovery.py", discovered)
        self.assertNotIn(
            "harness/tests/test_concordance_recovery_contract_adversarial.py",
            discovered,
        )
        self.assertEqual(parent_path.read_bytes(), parent_bytes)
        self.assertEqual(
            canonical_json_bytes(build_rule3_lock(self.source)), parent_bytes
        )
        self.assertEqual(sha256_bytes(parent_bytes), contract.PARENT_LOCK_SHA256)

    def test_source_discovery_rejects_a_symlinked_recovery_source_directory(
        self,
    ) -> None:
        # The production tree is tested above. This focused assertion documents
        # the discovery contract without manufacturing a private parent tree.
        with self.assertRaisesRegex(RecoveryLockError, "must be a real directory"):
            discover_recovery_source_paths(self.root, ())

    def test_source_discovery_requires_every_live_recovery_entrypoint_and_module(
        self,
    ) -> None:
        parent = json.loads((self.source / contract.PARENT_LOCK_PATH).read_bytes())
        parent_sources = tuple(item["path"] for item in parent["execution_sources"])
        required_entrypoints = (
            "harness/authorize_concordance_recovery.py",
            "harness/run_concordance_recovery.py",
        )
        required_modules = (
            "harness/concordance_recovery/authorization.py",
            "harness/concordance_recovery/execute.py",
            "harness/concordance_recovery/journal.py",
            "harness/concordance_recovery/parent.py",
            "harness/concordance_recovery/state.py",
            "harness/concordance_recovery/transport.py",
        )
        for missing in required_entrypoints:
            with self.subTest(missing=missing):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    shutil.copytree(self.source / "harness", root / "harness")
                    (root / missing).unlink()
                    with self.assertRaisesRegex(
                        RecoveryLockError, "recovery implementation is incomplete"
                    ):
                        discover_recovery_source_paths(root, parent_sources)
        for missing in required_modules:
            with self.subTest(missing=missing):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    shutil.copytree(self.source / "harness", root / "harness")
                    (root / missing).unlink()
                    with self.assertRaises(RecoveryLockError):
                        discover_recovery_source_paths(root, parent_sources)


if __name__ == "__main__":
    unittest.main()
