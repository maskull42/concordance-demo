from __future__ import annotations

import copy
import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from concordance_recovery import composite, contract
from concordance_recovery.journal import COMPOSITE_SCHEMA
from concordance_recovery.parent import ParentEvidence
from concordance_recovery.state import RecoveryPaths
import review_concordance_recovery
from rule3 import contract as rule3_contract
from rule3 import review
from rule3.budget import JournalRecord


SHA = {
    "lock": "1" * 64,
    "auth": "2" * 64,
    "pricing": "3" * 64,
    "parent_manifest": "4" * 64,
    "manifest": "5" * 64,
    "question": "6" * 64,
    "stranded": "7" * 64,
    "composite": "8" * 64,
    "claim": "9" * 64,
}
HEAD = "a" * 40


def record(path: Path, payload: dict, digest: str) -> JournalRecord:
    return JournalRecord(path=path, payload=payload, sha256=digest)


class CompositeFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.private = root / contract.PRIVATE_ROOT_RELATIVE
        self.parent_root = root / contract.PARENT_PRIVATE_ROOT
        self.lock_context = SimpleNamespace(
            git_head=HEAD,
            lock_sha256=SHA["lock"],
            lock={},
        )
        self.prepared = SimpleNamespace(
            repository_root=root,
            lock_context=self.lock_context,
            question=SimpleNamespace(sha256=SHA["question"]),
            paths=RecoveryPaths.for_repository(root),
        )
        self.parent_manifest = record(
            self.parent_root / contract.PARENT_MANIFEST_PATH,
            {"schema_version": "fixture"},
            SHA["parent_manifest"],
        )
        parent_outcomes = []
        for index, model_key in enumerate(contract.PRESERVED_MODEL_KEYS):
            parent_outcomes.append(
                record(
                    self.parent_root / contract.PARENT_GENERATION_OUTCOME_PATHS[index],
                    self.response(model_key),
                    f"{index + 10:064x}",
                )
            )
        self.stranded = record(
            self.parent_root / contract.STRANDED_COHERE["intent_path"],
            {"model_key": "cohere"},
            SHA["stranded"],
        )
        self.parent = ParentEvidence(
            private_root=self.parent_root,
            manifest=self.parent_manifest,
            preserved_outcomes=(parent_outcomes[0], parent_outcomes[1]),
            stranded_intent=self.stranded,
            reserved_microdollars=contract.PARENT_RESERVED_MICRODOLLARS,
        )
        self.manifest = record(
            self.private / "manifests/six-model-preflight.json",
            {"schema_version": "fixture", "preflight_outcomes": []},
            SHA["manifest"],
        )
        self.recovery_outcomes = tuple(
            record(
                self.private / f"generation/outcomes/{model_key}/attempt-"
                f"{2 if model_key == 'cohere' else 1}.json",
                self.response(model_key),
                f"{index + 20:064x}",
            )
            for index, model_key in enumerate(contract.TARGET_MODEL_KEYS)
        )
        self.payload = self.composite_payload()
        self.composite = record(
            self.private / f"runs/{contract.CANDIDATE_ID}.json",
            self.payload,
            SHA["composite"],
        )

    def response(self, model_key: str) -> dict:
        requested, provider, _ = rule3_contract.EXPECTED_MODELS[model_key]
        return {
            "status": "success",
            "candidate_id": contract.CANDIDATE_ID,
            "cell_id": f"{contract.CANDIDATE_ID}:{model_key}:default:answer",
            "model_key": model_key,
            "provider": provider,
            "requested_model_id": requested,
            "provider_response_id": f"fixture-{model_key}",
            "response_text": f"Private fixture answer for {model_key}.",
            "prompt_sha256": review._expected_prompt_sha(contract.CANDIDATE_ID),
        }

    def composite_payload(self) -> dict:
        outcomes = []
        for index, model_key in enumerate(contract.MODEL_ORDER):
            if model_key in contract.PRESERVED_MODEL_KEYS:
                source = self.parent.preserved_outcomes[index]
                outcomes.append(
                    {
                        "model_key": model_key,
                        "source_lane": "immutable-parent",
                        "path": contract.PARENT_GENERATION_OUTCOME_PATHS[index],
                        "sha256": source.sha256,
                        "semantic_attempt_number": 1,
                    }
                )
                continue
            attempt = 2 if model_key == "cohere" else 1
            source = next(
                item
                for item in self.recovery_outcomes
                if item.payload["model_key"] == model_key
            )
            outcomes.append(
                {
                    "model_key": model_key,
                    "source_lane": "successor-recovery",
                    "path": f"generation/outcomes/{model_key}/attempt-{attempt}.json",
                    "sha256": source.sha256,
                    "semantic_attempt_number": attempt,
                    "raw_response": {
                        "path": (
                            f"generation/raw-responses/{model_key}/"
                            f"attempt-{attempt}.json"
                        ),
                        "sha256": f"{30 + index:064x}",
                    },
                    "intent": {
                        "path": (
                            f"generation/intents/{model_key}/attempt-{attempt}.json"
                        ),
                        "sha256": f"{40 + index:064x}",
                    },
                }
            )
        new_reserved = 100
        return {
            "schema_version": COMPOSITE_SCHEMA,
            "status": "complete-eight-successes-two-parent-six-recovery",
            "recovery_id": contract.RECOVERY_ID,
            "pool_id": contract.POOL_ID,
            "candidate_id": contract.CANDIDATE_ID,
            "phase": contract.PRIORITY_PHASE,
            "git_head": HEAD,
            "recovery_lock_sha256": SHA["lock"],
            "authorization_receipt_sha256": SHA["auth"],
            "pricing_recheck_receipt_sha256": SHA["pricing"],
            "parent_lock_sha256": contract.PARENT_LOCK_SHA256,
            "parent_manifest_sha256": SHA["parent_manifest"],
            "parent_claim": {
                "path": self.prepared.paths.claim.relative_to(self.root).as_posix(),
                "sha256": SHA["claim"],
            },
            "sealed_at": "2026-07-13T12:00:00Z",
            "question_sha256": SHA["question"],
            "parent_plan_sha256": contract.PARENT_PLAN_SHA256,
            "recovery_manifest": {
                "path": "manifests/six-model-preflight.json",
                "sha256": SHA["manifest"],
            },
            "parent_stranded_cohere_intent": {
                "path": contract.STRANDED_COHERE["intent_path"],
                "sha256": SHA["stranded"],
                "disposition": contract.STRANDED_COHERE["disposition"],
            },
            "successful_outcome_count": 8,
            "outcomes": outcomes,
            "budget": {
                "parent_reserved_microdollars": (contract.PARENT_RESERVED_MICRODOLLARS),
                "new_reserved_microdollars": new_reserved,
                "combined_reserved_microdollars": (
                    contract.PARENT_RESERVED_MICRODOLLARS + new_reserved
                ),
                "new_reserved_cap_microdollars": (
                    contract.NEW_RESERVED_CAP_MICRODOLLARS
                ),
                "combined_reserved_cap_microdollars": (
                    contract.COMBINED_RESERVED_CAP_MICRODOLLARS
                ),
            },
        }

    def validated(self) -> composite._ValidatedComposite:
        return composite._ValidatedComposite(
            prepared=self.prepared,
            parent=self.parent,
            manifest=self.manifest,
            composite=self.composite,
            recovery_outcomes=self.recovery_outcomes,
        )


class CompositeShapeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = CompositeFixture(Path(self.temporary.name).resolve())

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def validate(self, payload: dict | None = None) -> tuple[dict, ...]:
        current = self.fixture.composite
        if payload is not None:
            current = record(current.path, payload, current.sha256)
        return composite._validate_composite_shape(
            self.fixture.prepared,
            self.fixture.parent,
            self.fixture.manifest,
            current,
        )

    def test_accepts_exact_two_parent_plus_six_recovery_order(self) -> None:
        items = self.validate()
        self.assertEqual(
            tuple(item["model_key"] for item in items), contract.MODEL_ORDER
        )
        self.assertEqual(
            tuple(item["source_lane"] for item in items[:2]),
            ("immutable-parent", "immutable-parent"),
        )
        self.assertEqual(
            tuple(item["source_lane"] for item in items[2:]),
            ("successor-recovery",) * 6,
        )

    def test_rejects_order_lane_path_and_duplicate_substitution(self) -> None:
        mutations = []
        reordered = copy.deepcopy(self.fixture.payload)
        reordered["outcomes"][2], reordered["outcomes"][3] = (
            reordered["outcomes"][3],
            reordered["outcomes"][2],
        )
        mutations.append(reordered)
        wrong_lane = copy.deepcopy(self.fixture.payload)
        wrong_lane["outcomes"][0]["source_lane"] = "successor-recovery"
        mutations.append(wrong_lane)
        wrong_path = copy.deepcopy(self.fixture.payload)
        wrong_path["outcomes"][2]["path"] = "generation/outcomes/qwen/attempt-1.json"
        mutations.append(wrong_path)
        wrong_attempt = copy.deepcopy(self.fixture.payload)
        wrong_attempt["outcomes"][2]["semantic_attempt_number"] = 1
        mutations.append(wrong_attempt)
        for changed in mutations:
            with self.subTest(changed=changed["outcomes"][:3]):
                with self.assertRaises(composite.CompositeRecoveryError):
                    self.validate(changed)

    def test_composite_receipt_may_not_contain_response_text(self) -> None:
        changed = copy.deepcopy(self.fixture.payload)
        changed["outcomes"][0]["response_text"] = "forbidden"
        with self.assertRaisesRegex(
            composite.CompositeRecoveryError, "forbidden response text"
        ):
            self.validate(changed)
        self.assertFalse(composite._contains_response_text(self.fixture.payload))

    def test_rejects_budget_and_preserved_hash_tamper(self) -> None:
        changed = copy.deepcopy(self.fixture.payload)
        changed["budget"]["new_reserved_microdollars"] = (
            contract.NEW_RESERVED_CAP_MICRODOLLARS + 1
        )
        with self.assertRaises(composite.CompositeRecoveryError):
            self.validate(changed)
        changed = copy.deepcopy(self.fixture.payload)
        changed["outcomes"][0]["sha256"] = "f" * 64
        with self.assertRaisesRegex(
            composite.CompositeRecoveryError, "preserve exact gemini"
        ):
            self.validate(changed)


class ResponseBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.fixture = CompositeFixture(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_builds_canonical_response_bundle_and_hash_only_bindings(self) -> None:
        facts = {
            "git_head": HEAD,
            "lock_sha256": contract.PARENT_LOCK_SHA256,
            "question_sha256": SHA["question"],
            "plan_sha256": contract.PARENT_PLAN_SHA256,
            "review_assets_sha256": "9" * 64,
        }
        with (
            mock.patch.object(
                composite,
                "_validate_composite",
                return_value=self.fixture.validated(),
            ),
            mock.patch.object(review, "_review_lock_facts", return_value=facts),
            mock.patch.object(review, "_require_bundle_lineage") as lineage,
        ):
            bundle = composite.load_composite_responses(
                self.root, contract.CANDIDATE_ID
            )
        self.assertEqual(
            tuple(item.model_key for item in bundle.responses), contract.MODEL_ORDER
        )
        self.assertEqual(bundle.responses[2].attempt_number, 2)
        self.assertEqual(bundle.bindings["model_manifest_sha256"], SHA["manifest"])
        self.assertEqual(bundle.bindings["run_receipt_sha256"], SHA["composite"])
        self.assertTrue(
            bundle.responses[0].outcome_path.startswith(
                contract.PARENT_PRIVATE_ROOT + "/"
            )
        )
        self.assertTrue(
            bundle.responses[2].outcome_path.startswith(
                contract.PRIVATE_ROOT_RELATIVE + "/"
            )
        )
        lineage.assert_called_once_with(self.root, contract.CANDIDATE_ID, bundle)

    def test_rejects_fallback_or_third_candidate(self) -> None:
        for candidate in (
            rule3_contract.CANDIDATES[1]["id"],
            "third-candidate",
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaisesRegex(
                    composite.CompositeRecoveryError, "only the locked priority"
                ):
                    composite._validate_composite(self.root, candidate)


class ReadOnlyReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = CompositeFixture(Path(self.temporary.name).resolve())

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_rejects_unfinalized_preflight_or_generation_attempt(self) -> None:
        cases = (
            (
                self.fixture.prepared.paths.preflight_intent("qwen", 1),
                "preflight attempt remains unfinalized",
            ),
            (
                self.fixture.prepared.paths.generation_intent("qwen", 1),
                "generation attempt remains unfinalized",
            ),
        )
        for path, message in cases:
            with self.subTest(path=path):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
                with self.assertRaisesRegex(composite.CompositeRecoveryError, message):
                    composite._require_closed_attempts(self.fixture.prepared)
                path.unlink()


class SuccessorContextTests(unittest.TestCase):
    def test_context_is_non_nestable_and_restores_globals(self) -> None:
        original_root = review.PRIVATE_RELATIVE_ROOT
        original_loader = review._review_response_bundle
        with composite.successor_review_context():
            self.assertEqual(
                review.PRIVATE_RELATIVE_ROOT, composite.SUCCESSOR_REVIEW_ROOT
            )
            self.assertIs(
                review._review_response_bundle, composite.load_composite_responses
            )
            with self.assertRaisesRegex(
                composite.CompositeRecoveryError, "already active"
            ):
                with composite.successor_review_context():
                    pass
        self.assertEqual(review.PRIVATE_RELATIVE_ROOT, original_root)
        self.assertIs(review._review_response_bundle, original_loader)

    def test_context_restores_globals_after_exception(self) -> None:
        original_root = review.PRIVATE_RELATIVE_ROOT
        original_loader = review._review_response_bundle
        with self.assertRaisesRegex(RuntimeError, "fixture failure"):
            with composite.successor_review_context():
                raise RuntimeError("fixture failure")
        self.assertEqual(review.PRIVATE_RELATIVE_ROOT, original_root)
        self.assertIs(review._review_response_bundle, original_loader)


class RecoveryReviewCliTests(unittest.TestCase):
    def test_subcommands_expose_only_their_supported_modes(self) -> None:
        accepted = (
            ["prepare", "--stage", "blind", "--write"],
            ["finalize", "--stage", "author", "--seal", "--input", "x.json"],
            ["evaluate", "--verify"],
        )
        for arguments in accepted:
            with self.subTest(arguments=arguments):
                review_concordance_recovery.parser().parse_args(arguments)

        rejected = (
            ["prepare", "--stage", "blind", "--seal"],
            ["finalize", "--stage", "author", "--write"],
            ["evaluate", "--seal"],
        )
        for arguments in rejected:
            with self.subTest(arguments=arguments):
                with (
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit),
                ):
                    review_concordance_recovery.parser().parse_args(arguments)

    def test_prepare_delegates_fixed_candidate_inside_successor_context(self) -> None:
        entered = []

        @contextlib.contextmanager
        def fixture_context():
            entered.append(True)
            yield

        with (
            mock.patch.object(
                review_concordance_recovery,
                "successor_review_context",
                fixture_context,
            ),
            mock.patch.object(
                review_concordance_recovery.prepare_rule3_review,
                "main",
                return_value=0,
            ) as delegated,
        ):
            result = review_concordance_recovery.main(
                ["prepare", "--stage", "blind", "--check"]
            )
        self.assertEqual(result, 0)
        self.assertEqual(entered, [True])
        delegated.assert_called_once_with(
            [
                "--stage",
                "blind",
                "--candidate",
                contract.CANDIDATE_ID,
                "--check",
            ]
        )


if __name__ == "__main__":
    unittest.main()
