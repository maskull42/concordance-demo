from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from concordance_harness.config import load_harness_config
from concordance_harness.providers import ProviderError
from concordance_recovery import contract, execute
from concordance_recovery.authorization import ReceiptBinding
from concordance_recovery.execute import Authority, RecoveryExecutionError
from concordance_recovery.journal import JournalRecord
from concordance_recovery.parent import ParentEvidence

from support import repository_root


HEAD = "a" * 40
LOCK_SHA = "b" * 64
QUESTION_SHA = "c" * 64
AUTH_SHA = "d" * 64
PRICING_SHA = "e" * 64
CLAIM_SHA = "f" * 64

T0 = "2026-07-13T10:00:00+00:00"
T1 = "2026-07-13T11:00:00+00:00"
T2 = "2026-07-13T12:00:00+00:00"
T3 = "2026-07-13T13:00:00+00:00"
T4 = "2026-07-13T14:00:00+00:00"
T5 = "2026-07-13T15:00:00+00:00"
T6 = "2026-07-13T16:00:00+00:00"

INTERRUPTED_SUMMARY = (
    "metadata attempt ended without a durable HTTP response; "
    "the idempotent GET is consumed and may advance"
)


def record(path: Path, payload: dict, seed: int) -> JournalRecord:
    return JournalRecord(path=path, payload=payload, sha256=f"{seed:064x}")


class SyntheticPaths:
    """The recovery path API rooted entirely in a disposable test directory."""

    def __init__(self, repository_root: Path) -> None:
        self.private_root = repository_root / "synthetic-private-recovery"
        self.claim = repository_root / "synthetic-claims" / "exact-parent.json"
        self.manifest = self.private_root / "manifests" / "six-model.json"
        self.composite = self.private_root / "runs" / "candidate.json"

    def preflight_intent(self, model_key: str, attempt: int) -> Path:
        return self.private_root / f"preflight/intents/{model_key}/{attempt}.json"

    def preflight_raw(self, model_key: str, attempt: int) -> Path:
        return self.private_root / f"preflight/raw/{model_key}/{attempt}.json"

    def preflight_outcome(self, model_key: str, attempt: int) -> Path:
        return self.private_root / f"preflight/outcomes/{model_key}/{attempt}.json"

    def generation_intent(self, model_key: str, attempt: int) -> Path:
        return self.private_root / f"generation/intents/{model_key}/{attempt}.json"

    def generation_raw(self, model_key: str, attempt: int) -> Path:
        return self.private_root / f"generation/raw/{model_key}/{attempt}.json"

    def generation_outcome(self, model_key: str, attempt: int) -> Path:
        return self.private_root / f"generation/outcomes/{model_key}/{attempt}.json"


class RecoveryLineageFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.paths = SyntheticPaths(self.root)
        config = load_harness_config(repository_root() / "harness/config/models.json")
        self.models = config.by_key()
        self.question = SimpleNamespace(sha256=QUESTION_SHA)
        self.calls = {
            model_key: SimpleNamespace(
                model=self.models[model_key],
                cell_id=f"synthetic:{model_key}:answer",
                question=self.question,
                answer_messages=self.messages,
            )
            for model_key in contract.TARGET_MODEL_KEYS
        }
        self.prepared = SimpleNamespace(
            repository_root=self.root,
            paths=self.paths,
            lock_context=SimpleNamespace(
                git_head=HEAD,
                lock_sha256=LOCK_SHA,
                lock={"target_plan": {"plan_sha256": "1" * 64}},
            ),
            config=SimpleNamespace(sha256="2" * 64),
            question=self.question,
            target_plan=tuple(
                self.calls[model_key] for model_key in contract.TARGET_MODEL_KEYS
            ),
        )
        self.claim = ReceiptBinding(
            self.paths.claim,
            {"claimed_at": T0},
            CLAIM_SHA,
        )
        self.authority = Authority(
            authorization=ReceiptBinding(
                self.paths.private_root / "authorization.json", {}, AUTH_SHA
            ),
            pricing=ReceiptBinding(
                self.paths.private_root / "pricing.json", {}, PRICING_SHA
            ),
            claim=self.claim,
        )
        parent_root = self.root / "synthetic-parent"
        self.parent = ParentEvidence(
            private_root=parent_root,
            manifest=record(parent_root / "manifest.json", {"sealed_at": T0}, 10),
            preserved_outcomes=(
                record(
                    parent_root / "gemini.json",
                    {"model_key": "gemini", "completed_at": T0},
                    11,
                ),
                record(
                    parent_root / "claude.json",
                    {"model_key": "claude", "completed_at": T0},
                    12,
                ),
            ),
            stranded_intent=record(
                parent_root / "cohere-intent.json",
                {"model_key": "cohere", "created_at": T0},
                13,
            ),
            reserved_microdollars=contract.PARENT_RESERVED_MICRODOLLARS,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def messages() -> list[dict[str, str]]:
        return [
            {"role": "system", "content": "Synthetic system prompt."},
            {"role": "user", "content": "Synthetic recovery question."},
        ]

    def preflight_intent(
        self, model_key: str = "qwen", *, created_at: str = T1
    ) -> JournalRecord:
        return record(
            self.paths.preflight_intent(model_key, 1),
            {"attempt_number": 1, "created_at": created_at},
            20,
        )

    def preflight_raw(
        self, model_key: str = "qwen", *, received_at: str = T2
    ) -> JournalRecord:
        return record(
            self.paths.preflight_raw(model_key, 1),
            {"received_at": received_at},
            21,
        )

    def preflight_outcomes(self, *, completed_at: str = T2) -> list[JournalRecord]:
        return [
            record(
                self.paths.preflight_outcome(model_key, 1),
                {
                    "status": "success",
                    "model_key": model_key,
                    "provider_returned_model_id": (
                        self.models[model_key].requested_model_id
                    ),
                    "completed_at": completed_at,
                },
                30 + index,
            )
            for index, model_key in enumerate(contract.TARGET_MODEL_KEYS)
        ]

    def manifest(self, *, sealed_at: str = T3) -> JournalRecord:
        return record(
            self.paths.manifest,
            {"sealed_at": sealed_at, "parent_claim": self.claim_binding()},
            40,
        )

    def generation_intent(
        self,
        model_key: str = "qwen",
        *,
        created_at: str = T4,
        manifest: JournalRecord | None = None,
        preflight: JournalRecord | None = None,
    ) -> JournalRecord:
        manifest = manifest or self.manifest()
        preflight = preflight or record(
            self.paths.preflight_outcome(model_key, 1),
            {
                "status": "success",
                "model_key": model_key,
                "provider_returned_model_id": (
                    self.models[model_key].requested_model_id
                ),
                "completed_at": T2,
            },
            41,
        )
        call = self.calls[model_key]
        attempt = 2 if model_key == "cohere" else 1
        payload = execute._generation_intent_payload(
            self.prepared,
            self.authority,
            self.parent,
            manifest,
            preflight,
            call,
            attempt,
            created_at=created_at,
        )
        return record(self.paths.generation_intent(model_key, attempt), payload, 50)

    def generation_raw(
        self, model_key: str = "qwen", *, received_at: str = T5
    ) -> JournalRecord:
        attempt = 2 if model_key == "cohere" else 1
        return record(
            self.paths.generation_raw(model_key, attempt),
            {"received_at": received_at},
            51,
        )

    def generation_outcomes(
        self,
        *,
        first_attempted_at: str = T4,
        first_completed_at: str = T5,
        sequential: bool = True,
    ) -> list[JournalRecord]:
        outcomes: list[JournalRecord] = []
        hour = 0
        for index, model_key in enumerate(contract.TARGET_MODEL_KEYS):
            attempt = 2 if model_key == "cohere" else 1
            attempted_at = (
                first_attempted_at
                if index == 0
                else f"2026-07-14T{hour + index * 2:02d}:00:00+00:00"
            )
            completed_at = (
                first_completed_at
                if index == 0
                else f"2026-07-14T{hour + index * 2 + 1:02d}:00:00+00:00"
            )
            if not sequential and index == 1:
                attempted_at = T4
                completed_at = T6
            outcomes.append(
                record(
                    self.paths.generation_outcome(model_key, attempt),
                    {
                        "status": "success",
                        "model_key": model_key,
                        "semantic_attempt_number": attempt,
                        "attempted_at": attempted_at,
                        "completed_at": completed_at,
                        "raw_response": {
                            "path": f"generation/raw/{model_key}/{attempt}.json",
                            "sha256": f"{70 + index:064x}",
                        },
                        "intent": {
                            "path": f"generation/intents/{model_key}/{attempt}.json",
                            "sha256": f"{80 + index:064x}",
                        },
                    },
                    60 + index,
                )
            )
        return outcomes

    def claim_binding(self) -> dict[str, str]:
        return {
            "path": self.paths.claim.relative_to(self.root).as_posix(),
            "sha256": CLAIM_SHA,
        }


class ChronologyTests(RecoveryLineageFixture):
    def test_preflight_outcome_cannot_complete_before_its_intent(self) -> None:
        intent = self.preflight_intent(created_at=T2)
        call = self.calls["qwen"]
        with self.assertRaisesRegex(RecoveryExecutionError, "chronolog|predat|before"):
            payload = execute._preflight_outcome_payload(
                self.prepared,
                self.authority,
                intent,
                call,
                raw=None,
                result=None,
                error={
                    "category": "metadata-interrupted",
                    "retryable": True,
                    "sanitized_summary": INTERRUPTED_SUMMARY,
                },
                completed_at=T1,
            )
            outcome = record(self.paths.preflight_outcome("qwen", 1), payload, 90)
            asyncio.run(
                execute._validate_preflight_outcome(
                    self.prepared,
                    self.authority,
                    call,
                    intent,
                    None,
                    outcome,
                )
            )

    def test_captured_preflight_outcome_cannot_complete_before_raw_receipt(
        self,
    ) -> None:
        intent = self.preflight_intent(created_at=T1)
        raw = self.preflight_raw(received_at=T3)
        call = self.calls["qwen"]
        with self.assertRaisesRegex(RecoveryExecutionError, "chronolog|predat|before"):
            payload = execute._preflight_outcome_payload(
                self.prepared,
                self.authority,
                intent,
                call,
                raw=raw,
                result=None,
                error={
                    "category": "provider-error",
                    "retryable": True,
                    "sanitized_summary": "canonical provider error",
                },
                completed_at=T2,
            )
            outcome = record(self.paths.preflight_outcome("qwen", 1), payload, 91)
            with mock.patch.object(
                execute,
                "_parse_preflight_capture",
                new=mock.AsyncMock(
                    side_effect=ProviderError(
                        "canonical provider error",
                        category="provider-error",
                        retryable=True,
                    )
                ),
            ):
                asyncio.run(
                    execute._validate_preflight_outcome(
                        self.prepared,
                        self.authority,
                        call,
                        intent,
                        raw,
                        outcome,
                    )
                )

    def test_manifest_cannot_be_sealed_before_preflight_completion(self) -> None:
        outcomes = self.preflight_outcomes(completed_at=T4)
        with self.assertRaisesRegex(
            RecoveryExecutionError, "manifest.*before|chronolog|predat"
        ):
            execute._manifest_payload(
                self.prepared,
                self.authority,
                self.parent,
                outcomes,
                sealed_at=T3,
            )

    def test_generation_intent_cannot_predate_manifest_or_preflight(self) -> None:
        manifest = self.manifest(sealed_at=T4)
        preflight = record(
            self.paths.preflight_outcome("qwen", 1),
            {
                "status": "success",
                "model_key": "qwen",
                "provider_returned_model_id": (self.models["qwen"].requested_model_id),
                "completed_at": T3,
            },
            92,
        )
        with self.assertRaisesRegex(
            RecoveryExecutionError, "generation.*before|chronolog|predat"
        ):
            self.generation_intent(
                created_at=T2,
                manifest=manifest,
                preflight=preflight,
            )

    def test_generation_outcome_cannot_complete_before_raw_receipt(self) -> None:
        manifest = self.manifest(sealed_at=T2)
        preflight = record(
            self.paths.preflight_outcome("qwen", 1),
            {
                "status": "success",
                "model_key": "qwen",
                "provider_returned_model_id": (self.models["qwen"].requested_model_id),
                "completed_at": T1,
            },
            93,
        )
        intent = self.generation_intent(
            created_at=T3, manifest=manifest, preflight=preflight
        )
        raw = self.generation_raw(received_at=T5)
        call = self.calls["qwen"]
        with self.assertRaisesRegex(RecoveryExecutionError, "chronolog|predat|before"):
            payload = execute._generation_outcome_payload(
                self.prepared,
                self.authority,
                intent,
                raw,
                call,
                result=None,
                error={
                    "category": "provider-error",
                    "retryable": True,
                    "sanitized_summary": "canonical generation error",
                },
                latency_ms=1,
                completed_at=T4,
            )
            outcome = record(self.paths.generation_outcome("qwen", 1), payload, 94)
            with mock.patch.object(
                execute,
                "_parse_generation_capture",
                new=mock.AsyncMock(
                    side_effect=ProviderError(
                        "canonical generation error",
                        category="provider-error",
                        retryable=True,
                    )
                ),
            ):
                asyncio.run(
                    execute._validate_generation_outcome(
                        self.prepared,
                        self.authority,
                        call,
                        preflight,
                        intent,
                        raw,
                        outcome,
                    )
                )

    def test_generation_cells_cannot_overlap_or_run_out_of_order(self) -> None:
        manifest = self.manifest(sealed_at=T3)
        outcomes = self.generation_outcomes(sequential=False)
        with self.assertRaisesRegex(
            RecoveryExecutionError, "generation.*order|chronolog|overlap|before"
        ):
            execute._composite_payload(
                self.prepared,
                self.authority,
                self.parent,
                manifest,
                outcomes,
                sealed_at="2026-07-15T12:00:00+00:00",
            )

    def test_composite_seal_must_follow_manifest_and_all_outcomes(self) -> None:
        for manifest_time, outcome_time, composite_time in (
            (T5, T3, T4),
            (T2, T5, T4),
        ):
            with self.subTest(
                manifest=manifest_time,
                outcome=outcome_time,
                composite=composite_time,
            ):
                manifest = self.manifest(sealed_at=manifest_time)
                outcomes = self.generation_outcomes(
                    first_attempted_at=T3,
                    first_completed_at=outcome_time,
                )
                with self.assertRaisesRegex(
                    RecoveryExecutionError,
                    "composite.*before|chronolog|predat",
                ):
                    execute._composite_payload(
                        self.prepared,
                        self.authority,
                        self.parent,
                        manifest,
                        outcomes,
                        sealed_at=composite_time,
                    )


class ErrorReceiptExactnessTests(RecoveryLineageFixture):
    def test_interrupted_preflight_receipt_is_not_free_form(self) -> None:
        intent = self.preflight_intent(created_at=T1)
        call = self.calls["qwen"]
        payload = execute._preflight_outcome_payload(
            self.prepared,
            self.authority,
            intent,
            call,
            raw=None,
            result=None,
            error={
                "category": "metadata-interrupted",
                "retryable": True,
                "sanitized_summary": "forged but nonempty interrupted summary",
            },
            completed_at=T2,
        )
        outcome = record(self.paths.preflight_outcome("qwen", 1), payload, 100)
        with self.assertRaisesRegex(
            RecoveryExecutionError, "interrupted.*changed|receipt.*changed|exact"
        ):
            asyncio.run(
                execute._validate_preflight_outcome(
                    self.prepared,
                    self.authority,
                    call,
                    intent,
                    None,
                    outcome,
                )
            )

    def test_captured_preflight_error_summary_must_match_replayed_error(self) -> None:
        intent = self.preflight_intent(created_at=T1)
        raw = self.preflight_raw(received_at=T2)
        call = self.calls["qwen"]
        payload = execute._preflight_outcome_payload(
            self.prepared,
            self.authority,
            intent,
            call,
            raw=raw,
            result=None,
            error={
                "category": "provider-error",
                "retryable": True,
                "sanitized_summary": "forged captured summary",
            },
            completed_at=T3,
        )
        outcome = record(self.paths.preflight_outcome("qwen", 1), payload, 101)
        with (
            mock.patch.object(
                execute,
                "_parse_preflight_capture",
                new=mock.AsyncMock(
                    side_effect=ProviderError(
                        "canonical provider error",
                        category="provider-error",
                        retryable=True,
                    )
                ),
            ),
            self.assertRaisesRegex(
                RecoveryExecutionError, "error receipt changed|summary"
            ),
        ):
            asyncio.run(
                execute._validate_preflight_outcome(
                    self.prepared,
                    self.authority,
                    call,
                    intent,
                    raw,
                    outcome,
                )
            )

    def test_captured_generation_error_summary_must_match_replayed_error(self) -> None:
        manifest = self.manifest(sealed_at=T2)
        preflight = record(
            self.paths.preflight_outcome("qwen", 1),
            {
                "status": "success",
                "model_key": "qwen",
                "provider_returned_model_id": (self.models["qwen"].requested_model_id),
                "completed_at": T1,
            },
            102,
        )
        intent = self.generation_intent(
            created_at=T3, manifest=manifest, preflight=preflight
        )
        raw = self.generation_raw(received_at=T4)
        call = self.calls["qwen"]
        payload = execute._generation_outcome_payload(
            self.prepared,
            self.authority,
            intent,
            raw,
            call,
            result=None,
            error={
                "category": "provider-error",
                "retryable": True,
                "sanitized_summary": "forged generation summary",
            },
            latency_ms=1,
            completed_at=T5,
        )
        outcome = record(self.paths.generation_outcome("qwen", 1), payload, 103)
        with (
            mock.patch.object(
                execute,
                "_parse_generation_capture",
                new=mock.AsyncMock(
                    side_effect=ProviderError(
                        "canonical generation error",
                        category="provider-error",
                        retryable=True,
                    )
                ),
            ),
            self.assertRaisesRegex(
                RecoveryExecutionError, "error receipt changed|summary"
            ),
        ):
            asyncio.run(
                execute._validate_generation_outcome(
                    self.prepared,
                    self.authority,
                    call,
                    preflight,
                    intent,
                    raw,
                    outcome,
                )
            )


class ParentClaimBindingTests(RecoveryLineageFixture):
    def test_manifest_and_composite_bind_the_exact_parent_claim(self) -> None:
        preflights = self.preflight_outcomes(completed_at=T2)
        manifest_payload = execute._manifest_payload(
            self.prepared,
            self.authority,
            self.parent,
            preflights,
            sealed_at=T3,
        )
        self.assertEqual(manifest_payload.get("parent_claim"), self.claim_binding())

        manifest = record(self.paths.manifest, manifest_payload, 110)
        outcomes = self.generation_outcomes()
        composite_payload = execute._composite_payload(
            self.prepared,
            self.authority,
            self.parent,
            manifest,
            outcomes,
            sealed_at="2026-07-15T12:00:00+00:00",
        )
        self.assertEqual(composite_payload.get("parent_claim"), self.claim_binding())


if __name__ == "__main__":
    unittest.main()
