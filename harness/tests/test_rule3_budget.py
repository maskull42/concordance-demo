from __future__ import annotations

import json
import stat
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from concordance_harness.util import canonical_json_bytes, sha256_bytes
from rule3.budget import (
    CANDIDATE_CAP_MICRODOLLARS,
    FALLBACK_CANDIDATE_ID,
    INTENT_SCHEMA_VERSION,
    OUTCOME_SCHEMA_VERSION,
    PRIORITY_CANDIDATE_ID,
    AttemptNotAllowed,
    BudgetError,
    BudgetExceeded,
    BudgetLedger,
    JournalRecord,
    StrandedIntent,
    write_once_private_json,
)

HASH = "a" * 64
AUTH_HASH = "b" * 64
PRICING_HASH = "c" * 64
GIT_HEAD = "d" * 40
QUESTION_HASH = "1" * 64
PROMPT_HASH = "2" * 64
MODELS = ("gemini", "claude")


class Rule3BudgetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = (Path(self.temporary.name) / "private").resolve()
        self.ledger = self.make_ledger()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def contracts(
        self, costs: dict[tuple[str, str], int] | None = None
    ) -> dict[tuple[str, str], dict[str, object]]:
        costs = costs or {}
        result = {}
        for candidate in (PRIORITY_CANDIDATE_ID, FALLBACK_CANDIDATE_ID):
            for model in MODELS:
                messages = [
                    {"role": "system", "content": "frozen system"},
                    {"role": "user", "content": f"question for {candidate}"},
                ]
                requested = {
                    "temperature": {"sent": False, "value": None},
                    "tools_enabled": False,
                }
                result[(candidate, model)] = {
                    "candidate_id": candidate,
                    "phase": (
                        "priority" if candidate == PRIORITY_CANDIDATE_ID else "fallback"
                    ),
                    "cell_id": f"{candidate}:{model}:default:answer",
                    "model_key": model,
                    "model_family": f"{model}-family",
                    "provider": f"{model}-provider",
                    "route": f"{model}-direct",
                    "requested_model_id": f"{model}-model",
                    "approved_returned_model_ids": [f"{model}-model"],
                    "api_style": "openai",
                    "question_sha256": QUESTION_HASH,
                    "prompt_sha256": PROMPT_HASH,
                    "messages": messages,
                    "messages_sha256": sha256_bytes(canonical_json_bytes(messages)),
                    "requested_params": requested,
                    "requested_params_sha256": sha256_bytes(
                        canonical_json_bytes(requested)
                    ),
                    "effective_params": {
                        "max_tokens": {
                            "state": "known",
                            "value": 16_384,
                            "source": "request",
                        }
                    },
                    "finish_reason": "stop",
                    "reserved_cost_microdollars": costs.get((candidate, model), 100),
                    "input_per_million": 1.0,
                    "output_per_million": 1.0,
                    "pricing_as_of": "2026-07-13",
                }
        return result

    def make_ledger(
        self, costs: dict[tuple[str, str], int] | None = None
    ) -> BudgetLedger:
        ledger = BudgetLedger(
            self.root,
            lock_sha256=HASH,
            authorization_receipt_sha256=AUTH_HASH,
            pricing_recheck_receipt_sha256=PRICING_HASH,
            git_head=GIT_HEAD,
            cell_contracts=self.contracts(costs),
        )
        ledger.initialize()
        return ledger

    def reserve(
        self,
        *,
        candidate: str = PRIORITY_CANDIDATE_ID,
        model: str = "gemini",
        cell: str | None = None,
        attempt: int = 1,
        cost: int | None = None,
    ) -> JournalRecord:
        contract = self.ledger.cell_contracts.get((candidate, model), {})
        return self.ledger.reserve(
            candidate_id=candidate,
            cell_id=cell
            or contract.get("cell_id", f"{candidate}:{model}:default:answer"),
            model_key=model,
            attempt_number=attempt,
            reserved_cost_microdollars=(
                contract.get("reserved_cost_microdollars", 100)
                if cost is None
                else cost
            ),
            question_sha256=contract.get("question_sha256", QUESTION_HASH),
            prompt_sha256=contract.get("prompt_sha256", PROMPT_HASH),
            messages_sha256=contract.get("messages_sha256", "3" * 64),
            requested_params_sha256=contract.get("requested_params_sha256", "4" * 64),
            manifest_sha256="5" * 64,
            created_at="2026-07-13T10:00:00Z",
        )

    def outcome(
        self,
        intent: JournalRecord,
        *,
        status: str,
        retryable: bool = False,
    ) -> JournalRecord:
        raw = intent.payload
        contract = self.ledger.cell_contracts[(raw["candidate_id"], raw["model_key"])]
        value = {
            "schema_version": OUTCOME_SCHEMA_VERSION,
            "lock_sha256": HASH,
            "authorization_receipt_sha256": AUTH_HASH,
            "pricing_recheck_receipt_sha256": PRICING_HASH,
            "git_head": GIT_HEAD,
            "candidate_id": raw["candidate_id"],
            "phase": contract["phase"],
            "cell_id": raw["cell_id"],
            "model_key": raw["model_key"],
            "model_family": contract["model_family"],
            "provider": contract["provider"],
            "route": contract["route"],
            "requested_model_id": contract["requested_model_id"],
            "question_sha256": contract["question_sha256"],
            "prompt_sha256": contract["prompt_sha256"],
            "messages": contract["messages"],
            "messages_sha256": contract["messages_sha256"],
            "requested_params": contract["requested_params"],
            "requested_params_sha256": contract["requested_params_sha256"],
            "manifest_path": f"manifests/{raw['candidate_id']}.json",
            "manifest_sha256": raw["manifest_sha256"],
            "attempt_number": raw["attempt_number"],
            "intent_path": str(intent.path.relative_to(self.root)),
            "intent_sha256": intent.sha256,
            "attempted_at": "2026-07-13T10:00:00Z",
            "status": status,
            "completed_at": "2026-07-13T10:00:01Z",
        }
        if status == "error":
            value["error"] = {
                "category": "provider-error",
                "retryable": retryable,
                "sanitized_summary": "safe",
            }
        else:
            response = "complete answer"
            value.update(
                {
                    "provider_returned_model_id": contract["requested_model_id"],
                    "provider_response_id": "response-1",
                    "effective_params": contract["effective_params"],
                    "response_text": response,
                    "response_sha256": sha256_bytes(response.encode()),
                    "finish_reason": "stop",
                    "usage": {
                        "input_tokens": 1,
                        "output_tokens": 1,
                        "reasoning_tokens": None,
                        "cache_read_tokens": None,
                        "cache_write_tokens": None,
                        "total_tokens": 2,
                    },
                    "latency_ms": 1,
                    "cost": {
                        "actual_estimate_microdollars": 2,
                        "reserved_microdollars": contract["reserved_cost_microdollars"],
                        "pricing_as_of": contract["pricing_as_of"],
                    },
                }
            )
        return self.ledger.record_outcome(intent, value)

    def test_intents_and_outcomes_are_private_write_once(self) -> None:
        intent = self.reserve()
        outcome = self.outcome(intent, status="success")
        self.assertEqual(stat.S_IMODE(intent.path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(outcome.path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
        with self.assertRaisesRegex(AttemptNotAllowed, "cannot be replayed"):
            self.reserve(attempt=2)

    def test_stranded_intent_persists_and_remains_charged(self) -> None:
        intent = self.reserve()
        restarted = self.make_ledger()
        snapshot = restarted.snapshot()
        self.assertEqual(snapshot.pool_reserved_microdollars, 100)
        self.assertEqual(snapshot.intent_count, 1)
        self.assertEqual(
            snapshot.stranded_intents,
            (str(intent.path.relative_to(self.root)),),
        )
        self.ledger = restarted
        with self.assertRaisesRegex(StrandedIntent, "stranded"):
            self.reserve(attempt=2)

    def test_only_recorded_retryable_error_unlocks_next_attempt(self) -> None:
        first = self.reserve()
        self.outcome(first, status="error", retryable=True)
        second = self.reserve(attempt=2)
        self.outcome(second, status="error", retryable=True)
        third = self.reserve(attempt=3)
        self.outcome(third, status="error", retryable=True)
        with self.assertRaisesRegex(AttemptNotAllowed, "three-attempt"):
            self.reserve(attempt=4)

        other = self.reserve(model="claude")
        self.outcome(other, status="error", retryable=False)
        with self.assertRaisesRegex(AttemptNotAllowed, "nonretryable"):
            self.reserve(model="claude", attempt=2)

    def test_concurrent_reservations_cannot_cross_candidate_cap(self) -> None:
        self.ledger = self.make_ledger(
            {
                (PRIORITY_CANDIDATE_ID, "gemini"): 4_000_000,
                (PRIORITY_CANDIDATE_ID, "claude"): 4_000_000,
            }
        )

        def attempt(model: str) -> str:
            try:
                self.reserve(model=model)
                return "reserved"
            except BudgetExceeded:
                return "blocked"

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(attempt, MODELS))
        self.assertEqual(sorted(results), ["blocked", "reserved"])
        snapshot = self.ledger.snapshot()
        self.assertLessEqual(
            snapshot.candidate_reserved_microdollars[PRIORITY_CANDIDATE_ID],
            CANDIDATE_CAP_MICRODOLLARS,
        )

    def test_concurrent_outcomes_publish_exactly_once_under_the_ledger_lock(
        self,
    ) -> None:
        intent = self.reserve()

        def publish(_: int) -> str:
            try:
                self.outcome(intent, status="success")
                return "published"
            except BudgetError:
                return "blocked"

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(publish, (1, 2)))
        self.assertEqual(sorted(results), ["blocked", "published"])
        history = self.ledger.cell_history(PRIORITY_CANDIDATE_ID, "gemini")
        self.assertEqual(len(history), 1)
        self.assertIsNotNone(history[0][1])

    def test_both_exact_caps_persist_across_ledger_instances(self) -> None:
        costs = {
            (PRIORITY_CANDIDATE_ID, "gemini"): 6_000_000,
            (FALLBACK_CANDIDATE_ID, "claude"): 6_000_000,
        }
        self.ledger = self.make_ledger(costs)
        self.reserve()
        self.reserve(candidate=FALLBACK_CANDIDATE_ID, model="claude")
        restarted = self.make_ledger(costs)
        snapshot = restarted.snapshot()
        self.assertEqual(
            snapshot.candidate_reserved_microdollars,
            {
                PRIORITY_CANDIDATE_ID: 6_000_000,
                FALLBACK_CANDIDATE_ID: 6_000_000,
            },
        )
        self.assertEqual(snapshot.pool_reserved_microdollars, 12_000_000)

    def test_third_candidate_and_skipped_attempt_are_rejected(self) -> None:
        with self.assertRaisesRegex(AttemptNotAllowed, "no third"):
            self.reserve(candidate="third-candidate")
        with self.assertRaisesRegex(AttemptNotAllowed, "requires 1"):
            self.reserve(attempt=2)

    def test_edited_reservation_cannot_lower_locked_cost(self) -> None:
        intent = self.reserve()
        value = json.loads(intent.path.read_bytes())
        value["reserved_cost_microdollars"] = 1
        intent.path.write_bytes(canonical_json_bytes(value))
        with self.assertRaisesRegex(BudgetError, "locked call contract"):
            self.ledger.snapshot()

    def test_retryability_tampering_is_rejected(self) -> None:
        intent = self.reserve()
        outcome = self.outcome(intent, status="error", retryable=True)
        value = json.loads(outcome.path.read_bytes())
        value["error"]["category"] = "authentication"
        outcome.path.write_bytes(canonical_json_bytes(value))
        with self.assertRaisesRegex(BudgetError, "retry policy"):
            self.ledger.snapshot()

    def test_success_cost_and_extra_field_tampering_are_rejected(self) -> None:
        intent = self.reserve()
        outcome = self.outcome(intent, status="success")
        value = json.loads(outcome.path.read_bytes())
        value["cost"]["actual_estimate_microdollars"] = 3
        outcome.path.write_bytes(canonical_json_bytes(value))
        with self.assertRaisesRegex(BudgetError, "locked result contract"):
            self.ledger.snapshot()

        value["unexpected"] = "field"
        outcome.path.write_bytes(canonical_json_bytes(value))
        with self.assertRaisesRegex(BudgetError, "fields differ"):
            self.ledger.snapshot()

    def test_success_finish_reason_tampering_is_rejected(self) -> None:
        intent = self.reserve()
        outcome = self.outcome(intent, status="success")
        value = json.loads(outcome.path.read_bytes())
        value["finish_reason"] = "length"
        outcome.path.write_bytes(canonical_json_bytes(value))
        with self.assertRaisesRegex(BudgetError, "locked result contract"):
            self.ledger.snapshot()

    def test_false_outcome_chronology_is_rejected(self) -> None:
        intent = self.reserve()
        outcome = self.outcome(intent, status="success")
        value = json.loads(outcome.path.read_bytes())
        value["attempted_at"] = "2026-07-13T09:59:59Z"
        value["completed_at"] = "2026-07-13T09:59:58Z"
        outcome.path.write_bytes(canonical_json_bytes(value))
        with self.assertRaisesRegex(BudgetError, "timestamps"):
            self.ledger.snapshot()

    def test_skipped_durable_attempt_is_rejected(self) -> None:
        contract = self.ledger.cell_contracts[(PRIORITY_CANDIDATE_ID, "gemini")]
        value = {
            "schema_version": INTENT_SCHEMA_VERSION,
            "status": "reserved-before-post",
            "pool_id": "concordance-divergence-supplement-1",
            "lock_sha256": HASH,
            "authorization_receipt_sha256": AUTH_HASH,
            "candidate_id": PRIORITY_CANDIDATE_ID,
            "cell_id": contract["cell_id"],
            "model_key": "gemini",
            "attempt_number": 2,
            "reserved_cost_microdollars": contract["reserved_cost_microdollars"],
            "question_sha256": contract["question_sha256"],
            "prompt_sha256": contract["prompt_sha256"],
            "messages_sha256": contract["messages_sha256"],
            "requested_params_sha256": contract["requested_params_sha256"],
            "manifest_sha256": "5" * 64,
            "created_at": "2026-07-13T10:00:00Z",
        }
        write_once_private_json(
            self.ledger.intent_path(PRIORITY_CANDIDATE_ID, "gemini", 2), value
        )
        with self.assertRaisesRegex(BudgetError, "not contiguous"):
            self.ledger.snapshot()


if __name__ == "__main__":
    unittest.main()
