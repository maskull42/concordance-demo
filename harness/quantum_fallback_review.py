"""Offline adapter from the sealed Quantum fallback panel to Rule 3 review."""

from __future__ import annotations

import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import run_quantum_fallback as execution
from concordance_recovery.journal import read_record
from rule3 import review


REVIEW_ROOT = Path(".pilot/quantum-fallback/quantum-fallback-1")
_ORIGINAL_REVIEW_ROOT = review.PRIVATE_RELATIVE_ROOT
_ORIGINAL_RESPONSE_LOADER = review._review_response_bundle
_CONTEXT_LOCK = threading.Lock()


class QuantumReviewError(review.Rule3ReviewError):
    pass


def load_quantum_responses(
    repository_root: Path, candidate_id: str
) -> review.ResponseBundle:
    if candidate_id != execution.CANDIDATE_ID:
        raise QuantumReviewError(
            "Quantum fallback contains only the fallback candidate"
        )
    root = Path(repository_root).resolve()
    context = execution.load_context()
    verified = execution.verify(context)
    private = root / REVIEW_ROOT
    run = read_record(private / "run.json", "Quantum fallback run")
    if (
        verified.get("run_sha256") != run.sha256
        or run.payload.get("successful_outcome_count") != 8
        or run.payload.get("failed_model_keys") != []
        or tuple(item.get("model_key") for item in run.payload.get("outcomes", []))
        != execution.MODEL_ORDER
    ):
        raise QuantumReviewError("Quantum fallback run is incomplete or changed")

    facts = review._review_lock_facts(root, candidate_id)
    if (
        facts["lock_sha256"] != execution.RULE3_LOCK_SHA256
        or facts["question_sha256"] != execution.QUESTION_SHA256
        or facts["plan_sha256"] != execution.PLAN_SHA256
    ):
        raise QuantumReviewError("review facts differ from the frozen Quantum plan")

    records = []
    for item in run.payload["outcomes"]:
        key = item["model_key"]
        outcome = read_record(private / item["path"], f"Quantum outcome {key}")
        intent_binding = outcome.payload.get("intent")
        if not isinstance(intent_binding, dict) or set(intent_binding) != {
            "path",
            "sha256",
        }:
            raise QuantumReviewError(f"Quantum outcome intent is malformed for {key}")
        intent = read_record(private / intent_binding["path"], f"Quantum intent {key}")
        result = outcome.payload.get("result")
        response = result.get("response_text") if isinstance(result, dict) else None
        response_id = (
            result.get("provider_response_id") if isinstance(result, dict) else None
        )
        call = context.call_by_key[key]
        expected_prompt_sha = context.runtime["prompt_sha256"](call.answer_messages())
        if (
            outcome.sha256 != item["sha256"]
            or outcome.payload.get("status") != "success"
            or outcome.payload.get("candidate_id") != candidate_id
            or outcome.payload.get("model_key") != key
            or outcome.payload.get("provider") != call.model.provider
            or outcome.payload.get("requested_model_id")
            != call.model.requested_model_id
            or outcome.payload.get("cell_id") != call.cell_id
            or outcome.payload.get("attempt_number") != 1
            or intent.sha256 != intent_binding["sha256"]
            or intent.payload.get("prompt_sha256") != expected_prompt_sha
            or not isinstance(response, str)
            or not response.strip()
            or (response_id is not None and not isinstance(response_id, str))
        ):
            raise QuantumReviewError(f"Quantum outcome lineage changed for {key}")
        records.append(
            review.ResponseRecord(
                candidate_id=candidate_id,
                cell_id=call.cell_id,
                model_key=key,
                provider=call.model.provider,
                requested_model_id=call.model.requested_model_id,
                response_id=response_id,
                response_text=response,
                prompt_sha256=expected_prompt_sha,
                outcome_path=outcome.path.relative_to(root).as_posix(),
                outcome_sha256=outcome.sha256,
                attempt_number=1,
            )
        )

    bundle = review.ResponseBundle(
        candidate_id=candidate_id,
        bindings={
            "git_head": facts["git_head"],
            "lock_sha256": facts["lock_sha256"],
            "question_sha256": facts["question_sha256"],
            "plan_sha256": facts["plan_sha256"],
            "review_assets_sha256": facts["review_assets_sha256"],
            "authorization_receipt_sha256": run.payload["authorization"]["sha256"],
            "pricing_recheck_receipt_sha256": run.payload["pricing_recheck"]["sha256"],
            "model_manifest_sha256": run.payload["manifest"]["sha256"],
            "run_receipt_sha256": run.sha256,
        },
        responses=tuple(records),
    )
    review._require_bundle_lineage(root, candidate_id, bundle)
    return bundle


@contextmanager
def quantum_review_context() -> Iterator[None]:
    if not _CONTEXT_LOCK.acquire(blocking=False):
        raise QuantumReviewError("Quantum review context is already active")
    saved_root = review.PRIVATE_RELATIVE_ROOT
    saved_loader = review._review_response_bundle
    try:
        if (
            saved_root != _ORIGINAL_REVIEW_ROOT
            or saved_loader is not _ORIGINAL_RESPONSE_LOADER
        ):
            raise QuantumReviewError("Rule 3 review globals changed before activation")
        review.PRIVATE_RELATIVE_ROOT = REVIEW_ROOT
        review._review_response_bundle = load_quantum_responses
        yield
    finally:
        review._review_response_bundle = saved_loader
        review.PRIVATE_RELATIVE_ROOT = saved_root
        _CONTEXT_LOCK.release()


__all__ = (
    "QuantumReviewError",
    "REVIEW_ROOT",
    "load_quantum_responses",
    "quantum_review_context",
)
