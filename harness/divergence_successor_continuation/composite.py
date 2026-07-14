"""Response-free terminal index and authenticated response loader."""

from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping

from concordance_recovery.journal import (
    RecoveryJournalError,
    read_record,
    require_timestamp,
)
from rule3.budget import JournalRecord

from . import authorization, contract


COMPOSITE_SCHEMA = "divergence-successor-continuation-composite-1.0.0"
COMPOSITE_STATUS = "complete-eight-corrected-preflight-generation-successes"


class ContinuationCompositeError(RuntimeError):
    """The response-free terminal index is incomplete or changed."""


def _binding(private_root: Path, record: JournalRecord, label: str) -> dict[str, str]:
    try:
        relative = record.path.resolve().relative_to(private_root.resolve()).as_posix()
    except ValueError as error:
        raise ContinuationCompositeError(
            f"{label} escapes the continuation root"
        ) from error
    return {"path": relative, "sha256": record.sha256}


def _contains_response(value: Any) -> bool:
    if isinstance(value, Mapping):
        return "response_text" in value or any(
            _contains_response(item) for item in value.values()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_response(item) for item in value)
    return False


def composite_payload(
    prepared: Any,
    *,
    authorization_record: JournalRecord,
    outcomes: Iterable[JournalRecord],
    sealed_at: str,
) -> dict[str, Any]:
    try:
        require_timestamp(sealed_at, "continuation composite time")
    except RecoveryJournalError as error:
        raise ContinuationCompositeError(str(error)) from error
    records = list(outcomes)
    if len(records) != 8:
        raise ContinuationCompositeError(
            "continuation composite requires eight outcomes"
        )
    sealed = datetime.fromisoformat(sealed_at.replace("Z", "+00:00"))
    values: list[dict[str, Any]] = []
    cells = prepared.lock_context.lock["plans"]["candidate_plans"][0]["cells"]
    for cell, record in zip(cells, records, strict=True):
        payload = record.payload
        completed = payload.get("completed_at")
        try:
            require_timestamp(completed, "generation outcome time")
        except RecoveryJournalError as error:
            raise ContinuationCompositeError(str(error)) from error
        if sealed < datetime.fromisoformat(completed.replace("Z", "+00:00")):
            raise ContinuationCompositeError("composite predates a generation outcome")
        if (
            payload.get("status") != "success"
            or payload.get("model_key") != cell["model_key"]
            or payload.get("cell_id") != cell["cell_id"]
            or record.path != prepared.paths.generation_outcome(cell["model_key"])
        ):
            raise ContinuationCompositeError("composite source is not an exact success")
        values.append(
            {
                "model_key": cell["model_key"],
                "cell_id": cell["cell_id"],
                "semantic_attempt_number": 1,
                **_binding(prepared.paths.private_root, record, "generation outcome"),
            }
        )
    payload = {
        "schema_version": COMPOSITE_SCHEMA,
        "status": COMPOSITE_STATUS,
        "pool_id": contract.POOL_ID,
        "candidate_id": contract.CANDIDATE_ID,
        "git_head": prepared.lock_context.git_head,
        "lock": {
            "path": contract.LOCK_PATH,
            "sha256": prepared.lock_context.lock_sha256,
        },
        "original_lock_sha256": prepared.parent.lock_context.lock_sha256,
        "question_sha256": prepared.parent.question.sha256,
        "plan_sha256": prepared.lock_context.lock["plans"]["candidate_plans"][0][
            "plan_sha256"
        ],
        "authorization": _binding(
            prepared.paths.private_root, authorization_record, "authorization"
        ),
        "historical_pricing_recheck_sha256": prepared.parent_authority.pricing.sha256,
        "offline_correction": _binding(
            prepared.paths.private_root,
            prepared.correction_record,
            "offline correction",
        ),
        "sealed_at": sealed_at,
        "successful_outcome_count": 8,
        "failed_model_keys": [],
        "network_contract": {
            "new_metadata_requests": 0,
            "generation_posts": 8,
            "automatic_retries": 0,
            "fallback_allowed": False,
            "tools_enabled": False,
            "web_search_enabled": False,
            "retrieval_enabled": False,
            "external_context_enabled": False,
        },
        "outcomes": values,
    }
    if _contains_response(payload):
        raise ContinuationCompositeError("composite contains response text")
    return payload


async def validate_composite_record(
    prepared: Any,
    paid: JournalRecord,
    record: JournalRecord,
) -> tuple[JournalRecord, ...]:
    from . import execute

    if record.path != prepared.paths.composite:
        raise ContinuationCompositeError("continuation composite path changed")
    outcomes: list[JournalRecord] = []
    for call in prepared.plan:
        try:
            outcome = read_record(
                prepared.paths.generation_outcome(call.model.model_key),
                f"continuation outcome {call.model.model_key}",
            )
            intent = read_record(
                prepared.paths.generation_intent(call.model.model_key),
                f"continuation intent {call.model.model_key}",
            )
            raw = read_record(
                prepared.paths.generation_raw(call.model.model_key),
                f"continuation raw response {call.model.model_key}",
            )
            result = await execute._validate_outcome(
                prepared, paid, call, intent, raw, outcome
            )
        except (OSError, RuntimeError, ValueError) as error:
            raise ContinuationCompositeError(str(error)) from error
        if result is None:
            raise ContinuationCompositeError("composite binds a failed outcome")
        outcomes.append(outcome)
    expected = composite_payload(
        prepared,
        authorization_record=paid,
        outcomes=outcomes,
        sealed_at=record.payload.get("sealed_at"),
    )
    if record.payload != expected:
        raise ContinuationCompositeError("continuation composite changed")
    return tuple(outcomes)


def _run(coroutine: Any) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine)
    if hasattr(coroutine, "close"):
        coroutine.close()
    raise ContinuationCompositeError(
        "use the async composite validator inside an event loop"
    )


def load_composite_responses(
    repository_root: Path | str,
    candidate_id: str,
) -> Any:
    """Read response text only after authenticating the response-free index."""

    from divergence_successor import review as parent_review
    from . import execute, review

    if candidate_id != contract.CANDIDATE_ID:
        raise ContinuationCompositeError("continuation has exactly one candidate")
    prepared = execute.prepare_continuation(repository_root, require_committed=True)
    paid = authorization.validate_authorization(prepared.lock_context)
    try:
        composite = read_record(prepared.paths.composite, "continuation composite")
    except RecoveryJournalError as error:
        raise ContinuationCompositeError(str(error)) from error
    outcomes = _run(validate_composite_record(prepared, paid, composite))
    cells = prepared.lock_context.lock["plans"]["candidate_plans"][0]["cells"]
    records: list[parent_review.ResponseRecord] = []
    for cell, outcome in zip(cells, outcomes, strict=True):
        result = outcome.payload["result"]
        records.append(
            parent_review.ResponseRecord(
                candidate_id=candidate_id,
                cell_id=cell["cell_id"],
                model_key=cell["model_key"],
                provider=outcome.payload["provider"],
                requested_model_id=outcome.payload["requested_model_id"],
                response_id=result.get("provider_response_id"),
                response_text=result["response_text"],
                prompt_sha256=cell["prompt_sha256"],
                outcome_path=outcome.path.relative_to(
                    prepared.repository_root
                ).as_posix(),
                outcome_sha256=outcome.sha256,
                attempt_number=1,
            )
        )
    facts = review.review_lock_facts(prepared)
    bindings = {
        **facts,
        "authorization_receipt_sha256": paid.sha256,
        "pricing_recheck_receipt_sha256": prepared.parent_authority.pricing.sha256,
        "model_manifest_sha256": prepared.correction_record.sha256,
        "run_receipt_sha256": composite.sha256,
    }
    bundle = parent_review.ResponseBundle(candidate_id, bindings, tuple(records))
    review.validate_bundle(prepared, bundle)
    return bundle


__all__ = (
    "COMPOSITE_SCHEMA",
    "COMPOSITE_STATUS",
    "ContinuationCompositeError",
    "composite_payload",
    "load_composite_responses",
    "validate_composite_record",
)
