"""Offline adapter from the three-lineage composite to Rule 3 review."""

from __future__ import annotations

import asyncio
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping

from concordance_recovery.journal import read_record
from rule3 import review

from . import contract, execute
from .parent import validate_parent_snapshot


SUCCESSOR_REVIEW_ROOT = Path(contract.PRIVATE_ROOT_RELATIVE)
_ORIGINAL_REVIEW_ROOT = review.PRIVATE_RELATIVE_ROOT
_ORIGINAL_RESPONSE_LOADER = review._review_response_bundle
_CONTEXT_LOCK = threading.Lock()


class CompositeError(review.Rule3ReviewError):
    pass


def _contains_response_text(value: Any) -> bool:
    if isinstance(value, Mapping):
        return "response_text" in value or any(
            _contains_response_text(item) for item in value.values()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_response_text(item) for item in value)
    return False


def _run(coroutine: Any) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine)
    coroutine.close()
    raise CompositeError(
        "successor composite validation requires a synchronous process"
    )


def _validate_composite(root: Path) -> tuple[Any, Any, Any, list[Any]]:
    prepared = execute.prepare_successor(root, require_committed=True)
    parent = validate_parent_snapshot(root, prepared.lock_context.lock)
    if not prepared.paths.manifest.exists() or not prepared.paths.composite.exists():
        raise CompositeError("successor manifest and composite are required")
    manifest = read_record(prepared.paths.manifest, "successor manifest")
    composite = read_record(prepared.paths.composite, "successor composite")
    if _contains_response_text(composite.payload):
        raise CompositeError("successor composite contains forbidden response text")
    authority = execute._authority(prepared, fresh=False)
    claim = execute._ensure_claim(prepared, authority, parent)
    authority = execute._with_claim(authority, claim)
    sealed_manifest, preflights, needs = _run(
        execute._ensure_manifest(prepared, authority, parent)
    )
    if needs or sealed_manifest is None or sealed_manifest.sha256 != manifest.sha256:
        raise CompositeError("successor preflight manifest is incomplete")
    runtime, network, reason = _run(
        execute._reconcile_composite(prepared, authority, parent, manifest, preflights)
    )
    if (
        runtime is None
        or network
        or reason is not None
        or runtime.sha256 != composite.sha256
        or runtime.payload != composite.payload
    ):
        raise CompositeError("runtime and successor composite disagree")
    outcomes = []
    for item in composite.payload.get("outcomes", []):
        if (
            not isinstance(item, dict)
            or item.get("model_key") not in contract.MODEL_ORDER
        ):
            raise CompositeError("successor composite outcome binding is malformed")
        lane = item.get("source_lane")
        key = item["model_key"]
        if lane == "immutable-rule3-parent":
            record = next(
                (
                    value
                    for value in parent.rule3.preserved_outcomes
                    if value.payload.get("model_key") == key
                ),
                None,
            )
        elif lane == "immutable-cohere-recovery" and key == "cohere":
            record = parent.cohere_outcome
        elif lane == "qwen-successor":
            path = prepared.paths.private_root / item.get("path", "")
            record = read_record(path, f"successor outcome {key}")
        else:
            raise CompositeError(f"invalid composite source lane for {key}")
        if record is None or record.sha256 != item.get("sha256"):
            raise CompositeError(f"composite source changed for {key}")
        outcomes.append(record)
    if (
        len(outcomes) != len(contract.MODEL_ORDER)
        or tuple(record.payload.get("model_key") for record in outcomes)
        != contract.MODEL_ORDER
    ):
        raise CompositeError("composite does not contain the exact eight outcomes")
    return prepared, manifest, composite, outcomes


def _response_record(
    root: Path, outcome: Any, *, semantic_attempt_number: int
) -> review.ResponseRecord:
    value = outcome.payload
    response = value.get("response_text")
    response_id = value.get("provider_response_id")
    if (
        value.get("status") != "success"
        or not isinstance(response, str)
        or not response.strip()
        or (response_id is not None and not isinstance(response_id, str))
    ):
        raise CompositeError("composite source is not a successful response")
    return review.ResponseRecord(
        candidate_id=value.get("candidate_id"),
        cell_id=value.get("cell_id"),
        model_key=value.get("model_key"),
        provider=value.get("provider"),
        requested_model_id=value.get("requested_model_id"),
        response_id=response_id,
        response_text=response,
        prompt_sha256=value.get("prompt_sha256"),
        outcome_path=outcome.path.resolve().relative_to(root).as_posix(),
        outcome_sha256=outcome.sha256,
        attempt_number=semantic_attempt_number,
    )


def load_composite_responses(
    repository_root: Path, candidate_id: str
) -> review.ResponseBundle:
    if candidate_id != contract.CANDIDATE_ID:
        raise CompositeError("Qwen successor contains only the priority candidate")
    root = Path(repository_root).resolve()
    prepared, manifest, composite, outcomes = _validate_composite(root)
    facts = review._review_lock_facts(root, candidate_id)
    if (
        facts["lock_sha256"] != contract.RULE3_LOCK_SHA256
        or facts["plan_sha256"] != contract.RULE3_PLAN_SHA256
        or facts["question_sha256"] != composite.payload.get("question_sha256")
    ):
        raise CompositeError("review facts differ from the immutable Rule 3 lineage")
    records = tuple(
        _response_record(
            root,
            outcome,
            semantic_attempt_number=item["semantic_attempt_number"],
        )
        for item, outcome in zip(composite.payload["outcomes"], outcomes, strict=True)
    )
    bundle = review.ResponseBundle(
        candidate_id=candidate_id,
        bindings={
            "git_head": facts["git_head"],
            "lock_sha256": facts["lock_sha256"],
            "question_sha256": facts["question_sha256"],
            "plan_sha256": facts["plan_sha256"],
            "review_assets_sha256": facts["review_assets_sha256"],
            "authorization_receipt_sha256": composite.payload[
                "authorization_receipt_sha256"
            ],
            "pricing_recheck_receipt_sha256": composite.payload[
                "pricing_recheck_receipt_sha256"
            ],
            "model_manifest_sha256": manifest.sha256,
            "run_receipt_sha256": composite.sha256,
        },
        responses=records,
    )
    review._require_bundle_lineage(root, candidate_id, bundle)
    return bundle


@contextmanager
def successor_review_context() -> Iterator[None]:
    if not _CONTEXT_LOCK.acquire(blocking=False):
        raise CompositeError("successor review context is already active")
    saved_root = review.PRIVATE_RELATIVE_ROOT
    saved_loader = review._review_response_bundle
    try:
        if (
            saved_root != _ORIGINAL_REVIEW_ROOT
            or saved_loader is not _ORIGINAL_RESPONSE_LOADER
        ):
            raise CompositeError("Rule 3 review globals changed before activation")
        review.PRIVATE_RELATIVE_ROOT = SUCCESSOR_REVIEW_ROOT
        review._review_response_bundle = load_composite_responses
        yield
    finally:
        review._review_response_bundle = saved_loader
        review.PRIVATE_RELATIVE_ROOT = saved_root
        _CONTEXT_LOCK.release()


__all__ = (
    "CompositeError",
    "SUCCESSOR_REVIEW_ROOT",
    "load_composite_responses",
    "successor_review_context",
)
