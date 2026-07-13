"""Offline adapter from a sealed recovery composite to Rule 3 review.

The recovery runtime owns provider evidence.  This module validates its exact
two-parent plus six-recovery receipt, then presents the unchanged Rule 3 review
lane with one ``ResponseBundle``.  It never reads credentials or sends a
request.  Raw answer text remains only in the private source outcomes.
"""

from __future__ import annotations

import asyncio
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterator, Mapping

from rule3 import review
from rule3.budget import JournalRecord

from . import contract, execute
from .journal import (
    COMPOSITE_SCHEMA,
    RecoveryJournalError,
    read_record,
    require_git_head,
    require_sha256,
    require_timestamp,
)
from .parent import ParentEvidence, validate_parent_evidence


SUCCESSOR_REVIEW_ROOT = Path(contract.PRIVATE_ROOT_RELATIVE)
_ORIGINAL_REVIEW_ROOT = review.PRIVATE_RELATIVE_ROOT
_ORIGINAL_RESPONSE_LOADER = review._review_response_bundle
_CONTEXT_LOCK = threading.Lock()


class CompositeRecoveryError(review.Rule3ReviewError):
    """Raised when recovery evidence cannot enter the review lane."""


@dataclass(frozen=True)
class _ValidatedComposite:
    prepared: execute.PreparedRecovery
    parent: ParentEvidence
    manifest: JournalRecord
    composite: JournalRecord
    recovery_outcomes: tuple[JournalRecord, ...]


def _sha256(value: Any, label: str) -> str:
    try:
        return require_sha256(value, label)
    except RecoveryJournalError as error:
        raise CompositeRecoveryError(str(error)) from error


def _git_head(value: Any, label: str) -> str:
    try:
        return require_git_head(value, label)
    except RecoveryJournalError as error:
        raise CompositeRecoveryError(str(error)) from error


def _timestamp(value: Any, label: str) -> str:
    try:
        return require_timestamp(value, label)
    except RecoveryJournalError as error:
        raise CompositeRecoveryError(str(error)) from error


def _relative_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise CompositeRecoveryError(f"{label} must be a canonical relative path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise CompositeRecoveryError(f"{label} must remain inside its private root")
    return value


def _binding(value: Any, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
        raise CompositeRecoveryError(f"{label} binding is malformed")
    return {
        "path": _relative_path(value.get("path"), f"{label} path"),
        "sha256": _sha256(value.get("sha256"), f"{label} hash"),
    }


def _read_bound_record(private_root: Path, value: Any, label: str) -> JournalRecord:
    bound = _binding(value, label)
    record = read_record(private_root / bound["path"], label)
    if record.sha256 != bound["sha256"]:
        raise CompositeRecoveryError(f"{label} differs from its composite binding")
    return record


def _contains_response_text(value: Any) -> bool:
    if isinstance(value, Mapping):
        if "response_text" in value:
            return True
        return any(_contains_response_text(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_response_text(item) for item in value)
    return False


def _expected_recovery_path(kind: str, model_key: str, attempt: int) -> str:
    return f"generation/{kind}/{model_key}/attempt-{attempt}.json"


def _validate_composite_shape(
    validated: execute.PreparedRecovery,
    parent: ParentEvidence,
    manifest: JournalRecord,
    composite: JournalRecord,
) -> tuple[dict[str, Any], ...]:
    value = composite.payload
    expected_keys = {
        "schema_version",
        "status",
        "recovery_id",
        "pool_id",
        "candidate_id",
        "phase",
        "git_head",
        "recovery_lock_sha256",
        "authorization_receipt_sha256",
        "pricing_recheck_receipt_sha256",
        "parent_lock_sha256",
        "parent_manifest_sha256",
        "parent_claim",
        "sealed_at",
        "question_sha256",
        "parent_plan_sha256",
        "recovery_manifest",
        "parent_stranded_cohere_intent",
        "successful_outcome_count",
        "outcomes",
        "budget",
    }
    if set(value) != expected_keys or _contains_response_text(value):
        raise CompositeRecoveryError(
            "composite receipt fields changed or contain forbidden response text"
        )
    git_head = _git_head(value.get("git_head"), "composite Git HEAD")
    _timestamp(value.get("sealed_at"), "composite seal time")
    if (
        value.get("schema_version") != COMPOSITE_SCHEMA
        or value.get("status") != "complete-eight-successes-two-parent-six-recovery"
        or value.get("recovery_id") != contract.RECOVERY_ID
        or value.get("pool_id") != contract.POOL_ID
        or value.get("candidate_id") != contract.CANDIDATE_ID
        or value.get("phase") != contract.PRIORITY_PHASE
        or git_head != validated.lock_context.git_head
        or value.get("recovery_lock_sha256") != validated.lock_context.lock_sha256
        or value.get("parent_lock_sha256") != contract.PARENT_LOCK_SHA256
        or value.get("parent_manifest_sha256") != parent.manifest.sha256
        or value.get("question_sha256") != validated.question.sha256
        or value.get("parent_plan_sha256") != contract.PARENT_PLAN_SHA256
        or value.get("successful_outcome_count") != len(contract.MODEL_ORDER)
        or value.get("recovery_manifest")
        != {
            "path": manifest.path.relative_to(validated.paths.private_root).as_posix(),
            "sha256": manifest.sha256,
        }
    ):
        raise CompositeRecoveryError(
            "composite receipt differs from its locked lineage"
        )
    _sha256(
        value.get("authorization_receipt_sha256"),
        "composite authorization receipt hash",
    )
    _sha256(
        value.get("pricing_recheck_receipt_sha256"),
        "composite pricing receipt hash",
    )
    parent_claim = _binding(value.get("parent_claim"), "parent claim")
    if (
        parent_claim["path"]
        != validated.paths.claim.relative_to(validated.repository_root).as_posix()
    ):
        raise CompositeRecoveryError("composite parent claim path changed")
    expected_stranded = {
        "path": contract.STRANDED_COHERE["intent_path"],
        "sha256": parent.stranded_intent.sha256,
        "disposition": contract.STRANDED_COHERE["disposition"],
    }
    if value.get("parent_stranded_cohere_intent") != expected_stranded:
        raise CompositeRecoveryError("composite changed the stranded Cohere lineage")

    budget = value.get("budget")
    expected_budget_keys = {
        "parent_reserved_microdollars",
        "new_reserved_microdollars",
        "combined_reserved_microdollars",
        "new_reserved_cap_microdollars",
        "combined_reserved_cap_microdollars",
    }
    if not isinstance(budget, dict) or set(budget) != expected_budget_keys:
        raise CompositeRecoveryError("composite budget receipt is malformed")
    new_reserved = budget.get("new_reserved_microdollars")
    if (
        not isinstance(new_reserved, int)
        or isinstance(new_reserved, bool)
        or new_reserved < 0
        or budget.get("parent_reserved_microdollars") != parent.reserved_microdollars
        or budget.get("combined_reserved_microdollars")
        != parent.reserved_microdollars + new_reserved
        or budget.get("new_reserved_cap_microdollars")
        != contract.NEW_RESERVED_CAP_MICRODOLLARS
        or budget.get("combined_reserved_cap_microdollars")
        != contract.COMBINED_RESERVED_CAP_MICRODOLLARS
        or new_reserved > contract.NEW_RESERVED_CAP_MICRODOLLARS
        or parent.reserved_microdollars + new_reserved
        > contract.COMBINED_RESERVED_CAP_MICRODOLLARS
    ):
        raise CompositeRecoveryError("composite budget exceeds its recovery contract")

    outcomes = value.get("outcomes")
    if not isinstance(outcomes, list) or len(outcomes) != len(contract.MODEL_ORDER):
        raise CompositeRecoveryError("composite must contain exactly eight outcomes")
    if [item.get("model_key") for item in outcomes if isinstance(item, dict)] != list(
        contract.MODEL_ORDER
    ):
        raise CompositeRecoveryError("composite outcome order changed")

    parent_by_key = {
        record.payload.get("model_key"): record for record in parent.preserved_outcomes
    }
    normalized: list[dict[str, Any]] = []
    seen_paths: set[tuple[str, str]] = set()
    for index, (model_key, item) in enumerate(
        zip(contract.MODEL_ORDER, outcomes, strict=True)
    ):
        if not isinstance(item, dict):
            raise CompositeRecoveryError("composite outcome binding is malformed")
        if model_key in contract.PRESERVED_MODEL_KEYS:
            if set(item) != {
                "model_key",
                "source_lane",
                "path",
                "sha256",
                "semantic_attempt_number",
            }:
                raise CompositeRecoveryError("parent outcome binding fields changed")
            record = parent_by_key.get(model_key)
            expected_path = contract.PARENT_GENERATION_OUTCOME_PATHS[index]
            if (
                record is None
                or item.get("source_lane") != "immutable-parent"
                or item.get("path") != expected_path
                or item.get("sha256") != record.sha256
                or item.get("semantic_attempt_number") != 1
            ):
                raise CompositeRecoveryError(
                    f"composite did not preserve exact {model_key} evidence"
                )
        else:
            if set(item) != {
                "model_key",
                "source_lane",
                "path",
                "sha256",
                "semantic_attempt_number",
                "raw_response",
                "intent",
            }:
                raise CompositeRecoveryError("recovery outcome binding fields changed")
            attempt = item.get("semantic_attempt_number")
            allowed = (
                (2,)
                if model_key == "cohere"
                else tuple(range(1, contract.MAX_UNTOUCHED_GENERATION_ATTEMPTS + 1))
            )
            raw_response = _binding(item.get("raw_response"), "raw response")
            intent = _binding(item.get("intent"), "generation intent")
            if (
                item.get("source_lane") != "successor-recovery"
                or attempt not in allowed
                or item.get("path")
                != _expected_recovery_path("outcomes", model_key, attempt)
                or raw_response["path"]
                != _expected_recovery_path("raw-responses", model_key, attempt)
                or intent["path"]
                != _expected_recovery_path("intents", model_key, attempt)
            ):
                raise CompositeRecoveryError(
                    f"recovery outcome lineage changed for {model_key}"
                )
            _sha256(item.get("sha256"), f"{model_key} outcome hash")
        key = (item["source_lane"], item["path"])
        if key in seen_paths:
            raise CompositeRecoveryError("composite outcome path is duplicated")
        seen_paths.add(key)
        normalized.append(item)
    return tuple(normalized)


def _require_closed_attempts(prepared: execute.PreparedRecovery) -> None:
    """Prove that execute's offline replay validators cannot publish a record."""
    for model_key in contract.TARGET_MODEL_KEYS:
        for attempt in range(1, contract.PREFLIGHT_ATTEMPTS_PER_MODEL + 1):
            intent = prepared.paths.preflight_intent(model_key, attempt)
            outcome = prepared.paths.preflight_outcome(model_key, attempt)
            if intent.exists() and not outcome.exists():
                raise CompositeRecoveryError(
                    f"preflight attempt remains unfinalized for {model_key}"
                )
        attempts = (
            (2,)
            if model_key == "cohere"
            else tuple(range(1, contract.MAX_UNTOUCHED_GENERATION_ATTEMPTS + 1))
        )
        for attempt in attempts:
            intent = prepared.paths.generation_intent(model_key, attempt)
            outcome = prepared.paths.generation_outcome(model_key, attempt)
            if intent.exists() and not outcome.exists():
                raise CompositeRecoveryError(
                    f"generation attempt remains unfinalized for {model_key}"
                )


async def _runtime_validate(
    prepared: execute.PreparedRecovery,
    parent: ParentEvidence,
    manifest: JournalRecord,
) -> JournalRecord:
    base_authority = execute._authority(prepared, fresh=False)
    claim = execute._ensure_claim(prepared, base_authority, parent)
    authority = execute._authority_with_claim(prepared, base_authority, claim)
    preflight = await execute._validate_manifest(prepared, authority, parent, manifest)
    (
        result,
        needs_network,
        stopped_reason,
    ) = await execute._validate_or_publish_composite(
        prepared, authority, parent, manifest, preflight
    )
    if result is None or needs_network or stopped_reason is not None:
        raise CompositeRecoveryError("recovery is not a complete reviewable composite")
    return result


def _run_offline_validation(coroutine: Any) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine)
    coroutine.close()
    raise CompositeRecoveryError(
        "composite review validation requires a synchronous offline process"
    )


def _validate_composite(
    repository_root: Path, candidate_id: str
) -> _ValidatedComposite:
    if candidate_id != contract.CANDIDATE_ID:
        raise CompositeRecoveryError(
            "this successor recovery contains only the locked priority candidate"
        )
    root = repository_root.resolve()
    try:
        prepared = execute.load_live_recovery(root)
        parent = validate_parent_evidence(root, prepared.lock_context.lock)
        if (
            not prepared.paths.manifest.exists()
            or not prepared.paths.composite.exists()
        ):
            raise CompositeRecoveryError(
                "sealed recovery manifest and composite required"
            )
        manifest = read_record(prepared.paths.manifest, "recovery model manifest")
        composite = read_record(prepared.paths.composite, "recovery composite run")
        items = _validate_composite_shape(prepared, parent, manifest, composite)

        _require_closed_attempts(prepared)

        # Require every bound success before invoking the runtime replay
        # validators. Closed-attempt validation above makes that replay read-only.
        recovery_outcomes = tuple(
            _read_bound_record(
                prepared.paths.private_root,
                {"path": item["path"], "sha256": item["sha256"]},
                f"recovery outcome {item['model_key']}",
            )
            for item in items
            if item["source_lane"] == "successor-recovery"
        )
        manifest_items = manifest.payload.get("preflight_outcomes")
        if not isinstance(manifest_items, list) or len(manifest_items) != len(
            contract.TARGET_MODEL_KEYS
        ):
            raise CompositeRecoveryError(
                "recovery manifest preflight set is incomplete"
            )
        for model_key, item in zip(
            contract.TARGET_MODEL_KEYS, manifest_items, strict=True
        ):
            if not isinstance(item, dict) or item.get("model_key") != model_key:
                raise CompositeRecoveryError("recovery preflight order changed")
            _read_bound_record(
                prepared.paths.private_root,
                {"path": item.get("path"), "sha256": item.get("sha256")},
                f"recovery preflight {model_key}",
            )

        runtime_composite = _run_offline_validation(
            _runtime_validate(prepared, parent, manifest)
        )
        if (
            runtime_composite.path.resolve() != composite.path.resolve()
            or runtime_composite.sha256 != composite.sha256
            or runtime_composite.payload != composite.payload
        ):
            raise CompositeRecoveryError("runtime and composite adapter disagree")
        return _ValidatedComposite(
            prepared=prepared,
            parent=parent,
            manifest=manifest,
            composite=composite,
            recovery_outcomes=recovery_outcomes,
        )
    except CompositeRecoveryError:
        raise
    except Exception as error:
        raise CompositeRecoveryError(str(error)) from error


def _repository_relative(root: Path, path: Path, label: str) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as error:
        raise CompositeRecoveryError(f"{label} escapes the repository") from error


def _response_record(
    root: Path,
    outcome: JournalRecord,
    *,
    semantic_attempt_number: int,
) -> review.ResponseRecord:
    value = outcome.payload
    response_text = value.get("response_text")
    response_id = value.get("provider_response_id")
    if (
        value.get("status") != "success"
        or not isinstance(response_text, str)
        or not response_text.strip()
        or (response_id is not None and not isinstance(response_id, str))
    ):
        raise CompositeRecoveryError("composite source is not a successful response")
    return review.ResponseRecord(
        candidate_id=value.get("candidate_id"),
        cell_id=value.get("cell_id"),
        model_key=value.get("model_key"),
        provider=value.get("provider"),
        requested_model_id=value.get("requested_model_id"),
        response_id=response_id,
        response_text=response_text,
        prompt_sha256=value.get("prompt_sha256"),
        outcome_path=_repository_relative(root, outcome.path, "source outcome"),
        outcome_sha256=outcome.sha256,
        attempt_number=semantic_attempt_number,
    )


def load_composite_responses(
    repository_root: Path, candidate_id: str
) -> review.ResponseBundle:
    """Return the exact eight-response composite for unchanged Rule 3 review."""
    root = Path(repository_root).resolve()
    validated = _validate_composite(root, candidate_id)
    facts = review._review_lock_facts(root, candidate_id)
    value = validated.composite.payload
    if (
        facts["git_head"] != validated.prepared.lock_context.git_head
        or facts["lock_sha256"] != contract.PARENT_LOCK_SHA256
        or facts["question_sha256"] != value["question_sha256"]
        or facts["plan_sha256"] != value["parent_plan_sha256"]
    ):
        raise CompositeRecoveryError(
            "composite review facts differ from the committed parent lock"
        )

    parent_by_key = {
        item.payload["model_key"]: item for item in validated.parent.preserved_outcomes
    }
    recovery_by_key = {
        item.payload["model_key"]: item for item in validated.recovery_outcomes
    }
    records: list[review.ResponseRecord] = []
    for item in value["outcomes"]:
        model_key = item["model_key"]
        source = (
            parent_by_key.get(model_key)
            if item["source_lane"] == "immutable-parent"
            else recovery_by_key.get(model_key)
        )
        if source is None or source.sha256 != item["sha256"]:
            raise CompositeRecoveryError(
                f"composite source binding changed for {model_key}"
            )
        records.append(
            _response_record(
                root,
                source,
                semantic_attempt_number=item["semantic_attempt_number"],
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
            "authorization_receipt_sha256": value["authorization_receipt_sha256"],
            "pricing_recheck_receipt_sha256": value["pricing_recheck_receipt_sha256"],
            "model_manifest_sha256": validated.manifest.sha256,
            "run_receipt_sha256": validated.composite.sha256,
        },
        responses=tuple(records),
    )
    review._require_bundle_lineage(root, candidate_id, bundle)
    return bundle


@contextmanager
def successor_review_context() -> Iterator[None]:
    """Activate the fixed composite loader and private root for one CLI action."""
    if not _CONTEXT_LOCK.acquire(blocking=False):
        raise CompositeRecoveryError("successor review context is already active")
    saved_root = review.PRIVATE_RELATIVE_ROOT
    saved_loader = review._review_response_bundle
    try:
        if (
            saved_root != _ORIGINAL_REVIEW_ROOT
            or saved_loader is not _ORIGINAL_RESPONSE_LOADER
        ):
            raise CompositeRecoveryError(
                "Rule 3 review globals changed before successor activation"
            )
        review.PRIVATE_RELATIVE_ROOT = SUCCESSOR_REVIEW_ROOT
        review._review_response_bundle = load_composite_responses
        yield
    finally:
        review._review_response_bundle = saved_loader
        review.PRIVATE_RELATIVE_ROOT = saved_root
        _CONTEXT_LOCK.release()


__all__ = (
    "CompositeRecoveryError",
    "SUCCESSOR_REVIEW_ROOT",
    "load_composite_responses",
    "successor_review_context",
)
