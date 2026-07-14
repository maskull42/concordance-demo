"""Response-free successor composite and offline review adapter."""

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

from . import authorization, contract, execute, review


COMPOSITE_SCHEMA = "divergence-successor-composite-run-1.0.0"
COMPOSITE_STATUS = "complete-eight-fresh-successes"


class DivergenceSuccessorCompositeError(review.DivergenceSuccessorReviewError):
    """The private eight-response composite is incomplete or changed."""


def _contains_response_text(value: Any) -> bool:
    if isinstance(value, Mapping):
        return "response_text" in value or any(
            _contains_response_text(item) for item in value.values()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_response_text(item) for item in value)
    return False


def _relative(private_root: Path, path: Path, label: str) -> str:
    try:
        relative = path.resolve().relative_to(private_root.resolve()).as_posix()
        contract.require_relative_path(relative, label)
    except (ValueError, contract.ContractError) as error:
        raise DivergenceSuccessorCompositeError(
            f"{label} escapes the successor private root"
        ) from error
    return relative


def _binding(private_root: Path, record: JournalRecord, label: str) -> dict[str, str]:
    return {
        "path": _relative(private_root, record.path, label),
        "sha256": record.sha256,
    }


def _plan(prepared: execute.PreparedSuccessor) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    plans = prepared.lock_context.lock.get("plans", {}).get("candidate_plans")
    if not isinstance(plans, list) or len(plans) != 1:
        raise DivergenceSuccessorCompositeError("successor candidate plan changed")
    plan = plans[0]
    cells = plan.get("cells") if isinstance(plan, dict) else None
    if (
        not isinstance(cells, list)
        or len(cells) != 8
        or tuple(cell.get("model_key") for cell in cells) != contract.MODEL_KEYS
    ):
        raise DivergenceSuccessorCompositeError("successor cell universe changed")
    return plan, cells


def composite_payload(
    prepared: execute.PreparedSuccessor,
    *,
    authorization_record: JournalRecord,
    pricing_recheck_record: JournalRecord,
    manifest_record: JournalRecord,
    outcomes: Iterable[JournalRecord],
    sealed_at: str,
) -> dict[str, Any]:
    """Build the terminal index while keeping every response in its source file."""

    try:
        require_timestamp(sealed_at, "successor composite time")
    except RecoveryJournalError as error:
        raise DivergenceSuccessorCompositeError(str(error)) from error
    plan, cells = _plan(prepared)
    records = list(outcomes)
    if len(records) != 8:
        raise DivergenceSuccessorCompositeError(
            "successor composite requires exactly eight outcomes"
        )
    sealed_time = datetime.fromisoformat(sealed_at.replace("Z", "+00:00"))
    source_times = [manifest_record.payload.get("sealed_at")] + [
        record.payload.get("completed_at") for record in records
    ]
    try:
        for value in source_times:
            require_timestamp(value, "successor composite source time")
            if sealed_time < datetime.fromisoformat(value.replace("Z", "+00:00")):
                raise DivergenceSuccessorCompositeError(
                    "successor composite predates one of its source records"
                )
    except DivergenceSuccessorCompositeError:
        raise
    except (AttributeError, ValueError, RecoveryJournalError) as error:
        raise DivergenceSuccessorCompositeError(str(error)) from error
    bindings: list[dict[str, Any]] = []
    for cell, record in zip(cells, records, strict=True):
        key = cell["model_key"]
        try:
            execute.validate_generation_outcome(
                record,
                model_key=key,
                prompt_sha256=cell["prompt_sha256"],
            )
        except execute.DivergenceSuccessorExecutionError as error:
            raise DivergenceSuccessorCompositeError(str(error)) from error
        if record.path != prepared.paths.generation_outcome(key):
            raise DivergenceSuccessorCompositeError(
                f"successor outcome path changed for {key}"
            )
        bindings.append(
            {
                "model_key": key,
                "cell_id": cell["cell_id"],
                "semantic_attempt_number": 1,
                **_binding(prepared.paths.private_root, record, f"outcome {key}"),
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
        "question_sha256": prepared.lock_context.lock["bindings"]["question"][
            "sha256"
        ],
        "plan_sha256": plan["plan_sha256"],
        "config_sha256": prepared.lock_context.lock["bindings"]["models_config"][
            "sha256"
        ],
        "authorization": _binding(
            prepared.paths.private_root,
            authorization_record,
            "paid authorization",
        ),
        "pricing_recheck": _binding(
            prepared.paths.private_root,
            pricing_recheck_record,
            "pricing recheck",
        ),
        "manifest": _binding(
            prepared.paths.private_root, manifest_record, "preflight manifest"
        ),
        "sealed_at": sealed_at,
        "successful_outcome_count": 8,
        "failed_model_keys": [],
        "network_contract": {
            "preflight_requests": 8,
            "generation_posts": 8,
            "automatic_retries": 0,
            "tools_enabled": False,
            "web_search_enabled": False,
            "retrieval_enabled": False,
            "external_context_enabled": False,
        },
        "outcomes": bindings,
    }
    validate_composite_value(prepared, payload)
    return payload


def validate_composite_value(
    prepared: execute.PreparedSuccessor, value: Mapping[str, Any]
) -> None:
    exact_fields = {
        "schema_version",
        "status",
        "pool_id",
        "candidate_id",
        "git_head",
        "lock",
        "question_sha256",
        "plan_sha256",
        "config_sha256",
        "authorization",
        "pricing_recheck",
        "manifest",
        "sealed_at",
        "successful_outcome_count",
        "failed_model_keys",
        "network_contract",
        "outcomes",
    }
    if set(value) != exact_fields:
        raise DivergenceSuccessorCompositeError(
            "successor composite top-level fields differ from the response-free schema"
        )
    if _contains_response_text(value):
        raise DivergenceSuccessorCompositeError(
            "successor composite must never contain response text"
        )
    plan, cells = _plan(prepared)
    outcomes = value.get("outcomes")
    expected_outcomes = [
        {
            "model_key": cell["model_key"],
            "cell_id": cell["cell_id"],
            "semantic_attempt_number": 1,
            "path": (
                f"generation/outcomes/{cell['model_key']}/attempt-1.json"
            ),
        }
        for cell in cells
    ]
    if (
        value.get("schema_version") != COMPOSITE_SCHEMA
        or value.get("status") != COMPOSITE_STATUS
        or value.get("pool_id") != contract.POOL_ID
        or value.get("candidate_id") != contract.CANDIDATE_ID
        or value.get("git_head") != prepared.lock_context.git_head
        or value.get("lock")
        != {
            "path": contract.LOCK_PATH,
            "sha256": prepared.lock_context.lock_sha256,
        }
        or value.get("question_sha256")
        != prepared.lock_context.lock["bindings"]["question"]["sha256"]
        or value.get("plan_sha256") != plan["plan_sha256"]
        or value.get("config_sha256")
        != prepared.lock_context.lock["bindings"]["models_config"]["sha256"]
        or value.get("successful_outcome_count") != 8
        or value.get("failed_model_keys") != []
        or value.get("network_contract")
        != {
            "preflight_requests": 8,
            "generation_posts": 8,
            "automatic_retries": 0,
            "tools_enabled": False,
            "web_search_enabled": False,
            "retrieval_enabled": False,
            "external_context_enabled": False,
        }
        or not isinstance(outcomes, list)
        or len(outcomes) != 8
    ):
        raise DivergenceSuccessorCompositeError(
            "successor composite header or exact panel changed"
        )
    try:
        require_timestamp(value.get("sealed_at"), "successor composite time")
    except RecoveryJournalError as error:
        raise DivergenceSuccessorCompositeError(str(error)) from error
    for actual, expected in zip(outcomes, expected_outcomes, strict=True):
        if (
            not isinstance(actual, dict)
            or set(actual) != {*expected, "sha256"}
            or any(actual[key] != item for key, item in expected.items())
            or not isinstance(actual["sha256"], str)
            or len(actual["sha256"]) != 64
        ):
            raise DivergenceSuccessorCompositeError(
                "successor composite outcome inventory changed"
            )
    for name in ("authorization", "pricing_recheck", "manifest"):
        binding = value.get(name)
        if (
            not isinstance(binding, dict)
            or set(binding) != {"path", "sha256"}
            or not isinstance(binding["path"], str)
            or not isinstance(binding["sha256"], str)
            or len(binding["sha256"]) != 64
        ):
            raise DivergenceSuccessorCompositeError(
                f"successor composite {name} binding is malformed"
            )
    execute.reject_tool_artifacts(value, path="composite")


async def validate_composite_record(
    prepared: execute.PreparedSuccessor,
    authority_value: Any,
    record: JournalRecord,
    *,
    manifest: JournalRecord | None = None,
    preflight_by_key: Mapping[str, JournalRecord] | None = None,
) -> tuple[JournalRecord, ...]:
    """Authenticate every semantic source bound by the response-free index."""

    from . import engine

    if record.path != prepared.paths.composite:
        raise DivergenceSuccessorCompositeError("successor composite path changed")
    validate_composite_value(prepared, record.payload)
    paid = _read_bound(
        prepared.paths.private_root,
        record.payload["authorization"],
        "successor paid authorization",
    )
    pricing = _read_bound(
        prepared.paths.private_root,
        record.payload["pricing_recheck"],
        "successor pricing recheck",
    )
    try:
        verified_paid = authorization.validate_authorization(
            prepared.lock_context
        )
        verified_pricing = authorization.validate_pricing_recheck(
            prepared.lock_context, verified_paid, fresh=False
        )
    except authorization.DivergenceSuccessorAuthorizationError as error:
        raise DivergenceSuccessorCompositeError(str(error)) from error
    if (
        paid.path != verified_paid.path
        or paid.payload != verified_paid.payload
        or paid.sha256 != verified_paid.sha256
        or pricing.path != verified_pricing.path
        or pricing.payload != verified_pricing.payload
        or pricing.sha256 != verified_pricing.sha256
        or authority_value.authorization != verified_paid
        or authority_value.pricing != verified_pricing
    ):
        raise DivergenceSuccessorCompositeError(
            "composite authority or pricing source changed"
        )
    if manifest is None:
        manifest = _read_bound(
            prepared.paths.private_root,
            record.payload["manifest"],
            "successor preflight manifest",
        )
    elif (
        _binding(prepared.paths.private_root, manifest, "preflight manifest")
        != record.payload["manifest"]
    ):
        raise DivergenceSuccessorCompositeError(
            "composite manifest binding changed"
        )
    if preflight_by_key is None:
        preflight_by_key = await engine.validate_manifest_record(
            prepared, authority_value, manifest
        )
    else:
        validated = await engine.validate_manifest_record(
            prepared, authority_value, manifest
        )
        if dict(preflight_by_key) != validated:
            raise DivergenceSuccessorCompositeError(
                "composite preflight sources changed"
            )
    outcomes: list[JournalRecord] = []
    _, cells = _plan(prepared)
    for cell, item in zip(cells, record.payload["outcomes"], strict=True):
        key = cell["model_key"]
        outcome = _read_bound(
            prepared.paths.private_root, item, f"successor outcome {key}"
        )
        intent = _read_bound(
            prepared.paths.private_root,
            outcome.payload.get("intent", {}),
            f"successor intent {key}",
        )
        raw = _read_bound(
            prepared.paths.private_root,
            outcome.payload.get("raw_response", {}),
            f"successor raw response {key}",
        )
        parsed = await engine.validate_generation_record(
            prepared,
            authority_value,
            manifest,
            preflight_by_key[key],
            prepared.call_by_key[key],
            intent,
            raw,
            outcome,
        )
        if parsed is None:
            raise DivergenceSuccessorCompositeError(
                f"composite binds a failed generation for {key}"
            )
        outcomes.append(outcome)
    expected = composite_payload(
        prepared,
        authorization_record=paid,
        pricing_recheck_record=pricing,
        manifest_record=manifest,
        outcomes=outcomes,
        sealed_at=record.payload["sealed_at"],
    )
    if record.payload != expected:
        raise DivergenceSuccessorCompositeError(
            "successor composite differs from its semantically verified sources"
        )
    return tuple(outcomes)


def _run(coroutine: Any) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine)
    coroutine.close()
    raise DivergenceSuccessorCompositeError(
        "successor review validation requires a synchronous process"
    )


def _read_bound(
    private_root: Path, binding: Mapping[str, Any], label: str
) -> JournalRecord:
    if not isinstance(binding, Mapping):
        raise DivergenceSuccessorCompositeError(f"{label} binding is malformed")
    try:
        relative = contract.require_relative_path(binding.get("path"), label)
        record = read_record(private_root / relative, label)
    except (contract.ContractError, RecoveryJournalError) as error:
        raise DivergenceSuccessorCompositeError(str(error)) from error
    if record.sha256 != binding.get("sha256"):
        raise DivergenceSuccessorCompositeError(f"{label} changed")
    return record


def load_composite_responses(
    repository_root: Path | str, candidate_id: str
) -> review.ResponseBundle:
    """Authenticate the terminal index, then read response text only at review."""

    if candidate_id != contract.CANDIDATE_ID:
        raise DivergenceSuccessorCompositeError(
            "successor composite contains only the replacement candidate"
        )
    prepared = execute.prepare_successor(repository_root, require_committed=True)
    try:
        composite = read_record(prepared.paths.composite, "successor composite")
    except RecoveryJournalError as error:
        raise DivergenceSuccessorCompositeError(str(error)) from error
    try:
        paid = authorization.validate_authorization(prepared.lock_context)
        pricing = authorization.validate_pricing_recheck(
            prepared.lock_context, paid, fresh=False
        )
    except authorization.DivergenceSuccessorAuthorizationError as error:
        raise DivergenceSuccessorCompositeError(str(error)) from error
    from .engine import Authority

    outcomes = _run(
        validate_composite_record(
            prepared, Authority(paid, pricing), composite
        )
    )
    facts = review._review_lock_facts(prepared.repository_root, candidate_id)
    if (
        facts["lock_sha256"] != prepared.lock_context.lock_sha256
        or facts["question_sha256"] != composite.payload["question_sha256"]
        or facts["plan_sha256"] != composite.payload["plan_sha256"]
    ):
        raise DivergenceSuccessorCompositeError(
            "review facts differ from the successor composite"
        )
    records: list[review.ResponseRecord] = []
    _, cells = _plan(prepared)
    for cell, item, outcome in zip(
        cells, composite.payload["outcomes"], outcomes, strict=True
    ):
        payload = execute.validate_generation_outcome(
            outcome,
            model_key=item["model_key"],
            prompt_sha256=cell["prompt_sha256"],
        )
        result = payload["result"]
        response_id = result.get("provider_response_id")
        if response_id is not None and not isinstance(response_id, str):
            raise DivergenceSuccessorCompositeError(
                "successor response ID is malformed"
            )
        records.append(
            review.ResponseRecord(
                candidate_id=candidate_id,
                cell_id=cell["cell_id"],
                model_key=item["model_key"],
                provider=payload["provider"],
                requested_model_id=payload["requested_model_id"],
                response_id=response_id,
                response_text=result["response_text"],
                prompt_sha256=cell["prompt_sha256"],
                outcome_path=outcome.path.relative_to(
                    prepared.repository_root
                ).as_posix(),
                outcome_sha256=outcome.sha256,
                attempt_number=1,
            )
        )
    bindings = {
        "git_head": facts["git_head"],
        "lock_sha256": facts["lock_sha256"],
        "question_sha256": facts["question_sha256"],
        "plan_sha256": facts["plan_sha256"],
        "review_assets_sha256": facts["review_assets_sha256"],
        "authorization_receipt_sha256": composite.payload["authorization"][
            "sha256"
        ],
        "pricing_recheck_receipt_sha256": composite.payload["pricing_recheck"][
            "sha256"
        ],
        "model_manifest_sha256": composite.payload["manifest"]["sha256"],
        "run_receipt_sha256": composite.sha256,
    }
    bundle = review.ResponseBundle(candidate_id, bindings, tuple(records))
    review._require_bundle_lineage(prepared.repository_root, candidate_id, bundle)
    return bundle


__all__ = (
    "COMPOSITE_SCHEMA",
    "COMPOSITE_STATUS",
    "DivergenceSuccessorCompositeError",
    "composite_payload",
    "load_composite_responses",
    "validate_composite_record",
    "validate_composite_value",
)
