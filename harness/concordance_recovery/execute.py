"""Execute the sealed two-plus-six successor recovery without replay.

All offline gates run before target credentials are read.  Generation is
strictly sequential.  Every POST has a durable intent first, and every HTTP
response is captured losslessly before provider parsing or semantic checks.
"""

from __future__ import annotations

import asyncio
import json
import os
import stat
import time
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, ROUND_CEILING
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping

from concordance_harness.config import (
    HarnessConfig,
    load_harness_config,
    returned_model_id_is_approved,
)
from concordance_harness.execution import RateLimiter, billed_output_tokens
from concordance_harness.planner import (
    PlannedCall,
    QuestionInput,
    build_plan,
    load_questions,
)
from concordance_harness.providers import (
    PreflightResult,
    ProviderAdapter,
    ProviderError,
    ProviderResult,
    Transport,
    UrllibTransport,
)
from concordance_harness.util import (
    canonical_json_bytes,
    estimate_message_tokens,
    prompt_sha256,
    sha256_bytes,
    utc_now,
)
from rule3 import contract as parent_contract
from rule3.budget import JournalRecord
from rule3.execute import plan_contract_sha256, reserved_microdollars

from . import contract
from .authorization import (
    ReceiptBinding,
    RecoveryAuthorizationError,
    validate_paid_authorization,
    validate_pricing_recheck,
)
from .journal import (
    COMPOSITE_SCHEMA,
    GENERATION_INTENT_SCHEMA,
    GENERATION_OUTCOME_SCHEMA,
    MANIFEST_SCHEMA,
    PREFLIGHT_INTENT_SCHEMA,
    PREFLIGHT_OUTCOME_SCHEMA,
    RecoveryJournalError,
    StrandedGenerationIntent,
    binding,
    read_record,
    require_timestamp,
    write_record,
)
from .lock import RecoveryLockContext, load_and_validate_recovery_lock
from .parent import ParentEvidence, validate_parent_evidence
from .state import RecoveryPaths, phase_lock
from .transport import CapturedReplayTransport, DurableCaptureTransport


CLAIM_SCHEMA = "concordance-recovery-parent-claim-1.0.0"
FINISH_REASON_BY_API_STYLE = {
    "cohere": "COMPLETE",
    "openai": "stop",
    "xai-responses": "completed",
}
SAFE_RETRY_CATEGORIES = {"invalid-request", "provider-error", "rate-limit"}
PREFLIGHT_RETRY_CATEGORIES = SAFE_RETRY_CATEGORIES | {
    "metadata-interrupted",
    "network",
    "timeout",
}


class RecoveryExecutionError(RuntimeError):
    """Raised before an unapproved, unauditable, or replayed request."""


@dataclass(frozen=True)
class PreparedRecovery:
    repository_root: Path
    lock_context: RecoveryLockContext
    config: HarnessConfig
    question: QuestionInput
    full_plan: tuple[PlannedCall, ...]
    target_plan: tuple[PlannedCall, ...]
    target_by_key: dict[str, PlannedCall]
    paths: RecoveryPaths


@dataclass(frozen=True)
class Authority:
    authorization: ReceiptBinding
    pricing: ReceiptBinding
    claim: ReceiptBinding | None = None


@dataclass(frozen=True)
class RecoveryResult:
    path: Path
    payload: dict[str, Any]
    sha256: str
    network_requests: int


def _load_protocol(root: Path) -> dict[str, str]:
    path = root / parent_contract.PROTOCOL_PATH
    try:
        raw = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as error:
        raise RecoveryExecutionError(
            f"parent protocol cannot be loaded: {error}"
        ) from error
    expected = {"protocol_version", "system_prompt", "standard_challenge_prompt"}
    if (
        not isinstance(raw, dict)
        or set(raw) != expected
        or not all(isinstance(raw.get(key), str) for key in expected)
        or raw["system_prompt"] != parent_contract.SYSTEM_PROMPT
    ):
        raise RecoveryExecutionError("parent protocol differs from its sealed shape")
    return raw


def _parent_priority_cells(
    lock_context: RecoveryLockContext,
) -> dict[str, dict[str, Any]]:
    parent = json.loads(
        (lock_context.repository_root / contract.PARENT_LOCK_PATH).read_bytes()
    )
    plans = parent.get("plans") if isinstance(parent, dict) else None
    values = plans.get("candidate_plans") if isinstance(plans, dict) else None
    matches = [
        item
        for item in values or []
        if isinstance(item, dict) and item.get("candidate_id") == contract.CANDIDATE_ID
    ]
    if (
        len(matches) != 1
        or matches[0].get("plan_sha256") != contract.PARENT_PLAN_SHA256
    ):
        raise RecoveryExecutionError("parent priority plan changed")
    cells = matches[0].get("cells")
    if not isinstance(cells, list) or len(cells) != len(contract.MODEL_ORDER):
        raise RecoveryExecutionError("parent priority plan is malformed")
    return {
        key: cell
        for key, cell in zip(contract.MODEL_ORDER, cells, strict=True)
        if isinstance(cell, dict)
    }


def _validate_target_plan(
    lock_context: RecoveryLockContext,
    full_plan: tuple[PlannedCall, ...],
    target_plan: tuple[PlannedCall, ...],
) -> None:
    if (
        plan_contract_sha256(full_plan) != contract.PARENT_PLAN_SHA256
        or tuple(call.model.model_key for call in full_plan) != contract.MODEL_ORDER
        or tuple(call.model.model_key for call in target_plan)
        != contract.TARGET_MODEL_KEYS
    ):
        raise RecoveryExecutionError("current plan differs from the sealed parent plan")
    locked = lock_context.lock.get("target_plan")
    records = locked.get("cells") if isinstance(locked, dict) else None
    parent_cells = _parent_priority_cells(lock_context)
    if (
        not isinstance(records, list)
        or len(records) != len(target_plan)
        or locked.get("model_order") != list(contract.TARGET_MODEL_KEYS)
        or locked.get("plan_sha256") != sha256_bytes(canonical_json_bytes(records))
    ):
        raise RecoveryExecutionError("recovery target plan is malformed")
    for call, record in zip(target_plan, records, strict=True):
        model_key = call.model.model_key
        if (
            record.get("model_key") != model_key
            or record.get("cell_id") != call.cell_id
            or record.get("requested_model_id") != call.model.requested_model_id
            or record.get("provider") != call.model.provider
            or record.get("route") != call.model.route
            or record.get("environment_variable") != call.model.environment_variable
            or record.get("fallback_allowed") is not False
            or record.get("reserved_cost_microdollars_per_post")
            != reserved_microdollars(call)
            or record.get("parent_cell_contract_sha256")
            != sha256_bytes(canonical_json_bytes(parent_cells[model_key]))
            or call.model.output_cap != contract.OUTPUT_TOKEN_CAP
        ):
            raise RecoveryExecutionError(
                f"locked recovery cell changed for {model_key}"
            )


def _load_question(root: Path) -> QuestionInput:
    questions = load_questions(root / "candidate/rule3/questions")
    matches = [item for item in questions if item.question_id == contract.CANDIDATE_ID]
    if len(matches) != 1:
        raise RecoveryExecutionError("priority question is not uniquely frozen")
    return matches[0]


def prepare_recovery(
    repository_root: Path,
    *,
    require_committed: bool,
) -> PreparedRecovery:
    root = repository_root.resolve()
    try:
        lock_context = load_and_validate_recovery_lock(
            root,
            require_committed=require_committed,
            require_parent_private=require_committed,
        )
    except Exception as error:
        raise RecoveryExecutionError(str(error)) from error
    config = load_harness_config(root / parent_contract.MODELS_CONFIG_PATH)
    question = _load_question(root)
    protocol = _load_protocol(root)
    full_plan = build_plan(
        (question,),
        config.models,
        protocol["system_prompt"],
        protocol["standard_challenge_prompt"],
        answer_only=True,
    )
    target_plan = tuple(
        call for call in full_plan if call.model.model_key in contract.TARGET_MODEL_KEYS
    )
    _validate_target_plan(lock_context, full_plan, target_plan)
    return PreparedRecovery(
        repository_root=root,
        lock_context=lock_context,
        config=config,
        question=question,
        full_plan=full_plan,
        target_plan=target_plan,
        target_by_key={call.model.model_key: call for call in target_plan},
        paths=RecoveryPaths.for_repository(root),
    )


def dry_run_summary(prepared: PreparedRecovery) -> dict[str, Any]:
    return {
        "recovery_id": contract.RECOVERY_ID,
        "candidate_id": contract.CANDIDATE_ID,
        "preserved_model_keys": list(contract.PRESERVED_MODEL_KEYS),
        "target_model_keys": list(contract.TARGET_MODEL_KEYS),
        "fresh_preflight_required": True,
        "maximum_preflight_requests": contract.MAX_PREFLIGHT_REQUESTS,
        "maximum_generation_posts": contract.MAX_GENERATION_POSTS,
        "parent_reserved_microdollars": contract.PARENT_RESERVED_MICRODOLLARS,
        "new_reserved_cap_microdollars": contract.NEW_RESERVED_CAP_MICRODOLLARS,
        "combined_reserved_cap_microdollars": (
            contract.COMBINED_RESERVED_CAP_MICRODOLLARS
        ),
        "network_requests": 0,
        "environment_variables_read": 0,
    }


def _authority(prepared: PreparedRecovery, *, fresh: bool) -> Authority:
    try:
        authorization = validate_paid_authorization(prepared.lock_context)
        pricing = validate_pricing_recheck(prepared.lock_context, require_fresh=fresh)
    except RecoveryAuthorizationError as error:
        raise RecoveryExecutionError(str(error)) from error
    return Authority(authorization, pricing)


def _common(prepared: PreparedRecovery, authority: Authority) -> dict[str, Any]:
    git_head = prepared.lock_context.git_head
    if not isinstance(git_head, str):
        raise RecoveryExecutionError("live recovery lacks a committed Git HEAD")
    value = {
        "recovery_id": contract.RECOVERY_ID,
        "pool_id": contract.POOL_ID,
        "candidate_id": contract.CANDIDATE_ID,
        "phase": contract.PRIORITY_PHASE,
        "git_head": git_head,
        "recovery_lock_sha256": prepared.lock_context.lock_sha256,
        "authorization_receipt_sha256": authority.authorization.sha256,
        "pricing_recheck_receipt_sha256": authority.pricing.sha256,
        "parent_lock_sha256": contract.PARENT_LOCK_SHA256,
        "parent_manifest_sha256": contract.PARENT_MANIFEST_SHA256,
    }
    if authority.claim is not None:
        if authority.claim.path != prepared.paths.claim:
            raise RecoveryExecutionError("parent claim path changed")
        value["parent_claim"] = {
            "path": authority.claim.path.relative_to(
                prepared.repository_root
            ).as_posix(),
            "sha256": authority.claim.sha256,
        }
    return value


def _authority_with_claim(
    prepared: PreparedRecovery,
    authority: Authority,
    claim: JournalRecord,
) -> Authority:
    if authority.claim is not None or claim.path != prepared.paths.claim:
        raise RecoveryExecutionError("parent claim binding is malformed")
    return Authority(
        authorization=authority.authorization,
        pricing=authority.pricing,
        claim=ReceiptBinding(claim.path, claim.payload, claim.sha256),
    )


def _claim_payload(
    prepared: PreparedRecovery,
    authority: Authority,
    parent: ParentEvidence,
    *,
    claimed_at: str,
) -> dict[str, Any]:
    if authority.claim is not None:
        raise RecoveryExecutionError("parent claim cannot bind itself")
    require_timestamp(claimed_at, "recovery claim time")
    return {
        "schema_version": CLAIM_SCHEMA,
        "status": "parent-stranded-intent-claimed-once",
        **_common(prepared, authority),
        "parent_stranded_intent": {
            "path": contract.STRANDED_COHERE["intent_path"],
            "sha256": parent.stranded_intent.sha256,
        },
        "replacement_model_key": "cohere",
        "replacement_semantic_attempt_number": 2,
        "claimed_at": claimed_at,
    }


def _ensure_claim(
    prepared: PreparedRecovery, authority: Authority, parent: ParentEvidence
) -> JournalRecord:
    path = prepared.paths.claim
    if path.exists():
        record = read_record(path, "cross-recovery parent claim")
        expected = _claim_payload(
            prepared,
            authority,
            parent,
            claimed_at=record.payload.get("claimed_at"),
        )
        if record.payload != expected:
            raise RecoveryExecutionError("parent recovery is already claimed")
        return record
    allowed_before_claim = {
        prepared.paths.private_root / "paid-authorization.json",
        prepared.paths.private_root / "pricing-evidence.json",
        prepared.paths.private_root / "pricing-recheck.json",
    }
    if prepared.paths.private_root.exists() and any(
        item.is_file()
        and item.resolve() not in {path.resolve() for path in allowed_before_claim}
        for item in prepared.paths.private_root.rglob("*")
    ):
        raise RecoveryExecutionError(
            "missing parent claim: downstream state exists; downstream recovery "
            "state cannot precede the parent claim"
        )
    payload = _claim_payload(prepared, authority, parent, claimed_at=utc_now())
    return write_record(path, payload)


def _collect_target_secrets(
    prepared: PreparedRecovery, environment: Mapping[str, str]
) -> dict[str, str]:
    result: dict[str, str] = {}
    for call in prepared.target_plan:
        name = call.model.environment_variable
        value = environment.get(name, "")
        if not value:
            raise RecoveryExecutionError(
                "missing required recovery environment variable: " + name
            )
        result[name] = value
    return result


def _record_binding(
    prepared: PreparedRecovery, record: JournalRecord
) -> dict[str, str]:
    return binding(prepared.paths.private_root, record).value()


def _preflight_intent_payload(
    prepared: PreparedRecovery,
    authority: Authority,
    call: PlannedCall,
    attempt: int,
    *,
    created_at: str,
) -> dict[str, Any]:
    require_timestamp(created_at, "preflight intent time")
    request = ProviderAdapter(call.model, _NeverTransport()).build_metadata_request(
        "redacted-offline-secret"
    )
    return {
        "schema_version": PREFLIGHT_INTENT_SCHEMA,
        "status": "reserved-before-metadata-get",
        **_common(prepared, authority),
        "model_key": call.model.model_key,
        "provider": call.model.provider,
        "route": call.model.route,
        "requested_model_id": call.model.requested_model_id,
        "attempt_number": attempt,
        "request_method": "GET",
        "request_origin": _safe_origin(request),
        "created_at": created_at,
    }


def _generation_intent_payload(
    prepared: PreparedRecovery,
    authority: Authority,
    parent: ParentEvidence,
    manifest: JournalRecord,
    preflight: JournalRecord,
    call: PlannedCall,
    attempt: int,
    *,
    created_at: str,
) -> dict[str, Any]:
    require_timestamp(created_at, "generation intent time")
    _require_not_before(
        created_at,
        "generation intent time",
        manifest.payload.get("sealed_at"),
        "recovery manifest time",
    )
    _require_not_before(
        created_at,
        "generation intent time",
        preflight.payload.get("completed_at"),
        "preflight completion time",
    )
    messages = call.answer_messages()
    request = ProviderAdapter(call.model, _NeverTransport()).build_generation_request(
        "redacted-offline-secret", messages
    )
    model_key = call.model.model_key
    replacement = (
        {
            "path": contract.STRANDED_COHERE["intent_path"],
            "sha256": parent.stranded_intent.sha256,
            "disposition": contract.STRANDED_COHERE["disposition"],
        }
        if model_key == "cohere"
        else None
    )
    return {
        "schema_version": GENERATION_INTENT_SCHEMA,
        "status": "reserved-before-generation-post",
        **_common(prepared, authority),
        "cell_id": call.cell_id,
        "model_key": model_key,
        "model_family": call.model.family,
        "provider": call.model.provider,
        "route": call.model.route,
        "requested_model_id": call.model.requested_model_id,
        "semantic_attempt_number": attempt,
        "reserved_cost_microdollars": reserved_microdollars(call),
        "question_sha256": call.question.sha256,
        "prompt_sha256": prompt_sha256(messages),
        "messages": messages,
        "messages_sha256": sha256_bytes(canonical_json_bytes(messages)),
        "requested_params": call.model.requested_params_receipt(),
        "requested_params_sha256": sha256_bytes(
            canonical_json_bytes(call.model.requested_params_receipt())
        ),
        "request_json_body_sha256": sha256_bytes(
            json.dumps(request.json_body, ensure_ascii=False).encode("utf-8")
        ),
        "manifest": _record_binding(prepared, manifest),
        "preflight_outcome": _record_binding(prepared, preflight),
        "replacement_of_parent_intent": replacement,
        "created_at": created_at,
    }


class _NeverTransport:
    async def send(self, request: Any) -> Any:
        del request
        raise RecoveryExecutionError("offline request builder attempted network access")


def _safe_origin(request: Any) -> str:
    from .journal import request_origin

    return request_origin(request)


def _validate_intent(
    record: JournalRecord,
    expected: dict[str, Any],
    expected_path: Path,
    label: str,
) -> None:
    expected["created_at"] = record.payload.get("created_at")
    if record.path.resolve() != expected_path.resolve() or record.payload != expected:
        raise RecoveryExecutionError(f"{label} differs from the locked request")


def _parsed_timestamp(value: Any, label: str) -> datetime:
    try:
        require_timestamp(value, label)
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (RecoveryJournalError, ValueError, AttributeError) as error:
        raise RecoveryExecutionError(str(error)) from error


def _require_not_before(
    later: Any,
    later_label: str,
    earlier: Any,
    earlier_label: str,
) -> None:
    if _parsed_timestamp(later, later_label) < _parsed_timestamp(
        earlier, earlier_label
    ):
        raise RecoveryExecutionError(
            f"chronology violation: {later_label} is before {earlier_label}"
        )


def _raw_common(
    prepared: PreparedRecovery,
    authority: Authority,
    *,
    model_key: str,
    attempt: int,
) -> dict[str, Any]:
    return {
        **_common(prepared, authority),
        "model_key": model_key,
        "semantic_attempt_number": attempt,
    }


def _error_value(
    error: ProviderError,
    secrets: Mapping[str, str],
    *,
    preflight: bool = False,
) -> dict[str, Any]:
    del secrets
    allowed = PREFLIGHT_RETRY_CATEGORIES if preflight else SAFE_RETRY_CATEGORIES
    kind = "metadata" if preflight else "generation"
    return {
        "category": error.category,
        "retryable": error.retryable and error.category in allowed,
        "sanitized_summary": f"{kind} request failed ({error.category})",
    }


def _interrupted_preflight_error() -> dict[str, Any]:
    return {
        "category": "metadata-interrupted",
        "retryable": True,
        "sanitized_summary": (
            "metadata attempt ended without a durable HTTP response; "
            "the idempotent GET is consumed and may advance"
        ),
    }


def _preflight_outcome_payload(
    prepared: PreparedRecovery,
    authority: Authority,
    intent: JournalRecord,
    call: PlannedCall,
    *,
    raw: JournalRecord | None,
    result: PreflightResult | None,
    error: dict[str, Any] | None,
    completed_at: str,
) -> dict[str, Any]:
    require_timestamp(completed_at, "preflight completion time")
    _require_not_before(
        completed_at,
        "preflight completion time",
        intent.payload.get("created_at"),
        "preflight intent time",
    )
    if raw is not None:
        _require_not_before(
            completed_at,
            "preflight completion time",
            raw.payload.get("received_at"),
            "preflight raw response time",
        )
    value: dict[str, Any] = {
        "schema_version": PREFLIGHT_OUTCOME_SCHEMA,
        "status": "success" if result is not None else "error",
        **_common(prepared, authority),
        "model_key": call.model.model_key,
        "provider": call.model.provider,
        "route": call.model.route,
        "requested_model_id": call.model.requested_model_id,
        "attempt_number": intent.payload["attempt_number"],
        "intent": _record_binding(prepared, intent),
        "raw_response": _record_binding(prepared, raw) if raw else None,
        "completed_at": completed_at,
    }
    if result is not None:
        value.update(
            {
                "provider_returned_model_id": result.returned_model_id,
                "provider_name": result.provider_name,
                "sanitized_note": result.note,
            }
        )
    else:
        value["error"] = error
    return value


def _generation_outcome_payload(
    prepared: PreparedRecovery,
    authority: Authority,
    intent: JournalRecord,
    raw: JournalRecord,
    call: PlannedCall,
    *,
    result: ProviderResult | None,
    error: dict[str, Any] | None,
    latency_ms: int,
    completed_at: str,
) -> dict[str, Any]:
    require_timestamp(completed_at, "generation completion time")
    _require_not_before(
        completed_at,
        "generation completion time",
        intent.payload.get("created_at"),
        "generation intent time",
    )
    _require_not_before(
        completed_at,
        "generation completion time",
        raw.payload.get("received_at"),
        "generation raw response time",
    )
    common: dict[str, Any] = {
        "schema_version": GENERATION_OUTCOME_SCHEMA,
        "status": "success" if result is not None else "error",
        **_common(prepared, authority),
        "cell_id": call.cell_id,
        "model_key": call.model.model_key,
        "model_family": call.model.family,
        "provider": call.model.provider,
        "route": call.model.route,
        "requested_model_id": call.model.requested_model_id,
        "semantic_attempt_number": intent.payload["semantic_attempt_number"],
        "question_sha256": intent.payload["question_sha256"],
        "prompt_sha256": intent.payload["prompt_sha256"],
        "messages_sha256": intent.payload["messages_sha256"],
        "requested_params_sha256": intent.payload["requested_params_sha256"],
        "manifest": intent.payload["manifest"],
        "preflight_outcome": intent.payload["preflight_outcome"],
        "intent": _record_binding(prepared, intent),
        "raw_response": _record_binding(prepared, raw),
        "attempted_at": intent.payload["created_at"],
        "completed_at": completed_at,
        "latency_ms": latency_ms,
    }
    if result is None:
        return {**common, "error": error}
    usage = result.usage
    input_tokens = usage.get("input_tokens")
    if input_tokens is None:
        input_tokens = estimate_message_tokens(call.answer_messages())
    output_tokens = billed_output_tokens(call.model, usage, result.response_text)
    pricing = call.model.planning_pricing
    actual = int(
        (
            Decimal(input_tokens) * Decimal(str(pricing["input_per_million"]))
            + Decimal(output_tokens) * Decimal(str(pricing["output_per_million"]))
        ).to_integral_value(rounding=ROUND_CEILING)
    )
    return {
        **common,
        "provider_returned_model_id": result.returned_model_id,
        "provider_response_id": result.provider_response_id,
        "provider_name": result.provider_name,
        "effective_params": result.effective_params,
        "response_text": result.response_text,
        "response_sha256": sha256_bytes(result.response_text.encode("utf-8")),
        "finish_reason": result.finish_reason,
        "usage": result.usage,
        "cost": {
            "actual_estimate_microdollars": actual,
            "reserved_microdollars": intent.payload["reserved_cost_microdollars"],
            "pricing_as_of": pricing["pricing_as_of"],
        },
    }


def _attempt_range(model_key: str) -> tuple[int, ...]:
    if model_key == "cohere":
        return (2,)
    return tuple(range(1, contract.MAX_UNTOUCHED_GENERATION_ATTEMPTS + 1))


def _preflight_history(
    prepared: PreparedRecovery,
    authority: Authority,
    call: PlannedCall,
) -> list[tuple[JournalRecord, JournalRecord | None, JournalRecord | None]]:
    history = []
    gap = False
    previous_outcome: JournalRecord | None = None
    for attempt in range(1, contract.PREFLIGHT_ATTEMPTS_PER_MODEL + 1):
        intent_path = prepared.paths.preflight_intent(call.model.model_key, attempt)
        raw_path = prepared.paths.preflight_raw(call.model.model_key, attempt)
        outcome_path = prepared.paths.preflight_outcome(call.model.model_key, attempt)
        if not intent_path.exists():
            if raw_path.exists() or outcome_path.exists():
                raise RecoveryExecutionError("orphan preflight evidence exists")
            gap = True
            continue
        if gap:
            raise RecoveryExecutionError("preflight attempts are not contiguous")
        if history and previous_outcome is None:
            raise RecoveryExecutionError(
                "preflight attempt follows an unfinalized attempt"
            )
        intent = read_record(intent_path, "recovery preflight intent")
        expected = _preflight_intent_payload(
            prepared,
            authority,
            call,
            attempt,
            created_at=intent.payload.get("created_at"),
        )
        _validate_intent(intent, expected, intent_path, "preflight intent")
        if previous_outcome is not None:
            _require_not_before(
                intent.payload.get("created_at"),
                "preflight intent time",
                previous_outcome.payload.get("completed_at"),
                "previous preflight completion time",
            )
        raw = (
            read_record(raw_path, "recovery preflight raw response")
            if raw_path.exists()
            else None
        )
        outcome = (
            read_record(outcome_path, "recovery preflight outcome")
            if outcome_path.exists()
            else None
        )
        history.append((intent, raw, outcome))
        previous_outcome = outcome
    return history


def _generation_history(
    prepared: PreparedRecovery,
    authority: Authority,
    parent: ParentEvidence,
    manifest: JournalRecord,
    preflight: JournalRecord,
    call: PlannedCall,
) -> list[tuple[JournalRecord, JournalRecord | None, JournalRecord | None]]:
    history = []
    gap = False
    previous_outcome: JournalRecord | None = None
    for attempt in _attempt_range(call.model.model_key):
        intent_path = prepared.paths.generation_intent(call.model.model_key, attempt)
        raw_path = prepared.paths.generation_raw(call.model.model_key, attempt)
        outcome_path = prepared.paths.generation_outcome(call.model.model_key, attempt)
        if not intent_path.exists():
            if raw_path.exists() or outcome_path.exists():
                raise RecoveryExecutionError("orphan generation evidence exists")
            gap = True
            continue
        if gap:
            raise RecoveryExecutionError("generation attempts are not contiguous")
        if history and previous_outcome is None:
            raise RecoveryExecutionError(
                "generation attempt follows an unfinalized attempt"
            )
        intent = read_record(intent_path, "recovery generation intent")
        expected = _generation_intent_payload(
            prepared,
            authority,
            parent,
            manifest,
            preflight,
            call,
            attempt,
            created_at=intent.payload.get("created_at"),
        )
        _validate_intent(intent, expected, intent_path, "generation intent")
        if previous_outcome is not None:
            _require_not_before(
                intent.payload.get("created_at"),
                "generation intent time",
                previous_outcome.payload.get("completed_at"),
                "previous generation completion time",
            )
        raw = (
            read_record(raw_path, "recovery generation raw response")
            if raw_path.exists()
            else None
        )
        outcome = (
            read_record(outcome_path, "recovery generation outcome")
            if outcome_path.exists()
            else None
        )
        history.append((intent, raw, outcome))
        previous_outcome = outcome
    return history


async def _parse_preflight_capture(
    prepared: PreparedRecovery,
    authority: Authority,
    call: PlannedCall,
    intent: JournalRecord,
    raw: JournalRecord,
) -> PreflightResult:
    expected_request = ProviderAdapter(
        call.model, _NeverTransport()
    ).build_metadata_request("redacted-offline-secret")
    replay = CapturedReplayTransport(
        raw,
        private_root=prepared.paths.private_root,
        common=_raw_common(
            prepared,
            authority,
            model_key=call.model.model_key,
            attempt=intent.payload["attempt_number"],
        ),
        intent=intent,
        request_kind="preflight",
        expected_request=expected_request,
    )
    return await ProviderAdapter(call.model, replay).preflight(
        "redacted-offline-secret"
    )


async def _parse_generation_capture(
    prepared: PreparedRecovery,
    authority: Authority,
    call: PlannedCall,
    intent: JournalRecord,
    raw: JournalRecord,
    preflight: JournalRecord,
) -> ProviderResult:
    messages = call.answer_messages()
    expected_request = ProviderAdapter(
        call.model, _NeverTransport()
    ).build_generation_request("redacted-offline-secret", messages)
    replay = CapturedReplayTransport(
        raw,
        private_root=prepared.paths.private_root,
        common=_raw_common(
            prepared,
            authority,
            model_key=call.model.model_key,
            attempt=intent.payload["semantic_attempt_number"],
        ),
        intent=intent,
        request_kind="generation",
        expected_request=expected_request,
    )
    result = await ProviderAdapter(call.model, replay).generate(
        "redacted-offline-secret", messages
    )
    returned = result.returned_model_id
    if call.model.model_key == "cohere":
        preflight_id = preflight.payload.get("provider_returned_model_id")
        body = expected_request.json_body
        if (
            preflight_id != call.model.requested_model_id
            or not isinstance(body, dict)
            or body.get("model") != call.model.requested_model_id
            or call.model.fallback_allowed
            or (
                returned is not None
                and not returned_model_id_is_approved(call.model, returned)
            )
        ):
            raise ProviderError(
                "Cohere generation identity lacks its exact request and fresh preflight",
                category="response-validation",
                retryable=False,
            )
    elif returned is None or not returned_model_id_is_approved(call.model, returned):
        raise ProviderError(
            "generation response lacks the exact returned model identifier",
            category="response-validation",
            retryable=False,
        )
    return result


def _validate_error_object(
    value: Any, label: str, *, allowed_retry_categories: set[str]
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != {"category", "retryable", "sanitized_summary"}
        or not isinstance(value.get("category"), str)
        or not isinstance(value.get("retryable"), bool)
        or not isinstance(value.get("sanitized_summary"), str)
        or not value["sanitized_summary"]
    ):
        raise RecoveryExecutionError(f"{label} error receipt is malformed")
    if value["retryable"] and value["category"] not in allowed_retry_categories:
        raise RecoveryExecutionError(f"{label} retry policy is not safe")
    return value


async def _validate_preflight_outcome(
    prepared: PreparedRecovery,
    authority: Authority,
    call: PlannedCall,
    intent: JournalRecord,
    raw: JournalRecord | None,
    outcome: JournalRecord,
) -> PreflightResult | None:
    value = outcome.payload
    common = {
        "schema_version": PREFLIGHT_OUTCOME_SCHEMA,
        **_common(prepared, authority),
        "model_key": call.model.model_key,
        "provider": call.model.provider,
        "route": call.model.route,
        "requested_model_id": call.model.requested_model_id,
        "attempt_number": intent.payload["attempt_number"],
        "intent": _record_binding(prepared, intent),
        "raw_response": _record_binding(prepared, raw) if raw else None,
    }
    for key, expected in common.items():
        if value.get(key) != expected:
            raise RecoveryExecutionError("preflight outcome lineage changed")
    require_timestamp(value.get("completed_at"), "preflight completion time")
    _require_not_before(
        value.get("completed_at"),
        "preflight completion time",
        intent.payload.get("created_at"),
        "preflight intent time",
    )
    if raw is not None:
        _require_not_before(
            value.get("completed_at"),
            "preflight completion time",
            raw.payload.get("received_at"),
            "preflight raw response time",
        )
    expected_path = prepared.paths.preflight_outcome(
        call.model.model_key, intent.payload["attempt_number"]
    )
    if outcome.path.resolve() != expected_path.resolve():
        raise RecoveryExecutionError("preflight outcome path changed")
    if value.get("status") == "success":
        if raw is None:
            raise RecoveryExecutionError("successful preflight lacks a raw response")
        try:
            result = await _parse_preflight_capture(
                prepared, authority, call, intent, raw
            )
        except ProviderError as error:
            raise RecoveryExecutionError(
                "successful preflight no longer parses as success"
            ) from error
        expected = _preflight_outcome_payload(
            prepared,
            authority,
            intent,
            call,
            raw=raw,
            result=result,
            error=None,
            completed_at=value["completed_at"],
        )
        if value != expected:
            raise RecoveryExecutionError("successful preflight outcome changed")
        return result
    if value.get("status") != "error":
        raise RecoveryExecutionError("preflight outcome status is invalid")
    error_value = _validate_error_object(
        value.get("error"),
        "preflight",
        allowed_retry_categories=PREFLIGHT_RETRY_CATEGORIES,
    )
    expected_keys = set(common) | {"status", "completed_at", "error"}
    if set(value) != expected_keys:
        raise RecoveryExecutionError("preflight error fields changed")
    if raw is not None:
        try:
            await _parse_preflight_capture(prepared, authority, call, intent, raw)
        except ProviderError as error:
            if error_value != _error_value(error, {}, preflight=True):
                raise RecoveryExecutionError(
                    "preflight error receipt changed"
                ) from error
        else:
            raise RecoveryExecutionError("preflight error now parses as success")
    elif error_value != _interrupted_preflight_error():
        raise RecoveryExecutionError("preflight error receipt changed")
    return None


async def _finalize_preflight_capture(
    prepared: PreparedRecovery,
    authority: Authority,
    call: PlannedCall,
    intent: JournalRecord,
    raw: JournalRecord,
    *,
    secrets: Mapping[str, str],
) -> JournalRecord:
    try:
        result = await _parse_preflight_capture(prepared, authority, call, intent, raw)
    except ProviderError as error:
        payload = _preflight_outcome_payload(
            prepared,
            authority,
            intent,
            call,
            raw=raw,
            result=None,
            error=_error_value(error, secrets, preflight=True),
            completed_at=utc_now(),
        )
    else:
        payload = _preflight_outcome_payload(
            prepared,
            authority,
            intent,
            call,
            raw=raw,
            result=result,
            error=None,
            completed_at=utc_now(),
        )
    return write_record(
        prepared.paths.preflight_outcome(
            call.model.model_key, intent.payload["attempt_number"]
        ),
        payload,
    )


def _interrupted_preflight_outcome(
    prepared: PreparedRecovery,
    authority: Authority,
    call: PlannedCall,
    intent: JournalRecord,
) -> JournalRecord:
    payload = _preflight_outcome_payload(
        prepared,
        authority,
        intent,
        call,
        raw=None,
        result=None,
        error=_interrupted_preflight_error(),
        completed_at=utc_now(),
    )
    # Metadata GETs are idempotent and unpaid.  Generation POSTs never use this
    # recovery rule.
    return write_record(
        prepared.paths.preflight_outcome(
            call.model.model_key, intent.payload["attempt_number"]
        ),
        payload,
    )


async def _reconcile_preflight(
    prepared: PreparedRecovery,
    authority: Authority,
    call: PlannedCall,
) -> tuple[JournalRecord | None, bool]:
    """Finish captured metadata offline; return success and whether network is needed."""
    history = _preflight_history(prepared, authority, call)
    for index, (intent, raw, outcome) in enumerate(history):
        if outcome is None:
            outcome = (
                await _finalize_preflight_capture(
                    prepared, authority, call, intent, raw, secrets={}
                )
                if raw is not None
                else _interrupted_preflight_outcome(prepared, authority, call, intent)
            )
            history[index] = (intent, raw, outcome)
        result = await _validate_preflight_outcome(
            prepared, authority, call, intent, raw, outcome
        )
        if result is not None:
            if index != len(history) - 1:
                raise RecoveryExecutionError("preflight attempt follows success")
            return outcome, False
        error = outcome.payload["error"]
        if not error["retryable"]:
            if index != len(history) - 1:
                raise RecoveryExecutionError("preflight attempt follows terminal error")
            raise RecoveryExecutionError(
                f"fresh preflight failed for {call.model.model_key}: "
                f"{error['sanitized_summary']}"
            )
    if len(history) >= contract.PREFLIGHT_ATTEMPTS_PER_MODEL:
        raise RecoveryExecutionError(
            f"three-attempt preflight ceiling exhausted for {call.model.model_key}"
        )
    return None, True


async def _run_preflight_request(
    prepared: PreparedRecovery,
    authority: Authority,
    call: PlannedCall,
    *,
    secret: str,
    delegate: Transport,
    limiter: RateLimiter,
    secrets: Mapping[str, str],
) -> JournalRecord:
    history = _preflight_history(prepared, authority, call)
    attempt = len(history) + 1
    if attempt > contract.PREFLIGHT_ATTEMPTS_PER_MODEL:
        raise RecoveryExecutionError("preflight request ceiling exceeded")
    intent = write_record(
        prepared.paths.preflight_intent(call.model.model_key, attempt),
        _preflight_intent_payload(
            prepared, authority, call, attempt, created_at=utc_now()
        ),
    )
    expected_request = ProviderAdapter(
        call.model, _NeverTransport()
    ).build_metadata_request(secret)
    capture_transport = DurableCaptureTransport(
        delegate,
        capture_path=prepared.paths.preflight_raw(call.model.model_key, attempt),
        private_root=prepared.paths.private_root,
        common=_raw_common(
            prepared,
            authority,
            model_key=call.model.model_key,
            attempt=attempt,
        ),
        intent=intent,
        request_kind="preflight",
        expected_request=expected_request,
    )
    await limiter.wait()
    try:
        result = await ProviderAdapter(call.model, capture_transport).preflight(secret)
    except ProviderError as error:
        raw = capture_transport.capture
        payload = _preflight_outcome_payload(
            prepared,
            authority,
            intent,
            call,
            raw=raw,
            result=None,
            error=(
                _error_value(error, secrets, preflight=True)
                if raw is not None
                else _interrupted_preflight_error()
            ),
            completed_at=utc_now(),
        )
    else:
        raw = capture_transport.capture
        if raw is None:
            raise RecoveryExecutionError(
                "preflight returned without durable raw evidence"
            )
        payload = _preflight_outcome_payload(
            prepared,
            authority,
            intent,
            call,
            raw=raw,
            result=result,
            error=None,
            completed_at=utc_now(),
        )
    return write_record(
        prepared.paths.preflight_outcome(call.model.model_key, attempt), payload
    )


def _manifest_payload(
    prepared: PreparedRecovery,
    authority: Authority,
    parent: ParentEvidence,
    outcomes: list[JournalRecord],
    *,
    sealed_at: str,
) -> dict[str, Any]:
    require_timestamp(sealed_at, "recovery manifest time")
    for outcome in outcomes:
        _require_not_before(
            sealed_at,
            "recovery manifest time",
            outcome.payload.get("completed_at"),
            "preflight completion time",
        )
    return {
        "schema_version": MANIFEST_SCHEMA,
        "status": "complete-six-model-fresh-preflight",
        **_common(prepared, authority),
        "config_sha256": prepared.config.sha256,
        "target_plan_sha256": prepared.lock_context.lock["target_plan"]["plan_sha256"],
        "parent_manifest": {
            "path": contract.PARENT_MANIFEST_PATH,
            "sha256": parent.manifest.sha256,
        },
        "sealed_at": sealed_at,
        "preflight_outcomes": [
            {
                "model_key": model_key,
                **_record_binding(prepared, outcome),
                "provider_returned_model_id": outcome.payload[
                    "provider_returned_model_id"
                ],
            }
            for model_key, outcome in zip(
                contract.TARGET_MODEL_KEYS, outcomes, strict=True
            )
        ],
    }


async def _validate_manifest(
    prepared: PreparedRecovery,
    authority: Authority,
    parent: ParentEvidence,
    record: JournalRecord,
) -> dict[str, JournalRecord]:
    outcomes: list[JournalRecord] = []
    for call in prepared.target_plan:
        success, needs_network = await _reconcile_preflight(prepared, authority, call)
        if success is None or needs_network:
            raise RecoveryExecutionError(
                "fresh six-model recovery manifest is incomplete"
            )
        outcomes.append(success)
    expected = _manifest_payload(
        prepared,
        authority,
        parent,
        outcomes,
        sealed_at=record.payload.get("sealed_at"),
    )
    if (
        record.path.resolve() != prepared.paths.manifest.resolve()
        or record.payload != expected
    ):
        raise RecoveryExecutionError("fresh six-model recovery manifest is invalid")
    return dict(zip(contract.TARGET_MODEL_KEYS, outcomes, strict=True))


async def _ensure_manifest_offline(
    prepared: PreparedRecovery,
    authority: Authority,
    parent: ParentEvidence,
) -> tuple[JournalRecord | None, dict[str, JournalRecord], bool]:
    if prepared.paths.manifest.exists():
        manifest = read_record(prepared.paths.manifest, "recovery preflight manifest")
        outcomes = await _validate_manifest(prepared, authority, parent, manifest)
        return manifest, outcomes, False
    outcomes: list[JournalRecord] = []
    needs_network = False
    for call in prepared.target_plan:
        success, needs = await _reconcile_preflight(prepared, authority, call)
        if success is not None:
            outcomes.append(success)
        else:
            needs_network = needs_network or needs
    if len(outcomes) == len(prepared.target_plan):
        manifest = write_record(
            prepared.paths.manifest,
            _manifest_payload(
                prepared, authority, parent, outcomes, sealed_at=utc_now()
            ),
        )
        return (
            manifest,
            dict(zip(contract.TARGET_MODEL_KEYS, outcomes, strict=True)),
            False,
        )
    return None, {}, needs_network


async def _validate_generation_outcome(
    prepared: PreparedRecovery,
    authority: Authority,
    call: PlannedCall,
    preflight: JournalRecord,
    intent: JournalRecord,
    raw: JournalRecord | None,
    outcome: JournalRecord,
) -> ProviderResult | None:
    if raw is None:
        raise RecoveryExecutionError("generation outcome lacks its raw HTTP response")
    value = outcome.payload
    common = {
        "schema_version": GENERATION_OUTCOME_SCHEMA,
        **_common(prepared, authority),
        "cell_id": call.cell_id,
        "model_key": call.model.model_key,
        "model_family": call.model.family,
        "provider": call.model.provider,
        "route": call.model.route,
        "requested_model_id": call.model.requested_model_id,
        "semantic_attempt_number": intent.payload["semantic_attempt_number"],
        "question_sha256": intent.payload["question_sha256"],
        "prompt_sha256": intent.payload["prompt_sha256"],
        "messages_sha256": intent.payload["messages_sha256"],
        "requested_params_sha256": intent.payload["requested_params_sha256"],
        "manifest": intent.payload["manifest"],
        "preflight_outcome": _record_binding(prepared, preflight),
        "intent": _record_binding(prepared, intent),
        "raw_response": _record_binding(prepared, raw),
        "attempted_at": intent.payload["created_at"],
    }
    for key, expected in common.items():
        if value.get(key) != expected:
            raise RecoveryExecutionError("generation outcome lineage changed")
    require_timestamp(value.get("completed_at"), "generation completion time")
    _require_not_before(
        value.get("completed_at"),
        "generation completion time",
        intent.payload.get("created_at"),
        "generation intent time",
    )
    _require_not_before(
        value.get("completed_at"),
        "generation completion time",
        raw.payload.get("received_at"),
        "generation raw response time",
    )
    latency = value.get("latency_ms")
    if not isinstance(latency, int) or isinstance(latency, bool) or latency < 0:
        raise RecoveryExecutionError("generation latency is malformed")
    expected_path = prepared.paths.generation_outcome(
        call.model.model_key, intent.payload["semantic_attempt_number"]
    )
    if outcome.path.resolve() != expected_path.resolve():
        raise RecoveryExecutionError("generation outcome path changed")
    if value.get("status") == "success":
        try:
            result = await _parse_generation_capture(
                prepared, authority, call, intent, raw, preflight
            )
        except ProviderError as error:
            raise RecoveryExecutionError(
                "successful generation no longer parses as success"
            ) from error
        expected = _generation_outcome_payload(
            prepared,
            authority,
            intent,
            raw,
            call,
            result=result,
            error=None,
            latency_ms=latency,
            completed_at=value["completed_at"],
        )
        if value != expected:
            raise RecoveryExecutionError("successful generation outcome changed")
        return result
    if value.get("status") != "error":
        raise RecoveryExecutionError("generation outcome status is invalid")
    error_value = _validate_error_object(
        value.get("error"),
        "generation",
        allowed_retry_categories=SAFE_RETRY_CATEGORIES,
    )
    expected_keys = set(common) | {
        "status",
        "completed_at",
        "latency_ms",
        "error",
    }
    if set(value) != expected_keys:
        raise RecoveryExecutionError("generation error fields changed")
    try:
        await _parse_generation_capture(
            prepared, authority, call, intent, raw, preflight
        )
    except ProviderError as error:
        if error_value != _error_value(error, {}):
            raise RecoveryExecutionError("generation error receipt changed") from error
    else:
        raise RecoveryExecutionError("generation error now parses as success")
    return None


async def _finalize_generation_capture(
    prepared: PreparedRecovery,
    authority: Authority,
    call: PlannedCall,
    preflight: JournalRecord,
    intent: JournalRecord,
    raw: JournalRecord,
    *,
    secrets: Mapping[str, str],
    latency_ms: int,
) -> JournalRecord:
    try:
        result = await _parse_generation_capture(
            prepared, authority, call, intent, raw, preflight
        )
    except ProviderError as error:
        payload = _generation_outcome_payload(
            prepared,
            authority,
            intent,
            raw,
            call,
            result=None,
            error=_error_value(error, secrets),
            latency_ms=latency_ms,
            completed_at=utc_now(),
        )
    else:
        payload = _generation_outcome_payload(
            prepared,
            authority,
            intent,
            raw,
            call,
            result=result,
            error=None,
            latency_ms=latency_ms,
            completed_at=utc_now(),
        )
    return write_record(
        prepared.paths.generation_outcome(
            call.model.model_key, intent.payload["semantic_attempt_number"]
        ),
        payload,
    )


def _reserved_total(prepared: PreparedRecovery) -> int:
    total = 0
    intent_root = prepared.paths.private_root / "generation/intents"
    if not intent_root.exists():
        return 0
    for path in sorted(intent_root.rglob("*.json")):
        record = read_record(path, "recovery generation intent")
        reserve = record.payload.get("reserved_cost_microdollars")
        if not isinstance(reserve, int) or isinstance(reserve, bool) or reserve < 0:
            raise RecoveryExecutionError("recovery reservation is malformed")
        total += reserve
    if (
        total > contract.NEW_RESERVED_CAP_MICRODOLLARS
        or total + contract.PARENT_RESERVED_MICRODOLLARS
        > contract.COMBINED_RESERVED_CAP_MICRODOLLARS
    ):
        raise RecoveryExecutionError("recovery reserved-cost cap was exceeded")
    return total


def _validate_recovery_inventory(prepared: PreparedRecovery) -> None:
    root = prepared.paths.private_root
    try:
        root_metadata = root.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise RecoveryExecutionError(
            f"recovery journal root cannot be inspected: {error}"
        ) from error
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise RecoveryExecutionError(
            "recovery journal root must be a real private directory"
        )
    if stat.S_IMODE(root_metadata.st_mode) != 0o700:
        raise RecoveryExecutionError(
            "recovery journal directories must remain mode 0700"
        )
    allowed = {
        root / "paid-authorization.json",
        root / "pricing-evidence.json",
        root / "pricing-recheck.json",
        prepared.paths.manifest,
        prepared.paths.composite,
    }
    for model_key in contract.TARGET_MODEL_KEYS:
        for attempt in range(1, contract.PREFLIGHT_ATTEMPTS_PER_MODEL + 1):
            allowed.update(
                {
                    prepared.paths.preflight_intent(model_key, attempt),
                    prepared.paths.preflight_raw(model_key, attempt),
                    prepared.paths.preflight_outcome(model_key, attempt),
                }
            )
        for attempt in _attempt_range(model_key):
            allowed.update(
                {
                    prepared.paths.generation_intent(model_key, attempt),
                    prepared.paths.generation_raw(model_key, attempt),
                    prepared.paths.generation_outcome(model_key, attempt),
                }
            )
    allowed_directories = {root}
    for path in allowed:
        parent = path.parent
        while parent != root:
            allowed_directories.add(parent)
            parent = parent.parent
    generation_paths: list[Path] = []
    for path in root.rglob("*"):
        try:
            metadata = path.lstat()
        except OSError as error:
            raise RecoveryExecutionError(
                f"recovery journal entry cannot be inspected: {error}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode):
            raise RecoveryExecutionError("recovery journal contains a symlink")
        if stat.S_ISDIR(metadata.st_mode):
            if path not in allowed_directories:
                raise RecoveryExecutionError(
                    "recovery journal contains an unexpected directory"
                )
            if stat.S_IMODE(metadata.st_mode) != 0o700:
                raise RecoveryExecutionError(
                    "recovery journal directories must remain mode 0700"
                )
            continue
        if (
            not stat.S_ISREG(metadata.st_mode)
            or path.suffix != ".json"
            or path not in allowed
        ):
            raise RecoveryExecutionError("recovery journal contains an unexpected file")
        if stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1:
            raise RecoveryExecutionError(
                "recovery journal files must remain single-link mode 0600"
            )
        if "generation" in path.relative_to(root).parts:
            generation_paths.append(path)
    if generation_paths and not prepared.paths.manifest.exists():
        raise RecoveryExecutionError(
            "generation state requires the sealed preflight manifest"
        )
    if prepared.paths.composite.exists():
        if not prepared.paths.manifest.exists():
            raise RecoveryExecutionError(
                "composite state requires the sealed preflight manifest"
            )
        missing_models = [
            model_key
            for model_key in contract.TARGET_MODEL_KEYS
            if not any(
                prepared.paths.generation_outcome(model_key, attempt).exists()
                for attempt in _attempt_range(model_key)
            )
        ]
        if missing_models:
            raise RecoveryExecutionError(
                "composite state exists before six generation outcomes"
            )


def _generation_state_exists(prepared: PreparedRecovery, model_key: str) -> bool:
    for attempt in _attempt_range(model_key):
        if any(
            path.exists()
            for path in (
                prepared.paths.generation_intent(model_key, attempt),
                prepared.paths.generation_raw(model_key, attempt),
                prepared.paths.generation_outcome(model_key, attempt),
            )
        ):
            return True
    return False


def _reserve_generation_intent(
    prepared: PreparedRecovery,
    authority: Authority,
    parent: ParentEvidence,
    manifest: JournalRecord,
    preflight: JournalRecord,
    call: PlannedCall,
    attempt: int,
) -> JournalRecord:
    current = _reserved_total(prepared)
    reserve = reserved_microdollars(call)
    if (
        current + reserve > contract.NEW_RESERVED_CAP_MICRODOLLARS
        or contract.PARENT_RESERVED_MICRODOLLARS + current + reserve
        > contract.COMBINED_RESERVED_CAP_MICRODOLLARS
    ):
        raise RecoveryExecutionError(
            "no request sent: recovery reservation cap exceeded"
        )
    return write_record(
        prepared.paths.generation_intent(call.model.model_key, attempt),
        _generation_intent_payload(
            prepared,
            authority,
            parent,
            manifest,
            preflight,
            call,
            attempt,
            created_at=utc_now(),
        ),
    )


async def _reconcile_generation(
    prepared: PreparedRecovery,
    authority: Authority,
    parent: ParentEvidence,
    manifest: JournalRecord,
    preflight: JournalRecord,
    call: PlannedCall,
) -> tuple[JournalRecord | None, bool, str | None]:
    """Finish captured POSTs offline and report success/network/terminal reason."""
    history = _generation_history(
        prepared, authority, parent, manifest, preflight, call
    )
    for index, (intent, raw, outcome) in enumerate(history):
        if outcome is None:
            if raw is None:
                raise StrandedGenerationIntent(
                    f"stranded recovery intent; no replay allowed: {call.cell_id}"
                )
            outcome = await _finalize_generation_capture(
                prepared,
                authority,
                call,
                preflight,
                intent,
                raw,
                secrets={},
                latency_ms=0,
            )
            history[index] = (intent, raw, outcome)
        result = await _validate_generation_outcome(
            prepared, authority, call, preflight, intent, raw, outcome
        )
        if result is not None:
            if index != len(history) - 1:
                raise RecoveryExecutionError("generation attempt follows success")
            return outcome, False, None
        error = outcome.payload["error"]
        if call.model.model_key == "cohere":
            if index != len(history) - 1:
                raise RecoveryExecutionError("Cohere replacement was replayed")
            return None, False, "Cohere replacement exhausted; no replay allowed"
        if not error["retryable"]:
            if index != len(history) - 1:
                raise RecoveryExecutionError(
                    "generation attempt follows terminal error"
                )
            return None, False, error["sanitized_summary"]
    if len(history) >= len(_attempt_range(call.model.model_key)):
        return None, False, f"safe attempt ceiling exhausted for {call.cell_id}"
    return None, True, None


async def _run_generation_request(
    prepared: PreparedRecovery,
    authority: Authority,
    parent: ParentEvidence,
    manifest: JournalRecord,
    preflight: JournalRecord,
    call: PlannedCall,
    *,
    secret: str,
    delegate: Transport,
    limiter: RateLimiter,
    secrets: Mapping[str, str],
) -> JournalRecord:
    history = _generation_history(
        prepared, authority, parent, manifest, preflight, call
    )
    attempts = _attempt_range(call.model.model_key)
    attempt = attempts[len(history)] if len(history) < len(attempts) else None
    if attempt is None:
        raise RecoveryExecutionError("generation POST ceiling exceeded")
    intent = _reserve_generation_intent(
        prepared,
        authority,
        parent,
        manifest,
        preflight,
        call,
        attempt,
    )
    messages = call.answer_messages()
    expected_request = ProviderAdapter(
        call.model, _NeverTransport()
    ).build_generation_request(secret, messages)
    capture_transport = DurableCaptureTransport(
        delegate,
        capture_path=prepared.paths.generation_raw(call.model.model_key, attempt),
        private_root=prepared.paths.private_root,
        common=_raw_common(
            prepared,
            authority,
            model_key=call.model.model_key,
            attempt=attempt,
        ),
        intent=intent,
        request_kind="generation",
        expected_request=expected_request,
    )
    await limiter.wait()
    started = time.monotonic()
    try:
        result = await ProviderAdapter(call.model, capture_transport).generate(
            secret, messages
        )
        raw = capture_transport.capture
        if raw is None:
            raise RecoveryExecutionError(
                "generation returned without durable raw evidence"
            )
        # Run the successor identity rule against the durable bytes, including
        # Cohere's documented omission of a generation-level model field.
        result = await _parse_generation_capture(
            prepared, authority, call, intent, raw, preflight
        )
    except ProviderError as error:
        raw = capture_transport.capture
        if raw is None:
            # The POST may have reached the provider.  Do not create a receipt
            # that could make it appear safe to replay.
            raise StrandedGenerationIntent(
                f"stranded recovery intent; no replay allowed: {call.cell_id}"
            ) from error
        payload = _generation_outcome_payload(
            prepared,
            authority,
            intent,
            raw,
            call,
            result=None,
            error=_error_value(error, secrets),
            latency_ms=int((time.monotonic() - started) * 1000),
            completed_at=utc_now(),
        )
    else:
        payload = _generation_outcome_payload(
            prepared,
            authority,
            intent,
            raw,
            call,
            result=result,
            error=None,
            latency_ms=int((time.monotonic() - started) * 1000),
            completed_at=utc_now(),
        )
    return write_record(
        prepared.paths.generation_outcome(call.model.model_key, attempt), payload
    )


def _composite_payload(
    prepared: PreparedRecovery,
    authority: Authority,
    parent: ParentEvidence,
    manifest: JournalRecord,
    recovery_outcomes: list[JournalRecord],
    *,
    sealed_at: str,
) -> dict[str, Any]:
    require_timestamp(sealed_at, "composite receipt time")
    if (
        tuple(outcome.payload.get("model_key") for outcome in recovery_outcomes)
        != contract.TARGET_MODEL_KEYS
    ):
        raise RecoveryExecutionError(
            "recovery outcomes are not in the locked generation order"
        )
    _require_not_before(
        sealed_at,
        "composite receipt time",
        manifest.payload.get("sealed_at"),
        "recovery manifest time",
    )
    for outcome in recovery_outcomes:
        _require_not_before(
            sealed_at,
            "composite receipt time",
            outcome.payload.get("completed_at"),
            "generation completion time",
        )
    for previous, current in zip(
        recovery_outcomes, recovery_outcomes[1:], strict=False
    ):
        _require_not_before(
            current.payload.get("attempted_at"),
            "generation intent time",
            previous.payload.get("completed_at"),
            "previous model generation completion time",
        )
    parent_by_key = {
        item.payload["model_key"]: item for item in parent.preserved_outcomes
    }
    recovery_by_key = {item.payload["model_key"]: item for item in recovery_outcomes}
    cells: list[dict[str, Any]] = []
    for model_key in contract.MODEL_ORDER:
        if model_key in parent_by_key:
            outcome = parent_by_key[model_key]
            cells.append(
                {
                    "model_key": model_key,
                    "source_lane": "immutable-parent",
                    "path": contract.PARENT_GENERATION_OUTCOME_PATHS[
                        contract.PRESERVED_MODEL_KEYS.index(model_key)
                    ],
                    "sha256": outcome.sha256,
                    "semantic_attempt_number": 1,
                }
            )
        else:
            outcome = recovery_by_key[model_key]
            cells.append(
                {
                    "model_key": model_key,
                    "source_lane": "successor-recovery",
                    **_record_binding(prepared, outcome),
                    "semantic_attempt_number": outcome.payload[
                        "semantic_attempt_number"
                    ],
                    "raw_response": outcome.payload["raw_response"],
                    "intent": outcome.payload["intent"],
                }
            )
    new_reserved = _reserved_total(prepared)
    return {
        "schema_version": COMPOSITE_SCHEMA,
        "status": "complete-eight-successes-two-parent-six-recovery",
        **_common(prepared, authority),
        "sealed_at": sealed_at,
        "question_sha256": prepared.question.sha256,
        "parent_plan_sha256": contract.PARENT_PLAN_SHA256,
        "recovery_manifest": _record_binding(prepared, manifest),
        "parent_stranded_cohere_intent": {
            "path": contract.STRANDED_COHERE["intent_path"],
            "sha256": parent.stranded_intent.sha256,
            "disposition": contract.STRANDED_COHERE["disposition"],
        },
        "successful_outcome_count": 8,
        "outcomes": cells,
        "budget": {
            "parent_reserved_microdollars": parent.reserved_microdollars,
            "new_reserved_microdollars": new_reserved,
            "combined_reserved_microdollars": parent.reserved_microdollars
            + new_reserved,
            "new_reserved_cap_microdollars": contract.NEW_RESERVED_CAP_MICRODOLLARS,
            "combined_reserved_cap_microdollars": (
                contract.COMBINED_RESERVED_CAP_MICRODOLLARS
            ),
        },
    }


async def _validate_or_publish_composite(
    prepared: PreparedRecovery,
    authority: Authority,
    parent: ParentEvidence,
    manifest: JournalRecord,
    preflight_by_key: dict[str, JournalRecord],
) -> tuple[JournalRecord | None, bool, str | None]:
    successes: list[JournalRecord] = []
    stopped = False
    previous_success: JournalRecord | None = None
    for index, call in enumerate(prepared.target_plan):
        success, needs_network, reason = await _reconcile_generation(
            prepared,
            authority,
            parent,
            manifest,
            preflight_by_key[call.model.model_key],
            call,
        )
        if stopped and (success is not None or needs_network):
            raise RecoveryExecutionError(
                "recovery journal violates sequential execution"
            )
        if success is not None:
            if previous_success is not None:
                _require_not_before(
                    success.payload.get("attempted_at"),
                    "generation intent time",
                    previous_success.payload.get("completed_at"),
                    "previous model generation completion time",
                )
            successes.append(success)
            previous_success = success
            continue
        if reason is not None:
            stopped = True
            if any(
                _generation_state_exists(prepared, later.model.model_key)
                for later in prepared.target_plan[index + 1 :]
            ):
                raise RecoveryExecutionError(
                    "recovery journal violates sequential execution"
                )
            return None, False, reason
        if needs_network:
            if any(
                _generation_state_exists(prepared, later.model.model_key)
                for later in prepared.target_plan[index + 1 :]
            ):
                raise RecoveryExecutionError(
                    "recovery journal violates sequential execution"
                )
            break
    if len(successes) != len(contract.TARGET_MODEL_KEYS):
        return None, True, None
    if prepared.paths.composite.exists():
        record = read_record(prepared.paths.composite, "recovery composite receipt")
        expected = _composite_payload(
            prepared,
            authority,
            parent,
            manifest,
            successes,
            sealed_at=record.payload.get("sealed_at"),
        )
        if record.payload != expected:
            raise RecoveryExecutionError("recovery composite receipt changed")
        return record, False, None
    return (
        write_record(
            prepared.paths.composite,
            _composite_payload(
                prepared,
                authority,
                parent,
                manifest,
                successes,
                sealed_at=utc_now(),
            ),
        ),
        False,
        None,
    )


async def _complete_preflights(
    prepared: PreparedRecovery,
    authority: Authority,
    parent: ParentEvidence,
    *,
    secrets: Mapping[str, str],
    transport: Transport,
    limiters: Mapping[str, RateLimiter],
    sleep: Callable[[float], Awaitable[None]],
) -> tuple[JournalRecord, dict[str, JournalRecord], int]:
    requests = 0
    successes: list[JournalRecord] = []
    for call in prepared.target_plan:
        while True:
            success, needs_network = await _reconcile_preflight(
                prepared, authority, call
            )
            if success is not None:
                successes.append(success)
                break
            if not needs_network:
                raise RecoveryExecutionError(
                    f"fresh preflight is terminal for {call.model.model_key}"
                )
            outcome = await _run_preflight_request(
                prepared,
                authority,
                call,
                secret=secrets[call.model.environment_variable],
                delegate=transport,
                limiter=limiters[call.model.model_key],
                secrets=secrets,
            )
            requests += 1
            if outcome.payload["status"] == "error":
                if not outcome.payload["error"]["retryable"]:
                    raise RecoveryExecutionError(
                        f"fresh preflight failed for {call.model.model_key}: "
                        + outcome.payload["error"]["sanitized_summary"]
                    )
                attempt = outcome.payload["attempt_number"]
                if attempt >= contract.PREFLIGHT_ATTEMPTS_PER_MODEL:
                    raise RecoveryExecutionError(
                        f"three-attempt preflight ceiling exhausted for "
                        f"{call.model.model_key}"
                    )
                await sleep(0.5 * (2 ** (attempt - 1)))
    if requests > contract.MAX_PREFLIGHT_REQUESTS:
        raise RecoveryExecutionError("preflight request ceiling exceeded")
    manifest = write_record(
        prepared.paths.manifest,
        _manifest_payload(prepared, authority, parent, successes, sealed_at=utc_now()),
    )
    return (
        manifest,
        dict(zip(contract.TARGET_MODEL_KEYS, successes, strict=True)),
        requests,
    )


async def _complete_generations(
    prepared: PreparedRecovery,
    authority: Authority,
    parent: ParentEvidence,
    manifest: JournalRecord,
    preflight_by_key: dict[str, JournalRecord],
    *,
    secrets: Mapping[str, str],
    transport: Transport,
    limiters: Mapping[str, RateLimiter],
    sleep: Callable[[float], Awaitable[None]],
) -> tuple[JournalRecord | None, int, str | None]:
    requests = 0
    for call in prepared.target_plan:
        while True:
            success, needs_network, reason = await _reconcile_generation(
                prepared,
                authority,
                parent,
                manifest,
                preflight_by_key[call.model.model_key],
                call,
            )
            if success is not None:
                break
            if reason is not None:
                return None, requests, reason
            if not needs_network:
                return None, requests, f"recovery stopped at {call.cell_id}"
            outcome = await _run_generation_request(
                prepared,
                authority,
                parent,
                manifest,
                preflight_by_key[call.model.model_key],
                call,
                secret=secrets[call.model.environment_variable],
                delegate=transport,
                limiter=limiters[call.model.model_key],
                secrets=secrets,
            )
            requests += 1
            if requests > contract.MAX_GENERATION_POSTS:
                raise RecoveryExecutionError("generation POST ceiling exceeded")
            if outcome.payload["status"] == "error":
                error = outcome.payload["error"]
                if call.model.model_key == "cohere":
                    return (
                        None,
                        requests,
                        "Cohere replacement exhausted; no replay allowed",
                    )
                if not error["retryable"]:
                    return None, requests, error["sanitized_summary"]
                attempt = outcome.payload["semantic_attempt_number"]
                if attempt >= contract.MAX_UNTOUCHED_GENERATION_ATTEMPTS:
                    return (
                        None,
                        requests,
                        f"safe attempt ceiling exhausted for {call.cell_id}",
                    )
                await sleep(0.5 * (2 ** (attempt - 1)))
    composite, _, reason = await _validate_or_publish_composite(
        prepared, authority, parent, manifest, preflight_by_key
    )
    if composite is None:
        raise RecoveryExecutionError(
            reason
            or "six successful recovery outcomes did not produce a composite receipt"
        )
    return composite, requests, None


def _same_prepared(left: PreparedRecovery, right: PreparedRecovery) -> bool:
    return (
        left.repository_root == right.repository_root
        and left.lock_context.lock == right.lock_context.lock
        and left.lock_context.lock_sha256 == right.lock_context.lock_sha256
        and left.config == right.config
        and left.question == right.question
        and left.full_plan == right.full_plan
        and left.target_plan == right.target_plan
        and left.paths == right.paths
    )


async def _execute_under_lock(
    prepared: PreparedRecovery,
    *,
    environment: Mapping[str, str],
    transport_factory: Callable[[], Transport],
    sleep: Callable[[float], Awaitable[None]],
) -> RecoveryResult:
    fresh = prepare_recovery(prepared.repository_root, require_committed=True)
    if not _same_prepared(prepared, fresh):
        raise RecoveryExecutionError(
            "recovery lock, plan, or source bytes changed before execution"
        )
    parent = validate_parent_evidence(fresh.repository_root, fresh.lock_context.lock)
    _validate_recovery_inventory(fresh)

    # Existing durable state may be completed offline even after the pricing
    # freshness window.  No target credential is read on this path.
    stale_base_authority = _authority(fresh, fresh=False)
    claim = _ensure_claim(fresh, stale_base_authority, parent)
    stale_authority = _authority_with_claim(fresh, stale_base_authority, claim)
    manifest, preflight_by_key, needs_preflight = await _ensure_manifest_offline(
        fresh, stale_authority, parent
    )
    if manifest is not None:
        (
            composite,
            needs_generation,
            terminal_reason,
        ) = await _validate_or_publish_composite(
            fresh,
            stale_authority,
            parent,
            manifest,
            preflight_by_key,
        )
        if composite is not None:
            return RecoveryResult(
                composite.path,
                composite.payload,
                composite.sha256,
                network_requests=0,
            )
        if terminal_reason is not None:
            return RecoveryResult(
                path=fresh.paths.private_root,
                payload={
                    "status": "terminal-recovery-incomplete",
                    "stopped_reason": terminal_reason,
                },
                sha256="",
                network_requests=0,
            )
        if not needs_generation:
            raise RecoveryExecutionError("recovery journal cannot advance")

    # Any outbound request requires a fresh price gate revalidated under the
    # cross-recovery phase lock.
    fresh_base_authority = _authority(fresh, fresh=True)
    if fresh_base_authority != stale_base_authority:
        raise RecoveryExecutionError("recovery authority changed under execution lock")
    authority = _authority_with_claim(fresh, fresh_base_authority, claim)
    secrets = _collect_target_secrets(fresh, environment)
    transport = transport_factory()
    limiters = {
        call.model.model_key: RateLimiter(call.model.requests_per_second)
        for call in fresh.target_plan
    }
    network_requests = 0
    if manifest is None:
        if not needs_preflight:
            raise RecoveryExecutionError("fresh preflight state cannot advance")
        manifest, preflight_by_key, count = await _complete_preflights(
            fresh,
            authority,
            parent,
            secrets=secrets,
            transport=transport,
            limiters=limiters,
            sleep=sleep,
        )
        network_requests += count
    composite, count, stopped_reason = await _complete_generations(
        fresh,
        authority,
        parent,
        manifest,
        preflight_by_key,
        secrets=secrets,
        transport=transport,
        limiters=limiters,
        sleep=sleep,
    )
    network_requests += count
    if network_requests > contract.MAX_OUTBOUND_REQUESTS:
        raise RecoveryExecutionError("recovery outbound request ceiling exceeded")
    if composite is None:
        return RecoveryResult(
            path=fresh.paths.private_root,
            payload={
                "status": "terminal-recovery-incomplete",
                "stopped_reason": stopped_reason,
            },
            sha256="",
            network_requests=network_requests,
        )
    return RecoveryResult(
        composite.path,
        composite.payload,
        composite.sha256,
        network_requests=network_requests,
    )


async def _execute_prepared(
    prepared: PreparedRecovery,
    *,
    environment: Mapping[str, str],
    transport_factory: Callable[[], Transport],
    sleep: Callable[[float], Awaitable[None]],
) -> RecoveryResult:
    if prepared.lock_context.git_head is None:
        raise RecoveryExecutionError(
            "live recovery requires a committed successor lock"
        )
    # Parent evidence is checked before even creating the cross-recovery lock.
    validate_parent_evidence(prepared.repository_root, prepared.lock_context.lock)
    async with phase_lock(prepared.paths.phase_lock):
        return await _execute_under_lock(
            prepared,
            environment=environment,
            transport_factory=transport_factory,
            sleep=sleep,
        )


async def execute_prepared(prepared: PreparedRecovery) -> RecoveryResult:
    """Execute with the committed lock, process environment, and real transport."""
    return await _execute_prepared(
        prepared,
        environment=os.environ,
        transport_factory=UrllibTransport,
        sleep=asyncio.sleep,
    )


def load_live_recovery(repository_root: Path) -> PreparedRecovery:
    return prepare_recovery(repository_root, require_committed=True)


__all__ = (
    "PreparedRecovery",
    "RecoveryExecutionError",
    "RecoveryResult",
    "dry_run_summary",
    "execute_prepared",
    "load_live_recovery",
    "prepare_recovery",
)
