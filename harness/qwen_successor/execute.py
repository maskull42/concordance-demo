"""Execute the five-model Qwen successor without replaying stranded POSTs."""

from __future__ import annotations

import asyncio
import json
import os
import stat
import time
from dataclasses import dataclass, replace
from decimal import Decimal, ROUND_CEILING
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping

from concordance_harness.execution import RateLimiter, billed_output_tokens
from concordance_harness.planner import PlannedCall
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
from concordance_recovery import execute as first_execute
from concordance_recovery.journal import (
    StrandedGenerationIntent,
    binding,
    read_record,
    require_timestamp,
    write_record,
)
from concordance_recovery.transport import (
    CapturedReplayTransport,
    DurableCaptureTransport,
)
from rule3.execute import reserved_microdollars

from . import contract
from .authorization import (
    ReceiptBinding,
    validate_authorization,
    validate_pricing_recheck,
)
from .lock import LockContext, load_lock
from .parent import ParentEvidence, validate_parent_snapshot
from .state import SuccessorPaths, phase_lock
from concordance_recovery.state import phase_lock as first_phase_lock


PREFLIGHT_INTENT_SCHEMA = "concordance-qwen-successor-preflight-intent-1.0.0"
PREFLIGHT_OUTCOME_SCHEMA = "concordance-qwen-successor-preflight-outcome-1.0.0"
GENERATION_INTENT_SCHEMA = "concordance-qwen-successor-generation-intent-1.0.0"
GENERATION_OUTCOME_SCHEMA = "concordance-qwen-successor-generation-outcome-1.0.0"
MANIFEST_SCHEMA = "concordance-qwen-successor-manifest-1.0.0"
CLAIM_SCHEMA = "concordance-qwen-successor-claim-1.0.0"
COMPOSITE_SCHEMA = "concordance-qwen-successor-composite-1.0.0"
SAFE_RETRY_CATEGORIES = {"invalid-request", "provider-error", "rate-limit"}
PREFLIGHT_RETRY_CATEGORIES = SAFE_RETRY_CATEGORIES | {
    "metadata-interrupted",
    "network",
    "timeout",
}


class SuccessorExecutionError(RuntimeError):
    pass


@dataclass(frozen=True)
class PreparedSuccessor:
    repository_root: Path
    lock_context: LockContext
    first_prepared: first_execute.PreparedRecovery
    target_plan: tuple[PlannedCall, ...]
    target_by_key: dict[str, PlannedCall]
    fallback_call: PlannedCall
    preflight_plan: tuple[PlannedCall, ...]
    paths: SuccessorPaths

    @property
    def config(self) -> Any:
        return self.first_prepared.config

    @property
    def question(self) -> Any:
        return self.first_prepared.question


@dataclass(frozen=True)
class Authority:
    authorization: ReceiptBinding
    pricing: ReceiptBinding
    claim: Any | None = None


@dataclass(frozen=True)
class SuccessorResult:
    path: Path
    payload: dict[str, Any]
    sha256: str
    network_requests: int


class _NeverTransport:
    async def send(self, request: Any) -> Any:
        del request
        raise SuccessorExecutionError("offline request builder attempted network")


class _SuccessorAdapter(ProviderAdapter):
    def assert_model_identity(self, returned: str) -> None:
        if self.config.route == contract.QWEN_OPENROUTER["route"]:
            if returned not in contract.QWEN_OPENROUTER["accepted_returned_model_ids"]:
                raise ProviderError(
                    "OpenRouter Qwen returned an unapproved model identifier",
                    category="response-validation",
                    retryable=False,
                )
            return
        super().assert_model_identity(returned)


def _route_key(call: PlannedCall) -> str:
    return (
        "qwen-openrouter"
        if call.model.route == contract.QWEN_OPENROUTER["route"]
        else call.model.model_key
    )


def _attempt_range(model_key: str) -> tuple[int, ...]:
    return (2, 3) if model_key == "qwen" else (1, 2, 3)


def prepare_successor(
    repository_root: Path | str, *, require_committed: bool
) -> PreparedSuccessor:
    root = Path(repository_root).resolve()
    context = load_lock(
        root,
        require_committed=require_committed,
        require_parent_private=require_committed,
    )
    first = first_execute.prepare_recovery(root, require_committed=require_committed)
    target = tuple(
        call
        for call in first.full_plan
        if call.model.model_key in contract.TARGET_MODEL_KEYS
    )
    if tuple(call.model.model_key for call in target) != contract.TARGET_MODEL_KEYS:
        raise SuccessorExecutionError("successor target plan order changed")
    locked = context.lock.get("target_plan")
    cells = locked.get("cells") if isinstance(locked, dict) else None
    if (
        not isinstance(cells, list)
        or len(cells) != len(target)
        or locked.get("qwen_openrouter_fallback") != contract.QWEN_OPENROUTER
    ):
        raise SuccessorExecutionError("locked successor target plan is malformed")
    for call, cell in zip(target, cells, strict=True):
        key = call.model.model_key
        if (
            cell.get("model_key") != key
            or cell.get("cell_id") != call.cell_id
            or cell.get("requested_model_id") != call.model.requested_model_id
            or cell.get("provider") != call.model.provider
            or cell.get("route") != call.model.route
            or cell.get("environment_variable") != call.model.environment_variable
            or cell.get("fallback_allowed") is not False
            or cell.get("reserved_cost_microdollars_per_post")
            != reserved_microdollars(call)
            or call.model.output_cap != contract.OUTPUT_TOKEN_CAP
        ):
            raise SuccessorExecutionError(f"locked successor cell changed for {key}")
    qwen = target[0].model
    if (
        qwen.provider != "deepinfra"
        or qwen.route != "deepinfra"
        or qwen.requested_model_id != "Qwen/Qwen3.5-397B-A17B"
    ):
        raise SuccessorExecutionError("Qwen DeepInfra selection changed")
    fallback_model = replace(
        qwen,
        provider=contract.QWEN_OPENROUTER["provider"],
        requested_model_id=contract.QWEN_OPENROUTER["requested_model_id"],
        route=contract.QWEN_OPENROUTER["route"],
        environment_variable=contract.QWEN_OPENROUTER["environment_variable"],
        api_style=contract.QWEN_OPENROUTER["api_style"],
        base_url=contract.QWEN_OPENROUTER["base_url"],
        generation_path=contract.QWEN_OPENROUTER["generation_path"],
        metadata_path=contract.QWEN_OPENROUTER["metadata_path"],
        metadata_mode=contract.QWEN_OPENROUTER["metadata_mode"],
        auth_kind=contract.QWEN_OPENROUTER["auth_kind"],
        fallback_allowed=True,
        provider_options=contract.QWEN_OPENROUTER["provider_options"],
        planning_pricing={
            "currency": "USD",
            **contract.QWEN_OPENROUTER["reservation_pricing"],
            "pricing_as_of": contract.QWEN_OPENROUTER["pricing_as_of"],
            "review_status": "author-verified",
        },
    )
    fallback_call = replace(target[0], model=fallback_model)
    preflight_plan = (target[0], fallback_call, *target[1:])
    return PreparedSuccessor(
        repository_root=root,
        lock_context=context,
        first_prepared=first,
        target_plan=target,
        target_by_key={call.model.model_key: call for call in target},
        fallback_call=fallback_call,
        preflight_plan=preflight_plan,
        paths=SuccessorPaths.for_repository(root),
    )


def dry_run_summary(prepared: PreparedSuccessor) -> dict[str, Any]:
    return {
        "recovery_id": contract.RECOVERY_ID,
        "candidate_id": contract.CANDIDATE_ID,
        "preserved_model_keys": list(contract.PRESERVED_MODEL_KEYS),
        "target_model_keys": list(contract.TARGET_MODEL_KEYS),
        "qwen_semantic_attempt_number": 2,
        "qwen_maximum_replacement_posts": 1,
        "qwen_openrouter_fallback_posts": 1,
        "fresh_preflight_route_keys": list(contract.PREFLIGHT_ROUTE_KEYS),
        "maximum_preflight_requests": contract.MAX_PREFLIGHT_REQUESTS,
        "maximum_generation_posts": contract.MAX_GENERATION_POSTS,
        "maximum_outbound_requests": contract.MAX_OUTBOUND_REQUESTS,
        "network_requests": 0,
        "environment_variables_read": 0,
    }


def _authority(prepared: PreparedSuccessor, *, fresh: bool) -> Authority:
    return Authority(
        validate_authorization(prepared.lock_context),
        validate_pricing_recheck(prepared.lock_context, require_fresh=fresh),
    )


def _common(prepared: PreparedSuccessor, authority: Authority) -> dict[str, Any]:
    head = prepared.lock_context.git_head
    if not isinstance(head, str):
        raise SuccessorExecutionError("live successor lacks a committed Git HEAD")
    result = {
        "recovery_id": contract.RECOVERY_ID,
        "pool_id": contract.POOL_ID,
        "candidate_id": contract.CANDIDATE_ID,
        "phase": contract.PHASE,
        "git_head": head,
        "successor_lock_sha256": prepared.lock_context.lock_sha256,
        "authorization_receipt_sha256": authority.authorization.sha256,
        "pricing_recheck_receipt_sha256": authority.pricing.sha256,
        "first_recovery_lock_sha256": contract.FIRST_LOCK_SHA256,
        "rule3_lock_sha256": contract.RULE3_LOCK_SHA256,
    }
    if authority.claim is not None:
        result["qwen_parent_claim"] = binding(
            prepared.repository_root, authority.claim
        ).value()
    return result


def _claim_payload(
    prepared: PreparedSuccessor,
    authority: Authority,
    parent: ParentEvidence,
    *,
    claimed_at: str,
) -> dict[str, Any]:
    require_timestamp(claimed_at, "Qwen successor claim time")
    return {
        "schema_version": CLAIM_SCHEMA,
        "status": "stranded-qwen-intent-claimed-once",
        **_common(prepared, authority),
        "first_recovery_claim": {
            "path": contract.FIRST_CLAIM_PATH,
            "sha256": parent.first_claim.sha256,
        },
        "stranded_qwen_intent": {
            "path": contract.QWEN_STRANDED_INTENT_PATH,
            "sha256": parent.stranded_qwen_intent.sha256,
            "disposition": "consumed-possibly-delivered-possibly-billed-one-replacement",
        },
        "replacement_semantic_attempt_number": 2,
        "claimed_at": claimed_at,
    }


def _ensure_claim(
    prepared: PreparedSuccessor, authority: Authority, parent: ParentEvidence
) -> Any:
    path = prepared.paths.claim
    if path.exists():
        record = read_record(path, "Qwen successor parent claim")
        expected = _claim_payload(
            prepared,
            authority,
            parent,
            claimed_at=record.payload.get("claimed_at"),
        )
        if record.payload != expected:
            raise SuccessorExecutionError("Qwen parent claim changed")
        return record
    allowed = {
        prepared.paths.private_root / "paid-authorization.json",
        prepared.paths.private_root / "pricing-evidence.json",
        prepared.paths.private_root / "pricing-recheck.json",
    }
    if prepared.paths.private_root.exists() and any(
        item.is_file() and item.resolve() not in {path.resolve() for path in allowed}
        for item in prepared.paths.private_root.rglob("*")
    ):
        raise SuccessorExecutionError("successor state cannot precede its Qwen claim")
    return write_record(
        path, _claim_payload(prepared, authority, parent, claimed_at=utc_now())
    )


def _with_claim(authority: Authority, claim: Any) -> Authority:
    return Authority(authority.authorization, authority.pricing, claim)


def _record_binding(prepared: PreparedSuccessor, record: Any) -> dict[str, str]:
    return binding(prepared.paths.private_root, record).value()


def _safe_origin(request: Any) -> str:
    from concordance_recovery.journal import request_origin

    return request_origin(request)


def _raw_common(
    prepared: PreparedSuccessor, authority: Authority, model_key: str, attempt: int
) -> dict[str, Any]:
    return {
        **_common(prepared, authority),
        "model_key": model_key,
        "semantic_attempt_number": attempt,
    }


def _preflight_intent_payload(
    prepared: PreparedSuccessor,
    authority: Authority,
    call: PlannedCall,
    attempt: int,
    *,
    created_at: str,
) -> dict[str, Any]:
    require_timestamp(created_at, "successor preflight intent time")
    request = _SuccessorAdapter(call.model, _NeverTransport()).build_metadata_request(
        "redacted-offline-secret"
    )
    return {
        "schema_version": PREFLIGHT_INTENT_SCHEMA,
        "status": "reserved-before-metadata-get",
        **_common(prepared, authority),
        "route_key": _route_key(call),
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
    prepared: PreparedSuccessor,
    authority: Authority,
    parent: ParentEvidence,
    manifest: Any,
    preflight: Any,
    call: PlannedCall,
    attempt: int,
    *,
    created_at: str,
) -> dict[str, Any]:
    require_timestamp(created_at, "successor generation intent time")
    messages = call.answer_messages()
    request = _SuccessorAdapter(call.model, _NeverTransport()).build_generation_request(
        "redacted-offline-secret", messages
    )
    replacement = None
    if call.model.model_key == "qwen" and attempt == 2:
        replacement = {
            "path": contract.QWEN_STRANDED_INTENT_PATH,
            "sha256": parent.stranded_qwen_intent.sha256,
            "disposition": "consumed-possibly-delivered-possibly-billed-one-replacement",
        }
    elif call.model.model_key == "qwen" and attempt == 3:
        prior_intent = read_record(
            prepared.paths.generation_intent("qwen", 2),
            "DeepInfra Qwen successor intent",
        )
        prior_outcome = read_record(
            prepared.paths.generation_outcome("qwen", 2),
            "DeepInfra Qwen successor disposition",
        )
        prior_status = prior_outcome.payload.get("status")
        if prior_status == "success":
            raise SuccessorExecutionError(
                "DeepInfra Qwen attempt 2 succeeded; OpenRouter fallback is forbidden"
            )
        if prior_status not in {"error", "consumed-without-capture"}:
            raise SuccessorExecutionError(
                "DeepInfra Qwen attempt 2 lacks an authorized non-success "
                "disposition"
            )
        replacement = {
            "path": prior_intent.path.relative_to(
                prepared.paths.private_root
            ).as_posix(),
            "sha256": prior_intent.sha256,
            "outcome": _record_binding(prepared, prior_outcome),
            "disposition": "deepinfra-nonsuccess-authorized-one-openrouter-fallback",
        }
    request_hash = sha256_bytes(
        json.dumps(request.json_body, ensure_ascii=False).encode("utf-8")
    )
    if call.model.model_key == "qwen" and attempt == 2:
        parent_value = parent.stranded_qwen_intent.payload
        exact_fields = {
            "prompt_sha256": prompt_sha256(messages),
            "messages_sha256": sha256_bytes(canonical_json_bytes(messages)),
            "requested_params_sha256": sha256_bytes(
                canonical_json_bytes(call.model.requested_params_receipt())
            ),
            "request_json_body_sha256": request_hash,
        }
        if any(parent_value.get(key) != value for key, value in exact_fields.items()):
            raise SuccessorExecutionError(
                "DeepInfra Qwen attempt 2 differs from the stranded request"
            )
    return {
        "schema_version": GENERATION_INTENT_SCHEMA,
        "status": "reserved-before-generation-post",
        **_common(prepared, authority),
        "cell_id": call.cell_id,
        "model_key": call.model.model_key,
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
        "request_json_body_sha256": request_hash,
        "manifest": _record_binding(prepared, manifest),
        "preflight_outcome": _record_binding(prepared, preflight),
        "replacement_of_parent_intent": replacement,
        "created_at": created_at,
    }


def _error(error: ProviderError, *, preflight: bool) -> dict[str, Any]:
    allowed = PREFLIGHT_RETRY_CATEGORIES if preflight else SAFE_RETRY_CATEGORIES
    return {
        "category": error.category,
        "retryable": error.retryable and error.category in allowed,
        "sanitized_summary": (
            f"{'metadata' if preflight else 'generation'} request failed "
            f"({error.category})"
        ),
    }


def _interrupted_preflight_error() -> dict[str, Any]:
    return {
        "category": "metadata-interrupted",
        "retryable": True,
        "sanitized_summary": "metadata GET ended without a durable HTTP response",
    }


async def _parse_preflight(
    prepared: PreparedSuccessor,
    authority: Authority,
    call: PlannedCall,
    intent: Any,
    raw: Any,
) -> PreflightResult:
    request = _SuccessorAdapter(call.model, _NeverTransport()).build_metadata_request(
        "redacted-offline-secret"
    )
    replay = CapturedReplayTransport(
        raw,
        private_root=prepared.paths.private_root,
        common=_raw_common(
            prepared, authority, _route_key(call), intent.payload["attempt_number"]
        ),
        intent=intent,
        request_kind="preflight",
        expected_request=request,
    )
    return await _adapter_preflight(call, replay, "redacted-offline-secret")


def _per_million(value: Any) -> Decimal:
    try:
        parsed = Decimal(str(value))
    except Exception as error:
        raise ProviderError(
            "OpenRouter endpoint pricing is malformed",
            category="response-validation",
            retryable=False,
        ) from error
    return parsed * Decimal(1_000_000) if parsed < Decimal("0.01") else parsed


async def _adapter_preflight(
    call: PlannedCall, transport: Transport, secret: str
) -> PreflightResult:
    adapter = _SuccessorAdapter(call.model, transport)
    if call.model.route != contract.QWEN_OPENROUTER["route"]:
        return await adapter.preflight(secret)
    response = await transport.send(adapter.build_metadata_request(secret))
    adapter._raise_for_status(response)
    raw = response.json()
    data = raw.get("data") if isinstance(raw.get("data"), dict) else raw
    returned = data.get("id") if isinstance(data, dict) else None
    adapter.assert_model_identity(str(returned))
    endpoints = data.get("endpoints") if isinstance(data, dict) else None
    if not isinstance(endpoints, list):
        raise ProviderError(
            "OpenRouter Qwen metadata lacks endpoints",
            category="response-validation",
            retryable=False,
        )
    approved = None
    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            continue
        provider = str(endpoint.get("provider_name", ""))
        parameters = endpoint.get("supported_parameters")
        pricing = endpoint.get("pricing")
        maximum = endpoint.get("max_completion_tokens")
        if (
            not provider
            or provider.casefold() == "deepinfra"
            or not isinstance(parameters, list)
            or "max_tokens" not in parameters
            or "temperature" not in parameters
            or (
                isinstance(maximum, int)
                and not isinstance(maximum, bool)
                and maximum < contract.OUTPUT_TOKEN_CAP
            )
            or not isinstance(pricing, dict)
        ):
            continue
        try:
            within_cap = _per_million(pricing.get("prompt")) <= Decimal(
                "0.45"
            ) and _per_million(pricing.get("completion")) <= Decimal("3.0")
        except ProviderError:
            continue
        if within_cap:
            approved = provider
            break
    if approved is None:
        raise ProviderError(
            "OpenRouter has no non-DeepInfra Qwen endpoint within the locked price "
            "and max_tokens policy",
            category="unavailable",
            retryable=False,
        )
    return PreflightResult(str(returned), approved, "non-DeepInfra endpoint verified")


async def _parse_generation(
    prepared: PreparedSuccessor,
    authority: Authority,
    call: PlannedCall,
    intent: Any,
    raw: Any,
) -> ProviderResult:
    messages = call.answer_messages()
    request = _SuccessorAdapter(call.model, _NeverTransport()).build_generation_request(
        "redacted-offline-secret", messages
    )
    replay = CapturedReplayTransport(
        raw,
        private_root=prepared.paths.private_root,
        common=_raw_common(
            prepared,
            authority,
            call.model.model_key,
            intent.payload["semantic_attempt_number"],
        ),
        intent=intent,
        request_kind="generation",
        expected_request=request,
    )
    result = await _SuccessorAdapter(call.model, replay).generate(
        "redacted-offline-secret", messages
    )
    if result.returned_model_id is None:
        raise ProviderError(
            "generation response lacks the exact returned model identifier",
            category="response-validation",
            retryable=False,
        )
    _SuccessorAdapter(call.model, _NeverTransport()).assert_model_identity(
        result.returned_model_id
    )
    if (
        call.model.route == contract.QWEN_OPENROUTER["route"]
        and result.provider_name is not None
        and result.provider_name.casefold() == "deepinfra"
    ):
        raise ProviderError(
            "OpenRouter Qwen fallback returned the excluded DeepInfra provider",
            category="response-validation",
            retryable=False,
        )
    return result


def _preflight_outcome_payload(
    prepared: PreparedSuccessor,
    authority: Authority,
    call: PlannedCall,
    intent: Any,
    raw: Any | None,
    *,
    result: PreflightResult | None,
    error: dict[str, Any] | None,
    completed_at: str,
) -> dict[str, Any]:
    value = {
        "schema_version": PREFLIGHT_OUTCOME_SCHEMA,
        "status": "success" if result is not None else "error",
        **_common(prepared, authority),
        "route_key": _route_key(call),
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
    prepared: PreparedSuccessor,
    authority: Authority,
    call: PlannedCall,
    intent: Any,
    raw: Any,
    *,
    result: ProviderResult | None,
    error: dict[str, Any] | None,
    latency_ms: int,
    completed_at: str,
) -> dict[str, Any]:
    common = {
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
    input_tokens = result.usage.get("input_tokens")
    if input_tokens is None:
        input_tokens = estimate_message_tokens(call.answer_messages())
    output_tokens = billed_output_tokens(call.model, result.usage, result.response_text)
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


def _consumed_without_capture_payload(
    prepared: PreparedSuccessor,
    authority: Authority,
    call: PlannedCall,
    intent: Any,
    *,
    completed_at: str,
) -> dict[str, Any]:
    if (
        call.model.model_key != "qwen"
        or intent.payload.get("semantic_attempt_number") != 2
    ):
        raise SuccessorExecutionError(
            "only DeepInfra Qwen attempt 2 may advance without a capture"
        )
    return {
        "schema_version": GENERATION_OUTCOME_SCHEMA,
        "status": "consumed-without-capture",
        **_common(prepared, authority),
        "cell_id": call.cell_id,
        "model_key": "qwen",
        "model_family": call.model.family,
        "provider": "deepinfra",
        "route": "deepinfra",
        "requested_model_id": "Qwen/Qwen3.5-397B-A17B",
        "semantic_attempt_number": 2,
        "question_sha256": intent.payload["question_sha256"],
        "prompt_sha256": intent.payload["prompt_sha256"],
        "messages_sha256": intent.payload["messages_sha256"],
        "requested_params_sha256": intent.payload["requested_params_sha256"],
        "manifest": intent.payload["manifest"],
        "preflight_outcome": intent.payload["preflight_outcome"],
        "intent": _record_binding(prepared, intent),
        "raw_response": None,
        "attempted_at": intent.payload["created_at"],
        "completed_at": completed_at,
        "latency_ms": 0,
        "disposition": {
            "category": "ambiguous-no-capture",
            "possibly_delivered": True,
            "possibly_billed": True,
            "deepinfra_replay_allowed": False,
            "openrouter_fallback_allowed_once": True,
        },
    }


def _preflight_history(
    prepared: PreparedSuccessor, authority: Authority, call: PlannedCall
) -> list[tuple[Any, Any | None, Any | None]]:
    result = []
    gap = False
    route_key = _route_key(call)
    for attempt in range(1, contract.PREFLIGHT_ATTEMPTS_PER_MODEL + 1):
        paths = (
            prepared.paths.preflight_intent(route_key, attempt),
            prepared.paths.preflight_raw(route_key, attempt),
            prepared.paths.preflight_outcome(route_key, attempt),
        )
        if not paths[0].exists():
            if paths[1].exists() or paths[2].exists():
                raise SuccessorExecutionError("orphan successor preflight evidence")
            gap = True
            continue
        if gap or (result and result[-1][2] is None):
            raise SuccessorExecutionError(
                "successor preflight attempts are not contiguous"
            )
        intent = read_record(paths[0], "successor preflight intent")
        expected = _preflight_intent_payload(
            prepared,
            authority,
            call,
            attempt,
            created_at=intent.payload.get("created_at"),
        )
        if intent.payload != expected:
            raise SuccessorExecutionError("successor preflight intent changed")
        raw = (
            read_record(paths[1], "successor preflight raw")
            if paths[1].exists()
            else None
        )
        outcome = (
            read_record(paths[2], "successor preflight outcome")
            if paths[2].exists()
            else None
        )
        result.append((intent, raw, outcome))
    return result


def _generation_history(
    prepared: PreparedSuccessor,
    authority: Authority,
    parent: ParentEvidence,
    manifest: Any,
    preflights: Mapping[str, Any],
    call: PlannedCall,
) -> list[tuple[PlannedCall, Any, Any, Any | None, Any | None]]:
    result = []
    gap = False
    for attempt in _attempt_range(call.model.model_key):
        actual_call = (
            prepared.fallback_call
            if call.model.model_key == "qwen" and attempt == 3
            else call
        )
        preflight = preflights[_route_key(actual_call)]
        paths = (
            prepared.paths.generation_intent(call.model.model_key, attempt),
            prepared.paths.generation_raw(call.model.model_key, attempt),
            prepared.paths.generation_outcome(call.model.model_key, attempt),
        )
        if not paths[0].exists():
            if paths[1].exists() or paths[2].exists():
                raise SuccessorExecutionError("orphan successor generation evidence")
            gap = True
            continue
        if gap or (result and result[-1][4] is None):
            raise SuccessorExecutionError(
                "successor generation attempts are not contiguous"
            )
        intent = read_record(paths[0], "successor generation intent")
        expected = _generation_intent_payload(
            prepared,
            authority,
            parent,
            manifest,
            preflight,
            actual_call,
            attempt,
            created_at=intent.payload.get("created_at"),
        )
        if intent.payload != expected:
            raise SuccessorExecutionError("successor generation intent changed")
        raw = (
            read_record(paths[1], "successor generation raw")
            if paths[1].exists()
            else None
        )
        outcome = (
            read_record(paths[2], "successor generation outcome")
            if paths[2].exists()
            else None
        )
        result.append((actual_call, preflight, intent, raw, outcome))
    return result


async def _reconcile_preflight(
    prepared: PreparedSuccessor, authority: Authority, call: PlannedCall
) -> tuple[Any | None, bool]:
    history = _preflight_history(prepared, authority, call)
    for index, (intent, raw, outcome) in enumerate(history):
        if outcome is None:
            if raw is None:
                payload = _preflight_outcome_payload(
                    prepared,
                    authority,
                    call,
                    intent,
                    None,
                    result=None,
                    error=_interrupted_preflight_error(),
                    completed_at=utc_now(),
                )
            else:
                try:
                    parsed = await _parse_preflight(
                        prepared, authority, call, intent, raw
                    )
                except ProviderError as error:
                    payload = _preflight_outcome_payload(
                        prepared,
                        authority,
                        call,
                        intent,
                        raw,
                        result=None,
                        error=_error(error, preflight=True),
                        completed_at=utc_now(),
                    )
                else:
                    payload = _preflight_outcome_payload(
                        prepared,
                        authority,
                        call,
                        intent,
                        raw,
                        result=parsed,
                        error=None,
                        completed_at=utc_now(),
                    )
            outcome = write_record(
                prepared.paths.preflight_outcome(
                    _route_key(call), intent.payload["attempt_number"]
                ),
                payload,
            )
        if outcome.payload.get("status") == "success":
            if raw is None:
                raise SuccessorExecutionError("successful preflight lacks raw response")
            parsed = await _parse_preflight(prepared, authority, call, intent, raw)
            expected = _preflight_outcome_payload(
                prepared,
                authority,
                call,
                intent,
                raw,
                result=parsed,
                error=None,
                completed_at=outcome.payload.get("completed_at"),
            )
            if outcome.payload != expected or index != len(history) - 1:
                raise SuccessorExecutionError("successor preflight outcome changed")
            return outcome, False
        error = outcome.payload.get("error")
        if not isinstance(error, dict) or not error.get("retryable"):
            raise SuccessorExecutionError(
                f"fresh preflight failed for {call.model.model_key}"
            )
    return (
        (None, True)
        if len(history) < contract.PREFLIGHT_ATTEMPTS_PER_MODEL
        else (None, False)
    )


async def _run_preflight(
    prepared: PreparedSuccessor,
    authority: Authority,
    call: PlannedCall,
    *,
    secret: str,
    transport: Transport,
    limiter: RateLimiter,
) -> Any:
    attempt = len(_preflight_history(prepared, authority, call)) + 1
    route_key = _route_key(call)
    intent = write_record(
        prepared.paths.preflight_intent(route_key, attempt),
        _preflight_intent_payload(
            prepared, authority, call, attempt, created_at=utc_now()
        ),
    )
    request = _SuccessorAdapter(call.model, _NeverTransport()).build_metadata_request(
        secret
    )
    capture = DurableCaptureTransport(
        transport,
        capture_path=prepared.paths.preflight_raw(route_key, attempt),
        private_root=prepared.paths.private_root,
        common=_raw_common(prepared, authority, route_key, attempt),
        intent=intent,
        request_kind="preflight",
        expected_request=request,
    )
    await limiter.wait()
    try:
        result = await _adapter_preflight(call, capture, secret)
    except ProviderError as error:
        raw = capture.capture
        payload = _preflight_outcome_payload(
            prepared,
            authority,
            call,
            intent,
            raw,
            result=None,
            error=(
                _error(error, preflight=True)
                if raw is not None
                else _interrupted_preflight_error()
            ),
            completed_at=utc_now(),
        )
    else:
        raw = capture.capture
        if raw is None:
            raise SuccessorExecutionError("preflight returned without durable capture")
        payload = _preflight_outcome_payload(
            prepared,
            authority,
            call,
            intent,
            raw,
            result=result,
            error=None,
            completed_at=utc_now(),
        )
    return write_record(prepared.paths.preflight_outcome(route_key, attempt), payload)


def _manifest_payload(
    prepared: PreparedSuccessor,
    authority: Authority,
    parent: ParentEvidence,
    outcomes: list[Any],
    *,
    sealed_at: str,
) -> dict[str, Any]:
    return {
        "schema_version": MANIFEST_SCHEMA,
        "status": "complete-six-route-five-model-fresh-preflight",
        **_common(prepared, authority),
        "config_sha256": prepared.config.sha256,
        "target_plan_sha256": prepared.lock_context.lock["target_plan"]["plan_sha256"],
        "first_recovery_manifest": {
            "path": contract.FIRST_MANIFEST_PATH,
            "sha256": parent.first_manifest.sha256,
        },
        "stranded_qwen_intent_sha256": parent.stranded_qwen_intent.sha256,
        "sealed_at": sealed_at,
        "preflight_outcomes": [
            {
                "route_key": key,
                "model_key": outcome.payload["model_key"],
                **_record_binding(prepared, outcome),
                "provider_returned_model_id": outcome.payload[
                    "provider_returned_model_id"
                ],
            }
            for key, outcome in zip(
                contract.PREFLIGHT_ROUTE_KEYS, outcomes, strict=True
            )
        ],
    }


async def _ensure_manifest(
    prepared: PreparedSuccessor,
    authority: Authority,
    parent: ParentEvidence,
) -> tuple[Any | None, dict[str, Any], bool]:
    outcomes = []
    needs = False
    for call in prepared.preflight_plan:
        success, network = await _reconcile_preflight(prepared, authority, call)
        if success is not None:
            outcomes.append(success)
        needs = needs or network
    if len(outcomes) != len(prepared.preflight_plan):
        return None, {}, needs
    by_key = dict(zip(contract.PREFLIGHT_ROUTE_KEYS, outcomes, strict=True))
    if prepared.paths.manifest.exists():
        record = read_record(prepared.paths.manifest, "successor preflight manifest")
        expected = _manifest_payload(
            prepared,
            authority,
            parent,
            outcomes,
            sealed_at=record.payload.get("sealed_at"),
        )
        if record.payload != expected:
            raise SuccessorExecutionError("successor preflight manifest changed")
        return record, by_key, False
    record = write_record(
        prepared.paths.manifest,
        _manifest_payload(prepared, authority, parent, outcomes, sealed_at=utc_now()),
    )
    return record, by_key, False


def _reserved_total(prepared: PreparedSuccessor) -> int:
    root = prepared.paths.private_root / "generation/intents"
    total = 0
    reservations: list[tuple[Path, int]] = []
    if root.exists():
        for path in sorted(root.rglob("*.json")):
            record = read_record(path, "successor generation intent")
            reserve = record.payload.get("reserved_cost_microdollars")
            if not isinstance(reserve, int) or isinstance(reserve, bool) or reserve < 0:
                raise SuccessorExecutionError("successor reservation is malformed")
            total += reserve
            reservations.append((path, reserve))
    if (
        total > contract.NEW_RESERVED_CAP_MICRODOLLARS
        or total + contract.INHERITED_RESERVED_MICRODOLLARS
        > contract.COMBINED_RESERVED_CAP_MICRODOLLARS
    ):
        raise SuccessorExecutionError("successor reserved-cost cap exceeded")
    for path, reserve in reservations:
        relative = path.relative_to(root)
        if len(relative.parts) != 2:
            raise SuccessorExecutionError("successor reservation path changed")
        model_key, filename = relative.parts
        try:
            attempt = int(filename.removeprefix("attempt-").removesuffix(".json"))
        except ValueError as error:
            raise SuccessorExecutionError(
                "successor reservation path changed"
            ) from error
        if filename != f"attempt-{attempt}.json" or attempt not in _attempt_range(
            model_key
        ):
            raise SuccessorExecutionError("successor reservation path changed")
        if model_key == "qwen" and attempt == 3:
            expected = contract.QWEN_OPENROUTER_RESERVED_MICRODOLLARS
        else:
            expected = contract.RESERVED_PER_POST.get(model_key)
        if expected is None or reserve != expected:
            raise SuccessorExecutionError(
                "successor reserved cost changed for a generation intent"
            )
    return total


def _reserve_generation(
    prepared: PreparedSuccessor,
    authority: Authority,
    parent: ParentEvidence,
    manifest: Any,
    preflight: Any,
    call: PlannedCall,
    attempt: int,
) -> Any:
    current = _reserved_total(prepared)
    reserve = reserved_microdollars(call)
    if current + reserve > contract.NEW_RESERVED_CAP_MICRODOLLARS:
        raise SuccessorExecutionError(
            "no POST sent: successor reservation cap exceeded"
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


async def _validate_generation_outcome(
    prepared: PreparedSuccessor,
    authority: Authority,
    call: PlannedCall,
    intent: Any,
    raw: Any | None,
    outcome: Any,
) -> ProviderResult | None:
    if outcome.payload.get("status") == "consumed-without-capture":
        if raw is not None:
            raise SuccessorExecutionError(
                "consumed no-capture disposition acquired raw data"
            )
        expected = _consumed_without_capture_payload(
            prepared,
            authority,
            call,
            intent,
            completed_at=outcome.payload.get("completed_at"),
        )
        if outcome.payload != expected:
            raise SuccessorExecutionError("Qwen no-capture disposition changed")
        return None
    if raw is None:
        raise SuccessorExecutionError("generation outcome lacks durable raw evidence")
    if outcome.payload.get("status") == "success":
        parsed = await _parse_generation(prepared, authority, call, intent, raw)
        expected = _generation_outcome_payload(
            prepared,
            authority,
            call,
            intent,
            raw,
            result=parsed,
            error=None,
            latency_ms=outcome.payload.get("latency_ms"),
            completed_at=outcome.payload.get("completed_at"),
        )
        if outcome.payload != expected:
            raise SuccessorExecutionError("successful generation outcome changed")
        return parsed
    if outcome.payload.get("status") != "error":
        raise SuccessorExecutionError("generation outcome status is invalid")
    try:
        await _parse_generation(prepared, authority, call, intent, raw)
    except ProviderError as error:
        expected = _generation_outcome_payload(
            prepared,
            authority,
            call,
            intent,
            raw,
            result=None,
            error=_error(error, preflight=False),
            latency_ms=outcome.payload.get("latency_ms"),
            completed_at=outcome.payload.get("completed_at"),
        )
        if outcome.payload != expected:
            raise SuccessorExecutionError("generation error outcome changed")
    else:
        raise SuccessorExecutionError("generation error now parses as success")
    return None


async def _reconcile_generation(
    prepared: PreparedSuccessor,
    authority: Authority,
    parent: ParentEvidence,
    manifest: Any,
    preflights: Mapping[str, Any],
    call: PlannedCall,
) -> tuple[Any | None, bool, str | None]:
    history = _generation_history(
        prepared, authority, parent, manifest, preflights, call
    )
    for index, (actual_call, preflight, intent, raw, outcome) in enumerate(history):
        if outcome is None:
            if raw is None:
                if (
                    call.model.model_key == "qwen"
                    and intent.payload.get("semantic_attempt_number") == 2
                ):
                    outcome = write_record(
                        prepared.paths.generation_outcome("qwen", 2),
                        _consumed_without_capture_payload(
                            prepared,
                            authority,
                            actual_call,
                            intent,
                            completed_at=utc_now(),
                        ),
                    )
                else:
                    return (
                        None,
                        False,
                        f"stranded successor intent is terminal: {call.cell_id}",
                    )
            elif outcome is None:
                try:
                    result = await _parse_generation(
                        prepared, authority, actual_call, intent, raw
                    )
                except ProviderError as error:
                    payload = _generation_outcome_payload(
                        prepared,
                        authority,
                        actual_call,
                        intent,
                        raw,
                        result=None,
                        error=_error(error, preflight=False),
                        latency_ms=0,
                        completed_at=utc_now(),
                    )
                else:
                    payload = _generation_outcome_payload(
                        prepared,
                        authority,
                        actual_call,
                        intent,
                        raw,
                        result=result,
                        error=None,
                        latency_ms=0,
                        completed_at=utc_now(),
                    )
                outcome = write_record(
                    prepared.paths.generation_outcome(
                        call.model.model_key,
                        intent.payload["semantic_attempt_number"],
                    ),
                    payload,
                )
        parsed = await _validate_generation_outcome(
            prepared, authority, actual_call, intent, raw, outcome
        )
        attempt = intent.payload["semantic_attempt_number"]
        if parsed is not None:
            if index != len(history) - 1:
                raise SuccessorExecutionError("generation attempt follows success")
            return outcome, False, None
        if call.model.model_key == "qwen":
            if attempt == 2:
                if index != 0:
                    raise SuccessorExecutionError(
                        "DeepInfra Qwen attempt order changed"
                    )
                continue
            return (
                None,
                False,
                "OpenRouter Qwen fallback failed; no further Qwen call allowed",
            )
        error = outcome.payload.get("error")
        if not isinstance(error, dict) or not error.get("retryable"):
            return (
                None,
                False,
                str(
                    error.get("sanitized_summary", "terminal generation error")
                    if isinstance(error, dict)
                    else "terminal generation error"
                ),
            )
    if len(history) >= len(_attempt_range(call.model.model_key)):
        return None, False, f"safe attempt ceiling exhausted for {call.cell_id}"
    return None, True, None


async def _run_generation(
    prepared: PreparedSuccessor,
    authority: Authority,
    parent: ParentEvidence,
    manifest: Any,
    preflights: Mapping[str, Any],
    call: PlannedCall,
    *,
    secrets: Mapping[str, str],
    transport: Transport,
    limiters: Mapping[str, RateLimiter],
) -> Any:
    history = _generation_history(
        prepared, authority, parent, manifest, preflights, call
    )
    attempts = _attempt_range(call.model.model_key)
    if len(history) >= len(attempts):
        raise SuccessorExecutionError("generation POST ceiling exceeded")
    attempt = attempts[len(history)]
    actual_call = (
        prepared.fallback_call
        if call.model.model_key == "qwen" and attempt == 3
        else call
    )
    preflight = preflights[_route_key(actual_call)]
    intent = _reserve_generation(
        prepared, authority, parent, manifest, preflight, actual_call, attempt
    )
    messages = actual_call.answer_messages()
    secret = secrets[actual_call.model.environment_variable]
    request = _SuccessorAdapter(
        actual_call.model, _NeverTransport()
    ).build_generation_request(secret, messages)
    capture = DurableCaptureTransport(
        transport,
        capture_path=prepared.paths.generation_raw(call.model.model_key, attempt),
        private_root=prepared.paths.private_root,
        common=_raw_common(prepared, authority, call.model.model_key, attempt),
        intent=intent,
        request_kind="generation",
        expected_request=request,
    )
    await limiters[_route_key(actual_call)].wait()
    started = time.monotonic()
    try:
        result = await _SuccessorAdapter(actual_call.model, capture).generate(
            secret, messages
        )
        raw = capture.capture
        if raw is None:
            raise SuccessorExecutionError("generation returned without durable capture")
        result = await _parse_generation(prepared, authority, actual_call, intent, raw)
    except ProviderError as error:
        raw = capture.capture
        if raw is None:
            if call.model.model_key == "qwen" and attempt == 2:
                return write_record(
                    prepared.paths.generation_outcome("qwen", 2),
                    _consumed_without_capture_payload(
                        prepared,
                        authority,
                        actual_call,
                        intent,
                        completed_at=utc_now(),
                    ),
                )
            raise StrandedGenerationIntent(
                f"stranded successor intent; no replay allowed: {call.cell_id}"
            ) from error
        payload = _generation_outcome_payload(
            prepared,
            authority,
            actual_call,
            intent,
            raw,
            result=None,
            error=_error(error, preflight=False),
            latency_ms=int((time.monotonic() - started) * 1000),
            completed_at=utc_now(),
        )
    else:
        payload = _generation_outcome_payload(
            prepared,
            authority,
            actual_call,
            intent,
            raw,
            result=result,
            error=None,
            latency_ms=int((time.monotonic() - started) * 1000),
            completed_at=utc_now(),
        )
    return write_record(
        prepared.paths.generation_outcome(call.model.model_key, attempt), payload
    )


def _composite_payload(
    prepared: PreparedSuccessor,
    authority: Authority,
    parent: ParentEvidence,
    manifest: Any,
    outcomes: list[Any],
    *,
    sealed_at: str,
) -> dict[str, Any]:
    model_keys = [record.payload.get("model_key") for record in outcomes]
    if model_keys.count("qwen") != 1:
        raise SuccessorExecutionError(
            "successor outcomes contain duplicate or missing Qwen results"
        )
    if len(set(model_keys)) != len(model_keys):
        raise SuccessorExecutionError("successor outcomes contain a duplicate model")
    if tuple(model_keys) != contract.TARGET_MODEL_KEYS:
        raise SuccessorExecutionError(
            "successor outcomes are missing or outside the locked target order"
        )
    if any(record.payload.get("status") != "success" for record in outcomes):
        raise SuccessorExecutionError(
            "successor composite requires five successful outcomes"
        )
    by_key = {record.payload["model_key"]: record for record in outcomes}
    rule3 = {
        record.payload["model_key"]: record
        for record in parent.rule3.preserved_outcomes
    }
    cells = []
    for key in contract.MODEL_ORDER:
        if key in rule3:
            record = rule3[key]
            cells.append(
                {
                    "model_key": key,
                    "source_lane": "immutable-rule3-parent",
                    "path": record.path.relative_to(
                        parent.rule3.private_root
                    ).as_posix(),
                    "sha256": record.sha256,
                    "semantic_attempt_number": 1,
                }
            )
        elif key == "cohere":
            cells.append(
                {
                    "model_key": "cohere",
                    "source_lane": "immutable-cohere-recovery",
                    "path": contract.COHERE_OUTCOME_PATH,
                    "sha256": parent.cohere_outcome.sha256,
                    "semantic_attempt_number": 2,
                }
            )
        else:
            record = by_key[key]
            cells.append(
                {
                    "model_key": key,
                    "source_lane": "qwen-successor",
                    **_record_binding(prepared, record),
                    "semantic_attempt_number": record.payload[
                        "semantic_attempt_number"
                    ],
                    "intent": record.payload["intent"],
                    "raw_response": record.payload["raw_response"],
                }
            )
    new_reserved = _reserved_total(prepared)
    return {
        "schema_version": COMPOSITE_SCHEMA,
        "status": "complete-eight-successes-three-lineage-five-recovery",
        **_common(prepared, authority),
        "sealed_at": sealed_at,
        "question_sha256": prepared.question.sha256,
        "rule3_plan_sha256": contract.RULE3_PLAN_SHA256,
        "first_recovery_manifest_sha256": parent.first_manifest.sha256,
        "successor_manifest": _record_binding(prepared, manifest),
        "parent_stranded_qwen_intent": {
            "path": contract.QWEN_STRANDED_INTENT_PATH,
            "sha256": parent.stranded_qwen_intent.sha256,
            "disposition": "consumed-possibly-delivered-possibly-billed-one-replacement",
        },
        "successful_outcome_count": 8,
        "outcomes": cells,
        "budget": {
            "inherited_reserved_microdollars": parent.reserved_microdollars,
            "new_reserved_microdollars": new_reserved,
            "combined_reserved_microdollars": parent.reserved_microdollars
            + new_reserved,
            "new_reserved_cap_microdollars": contract.NEW_RESERVED_CAP_MICRODOLLARS,
            "combined_reserved_cap_microdollars": contract.COMBINED_RESERVED_CAP_MICRODOLLARS,
        },
    }


async def _reconcile_composite(
    prepared: PreparedSuccessor,
    authority: Authority,
    parent: ParentEvidence,
    manifest: Any,
    preflights: dict[str, Any],
) -> tuple[Any | None, bool, str | None]:
    outcomes = []
    stopped = False
    for index, call in enumerate(prepared.target_plan):
        success, network, reason = await _reconcile_generation(
            prepared,
            authority,
            parent,
            manifest,
            preflights,
            call,
        )
        if stopped and (success is not None or network):
            raise SuccessorExecutionError("successor generation order changed")
        if success is not None:
            outcomes.append(success)
            continue
        if reason is not None:
            stopped = True
            for later in prepared.target_plan[index + 1 :]:
                if any(
                    prepared.paths.generation_intent(
                        later.model.model_key, attempt
                    ).exists()
                    for attempt in _attempt_range(later.model.model_key)
                ):
                    raise SuccessorExecutionError(
                        "later generation state follows a stop"
                    )
            return None, False, reason
        if network:
            break
    if len(outcomes) != len(contract.TARGET_MODEL_KEYS):
        return None, True, None
    if prepared.paths.composite.exists():
        record = read_record(prepared.paths.composite, "successor composite")
        expected = _composite_payload(
            prepared,
            authority,
            parent,
            manifest,
            outcomes,
            sealed_at=record.payload.get("sealed_at"),
        )
        if record.payload != expected:
            raise SuccessorExecutionError("successor composite changed")
        return record, False, None
    return (
        write_record(
            prepared.paths.composite,
            _composite_payload(
                prepared,
                authority,
                parent,
                manifest,
                outcomes,
                sealed_at=utc_now(),
            ),
        ),
        False,
        None,
    )


def _collect_secrets(
    prepared: PreparedSuccessor, environment: Mapping[str, str]
) -> dict[str, str]:
    result = {}
    for call in prepared.preflight_plan:
        name = call.model.environment_variable
        value = environment.get(name, "")
        if not value:
            raise SuccessorExecutionError(
                f"missing required environment variable: {name}"
            )
        result[name] = value
    return result


def _validate_inventory(prepared: PreparedSuccessor) -> None:
    root = prepared.paths.private_root
    if not root.exists():
        return
    metadata = root.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise SuccessorExecutionError("successor private root must be mode 0700")
    allowed = {
        root / "paid-authorization.json",
        root / "pricing-evidence.json",
        root / "pricing-recheck.json",
        prepared.paths.manifest,
        prepared.paths.composite,
    }
    for key in contract.PREFLIGHT_ROUTE_KEYS:
        for attempt in range(1, contract.PREFLIGHT_ATTEMPTS_PER_MODEL + 1):
            allowed.update(
                {
                    prepared.paths.preflight_intent(key, attempt),
                    prepared.paths.preflight_raw(key, attempt),
                    prepared.paths.preflight_outcome(key, attempt),
                }
            )
    for key in contract.TARGET_MODEL_KEYS:
        for attempt in _attempt_range(key):
            allowed.update(
                {
                    prepared.paths.generation_intent(key, attempt),
                    prepared.paths.generation_raw(key, attempt),
                    prepared.paths.generation_outcome(key, attempt),
                }
            )
    directories = {root}
    for path in allowed:
        cursor = path.parent
        while cursor != root:
            directories.add(cursor)
            cursor = cursor.parent
    for path in root.rglob("*"):
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            raise SuccessorExecutionError("successor journal contains a symlink")
        if stat.S_ISDIR(mode):
            if path not in directories or stat.S_IMODE(mode) != 0o700:
                raise SuccessorExecutionError("successor journal directory changed")
        elif (
            path not in allowed
            or not stat.S_ISREG(mode)
            or stat.S_IMODE(mode) != 0o600
            or path.stat().st_nlink != 1
        ):
            raise SuccessorExecutionError(
                "successor journal contains an unexpected file"
            )
    generation_root = root / "generation"
    if (
        generation_root.exists()
        and any(path.is_file() for path in generation_root.rglob("*"))
        and not prepared.paths.manifest.exists()
    ):
        raise SuccessorExecutionError(
            "successor generation state requires the sealed six-route manifest"
        )
    if prepared.paths.composite.exists():
        for key in contract.TARGET_MODEL_KEYS:
            if not any(
                prepared.paths.generation_outcome(key, attempt).exists()
                for attempt in _attempt_range(key)
            ):
                raise SuccessorExecutionError(
                    "successor composite exists before all five outcomes"
                )


async def _execute_prepared(
    prepared: PreparedSuccessor,
    *,
    environment: Mapping[str, str],
    transport_factory: Callable[[], Transport],
    sleep: Callable[[float], Awaitable[None]],
) -> SuccessorResult:
    parent = validate_parent_snapshot(
        prepared.repository_root, prepared.lock_context.lock
    )
    _validate_inventory(prepared)
    stale = _authority(prepared, fresh=False)
    async with first_phase_lock(
        prepared.repository_root / contract.FIRST_CLAIM_LOCK_PATH
    ):
        async with phase_lock(prepared.paths.phase_lock):
            parent = validate_parent_snapshot(
                prepared.repository_root, prepared.lock_context.lock
            )
            claim = _ensure_claim(prepared, stale, parent)
            stale = _with_claim(stale, claim)
            manifest, preflights, needs_preflight = await _ensure_manifest(
                prepared, stale, parent
            )
            if manifest is not None:
                composite, needs_generation, terminal = await _reconcile_composite(
                    prepared, stale, parent, manifest, preflights
                )
                if composite is not None:
                    return SuccessorResult(
                        composite.path, composite.payload, composite.sha256, 0
                    )
                if terminal is not None:
                    return SuccessorResult(
                        prepared.paths.private_root,
                        {
                            "status": "terminal-successor-incomplete",
                            "stopped_reason": terminal,
                        },
                        "",
                        0,
                    )
                if not needs_generation:
                    raise SuccessorExecutionError("successor journal cannot advance")
            fresh = _authority(prepared, fresh=True)
            if fresh != Authority(stale.authorization, stale.pricing):
                raise SuccessorExecutionError("successor authority changed under lock")
            authority = _with_claim(fresh, claim)
            secrets = _collect_secrets(prepared, environment)
            transport = transport_factory()
            limiters = {
                _route_key(call): RateLimiter(call.model.requests_per_second)
                for call in prepared.preflight_plan
            }
            requests = 0
            if manifest is None:
                if not needs_preflight:
                    raise SuccessorExecutionError("fresh preflight cannot advance")
                outcomes = []
                for call in prepared.preflight_plan:
                    while True:
                        success, needs = await _reconcile_preflight(
                            prepared, authority, call
                        )
                        if success is not None:
                            outcomes.append(success)
                            break
                        if not needs:
                            raise SuccessorExecutionError(
                                f"preflight ceiling exhausted for {call.model.model_key}"
                            )
                        outcome = await _run_preflight(
                            prepared,
                            authority,
                            call,
                            secret=secrets[call.model.environment_variable],
                            transport=transport,
                            limiter=limiters[_route_key(call)],
                        )
                        requests += 1
                        if outcome.payload["status"] == "error":
                            await sleep(
                                0.5 * (2 ** (outcome.payload["attempt_number"] - 1))
                            )
                manifest = write_record(
                    prepared.paths.manifest,
                    _manifest_payload(
                        prepared, authority, parent, outcomes, sealed_at=utc_now()
                    ),
                )
                preflights = dict(
                    zip(contract.PREFLIGHT_ROUTE_KEYS, outcomes, strict=True)
                )
            for call in prepared.target_plan:
                while True:
                    success, needs, reason = await _reconcile_generation(
                        prepared,
                        authority,
                        parent,
                        manifest,
                        preflights,
                        call,
                    )
                    if success is not None:
                        break
                    if reason is not None:
                        return SuccessorResult(
                            prepared.paths.private_root,
                            {
                                "status": "terminal-successor-incomplete",
                                "stopped_reason": reason,
                            },
                            "",
                            requests,
                        )
                    if not needs:
                        raise SuccessorExecutionError(
                            "successor generation cannot advance"
                        )
                    try:
                        outcome = await _run_generation(
                            prepared,
                            authority,
                            parent,
                            manifest,
                            preflights,
                            call,
                            secrets=secrets,
                            transport=transport,
                            limiters=limiters,
                        )
                    except StrandedGenerationIntent:
                        return SuccessorResult(
                            prepared.paths.private_root,
                            {
                                "status": "terminal-successor-incomplete",
                                "stopped_reason": (
                                    "successor POST ended without a durable response; "
                                    "no further call is allowed for that route"
                                ),
                            },
                            "",
                            requests + 1,
                        )
                    requests += 1
                    if (
                        outcome.payload["status"] != "success"
                        and call.model.model_key != "qwen"
                    ):
                        await sleep(
                            0.5
                            * (2 ** (outcome.payload["semantic_attempt_number"] - 1))
                        )
            composite, _, terminal = await _reconcile_composite(
                prepared, authority, parent, manifest, preflights
            )
            if composite is None:
                raise SuccessorExecutionError(
                    terminal or "successor composite was not sealed"
                )
            if requests > contract.MAX_OUTBOUND_REQUESTS:
                raise SuccessorExecutionError(
                    "successor outbound request ceiling exceeded"
                )
            return SuccessorResult(
                composite.path, composite.payload, composite.sha256, requests
            )


async def execute_prepared(prepared: PreparedSuccessor) -> SuccessorResult:
    return await _execute_prepared(
        prepared,
        environment=os.environ,
        transport_factory=UrllibTransport,
        sleep=asyncio.sleep,
    )


__all__ = (
    "PreparedSuccessor",
    "SuccessorExecutionError",
    "SuccessorResult",
    "_attempt_range",
    "_execute_prepared",
    "dry_run_summary",
    "execute_prepared",
    "prepare_successor",
)
