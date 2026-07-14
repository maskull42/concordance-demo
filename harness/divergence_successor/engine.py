"""Durable one-attempt runtime for the divergence successor.

Every request has a write-ahead intent.  Every HTTP response is sealed before
provider parsing.  Preflights form one complete gate; generation begins only
after that gate is durably sealed, and all eight generation calls are then
released concurrently.  An intent without a raw response is consumed forever.
"""

from __future__ import annotations

import asyncio
import os
import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, ROUND_CEILING
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping

from concordance_harness.config import returned_model_id_is_approved
from concordance_harness.execution import billed_output_tokens
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
from concordance_recovery.journal import (
    RecoveryJournalError,
    StrandedGenerationIntent,
    binding,
    read_record,
    request_body_bytes,
    request_origin,
    require_timestamp,
    validate_raw_response,
    write_record,
)
from concordance_recovery.transport import (
    CapturedReplayTransport,
    DurableCaptureTransport,
)
from rule3.budget import JournalRecord

from . import authorization, contract, execute
from .state import inspect_inventory, phase_lock


PREFLIGHT_INTENT_SCHEMA = "divergence-successor-preflight-intent-1.0.0"
PREFLIGHT_OUTCOME_SCHEMA = "divergence-successor-preflight-outcome-1.0.0"
GENERATION_INTENT_SCHEMA = "divergence-successor-generation-intent-1.0.0"
GENERATION_OUTCOME_SCHEMA = "divergence-successor-generation-outcome-1.0.0"
MANIFEST_SCHEMA = "divergence-successor-model-manifest-1.0.0"
MANIFEST_STATUS = "complete-eight-model-fresh-preflight"


@dataclass(frozen=True)
class Authority:
    authorization: authorization.AuthorizationBinding
    pricing: authorization.AuthorizationBinding


@dataclass(frozen=True)
class SuccessorExecutionResult:
    path: Path
    payload: dict[str, Any]
    sha256: str
    network_requests: int


class _NeverTransport:
    async def send(self, request: Any) -> Any:
        del request
        raise execute.DivergenceSuccessorExecutionError(
            "offline request construction attempted network access"
        )


def _require_runtime(prepared: execute.PreparedSuccessor) -> None:
    if (
        prepared.config is None
        or prepared.question is None
        or len(prepared.plan) != 8
        or tuple(prepared.call_by_key) != contract.MODEL_KEYS
        or prepared.lock_context.git_head is None
    ):
        raise execute.DivergenceSuccessorExecutionError(
            "successor runtime lacks the committed exact plan"
        )


def _authority(
    prepared: execute.PreparedSuccessor, *, fresh: bool
) -> Authority:
    try:
        paid = authorization.validate_authorization(prepared.lock_context)
        pricing = authorization.validate_pricing_recheck(
            prepared.lock_context, paid, fresh=fresh
        )
    except authorization.DivergenceSuccessorAuthorizationError as error:
        raise execute.DivergenceSuccessorExecutionError(str(error)) from error
    if (
        paid.path != prepared.paths.authorization
        or pricing.path != prepared.paths.pricing_recheck
    ):
        raise execute.DivergenceSuccessorExecutionError(
            "successor authority paths differ from the fixed private lane"
        )
    return Authority(paid, pricing)


def _common(
    prepared: execute.PreparedSuccessor, authority: Authority
) -> dict[str, Any]:
    git_head = prepared.lock_context.git_head
    if not isinstance(git_head, str):
        raise execute.DivergenceSuccessorExecutionError(
            "live successor lacks a committed Git HEAD"
        )
    return {
        "pool_id": contract.POOL_ID,
        "candidate_id": contract.CANDIDATE_ID,
        "git_head": git_head,
        "lock_sha256": prepared.lock_context.lock_sha256,
        "authorization_receipt_sha256": authority.authorization.sha256,
        "pricing_recheck_receipt_sha256": authority.pricing.sha256,
        "parent_contract_sha256": sha256_bytes(
            canonical_json_bytes(prepared.lock_context.lock["parent"])
        ),
    }


def _record_binding(
    prepared: execute.PreparedSuccessor, record: JournalRecord
) -> dict[str, str]:
    try:
        return binding(prepared.paths.private_root, record).value()
    except RecoveryJournalError as error:
        raise execute.DivergenceSuccessorExecutionError(str(error)) from error


def _parsed_time(value: Any, label: str) -> datetime:
    try:
        require_timestamp(value, label)
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError, RecoveryJournalError) as error:
        raise execute.DivergenceSuccessorExecutionError(str(error)) from error


def _not_before(
    later: Any, later_label: str, earlier: Any, earlier_label: str
) -> None:
    if _parsed_time(later, later_label) < _parsed_time(earlier, earlier_label):
        raise execute.DivergenceSuccessorExecutionError(
            f"chronology violation: {later_label} precedes {earlier_label}"
        )


def _validate_request(call: PlannedCall, request: Any, method: str) -> None:
    try:
        parsed = urllib.parse.urlsplit(request.url)
        base = urllib.parse.urlsplit(call.model.base_url)
        port = parsed.port
    except (AttributeError, TypeError, ValueError) as error:
        raise execute.DivergenceSuccessorExecutionError(
            "provider request URL is malformed"
        ) from error
    host = (parsed.hostname or "").lower().rstrip(".")
    expected_host = (base.hostname or "").lower().rstrip(".")
    if (
        request.method != method
        or parsed.scheme != "https"
        or host != expected_host
        or host not in contract.AUTHORIZED_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or parsed.fragment
    ):
        raise execute.DivergenceSuccessorExecutionError(
            f"request escaped the locked route for {call.model.model_key}"
        )
    if method == "GET" and request.json_body is not None:
        raise execute.DivergenceSuccessorExecutionError(
            "metadata request unexpectedly contains a body"
        )
    if method == "POST":
        if not isinstance(request.json_body, dict):
            raise execute.DivergenceSuccessorExecutionError(
                "generation request lacks its exact JSON body"
            )
        execute.reject_tool_artifacts(
            request.json_body,
            path=f"request[{call.model.model_key}]",
        )


def _offline_metadata_request(call: PlannedCall) -> Any:
    request = ProviderAdapter(call.model, _NeverTransport()).build_metadata_request(
        "redacted-offline-secret"
    )
    _validate_request(call, request, "GET")
    return request


def _offline_generation_request(call: PlannedCall) -> Any:
    request = ProviderAdapter(call.model, _NeverTransport()).build_generation_request(
        "redacted-offline-secret", call.answer_messages()
    )
    _validate_request(call, request, "POST")
    return request


def _preflight_intent_payload(
    prepared: execute.PreparedSuccessor,
    authority: Authority,
    call: PlannedCall,
    *,
    created_at: str,
) -> dict[str, Any]:
    require_timestamp(created_at, "successor preflight intent time")
    request = _offline_metadata_request(call)
    return {
        "schema_version": PREFLIGHT_INTENT_SCHEMA,
        "status": "reserved-before-metadata-get",
        **_common(prepared, authority),
        "model_key": call.model.model_key,
        "provider": call.model.provider,
        "route": call.model.route,
        "requested_model_id": call.model.requested_model_id,
        "attempt_number": 1,
        "request_method": "GET",
        "request_origin": request_origin(request),
        "request_json_body_sha256": sha256_bytes(request_body_bytes(request)),
        "created_at": created_at,
    }


def _price_record(authority: Authority, model_key: str) -> dict[str, Any]:
    values = authority.pricing.payload.get("prices")
    matches = [
        item
        for item in values or []
        if isinstance(item, dict) and item.get("model_key") == model_key
    ]
    if len(matches) != 1:
        raise execute.DivergenceSuccessorExecutionError(
            f"fresh pricing lacks the exact {model_key} route"
        )
    return matches[0]


def _generation_intent_payload(
    prepared: execute.PreparedSuccessor,
    authority: Authority,
    manifest: JournalRecord,
    preflight: JournalRecord,
    call: PlannedCall,
    *,
    created_at: str,
) -> dict[str, Any]:
    require_timestamp(created_at, "successor generation intent time")
    _not_before(
        created_at,
        "generation intent time",
        manifest.payload.get("sealed_at"),
        "preflight manifest time",
    )
    _not_before(
        created_at,
        "generation intent time",
        preflight.payload.get("completed_at"),
        "preflight completion time",
    )
    request = _offline_generation_request(call)
    messages = call.answer_messages()
    price = _price_record(authority, call.model.model_key)
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
        "attempt_number": 1,
        "reserved_cost_microdollars": price["reservation_microdollars"],
        "question_sha256": prepared.question.sha256,
        "prompt_sha256": prompt_sha256(messages),
        "messages": messages,
        "messages_sha256": sha256_bytes(canonical_json_bytes(messages)),
        "requested_params": call.model.requested_params_receipt(),
        "requested_params_sha256": sha256_bytes(
            canonical_json_bytes(call.model.requested_params_receipt())
        ),
        "request_method": "POST",
        "request_origin": request_origin(request),
        "request_json_body_sha256": sha256_bytes(request_body_bytes(request)),
        "manifest": _record_binding(prepared, manifest),
        "preflight_outcome": _record_binding(prepared, preflight),
        "created_at": created_at,
    }


def _validate_intent(
    record: JournalRecord,
    expected: dict[str, Any],
    expected_path: Path,
    label: str,
) -> None:
    expected["created_at"] = record.payload.get("created_at")
    if record.path.resolve() != expected_path.resolve() or record.payload != expected:
        raise execute.DivergenceSuccessorExecutionError(
            f"{label} differs from the exact locked request"
        )


def _raw_common(
    prepared: execute.PreparedSuccessor,
    authority: Authority,
    *,
    model_key: str,
) -> dict[str, Any]:
    return {
        **_common(prepared, authority),
        "model_key": model_key,
        "semantic_attempt_number": 1,
    }


def _error_value(error: ProviderError, request_kind: str) -> dict[str, Any]:
    return {
        "category": error.category,
        "retryable": False,
        "sanitized_summary": f"{request_kind} request failed ({error.category})",
    }


def _validate_error(value: Any, label: str) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != {"category", "retryable", "sanitized_summary"}
        or not isinstance(value.get("category"), str)
        or value.get("retryable") is not False
        or not isinstance(value.get("sanitized_summary"), str)
        or not value["sanitized_summary"]
    ):
        raise execute.DivergenceSuccessorExecutionError(
            f"{label} error receipt is malformed or retryable"
        )
    return value


def _scan_raw_json(response: Any, label: str) -> None:
    try:
        value = response.json()
        execute.reject_tool_artifacts(value, path=label)
    except execute.DivergenceSuccessorExecutionError as error:
        raise ProviderError(
            "provider response contains a forbidden tool or context artifact",
            category="response-validation",
            retryable=False,
        ) from error


async def _parse_preflight_capture(
    prepared: execute.PreparedSuccessor,
    authority: Authority,
    call: PlannedCall,
    intent: JournalRecord,
    raw: JournalRecord,
) -> PreflightResult:
    request = _offline_metadata_request(call)
    common = _raw_common(
        prepared, authority, model_key=call.model.model_key
    )
    response = validate_raw_response(
        raw,
        expected_common=common,
        expected_intent=intent,
        private_root=prepared.paths.private_root,
        request_kind="preflight",
        expected_request=request,
    )
    _scan_raw_json(response, f"preflight_raw[{call.model.model_key}]")
    replay = CapturedReplayTransport(
        raw,
        private_root=prepared.paths.private_root,
        common=common,
        intent=intent,
        request_kind="preflight",
        expected_request=request,
    )
    return await ProviderAdapter(call.model, replay).preflight(
        "redacted-offline-secret"
    )


async def _parse_generation_capture(
    prepared: execute.PreparedSuccessor,
    authority: Authority,
    call: PlannedCall,
    intent: JournalRecord,
    raw: JournalRecord,
    preflight: JournalRecord,
) -> ProviderResult:
    request = _offline_generation_request(call)
    common = _raw_common(
        prepared, authority, model_key=call.model.model_key
    )
    response = validate_raw_response(
        raw,
        expected_common=common,
        expected_intent=intent,
        private_root=prepared.paths.private_root,
        request_kind="generation",
        expected_request=request,
    )
    _scan_raw_json(response, f"generation_raw[{call.model.model_key}]")
    replay = CapturedReplayTransport(
        raw,
        private_root=prepared.paths.private_root,
        common=common,
        intent=intent,
        request_kind="generation",
        expected_request=request,
    )
    result = await ProviderAdapter(call.model, replay).generate(
        "redacted-offline-secret", call.answer_messages()
    )
    returned = result.returned_model_id
    preflight_id = preflight.payload.get("provider_returned_model_id")
    if call.model.model_key == "cohere":
        body = request.json_body
        if (
            not execute.returned_model_id_is_approved("cohere", preflight_id)
            or not isinstance(body, dict)
            or body.get("model") != call.model.requested_model_id
            or call.model.fallback_allowed
            or (
                returned is not None
                and not returned_model_id_is_approved(call.model, returned)
            )
        ):
            raise ProviderError(
                "Cohere generation identity lacks its request and fresh preflight",
                category="response-validation",
                retryable=False,
            )
    elif returned is None or not returned_model_id_is_approved(
        call.model, returned
    ):
        raise ProviderError(
            "generation response lacks an approved canonical model identifier",
            category="response-validation",
            retryable=False,
        )
    return result


def _preflight_outcome_payload(
    prepared: execute.PreparedSuccessor,
    authority: Authority,
    intent: JournalRecord,
    raw: JournalRecord,
    call: PlannedCall,
    *,
    result: PreflightResult | None,
    error: dict[str, Any] | None,
    completed_at: str,
) -> dict[str, Any]:
    require_timestamp(completed_at, "successor preflight completion time")
    _not_before(
        completed_at,
        "preflight completion time",
        intent.payload.get("created_at"),
        "preflight intent time",
    )
    _not_before(
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
        "attempt_number": 1,
        "intent": _record_binding(prepared, intent),
        "raw_response": _record_binding(prepared, raw),
        "completed_at": completed_at,
    }
    if result is None:
        value["error"] = error
    else:
        value.update(
            {
                "provider_returned_model_id": result.returned_model_id,
                "provider_name": result.provider_name,
                "sanitized_note": result.note,
            }
        )
    return value


async def _validate_preflight_record(
    prepared: execute.PreparedSuccessor,
    authority: Authority,
    call: PlannedCall,
    intent: JournalRecord,
    raw: JournalRecord,
    outcome: JournalRecord,
) -> PreflightResult | None:
    if outcome.path != prepared.paths.preflight_outcome(call.model.model_key):
        raise execute.DivergenceSuccessorExecutionError(
            "preflight outcome path changed"
        )
    try:
        result = await _parse_preflight_capture(
            prepared, authority, call, intent, raw
        )
    except ProviderError as provider_error:
        expected = _preflight_outcome_payload(
            prepared,
            authority,
            intent,
            raw,
            call,
            result=None,
            error=_error_value(provider_error, "preflight"),
            completed_at=outcome.payload.get("completed_at"),
        )
        _validate_error(outcome.payload.get("error"), "preflight")
        parsed = None
    else:
        expected = _preflight_outcome_payload(
            prepared,
            authority,
            intent,
            raw,
            call,
            result=result,
            error=None,
            completed_at=outcome.payload.get("completed_at"),
        )
        parsed = result
    if outcome.payload != expected:
        raise execute.DivergenceSuccessorExecutionError(
            "preflight outcome differs from its exact request and raw response"
        )
    execute.validate_preflight_outcome(outcome, model_key=call.model.model_key)
    return parsed


async def _finalize_preflight(
    prepared: execute.PreparedSuccessor,
    authority: Authority,
    call: PlannedCall,
    intent: JournalRecord,
    raw: JournalRecord,
) -> JournalRecord:
    try:
        result = await _parse_preflight_capture(
            prepared, authority, call, intent, raw
        )
    except ProviderError as provider_error:
        result = None
        error = _error_value(provider_error, "preflight")
    else:
        error = None
    return write_record(
        prepared.paths.preflight_outcome(call.model.model_key),
        _preflight_outcome_payload(
            prepared,
            authority,
            intent,
            raw,
            call,
            result=result,
            error=error,
            completed_at=utc_now(),
        ),
    )


def _read_preflight_intent(
    prepared: execute.PreparedSuccessor,
    authority: Authority,
    call: PlannedCall,
) -> JournalRecord:
    intent = read_record(
        prepared.paths.preflight_intent(call.model.model_key),
        f"successor preflight intent {call.model.model_key}",
    )
    _validate_intent(
        intent,
        _preflight_intent_payload(
            prepared, authority, call, created_at=intent.payload.get("created_at")
        ),
        prepared.paths.preflight_intent(call.model.model_key),
        "preflight intent",
    )
    return intent


async def _load_preflight_success(
    prepared: execute.PreparedSuccessor,
    authority: Authority,
    call: PlannedCall,
) -> JournalRecord | None:
    state = execute.cell_state(prepared.paths, "preflight", call.model.model_key)
    if state["status"] == "unstarted":
        return None
    intent = _read_preflight_intent(prepared, authority, call)
    if state["status"] == "consumed-stranded-no-replay":
        raise execute.DivergenceSuccessorExecutionError(
            f"stranded preflight intent; no retry allowed: {call.model.model_key}"
        )
    raw = read_record(
        state["raw"], f"successor preflight raw {call.model.model_key}"
    )
    if state["status"] == "captured-offline-finalization-required":
        outcome = await _finalize_preflight(
            prepared, authority, call, intent, raw
        )
    else:
        outcome = read_record(
            state["outcome"], f"successor preflight outcome {call.model.model_key}"
        )
    result = await _validate_preflight_record(
        prepared, authority, call, intent, raw, outcome
    )
    if result is None:
        raise execute.DivergenceSuccessorExecutionError(
            f"terminal preflight failure; no retry allowed: {call.model.model_key}"
        )
    return outcome


async def _send_preflight(
    prepared: execute.PreparedSuccessor,
    authority: Authority,
    call: PlannedCall,
    intent: JournalRecord,
    *,
    secret: str,
    transport: Transport,
) -> JournalRecord:
    request = ProviderAdapter(call.model, _NeverTransport()).build_metadata_request(
        secret
    )
    _validate_request(call, request, "GET")
    capture = DurableCaptureTransport(
        transport,
        capture_path=prepared.paths.preflight_raw(call.model.model_key),
        private_root=prepared.paths.private_root,
        common=_raw_common(
            prepared, authority, model_key=call.model.model_key
        ),
        intent=intent,
        request_kind="preflight",
        expected_request=request,
    )
    try:
        await ProviderAdapter(call.model, capture).preflight(secret)
    except ProviderError:
        pass
    raw = capture.capture
    if raw is None:
        raise execute.DivergenceSuccessorExecutionError(
            f"preflight intent is consumed without a response: {call.model.model_key}"
        )
    return await _finalize_preflight(prepared, authority, call, intent, raw)


def _manifest_payload(
    prepared: execute.PreparedSuccessor,
    authority: Authority,
    outcomes: list[JournalRecord],
    *,
    sealed_at: str,
) -> dict[str, Any]:
    require_timestamp(sealed_at, "successor manifest time")
    for outcome in outcomes:
        _not_before(
            sealed_at,
            "manifest time",
            outcome.payload.get("completed_at"),
            "preflight completion time",
        )
    plan = prepared.lock_context.lock["plans"]["candidate_plans"][0]
    return {
        "schema_version": MANIFEST_SCHEMA,
        "status": MANIFEST_STATUS,
        **_common(prepared, authority),
        "config_sha256": prepared.config.sha256,
        "question_sha256": prepared.question.sha256,
        "plan_sha256": plan["plan_sha256"],
        "sealed_at": sealed_at,
        "preflight_outcomes": [
            {
                "model_key": key,
                **_record_binding(prepared, outcome),
                "provider_returned_model_id": outcome.payload[
                    "provider_returned_model_id"
                ],
            }
            for key, outcome in zip(contract.MODEL_KEYS, outcomes, strict=True)
        ],
    }


async def validate_manifest_record(
    prepared: execute.PreparedSuccessor,
    authority: Authority,
    manifest: JournalRecord,
) -> dict[str, JournalRecord]:
    if manifest.path != prepared.paths.manifest:
        raise execute.DivergenceSuccessorExecutionError("manifest path changed")
    outcomes: list[JournalRecord] = []
    for call in prepared.plan:
        outcome = await _load_preflight_success(prepared, authority, call)
        if outcome is None:
            raise execute.DivergenceSuccessorExecutionError(
                "manifest exists before every preflight success"
            )
        outcomes.append(outcome)
    expected = _manifest_payload(
        prepared,
        authority,
        outcomes,
        sealed_at=manifest.payload.get("sealed_at"),
    )
    if manifest.payload != expected:
        raise execute.DivergenceSuccessorExecutionError(
            "manifest differs from the exact eight preflight records"
        )
    return dict(zip(contract.MODEL_KEYS, outcomes, strict=True))


async def _ensure_preflights(
    prepared: execute.PreparedSuccessor,
    authority: Authority,
    *,
    secrets: Mapping[str, str],
    transport: Transport,
) -> tuple[JournalRecord, dict[str, JournalRecord], int]:
    if prepared.paths.manifest.exists():
        manifest = read_record(prepared.paths.manifest, "successor manifest")
        return manifest, await validate_manifest_record(
            prepared, authority, manifest
        ), 0
    existing: dict[str, JournalRecord] = {}
    unstarted: list[PlannedCall] = []
    for call in prepared.plan:
        outcome = await _load_preflight_success(prepared, authority, call)
        if outcome is None:
            unstarted.append(call)
        else:
            existing[call.model.model_key] = outcome
    intents: dict[str, JournalRecord] = {}
    for call in unstarted:
        intents[call.model.model_key] = write_record(
            prepared.paths.preflight_intent(call.model.model_key),
            _preflight_intent_payload(
                prepared, authority, call, created_at=utc_now()
            ),
        )
    if unstarted:
        results = await asyncio.gather(
            *(
                _send_preflight(
                    prepared,
                    authority,
                    call,
                    intents[call.model.model_key],
                    secret=secrets[call.model.environment_variable],
                    transport=transport,
                )
                for call in unstarted
            ),
            return_exceptions=True,
        )
        errors = [item for item in results if isinstance(item, BaseException)]
        if errors:
            raise execute.DivergenceSuccessorExecutionError(
                "one or more preflight requests stranded or failed before validation"
            ) from errors[0]
    outcomes: list[JournalRecord] = []
    for call in prepared.plan:
        outcome = await _load_preflight_success(prepared, authority, call)
        if outcome is None:
            raise execute.DivergenceSuccessorExecutionError(
                "all-eight preflight gate is incomplete"
            )
        outcomes.append(outcome)
    manifest = write_record(
        prepared.paths.manifest,
        _manifest_payload(
            prepared, authority, outcomes, sealed_at=utc_now()
        ),
    )
    return (
        manifest,
        dict(zip(contract.MODEL_KEYS, outcomes, strict=True)),
        len(unstarted),
    )


async def _ensure_manifest_offline(
    prepared: execute.PreparedSuccessor,
    authority: Authority,
) -> tuple[JournalRecord | None, dict[str, JournalRecord]]:
    """Finalize captured preflights without credentials or a transport."""

    if prepared.paths.manifest.exists():
        manifest = read_record(prepared.paths.manifest, "successor manifest")
        return manifest, await validate_manifest_record(
            prepared, authority, manifest
        )
    outcomes: list[JournalRecord] = []
    unstarted: list[str] = []
    for call in prepared.plan:
        outcome = await _load_preflight_success(prepared, authority, call)
        if outcome is None:
            unstarted.append(call.model.model_key)
        else:
            outcomes.append(outcome)
    if unstarted:
        if outcomes:
            raise execute.DivergenceSuccessorExecutionError(
                "partial preflight inventory cannot contain unstarted cells"
            )
        return None, {}
    manifest = write_record(
        prepared.paths.manifest,
        _manifest_payload(
            prepared, authority, outcomes, sealed_at=utc_now()
        ),
    )
    return manifest, dict(zip(contract.MODEL_KEYS, outcomes, strict=True))


def _generation_outcome_payload(
    prepared: execute.PreparedSuccessor,
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
    require_timestamp(completed_at, "successor generation completion time")
    _not_before(
        completed_at,
        "generation completion time",
        intent.payload.get("created_at"),
        "generation intent time",
    )
    _not_before(
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
        "attempt_number": 1,
        "question_sha256": intent.payload["question_sha256"],
        "prompt_sha256": intent.payload["prompt_sha256"],
        "messages_sha256": intent.payload["messages_sha256"],
        "requested_params_sha256": intent.payload["requested_params_sha256"],
        "request_json_body_sha256": intent.payload["request_json_body_sha256"],
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
    price = _price_record(authority, call.model.model_key)
    actual = int(
        (
            Decimal(input_tokens) * Decimal(str(price["input_per_million"]))
            + Decimal(output_tokens) * Decimal(str(price["output_per_million"]))
        ).to_integral_value(rounding=ROUND_CEILING)
    )
    result_value = {
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
            "reserved_microdollars": intent.payload[
                "reserved_cost_microdollars"
            ],
            "pricing_checked_at": authority.pricing.payload["checked_at"],
        },
    }
    return {**common, "result": result_value}


async def validate_generation_record(
    prepared: execute.PreparedSuccessor,
    authority: Authority,
    manifest: JournalRecord,
    preflight: JournalRecord,
    call: PlannedCall,
    intent: JournalRecord,
    raw: JournalRecord,
    outcome: JournalRecord,
) -> ProviderResult | None:
    if outcome.path != prepared.paths.generation_outcome(call.model.model_key):
        raise execute.DivergenceSuccessorExecutionError(
            "generation outcome path changed"
        )
    expected_intent = _generation_intent_payload(
        prepared,
        authority,
        manifest,
        preflight,
        call,
        created_at=intent.payload.get("created_at"),
    )
    _validate_intent(
        intent,
        expected_intent,
        prepared.paths.generation_intent(call.model.model_key),
        "generation intent",
    )
    latency = outcome.payload.get("latency_ms")
    if not isinstance(latency, int) or isinstance(latency, bool) or latency < 0:
        raise execute.DivergenceSuccessorExecutionError(
            "generation latency is malformed"
        )
    try:
        result = await _parse_generation_capture(
            prepared, authority, call, intent, raw, preflight
        )
    except ProviderError as provider_error:
        expected = _generation_outcome_payload(
            prepared,
            authority,
            intent,
            raw,
            call,
            result=None,
            error=_error_value(provider_error, "generation"),
            latency_ms=latency,
            completed_at=outcome.payload.get("completed_at"),
        )
        _validate_error(outcome.payload.get("error"), "generation")
        parsed = None
    else:
        expected = _generation_outcome_payload(
            prepared,
            authority,
            intent,
            raw,
            call,
            result=result,
            error=None,
            latency_ms=latency,
            completed_at=outcome.payload.get("completed_at"),
        )
        parsed = result
    if outcome.payload != expected:
        raise execute.DivergenceSuccessorExecutionError(
            "generation outcome differs from its lock, authority, manifest, "
            "request, raw response, or response hash"
        )
    if parsed is not None:
        execute.validate_generation_outcome(
            outcome,
            model_key=call.model.model_key,
            prompt_sha256=prompt_sha256(call.answer_messages()),
        )
    return parsed


async def _finalize_generation(
    prepared: execute.PreparedSuccessor,
    authority: Authority,
    manifest: JournalRecord,
    preflight: JournalRecord,
    call: PlannedCall,
    intent: JournalRecord,
    raw: JournalRecord,
    *,
    latency_ms: int,
) -> JournalRecord:
    try:
        result = await _parse_generation_capture(
            prepared, authority, call, intent, raw, preflight
        )
    except ProviderError as provider_error:
        result = None
        error = _error_value(provider_error, "generation")
    else:
        error = None
    return write_record(
        prepared.paths.generation_outcome(call.model.model_key),
        _generation_outcome_payload(
            prepared,
            authority,
            intent,
            raw,
            call,
            result=result,
            error=error,
            latency_ms=latency_ms,
            completed_at=utc_now(),
        ),
    )


async def _load_generation_success(
    prepared: execute.PreparedSuccessor,
    authority: Authority,
    manifest: JournalRecord,
    preflight: JournalRecord,
    call: PlannedCall,
) -> JournalRecord | None:
    state = execute.cell_state(prepared.paths, "generation", call.model.model_key)
    if state["status"] == "unstarted":
        return None
    intent = read_record(
        state["intent"], f"successor generation intent {call.model.model_key}"
    )
    _validate_intent(
        intent,
        _generation_intent_payload(
            prepared,
            authority,
            manifest,
            preflight,
            call,
            created_at=intent.payload.get("created_at"),
        ),
        prepared.paths.generation_intent(call.model.model_key),
        "generation intent",
    )
    if state["status"] == "consumed-stranded-no-replay":
        raise StrandedGenerationIntent(
            f"stranded successor generation intent; no replay allowed: {call.cell_id}"
        )
    raw = read_record(
        state["raw"], f"successor generation raw {call.model.model_key}"
    )
    if state["status"] == "captured-offline-finalization-required":
        outcome = await _finalize_generation(
            prepared,
            authority,
            manifest,
            preflight,
            call,
            intent,
            raw,
            latency_ms=0,
        )
    else:
        outcome = read_record(
            state["outcome"], f"successor generation outcome {call.model.model_key}"
        )
    result = await validate_generation_record(
        prepared,
        authority,
        manifest,
        preflight,
        call,
        intent,
        raw,
        outcome,
    )
    if result is None:
        raise execute.DivergenceSuccessorExecutionError(
            f"terminal generation failure; no retry allowed: {call.model.model_key}"
        )
    return outcome


async def _send_generation(
    prepared: execute.PreparedSuccessor,
    authority: Authority,
    manifest: JournalRecord,
    preflight: JournalRecord,
    call: PlannedCall,
    intent: JournalRecord,
    *,
    secret: str,
    transport: Transport,
) -> JournalRecord:
    request = ProviderAdapter(call.model, _NeverTransport()).build_generation_request(
        secret, call.answer_messages()
    )
    _validate_request(call, request, "POST")
    capture = DurableCaptureTransport(
        transport,
        capture_path=prepared.paths.generation_raw(call.model.model_key),
        private_root=prepared.paths.private_root,
        common=_raw_common(
            prepared, authority, model_key=call.model.model_key
        ),
        intent=intent,
        request_kind="generation",
        expected_request=request,
    )
    started = time.monotonic()
    try:
        await ProviderAdapter(call.model, capture).generate(
            secret, call.answer_messages()
        )
    except ProviderError:
        pass
    raw = capture.capture
    if raw is None:
        raise StrandedGenerationIntent(
            f"stranded successor generation intent; no replay allowed: {call.cell_id}"
        )
    return await _finalize_generation(
        prepared,
        authority,
        manifest,
        preflight,
        call,
        intent,
        raw,
        latency_ms=int((time.monotonic() - started) * 1000),
    )


async def _ensure_generations(
    prepared: execute.PreparedSuccessor,
    authority: Authority,
    manifest: JournalRecord,
    preflight_by_key: Mapping[str, JournalRecord],
    *,
    secrets: Mapping[str, str],
    transport: Transport,
) -> tuple[list[JournalRecord], int]:
    existing: list[JournalRecord] = []
    unstarted: list[PlannedCall] = []
    for call in prepared.plan:
        outcome = await _load_generation_success(
            prepared,
            authority,
            manifest,
            preflight_by_key[call.model.model_key],
            call,
        )
        if outcome is None:
            unstarted.append(call)
        else:
            existing.append(outcome)
    if existing and unstarted:
        raise execute.DivergenceSuccessorExecutionError(
            "partial generation inventory cannot reopen an unstarted paid cell"
        )
    if not unstarted:
        return existing, 0
    intents: dict[str, JournalRecord] = {}
    for call in prepared.plan:
        intents[call.model.model_key] = write_record(
            prepared.paths.generation_intent(call.model.model_key),
            _generation_intent_payload(
                prepared,
                authority,
                manifest,
                preflight_by_key[call.model.model_key],
                call,
                created_at=utc_now(),
            ),
        )
    results = await asyncio.gather(
        *(
            _send_generation(
                prepared,
                authority,
                manifest,
                preflight_by_key[call.model.model_key],
                call,
                intents[call.model.model_key],
                secret=secrets[call.model.environment_variable],
                transport=transport,
            )
            for call in prepared.plan
        ),
        return_exceptions=True,
    )
    errors = [item for item in results if isinstance(item, BaseException)]
    if errors:
        raise execute.DivergenceSuccessorExecutionError(
            "one or more parallel generation calls stranded or failed validation"
        ) from errors[0]
    outcomes: list[JournalRecord] = []
    for call in prepared.plan:
        outcome = await _load_generation_success(
            prepared,
            authority,
            manifest,
            preflight_by_key[call.model.model_key],
            call,
        )
        if outcome is None:
            raise execute.DivergenceSuccessorExecutionError(
                "parallel generation did not produce the exact eight outcomes"
            )
        outcomes.append(outcome)
    return outcomes, 8


def _collect_secrets(
    prepared: execute.PreparedSuccessor, environment: Mapping[str, str]
) -> dict[str, str]:
    values: dict[str, str] = {}
    for call in prepared.plan:
        name = call.model.environment_variable
        secret = environment.get(name, "")
        if not isinstance(secret, str) or not secret:
            raise execute.DivergenceSuccessorExecutionError(
                f"missing required successor environment variable: {name}"
            )
        values[name] = secret
    return values


def _same_prepared(
    left: execute.PreparedSuccessor, right: execute.PreparedSuccessor
) -> bool:
    return (
        left.repository_root == right.repository_root
        and left.lock_context.lock == right.lock_context.lock
        and left.lock_context.lock_sha256 == right.lock_context.lock_sha256
        and left.lock_context.git_head == right.lock_context.git_head
        and left.config == right.config
        and left.question == right.question
        and left.plan == right.plan
        and left.paths == right.paths
    )


async def _load_or_publish_composite(
    prepared: execute.PreparedSuccessor,
    authority: Authority,
    manifest: JournalRecord,
    preflight_by_key: Mapping[str, JournalRecord],
    outcomes: list[JournalRecord],
) -> JournalRecord:
    from . import composite

    if prepared.paths.composite.exists():
        record = read_record(prepared.paths.composite, "successor composite")
        await composite.validate_composite_record(
            prepared,
            authority,
            record,
            manifest=manifest,
            preflight_by_key=preflight_by_key,
        )
        return record
    payload = composite.composite_payload(
        prepared,
        authorization_record=JournalRecord(
            authority.authorization.path,
            authority.authorization.payload,
            authority.authorization.sha256,
        ),
        pricing_recheck_record=JournalRecord(
            authority.pricing.path,
            authority.pricing.payload,
            authority.pricing.sha256,
        ),
        manifest_record=manifest,
        outcomes=outcomes,
        sealed_at=utc_now(),
    )
    return write_record(prepared.paths.composite, payload)


async def _execute_under_lock(
    prepared: execute.PreparedSuccessor,
    *,
    environment: Mapping[str, str],
    transport_factory: Callable[[], Transport],
) -> SuccessorExecutionResult:
    fresh = execute.prepare_successor(
        prepared.repository_root, require_committed=True
    )
    if not _same_prepared(prepared, fresh):
        raise execute.DivergenceSuccessorExecutionError(
            "successor lock, plan, or source bytes changed under execution"
        )
    inspect_inventory(fresh.paths)
    stale_authority = _authority(fresh, fresh=False)
    manifest, preflight_by_key = await _ensure_manifest_offline(
        fresh, stale_authority
    )
    if manifest is not None:
        if fresh.paths.composite.exists():
            outcomes = []
            for call in fresh.plan:
                outcome = await _load_generation_success(
                    fresh,
                    stale_authority,
                    manifest,
                    preflight_by_key[call.model.model_key],
                    call,
                )
                if outcome is None:
                    raise execute.DivergenceSuccessorExecutionError(
                        "composite exists before eight outcomes"
                    )
                outcomes.append(outcome)
            composite = await _load_or_publish_composite(
                fresh,
                stale_authority,
                manifest,
                preflight_by_key,
                outcomes,
            )
            return SuccessorExecutionResult(
                composite.path,
                composite.payload,
                composite.sha256,
                network_requests=0,
            )
        generation_states = [
            execute.cell_state(fresh.paths, "generation", key)["status"]
            for key in contract.MODEL_KEYS
        ]
        if any(status != "unstarted" for status in generation_states):
            outcomes, count = await _ensure_generations(
                fresh,
                stale_authority,
                manifest,
                preflight_by_key,
                secrets={},
                transport=_NeverTransport(),
            )
            if count:
                raise execute.DivergenceSuccessorExecutionError(
                    "offline reconciliation attempted a provider request"
                )
            composite = await _load_or_publish_composite(
                fresh,
                stale_authority,
                manifest,
                preflight_by_key,
                outcomes,
            )
            return SuccessorExecutionResult(
                composite.path,
                composite.payload,
                composite.sha256,
                network_requests=0,
            )
    fresh_authority = _authority(fresh, fresh=True)
    if fresh_authority != stale_authority:
        raise execute.DivergenceSuccessorExecutionError(
            "successor authority changed under the single-flight lock"
        )
    secrets = _collect_secrets(fresh, environment)
    transport = transport_factory()
    requests = 0
    if manifest is None:
        manifest, preflight_by_key, count = await _ensure_preflights(
            fresh,
            fresh_authority,
            secrets=secrets,
            transport=transport,
        )
        requests += count
    outcomes, count = await _ensure_generations(
        fresh,
        fresh_authority,
        manifest,
        preflight_by_key,
        secrets=secrets,
        transport=transport,
    )
    requests += count
    if requests > 16:
        raise execute.DivergenceSuccessorExecutionError(
            "successor outbound request ceiling exceeded"
        )
    composite = await _load_or_publish_composite(
        fresh,
        fresh_authority,
        manifest,
        preflight_by_key,
        outcomes,
    )
    return SuccessorExecutionResult(
        composite.path,
        composite.payload,
        composite.sha256,
        network_requests=requests,
    )


async def _execute_prepared(
    prepared: execute.PreparedSuccessor,
    *,
    environment: Mapping[str, str],
    transport_factory: Callable[[], Transport],
    sleep: Callable[[float], Awaitable[None]] | None = None,
) -> SuccessorExecutionResult:
    """Test seam using an injected environment and transport."""

    del sleep
    authorization.require_approval_enabled()
    _require_runtime(prepared)
    execute.verify_parent_snapshot(prepared.repository_root)
    async with phase_lock(
        prepared.paths.phase_lock, context=prepared.lock_context
    ):
        return await _execute_under_lock(
            prepared,
            environment=environment,
            transport_factory=transport_factory,
        )


async def execute_prepared(
    prepared: execute.PreparedSuccessor,
) -> SuccessorExecutionResult:
    """Execute with the process environment and real HTTPS transport."""

    authorization.require_approval_enabled()
    return await _execute_prepared(
        prepared,
        environment=os.environ,
        transport_factory=UrllibTransport,
    )


def load_live_successor(repository_root: Path | str) -> execute.PreparedSuccessor:
    authorization.require_approval_enabled()
    return execute.prepare_successor(repository_root, require_committed=True)


__all__ = (
    "Authority",
    "SuccessorExecutionResult",
    "_execute_prepared",
    "execute_prepared",
    "load_live_successor",
    "validate_generation_record",
    "validate_manifest_record",
)
