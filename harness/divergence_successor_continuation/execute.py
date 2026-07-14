"""One-shot, eight-way generation runtime for the corrected successor gate."""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, ROUND_CEILING
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping

from concordance_harness.config import returned_model_id_is_approved
from concordance_harness.execution import billed_output_tokens
from concordance_harness.planner import PlannedCall
from concordance_harness.providers import (
    ProviderAdapter,
    ProviderError,
    ProviderResult,
    Transport,
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
from divergence_successor import engine as parent_engine
from divergence_successor import execute as parent_execute
from rule3.budget import JournalRecord

from . import authorization, contract, correction, lock
from .state import ContinuationPaths, inspect_inventory, phase_lock
from .transport import NoRedirectHttpsTransport


GENERATION_INTENT_SCHEMA = "divergence-successor-continuation-generation-intent-1.0.0"
GENERATION_OUTCOME_SCHEMA = "divergence-successor-continuation-generation-outcome-1.0.0"


class ContinuationExecutionError(RuntimeError):
    """The continuation cannot safely enter or finish the provider boundary."""


@dataclass(frozen=True)
class PreparedContinuation:
    repository_root: Path
    lock_context: lock.LockContext
    parent: parent_execute.PreparedSuccessor
    parent_authority: parent_engine.Authority
    correction_record: JournalRecord
    paths: ContinuationPaths
    plan: tuple[PlannedCall, ...]


@dataclass(frozen=True)
class ContinuationExecutionResult:
    path: Path
    payload: dict[str, Any]
    sha256: str
    network_requests: int


class _NeverTransport:
    async def send(self, request: Any) -> Any:
        del request
        raise ContinuationExecutionError(
            "offline continuation attempted network access"
        )


class _AttemptCountingTransport:
    """Count an outbound attempt before the delegate can send or fail."""

    def __init__(self, delegate: Transport) -> None:
        self.delegate = delegate
        self.attempts = 0

    async def send(self, request: Any) -> Any:
        self.attempts += 1
        if self.attempts > 8:
            raise ContinuationExecutionError("continuation outbound ceiling exceeded")
        return await self.delegate.send(request)


def _record_binding(paths: ContinuationPaths, record: JournalRecord) -> dict[str, str]:
    try:
        return binding(paths.private_root, record).value()
    except RecoveryJournalError as error:
        raise ContinuationExecutionError(str(error)) from error


def _parsed_time(value: Any, label: str) -> datetime:
    try:
        require_timestamp(value, label)
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError, RecoveryJournalError) as error:
        raise ContinuationExecutionError(str(error)) from error


def _not_before(later: Any, later_label: str, earlier: Any, earlier_label: str) -> None:
    if _parsed_time(later, later_label) < _parsed_time(earlier, earlier_label):
        raise ContinuationExecutionError(
            f"chronology violation: {later_label} precedes {earlier_label}"
        )


def prepare_continuation(
    repository_root: Path | str,
    *,
    require_committed: bool = True,
    fresh_pricing: bool = False,
) -> PreparedContinuation:
    context = lock.load_and_validate_lock(
        repository_root, require_committed=require_committed
    )
    try:
        parent, parent_authority = correction.load_historical_parent(
            context.repository_root, fresh_pricing=fresh_pricing
        )
        corrected = correction.verify_correction_record(context.repository_root)
    except correction.OfflineCorrectionError as error:
        raise ContinuationExecutionError(str(error)) from error
    if (
        context.lock["parent"]["lock"]["sha256"] != parent.lock_context.lock_sha256
        or context.lock["parent"]["authorization"]["sha256"]
        != parent_authority.authorization.sha256
        or context.lock["parent"]["pricing_recheck"]["sha256"]
        != parent_authority.pricing.sha256
        or context.lock["offline_correction"]["sha256"] != corrected.sha256
        or context.lock["plans"] != parent.lock_context.lock["plans"]
        or context.lock["models"] != parent.lock_context.lock["models"]
        or tuple(call.model.model_key for call in parent.plan) != contract.MODEL_KEYS
    ):
        raise ContinuationExecutionError("continuation differs from its frozen parent")
    paths = ContinuationPaths.for_repository(context.repository_root)
    inspect_inventory(paths)
    return PreparedContinuation(
        context.repository_root,
        context,
        parent,
        parent_authority,
        corrected,
        paths,
        parent.plan,
    )


def _common(
    prepared: PreparedContinuation,
    paid: JournalRecord,
    *,
    model_key: str,
) -> dict[str, Any]:
    if not isinstance(prepared.lock_context.git_head, str):
        raise ContinuationExecutionError("continuation lacks a committed Git HEAD")
    return {
        "pool_id": contract.POOL_ID,
        "candidate_id": contract.CANDIDATE_ID,
        "git_head": prepared.lock_context.git_head,
        "lock_sha256": prepared.lock_context.lock_sha256,
        "authorization_receipt_sha256": paid.sha256,
        "historical_pricing_recheck_sha256": prepared.parent_authority.pricing.sha256,
        "offline_correction_sha256": prepared.correction_record.sha256,
        "original_lock_sha256": prepared.parent.lock_context.lock_sha256,
        "model_key": model_key,
        "semantic_attempt_number": 1,
    }


def _offline_request(call: PlannedCall) -> Any:
    request = ProviderAdapter(call.model, _NeverTransport()).build_generation_request(
        "redacted-offline-secret", call.answer_messages()
    )
    try:
        parent_engine._validate_request(call, request, "POST")
    except (RuntimeError, ValueError) as error:
        raise ContinuationExecutionError(str(error)) from error
    if request.method != "POST" or not isinstance(request.json_body, dict):
        raise ContinuationExecutionError("continuation request is not one JSON POST")
    return request


def _price(prepared: PreparedContinuation, model_key: str) -> dict[str, Any]:
    matches = [
        item
        for item in prepared.parent_authority.pricing.payload.get("prices", [])
        if isinstance(item, dict) and item.get("model_key") == model_key
    ]
    if len(matches) != 1:
        raise ContinuationExecutionError(f"historical pricing lacks {model_key}")
    return matches[0]


def _intent_payload(
    prepared: PreparedContinuation,
    paid: JournalRecord,
    call: PlannedCall,
    *,
    created_at: str,
) -> dict[str, Any]:
    try:
        require_timestamp(created_at, "continuation generation intent time")
    except RecoveryJournalError as error:
        raise ContinuationExecutionError(str(error)) from error
    _not_before(
        created_at,
        "generation intent time",
        prepared.correction_record.payload.get("corrected_at"),
        "offline correction time",
    )
    request = _offline_request(call)
    messages = call.answer_messages()
    price = _price(prepared, call.model.model_key)
    return {
        "schema_version": GENERATION_INTENT_SCHEMA,
        "status": "reserved-before-one-shot-generation-post",
        **_common(prepared, paid, model_key=call.model.model_key),
        "cell_id": call.cell_id,
        "model_family": call.model.family,
        "provider": call.model.provider,
        "route": call.model.route,
        "requested_model_id": call.model.requested_model_id,
        "attempt_number": 1,
        "reserved_cost_microdollars": price["reservation_microdollars"],
        "question_sha256": prepared.parent.question.sha256,
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
        "offline_correction": _record_binding(
            prepared.paths, prepared.correction_record
        ),
        "created_at": created_at,
    }


def _validate_intent(
    prepared: PreparedContinuation,
    paid: JournalRecord,
    call: PlannedCall,
    intent: JournalRecord,
) -> None:
    expected = _intent_payload(
        prepared, paid, call, created_at=intent.payload.get("created_at")
    )
    if (
        intent.path != prepared.paths.generation_intent(call.model.model_key)
        or intent.payload != expected
    ):
        raise ContinuationExecutionError(
            "generation intent differs from the frozen request"
        )


def _reject_generation_artifacts(model_key: str, value: Any) -> None:
    """Reject provider-specific evidence that an unrequested tool lane ran."""

    if not isinstance(value, Mapping):
        raise ContinuationExecutionError("generation response is not a JSON object")
    if model_key == "gemini":
        candidates = value.get("candidates")
        for candidate in candidates or []:
            if not isinstance(candidate, Mapping):
                continue
            if any(
                candidate.get(name) not in (None, False, "", [], {})
                for name in (
                    "groundingMetadata",
                    "urlContextMetadata",
                    "citationMetadata",
                )
            ):
                raise ContinuationExecutionError(
                    "Gemini returned grounding or citation artifacts"
                )
            content = candidate.get("content")
            parts = content.get("parts") if isinstance(content, Mapping) else []
            for part in parts or []:
                if isinstance(part, Mapping) and any(
                    part.get(name) not in (None, False, "", [], {})
                    for name in (
                        "functionCall",
                        "functionResponse",
                        "executableCode",
                        "codeExecutionResult",
                    )
                ):
                    raise ContinuationExecutionError("Gemini returned a tool artifact")
    elif model_key == "claude":
        for block in value.get("content") or []:
            if isinstance(block, Mapping) and block.get("type") in {
                "tool_use",
                "server_tool_use",
                "web_search_tool_result",
            }:
                raise ContinuationExecutionError("Claude returned a tool artifact")
    elif model_key == "cohere":
        message = value.get("message")
        if isinstance(message, Mapping) and any(
            message.get(name) not in (None, False, "", [], {})
            for name in ("tool_calls", "citations", "documents", "search_results")
        ):
            raise ContinuationExecutionError(
                "Cohere returned a tool or retrieval artifact"
            )
    elif model_key == "grok":
        for item in value.get("output") or []:
            if isinstance(item, Mapping) and item.get("type") not in {
                "message",
                "reasoning",
            }:
                raise ContinuationExecutionError(
                    "Grok returned a non-message tool artifact"
                )
    else:
        for choice in value.get("choices") or []:
            message = choice.get("message") if isinstance(choice, Mapping) else None
            if isinstance(message, Mapping) and any(
                message.get(name) not in (None, False, "", [], {})
                for name in ("tool_calls", "function_call", "annotations", "citations")
            ):
                raise ContinuationExecutionError(
                    f"{model_key} returned a tool or citation artifact"
                )
            if isinstance(choice, Mapping) and choice.get("finish_reason") in {
                "tool_calls",
                "function_call",
            }:
                raise ContinuationExecutionError(f"{model_key} stopped for tool use")
    try:
        parent_execute.reject_tool_artifacts(value, path=f"generation_raw[{model_key}]")
    except parent_execute.DivergenceSuccessorExecutionError as error:
        raise ContinuationExecutionError(str(error)) from error


async def _parse_capture(
    prepared: PreparedContinuation,
    paid: JournalRecord,
    call: PlannedCall,
    intent: JournalRecord,
    raw: JournalRecord,
) -> ProviderResult:
    request = _offline_request(call)
    common = _common(prepared, paid, model_key=call.model.model_key)
    try:
        response = validate_raw_response(
            raw,
            expected_common=common,
            expected_intent=intent,
            private_root=prepared.paths.private_root,
            request_kind="generation",
            expected_request=request,
        )
        _reject_generation_artifacts(call.model.model_key, response.json())
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
    except ContinuationExecutionError:
        raise
    except (RecoveryJournalError, ProviderError, ValueError) as error:
        if isinstance(error, ProviderError):
            raise
        raise ProviderError(
            "captured continuation response failed validation",
            category="response-validation",
            retryable=False,
        ) from error
    returned = result.returned_model_id
    if call.model.model_key == "cohere":
        if returned is not None and not returned_model_id_is_approved(
            call.model, returned
        ):
            raise ProviderError(
                "Cohere returned another model",
                category="response-validation",
                retryable=False,
            )
    elif returned is None or not returned_model_id_is_approved(call.model, returned):
        raise ProviderError(
            "generation response lacks the approved model identity",
            category="response-validation",
            retryable=False,
        )
    return result


def _error(error: BaseException) -> dict[str, Any]:
    category = (
        error.category if isinstance(error, ProviderError) else "response-validation"
    )
    return {
        "category": category,
        "retryable": False,
        "sanitized_summary": f"generation request failed ({category})",
    }


def _outcome_payload(
    prepared: PreparedContinuation,
    paid: JournalRecord,
    call: PlannedCall,
    intent: JournalRecord,
    raw: JournalRecord,
    *,
    result: ProviderResult | None,
    error: dict[str, Any] | None,
    latency_ms: int,
    completed_at: str,
) -> dict[str, Any]:
    _not_before(
        completed_at,
        "generation completion time",
        intent.payload["created_at"],
        "intent time",
    )
    _not_before(
        completed_at,
        "generation completion time",
        raw.payload["received_at"],
        "raw response time",
    )
    if (
        not isinstance(latency_ms, int)
        or isinstance(latency_ms, bool)
        or latency_ms < 0
    ):
        raise ContinuationExecutionError("generation latency is malformed")
    value: dict[str, Any] = {
        "schema_version": GENERATION_OUTCOME_SCHEMA,
        "status": "success" if result is not None else "error",
        **_common(prepared, paid, model_key=call.model.model_key),
        "cell_id": call.cell_id,
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
        "offline_correction": intent.payload["offline_correction"],
        "intent": _record_binding(prepared.paths, intent),
        "raw_response": _record_binding(prepared.paths, raw),
        "attempted_at": intent.payload["created_at"],
        "completed_at": completed_at,
        "latency_ms": latency_ms,
    }
    if result is None:
        return {**value, "error": error}
    usage = result.usage
    input_tokens = usage.get("input_tokens")
    if input_tokens is None:
        input_tokens = estimate_message_tokens(call.answer_messages())
    output_tokens = billed_output_tokens(call.model, usage, result.response_text)
    price = _price(prepared, call.model.model_key)
    actual = int(
        (
            Decimal(input_tokens) * Decimal(str(price["input_per_million"]))
            + Decimal(output_tokens) * Decimal(str(price["output_per_million"]))
        ).to_integral_value(rounding=ROUND_CEILING)
    )
    return {
        **value,
        "result": {
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
                "pricing_checked_at": prepared.parent_authority.pricing.payload[
                    "checked_at"
                ],
            },
        },
    }


async def _validate_outcome(
    prepared: PreparedContinuation,
    paid: JournalRecord,
    call: PlannedCall,
    intent: JournalRecord,
    raw: JournalRecord,
    outcome: JournalRecord,
) -> ProviderResult | None:
    _validate_intent(prepared, paid, call, intent)
    try:
        result = await _parse_capture(prepared, paid, call, intent, raw)
    except (ProviderError, ContinuationExecutionError) as error:
        result = None
        expected = _outcome_payload(
            prepared,
            paid,
            call,
            intent,
            raw,
            result=None,
            error=_error(error),
            latency_ms=outcome.payload.get("latency_ms"),
            completed_at=outcome.payload.get("completed_at"),
        )
    else:
        expected = _outcome_payload(
            prepared,
            paid,
            call,
            intent,
            raw,
            result=result,
            error=None,
            latency_ms=outcome.payload.get("latency_ms"),
            completed_at=outcome.payload.get("completed_at"),
        )
    if (
        outcome.path != prepared.paths.generation_outcome(call.model.model_key)
        or outcome.payload != expected
    ):
        raise ContinuationExecutionError(
            f"generation outcome changed for {call.model.model_key}"
        )
    return result


async def _finalize(
    prepared: PreparedContinuation,
    paid: JournalRecord,
    call: PlannedCall,
    intent: JournalRecord,
    raw: JournalRecord,
    *,
    latency_ms: int,
) -> JournalRecord:
    try:
        result = await _parse_capture(prepared, paid, call, intent, raw)
    except (ProviderError, ContinuationExecutionError) as error:
        result = None
        error_value = _error(error)
    else:
        error_value = None
    try:
        return write_record(
            prepared.paths.generation_outcome(call.model.model_key),
            _outcome_payload(
                prepared,
                paid,
                call,
                intent,
                raw,
                result=result,
                error=error_value,
                latency_ms=latency_ms,
                completed_at=utc_now(),
            ),
        )
    except RecoveryJournalError as error:
        raise ContinuationExecutionError(str(error)) from error


def cell_state(paths: ContinuationPaths, model_key: str) -> str:
    present = (
        paths.generation_intent(model_key).exists(),
        paths.generation_raw(model_key).exists(),
        paths.generation_outcome(model_key).exists(),
    )
    states = {
        (False, False, False): "unstarted",
        (True, False, False): "stranded",
        (True, True, False): "captured",
        (True, True, True): "terminal",
    }
    if present not in states:
        raise ContinuationExecutionError(f"impossible journal ordering for {model_key}")
    return states[present]


async def _load_success(
    prepared: PreparedContinuation,
    paid: JournalRecord,
    call: PlannedCall,
) -> JournalRecord | None:
    state = cell_state(prepared.paths, call.model.model_key)
    if state == "unstarted":
        return None
    intent = read_record(
        prepared.paths.generation_intent(call.model.model_key),
        f"continuation intent {call.model.model_key}",
    )
    _validate_intent(prepared, paid, call, intent)
    if state == "stranded":
        raise StrandedGenerationIntent(
            f"continuation intent is consumed without a response: {call.cell_id}"
        )
    raw = read_record(
        prepared.paths.generation_raw(call.model.model_key),
        f"continuation raw response {call.model.model_key}",
    )
    if state == "captured":
        outcome = await _finalize(prepared, paid, call, intent, raw, latency_ms=0)
    else:
        outcome = read_record(
            prepared.paths.generation_outcome(call.model.model_key),
            f"continuation outcome {call.model.model_key}",
        )
    result = await _validate_outcome(prepared, paid, call, intent, raw, outcome)
    if result is None:
        raise ContinuationExecutionError(
            f"terminal generation failure; no retry allowed: {call.model.model_key}"
        )
    return outcome


async def _send(
    prepared: PreparedContinuation,
    paid: JournalRecord,
    call: PlannedCall,
    intent: JournalRecord,
    *,
    secret: str,
    transport: Transport,
    expected_request: Any,
) -> JournalRecord:
    capture = DurableCaptureTransport(
        transport,
        capture_path=prepared.paths.generation_raw(call.model.model_key),
        private_root=prepared.paths.private_root,
        common=_common(prepared, paid, model_key=call.model.model_key),
        intent=intent,
        request_kind="generation",
        expected_request=expected_request,
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
            f"continuation request has no durable response: {call.cell_id}"
        )
    return await _finalize(
        prepared,
        paid,
        call,
        intent,
        raw,
        latency_ms=int((time.monotonic() - started) * 1000),
    )


def _collect_secrets(
    prepared: PreparedContinuation, environment: Mapping[str, str]
) -> dict[str, str]:
    values: dict[str, str] = {}
    for call in prepared.plan:
        name = call.model.environment_variable
        value = environment.get(name, "")
        if not isinstance(value, str) or not value:
            raise ContinuationExecutionError(
                f"missing required environment variable: {name}"
            )
        values[name] = value
    if len(values) != 8:
        raise ContinuationExecutionError(
            "continuation requires exactly eight credentials"
        )
    return values


def _same(left: PreparedContinuation, right: PreparedContinuation) -> bool:
    return (
        left.lock_context.lock == right.lock_context.lock
        and left.lock_context.lock_sha256 == right.lock_context.lock_sha256
        and left.lock_context.git_head == right.lock_context.git_head
        and left.parent.lock_context.lock == right.parent.lock_context.lock
        and left.parent.lock_context.git_head == right.parent.lock_context.git_head
        and left.parent_authority == right.parent_authority
        and left.correction_record == right.correction_record
        and left.plan == right.plan
        and left.paths == right.paths
    )


async def _publish_composite(
    prepared: PreparedContinuation,
    paid: JournalRecord,
    outcomes: list[JournalRecord],
) -> JournalRecord:
    from . import composite

    if prepared.paths.composite.exists():
        record = read_record(prepared.paths.composite, "continuation composite")
        await composite.validate_composite_record(prepared, paid, record)
        return record
    payload = composite.composite_payload(
        prepared,
        authorization_record=paid,
        outcomes=outcomes,
        sealed_at=utc_now(),
    )
    return write_record(prepared.paths.composite, payload)


async def _under_lock(
    prepared: PreparedContinuation,
    *,
    environment: Mapping[str, str],
    transport_factory: Callable[[], Transport],
) -> ContinuationExecutionResult:
    fresh = prepare_continuation(prepared.repository_root, require_committed=True)
    if not _same(prepared, fresh):
        raise ContinuationExecutionError("continuation sources changed under lock")
    paid = authorization.validate_authorization(fresh.lock_context)
    states = [cell_state(fresh.paths, key) for key in contract.MODEL_KEYS]
    if fresh.paths.composite.exists() or any(state != "unstarted" for state in states):
        if any(state == "unstarted" for state in states):
            raise ContinuationExecutionError(
                "partial continuation state cannot reopen an unstarted paid cell"
            )
        outcomes: list[JournalRecord] = []
        for call in fresh.plan:
            outcome = await _load_success(fresh, paid, call)
            if outcome is None:
                raise ContinuationExecutionError(
                    "continuation reconciliation is incomplete"
                )
            outcomes.append(outcome)
        record = await _publish_composite(fresh, paid, outcomes)
        return ContinuationExecutionResult(
            record.path, record.payload, record.sha256, 0
        )

    # The final pre-POST gate repeats every historical, correction, price,
    # authority, request, and inventory check while both single-flight locks are held.
    priced_parent, priced_authority = authorization.validate_fresh_historical_pricing(
        fresh.lock_context
    )
    fresh_priced = prepare_continuation(
        fresh.repository_root, require_committed=True, fresh_pricing=True
    )
    if (
        priced_parent.lock_context != fresh_priced.parent.lock_context
        or priced_authority != fresh_priced.parent_authority
        or fresh_priced.correction_record != fresh.correction_record
    ):
        raise ContinuationExecutionError("fresh pricing or historical evidence changed")
    paid = authorization.validate_authorization(fresh_priced.lock_context)
    secrets = _collect_secrets(fresh_priced, environment)
    requests: dict[str, Any] = {}
    for call in fresh_priced.plan:
        _offline_request(call)
        request = ProviderAdapter(
            call.model, _NeverTransport()
        ).build_generation_request(
            secrets[call.model.environment_variable], call.answer_messages()
        )
        parent_engine._validate_request(call, request, "POST")
        requests[call.model.model_key] = request
    if tuple(requests) != contract.MODEL_KEYS:
        raise ContinuationExecutionError("exact eight-request panel was not prepared")
    intents: dict[str, JournalRecord] = {}
    for call in fresh_priced.plan:
        intents[call.model.model_key] = write_record(
            fresh_priced.paths.generation_intent(call.model.model_key),
            _intent_payload(fresh_priced, paid, call, created_at=utc_now()),
        )
    counting = _AttemptCountingTransport(transport_factory())
    results = await asyncio.gather(
        *(
            _send(
                fresh_priced,
                paid,
                call,
                intents[call.model.model_key],
                secret=secrets[call.model.environment_variable],
                transport=counting,
                expected_request=requests[call.model.model_key],
            )
            for call in fresh_priced.plan
        ),
        return_exceptions=True,
    )
    if counting.attempts != 8:
        raise ContinuationExecutionError(
            f"parallel continuation attempted {counting.attempts} requests, expected 8"
        )
    errors = [item for item in results if isinstance(item, BaseException)]
    if errors:
        raise ContinuationExecutionError(
            "one or more one-shot generation cells failed; no retry is allowed"
        ) from errors[0]
    outcomes = []
    for call in fresh_priced.plan:
        outcome = await _load_success(fresh_priced, paid, call)
        if outcome is None:
            raise ContinuationExecutionError(
                "parallel generation did not complete all cells"
            )
        outcomes.append(outcome)
    record = await _publish_composite(fresh_priced, paid, outcomes)
    return ContinuationExecutionResult(record.path, record.payload, record.sha256, 8)


async def _execute_prepared(
    prepared: PreparedContinuation,
    *,
    environment: Mapping[str, str],
    transport_factory: Callable[[], Transport],
    sleep: Callable[[float], Awaitable[None]] | None = None,
) -> ContinuationExecutionResult:
    del sleep
    contract.require_approval()
    authorization.validate_authorization(prepared.lock_context)
    async with phase_lock(
        prepared.paths,
        validate_authority=lambda: authorization.validate_authorization(
            prepared.lock_context
        ),
    ):
        return await _under_lock(
            prepared,
            environment=environment,
            transport_factory=transport_factory,
        )


async def execute_prepared(
    prepared: PreparedContinuation,
) -> ContinuationExecutionResult:
    return await _execute_prepared(
        prepared,
        environment=os.environ,
        transport_factory=NoRedirectHttpsTransport,
    )


async def execute_live(repository_root: Path | str) -> ContinuationExecutionResult:
    prepared = prepare_continuation(repository_root, require_committed=True)
    return await execute_prepared(prepared)


def execution_readiness(repository_root: Path | str) -> dict[str, Any]:
    issues: list[str] = []
    try:
        prepared = prepare_continuation(repository_root, require_committed=True)
        authorization.validate_authorization(prepared.lock_context)
    except (OSError, RuntimeError, ValueError) as error:
        issues.append(str(error))
    return {
        "status": "ready-for-eight-generation-posts" if not issues else "blocked",
        "issues": issues,
        "model_keys": list(contract.MODEL_KEYS),
        "metadata_requests_planned": 0,
        "generation_posts_planned": 8,
        "automatic_retries": 0,
        "network_requests": 0,
        "environment_variables_read": 0,
        "private_writes": 0,
    }


__all__ = (
    "ContinuationExecutionError",
    "ContinuationExecutionResult",
    "PreparedContinuation",
    "_execute_prepared",
    "cell_state",
    "execute_live",
    "execute_prepared",
    "execution_readiness",
    "prepare_continuation",
)
