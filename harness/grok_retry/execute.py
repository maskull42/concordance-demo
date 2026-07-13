"""Execute the one-call xAI Grok retry and gated GPT continuation."""

from __future__ import annotations

import asyncio
import json
import os
import stat
import time
from dataclasses import dataclass
from decimal import Decimal, ROUND_CEILING
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping

from concordance_harness.execution import RateLimiter, billed_output_tokens
from concordance_harness.planner import PlannedCall
from concordance_harness.providers import (
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
    binding,
    read_record,
    require_timestamp,
    write_record,
)
from concordance_recovery.state import phase_lock as first_phase_lock
from concordance_recovery.transport import (
    CapturedReplayTransport,
    DurableCaptureTransport,
)
from qwen_successor import contract as qwen_contract
from qwen_successor import execute as qwen_execute
from qwen_successor.state import (
    SuccessorPaths as QwenSuccessorPaths,
    phase_lock as qwen_phase_lock,
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
from .state import GrokRetryPaths, phase_lock


GENERATION_INTENT_SCHEMA = "concordance-grok-retry-generation-intent-1.0.0"
GENERATION_OUTCOME_SCHEMA = "concordance-grok-retry-generation-outcome-1.0.0"
CLAIM_SCHEMA = "concordance-grok-retry-claim-1.0.0"
COMPOSITE_SCHEMA = "concordance-grok-retry-composite-1.0.0"
SAFE_RETRY_CATEGORIES = {"invalid-request", "provider-error", "rate-limit"}
_TOOL_ARTIFACT_KEYS = {
    "annotations",
    "citations",
    "code_interpreter_call",
    "computer_call",
    "file_search_call",
    "function_call",
    "function_calls",
    "search_results",
    "sources",
    "tool_call",
    "tool_calls",
    "web_search_call",
}
_TOOL_ARTIFACT_TYPES = (
    "citation",
    "code_interpreter",
    "computer_call",
    "file_search",
    "function_call",
    "tool_call",
    "web_search",
)


class GrokRetryExecutionError(RuntimeError):
    pass


@dataclass(frozen=True)
class PreparedRetry:
    repository_root: Path
    lock_context: LockContext
    qwen_prepared: qwen_execute.PreparedSuccessor
    target_plan: tuple[PlannedCall, PlannedCall]
    target_by_key: dict[str, PlannedCall]
    paths: GrokRetryPaths

    @property
    def config(self) -> Any:
        return self.qwen_prepared.config

    @property
    def question(self) -> Any:
        return self.qwen_prepared.question


@dataclass(frozen=True)
class Authority:
    authorization: ReceiptBinding
    pricing: ReceiptBinding
    claim: Any | None = None


@dataclass(frozen=True)
class RetryResult:
    path: Path
    payload: dict[str, Any]
    sha256: str
    network_requests: int


class _NeverTransport:
    async def send(self, request: Any) -> Any:
        del request
        raise GrokRetryExecutionError("offline request builder attempted network")


def _has_tool_artifact(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = str(key).casefold().replace("-", "_")
            if normalized in _TOOL_ARTIFACT_KEYS and item not in (None, [], {}):
                return True
            if normalized == "type" and isinstance(item, str):
                kind = item.casefold().replace("-", "_")
                if any(fragment in kind for fragment in _TOOL_ARTIFACT_TYPES):
                    return True
            if _has_tool_artifact(item):
                return True
        return False
    if isinstance(value, (list, tuple)):
        return any(_has_tool_artifact(item) for item in value)
    return False


def _valid_usage(result: ProviderResult) -> bool:
    usage = result.usage
    values = (
        usage.get("input_tokens"),
        usage.get("output_tokens"),
        usage.get("total_tokens"),
    )
    if any(
        not isinstance(value, int) or isinstance(value, bool) or value < 0
        for value in values
    ):
        return False
    input_tokens, output_tokens, total_tokens = values
    return output_tokens > 0 and total_tokens >= input_tokens + output_tokens


class _RetryAdapter(ProviderAdapter):
    def _parse_generation(self, raw: dict[str, Any]) -> ProviderResult:
        if _has_tool_artifact(raw):
            raise ProviderError(
                "provider response contains a forbidden tool or retrieval artifact",
                category="response-validation",
                retryable=False,
            )
        result = super()._parse_generation(raw)
        if not _valid_usage(result):
            raise ProviderError(
                "provider response has invalid usage fields",
                category="response-validation",
                retryable=False,
            )
        if self.config.model_key == "gpt" and (
            result.provider_name is None or result.provider_name.casefold() != "openai"
        ):
            raise ProviderError(
                "OpenRouter GPT response does not identify the pinned OpenAI provider",
                category="response-validation",
                retryable=False,
            )
        return result


def _attempt_range(model_key: str) -> tuple[int, ...]:
    if model_key == "grok":
        return (contract.GROK_SEMANTIC_ATTEMPT_NUMBER,)
    if model_key == "gpt":
        return tuple(range(1, contract.GPT_MAXIMUM_SAFE_ATTEMPTS + 1))
    raise GrokRetryExecutionError("generation requested outside the Grok retry lane")


def prepare_retry(
    repository_root: Path | str, *, require_committed: bool
) -> PreparedRetry:
    root = Path(repository_root).resolve()
    context = load_lock(
        root,
        require_committed=require_committed,
        require_parent_private=require_committed,
    )
    qwen = qwen_execute.prepare_successor(root, require_committed=require_committed)
    target = tuple(qwen.target_by_key[key] for key in contract.TARGET_MODEL_KEYS)
    if tuple(call.model.model_key for call in target) != contract.TARGET_MODEL_KEYS:
        raise GrokRetryExecutionError("Grok retry target order changed")
    locked = context.lock.get("target_plan")
    cells = locked.get("cells") if isinstance(locked, dict) else None
    if not isinstance(cells, list) or len(cells) != len(target):
        raise GrokRetryExecutionError("locked Grok retry target plan is malformed")
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
            raise GrokRetryExecutionError(f"locked retry cell changed for {key}")
    grok, gpt = target
    if (
        grok.model.provider != "xai"
        or grok.model.route != "xai-direct"
        or grok.model.requested_model_id != "grok-4.5"
        or grok.model.fallback_allowed
        or gpt.model.provider != "openrouter"
        or gpt.model.route != "openrouter-openai-pinned"
        or gpt.model.requested_model_id != "openai/gpt-5.6-sol"
        or gpt.model.fallback_allowed
        or gpt.model.provider_options
        != {
            "service_tier": "default",
            "provider": {
                "only": ["openai"],
                "allow_fallbacks": False,
                "require_parameters": True,
            },
        }
    ):
        raise GrokRetryExecutionError("locked direct Grok or pinned GPT route changed")
    return PreparedRetry(
        repository_root=root,
        lock_context=context,
        qwen_prepared=qwen,
        target_plan=(grok, gpt),
        target_by_key={call.model.model_key: call for call in target},
        paths=GrokRetryPaths.for_repository(root),
    )


def dry_run_summary(prepared: PreparedRetry) -> dict[str, Any]:
    return {
        "recovery_id": contract.RECOVERY_ID,
        "candidate_id": contract.CANDIDATE_ID,
        "preserved_model_keys": list(contract.PRESERVED_MODEL_KEYS),
        "target_model_keys": list(contract.TARGET_MODEL_KEYS),
        "reused_preflight_route_keys": list(contract.PREFLIGHT_ROUTE_KEYS),
        "fresh_metadata_requests": 0,
        "grok_semantic_attempt_number": contract.GROK_SEMANTIC_ATTEMPT_NUMBER,
        "grok_maximum_posts": contract.GROK_MAXIMUM_POSTS,
        "gpt_maximum_safe_attempts": contract.GPT_MAXIMUM_SAFE_ATTEMPTS,
        "maximum_generation_posts": contract.MAX_GENERATION_POSTS,
        "maximum_outbound_requests": contract.MAX_OUTBOUND_REQUESTS,
        "network_requests": 0,
        "environment_variables_read": 0,
    }


def _authority(prepared: PreparedRetry, *, fresh: bool) -> Authority:
    return Authority(
        validate_authorization(prepared.lock_context),
        validate_pricing_recheck(prepared.lock_context, require_fresh=fresh),
    )


def _common(prepared: PreparedRetry, authority: Authority) -> dict[str, Any]:
    head = prepared.lock_context.git_head
    if not isinstance(head, str):
        raise GrokRetryExecutionError("live Grok retry lacks a committed Git HEAD")
    result = {
        "recovery_id": contract.RECOVERY_ID,
        "pool_id": contract.POOL_ID,
        "candidate_id": contract.CANDIDATE_ID,
        "phase": contract.PHASE,
        "git_head": head,
        "grok_retry_lock_sha256": prepared.lock_context.lock_sha256,
        "authorization_receipt_sha256": authority.authorization.sha256,
        "pricing_recheck_receipt_sha256": authority.pricing.sha256,
        "qwen_successor_lock_sha256": contract.QWEN_LOCK_SHA256,
        "first_recovery_lock_sha256": contract.FIRST_LOCK_SHA256,
        "rule3_lock_sha256": contract.RULE3_LOCK_SHA256,
    }
    if authority.claim is not None:
        result["grok_parent_claim"] = binding(
            prepared.repository_root, authority.claim
        ).value()
    return result


def _claim_payload(
    prepared: PreparedRetry,
    authority: Authority,
    parent: ParentEvidence,
    *,
    claimed_at: str,
) -> dict[str, Any]:
    require_timestamp(claimed_at, "Grok retry claim time")
    return {
        "schema_version": CLAIM_SCHEMA,
        "status": "captured-grok-error-claimed-once",
        **_common(prepared, authority),
        "parent_manifest": _parent_binding(parent, parent.parent_manifest),
        "grok_attempt_1": {
            "intent": _parent_binding(parent, parent.grok_error_intent),
            "raw_response": _parent_binding(parent, parent.grok_error_raw),
            "outcome": _parent_binding(parent, parent.grok_error_outcome),
            "disposition": "captured-403-consumed-user-authorized-one-xai-retry",
        },
        "replacement_semantic_attempt_number": 2,
        "claimed_at": claimed_at,
    }


def _validate_claim_inventory(prepared: PreparedRetry, *, claimed: bool) -> None:
    root = prepared.paths.claim.parent
    try:
        root_metadata = root.lstat()
    except OSError as error:
        raise GrokRetryExecutionError(
            f"Grok retry claim root cannot be inspected: {error}"
        ) from error
    if (
        stat.S_ISLNK(root_metadata.st_mode)
        or not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
    ):
        raise GrokRetryExecutionError(
            "Grok retry claim root must be a real mode-0700 directory"
        )
    expected = {prepared.paths.phase_lock.resolve()}
    if claimed:
        expected.add(prepared.paths.claim.resolve())
    actual = set()
    for path in root.iterdir():
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise GrokRetryExecutionError("Grok retry claim inventory changed")
        if path == prepared.paths.phase_lock and metadata.st_size != 0:
            raise GrokRetryExecutionError("Grok retry phase lock changed")
        actual.add(path.resolve())
    if actual != expected:
        raise GrokRetryExecutionError("Grok retry claim inventory changed")


def _ensure_claim(
    prepared: PreparedRetry, authority: Authority, parent: ParentEvidence
) -> Any:
    path = prepared.paths.claim
    if path.exists():
        _validate_claim_inventory(prepared, claimed=True)
        record = read_record(path, "Grok retry parent claim")
        expected = _claim_payload(
            prepared,
            authority,
            parent,
            claimed_at=record.payload.get("claimed_at"),
        )
        if record.payload != expected:
            raise GrokRetryExecutionError("Grok parent claim changed")
        _validate_claim_inventory(prepared, claimed=True)
        return record
    _validate_claim_inventory(prepared, claimed=False)
    allowed = {
        prepared.paths.private_root / "paid-authorization.json",
        prepared.paths.private_root / "pricing-evidence.json",
        prepared.paths.private_root / "pricing-recheck.json",
    }
    if prepared.paths.private_root.exists() and any(
        item.is_file() and item.resolve() not in {value.resolve() for value in allowed}
        for item in prepared.paths.private_root.rglob("*")
    ):
        raise GrokRetryExecutionError("retry state cannot precede its Grok claim")
    record = write_record(
        path,
        _claim_payload(prepared, authority, parent, claimed_at=utc_now()),
    )
    _validate_claim_inventory(prepared, claimed=True)
    return record


def _with_claim(authority: Authority, claim: Any) -> Authority:
    return Authority(authority.authorization, authority.pricing, claim)


def _record_binding(prepared: PreparedRetry, record: Any) -> dict[str, str]:
    return binding(prepared.paths.private_root, record).value()


def _parent_binding(parent: ParentEvidence, record: Any) -> dict[str, str]:
    return binding(parent.private_root, record).value()


def _parent_preflight(parent: ParentEvidence, model_key: str) -> Any:
    expected_path = {
        "grok": contract.GROK_PREFLIGHT_OUTCOME_PATH,
        "gpt": contract.GPT_PREFLIGHT_OUTCOME_PATH,
    }.get(model_key)
    expected_sha = {
        "grok": contract.GROK_PREFLIGHT_OUTCOME_SHA256,
        "gpt": contract.GPT_PREFLIGHT_OUTCOME_SHA256,
    }.get(model_key)
    if expected_path is None or expected_sha is None:
        raise GrokRetryExecutionError("preflight requested outside the retry target")
    record = read_record(
        parent.private_root / expected_path, f"parent {model_key} preflight"
    )
    if (
        record.sha256 != expected_sha
        or record.payload.get("status") != "success"
        or record.payload.get("model_key") != model_key
        or record.payload.get("requested_model_id")
        != ("grok-4.5" if model_key == "grok" else "openai/gpt-5.6-sol")
    ):
        raise GrokRetryExecutionError(
            f"sealed parent preflight changed for {model_key}"
        )
    return record


def _raw_common(
    prepared: PreparedRetry, authority: Authority, model_key: str, attempt: int
) -> dict[str, Any]:
    return {
        **_common(prepared, authority),
        "model_key": model_key,
        "semantic_attempt_number": attempt,
    }


def _generation_request(call: PlannedCall, secret: str) -> Any:
    return _RetryAdapter(call.model, _NeverTransport()).build_generation_request(
        secret, call.answer_messages()
    )


def _generation_intent_payload(
    prepared: PreparedRetry,
    authority: Authority,
    parent: ParentEvidence,
    call: PlannedCall,
    attempt: int,
    *,
    created_at: str,
) -> dict[str, Any]:
    require_timestamp(created_at, "Grok retry generation intent time")
    messages = call.answer_messages()
    request = _generation_request(call, "redacted-offline-secret")
    request_hash = sha256_bytes(
        json.dumps(request.json_body, ensure_ascii=False).encode("utf-8")
    )
    if call.model.model_key == "grok":
        parent_value = parent.grok_error_intent.payload
        exact = {
            "prompt_sha256": prompt_sha256(messages),
            "messages_sha256": sha256_bytes(canonical_json_bytes(messages)),
            "requested_params_sha256": sha256_bytes(
                canonical_json_bytes(call.model.requested_params_receipt())
            ),
            "request_json_body_sha256": request_hash,
        }
        if (
            attempt != contract.GROK_SEMANTIC_ATTEMPT_NUMBER
            or exact
            != {
                "prompt_sha256": contract.GROK_PROMPT_SHA256,
                "messages_sha256": contract.GROK_MESSAGES_SHA256,
                "requested_params_sha256": contract.GROK_REQUESTED_PARAMS_SHA256,
                "request_json_body_sha256": contract.GROK_REQUEST_BODY_SHA256,
            }
            or any(parent_value.get(key) != value for key, value in exact.items())
            or not isinstance(request.json_body, dict)
            or request.json_body.get("tools") != []
            or set(request.json_body)
            != {
                "model",
                "input",
                "max_output_tokens",
                "tools",
                "store",
                "service_tier",
                "temperature",
            }
        ):
            raise GrokRetryExecutionError(
                "Grok retry request differs from the consumed xAI request"
            )
        replacement = {
            "intent": _parent_binding(parent, parent.grok_error_intent),
            "raw_response": _parent_binding(parent, parent.grok_error_raw),
            "outcome": _parent_binding(parent, parent.grok_error_outcome),
            "disposition": "captured-403-consumed-user-authorized-one-xai-retry",
        }
    else:
        replacement = None
    preflight = _parent_preflight(parent, call.model.model_key)
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
        "parent_manifest": _parent_binding(parent, parent.parent_manifest),
        "preflight_outcome": _parent_binding(parent, preflight),
        "replacement_of_parent_attempt": replacement,
        "created_at": created_at,
    }


def _error(error: ProviderError, *, allow_retry: bool) -> dict[str, Any]:
    return {
        "category": error.category,
        "retryable": bool(
            allow_retry and error.retryable and error.category in SAFE_RETRY_CATEGORIES
        ),
        "sanitized_summary": f"generation request failed ({error.category})",
    }


async def _parse_generation(
    prepared: PreparedRetry,
    authority: Authority,
    call: PlannedCall,
    intent: Any,
    raw: Any,
) -> ProviderResult:
    request = _generation_request(call, "redacted-offline-secret")
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
    result = await _RetryAdapter(call.model, replay).generate(
        "redacted-offline-secret", call.answer_messages()
    )
    if result.returned_model_id is None:
        raise ProviderError(
            "generation response lacks exact returned model identity",
            category="response-validation",
            retryable=False,
        )
    _RetryAdapter(call.model, _NeverTransport()).assert_model_identity(
        result.returned_model_id
    )
    return result


def _generation_outcome_payload(
    prepared: PreparedRetry,
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
        "parent_manifest": intent.payload["parent_manifest"],
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
    prepared: PreparedRetry,
    authority: Authority,
    call: PlannedCall,
    intent: Any,
    *,
    completed_at: str,
) -> dict[str, Any]:
    attempt = intent.payload.get("semantic_attempt_number")
    if attempt not in _attempt_range(call.model.model_key):
        raise GrokRetryExecutionError("no-capture attempt is outside the locked range")
    return {
        "schema_version": GENERATION_OUTCOME_SCHEMA,
        "status": "consumed-without-capture",
        **_common(prepared, authority),
        "cell_id": call.cell_id,
        "model_key": call.model.model_key,
        "model_family": call.model.family,
        "provider": call.model.provider,
        "route": call.model.route,
        "requested_model_id": call.model.requested_model_id,
        "semantic_attempt_number": attempt,
        "question_sha256": intent.payload["question_sha256"],
        "prompt_sha256": intent.payload["prompt_sha256"],
        "messages_sha256": intent.payload["messages_sha256"],
        "requested_params_sha256": intent.payload["requested_params_sha256"],
        "parent_manifest": intent.payload["parent_manifest"],
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
            "replay_allowed": False,
            "later_attempt_allowed": False,
        },
    }


def _generation_history(
    prepared: PreparedRetry,
    authority: Authority,
    parent: ParentEvidence,
    call: PlannedCall,
) -> list[tuple[Any, Any | None, Any | None]]:
    history = []
    gap = False
    for attempt in _attempt_range(call.model.model_key):
        paths = (
            prepared.paths.generation_intent(call.model.model_key, attempt),
            prepared.paths.generation_raw(call.model.model_key, attempt),
            prepared.paths.generation_outcome(call.model.model_key, attempt),
        )
        if not paths[0].exists():
            if paths[1].exists() or paths[2].exists():
                raise GrokRetryExecutionError("orphan retry generation evidence")
            gap = True
            continue
        if gap or (history and history[-1][2] is None):
            raise GrokRetryExecutionError(
                "retry generation attempts are not contiguous"
            )
        intent = read_record(paths[0], "Grok retry generation intent")
        expected = _generation_intent_payload(
            prepared,
            authority,
            parent,
            call,
            attempt,
            created_at=intent.payload.get("created_at"),
        )
        if intent.payload != expected:
            raise GrokRetryExecutionError("retry generation intent changed")
        raw = (
            read_record(paths[1], "Grok retry raw response")
            if paths[1].exists()
            else None
        )
        outcome = (
            read_record(paths[2], "Grok retry outcome") if paths[2].exists() else None
        )
        history.append((intent, raw, outcome))
    return history


async def _validate_generation_outcome(
    prepared: PreparedRetry,
    authority: Authority,
    call: PlannedCall,
    intent: Any,
    raw: Any | None,
    outcome: Any,
) -> ProviderResult | None:
    if outcome.payload.get("status") == "consumed-without-capture":
        if raw is not None:
            raise GrokRetryExecutionError("no-capture disposition acquired raw data")
        expected = _consumed_without_capture_payload(
            prepared,
            authority,
            call,
            intent,
            completed_at=outcome.payload.get("completed_at"),
        )
        if outcome.payload != expected:
            raise GrokRetryExecutionError("no-capture disposition changed")
        return None
    if raw is None:
        raise GrokRetryExecutionError("generation outcome lacks durable raw evidence")
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
            raise GrokRetryExecutionError("successful retry outcome changed")
        return parsed
    if outcome.payload.get("status") != "error":
        raise GrokRetryExecutionError("retry outcome status is invalid")
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
            error=_error(error, allow_retry=call.model.model_key == "gpt"),
            latency_ms=outcome.payload.get("latency_ms"),
            completed_at=outcome.payload.get("completed_at"),
        )
        if outcome.payload != expected:
            raise GrokRetryExecutionError("retry error outcome changed")
    else:
        raise GrokRetryExecutionError("retry error now parses as success")
    return None


async def _reconcile_generation(
    prepared: PreparedRetry,
    authority: Authority,
    parent: ParentEvidence,
    call: PlannedCall,
) -> tuple[Any | None, bool, str | None]:
    history = _generation_history(prepared, authority, parent, call)
    for index, (intent, raw, outcome) in enumerate(history):
        attempt = intent.payload["semantic_attempt_number"]
        if outcome is None:
            if raw is None:
                outcome = write_record(
                    prepared.paths.generation_outcome(call.model.model_key, attempt),
                    _consumed_without_capture_payload(
                        prepared,
                        authority,
                        call,
                        intent,
                        completed_at=utc_now(),
                    ),
                )
            else:
                try:
                    parsed = await _parse_generation(
                        prepared, authority, call, intent, raw
                    )
                except ProviderError as error:
                    payload = _generation_outcome_payload(
                        prepared,
                        authority,
                        call,
                        intent,
                        raw,
                        result=None,
                        error=_error(error, allow_retry=call.model.model_key == "gpt"),
                        latency_ms=0,
                        completed_at=utc_now(),
                    )
                else:
                    payload = _generation_outcome_payload(
                        prepared,
                        authority,
                        call,
                        intent,
                        raw,
                        result=parsed,
                        error=None,
                        latency_ms=0,
                        completed_at=utc_now(),
                    )
                outcome = write_record(
                    prepared.paths.generation_outcome(call.model.model_key, attempt),
                    payload,
                )
        parsed = await _validate_generation_outcome(
            prepared, authority, call, intent, raw, outcome
        )
        if parsed is not None:
            if index != len(history) - 1:
                raise GrokRetryExecutionError("generation attempt follows success")
            return outcome, False, None
        if outcome.payload.get("status") == "consumed-without-capture":
            if index != len(history) - 1:
                raise GrokRetryExecutionError(
                    "generation attempt follows a no-capture disposition"
                )
            return (
                None,
                False,
                f"{call.model.model_key} POST ended without durable capture",
            )
        if call.model.model_key == "grok":
            return None, False, "xAI Grok retry failed; no GPT call is allowed"
        error = outcome.payload.get("error")
        if not isinstance(error, dict) or not error.get("retryable"):
            if index != len(history) - 1:
                raise GrokRetryExecutionError(
                    "generation attempt follows a terminal captured error"
                )
            return (
                None,
                False,
                str(
                    error.get("sanitized_summary", "terminal GPT generation error")
                    if isinstance(error, dict)
                    else "terminal GPT generation error"
                ),
            )
    if len(history) >= len(_attempt_range(call.model.model_key)):
        return None, False, f"safe attempt ceiling exhausted for {call.cell_id}"
    return None, True, None


def _reserved_total(prepared: PreparedRetry) -> int:
    root = prepared.paths.private_root / "generation/intents"
    total = 0
    if root.exists():
        for path in sorted(root.rglob("*.json")):
            record = read_record(path, "Grok retry generation intent")
            reserve = record.payload.get("reserved_cost_microdollars")
            if not isinstance(reserve, int) or isinstance(reserve, bool) or reserve < 0:
                raise GrokRetryExecutionError("retry reservation is malformed")
            relative = path.relative_to(root)
            if len(relative.parts) != 2:
                raise GrokRetryExecutionError("retry reservation path changed")
            model_key, filename = relative.parts
            try:
                attempt = int(filename.removeprefix("attempt-").removesuffix(".json"))
            except ValueError as error:
                raise GrokRetryExecutionError(
                    "retry reservation path changed"
                ) from error
            if filename != f"attempt-{attempt}.json" or attempt not in _attempt_range(
                model_key
            ):
                raise GrokRetryExecutionError("retry reservation path changed")
            if reserve != contract.RESERVED_PER_POST.get(model_key):
                raise GrokRetryExecutionError("retry reserved cost changed")
            total += reserve
    if (
        total > contract.NEW_RESERVED_CAP_MICRODOLLARS
        or total + contract.INHERITED_RESERVED_MICRODOLLARS
        > contract.COMBINED_RESERVED_CAP_MICRODOLLARS
    ):
        raise GrokRetryExecutionError("retry reserved-cost cap exceeded")
    return total


def _reserve_generation(
    prepared: PreparedRetry,
    authority: Authority,
    parent: ParentEvidence,
    call: PlannedCall,
    attempt: int,
) -> Any:
    current = _reserved_total(prepared)
    reserve = reserved_microdollars(call)
    if current + reserve > contract.NEW_RESERVED_CAP_MICRODOLLARS:
        raise GrokRetryExecutionError("no POST sent: retry reservation cap exceeded")
    return write_record(
        prepared.paths.generation_intent(call.model.model_key, attempt),
        _generation_intent_payload(
            prepared,
            authority,
            parent,
            call,
            attempt,
            created_at=utc_now(),
        ),
    )


async def _run_generation(
    prepared: PreparedRetry,
    authority: Authority,
    parent: ParentEvidence,
    call: PlannedCall,
    *,
    secret: str,
    transport: Transport,
    limiter: RateLimiter,
) -> Any:
    history = _generation_history(prepared, authority, parent, call)
    attempts = _attempt_range(call.model.model_key)
    if len(history) >= len(attempts):
        raise GrokRetryExecutionError("generation POST ceiling exceeded")
    attempt = attempts[len(history)]
    intent = _reserve_generation(prepared, authority, parent, call, attempt)
    request = _generation_request(call, secret)
    if call.model.model_key == "grok":
        request_hash = sha256_bytes(
            json.dumps(request.json_body, ensure_ascii=False).encode("utf-8")
        )
        if request_hash != contract.GROK_REQUEST_BODY_SHA256:
            raise GrokRetryExecutionError(
                "live Grok request differs from the locked body"
            )
    capture = DurableCaptureTransport(
        transport,
        capture_path=prepared.paths.generation_raw(call.model.model_key, attempt),
        private_root=prepared.paths.private_root,
        common=_raw_common(prepared, authority, call.model.model_key, attempt),
        intent=intent,
        request_kind="generation",
        expected_request=request,
    )
    await limiter.wait()
    started = time.monotonic()
    try:
        await _RetryAdapter(call.model, capture).generate(
            secret, call.answer_messages()
        )
        raw = capture.capture
        if raw is None:
            raise GrokRetryExecutionError("generation returned without durable capture")
        result = await _parse_generation(prepared, authority, call, intent, raw)
    except ProviderError as error:
        raw = capture.capture
        if raw is None:
            return write_record(
                prepared.paths.generation_outcome(call.model.model_key, attempt),
                _consumed_without_capture_payload(
                    prepared,
                    authority,
                    call,
                    intent,
                    completed_at=utc_now(),
                ),
            )
        payload = _generation_outcome_payload(
            prepared,
            authority,
            call,
            intent,
            raw,
            result=None,
            error=_error(error, allow_retry=call.model.model_key == "gpt"),
            latency_ms=int((time.monotonic() - started) * 1000),
            completed_at=utc_now(),
        )
    else:
        payload = _generation_outcome_payload(
            prepared,
            authority,
            call,
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
    prepared: PreparedRetry,
    authority: Authority,
    parent: ParentEvidence,
    outcomes: tuple[Any, Any],
    *,
    sealed_at: str,
) -> dict[str, Any]:
    if tuple(
        record.payload.get("model_key") for record in outcomes
    ) != contract.TARGET_MODEL_KEYS or any(
        record.payload.get("status") != "success" for record in outcomes
    ):
        raise GrokRetryExecutionError("retry composite requires Grok and GPT success")
    cells = []
    preserved = {
        record.payload.get("model_key"): record for record in parent.preserved_outcomes
    }
    recovered = {record.payload.get("model_key"): record for record in outcomes}
    for key in contract.MODEL_ORDER:
        if key in preserved:
            record = preserved[key]
            if key in {"gemini", "claude"}:
                lane = "immutable-rule3-parent"
                root = parent.rule3.private_root
                attempt = 1
            elif key == "cohere":
                lane = "immutable-cohere-recovery"
                root = prepared.repository_root / qwen_contract.FIRST_PRIVATE_ROOT
                attempt = 2
            else:
                lane = "immutable-qwen-successor"
                root = parent.private_root
                attempt = record.payload["semantic_attempt_number"]
            cells.append(
                {
                    "model_key": key,
                    "source_lane": lane,
                    "path": record.path.relative_to(root).as_posix(),
                    "sha256": record.sha256,
                    "semantic_attempt_number": attempt,
                }
            )
        else:
            record = recovered[key]
            cells.append(
                {
                    "model_key": key,
                    "source_lane": "grok-retry",
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
        "status": "complete-eight-successes-four-lineage-two-recovery",
        **_common(prepared, authority),
        "sealed_at": sealed_at,
        "question_sha256": prepared.question.sha256,
        "rule3_plan_sha256": contract.RULE3_PLAN_SHA256,
        "parent_manifest": _parent_binding(parent, parent.parent_manifest),
        "parent_grok_attempt_1": {
            "intent": _parent_binding(parent, parent.grok_error_intent),
            "raw_response": _parent_binding(parent, parent.grok_error_raw),
            "outcome": _parent_binding(parent, parent.grok_error_outcome),
            "disposition": "captured-403-consumed-user-authorized-one-xai-retry",
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
    prepared: PreparedRetry,
    authority: Authority,
    parent: ParentEvidence,
) -> tuple[Any | None, bool, str | None]:
    winners = []
    grok = prepared.target_by_key["grok"]
    grok_success, grok_network, grok_reason = await _reconcile_generation(
        prepared, authority, parent, grok
    )
    if grok_success is None:
        gpt = prepared.target_by_key["gpt"]
        if any(
            prepared.paths.generation_intent("gpt", attempt).exists()
            or prepared.paths.generation_raw("gpt", attempt).exists()
            or prepared.paths.generation_outcome("gpt", attempt).exists()
            for attempt in _attempt_range("gpt")
        ):
            raise GrokRetryExecutionError("GPT state exists before Grok success")
        return None, grok_network, grok_reason
    winners.append(grok_success)
    gpt = prepared.target_by_key["gpt"]
    gpt_success, gpt_network, gpt_reason = await _reconcile_generation(
        prepared, authority, parent, gpt
    )
    if gpt_success is None:
        return None, gpt_network, gpt_reason
    winners.append(gpt_success)
    if prepared.paths.composite.exists():
        record = read_record(prepared.paths.composite, "Grok retry composite")
        expected = _composite_payload(
            prepared,
            authority,
            parent,
            (winners[0], winners[1]),
            sealed_at=record.payload.get("sealed_at"),
        )
        if record.payload != expected:
            raise GrokRetryExecutionError("Grok retry composite changed")
        return record, False, None
    return (
        write_record(
            prepared.paths.composite,
            _composite_payload(
                prepared,
                authority,
                parent,
                (winners[0], winners[1]),
                sealed_at=utc_now(),
            ),
        ),
        False,
        None,
    )


def _validate_inventory(prepared: PreparedRetry) -> None:
    root = prepared.paths.private_root
    if not root.exists():
        return
    metadata = root.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise GrokRetryExecutionError("Grok retry private root must be mode 0700")
    allowed = {
        root / "paid-authorization.json",
        root / "pricing-evidence.json",
        root / "pricing-recheck.json",
        prepared.paths.composite,
    }
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
            raise GrokRetryExecutionError("Grok retry journal contains a symlink")
        if stat.S_ISDIR(mode):
            if path not in directories or stat.S_IMODE(mode) != 0o700:
                raise GrokRetryExecutionError("Grok retry journal directory changed")
        elif (
            path not in allowed
            or not stat.S_ISREG(mode)
            or stat.S_IMODE(mode) != 0o600
            or path.stat().st_nlink != 1
        ):
            raise GrokRetryExecutionError(
                "Grok retry journal contains an unexpected file"
            )
    if prepared.paths.composite.exists():
        if not prepared.paths.generation_outcome("grok", 2).exists() or not any(
            prepared.paths.generation_outcome("gpt", attempt).exists()
            for attempt in _attempt_range("gpt")
        ):
            raise GrokRetryExecutionError("retry composite exists before both winners")


def _secret(environment: Mapping[str, str], name: str) -> str:
    value = environment.get(name, "")
    if not value:
        raise GrokRetryExecutionError(f"missing required environment variable: {name}")
    return value


async def _execute_prepared(
    prepared: PreparedRetry,
    *,
    environment: Mapping[str, str],
    transport_factory: Callable[[], Transport],
    sleep: Callable[[float], Awaitable[None]],
) -> RetryResult:
    parent = validate_parent_snapshot(
        prepared.repository_root, prepared.lock_context.lock
    )
    _validate_inventory(prepared)
    stale = _authority(prepared, fresh=False)
    first_lock_path = prepared.repository_root / qwen_contract.FIRST_CLAIM_LOCK_PATH
    qwen_paths = QwenSuccessorPaths.for_repository(prepared.repository_root)
    async with first_phase_lock(first_lock_path):
        async with qwen_phase_lock(qwen_paths.phase_lock):
            async with phase_lock(prepared.paths.phase_lock):
                parent = validate_parent_snapshot(
                    prepared.repository_root, prepared.lock_context.lock
                )
                claim = _ensure_claim(prepared, stale, parent)
                stale = _with_claim(stale, claim)
                composite, needs_network, terminal = await _reconcile_composite(
                    prepared, stale, parent
                )
                if composite is not None:
                    return RetryResult(
                        composite.path, composite.payload, composite.sha256, 0
                    )
                if terminal is not None:
                    return RetryResult(
                        prepared.paths.private_root,
                        {
                            "status": "terminal-grok-retry-incomplete",
                            "stopped_reason": terminal,
                        },
                        "",
                        0,
                    )
                if not needs_network:
                    raise GrokRetryExecutionError("Grok retry journal cannot advance")
                fresh = _authority(prepared, fresh=True)
                if fresh != Authority(stale.authorization, stale.pricing):
                    raise GrokRetryExecutionError("retry authority changed under lock")
                authority = _with_claim(fresh, claim)
                transport = transport_factory()
                limiters = {
                    key: RateLimiter(
                        prepared.target_by_key[key].model.requests_per_second
                    )
                    for key in contract.TARGET_MODEL_KEYS
                }
                requests = 0

                grok = prepared.target_by_key["grok"]
                grok_success, grok_needs, grok_reason = await _reconcile_generation(
                    prepared, authority, parent, grok
                )
                if grok_success is None:
                    if grok_reason is not None:
                        return RetryResult(
                            prepared.paths.private_root,
                            {
                                "status": "terminal-grok-retry-incomplete",
                                "stopped_reason": grok_reason,
                            },
                            "",
                            requests,
                        )
                    if not grok_needs:
                        raise GrokRetryExecutionError("Grok retry cannot advance")
                    outcome = await _run_generation(
                        prepared,
                        authority,
                        parent,
                        grok,
                        secret=_secret(environment, "XAI_API_KEY"),
                        transport=transport,
                        limiter=limiters["grok"],
                    )
                    requests += 1
                    if outcome.payload.get("status") != "success":
                        return RetryResult(
                            prepared.paths.private_root,
                            {
                                "status": "terminal-grok-retry-incomplete",
                                "stopped_reason": (
                                    "xAI Grok retry did not produce a durable success; "
                                    "no GPT call is allowed"
                                ),
                            },
                            "",
                            requests,
                        )

                gpt = prepared.target_by_key["gpt"]
                while True:
                    gpt_success, gpt_needs, gpt_reason = await _reconcile_generation(
                        prepared, authority, parent, gpt
                    )
                    if gpt_success is not None:
                        break
                    if gpt_reason is not None:
                        return RetryResult(
                            prepared.paths.private_root,
                            {
                                "status": "terminal-grok-retry-incomplete",
                                "stopped_reason": gpt_reason,
                            },
                            "",
                            requests,
                        )
                    if not gpt_needs:
                        raise GrokRetryExecutionError("GPT continuation cannot advance")
                    outcome = await _run_generation(
                        prepared,
                        authority,
                        parent,
                        gpt,
                        secret=_secret(environment, "OPENROUTER_API_KEY"),
                        transport=transport,
                        limiter=limiters["gpt"],
                    )
                    requests += 1
                    if outcome.payload.get("status") == "error":
                        await sleep(
                            0.5
                            * (2 ** (outcome.payload["semantic_attempt_number"] - 1))
                        )

                composite, _, terminal = await _reconcile_composite(
                    prepared, authority, parent
                )
                if composite is None:
                    raise GrokRetryExecutionError(
                        terminal or "Grok retry composite was not sealed"
                    )
                if requests > contract.MAX_OUTBOUND_REQUESTS:
                    raise GrokRetryExecutionError(
                        "retry outbound request ceiling exceeded"
                    )
                return RetryResult(
                    composite.path, composite.payload, composite.sha256, requests
                )


async def execute_prepared(prepared: PreparedRetry) -> RetryResult:
    return await _execute_prepared(
        prepared,
        environment=os.environ,
        transport_factory=UrllibTransport,
        sleep=asyncio.sleep,
    )


__all__ = (
    "Authority",
    "GrokRetryExecutionError",
    "PreparedRetry",
    "RetryResult",
    "_attempt_range",
    "_execute_prepared",
    "dry_run_summary",
    "execute_prepared",
    "prepare_retry",
)
