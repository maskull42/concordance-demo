"""Execution gates for the one-candidate divergence successor.

The production entry remains inert until exact author approval is committed.
Once that gate exists, the runtime in :mod:`divergence_successor.engine` uses
the proven provider adapters and durable-capture journal without retrying a
single semantic cell.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

from concordance_harness.config import (
    GPT_APPROVED_CANONICAL_MODEL_ID,
    GPT_FROZEN_REQUESTED_MODEL_ID,
    HarnessConfig,
    load_harness_config,
)
from concordance_harness.planner import PlannedCall, QuestionInput, build_plan
from concordance_harness.util import prompt_sha256, sha256_bytes
from concordance_recovery.journal import RecoveryJournalError, read_record
from rule3.budget import JournalRecord

from . import authorization, contract, lock
from .parent import ParentEvidence, verify_parent_snapshot
from .state import SuccessorPaths, inspect_inventory


FORBIDDEN_TOOL_KEYS = frozenset(
    {
        "annotations",
        "apply_patch_call",
        "browser",
        "citations",
        "code_interpreter_call",
        "codeexecutionresult",
        "computer_call",
        "custom_tool_call",
        "executablecode",
        "external_context",
        "externalcontext",
        "file_search_call",
        "functioncall",
        "functioncalls",
        "groundingchunks",
        "groundingmetadata",
        "groundingsupports",
        "grounding_metadata",
        "image_generation_call",
        "local_shell_call",
        "mcp_approval_request",
        "mcp_call",
        "mcp_list_tools",
        "retrieval",
        "retrievalmetadata",
        "search_results",
        "searchresults",
        "searchentrypoint",
        "server_tool_use",
        "shell_call",
        "sources",
        "tool_call",
        "tool_calls",
        "toolcall",
        "toolcalls",
        "tool_results",
        "toolresults",
        "tool_use",
        "tools",
        "url_context_metadata",
        "url_citation",
        "url_citations",
        "web_search",
        "web_search_call",
        "websearch",
        "websearchqueries",
        "urlcontextmetadata",
    }
)
FORBIDDEN_ARTIFACT_TYPES = frozenset(
    {
        "browser",
        "apply_patch_call",
        "apply_patch_call_output",
        "citation",
        "code_interpreter",
        "code_interpreter_call",
        "computer_call",
        "computer_call_output",
        "computer_use",
        "custom_tool_call",
        "custom_tool_call_output",
        "file_search_call",
        "file_search",
        "function_call",
        "function_call_output",
        "grounding",
        "image_generation_call",
        "local_shell_call",
        "local_shell_call_output",
        "mcp_approval_request",
        "mcp_approval_response",
        "mcp_call",
        "mcp_list_tools",
        "retrieval",
        "search",
        "tool_call",
        "tool_result",
        "tool_use",
        "url_citation",
        "url_context",
        "server_tool_use",
        "shell_call",
        "shell_call_output",
        "web_search",
        "web_search_call",
        "web_search_tool_result",
    }
)


class DivergenceSuccessorExecutionError(RuntimeError):
    """The successor cannot safely cross the provider-call boundary."""


@dataclass(frozen=True)
class PreparedSuccessor:
    repository_root: Path
    lock_context: lock.LockContext
    parent: ParentEvidence
    paths: SuccessorPaths
    config: HarnessConfig | None = None
    question: QuestionInput | None = None
    plan: tuple[PlannedCall, ...] = ()
    call_by_key: dict[str, PlannedCall] = field(default_factory=dict)


def _nonempty_artifact(value: Any) -> bool:
    return value not in (None, False, "", [], {})


def _normalized_key(value: str) -> str:
    return "".join(character for character in value.casefold() if character.isalnum())


_NORMALIZED_FORBIDDEN_TOOL_KEYS = frozenset(
    _normalized_key(value) for value in FORBIDDEN_TOOL_KEYS
)
_NORMALIZED_FORBIDDEN_ARTIFACT_TYPES = frozenset(
    _normalized_key(value) for value in FORBIDDEN_ARTIFACT_TYPES
)


def reject_tool_artifacts(value: Any, *, path: str = "payload") -> None:
    """Reject evidence that any tool, web, retrieval, or context lane ran."""

    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = _normalized_key(key) if isinstance(key, str) else ""
            if normalized in _NORMALIZED_FORBIDDEN_TOOL_KEYS:
                if _nonempty_artifact(item):
                    raise DivergenceSuccessorExecutionError(
                        f"{path}.{key} contains a forbidden tool or context artifact"
                    )
            if (
                normalized == "type"
                and isinstance(item, str)
                and _normalized_key(item)
                in _NORMALIZED_FORBIDDEN_ARTIFACT_TYPES
            ):
                raise DivergenceSuccessorExecutionError(
                    f"{path}.{key} identifies a forbidden provider artifact"
                )
            reject_tool_artifacts(item, path=f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            reject_tool_artifacts(item, path=f"{path}[{index}]")


def _record_payload(value: JournalRecord | Mapping[str, Any]) -> Mapping[str, Any]:
    if isinstance(value, JournalRecord):
        return value.payload
    if not isinstance(value, Mapping):
        raise DivergenceSuccessorExecutionError("journal evidence must be an object")
    return value


def _expected_model(model_key: str) -> tuple[str, str, str]:
    if model_key not in contract.MODEL_KEYS:
        raise DivergenceSuccessorExecutionError("model key is outside the locked panel")
    return contract.EXPECTED_MODELS[model_key]


def returned_model_id_is_approved(model_key: str, returned: Any) -> bool:
    if not isinstance(returned, str):
        return False
    requested, provider, route = _expected_model(model_key)
    if returned == requested:
        return True
    if provider == "google" and returned == f"models/{requested}":
        return True
    return (
        model_key == "gpt"
        and provider == "openrouter"
        and route == "openrouter-openai-pinned"
        and requested == GPT_FROZEN_REQUESTED_MODEL_ID
        and returned == GPT_APPROVED_CANONICAL_MODEL_ID
    )


def validate_preflight_outcome(
    value: JournalRecord | Mapping[str, Any], *, model_key: str
) -> Mapping[str, Any]:
    payload = _record_payload(value)
    requested, provider, route = _expected_model(model_key)
    returned = payload.get("provider_returned_model_id")
    if (
        payload.get("status") != "success"
        or payload.get("model_key") != model_key
        or payload.get("requested_model_id") != requested
        or payload.get("provider") != provider
        or payload.get("route") != route
        or not returned_model_id_is_approved(model_key, returned)
        or payload.get("attempt_number") != 1
    ):
        raise DivergenceSuccessorExecutionError(
            f"preflight identity or success state differs for {model_key}"
        )
    reject_tool_artifacts(payload, path=f"preflight[{model_key}]")
    return payload


def preflight_gate(
    outcomes: Iterable[JournalRecord | Mapping[str, Any]],
) -> dict[str, Mapping[str, Any]]:
    """Require all eight ordered successes before any generation can begin."""

    values = list(outcomes)
    if len(values) != 8:
        raise DivergenceSuccessorExecutionError(
            "generation requires exactly eight completed preflight outcomes"
        )
    result: dict[str, Mapping[str, Any]] = {}
    for expected_key, value in zip(contract.MODEL_KEYS, values, strict=True):
        payload = validate_preflight_outcome(value, model_key=expected_key)
        if expected_key in result:
            raise DivergenceSuccessorExecutionError("preflight panel is duplicated")
        result[expected_key] = payload
    if tuple(result) != contract.MODEL_KEYS:
        raise DivergenceSuccessorExecutionError("preflight panel order changed")
    return result


def validate_generation_outcome(
    value: JournalRecord | Mapping[str, Any],
    *,
    model_key: str,
    prompt_sha256: str,
) -> Mapping[str, Any]:
    payload = _record_payload(value)
    requested, provider, route = _expected_model(model_key)
    result = payload.get("result")
    response = result.get("response_text") if isinstance(result, Mapping) else None
    returned = payload.get("provider_returned_model_id")
    if returned is None and isinstance(result, Mapping):
        returned = result.get("provider_returned_model_id")
    expected_cell = f"{contract.CANDIDATE_ID}:{model_key}:default:answer"
    identity_ok = returned_model_id_is_approved(model_key, returned)
    if model_key == "cohere" and returned is None:
        identity_ok = True
    if (
        payload.get("status") != "success"
        or payload.get("candidate_id") != contract.CANDIDATE_ID
        or payload.get("cell_id") != expected_cell
        or payload.get("model_key") != model_key
        or payload.get("requested_model_id") != requested
        or payload.get("provider") != provider
        or payload.get("route") != route
        or not identity_ok
        or payload.get("attempt_number") != 1
        or payload.get("prompt_sha256") != prompt_sha256
        or not isinstance(response, str)
        or not response.strip()
        or not isinstance(result, Mapping)
        or result.get("response_sha256")
        != sha256_bytes(response.encode("utf-8"))
    ):
        raise DivergenceSuccessorExecutionError(
            f"generation identity or success state differs for {model_key}"
        )
    reject_tool_artifacts(payload, path=f"generation[{model_key}]")
    return payload


def _exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError as error:
        raise DivergenceSuccessorExecutionError(
            f"journal path cannot be inspected: {error}"
        ) from error


def cell_state(
    paths: SuccessorPaths, request_kind: str, model_key: str
) -> dict[str, Any]:
    """Classify one attempt without ever opening a replay lane."""

    if request_kind == "preflight":
        intent = paths.preflight_intent(model_key)
        raw = paths.preflight_raw(model_key)
        outcome = paths.preflight_outcome(model_key)
    elif request_kind == "generation":
        intent = paths.generation_intent(model_key)
        raw = paths.generation_raw(model_key)
        outcome = paths.generation_outcome(model_key)
    else:
        raise DivergenceSuccessorExecutionError("request kind is not approved")
    present = (_exists(intent), _exists(raw), _exists(outcome))
    if present == (False, False, False):
        status = "unstarted"
    elif present == (True, False, False):
        status = "consumed-stranded-no-replay"
    elif present == (True, True, False):
        status = "captured-offline-finalization-required"
    elif present == (True, True, True):
        status = "terminal"
    else:
        raise DivergenceSuccessorExecutionError(
            f"{request_kind} journal ordering is impossible for {model_key}"
        )
    return {
        "request_kind": request_kind,
        "model_key": model_key,
        "attempt_number": 1,
        "status": status,
        "network_replay_allowed": False,
        "intent": intent,
        "raw": raw,
        "outcome": outcome,
    }


def load_complete_preflight(paths: SuccessorPaths) -> tuple[JournalRecord, ...]:
    records: list[JournalRecord] = []
    for key in contract.MODEL_KEYS:
        state = cell_state(paths, "preflight", key)
        if state["status"] != "terminal":
            raise DivergenceSuccessorExecutionError(
                f"preflight gate is not terminal for {key}: {state['status']}"
            )
        try:
            record = read_record(state["outcome"], f"successor preflight {key}")
        except RecoveryJournalError as error:
            raise DivergenceSuccessorExecutionError(str(error)) from error
        records.append(record)
    preflight_gate(records)
    return tuple(records)


def prepare_successor(
    repository_root: Path | str, *, require_committed: bool = True
) -> PreparedSuccessor:
    context = lock.load_and_validate_divergence_successor_lock(
        repository_root,
        require_committed=require_committed,
        require_parent_private=require_committed,
    )
    parent = verify_parent_snapshot(context.repository_root)
    paths = SuccessorPaths.for_repository(context.repository_root)
    inspect_inventory(paths)
    config = load_harness_config(
        context.repository_root / contract.MODELS_CONFIG_PATH
    )
    if config.sha256 != context.lock["bindings"]["models_config"]["sha256"]:
        raise DivergenceSuccessorExecutionError(
            "successor model configuration differs from the lock"
        )
    try:
        question_value, question_payload = contract.read_json_file(
            context.repository_root, contract.QUESTION_PATH
        )
        protocol, _ = contract.read_json_file(
            context.repository_root, contract.PROTOCOL_PATH
        )
    except contract.ContractError as error:
        raise DivergenceSuccessorExecutionError(str(error)) from error
    if not isinstance(question_value, dict) or not isinstance(protocol, dict):
        raise DivergenceSuccessorExecutionError(
            "successor question or protocol is malformed"
        )
    if protocol != {
        "protocol_version": "rule3-successor-1.0.0",
        "system_prompt": contract.SYSTEM_PROMPT,
        "standard_challenge_prompt": contract.STANDARD_CHALLENGE_PROMPT,
    }:
        raise DivergenceSuccessorExecutionError("successor protocol changed")
    question = QuestionInput(
        path=context.repository_root / contract.QUESTION_PATH,
        raw=question_value,
        sha256=sha256_bytes(question_payload),
    )
    plan = build_plan(
        (question,),
        config.models,
        protocol["system_prompt"],
        protocol["standard_challenge_prompt"],
        answer_only=True,
    )
    locked_plans = context.lock.get("plans", {}).get("candidate_plans")
    locked_cells = (
        locked_plans[0].get("cells")
        if isinstance(locked_plans, list) and len(locked_plans) == 1
        else None
    )
    expected_cells = [
        {
            "cell_id": call.cell_id,
            "model_key": call.model.model_key,
            "prompt_sha256": prompt_sha256(call.answer_messages()),
            "requested_model_id": call.model.requested_model_id,
            "route": call.model.route,
            "requested_params": call.model.requested_params_receipt(),
            "semantic_attempt_number": 1,
            "maximum_generation_posts": 1,
        }
        for call in plan
    ]
    if (
        tuple(call.model.model_key for call in plan) != contract.MODEL_KEYS
        or locked_cells != expected_cells
        or locked_plans[0].get("plan_sha256")
        != sha256_bytes(contract.canonical_json_bytes(expected_cells))
        or context.candidate_plan_sha256.get(contract.CANDIDATE_ID)
        != locked_plans[0].get("plan_sha256")
    ):
        raise DivergenceSuccessorExecutionError(
            "successor runtime plan differs from the exact lock"
        )
    for model, locked_model in zip(
        config.models, context.lock.get("models", ()), strict=True
    ):
        transport = contract.APPROVED_MODEL_TRANSPORTS[model.model_key]
        if (
            any(getattr(model, name) != value for name, value in transport.items())
            or model.requested_params_receipt()
            != contract.EXPECTED_REQUEST_PARAMS[model.model_key]
            or model.planning_pricing
            != contract.APPROVED_PLANNING_PRICING[model.model_key]
            or any(locked_model.get(name) != value for name, value in transport.items())
        ):
            raise DivergenceSuccessorExecutionError(
                f"runtime model transport changed for {model.model_key}"
            )
    return PreparedSuccessor(
        context.repository_root,
        context,
        parent,
        paths,
        config,
        question,
        plan,
        {call.model.model_key: call for call in plan},
    )


def execution_readiness(repository_root: Path | str) -> dict[str, Any]:
    """Inspect public readiness only. Never read env, write state, or call a host."""

    lock_state = lock.readiness(repository_root)
    approval = authorization.approval_readiness()
    issues = [*lock_state["issues"], *approval["issues"]]
    return {
        "status": "ready-at-provider-boundary" if not issues else "blocked-before-provider-calls",
        "candidate_id": contract.CANDIDATE_ID,
        "model_keys": list(contract.MODEL_KEYS),
        "issues": issues,
        "preflight_requests_planned": 8,
        "generation_posts_planned": 8,
        "automatic_retries": 0,
        "private_writes": 0,
        "network_requests": 0,
        "environment_variables_read": 0,
    }


async def execute_live(repository_root: Path | str) -> Any:
    """Execute the committed lane only after the exact public approval gate."""

    authorization.require_approval_enabled()
    prepared = prepare_successor(repository_root, require_committed=True)
    from .engine import execute_prepared

    return await execute_prepared(prepared)


__all__ = (
    "DivergenceSuccessorExecutionError",
    "PreparedSuccessor",
    "cell_state",
    "execute_live",
    "execution_readiness",
    "load_complete_preflight",
    "preflight_gate",
    "prepare_successor",
    "reject_tool_artifacts",
    "returned_model_id_is_approved",
    "validate_generation_outcome",
    "validate_preflight_outcome",
)
