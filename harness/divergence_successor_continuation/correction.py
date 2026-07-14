"""Offline, append-only correction of the sealed metadata preflight gate.

This module never constructs a live transport and never reads a credential.  It
authenticates the original intent, raw response, and outcome for every model,
then replays each sealed HTTP body through the provider metadata parser without
applying the generation-only tool-artifact scanner to capability documents.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from concordance_harness.providers import (
    PreflightResult,
    ProviderAdapter,
    ProviderError,
)
from concordance_harness.util import canonical_json_bytes, sha256_bytes, utc_now
from concordance_recovery.journal import (
    RecoveryJournalError,
    read_record,
    require_timestamp,
    validate_raw_response,
    write_record,
)
from concordance_recovery.transport import CapturedReplayTransport
from divergence_successor import authorization as parent_authorization
from divergence_successor import contract as parent_contract
from divergence_successor import engine as parent_engine
from divergence_successor import execute as parent_execute
from divergence_successor.state import inspect_inventory as inspect_parent_inventory
from rule3.budget import JournalRecord

from . import contract
from .state import ContinuationPaths, inspect_inventory


CORRECTION_SCHEMA = "divergence-successor-offline-preflight-correction-1.0.0"
CORRECTION_STATUS = "complete-eight-model-offline-metadata-correction"
FALSE_NEGATIVE_KEYS = frozenset({"claude", "gpt"})
EMPTY_BODY_SHA256 = sha256_bytes(b"")


class OfflineCorrectionError(RuntimeError):
    """The sealed preflight evidence cannot support the approved correction."""


def _timestamp(value: Any, label: str) -> datetime:
    try:
        require_timestamp(value, label)
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError, RecoveryJournalError) as error:
        raise OfflineCorrectionError(str(error)) from error


def _binding(root: Path, record: JournalRecord, label: str) -> dict[str, str]:
    try:
        relative = record.path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as error:
        raise OfflineCorrectionError(f"{label} escapes the repository") from error
    return {"path": relative, "sha256": record.sha256}


def _public_binding(root: Path, relative: str, label: str) -> dict[str, str]:
    try:
        payload = parent_contract.read_regular_file(root, relative)
    except parent_contract.ContractError as error:
        raise OfflineCorrectionError(str(error)) from error
    return {"path": relative, "sha256": sha256_bytes(payload)}


def load_historical_parent(
    repository_root: Path | str,
    *,
    fresh_pricing: bool,
) -> tuple[parent_execute.PreparedSuccessor, parent_engine.Authority]:
    """Reconstruct the original authority at its sealed historical Git HEAD."""

    root = contract.repository_root(repository_root)
    try:
        prepared = parent_execute.prepare_successor(root, require_committed=False)
        original_files = set(inspect_parent_inventory(prepared.paths))
        expected = {
            prepared.paths.phase_lock,
            prepared.paths.authorization,
            prepared.paths.pricing_recheck,
        }
        for key in contract.MODEL_KEYS:
            expected.update(
                {
                    prepared.paths.preflight_intent(key),
                    prepared.paths.preflight_raw(key),
                    prepared.paths.preflight_outcome(key),
                }
            )
        if original_files != expected or len(original_files) != 27:
            raise OfflineCorrectionError(
                "original successor root is not the exact sealed 27-file preflight inventory"
            )
        phase_metadata = prepared.paths.phase_lock.lstat()
        if phase_metadata.st_size != 0:
            raise OfflineCorrectionError(
                "original successor phase lock is not zero bytes"
            )
        if prepared.lock_context.lock_sha256 != contract.ORIGINAL_LOCK_SHA256:
            raise OfflineCorrectionError(
                "original successor lock is not the approved lock"
            )
        parent_digest = sha256_bytes(
            canonical_json_bytes(prepared.lock_context.lock["parent"])
        )
        if parent_digest != contract.ORIGINAL_PARENT_CONTRACT_SHA256:
            raise OfflineCorrectionError("original parent-contract hash changed")
        historical_paid = read_record(
            prepared.paths.authorization, "historical successor authorization"
        )
        historical_head = historical_paid.payload.get("git_head")
        if (
            not isinstance(historical_head, str)
            or len(historical_head) not in {40, 64}
            or any(character not in "0123456789abcdef" for character in historical_head)
        ):
            raise OfflineCorrectionError(
                "historical authorization lacks its exact Git HEAD"
            )
        if historical_head != contract.ORIGINAL_GIT_HEAD:
            raise OfflineCorrectionError(
                "historical Git HEAD is not the approved source commit"
            )
        historical_context = replace(prepared.lock_context, git_head=historical_head)
        prepared = replace(prepared, lock_context=historical_context)
        paid = parent_authorization.validate_authorization(historical_context)
        pricing = parent_authorization.validate_pricing_recheck(
            historical_context, paid, fresh=fresh_pricing
        )
        if (
            historical_paid.path != paid.path
            or historical_paid.payload != paid.payload
            or historical_paid.sha256 != paid.sha256
        ):
            raise OfflineCorrectionError("historical authorization bytes changed")
        if paid.sha256 != contract.ORIGINAL_AUTHORIZATION_SHA256:
            raise OfflineCorrectionError("historical authorization hash changed")
        if pricing.sha256 != contract.ORIGINAL_PRICING_SHA256:
            raise OfflineCorrectionError("historical pricing hash changed")
    except OfflineCorrectionError:
        raise
    except (OSError, RuntimeError, ValueError) as error:
        raise OfflineCorrectionError(str(error)) from error
    return prepared, parent_engine.Authority(paid, pricing)


def _advertisement_paths(value: Any, path: str = "metadata") -> tuple[str, ...]:
    """Describe capability advertisements without treating them as executions."""

    found: set[str] = set()
    forbidden = parent_execute._NORMALIZED_FORBIDDEN_TOOL_KEYS
    if isinstance(value, Mapping):
        for key, item in value.items():
            child = f"{path}.{key}"
            normalized = (
                parent_execute._normalized_key(key) if isinstance(key, str) else ""
            )
            if normalized in forbidden and item not in (None, False, "", [], {}):
                found.add(child)
            if normalized == "supportedparameters" and isinstance(item, list):
                for index, parameter in enumerate(item):
                    if (
                        isinstance(parameter, str)
                        and parent_execute._normalized_key(parameter) in forbidden
                    ):
                        found.add(f"{child}[{index}]={parameter}")
            found.update(_advertisement_paths(item, child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.update(_advertisement_paths(item, f"{path}[{index}]"))
    return tuple(sorted(found))


def _validate_advertisement_scope(model_key: str, paths: tuple[str, ...]) -> None:
    if model_key == "claude":
        if not paths or any(
            not item.startswith("metadata.capabilities.") for item in paths
        ):
            raise OfflineCorrectionError(
                "Claude's scanner hit is not confined to metadata capabilities"
            )
        return
    if model_key == "gpt":
        allowed = (".pricing.web_search", ".supported_parameters[")
        if not paths or any(
            not any(marker in item for marker in allowed) for item in paths
        ):
            raise OfflineCorrectionError(
                "GPT's scanner hit is not confined to endpoint capability advertising"
            )
        return
    if paths:
        raise OfflineCorrectionError(
            f"unexpected capability-advertisement scanner hit for {model_key}"
        )


def _validate_openrouter_standard_route(metadata: Mapping[str, Any]) -> None:
    data = metadata.get("data")
    endpoints = data.get("endpoints") if isinstance(data, Mapping) else None
    if not isinstance(data, Mapping) or data.get("id") != "openai/gpt-5.6-sol":
        raise OfflineCorrectionError("OpenRouter metadata identifies another model")
    matches = [
        item
        for item in endpoints or []
        if isinstance(item, Mapping)
        and str(item.get("provider_name", "")).casefold() == "openai"
        and item.get("tag") == "openai"
        and item.get("model_id") == "openai/gpt-5.6-sol"
        and isinstance(item.get("pricing"), Mapping)
        and item["pricing"].get("prompt") == "0.000005"
        and item["pricing"].get("completion") == "0.00003"
    ]
    if len(matches) != 1:
        raise OfflineCorrectionError(
            "OpenRouter metadata lacks one exact standard OpenAI endpoint"
        )


async def _corrected_result(
    prepared: parent_execute.PreparedSuccessor,
    authority: parent_engine.Authority,
    call: Any,
    intent: JournalRecord,
    raw: JournalRecord,
) -> tuple[PreflightResult, dict[str, Any], tuple[str, ...]]:
    request = parent_engine._offline_metadata_request(call)
    common = parent_engine._raw_common(
        prepared, authority, model_key=call.model.model_key
    )
    try:
        response = validate_raw_response(
            raw,
            expected_common=common,
            expected_intent=intent,
            private_root=prepared.paths.private_root,
            request_kind="preflight",
            expected_request=request,
        )
        metadata = response.json()
    except (RecoveryJournalError, ValueError) as error:
        raise OfflineCorrectionError(
            f"sealed metadata cannot be decoded for {call.model.model_key}"
        ) from error
    if (
        request.method != "GET"
        or request.json_body is not None
        or raw.payload.get("request", {}).get("json_body_sha256") != EMPTY_BODY_SHA256
        or response.status != 200
        or not isinstance(metadata, dict)
    ):
        raise OfflineCorrectionError(
            f"sealed preflight is not a successful body-free GET for {call.model.model_key}"
        )
    paths = _advertisement_paths(metadata)
    scanner_rejected = False
    try:
        parent_execute.reject_tool_artifacts(
            metadata, path=f"sealed_metadata[{call.model.model_key}]"
        )
    except parent_execute.DivergenceSuccessorExecutionError:
        scanner_rejected = True
    if scanner_rejected != (call.model.model_key in FALSE_NEGATIVE_KEYS):
        raise OfflineCorrectionError(
            f"original scanner behavior changed for {call.model.model_key}"
        )
    _validate_advertisement_scope(call.model.model_key, paths)
    if call.model.model_key == "gpt":
        _validate_openrouter_standard_route(metadata)
    replay = CapturedReplayTransport(
        raw,
        private_root=prepared.paths.private_root,
        common=common,
        intent=intent,
        request_kind="preflight",
        expected_request=request,
    )
    try:
        result = await ProviderAdapter(call.model, replay).preflight(
            "redacted-offline-secret"
        )
    except (RecoveryJournalError, RuntimeError) as error:
        raise OfflineCorrectionError(
            f"sealed metadata identity failed for {call.model.model_key}"
        ) from error
    if not parent_execute.returned_model_id_is_approved(
        call.model.model_key, result.returned_model_id
    ):
        raise OfflineCorrectionError(
            f"corrected metadata identity differs for {call.model.model_key}"
        )
    return result, metadata, paths


async def build_correction_payload(
    repository_root: Path | str,
    *,
    corrected_at: str,
) -> dict[str, Any]:
    """Authenticate all original preflights and build a response-free receipt."""

    root = contract.repository_root(repository_root)
    corrected_time = _timestamp(corrected_at, "offline correction time")
    contract.require_approval()
    prepared, authority = load_historical_parent(root, fresh_pricing=False)
    paid = authority.authorization
    pricing = authority.pricing
    paths = ContinuationPaths.for_repository(root)
    inspect_inventory(paths)
    if prepared.paths.manifest.exists() or prepared.paths.composite.exists():
        raise OfflineCorrectionError(
            "the failed original lane unexpectedly has a terminal run"
        )
    for key in contract.MODEL_KEYS:
        if (
            parent_execute.cell_state(prepared.paths, "generation", key)["status"]
            != "unstarted"
        ):
            raise OfflineCorrectionError(
                "the original lane already contains generation state"
            )

    records: list[dict[str, Any]] = []
    latest_original = datetime.min.replace(tzinfo=corrected_time.tzinfo)
    for call in prepared.plan:
        key = call.model.model_key
        try:
            intent = parent_engine._read_preflight_intent(prepared, authority, call)
            raw = read_record(
                prepared.paths.preflight_raw(key), f"original raw metadata {key}"
            )
            outcome = read_record(
                prepared.paths.preflight_outcome(key),
                f"original preflight outcome {key}",
            )
            exact_hashes = contract.ORIGINAL_PREFLIGHT_SHA256[key]
            if (
                intent.sha256 != exact_hashes["intent"]
                or raw.sha256 != exact_hashes["raw_response"]
                or outcome.sha256 != exact_hashes["outcome"]
                or raw.payload.get("parent_contract_sha256")
                != contract.ORIGINAL_PARENT_CONTRACT_SHA256
            ):
                raise OfflineCorrectionError(
                    f"original approved preflight bytes changed for {key}"
                )
            try:
                original_result = await parent_engine._parse_preflight_capture(
                    prepared, authority, call, intent, raw
                )
            except ProviderError as provider_error:
                original_result = None
                expected_original = parent_engine._preflight_outcome_payload(
                    prepared,
                    authority,
                    intent,
                    raw,
                    call,
                    result=None,
                    error=parent_engine._error_value(provider_error, "preflight"),
                    completed_at=outcome.payload.get("completed_at"),
                )
                parent_engine._validate_error(
                    outcome.payload.get("error"), "original preflight"
                )
            else:
                expected_original = parent_engine._preflight_outcome_payload(
                    prepared,
                    authority,
                    intent,
                    raw,
                    call,
                    result=original_result,
                    error=None,
                    completed_at=outcome.payload.get("completed_at"),
                )
                parent_execute.validate_preflight_outcome(outcome, model_key=key)
            if outcome.path != prepared.paths.preflight_outcome(key):
                raise OfflineCorrectionError("original preflight outcome path changed")
            if outcome.payload != expected_original:
                raise OfflineCorrectionError(
                    "original preflight outcome differs from its sealed raw response"
                )
        except (OSError, RuntimeError, ValueError) as error:
            raise OfflineCorrectionError(
                f"original preflight lineage failed for {key}: {error}"
            ) from error
        corrected_result, _, advertisements = await _corrected_result(
            prepared, authority, call, intent, raw
        )
        original_status = "success" if original_result is not None else "error"
        expected_status = "error" if key in FALSE_NEGATIVE_KEYS else "success"
        if (
            outcome.payload.get("status") != expected_status
            or original_status != expected_status
        ):
            raise OfflineCorrectionError(f"original terminal status changed for {key}")
        completed = _timestamp(
            outcome.payload.get("completed_at"), f"original completion time {key}"
        )
        latest_original = max(latest_original, completed)
        records.append(
            {
                "model_key": key,
                "provider": call.model.provider,
                "route": call.model.route,
                "requested_model_id": call.model.requested_model_id,
                "provider_returned_model_id": corrected_result.returned_model_id,
                "provider_name": corrected_result.provider_name,
                "original_status": original_status,
                "corrected_status": "success",
                "correction_reason": (
                    "metadata-capability-advertisement-was-misclassified"
                    if key in FALSE_NEGATIVE_KEYS
                    else "original-success-independently-confirmed"
                ),
                "capability_advertisement_paths": list(advertisements),
                "request_method": "GET",
                "request_body_present": False,
                "runtime_tool_artifact_present": False,
                "intent": _binding(root, intent, f"original intent {key}"),
                "raw_response": _binding(root, raw, f"original raw response {key}"),
                "original_outcome": _binding(root, outcome, f"original outcome {key}"),
            }
        )
    if corrected_time < latest_original:
        raise OfflineCorrectionError("offline correction predates an original outcome")
    return {
        "schema_version": CORRECTION_SCHEMA,
        "status": CORRECTION_STATUS,
        "pool_id": contract.POOL_ID,
        "candidate_id": contract.CANDIDATE_ID,
        "approval_statement": contract.APPROVAL_STATEMENT,
        "approval_statement_sha256": contract.APPROVAL_STATEMENT_SHA256,
        "original_lock": _public_binding(
            root, contract.ORIGINAL_LOCK_PATH, "original lock"
        ),
        "original_authorization": _binding(
            root,
            JournalRecord(paid.path, paid.payload, paid.sha256),
            "original authorization",
        ),
        "original_pricing_recheck": _binding(
            root,
            JournalRecord(pricing.path, pricing.payload, pricing.sha256),
            "original pricing recheck",
        ),
        "corrected_at": corrected_at,
        "method": {
            "network_requests": 0,
            "environment_variables_read": 0,
            "credentials_read": 0,
            "sealed_metadata_responses_replayed": 8,
            "new_metadata_requests": 0,
            "generation_requests": 0,
            "generation_only_artifact_scanner_applied_to_metadata": False,
        },
        "original_network_inventory": {
            "metadata_gets": 8,
            "generation_posts": 0,
            "automatic_retries": 0,
        },
        "false_negative_model_keys": [
            key for key in contract.MODEL_KEYS if key in FALSE_NEGATIVE_KEYS
        ],
        "model_records": records,
    }


async def verify_correction_record_async(
    repository_root: Path | str,
) -> JournalRecord:
    root = contract.repository_root(repository_root)
    paths = ContinuationPaths.for_repository(root)
    try:
        record = read_record(paths.correction, "offline correction receipt")
    except RecoveryJournalError as error:
        raise OfflineCorrectionError(str(error)) from error
    expected = await build_correction_payload(
        root, corrected_at=record.payload.get("corrected_at")
    )
    if record.payload != expected:
        raise OfflineCorrectionError("offline correction receipt changed")
    return record


def _run(coroutine: Any) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine)
    # Lock validation is synchronous by design and can run inside the live
    # coroutine.  A one-worker thread gives the sealed replay its own loop while
    # preserving a zero-network, zero-credential boundary.
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        return executor.submit(asyncio.run, coroutine).result()


def verify_correction_record(repository_root: Path | str) -> JournalRecord:
    return _run(verify_correction_record_async(repository_root))


def write_correction_record(
    repository_root: Path | str,
    *,
    corrected_at: str | None = None,
) -> JournalRecord:
    root = contract.repository_root(repository_root)
    paths = ContinuationPaths.for_repository(root)
    if paths.correction.exists():
        return verify_correction_record(root)
    if inspect_inventory(paths):
        raise OfflineCorrectionError(
            "offline correction must be the first continuation record"
        )
    payload = _run(
        build_correction_payload(root, corrected_at=corrected_at or utc_now())
    )
    try:
        return write_record(paths.correction, payload)
    except RecoveryJournalError as error:
        raise OfflineCorrectionError(str(error)) from error


__all__ = (
    "CORRECTION_SCHEMA",
    "CORRECTION_STATUS",
    "FALSE_NEGATIVE_KEYS",
    "OfflineCorrectionError",
    "build_correction_payload",
    "load_historical_parent",
    "verify_correction_record",
    "verify_correction_record_async",
    "write_correction_record",
)
