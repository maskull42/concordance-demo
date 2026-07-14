"""Build and validate the fail-closed divergence successor lock."""

from __future__ import annotations

import copy
import os
import subprocess
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from . import contract
from .parent import expected_parent_contract, verify_parent_snapshot


LOCK_SCHEMA_PATH = "candidate/rule3-successor-lock.schema.json"
PROTOCOL_PATH = "config/rule3-successor-protocol.json"
MODELS_CONFIG_PATH = "harness/config/models.json"
RULE3_LOCK_PATH = "candidate/rule3-lock.json"
RULE3_LOCK_SHA256 = (
    "8f4daf2ae53d07c7c53fc3f38d3ccd11aa18420185db632467fc9c280be523cc"
)

EXPECTED_CONTRACT_VALUES: dict[str, Any] = {
    "LOCK_SCHEMA_VERSION": "rule3-successor-lock-1.0.0",
    "LOCK_STATUS": "immutable-successor-preexecution-lock-no-spending-authorized",
    "LOCK_SCHEMA_PATH": LOCK_SCHEMA_PATH,
    "PROTOCOL_PATH": PROTOCOL_PATH,
    "MODELS_CONFIG_PATH": MODELS_CONFIG_PATH,
    "PRIVATE_ROOT_RELATIVE": f".pilot/divergence-successor/{contract.POOL_ID}",
    "POOL_SIZE": 1,
    "ATTEMPTS_PER_CELL": 1,
    "OUTPUT_TOKEN_CAP": 16_384,
    "CANDIDATE_COST_CAP_MICRODOLLARS": 6_000_000,
    "POOL_COST_CAP_MICRODOLLARS": 6_000_000,
    "MINIMUM_NON_NULL_ENDORSEMENTS": 6,
    "MINIMUM_DISTINCT_POSITIONS": 3,
    "MAXIMUM_ENDORSEMENTS_PER_POSITION": 4,
    "PREFLIGHT_REQUESTS_PER_MODEL": 1,
    "GENERATION_POSTS_PER_MODEL": 1,
    "AUTOMATIC_RETRIES": 0,
    "AUTHORIZATION_ENABLED": False,
    "AUTHORIZATION_STATEMENT": None,
    "AUTHORIZATION_STATEMENT_SHA256": None,
}
EXPECTED_AUTHORIZED_HOSTS = (
    "generativelanguage.googleapis.com",
    "api.anthropic.com",
    "api.cohere.com",
    "api.deepinfra.com",
    "api.deepseek.com",
    "api.mistral.ai",
    "api.x.ai",
    "openrouter.ai",
)
FULL_TRANSPORT_FIELDS = {
    "family",
    "provider",
    "requested_model_id",
    "route",
    "environment_variable",
    "api_style",
    "base_url",
    "generation_path",
    "metadata_path",
    "metadata_mode",
    "auth_kind",
    "fallback_allowed",
    "requests_per_second",
}

EXECUTION_SOURCE_PATHS = (
    "harness/authorize_divergence_successor.py",
    "harness/concordance_harness/__init__.py",
    "harness/concordance_harness/config.py",
    "harness/concordance_harness/execution.py",
    "harness/concordance_harness/planner.py",
    "harness/concordance_harness/providers.py",
    "harness/concordance_harness/util.py",
    "harness/concordance_recovery/__init__.py",
    "harness/concordance_recovery/journal.py",
    "harness/concordance_recovery/transport.py",
    "harness/create_divergence_successor_lock.py",
    "harness/divergence_successor/__init__.py",
    "harness/divergence_successor/authorization.py",
    "harness/divergence_successor/composite.py",
    "harness/divergence_successor/contract.py",
    "harness/divergence_successor/engine.py",
    "harness/divergence_successor/execute.py",
    "harness/divergence_successor/lock.py",
    "harness/divergence_successor/parent.py",
    "harness/divergence_successor/review.py",
    "harness/divergence_successor/review_assets/review.css",
    "harness/divergence_successor/review_assets/review.js",
    "harness/divergence_successor/state.py",
    "harness/private_directory_publication.py",
    "harness/quantum_disposition/__init__.py",
    "harness/quantum_disposition/contract.py",
    "harness/quantum_disposition/parent.py",
    "harness/quantum_disposition/record.py",
    "harness/run_divergence_successor.py",
    "harness/rule3/budget.py",
)


class DivergenceSuccessorContractIncomplete(contract.DivergenceSuccessorLockError):
    """The research contract does not yet contain execution authority facts."""


@dataclass(frozen=True)
class LockContext:
    repository_root: Path
    lock: dict[str, Any]
    lock_bytes: bytes
    lock_sha256: str
    git_head: str | None
    question_paths: tuple[Path, ...]
    candidate_plan_sha256: dict[str, str]


def contract_readiness() -> tuple[str, ...]:
    issues: list[str] = []
    for name, expected in EXPECTED_CONTRACT_VALUES.items():
        if not hasattr(contract, name):
            issues.append(f"missing contract.{name} = {expected!r}")
        elif getattr(contract, name) != expected:
            issues.append(
                f"contract.{name} must be {expected!r}, found {getattr(contract, name)!r}"
            )
    hosts = getattr(contract, "AUTHORIZED_HOSTS", None)
    if hosts != EXPECTED_AUTHORIZED_HOSTS:
        issues.append(
            "contract.AUTHORIZED_HOSTS must equal the eight ordered approved hosts"
        )
    params = getattr(contract, "EXPECTED_REQUEST_PARAMS", None)
    if not isinstance(params, dict) or set(params) != set(contract.MODEL_KEYS):
        issues.append(
            "contract.EXPECTED_REQUEST_PARAMS must bind every exact request parameter record"
        )
    pricing = getattr(contract, "APPROVED_PLANNING_PRICING", None)
    if not isinstance(pricing, dict) or set(pricing) != set(contract.MODEL_KEYS):
        issues.append(
            "contract.APPROVED_PLANNING_PRICING must bind all eight planning prices"
        )
    challenge = getattr(contract, "STANDARD_CHALLENGE_PROMPT", None)
    if not isinstance(challenge, str) or not challenge:
        issues.append("missing contract.STANDARD_CHALLENGE_PROMPT")
    transports = getattr(contract, "APPROVED_MODEL_TRANSPORTS", None)
    if not isinstance(transports, dict) or set(transports) != set(contract.MODEL_KEYS):
        issues.append("contract.APPROVED_MODEL_TRANSPORTS must bind all eight routes")
    else:
        for key in contract.MODEL_KEYS:
            value = transports.get(key)
            if not isinstance(value, dict) or set(value) != FULL_TRANSPORT_FIELDS:
                issues.append(
                    f"contract.APPROVED_MODEL_TRANSPORTS[{key!r}] lacks the full transport record"
                )
    return tuple(issues)


def require_contract_ready() -> None:
    issues = contract_readiness()
    if issues:
        raise DivergenceSuccessorContractIncomplete("; ".join(issues))


def _binding(root: Path, relative: str) -> dict[str, str]:
    try:
        payload = contract.read_regular_file(root, relative)
    except contract.ContractError as error:
        raise contract.DivergenceSuccessorLockError(str(error)) from error
    return {"path": relative, "sha256": contract.sha256_bytes(payload)}


def _json(root: Path, relative: str) -> tuple[dict[str, Any], bytes]:
    try:
        value, payload = contract.read_json_file(root, relative)
    except contract.ContractError as error:
        raise contract.DivergenceSuccessorLockError(str(error)) from error
    if not isinstance(value, dict):
        raise contract.DivergenceSuccessorLockError(f"{relative} must be an object")
    return value, payload


def _validate_question(value: dict[str, Any]) -> None:
    prompts = value.get("prompt_variants")
    positions = value.get("position_map")
    selection = value.get("selection")
    if (
        value.get("schema_version") != "1.0.0"
        or value.get("content_version") != contract.CONTENT_VERSION
        or value.get("data_class") != "research"
        or value.get("id") != contract.CANDIDATE_ID
        or value.get("kind") != "divergent"
        or not isinstance(selection, dict)
        or selection.get("status") != "candidate"
        or selection.get("pool_id") != contract.POOL_ID
        or selection.get("pool_size") != 1
        or selection.get("rule_version") != contract.RULE_VERSION
        or selection.get("candidate_role") != "replacement"
        or not isinstance(prompts, list)
        or len(prompts) != 1
        or prompts[0].get("id") != "default"
        or prompts[0].get("user_prompt") != contract.CANDIDATE_PROMPT
        or not isinstance(positions, list)
        or len(positions) != 4
        or value.get("map_is_nonexhaustive") is not True
        or value.get("verification")
        != {"status": "proposed", "verified_by": None, "verified_at": None}
    ):
        raise contract.DivergenceSuccessorLockError(
            "replacement question differs from the proposed successor contract"
        )
    position_ids = [item.get("id") for item in positions if isinstance(item, dict)]
    if position_ids != [
        "development-stage-licensing",
        "deployment-release-licensing",
        "binding-frontier-supervision",
        "use-centered-general-law",
    ]:
        raise contract.DivergenceSuccessorLockError(
            "replacement position hierarchy changed"
        )


def _validate_source_freeze(value: dict[str, Any]) -> None:
    questions = value.get("questions")
    question = questions[0] if isinstance(questions, list) and len(questions) == 1 else None
    sources = question.get("sources") if isinstance(question, dict) else None
    if (
        value.get("schema_version")
        != "rule3-successor-source-freeze-1.0.0"
        or value.get("content_version") != contract.CONTENT_VERSION
        or value.get("pool_id") != contract.POOL_ID
        or value.get("status") != "research-source-freeze-proposed"
        or value.get("access_state", {}).get("university_library_required")
        is not False
        or not isinstance(question, dict)
        or question.get("question_id") != contract.CANDIDATE_ID
        or question.get("question_path") != contract.QUESTION_PATH
        or not isinstance(sources, list)
        or len(sources) < 4
    ):
        raise contract.DivergenceSuccessorLockError(
            "successor source freeze does not bind the replacement question"
        )
    source_ids: set[str] = set()
    for source in sources:
        artifact = source.get("artifact") if isinstance(source, dict) else None
        verification = source.get("verification") if isinstance(source, dict) else None
        source_id = source.get("source_id") if isinstance(source, dict) else None
        digest = artifact.get("sha256") if isinstance(artifact, dict) else None
        if (
            not isinstance(source_id, str)
            or source_id in source_ids
            or not isinstance(source.get("source_url"), str)
            or not isinstance(artifact, dict)
            or (
                digest is not None
                and (
                    not isinstance(digest, str)
                    or len(digest) != 64
                    or any(character not in "0123456789abcdef" for character in digest)
                )
            )
            or verification
            != {"status": "proposed", "verified_by": None, "verified_at": None}
        ):
            raise contract.DivergenceSuccessorLockError(
                "successor source freeze contains malformed source evidence"
            )
        source_ids.add(source_id)


def _load_protocol(root: Path) -> tuple[dict[str, Any], bytes]:
    value, payload = _json(root, PROTOCOL_PATH)
    expected = {
        "protocol_version": "rule3-successor-1.0.0",
        "system_prompt": contract.SYSTEM_PROMPT,
        "standard_challenge_prompt": contract.STANDARD_CHALLENGE_PROMPT,
    }
    if value != expected:
        raise contract.DivergenceSuccessorLockError(
            "successor protocol differs from the execution contract"
        )
    return value, payload


def _load_parent_models(
    root: Path,
) -> tuple[list[dict[str, Any]], bytes, dict[str, Any]]:
    value, payload = _json(root, RULE3_LOCK_PATH)
    if contract.sha256_bytes(payload) != RULE3_LOCK_SHA256:
        raise contract.DivergenceSuccessorLockError("old Rule 3 lock changed")
    models = value.get("models")
    if not isinstance(models, list) or len(models) != len(contract.MODEL_KEYS):
        raise contract.DivergenceSuccessorLockError("old Rule 3 model panel changed")
    result: list[dict[str, Any]] = []
    for key, model in zip(contract.MODEL_KEYS, models, strict=True):
        if not isinstance(model, dict) or model.get("model_key") != key:
            raise contract.DivergenceSuccessorLockError("model panel order changed")
        requested, provider, route = contract.EXPECTED_MODELS[key]
        transport = contract.APPROVED_MODEL_TRANSPORTS[key]
        if (
            model.get("requested_model_id") != requested
            or model.get("provider") != provider
            or model.get("route") != route
            or any(model.get(name) != value for name, value in transport.items())
            or model.get("fallback_allowed") is not False
            or model.get("requested_params")
            != contract.EXPECTED_REQUEST_PARAMS[key]
            or model.get("planning_pricing")
            != contract.APPROVED_PLANNING_PRICING[key]
            or model.get("requested_params", {}).get("tools_enabled") is not False
            or model.get("requested_params", {}).get("web_search_enabled") is not False
            or model.get("requested_params", {}).get("retrieval_enabled") is not False
            or model.get("requested_params", {})
            .get("output_limit", {})
            .get("value")
            != contract.OUTPUT_TOKEN_CAP
        ):
            raise contract.DivergenceSuccessorLockError(
                f"successor route contract changed for {key}"
            )
        result.append(copy.deepcopy(model))
    models_config = value.get("bindings", {}).get("models_config")
    if (
        not isinstance(models_config, dict)
        or models_config.get("path") != MODELS_CONFIG_PATH
        or not isinstance(models_config.get("sha256"), str)
    ):
        raise contract.DivergenceSuccessorLockError(
            "old Rule 3 model-config binding changed"
        )
    return result, payload, models_config


def _host(model: Mapping[str, Any]) -> str:
    try:
        parsed = urllib.parse.urlsplit(model["base_url"])
        port = parsed.port
    except (KeyError, TypeError, ValueError) as error:
        raise contract.DivergenceSuccessorLockError(
            "model base URL is malformed"
        ) from error
    host = (parsed.hostname or "").lower().rstrip(".")
    if (
        parsed.scheme != "https"
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
    ):
        raise contract.DivergenceSuccessorLockError(
            "model base URL is not an approved HTTPS origin"
        )
    return host


def _plans(protocol: dict[str, Any], models: list[dict[str, Any]]) -> dict[str, Any]:
    messages = [
        {"role": "system", "content": protocol["system_prompt"]},
        {"role": "user", "content": contract.CANDIDATE_PROMPT},
    ]
    prompt_sha = contract.prompt_sha256(messages)
    cells = [
        {
            "cell_id": f"{contract.CANDIDATE_ID}:{model['model_key']}:default:answer",
            "model_key": model["model_key"],
            "prompt_sha256": prompt_sha,
            "requested_model_id": model["requested_model_id"],
            "route": model["route"],
            "requested_params": copy.deepcopy(model["requested_params"]),
            "semantic_attempt_number": 1,
            "maximum_generation_posts": 1,
        }
        for model in models
    ]
    plan_sha = contract.sha256_bytes(contract.canonical_json_bytes(cells))
    return {
        "call_type": "answer",
        "variant_id": "default",
        "candidate_plans": [
            {
                "candidate_id": contract.CANDIDATE_ID,
                "role": "replacement",
                "cell_count": 8,
                "cells": cells,
                "plan_sha256": plan_sha,
            }
        ],
        "ordered_universe_plan_sha256": plan_sha,
    }


def build_divergence_successor_lock(repository_root: Path | str) -> dict[str, Any]:
    """Build without credentials, private evidence, network, or spending authority."""

    require_contract_ready()
    root = contract.repository_root(repository_root)
    question, question_payload = _json(root, contract.QUESTION_PATH)
    _validate_question(question)
    freeze, freeze_payload = _json(root, contract.SOURCE_FREEZE_PATH)
    _validate_source_freeze(freeze)
    protocol, protocol_payload = _load_protocol(root)
    models, parent_lock_payload, parent_models_config = _load_parent_models(root)
    current_models_config = _binding(root, contract.MODELS_CONFIG_PATH)
    if current_models_config["sha256"] != parent_models_config["sha256"]:
        raise contract.DivergenceSuccessorLockError(
            "the shared eight-model configuration changed after Rule 3"
        )
    plans = _plans(protocol, models)
    hosts = tuple(_host(model) for model in models)
    if hosts != contract.AUTHORIZED_HOSTS:
        raise contract.DivergenceSuccessorLockError(
            "derived provider hosts differ from the contract allowlist"
        )
    execution_sources = [_binding(root, path) for path in EXECUTION_SOURCE_PATHS]
    return {
        "schema_version": contract.LOCK_SCHEMA_VERSION,
        "status": contract.LOCK_STATUS,
        "pool_id": contract.POOL_ID,
        "pool_size": contract.POOL_SIZE,
        "rule_version": contract.RULE_VERSION,
        "content_version": contract.CONTENT_VERSION,
        "private_root": contract.PRIVATE_ROOT_RELATIVE,
        "bindings": {
            "question": {
                "path": contract.QUESTION_PATH,
                "sha256": contract.sha256_bytes(question_payload),
            },
            "source_freeze": {
                "path": contract.SOURCE_FREEZE_PATH,
                "sha256": contract.sha256_bytes(freeze_payload),
            },
            "protocol": {
                "path": contract.PROTOCOL_PATH,
                "protocol_version": protocol["protocol_version"],
                "sha256": contract.sha256_bytes(protocol_payload),
            },
            "models_config": current_models_config,
            "lock_schema": _binding(root, contract.LOCK_SCHEMA_PATH),
            "old_rule3_lock": {
                "path": RULE3_LOCK_PATH,
                "sha256": contract.sha256_bytes(parent_lock_payload),
            },
        },
        "parent": expected_parent_contract(),
        "candidates": [
            {
                "id": contract.CANDIDATE_ID,
                "role": "replacement",
                "kind": "divergent",
                "path": contract.QUESTION_PATH,
                "sha256": contract.sha256_bytes(question_payload),
            }
        ],
        "models": models,
        "plans": plans,
        "execution_policy": {
            "call_type": "answer",
            "cells": 8,
            "preflight_requests_per_model": 1,
            "generation_posts_per_model": 1,
            "attempts_per_cell": 1,
            "automatic_retries": 0,
            "all_preflights_must_succeed_before_generation": True,
            "generation_parallel_after_gate": True,
            "intent_before_request": True,
            "raw_response_before_validation": True,
            "no_capture_attempt_is_consumed_and_terminal": True,
            "output_token_cap": contract.OUTPUT_TOKEN_CAP,
            "tools_enabled": False,
            "web_search_enabled": False,
            "retrieval_enabled": False,
            "external_context_enabled": False,
        },
        "budget": {
            "historical_reserved_microdollars": 3_543_497,
            "historical_spend_is_informational_only": True,
            "new_candidate_cap_microdollars": contract.CANDIDATE_COST_CAP_MICRODOLLARS,
            "new_pool_cap_microdollars": contract.POOL_COST_CAP_MICRODOLLARS,
            "lock_authorizes_spending": False,
        },
        "threshold": {
            "required_completed_responses": contract.REQUIRED_COMPLETED_RESPONSES,
            "minimum_non_null_primary_endorsements": contract.MINIMUM_NON_NULL_ENDORSEMENTS,
            "minimum_distinct_primary_positions": contract.MINIMUM_DISTINCT_POSITIONS,
            "maximum_primary_endorsements_per_position": contract.MAXIMUM_ENDORSEMENTS_PER_POSITION,
        },
        "network_policy": {
            "maximum_preflight_gets": 8,
            "maximum_generation_posts": 8,
            "maximum_outbound_requests": 16,
            "authorized_hosts": list(hosts),
            "unlisted_network_access_allowed": False,
        },
        "paid_authorization": {
            "required": True,
            "enabled": False,
            "lock_authorizes_spending": False,
            "exact_author_approval_committed": False,
            "authorization_statement": None,
            "authorization_statement_sha256": None,
            "fresh_official_pricing_recheck_required": True,
            "private_authorization_write_allowed": False,
            "provider_calls_allowed": False,
        },
        "execution_sources": execution_sources,
    }


def _difference(actual: Any, expected: Any, path: str = "lock") -> str | None:
    if type(actual) is not type(expected):
        return f"{path} type differs"
    if isinstance(expected, dict):
        if set(actual) != set(expected):
            return f"{path} fields differ"
        for key in expected:
            found = _difference(actual[key], expected[key], f"{path}.{key}")
            if found:
                return found
        return None
    if isinstance(expected, list):
        if len(actual) != len(expected):
            return f"{path} length differs"
        for index, (left, right) in enumerate(zip(actual, expected, strict=True)):
            found = _difference(left, right, f"{path}[{index}]")
            if found:
                return found
        return None
    return None if actual == expected else f"{path} differs"


def _git(root: Path, arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["/usr/bin/git", *arguments],
        cwd=root,
        check=False,
        capture_output=True,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": "/var/empty",
            "LANG": "C",
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
        },
    )


def _require_bound_sources_committed(
    root: Path, lock: dict[str, Any], *, include_lock: bool
) -> str:
    head_result = _git(root, ["rev-parse", "HEAD"])
    if head_result.returncode:
        raise contract.DivergenceSuccessorLockError("Git HEAD cannot be read")
    head = head_result.stdout.decode().strip()
    paths = [contract.LOCK_PATH] if include_lock else []
    paths.extend(item["path"] for item in lock["bindings"].values())
    paths.extend(item["path"] for item in lock["execution_sources"])
    paths = list(dict.fromkeys(paths))
    status = _git(
        root,
        ["status", "--porcelain", "--untracked-files=all", "--", *paths],
    )
    if status.returncode or status.stdout.strip():
        raise contract.DivergenceSuccessorLockError(
            "successor lock and bound sources must be committed and clean"
            if include_lock
            else "bound successor sources must be committed and clean before lock creation"
        )
    for relative in paths:
        disk = contract.read_regular_file(root, relative)
        committed = _git(root, ["show", f"{head}:{relative}"])
        if committed.returncode or committed.stdout != disk:
            raise contract.DivergenceSuccessorLockError(
                f"{relative} differs from committed HEAD"
            )
    return head


def _require_committed(root: Path, lock: dict[str, Any]) -> str:
    return _require_bound_sources_committed(root, lock, include_lock=True)


def load_and_validate_divergence_successor_lock(
    repository_root: Path | str,
    *,
    require_committed: bool = False,
    require_parent_private: bool = False,
) -> LockContext:
    root = contract.repository_root(repository_root)
    value, payload = _json(root, contract.LOCK_PATH)
    if payload != contract.canonical_json_bytes(value):
        raise contract.DivergenceSuccessorLockError(
            "successor lock is not canonical JSON"
        )
    expected = build_divergence_successor_lock(root)
    difference = _difference(value, expected)
    if difference:
        raise contract.DivergenceSuccessorLockError(difference)
    if require_parent_private:
        parent = verify_parent_snapshot(root)
        if value.get("parent") != parent.value():
            raise contract.DivergenceSuccessorLockError(
                "successor lock and private parent disagree"
            )
    git_head = _require_committed(root, value) if require_committed else None
    plan = value["plans"]["candidate_plans"][0]
    return LockContext(
        repository_root=root,
        lock=value,
        lock_bytes=payload,
        lock_sha256=contract.sha256_bytes(payload),
        git_head=git_head,
        question_paths=(root / contract.QUESTION_PATH,),
        candidate_plan_sha256={contract.CANDIDATE_ID: plan["plan_sha256"]},
    )


def write_divergence_successor_lock(repository_root: Path | str) -> LockContext:
    from .authorization import require_approval_enabled

    # The lock is non-spending authority, but it also binds the execution source
    # containing the exact later approval.  Sealing it earlier would make that
    # source hash stale the moment approval was committed.
    require_approval_enabled()
    root = contract.repository_root(repository_root)
    path = root / contract.LOCK_PATH
    value = build_divergence_successor_lock(root)
    payload = contract.canonical_json_bytes(value)
    _require_bound_sources_committed(root, value, include_lock=False)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(path, flags, 0o644)
    except FileExistsError as error:
        raise contract.DivergenceSuccessorLockError(
            "successor lock is write-once and already exists"
        ) from error
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    return load_and_validate_divergence_successor_lock(root)


def readiness(repository_root: Path | str) -> dict[str, Any]:
    issues = list(contract_readiness())
    if not issues:
        try:
            build_divergence_successor_lock(repository_root)
        except (OSError, ValueError, contract.DivergenceSuccessorLockError) as error:
            issues.append(str(error))
    from .authorization import approval_readiness

    approval_issues = approval_readiness()["issues"]
    status = (
        "ready-to-seal-successor-lock"
        if not issues and not approval_issues
        else (
            "ready-to-render-awaiting-exact-paid-approval"
            if not issues
            else "blocked-contract-incomplete"
        )
    )
    return {
        "status": status,
        "candidate_id": contract.CANDIDATE_ID,
        "issues": issues,
        "seal_issues": approval_issues,
        "lock_authorizes_spending": False,
        "private_writes": 0,
        "network_requests": 0,
        "environment_variables_read": 0,
    }


__all__ = (
    "DivergenceSuccessorContractIncomplete",
    "LockContext",
    "build_divergence_successor_lock",
    "contract_readiness",
    "load_and_validate_divergence_successor_lock",
    "readiness",
    "require_contract_ready",
    "write_divergence_successor_lock",
)
