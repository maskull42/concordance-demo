from __future__ import annotations

import asyncio
import fcntl
import json
import os
import re
import stat
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, ROUND_CEILING
from pathlib import Path, PurePosixPath
from typing import Any, AsyncIterator, Awaitable, Callable, Mapping

from concordance_harness import HARNESS_VERSION
from concordance_harness.config import (
    HarnessConfig,
    returned_model_id_is_approved,
    load_harness_config,
)
from concordance_harness.execution import (
    RateLimiter,
    billed_output_tokens,
    create_model_manifest,
)
from concordance_harness.planner import (
    PlannedCall,
    QuestionInput,
    build_plan,
    load_questions,
)
from concordance_harness.providers import (
    ProviderAdapter,
    ProviderError,
    ProviderResult,
    PreflightResult,
    Transport,
    UrllibTransport,
)
from concordance_harness.util import (
    canonical_json_bytes,
    estimate_message_tokens,
    prompt_sha256,
    sanitize,
    sha256_bytes,
    utc_now,
)

from .authorization import (
    RULE_VERSION,
    AuthorizationError,
    ContractBinding,
    ReceiptBinding,
    contract_binding,
    load_committed_lock,
    private_root,
    validate_paid_authorization,
    validate_pricing_recheck,
)
from .budget import (
    ATTEMPTS_PER_CELL,
    CANDIDATE_CAP_MICRODOLLARS,
    CANDIDATE_ORDER,
    FALLBACK_CANDIDATE_ID,
    OUTCOME_SCHEMA_VERSION,
    POOL_CAP_MICRODOLLARS,
    POOL_ID,
    PRIORITY_CANDIDATE_ID,
    AttemptNotAllowed,
    BudgetError,
    BudgetLedger,
    JournalRecord,
    StrandedIntent,
    ensure_private_root,
    read_private_json,
    write_once_private_json,
)

PHASE_CANDIDATE = {
    "priority": PRIORITY_CANDIDATE_ID,
    "fallback": FALLBACK_CANDIDATE_ID,
}
MODEL_KEYS = (
    "gemini",
    "claude",
    "cohere",
    "qwen",
    "deepseek",
    "mistral",
    "grok",
    "gpt",
)
OUTPUT_TOKEN_CAP = 16_384
EXPECTED_CELL_COUNT = 8
FINISH_REASON_BY_API_STYLE = {
    "google": "STOP",
    "anthropic": "end_turn",
    "cohere": "COMPLETE",
    "xai-responses": "completed",
    "openai": "stop",
}

MANIFEST_SCHEMA_VERSION = "rule3-model-manifest-1.0.0"
PREFLIGHT_INTENT_SCHEMA_VERSION = "rule3-preflight-intent-1.0.0"
PREFLIGHT_OUTCOME_SCHEMA_VERSION = "rule3-preflight-outcome-1.0.0"
RUN_SCHEMA_VERSION = "rule3-candidate-run-1.0.0"
FALLBACK_ELIGIBILITY_SCHEMA_VERSION = "rule3-fallback-eligibility-1.0.0"
FALLBACK_ELIGIBILITY_FILENAME = "fallback-eligibility.json"
FINAL_SELECTION_FILENAMES = ("selection.json", "terminal.json")
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
MANIFEST_ID_PATTERN = re.compile(r"^model-panel-[0-9]{8}-[0-9]{6}$")

PREFLIGHT_INTENT_KEYS = {
    "schema_version",
    "status",
    "pool_id",
    "rule_version",
    "git_head",
    "lock_sha256",
    "authorization_receipt_sha256",
    "pricing_recheck_receipt_sha256",
    "candidate_id",
    "phase",
    "config_sha256",
    "model_key",
    "provider",
    "route",
    "requested_model_id",
    "attempt_number",
    "created_at",
}
PREFLIGHT_OUTCOME_COMMON_KEYS = PREFLIGHT_INTENT_KEYS | {
    "intent_path",
    "intent_sha256",
    "completed_at",
}
PREFLIGHT_SUCCESS_KEYS = PREFLIGHT_OUTCOME_COMMON_KEYS | {
    "provider_returned_model_id",
    "provider_name",
    "sanitized_note",
}
PREFLIGHT_ERROR_KEYS = PREFLIGHT_OUTCOME_COMMON_KEYS | {"error"}

FALLBACK_ELIGIBILITY_KEYS = {
    "schema_version",
    "status",
    "pool_id",
    "rule_version",
    "created_at",
    "git_head",
    "lock_sha256",
    "authorization_receipt_sha256",
    "pricing_recheck_receipt_sha256",
    "priority_candidate_id",
    "fallback_candidate_id",
    "priority_run_receipt",
    "author_review_receipt",
    "evaluation_receipt",
    "threshold_result",
}


class Rule3ExecutionError(RuntimeError):
    """Raised before an unapproved, unauditable, or replayed Rule 3 request."""


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.utcoffset() is not None else None


def _is_timestamp(value: Any) -> bool:
    return _parse_timestamp(value) is not None


@dataclass(frozen=True)
class PreparedExecution:
    repository_root: Path
    phase: str
    candidate_id: str
    lock_context: Any
    binding: ContractBinding
    authorization: ReceiptBinding | None
    pricing_recheck: ReceiptBinding | None
    config: HarnessConfig
    protocol: dict[str, str]
    questions: tuple[QuestionInput, ...]
    question: QuestionInput
    plan: tuple[PlannedCall, ...]
    plan_sha256: str
    all_plans: dict[str, tuple[PlannedCall, ...]]
    all_plan_sha256: dict[str, str]
    private_root: Path


@dataclass(frozen=True)
class ExecutionResult:
    path: Path
    payload: dict[str, Any]
    sha256: str
    network_requests: int


def _load_protocol(path: Path) -> dict[str, str]:
    try:
        raw = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as error:
        raise Rule3ExecutionError(
            f"locked protocol cannot be loaded: {error}"
        ) from error
    expected = {"protocol_version", "system_prompt", "standard_challenge_prompt"}
    if (
        not isinstance(raw, dict)
        or set(raw) != expected
        or not all(isinstance(raw.get(key), str) for key in expected)
    ):
        raise Rule3ExecutionError("locked protocol differs from its frozen shape")
    return raw


def plan_contract_sha256(plan: tuple[PlannedCall, ...]) -> str:
    contract = [
        {
            "cell_id": call.cell_id,
            "prompt_sha256": prompt_sha256(call.answer_messages()),
            "requested_model_id": call.model.requested_model_id,
            "route": call.model.route,
            "requested_params": call.model.requested_params_receipt(),
        }
        for call in plan
    ]
    return sha256_bytes(canonical_json_bytes(contract))


def _question_paths(lock_context: Any) -> tuple[Path, ...]:
    try:
        values = tuple(Path(path).resolve() for path in lock_context.question_paths)
    except (AttributeError, TypeError) as error:
        raise Rule3ExecutionError(
            "lock context lacks two exact question paths"
        ) from error
    if len(values) != 2:
        raise Rule3ExecutionError("lock context must bind exactly two questions")
    return values


def _load_bound_questions(lock_context: Any, root: Path) -> tuple[QuestionInput, ...]:
    paths = _question_paths(lock_context)
    parents = {path.parent for path in paths}
    if len(parents) != 1:
        raise Rule3ExecutionError("locked Rule 3 questions must share one directory")
    questions = load_questions(next(iter(parents)))
    by_id = {question.question_id: question for question in questions}
    if tuple(by_id) != tuple(sorted(by_id)):
        # load_questions sorts paths. This branch documents that ordering never
        # chooses priority; the lock does.
        by_id = dict(by_id)
    if set(by_id) != set(CANDIDATE_ORDER):
        raise Rule3ExecutionError(
            "question directory differs from the two-candidate lock"
        )
    ordered = tuple(by_id[candidate] for candidate in CANDIDATE_ORDER)
    if tuple(question.path.resolve() for question in ordered) != paths:
        # Lock context is required to expose priority then fallback paths.
        raise Rule3ExecutionError(
            "lock question order differs from priority then fallback"
        )
    for question in ordered:
        try:
            question.path.resolve().relative_to(root)
        except ValueError as error:
            raise Rule3ExecutionError(
                "locked question escapes the repository"
            ) from error
    return ordered


def _context_plan_hash(lock_context: Any, candidate_id: str) -> str:
    try:
        value = lock_context.candidate_plan_sha256
    except AttributeError as error:
        raise Rule3ExecutionError("lock context lacks candidate plan hashes") from error
    if isinstance(value, dict):
        digest = value.get(candidate_id)
    elif isinstance(value, (tuple, list)) and len(value) == 2:
        digest = value[CANDIDATE_ORDER.index(candidate_id)]
    else:
        digest = None
    if not isinstance(digest, str) or not SHA256_PATTERN.fullmatch(digest):
        raise Rule3ExecutionError(f"lock plan hash is missing for {candidate_id}")
    return digest


def _validate_plan(
    plan: tuple[PlannedCall, ...],
    candidate_id: str,
    expected_hash: str,
) -> str:
    if (
        len(plan) != EXPECTED_CELL_COUNT
        or tuple(call.model.model_key for call in plan) != MODEL_KEYS
        or any(call.question.question_id != candidate_id for call in plan)
        or any(call.variant_id != "default" for call in plan)
        or any(call.call_type != "answer" for call in plan)
        or len({call.cell_id for call in plan}) != EXPECTED_CELL_COUNT
        or any(call.model.output_cap != OUTPUT_TOKEN_CAP for call in plan)
    ):
        raise Rule3ExecutionError(
            f"{candidate_id} is not the exact eight-cell answer-only plan"
        )
    digest = plan_contract_sha256(plan)
    if digest != expected_hash:
        raise Rule3ExecutionError(
            f"{candidate_id} plan differs from the committed lock"
        )
    return digest


def reserved_microdollars(call: PlannedCall) -> int:
    """Reserve deterministic input plus the complete total-output ceiling."""
    input_tokens = estimate_message_tokens(call.answer_messages())
    pricing = call.model.planning_pricing
    microdollars = Decimal(input_tokens) * Decimal(
        str(pricing["input_per_million"])
    ) + Decimal(call.model.output_cap) * Decimal(str(pricing["output_per_million"]))
    return int(microdollars.to_integral_value(rounding=ROUND_CEILING))


def _expected_effective_params(call: PlannedCall) -> dict[str, Any]:
    model = call.model
    values: dict[str, Any] = {}
    if model.temperature["mode"] == "fixed":
        values["temperature"] = {
            "state": "known",
            "value": model.temperature["value"],
            "source": "request",
        }
    else:
        values["temperature"] = {"state": "not-reported", "value": None}
    values[model.output_limit["parameter"]] = {
        "state": "known",
        "value": model.output_cap,
        "source": "request",
    }
    if model.provider_options:
        values["provider_options"] = {
            "state": "known",
            "value": model.provider_options,
            "source": "request",
        }
    return values


def _approved_returned_model_ids(call: PlannedCall) -> list[str]:
    candidates = (
        call.model.requested_model_id,
        f"models/{call.model.requested_model_id}",
        "openai/gpt-5.6-sol-20260709",
    )
    return [
        value
        for value in dict.fromkeys(candidates)
        if returned_model_id_is_approved(call.model, value)
    ]


def _cell_contracts(
    prepared: PreparedExecution,
) -> dict[tuple[str, str], dict[str, Any]]:
    contracts = {}
    for candidate_id, plan in prepared.all_plans.items():
        phase = "priority" if candidate_id == PRIORITY_CANDIDATE_ID else "fallback"
        for call in plan:
            messages = call.answer_messages()
            requested = call.model.requested_params_receipt()
            pricing = call.model.planning_pricing
            contracts[(candidate_id, call.model.model_key)] = {
                "candidate_id": candidate_id,
                "phase": phase,
                "cell_id": call.cell_id,
                "model_key": call.model.model_key,
                "model_family": call.model.family,
                "provider": call.model.provider,
                "route": call.model.route,
                "requested_model_id": call.model.requested_model_id,
                "approved_returned_model_ids": _approved_returned_model_ids(call),
                "api_style": call.model.api_style,
                "question_sha256": call.question.sha256,
                "prompt_sha256": prompt_sha256(messages),
                "messages": messages,
                "messages_sha256": sha256_bytes(canonical_json_bytes(messages)),
                "requested_params": requested,
                "requested_params_sha256": sha256_bytes(
                    canonical_json_bytes(requested)
                ),
                "effective_params": _expected_effective_params(call),
                "finish_reason": FINISH_REASON_BY_API_STYLE[call.model.api_style],
                "reserved_cost_microdollars": reserved_microdollars(call),
                "input_per_million": pricing["input_per_million"],
                "output_per_million": pricing["output_per_million"],
                "pricing_as_of": pricing["pricing_as_of"],
            }
    return contracts


def _make_ledger(prepared: PreparedExecution) -> BudgetLedger:
    assert prepared.authorization is not None
    assert prepared.pricing_recheck is not None
    if prepared.binding.git_head is None:
        raise Rule3ExecutionError("live Rule 3 execution lacks a committed Git HEAD")
    return BudgetLedger(
        prepared.private_root,
        lock_sha256=prepared.binding.lock_sha256,
        authorization_receipt_sha256=prepared.authorization.sha256,
        pricing_recheck_receipt_sha256=prepared.pricing_recheck.sha256,
        git_head=prepared.binding.git_head,
        cell_contracts=_cell_contracts(prepared),
    )


def _validate_caps(all_plans: dict[str, tuple[PlannedCall, ...]]) -> None:
    candidate_maxima = {
        candidate: ATTEMPTS_PER_CELL * sum(reserved_microdollars(call) for call in plan)
        for candidate, plan in all_plans.items()
    }
    if any(value > CANDIDATE_CAP_MICRODOLLARS for value in candidate_maxima.values()):
        raise Rule3ExecutionError(
            "locked three-attempt plan exceeds the $6 candidate reservation cap"
        )
    if sum(candidate_maxima.values()) > POOL_CAP_MICRODOLLARS:
        raise Rule3ExecutionError(
            "locked two-candidate plan exceeds the $12 pool reservation cap"
        )


def _manifest_path(root: Path, candidate_id: str) -> Path:
    return root / "manifests" / f"{candidate_id}.json"


def _preflight_intent_path(
    root: Path, candidate_id: str, model_key: str, attempt_number: int
) -> Path:
    return (
        root
        / "preflight"
        / "intents"
        / candidate_id
        / model_key
        / f"attempt-{attempt_number}.json"
    )


def _preflight_outcome_path(
    root: Path, candidate_id: str, model_key: str, attempt_number: int
) -> Path:
    return (
        root
        / "preflight"
        / "outcomes"
        / candidate_id
        / model_key
        / f"attempt-{attempt_number}.json"
    )


def _run_path(root: Path, candidate_id: str) -> Path:
    return root / "runs" / f"{candidate_id}.json"


def _eligibility_path(root: Path) -> Path:
    return root / FALLBACK_ELIGIBILITY_FILENAME


def _relative_private_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise Rule3ExecutionError(f"{label} path is malformed")
    pure = PurePosixPath(value)
    if (
        pure.is_absolute()
        or str(pure) != value
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise Rule3ExecutionError(f"{label} path escapes the private root")
    return value


def _bound_private_record(root: Path, value: Any, label: str) -> JournalRecord:
    if (
        not isinstance(value, dict)
        or set(value) != {"path", "sha256"}
        or not isinstance(value.get("sha256"), str)
        or not SHA256_PATTERN.fullmatch(value["sha256"])
    ):
        raise Rule3ExecutionError(f"{label} binding is malformed")
    relative = _relative_private_path(value.get("path"), label)
    path = root / relative
    try:
        record = read_private_json(path, label)
    except BudgetError as error:
        raise Rule3ExecutionError(str(error)) from error
    if record.sha256 != value["sha256"]:
        raise Rule3ExecutionError(f"{label} differs from its eligibility binding")
    return record


def validate_fallback_eligibility(prepared: PreparedExecution) -> ReceiptBinding:
    assert prepared.authorization is not None
    assert prepared.pricing_recheck is not None
    path = _eligibility_path(prepared.private_root)
    try:
        record = read_private_json(path, "Rule 3 fallback eligibility")
    except BudgetError as error:
        raise Rule3ExecutionError(str(error)) from error
    raw = record.payload
    if set(raw) != FALLBACK_ELIGIBILITY_KEYS:
        raise Rule3ExecutionError(
            "fallback eligibility fields differ from the contract"
        )
    threshold = raw.get("threshold_result")
    if (
        raw.get("schema_version") != FALLBACK_ELIGIBILITY_SCHEMA_VERSION
        or raw.get("status")
        != "fallback-eligible-after-complete-reviewed-priority-failure"
        or raw.get("pool_id") != POOL_ID
        or raw.get("rule_version") != RULE_VERSION
        or not isinstance(raw.get("created_at"), str)
        or raw.get("git_head") != prepared.binding.git_head
        or raw.get("lock_sha256") != prepared.binding.lock_sha256
        or raw.get("authorization_receipt_sha256") != prepared.authorization.sha256
        or raw.get("pricing_recheck_receipt_sha256") != prepared.pricing_recheck.sha256
        or raw.get("priority_candidate_id") != PRIORITY_CANDIDATE_ID
        or raw.get("fallback_candidate_id") != FALLBACK_CANDIDATE_ID
        or not isinstance(threshold, dict)
        or set(threshold)
        != {
            "evidence_complete",
            "author_review_complete",
            "qualifies",
            "non_null_primary_count",
            "represented_position_count",
            "maximum_position_primary_count",
            "failure_reasons",
        }
        or threshold.get("evidence_complete") is not True
        or threshold.get("author_review_complete") is not True
        or threshold.get("qualifies") is not False
        or not isinstance(threshold.get("failure_reasons"), list)
        or not threshold["failure_reasons"]
    ):
        raise Rule3ExecutionError(
            "fallback eligibility does not prove a complete author-reviewed threshold failure"
        )
    priority = _bound_private_record(
        prepared.private_root, raw.get("priority_run_receipt"), "priority run receipt"
    )
    if (
        priority.payload.get("schema_version") != RUN_SCHEMA_VERSION
        or priority.payload.get("status") != "complete-eight-successes"
        or priority.payload.get("candidate_id") != PRIORITY_CANDIDATE_ID
        or priority.payload.get("successful_outcome_count") != 8
    ):
        raise Rule3ExecutionError(
            "fallback eligibility binds an incomplete priority run"
        )
    _bound_private_record(
        prepared.private_root, raw.get("author_review_receipt"), "author review receipt"
    )
    _bound_private_record(
        prepared.private_root,
        raw.get("evaluation_receipt"),
        "priority evaluation receipt",
    )
    try:
        from .evaluate import Rule3EvaluationError, verify_fallback_eligibility
        from .review import Rule3ReviewError
    except (ImportError, AttributeError) as error:
        raise Rule3ExecutionError(
            f"fallback eligibility verifier is unavailable: {error}"
        ) from error
    try:
        verified = verify_fallback_eligibility(prepared.repository_root)
    except (Rule3EvaluationError, Rule3ReviewError, BudgetError, OSError) as error:
        raise Rule3ExecutionError(
            f"fallback eligibility failed its complete offline review verification: {error}"
        ) from error
    verified_path = verified.get("path") if isinstance(verified, dict) else None
    if (
        not isinstance(verified, dict)
        or verified.get("value") != raw
        or verified.get("sha256") != record.sha256
        or not isinstance(verified_path, (str, Path))
        or Path(verified_path).resolve() != path.resolve()
    ):
        raise Rule3ExecutionError(
            "fallback eligibility differs from the verified offline review chain"
        )
    return ReceiptBinding(path=path, payload=raw, sha256=record.sha256)


def _fallback_state_paths(root: Path) -> tuple[Path, ...]:
    return (
        _eligibility_path(root),
        _manifest_path(root, FALLBACK_CANDIDATE_ID),
        root / "budget" / "intents" / FALLBACK_CANDIDATE_ID,
        root / "outcomes" / FALLBACK_CANDIDATE_ID,
        root / "preflight" / "intents" / FALLBACK_CANDIDATE_ID,
        root / "preflight" / "outcomes" / FALLBACK_CANDIDATE_ID,
        _run_path(root, FALLBACK_CANDIDATE_ID),
    )


def _has_state(path: Path) -> bool:
    if not path.exists():
        return False
    if path.is_dir():
        return any(path.iterdir())
    return True


def _validate_phase_state(prepared: PreparedExecution) -> None:
    if any(
        _has_state(prepared.private_root / name) for name in FINAL_SELECTION_FILENAMES
    ):
        raise Rule3ExecutionError(
            "Rule 3 already has a terminal receipt; no replay allowed"
        )
    run_path = _run_path(prepared.private_root, prepared.candidate_id)
    if run_path.exists():
        raise Rule3ExecutionError(
            f"{prepared.candidate_id} already has a write-once run receipt; no replay allowed"
        )
    if prepared.phase == "priority":
        existing = [
            path
            for path in _fallback_state_paths(prepared.private_root)
            if _has_state(path)
        ]
        if existing:
            raise Rule3ExecutionError(
                "priority execution refuses existing fallback state; no request sent"
            )
    else:
        validate_fallback_eligibility(prepared)


def _history_gate(prepared: PreparedExecution, ledger: BudgetLedger) -> None:
    # Validate every durable record, including orphan outcomes and skipped
    # attempts, before interpreting the candidate's latest state.
    ledger.snapshot()
    manifest_path = _manifest_path(prepared.private_root, prepared.candidate_id)
    manifest = _load_manifest(prepared) if manifest_path.is_file() else None
    candidate_has_journal = any(
        ledger.cell_history(prepared.candidate_id, model_key)
        for model_key in MODEL_KEYS
    )
    if candidate_has_journal and manifest is None:
        raise Rule3ExecutionError(
            "attempt journal exists without its bound model manifest"
        )
    for model_key in MODEL_KEYS:
        history = ledger.cell_history(prepared.candidate_id, model_key)
        if not history:
            continue
        if manifest is not None and any(
            attempt.payload["manifest_sha256"] != manifest.sha256
            or (
                attempt_outcome is not None
                and attempt_outcome.payload["manifest_sha256"] != manifest.sha256
            )
            for attempt, attempt_outcome in history
        ):
            raise Rule3ExecutionError(
                f"attempt journal binds another model manifest for "
                f"{history[-1][0].payload['cell_id']}"
            )
        intent, outcome = history[-1]
        if outcome is None:
            raise Rule3ExecutionError(
                f"stranded intent stops {intent.payload['cell_id']}; no environment variable read"
            )
        if outcome.payload["status"] == "success":
            continue
        error = outcome.payload["error"]
        if not error["retryable"]:
            raise Rule3ExecutionError(
                f"nonretryable outcome stops {intent.payload['cell_id']}; no replay allowed"
            )
        if intent.payload["attempt_number"] >= ATTEMPTS_PER_CELL:
            raise Rule3ExecutionError(
                f"three-attempt ceiling exhausted for {intent.payload['cell_id']}"
            )


def _prepare_execution(
    repository_root: Path,
    phase: str,
    *,
    live: bool,
    lock_loader: Callable[[Path], Any],
) -> PreparedExecution:
    """Validate the complete plan and, for live use, every pre-environment gate."""
    if phase not in PHASE_CANDIDATE:
        raise Rule3ExecutionError(
            "Rule 3 phase must be priority or fallback; no third candidate"
        )
    root = repository_root.resolve()
    try:
        lock_context = lock_loader(root)
        binding = contract_binding(lock_context, require_git_head=live)
    except AuthorizationError as error:
        raise Rule3ExecutionError(str(error)) from error
    if binding.repository_root != root:
        raise Rule3ExecutionError("Rule 3 lock belongs to another repository")

    config = load_harness_config(binding.models_config_path)
    protocol_path = Path(lock_context.protocol_path).resolve()
    protocol = _load_protocol(protocol_path)
    questions = _load_bound_questions(lock_context, root)
    all_plans: dict[str, tuple[PlannedCall, ...]] = {}
    all_hashes: dict[str, str] = {}
    for question in questions:
        candidate_plan = build_plan(
            (question,),
            config.models,
            protocol["system_prompt"],
            protocol["standard_challenge_prompt"],
            answer_only=True,
        )
        expected = _context_plan_hash(lock_context, question.question_id)
        all_hashes[question.question_id] = _validate_plan(
            candidate_plan, question.question_id, expected
        )
        all_plans[question.question_id] = candidate_plan
    _validate_caps(all_plans)

    candidate_id = PHASE_CANDIDATE[phase]
    question = next(item for item in questions if item.question_id == candidate_id)
    authorization = None
    pricing = None
    private = private_root(root)
    prepared = PreparedExecution(
        repository_root=root,
        phase=phase,
        candidate_id=candidate_id,
        lock_context=lock_context,
        binding=binding,
        authorization=None,
        pricing_recheck=None,
        config=config,
        protocol=protocol,
        questions=questions,
        question=question,
        plan=all_plans[candidate_id],
        plan_sha256=all_hashes[candidate_id],
        all_plans=all_plans,
        all_plan_sha256=all_hashes,
        private_root=private,
    )
    if not live:
        return prepared

    try:
        authorization = validate_paid_authorization(lock_context)
        pricing = validate_pricing_recheck(lock_context)
    except AuthorizationError as error:
        raise Rule3ExecutionError(str(error)) from error
    prepared = PreparedExecution(
        **{
            **prepared.__dict__,
            "authorization": authorization,
            "pricing_recheck": pricing,
        }
    )
    _validate_phase_state(prepared)
    ledger = _make_ledger(prepared)
    try:
        _history_gate(prepared, ledger)
        _preflight_state_gate(prepared)
        if _manifest_path(private, candidate_id).exists():
            _load_manifest(prepared)
    except BudgetError as error:
        raise Rule3ExecutionError(str(error)) from error
    return prepared


def prepare_execution(
    repository_root: Path,
    phase: str,
    *,
    live: bool,
) -> PreparedExecution:
    """Use only the fixed production lock loaders at the public boundary."""
    loader = load_committed_lock if live else _load_uncommitted_lock
    return _prepare_execution(
        repository_root,
        phase,
        live=live,
        lock_loader=loader,
    )


def _load_uncommitted_lock(repository_root: Path) -> Any:
    try:
        from rule3.lock import Rule3LockError, load_and_validate_rule3_lock
    except (ImportError, AttributeError) as error:
        raise AuthorizationError(
            "Rule 3 lock adapter unavailable for dry-run planning"
        ) from error
    try:
        return load_and_validate_rule3_lock(
            repository_root.resolve(), require_committed=False
        )
    except Rule3LockError as error:
        raise AuthorizationError(str(error)) from error


def dry_run_summary(prepared: PreparedExecution) -> dict[str, Any]:
    costs = {
        call.model.model_key: reserved_microdollars(call) for call in prepared.plan
    }
    return {
        "phase": prepared.phase,
        "candidate_id": prepared.candidate_id,
        "logical_cells": len(prepared.plan),
        "call_type": "answer",
        "model_keys": list(MODEL_KEYS),
        "plan_sha256": prepared.plan_sha256,
        "one_attempt_reserved_microdollars": sum(costs.values()),
        "three_attempt_reserved_microdollars": ATTEMPTS_PER_CELL * sum(costs.values()),
        "per_model_reserved_microdollars": costs,
        "network_requests": 0,
        "environment_variables_read": 0,
    }


def _preflight_intent_payload(
    prepared: PreparedExecution, model: Any, attempt_number: int
) -> dict[str, Any]:
    assert prepared.authorization is not None
    assert prepared.pricing_recheck is not None
    return {
        "schema_version": PREFLIGHT_INTENT_SCHEMA_VERSION,
        "status": "reserved-before-metadata",
        "pool_id": POOL_ID,
        "rule_version": RULE_VERSION,
        "git_head": prepared.binding.git_head,
        "lock_sha256": prepared.binding.lock_sha256,
        "authorization_receipt_sha256": prepared.authorization.sha256,
        "pricing_recheck_receipt_sha256": prepared.pricing_recheck.sha256,
        "candidate_id": prepared.candidate_id,
        "phase": prepared.phase,
        "config_sha256": prepared.config.sha256,
        "model_key": model.model_key,
        "provider": model.provider,
        "route": model.route,
        "requested_model_id": model.requested_model_id,
        "attempt_number": attempt_number,
        "created_at": utc_now(),
    }


def _validate_preflight_intent(
    prepared: PreparedExecution,
    model: Any,
    record: JournalRecord,
    attempt_number: int,
) -> None:
    expected = _preflight_intent_payload(prepared, model, attempt_number)
    expected["created_at"] = record.payload.get("created_at")
    expected_path = _preflight_intent_path(
        prepared.private_root,
        prepared.candidate_id,
        model.model_key,
        attempt_number,
    )
    if (
        set(record.payload) != PREFLIGHT_INTENT_KEYS
        or record.payload != expected
        or not isinstance(record.payload.get("attempt_number"), int)
        or isinstance(record.payload.get("attempt_number"), bool)
        or not 1 <= record.payload["attempt_number"] <= ATTEMPTS_PER_CELL
        or not _is_timestamp(record.payload.get("created_at"))
        or record.path.absolute() != expected_path.absolute()
    ):
        raise Rule3ExecutionError(
            f"preflight intent differs from the locked model {model.model_key}"
        )


def _preflight_outcome_payload(
    prepared: PreparedExecution,
    intent: JournalRecord,
    *,
    result: PreflightResult | None = None,
    error: ProviderError | None = None,
    secrets: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    value = {
        **intent.payload,
        "schema_version": PREFLIGHT_OUTCOME_SCHEMA_VERSION,
        "status": "success" if result is not None else "error",
        "intent_path": str(intent.path.relative_to(prepared.private_root)),
        "intent_sha256": intent.sha256,
        "completed_at": utc_now(),
    }
    if result is not None:
        return {
            **value,
            "provider_returned_model_id": result.returned_model_id,
            "provider_name": result.provider_name,
            "sanitized_note": result.note,
        }
    assert error is not None
    return {
        **value,
        "error": {
            "category": error.category,
            "retryable": error.retryable,
            "sanitized_summary": sanitize(error, (secrets or {}).values()),
        },
    }


def _validate_preflight_outcome(
    prepared: PreparedExecution,
    model: Any,
    intent: JournalRecord,
    outcome: JournalRecord,
) -> PreflightResult | None:
    attempt = intent.payload["attempt_number"]
    _validate_preflight_intent(prepared, model, intent, attempt)
    value = outcome.payload
    if value.get("status") not in {"success", "error"}:
        raise Rule3ExecutionError(
            f"preflight outcome status is invalid for {model.model_key}"
        )
    expected_keys = (
        PREFLIGHT_SUCCESS_KEYS
        if value.get("status") == "success"
        else PREFLIGHT_ERROR_KEYS
    )
    expected_common = {
        **intent.payload,
        "schema_version": PREFLIGHT_OUTCOME_SCHEMA_VERSION,
        "status": value.get("status"),
        "intent_path": str(intent.path.relative_to(prepared.private_root)),
        "intent_sha256": intent.sha256,
        "completed_at": value.get("completed_at"),
    }
    expected_path = _preflight_outcome_path(
        prepared.private_root,
        prepared.candidate_id,
        model.model_key,
        attempt,
    )
    created_at = _parse_timestamp(intent.payload.get("created_at"))
    completed_at = _parse_timestamp(value.get("completed_at"))
    if (
        set(value) != expected_keys
        or any(value.get(key) != expected for key, expected in expected_common.items())
        or created_at is None
        or completed_at is None
        or completed_at < created_at
        or outcome.path.absolute() != expected_path.absolute()
    ):
        raise Rule3ExecutionError(
            f"preflight outcome differs from its durable intent for {model.model_key}"
        )
    if value["status"] == "success":
        returned = value.get("provider_returned_model_id")
        provider_name = value.get("provider_name")
        note = value.get("sanitized_note")
        if (
            not isinstance(returned, str)
            or not returned_model_id_is_approved(model, returned)
            or (
                provider_name is not None
                and (not isinstance(provider_name, str) or not provider_name)
            )
            or (note is not None and (not isinstance(note, str) or not note))
            or (model.model_key == "gpt" and provider_name != "OpenAI")
        ):
            raise Rule3ExecutionError(
                f"preflight model identity differs for {model.model_key}"
            )
        return PreflightResult(returned, provider_name, note)
    error = value.get("error")
    retryable_categories = {
        "invalid-request",
        "network",
        "provider-error",
        "rate-limit",
        "timeout",
    }
    categories = retryable_categories | {
        "authentication",
        "authorization",
        "response-validation",
        "unavailable",
    }
    if (
        not isinstance(error, dict)
        or set(error) != {"category", "retryable", "sanitized_summary"}
        or error.get("category") not in categories
        or not isinstance(error.get("retryable"), bool)
        or (error["retryable"] and error["category"] not in retryable_categories)
        or not isinstance(error.get("sanitized_summary"), str)
        or not error["sanitized_summary"]
    ):
        raise Rule3ExecutionError(
            f"preflight error retry policy is malformed for {model.model_key}"
        )
    return None


def _preflight_history(
    prepared: PreparedExecution, model: Any
) -> tuple[tuple[JournalRecord, JournalRecord | None], ...]:
    history = []
    found_gap = False
    for attempt in range(1, ATTEMPTS_PER_CELL + 1):
        intent_path = _preflight_intent_path(
            prepared.private_root,
            prepared.candidate_id,
            model.model_key,
            attempt,
        )
        outcome_path = _preflight_outcome_path(
            prepared.private_root,
            prepared.candidate_id,
            model.model_key,
            attempt,
        )
        if not intent_path.exists():
            found_gap = True
            if outcome_path.exists():
                raise Rule3ExecutionError(
                    f"orphan preflight outcome exists for {model.model_key}"
                )
            continue
        if found_gap:
            raise Rule3ExecutionError(
                f"preflight attempt history skips a number for {model.model_key}"
            )
        try:
            intent = read_private_json(intent_path, "Rule 3 preflight intent")
            _validate_preflight_intent(prepared, model, intent, attempt)
            outcome = (
                read_private_json(outcome_path, "Rule 3 preflight outcome")
                if outcome_path.exists()
                else None
            )
        except BudgetError as error:
            raise Rule3ExecutionError(str(error)) from error
        if outcome is not None:
            _validate_preflight_outcome(prepared, model, intent, outcome)
        history.append((intent, outcome))
    for index, (_, outcome) in enumerate(history[:-1]):
        if (
            outcome is None
            or outcome.payload["status"] != "error"
            or not outcome.payload["error"]["retryable"]
        ):
            raise Rule3ExecutionError(
                f"preflight attempt follows a terminal result for {model.model_key}"
            )
    return tuple(history)


def _validate_preflight_tree(prepared: PreparedExecution) -> None:
    expected: set[Path] = set()
    for model in prepared.config.models:
        for intent, outcome in _preflight_history(prepared, model):
            expected.add(intent.path.absolute())
            if outcome is not None:
                expected.add(outcome.path.absolute())
    actual: set[Path] = set()
    for kind in ("intents", "outcomes"):
        root = prepared.private_root / "preflight" / kind / prepared.candidate_id
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.is_dir():
                if path.is_symlink():
                    raise Rule3ExecutionError("preflight journal contains a symlink")
                continue
            if path.is_symlink() or path.suffix != ".json":
                raise Rule3ExecutionError(
                    "preflight journal contains an unexpected file"
                )
            actual.add(path.absolute())
    if actual != expected:
        raise Rule3ExecutionError("preflight journal contains an unknown record")


def _preflight_state_gate(prepared: PreparedExecution) -> None:
    """Reject terminal or stranded metadata state before credential access."""
    _validate_preflight_tree(prepared)
    for model in prepared.config.models:
        history = _preflight_history(prepared, model)
        if not history:
            continue
        intent, outcome = history[-1]
        if outcome is None:
            raise Rule3ExecutionError(
                f"stranded preflight intent stops {model.model_key}; "
                "no credential was read"
            )
        if outcome.payload["status"] == "success":
            continue
        error = outcome.payload["error"]
        if not error["retryable"]:
            raise Rule3ExecutionError(
                f"terminal preflight error stops {model.model_key}; "
                "no credential was read"
            )
        if intent.payload["attempt_number"] >= ATTEMPTS_PER_CELL:
            raise Rule3ExecutionError(
                f"three-attempt preflight ceiling exhausted for {model.model_key}; "
                "no credential was read"
            )


async def _run_preflight_model(
    prepared: PreparedExecution,
    model: Any,
    secrets: dict[str, str],
    transport: Transport,
    sleep: Callable[[float], Awaitable[None]],
) -> tuple[PreflightResult, JournalRecord, int]:
    history = _preflight_history(prepared, model)
    request_count = 0
    if history:
        last_intent, last_outcome = history[-1]
        if last_outcome is None:
            raise Rule3ExecutionError(
                f"stranded preflight intent stops {model.model_key}; no replay allowed"
            )
        prior_result = _validate_preflight_outcome(
            prepared, model, last_intent, last_outcome
        )
        if prior_result is not None:
            return prior_result, last_outcome, 0
        error = last_outcome.payload["error"]
        if (
            not error["retryable"]
            or last_intent.payload["attempt_number"] >= ATTEMPTS_PER_CELL
        ):
            raise Rule3ExecutionError(
                f"terminal preflight error stops {model.model_key}: "
                f"{error['sanitized_summary']}"
            )
        next_attempt = last_intent.payload["attempt_number"] + 1
    else:
        next_attempt = 1

    adapter = ProviderAdapter(model, transport)
    while next_attempt <= ATTEMPTS_PER_CELL:
        intent_payload = _preflight_intent_payload(prepared, model, next_attempt)
        intent_path = _preflight_intent_path(
            prepared.private_root,
            prepared.candidate_id,
            model.model_key,
            next_attempt,
        )
        try:
            intent_sha = write_once_private_json(intent_path, intent_payload)
        except BudgetError as error:
            raise Rule3ExecutionError(str(error)) from error
        intent = JournalRecord(intent_path, intent_payload, intent_sha)
        request_count += 1
        try:
            result = await adapter.preflight(secrets[model.environment_variable])
        except ProviderError as error:
            outcome_payload = _preflight_outcome_payload(
                prepared,
                intent,
                error=error,
                secrets=secrets,
            )
            outcome_path = _preflight_outcome_path(
                prepared.private_root,
                prepared.candidate_id,
                model.model_key,
                next_attempt,
            )
            try:
                outcome_sha = write_once_private_json(outcome_path, outcome_payload)
            except BudgetError as budget_error:
                raise Rule3ExecutionError(str(budget_error)) from budget_error
            outcome = JournalRecord(outcome_path, outcome_payload, outcome_sha)
            _validate_preflight_outcome(prepared, model, intent, outcome)
            if not error.retryable or next_attempt >= ATTEMPTS_PER_CELL:
                raise Rule3ExecutionError(
                    f"terminal preflight error stops {model.model_key}: "
                    f"{outcome_payload['error']['sanitized_summary']}"
                )
            await sleep(0.5 * (2 ** (next_attempt - 1)))
            next_attempt += 1
            continue
        outcome_payload = _preflight_outcome_payload(
            prepared,
            intent,
            result=result,
        )
        outcome_path = _preflight_outcome_path(
            prepared.private_root,
            prepared.candidate_id,
            model.model_key,
            next_attempt,
        )
        try:
            outcome_sha = write_once_private_json(outcome_path, outcome_payload)
        except BudgetError as error:
            raise Rule3ExecutionError(str(error)) from error
        outcome = JournalRecord(outcome_path, outcome_payload, outcome_sha)
        _validate_preflight_outcome(prepared, model, intent, outcome)
        return result, outcome, request_count
    raise Rule3ExecutionError(
        f"three-attempt preflight ceiling exhausted for {model.model_key}"
    )


def _manifest_payload(
    prepared: PreparedExecution,
    preflight: dict[str, PreflightResult],
    receipts: list[dict[str, Any]],
) -> dict[str, Any]:
    assert prepared.authorization is not None
    assert prepared.pricing_recheck is not None
    inner = create_model_manifest(prepared.config, preflight, "research")
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "status": "complete-eight-model-preflight",
        "pool_id": POOL_ID,
        "rule_version": RULE_VERSION,
        "git_head": prepared.binding.git_head,
        "lock_sha256": prepared.binding.lock_sha256,
        "authorization_receipt_sha256": prepared.authorization.sha256,
        "pricing_recheck_receipt_sha256": prepared.pricing_recheck.sha256,
        "candidate_id": prepared.candidate_id,
        "phase": prepared.phase,
        "config_sha256": prepared.config.sha256,
        "plan_sha256": prepared.plan_sha256,
        "captured_at": inner["captured_at"],
        "preflight_receipts": receipts,
        "model_manifest": inner,
    }


def _validate_manifest_payload(
    prepared: PreparedExecution, raw: dict[str, Any]
) -> None:
    assert prepared.authorization is not None
    assert prepared.pricing_recheck is not None
    expected_keys = {
        "schema_version",
        "status",
        "pool_id",
        "rule_version",
        "git_head",
        "lock_sha256",
        "authorization_receipt_sha256",
        "pricing_recheck_receipt_sha256",
        "candidate_id",
        "phase",
        "config_sha256",
        "plan_sha256",
        "captured_at",
        "preflight_receipts",
        "model_manifest",
    }
    if (
        set(raw) != expected_keys
        or raw.get("schema_version") != MANIFEST_SCHEMA_VERSION
        or raw.get("status") != "complete-eight-model-preflight"
        or raw.get("pool_id") != POOL_ID
        or raw.get("rule_version") != RULE_VERSION
        or raw.get("git_head") != prepared.binding.git_head
        or raw.get("lock_sha256") != prepared.binding.lock_sha256
        or raw.get("authorization_receipt_sha256") != prepared.authorization.sha256
        or raw.get("pricing_recheck_receipt_sha256") != prepared.pricing_recheck.sha256
        or raw.get("candidate_id") != prepared.candidate_id
        or raw.get("phase") != prepared.phase
        or raw.get("config_sha256") != prepared.config.sha256
        or raw.get("plan_sha256") != prepared.plan_sha256
        or not _is_timestamp(raw.get("captured_at"))
    ):
        raise Rule3ExecutionError("model manifest differs from the locked execution")
    receipt_values = raw.get("preflight_receipts")
    if (
        not isinstance(receipt_values, list)
        or len(receipt_values) != EXPECTED_CELL_COUNT
        or [
            item.get("model_key") if isinstance(item, dict) else None
            for item in receipt_values
        ]
        != list(MODEL_KEYS)
    ):
        raise Rule3ExecutionError(
            "model manifest lacks eight ordered preflight receipts"
        )
    receipt_results: dict[str, PreflightResult] = {}
    for model, binding in zip(prepared.config.models, receipt_values, strict=True):
        if (
            not isinstance(binding, dict)
            or set(binding) != {"model_key", "attempt_number", "path", "sha256"}
            or binding.get("model_key") != model.model_key
            or not isinstance(binding.get("attempt_number"), int)
            or isinstance(binding.get("attempt_number"), bool)
            or not 1 <= binding["attempt_number"] <= ATTEMPTS_PER_CELL
            or not isinstance(binding.get("sha256"), str)
            or not SHA256_PATTERN.fullmatch(binding["sha256"])
        ):
            raise Rule3ExecutionError(
                f"preflight receipt binding is malformed for {model.model_key}"
            )
        attempt = binding["attempt_number"]
        expected_outcome = _preflight_outcome_path(
            prepared.private_root,
            prepared.candidate_id,
            model.model_key,
            attempt,
        )
        expected_relative = str(expected_outcome.relative_to(prepared.private_root))
        if binding.get("path") != expected_relative:
            raise Rule3ExecutionError(
                f"preflight receipt path differs for {model.model_key}"
            )
        intent_path = _preflight_intent_path(
            prepared.private_root,
            prepared.candidate_id,
            model.model_key,
            attempt,
        )
        try:
            intent = read_private_json(intent_path, "Rule 3 preflight intent")
            outcome = read_private_json(expected_outcome, "Rule 3 preflight outcome")
        except BudgetError as error:
            raise Rule3ExecutionError(str(error)) from error
        if outcome.sha256 != binding["sha256"]:
            raise Rule3ExecutionError(
                f"preflight outcome differs from its manifest binding for {model.model_key}"
            )
        captured_at = _parse_timestamp(raw["captured_at"])
        preflight_completed_at = _parse_timestamp(outcome.payload.get("completed_at"))
        if (
            captured_at is None
            or preflight_completed_at is None
            or captured_at < preflight_completed_at
        ):
            raise Rule3ExecutionError(
                f"manifest predates its preflight receipt for {model.model_key}"
            )
        result = _validate_preflight_outcome(prepared, model, intent, outcome)
        if result is None:
            raise Rule3ExecutionError(
                f"manifest binds a failed preflight for {model.model_key}"
            )
        receipt_results[model.model_key] = result
    _validate_preflight_tree(prepared)
    manifest = raw.get("model_manifest")
    if (
        not isinstance(manifest, dict)
        or set(manifest)
        != {
            "schema_version",
            "manifest_id",
            "captured_at",
            "harness_version",
            "config_sha256",
            "data_class",
            "models",
        }
        or manifest.get("schema_version") != "1.0.0"
        or not isinstance(manifest.get("manifest_id"), str)
        or not MANIFEST_ID_PATTERN.fullmatch(manifest["manifest_id"])
        or manifest.get("harness_version") != HARNESS_VERSION
        or manifest.get("captured_at") != raw["captured_at"]
        or manifest.get("config_sha256") != prepared.config.sha256
        or manifest.get("data_class") != "research"
        or not isinstance(manifest.get("models"), list)
        or len(manifest["models"]) != 8
    ):
        raise Rule3ExecutionError("inner model manifest is malformed")
    for model, snapshot in zip(prepared.config.models, manifest["models"], strict=True):
        preflight = snapshot.get("preflight") if isinstance(snapshot, dict) else None
        returned = (
            preflight.get("provider_returned_model_id")
            if isinstance(preflight, dict)
            else None
        )
        if (
            not isinstance(snapshot, dict)
            or set(snapshot)
            != {
                "model_key",
                "family",
                "provider",
                "requested_model_id",
                "route",
                "environment_variable",
                "fallback_allowed",
                "capabilities",
                "policy",
                "pricing",
                "preflight",
            }
            or snapshot.get("model_key") != model.model_key
            or snapshot.get("family") != model.family
            or snapshot.get("provider") != model.provider
            or snapshot.get("requested_model_id") != model.requested_model_id
            or snapshot.get("route") != model.route
            or snapshot.get("environment_variable") != model.environment_variable
            or snapshot.get("fallback_allowed") is not False
            or snapshot.get("capabilities")
            != {"tools": False, "web_search": False, "retrieval": False}
            or snapshot.get("policy") != model.manifest_policy()
            or snapshot.get("pricing")
            != {
                "currency": model.planning_pricing["currency"],
                "input_per_million": model.planning_pricing["input_per_million"],
                "output_per_million": model.planning_pricing["output_per_million"],
                "pricing_as_of": model.planning_pricing["pricing_as_of"],
            }
            or not isinstance(preflight, dict)
            or set(preflight)
            != {
                "status",
                "checked_at",
                "provider_returned_model_id",
                "sanitized_note",
            }
            or preflight.get("status") != "available"
            or preflight.get("checked_at") != raw["captured_at"]
            or not isinstance(returned, str)
            or not returned_model_id_is_approved(model, returned)
            or returned != receipt_results[model.model_key].returned_model_id
            or preflight.get("sanitized_note")
            != (
                receipt_results[model.model_key].note
                or (
                    "Provider endpoint: "
                    + receipt_results[model.model_key].provider_name
                    if receipt_results[model.model_key].provider_name
                    else None
                )
            )
        ):
            raise Rule3ExecutionError(
                f"manifest identity differs for exact model {model.model_key}"
            )


def _load_manifest(prepared: PreparedExecution) -> ReceiptBinding:
    path = _manifest_path(prepared.private_root, prepared.candidate_id)
    try:
        record = read_private_json(path, "Rule 3 model manifest")
    except BudgetError as error:
        raise Rule3ExecutionError(str(error)) from error
    _validate_manifest_payload(prepared, record.payload)
    return ReceiptBinding(path=path, payload=record.payload, sha256=record.sha256)


async def _create_manifest(
    prepared: PreparedExecution,
    secrets: dict[str, str],
    transport: Transport,
    sleep: Callable[[float], Awaitable[None]],
) -> tuple[ReceiptBinding, int]:
    preflight: dict[str, PreflightResult] = {}
    receipts = []
    request_count = 0
    for model in prepared.config.models:
        result, outcome, count = await _run_preflight_model(
            prepared, model, secrets, transport, sleep
        )
        preflight[model.model_key] = result
        receipts.append(
            {
                "model_key": model.model_key,
                "attempt_number": outcome.payload["attempt_number"],
                "path": str(outcome.path.relative_to(prepared.private_root)),
                "sha256": outcome.sha256,
            }
        )
        request_count += count
    _validate_preflight_tree(prepared)
    payload = _manifest_payload(prepared, preflight, receipts)
    path = _manifest_path(prepared.private_root, prepared.candidate_id)
    try:
        digest = write_once_private_json(path, payload)
    except BudgetError as error:
        raise Rule3ExecutionError(str(error)) from error
    receipt = ReceiptBinding(path=path, payload=payload, sha256=digest)
    _validate_manifest_payload(prepared, payload)
    return receipt, request_count


def _common_outcome(
    prepared: PreparedExecution,
    call: PlannedCall,
    manifest: ReceiptBinding,
    intent: JournalRecord,
    attempted_at: str,
) -> dict[str, Any]:
    assert prepared.authorization is not None
    assert prepared.pricing_recheck is not None
    messages = call.answer_messages()
    requested_params = call.model.requested_params_receipt()
    return {
        "schema_version": OUTCOME_SCHEMA_VERSION,
        "lock_sha256": prepared.binding.lock_sha256,
        "authorization_receipt_sha256": prepared.authorization.sha256,
        "pricing_recheck_receipt_sha256": prepared.pricing_recheck.sha256,
        "git_head": prepared.binding.git_head,
        "candidate_id": prepared.candidate_id,
        "phase": prepared.phase,
        "cell_id": call.cell_id,
        "model_key": call.model.model_key,
        "model_family": call.model.family,
        "provider": call.model.provider,
        "route": call.model.route,
        "requested_model_id": call.model.requested_model_id,
        "question_sha256": call.question.sha256,
        "prompt_sha256": prompt_sha256(messages),
        "messages": messages,
        "messages_sha256": sha256_bytes(canonical_json_bytes(messages)),
        "requested_params": requested_params,
        "requested_params_sha256": sha256_bytes(canonical_json_bytes(requested_params)),
        "manifest_path": str(manifest.path.relative_to(prepared.private_root)),
        "manifest_sha256": manifest.sha256,
        "attempt_number": intent.payload["attempt_number"],
        "intent_path": str(intent.path.relative_to(prepared.private_root)),
        "intent_sha256": intent.sha256,
        "attempted_at": attempted_at,
    }


def _success_outcome(
    prepared: PreparedExecution,
    call: PlannedCall,
    manifest: ReceiptBinding,
    intent: JournalRecord,
    attempted_at: str,
    result: ProviderResult,
    latency_ms: int,
) -> dict[str, Any]:
    common = _common_outcome(prepared, call, manifest, intent, attempted_at)
    usage = result.usage
    input_tokens = (
        usage["input_tokens"]
        if usage["input_tokens"] is not None
        else estimate_message_tokens(call.answer_messages())
    )
    output_tokens = billed_output_tokens(call.model, usage, result.response_text)
    pricing = call.model.planning_pricing
    actual_microdollars = int(
        (
            Decimal(input_tokens) * Decimal(str(pricing["input_per_million"]))
            + Decimal(output_tokens) * Decimal(str(pricing["output_per_million"]))
        ).to_integral_value(rounding=ROUND_CEILING)
    )
    return {
        **common,
        "status": "success",
        "completed_at": utc_now(),
        "provider_returned_model_id": result.returned_model_id,
        "provider_response_id": result.provider_response_id,
        "effective_params": result.effective_params,
        "response_text": result.response_text,
        "response_sha256": sha256_bytes(result.response_text.encode("utf-8")),
        "finish_reason": result.finish_reason,
        "usage": usage,
        "latency_ms": latency_ms,
        "cost": {
            "actual_estimate_microdollars": actual_microdollars,
            "reserved_microdollars": intent.payload["reserved_cost_microdollars"],
            "pricing_as_of": pricing["pricing_as_of"],
        },
    }


def _error_outcome(
    prepared: PreparedExecution,
    call: PlannedCall,
    manifest: ReceiptBinding,
    intent: JournalRecord,
    attempted_at: str,
    error: ProviderError,
    secrets: Mapping[str, str],
) -> dict[str, Any]:
    return {
        **_common_outcome(prepared, call, manifest, intent, attempted_at),
        "status": "error",
        "completed_at": utc_now(),
        "error": {
            "category": error.category,
            "retryable": error.retryable,
            "sanitized_summary": sanitize(error, secrets.values()),
        },
    }


async def _run_call(
    prepared: PreparedExecution,
    call: PlannedCall,
    manifest: ReceiptBinding,
    ledger: BudgetLedger,
    secrets: dict[str, str],
    transport: Transport,
    limiter: RateLimiter,
    sleep: Callable[[float], Awaitable[None]],
) -> tuple[JournalRecord | None, int, str | None]:
    history = ledger.cell_history(prepared.candidate_id, call.model.model_key)
    if history:
        last_intent, last_outcome = history[-1]
        if last_outcome is None:
            raise StrandedIntent(f"stranded intent stops {call.cell_id}")
        if last_outcome.payload["status"] == "success":
            return last_outcome, 0, None
        if not last_outcome.payload["error"]["retryable"]:
            raise AttemptNotAllowed(
                f"nonretryable cell cannot be replayed: {call.cell_id}"
            )
        next_attempt = last_intent.payload["attempt_number"] + 1
    else:
        next_attempt = 1

    request_count = 0
    while next_attempt <= ATTEMPTS_PER_CELL:
        messages = call.answer_messages()
        requested = call.model.requested_params_receipt()
        attempted_at = utc_now()
        intent = ledger.reserve(
            candidate_id=prepared.candidate_id,
            cell_id=call.cell_id,
            model_key=call.model.model_key,
            attempt_number=next_attempt,
            reserved_cost_microdollars=reserved_microdollars(call),
            question_sha256=call.question.sha256,
            prompt_sha256=prompt_sha256(messages),
            messages_sha256=sha256_bytes(canonical_json_bytes(messages)),
            requested_params_sha256=sha256_bytes(canonical_json_bytes(requested)),
            manifest_sha256=manifest.sha256,
            created_at=attempted_at,
        )
        await limiter.wait()
        request_count += 1
        started = time.monotonic()
        adapter = ProviderAdapter(call.model, transport)
        try:
            result = await adapter.generate(
                secrets[call.model.environment_variable], messages
            )
        except ProviderError as error:
            outcome_payload = _error_outcome(
                prepared,
                call,
                manifest,
                intent,
                attempted_at,
                error,
                secrets,
            )
            outcome = ledger.record_outcome(intent, outcome_payload)
            if not error.retryable:
                return (
                    outcome,
                    request_count,
                    f"nonretryable provider outcome stops {call.cell_id}",
                )
            if next_attempt >= ATTEMPTS_PER_CELL:
                return (
                    outcome,
                    request_count,
                    f"three-attempt ceiling exhausted for {call.cell_id}",
                )
            await sleep(0.5 * (2 ** (next_attempt - 1)))
            next_attempt += 1
            continue
        latency_ms = int((time.monotonic() - started) * 1000)
        outcome_payload = _success_outcome(
            prepared,
            call,
            manifest,
            intent,
            attempted_at,
            result,
            latency_ms,
        )
        return ledger.record_outcome(intent, outcome_payload), request_count, None
    raise AttemptNotAllowed(f"three-attempt ceiling exhausted for {call.cell_id}")


def _candidate_receipt(
    prepared: PreparedExecution,
    manifest: ReceiptBinding,
    ledger: BudgetLedger,
    outcomes: list[JournalRecord],
    *,
    status: str,
    stopped_reason: str | None,
) -> dict[str, Any]:
    assert prepared.authorization is not None
    assert prepared.pricing_recheck is not None
    snapshot = ledger.snapshot()
    return {
        "schema_version": RUN_SCHEMA_VERSION,
        "status": status,
        "pool_id": POOL_ID,
        "rule_version": RULE_VERSION,
        "created_at": utc_now(),
        "git_head": prepared.binding.git_head,
        "lock_sha256": prepared.binding.lock_sha256,
        "authorization_receipt_sha256": prepared.authorization.sha256,
        "pricing_recheck_receipt_sha256": prepared.pricing_recheck.sha256,
        "candidate_id": prepared.candidate_id,
        "phase": prepared.phase,
        "question_sha256": prepared.question.sha256,
        "plan_sha256": prepared.plan_sha256,
        "manifest": {
            "path": str(manifest.path.relative_to(prepared.private_root)),
            "sha256": manifest.sha256,
        },
        "successful_outcome_count": sum(
            outcome.payload.get("status") == "success" for outcome in outcomes
        ),
        "outcomes": [
            {
                "model_key": outcome.payload["model_key"],
                "path": str(outcome.path.relative_to(prepared.private_root)),
                "sha256": outcome.sha256,
                "status": outcome.payload["status"],
                "attempt_number": outcome.payload["attempt_number"],
            }
            for outcome in outcomes
        ],
        "stopped_reason": stopped_reason,
        "budget": {
            "candidate_reserved_microdollars": snapshot.candidate_reserved_microdollars[
                prepared.candidate_id
            ],
            "pool_reserved_microdollars": snapshot.pool_reserved_microdollars,
            "candidate_cap_microdollars": CANDIDATE_CAP_MICRODOLLARS,
            "pool_cap_microdollars": POOL_CAP_MICRODOLLARS,
        },
    }


def _latest_outcomes(
    prepared: PreparedExecution, ledger: BudgetLedger
) -> list[JournalRecord]:
    result = []
    for model_key in MODEL_KEYS:
        history = ledger.cell_history(prepared.candidate_id, model_key)
        if not history:
            continue
        _, outcome = history[-1]
        if outcome is not None:
            result.append(outcome)
    return result


def _write_run_receipt(
    prepared: PreparedExecution,
    manifest: ReceiptBinding,
    ledger: BudgetLedger,
    *,
    status: str,
    stopped_reason: str | None,
) -> ExecutionResult:
    outcomes = _latest_outcomes(prepared, ledger)
    payload = _candidate_receipt(
        prepared,
        manifest,
        ledger,
        outcomes,
        status=status,
        stopped_reason=stopped_reason,
    )
    path = _run_path(prepared.private_root, prepared.candidate_id)
    try:
        digest = write_once_private_json(path, payload)
    except BudgetError as error:
        raise Rule3ExecutionError(str(error)) from error
    return ExecutionResult(
        path=path, payload=payload, sha256=digest, network_requests=0
    )


def _collect_secrets(
    prepared: PreparedExecution, environment: Mapping[str, str]
) -> dict[str, str]:
    secrets = {
        model.environment_variable: environment.get(model.environment_variable, "")
        for model in prepared.config.models
    }
    missing = sorted(name for name, value in secrets.items() if not value)
    if missing:
        raise Rule3ExecutionError(
            "missing required environment variables after all offline gates: "
            + ", ".join(missing)
        )
    return secrets


def _assert_prepared_contract_unchanged(
    prepared: PreparedExecution, fresh: PreparedExecution
) -> None:
    comparisons = (
        prepared.repository_root == fresh.repository_root,
        prepared.phase == fresh.phase,
        prepared.candidate_id == fresh.candidate_id,
        prepared.binding == fresh.binding,
        prepared.authorization == fresh.authorization,
        prepared.pricing_recheck == fresh.pricing_recheck,
        prepared.config == fresh.config,
        prepared.protocol == fresh.protocol,
        prepared.questions == fresh.questions,
        prepared.question == fresh.question,
        prepared.plan == fresh.plan,
        prepared.plan_sha256 == fresh.plan_sha256,
        prepared.all_plans == fresh.all_plans,
        prepared.all_plan_sha256 == fresh.all_plan_sha256,
        prepared.private_root == fresh.private_root,
    )
    if not all(comparisons):
        raise Rule3ExecutionError(
            "prepared Rule 3 config, protocol, question, or plan changed; "
            "no credential was read"
        )


def _rebuild_pre_environment(
    prepared: PreparedExecution,
    *,
    lock_loader: Callable[[Path], Any],
) -> PreparedExecution:
    """Rebuild from committed bytes and return the only state execution may use."""
    fresh = _prepare_execution(
        prepared.repository_root,
        prepared.phase,
        live=True,
        lock_loader=lock_loader,
    )
    _assert_prepared_contract_unchanged(prepared, fresh)
    return fresh


def _execution_lock_target(
    prepared: PreparedExecution,
    *,
    lock_loader: Callable[[Path], Any],
) -> Path:
    """Authenticate the repository before creating its fixed phase lock."""
    if prepared.phase not in PHASE_CANDIDATE:
        raise Rule3ExecutionError("Rule 3 phase has no execution lock")
    root = prepared.repository_root.resolve()
    try:
        context = lock_loader(root)
        binding = contract_binding(context, require_git_head=True)
    except AuthorizationError as error:
        raise Rule3ExecutionError(str(error)) from error
    candidate_id = PHASE_CANDIDATE[prepared.phase]
    expected_private_root = private_root(root)
    if (
        prepared.repository_root != root
        or prepared.candidate_id != candidate_id
        or prepared.private_root != expected_private_root
        or binding.repository_root != root
        or prepared.binding != binding
    ):
        raise Rule3ExecutionError(
            "prepared Rule 3 execution has no authenticated phase-lock target"
        )
    return expected_private_root / "execution-locks" / f"{candidate_id}.lock"


@asynccontextmanager
async def _phase_execution_lock(path: Path) -> AsyncIterator[None]:
    """Serialize one candidate across gates, provider calls, and final receipt."""
    try:
        ensure_private_root(path.parent)
    except BudgetError as error:
        raise Rule3ExecutionError(str(error)) from error
    flags = os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            raise Rule3ExecutionError(
                f"phase execution lock cannot be opened: {error}"
            ) from error
    except OSError as error:
        raise Rule3ExecutionError(
            f"phase execution lock cannot be created: {error}"
        ) from error
    try:
        os.fsync(descriptor)
    except OSError as error:
        os.close(descriptor)
        raise Rule3ExecutionError(
            f"phase execution lock cannot be synchronized: {error}"
        ) from error
    locked = False
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size != 0
            or metadata.st_nlink != 1
        ):
            raise Rule3ExecutionError(
                "phase execution lock must remain an empty mode-0600 regular file"
            )
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except BlockingIOError:
                await asyncio.sleep(0.05)
            except OSError as error:
                raise Rule3ExecutionError(
                    f"phase execution lock cannot be acquired: {error}"
                ) from error
        yield
    finally:
        if locked:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


async def _execute_under_phase_lock(
    prepared: PreparedExecution,
    *,
    environment: Mapping[str, str],
    transport_factory: Callable[[], Transport],
    sleep: Callable[[float], Awaitable[None]],
) -> ExecutionResult:
    if prepared.authorization is None or prepared.pricing_recheck is None:
        raise Rule3ExecutionError("dry-run plans cannot enter the live execution path")
    ledger = _make_ledger(prepared)
    try:
        # A crash after all eight outcomes but before the final receipt is safely
        # recoverable without reading credentials or contacting a provider.
        outcomes = _latest_outcomes(prepared, ledger)
        if len(outcomes) == 8 and all(
            outcome.payload["status"] == "success" for outcome in outcomes
        ):
            manifest = _load_manifest(prepared)
            return _write_run_receipt(
                prepared,
                manifest,
                ledger,
                status="complete-eight-successes",
                stopped_reason=None,
            )
    except BudgetError as error:
        raise Rule3ExecutionError(str(error)) from error

    # This is the first environment access and occurs only after lock,
    # authorization, pricing, phase, replay, plan, and budget gates pass.
    secrets = _collect_secrets(prepared, environment)
    actual_transport = transport_factory()
    network_requests = 0
    manifest_path = _manifest_path(prepared.private_root, prepared.candidate_id)
    if manifest_path.exists():
        manifest = _load_manifest(prepared)
    else:
        try:
            manifest, count = await _create_manifest(
                prepared, secrets, actual_transport, sleep
            )
        except ProviderError as error:
            raise Rule3ExecutionError(
                "exact eight-model preflight failed before generation: "
                + sanitize(error, secrets.values())
            ) from None
        network_requests += count

    limiters = {
        model.model_key: RateLimiter(model.requests_per_second)
        for model in prepared.config.models
    }
    stopped_reason = None
    for call in prepared.plan:
        try:
            _, count, call_stop = await _run_call(
                prepared,
                call,
                manifest,
                ledger,
                secrets,
                actual_transport,
                limiters[call.model.model_key],
                sleep,
            )
            network_requests += count
            if call_stop is not None:
                stopped_reason = call_stop
                break
        except (BudgetError, AttemptNotAllowed, StrandedIntent) as error:
            raise Rule3ExecutionError(str(error)) from error
    outcomes = _latest_outcomes(prepared, ledger)
    complete = len(outcomes) == 8 and all(
        outcome.payload["status"] == "success" for outcome in outcomes
    )
    result = _write_run_receipt(
        prepared,
        manifest,
        ledger,
        status=("complete-eight-successes" if complete else "incomplete-terminal-stop"),
        stopped_reason=(None if complete else stopped_reason or "candidate incomplete"),
    )
    return ExecutionResult(
        path=result.path,
        payload=result.payload,
        sha256=result.sha256,
        network_requests=network_requests,
    )


async def _execute_prepared(
    prepared: PreparedExecution,
    *,
    lock_loader: Callable[[Path], Any],
    environment: Mapping[str, str],
    transport_factory: Callable[[], Transport],
    sleep: Callable[[float], Awaitable[None]],
) -> ExecutionResult:
    target = _execution_lock_target(prepared, lock_loader=lock_loader)
    async with _phase_execution_lock(target):
        fresh = _rebuild_pre_environment(prepared, lock_loader=lock_loader)
        return await _execute_under_phase_lock(
            fresh,
            environment=environment,
            transport_factory=transport_factory,
            sleep=sleep,
        )


async def execute_prepared(prepared: PreparedExecution) -> ExecutionResult:
    """Execute with the real committed lock, process environment, and transport."""
    return await _execute_prepared(
        prepared,
        lock_loader=load_committed_lock,
        environment=os.environ,
        transport_factory=UrllibTransport,
        sleep=asyncio.sleep,
    )
