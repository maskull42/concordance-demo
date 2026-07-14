#!/usr/bin/env python3
"""Run the approved Quantum fallback as one append-only eight-model panel."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from decimal import Decimal, ROUND_CEILING
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent.parent
PRIVATE_ROOT = ROOT / ".pilot/quantum-fallback/quantum-fallback-1"
CANDIDATE_ID = "quantum-measurement-realist-strategies"
PRIORITY_ID = "galatians-pistis-christou"
POOL_ID = "concordance-divergence-supplement-1"
MODEL_ORDER = (
    "gemini",
    "claude",
    "cohere",
    "qwen",
    "deepseek",
    "mistral",
    "grok",
    "gpt",
)
QUESTION_SHA256 = "d1516759687b491d39c6bd2f33dfc0e6a92cc02ffc0b75fd691bfd83d42a8350"
PLAN_SHA256 = "a553e6ea4c0447cc9ab7bf8772d564279bc7370bf7b0500f2fcc23790c2cf456"
RULE3_LOCK_SHA256 = "8f4daf2ae53d07c7c53fc3f38d3ccd11aa18420185db632467fc9c280be523cc"
PARENT_COMPOSITE_SHA256 = (
    "e16c4b364a60e18b6554db5fc35b8e46e446a094fe346476084b4e9eb4516b7d"
)
AMENDMENT_SHA256 = "40f13ca059cf66960cac77f0132742567a42dc1184d4b330116d0d7285c2dff9"
ELIGIBILITY_SHA256 = "aae3f6cb0b2b8ed01935c3ef443d1d5491f8fdf0276783b68423031e386e6f30"
SUPERSEDING_EVALUATION_SHA256 = (
    "0caf412b77113d5b87d8d8cc971da06e0a95fc83987ba3b76248ef6ef1b64743"
)
INHERITED_RESERVED_MICRODOLLARS = 1_845_683
CANDIDATE_CAP_MICRODOLLARS = 6_000_000
POOL_CAP_MICRODOLLARS = 12_000_000

APPROVAL_SCOPE = (
    "The quantum-measurement fallback is now formally eligible. Your approval "
    "is the only remaining gate before I prepare and run those provider calls."
)
USER_APPROVAL = "I approve"
USER_CONTINUATION = "Please continue"

BOUND_SOURCES = (
    "candidate/rule3-lock.json",
    "candidate/rule3/questions/quantum-measurement-realist-strategies.json",
    "config/rule3-protocol.json",
    "harness/config/models.json",
    "harness/concordance_harness/__init__.py",
    "harness/concordance_harness/config.py",
    "harness/concordance_harness/planner.py",
    "harness/concordance_harness/providers.py",
    "harness/concordance_harness/util.py",
    "harness/concordance_recovery/journal.py",
    "harness/rule3/budget.py",
    "harness/run_quantum_fallback.py",
)

PRIVATE_BINDINGS = {
    "parent_composite": (
        ROOT
        / ".pilot/grok-retry/grok-xai-403-retry-1/runs/galatians-pistis-christou.json",
        PARENT_COMPOSITE_SHA256,
    ),
    "amendment": (
        ROOT
        / ".pilot/grok-review-amendment/galatians-local-handle-correction-1/amendment.json",
        AMENDMENT_SHA256,
    ),
    "fallback_eligibility": (
        ROOT
        / ".pilot/grok-review-amendment/galatians-local-handle-correction-1/fallback-eligibility.json",
        ELIGIBILITY_SHA256,
    ),
    "superseding_evaluation": (
        ROOT
        / ".pilot/grok-review-amendment/galatians-local-handle-correction-1/superseding-evaluation.json",
        SUPERSEDING_EVALUATION_SHA256,
    ),
}

PRICING = (
    (
        "gemini",
        "gemini-3.1-pro-preview",
        2.0,
        12.0,
        "https://ai.google.dev/gemini-api/docs/pricing",
    ),
    (
        "claude",
        "claude-fable-5",
        10.0,
        50.0,
        "https://platform.claude.com/docs/en/about-claude/models/introducing-claude-fable-5-and-claude-mythos-5",
    ),
    (
        "cohere",
        "command-a-plus-05-2026",
        0.0,
        0.0,
        "https://docs.cohere.com/docs/command-a-plus",
    ),
    (
        "qwen",
        "Qwen/Qwen3.5-397B-A17B",
        0.45,
        3.0,
        "https://deepinfra.com/Qwen/Qwen3.5-397B-A17B/api",
    ),
    (
        "deepseek",
        "deepseek-v4-pro",
        0.435,
        0.87,
        "https://api-docs.deepseek.com/quick_start/pricing/",
    ),
    (
        "mistral",
        "mistral-large-2512",
        0.5,
        1.5,
        "https://docs.mistral.ai/models/model-cards/mistral-large-3-25-12",
    ),
    (
        "grok",
        "grok-4.5",
        2.0,
        6.0,
        "https://docs.x.ai/developers/pricing",
    ),
    (
        "gpt",
        "openai/gpt-5.6-sol",
        5.0,
        30.0,
        "https://openrouter.ai/openai/gpt-5.6-sol-20260709",
    ),
)


class QuantumFallbackError(RuntimeError):
    pass


def sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def canonical(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def git(arguments: list[str]) -> bytes:
    result = subprocess.run(
        ["/usr/bin/git", *arguments],
        cwd=ROOT,
        check=False,
        capture_output=True,
        env={
            "HOME": "/var/empty",
            "PATH": "/usr/bin:/bin",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "LANG": "C",
            "LC_ALL": "C",
        },
    )
    if result.returncode:
        raise QuantumFallbackError(
            result.stderr.decode(errors="replace").strip() or "git failed"
        )
    return result.stdout


def committed_source_bindings() -> tuple[str, dict[str, str]]:
    head = git(["rev-parse", "HEAD"]).decode().strip()
    bindings = {}
    for relative in BOUND_SOURCES:
        disk = (ROOT / relative).read_bytes()
        if git(["show", f"{head}:{relative}"]) != disk:
            raise QuantumFallbackError(f"{relative} differs from committed HEAD")
        bindings[relative] = sha(disk)
    staged = git(["diff", "--cached", "--name-only", "--", *BOUND_SOURCES])
    if staged.strip():
        raise QuantumFallbackError("a bound fallback source has a staged change")
    return head, bindings


def read_bound_object(path: Path, digest: str, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or sha(path.read_bytes()) != digest:
        raise QuantumFallbackError(f"{label} differs from its approved binding")
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise QuantumFallbackError(f"{label} is malformed: {error}") from error
    if not isinstance(value, dict):
        raise QuantumFallbackError(f"{label} must be an object")
    return value


def validate_private_lineage() -> dict[str, dict[str, Any]]:
    values = {
        label: read_bound_object(path, digest, label)
        for label, (path, digest) in PRIVATE_BINDINGS.items()
    }
    parent = values["parent_composite"]
    evaluation = values["superseding_evaluation"]
    eligibility = values["fallback_eligibility"]
    if (
        parent.get("candidate_id") != PRIORITY_ID
        or parent.get("successful_outcome_count") != 8
        or parent.get("budget", {}).get("combined_reserved_microdollars")
        != INHERITED_RESERVED_MICRODOLLARS
        or eligibility.get("fallback_candidate_id") != CANDIDATE_ID
        or eligibility.get("priority_candidate_id") != PRIORITY_ID
        or eligibility.get("threshold_result", {}).get("qualifies") is not False
        or evaluation.get("threshold_result") != eligibility.get("threshold_result")
        or evaluation.get("supersedes", {}).get("invalid_for_selection") is not True
    ):
        raise QuantumFallbackError("corrected fallback lineage is not eligible")
    return values


def import_runtime() -> dict[str, Any]:
    harness = str(ROOT / "harness")
    if harness not in sys.path:
        sys.path.insert(0, harness)
    from concordance_harness import config, planner, providers, util
    from concordance_recovery import journal

    return {
        "load_harness_config": config.load_harness_config,
        "build_plan": planner.build_plan,
        "load_questions": planner.load_questions,
        "ProviderAdapter": providers.ProviderAdapter,
        "ProviderError": providers.ProviderError,
        "UrllibTransport": providers.UrllibTransport,
        "estimate_message_tokens": util.estimate_message_tokens,
        "prompt_sha256": util.prompt_sha256,
        "sanitize": util.sanitize,
        "utc_now": util.utc_now,
        "binding": journal.binding,
        "initialize_private_root": journal.initialize_private_root,
        "raw_response_payload": journal.raw_response_payload,
        "read_record": journal.read_record,
        "validate_raw_response": journal.validate_raw_response,
        "write_record": journal.write_record,
    }


@dataclass(frozen=True)
class Context:
    head: str
    sources: dict[str, str]
    runtime: dict[str, Any]
    config: Any
    call_by_key: dict[str, Any]
    new_reserved_microdollars: int


def load_context() -> Context:
    head, sources = committed_source_bindings()
    validate_private_lineage()
    if sha((ROOT / "candidate/rule3-lock.json").read_bytes()) != RULE3_LOCK_SHA256:
        raise QuantumFallbackError("Rule 3 lock changed")
    runtime = import_runtime()
    config = runtime["load_harness_config"](ROOT / "harness/config/models.json")
    questions = runtime["load_questions"](ROOT / "candidate/rule3/questions")
    question = next(item for item in questions if item.question_id == CANDIDATE_ID)
    if question.sha256 != QUESTION_SHA256:
        raise QuantumFallbackError("Quantum question changed")
    protocol = json.loads((ROOT / "config/rule3-protocol.json").read_bytes())
    plan = runtime["build_plan"](
        (question,),
        config.models,
        protocol["system_prompt"],
        protocol["standard_challenge_prompt"],
        answer_only=True,
    )
    plan_value = [
        {
            "cell_id": call.cell_id,
            "prompt_sha256": runtime["prompt_sha256"](call.answer_messages()),
            "requested_model_id": call.model.requested_model_id,
            "route": call.model.route,
            "requested_params": call.model.requested_params_receipt(),
        }
        for call in plan
    ]
    if sha(canonical(plan_value)) != PLAN_SHA256:
        raise QuantumFallbackError(
            "Quantum plan differs from the committed Rule 3 plan"
        )
    if tuple(call.model.model_key for call in plan) != MODEL_ORDER:
        raise QuantumFallbackError("Quantum panel order changed")
    pricing_by_key = {item[0]: item for item in PRICING}
    reservations = []
    for call in plan:
        evidence = pricing_by_key[call.model.model_key]
        pricing = call.model.planning_pricing
        if (
            call.model.requested_model_id != evidence[1]
            or float(pricing["input_per_million"]) != evidence[2]
            or float(pricing["output_per_million"]) != evidence[3]
            or call.model.requested_params_receipt()["tools_enabled"] is not False
            or call.model.requested_params_receipt()["web_search_enabled"] is not False
            or call.model.requested_params_receipt()["retrieval_enabled"] is not False
        ):
            raise QuantumFallbackError(
                f"locked request or reviewed pricing changed for {call.model.model_key}"
            )
        input_tokens = runtime["estimate_message_tokens"](call.answer_messages())
        reserved = Decimal(input_tokens) * Decimal(str(evidence[2])) + Decimal(
            call.model.output_cap
        ) * Decimal(str(evidence[3]))
        reservations.append(int(reserved.to_integral_value(rounding=ROUND_CEILING)))
    new_reserved = sum(reservations)
    if (
        new_reserved > CANDIDATE_CAP_MICRODOLLARS
        or INHERITED_RESERVED_MICRODOLLARS + new_reserved > POOL_CAP_MICRODOLLARS
    ):
        raise QuantumFallbackError("fallback reservation exceeds a frozen budget cap")
    return Context(
        head=head,
        sources=sources,
        runtime=runtime,
        config=config,
        call_by_key={call.model.model_key: call for call in plan},
        new_reserved_microdollars=new_reserved,
    )


def common(context: Context, model_key: str) -> dict[str, Any]:
    call = context.call_by_key[model_key]
    return {
        "recovery_id": "quantum-fallback-1",
        "pool_id": POOL_ID,
        "candidate_id": CANDIDATE_ID,
        "phase": "fallback",
        "git_head": context.head,
        "question_sha256": QUESTION_SHA256,
        "plan_sha256": PLAN_SHA256,
        "model_key": model_key,
        "provider": call.model.provider,
        "route": call.model.route,
        "requested_model_id": call.model.requested_model_id,
        "cell_id": call.cell_id,
        "attempt_number": 1,
    }


def authorization_value(context: Context, created_at: str) -> dict[str, Any]:
    return {
        "schema_version": "concordance-quantum-fallback-authorization-1.0.0",
        "status": "eight-answer-only-fallback-calls-authorized",
        "authorized_at": created_at,
        "authorized_by": {"id": "ag-elrod", "display_name": "A.G. Elrod"},
        "approval_scope_verbatim": APPROVAL_SCOPE,
        "user_approval_verbatim": USER_APPROVAL,
        "user_continuation_verbatim": USER_CONTINUATION,
        "git_head": context.head,
        "execution_sources": context.sources,
        "candidate_id": CANDIDATE_ID,
        "fallback_eligibility_sha256": ELIGIBILITY_SHA256,
        "scope": {
            "model_keys": list(MODEL_ORDER),
            "answer_only_cells": 8,
            "maximum_preflight_requests": 8,
            "maximum_generation_posts": 8,
            "automatic_generation_retries": 0,
            "parallel_generation_allowed": True,
            "tools_enabled": False,
            "web_search_enabled": False,
            "retrieval_enabled": False,
            "external_context_enabled": False,
            "third_candidate_allowed": False,
            "inherited_reserved_microdollars": INHERITED_RESERVED_MICRODOLLARS,
            "new_reserved_microdollars": context.new_reserved_microdollars,
            "candidate_cap_microdollars": CANDIDATE_CAP_MICRODOLLARS,
            "pool_cap_microdollars": POOL_CAP_MICRODOLLARS,
        },
    }


def pricing_value(context: Context, created_at: str) -> dict[str, Any]:
    return {
        "schema_version": "concordance-quantum-fallback-pricing-recheck-1.0.0",
        "status": "eight-route-official-pricing-rechecked",
        "rechecked_at": created_at,
        "reviewed_by": "Codex official-source recheck",
        "git_head": context.head,
        "candidate_id": CANDIDATE_ID,
        "official_evidence": [
            {
                "model_key": key,
                "requested_model_id": model,
                "input_per_million": input_price,
                "output_per_million": output_price,
                "official_source_url": url,
            }
            for key, model, input_price, output_price, url in PRICING
        ],
    }


def path_for(kind: str, model_key: str) -> Path:
    groups = {
        "preflight-intent": "preflight/intents",
        "preflight-raw": "preflight/raw-responses",
        "preflight-outcome": "preflight/outcomes",
        "generation-intent": "generation/intents",
        "generation-raw": "generation/raw-responses",
        "generation-outcome": "generation/outcomes",
    }
    return PRIVATE_ROOT / groups[kind] / model_key / "attempt-1.json"


class CaptureTransport:
    def __init__(
        self,
        inner: Any,
        callback: Callable[[Any, Any], None],
    ) -> None:
        self.inner = inner
        self.callback = callback

    async def send(self, request: Any) -> Any:
        response = await self.inner.send(request)
        self.callback(request, response)
        return response


class ReplayTransport:
    def __init__(self, response: Any) -> None:
        self.response = response

    async def send(self, request: Any) -> Any:
        return self.response


def intent_value(
    context: Context, model_key: str, request_kind: str, created_at: str
) -> dict[str, Any]:
    call = context.call_by_key[model_key]
    return {
        "schema_version": f"concordance-quantum-{request_kind}-intent-1.0.0",
        "status": "reserved-before-network-request",
        **common(context, model_key),
        "request_kind": request_kind,
        "prompt_sha256": context.runtime["prompt_sha256"](call.answer_messages()),
        "requested_params": call.model.requested_params_receipt(),
        "reserved_cost_microdollars": (
            0 if request_kind == "preflight" else reserved_for_call(context, model_key)
        ),
        "created_at": created_at,
    }


def reserved_for_call(context: Context, model_key: str) -> int:
    call = context.call_by_key[model_key]
    evidence = {item[0]: item for item in PRICING}[model_key]
    tokens = context.runtime["estimate_message_tokens"](call.answer_messages())
    value = Decimal(tokens) * Decimal(str(evidence[2])) + Decimal(
        call.model.output_cap
    ) * Decimal(str(evidence[3]))
    return int(value.to_integral_value(rounding=ROUND_CEILING))


def read_or_write_record(context: Context, path: Path, value: dict[str, Any]) -> Any:
    if path.exists():
        record = context.runtime["read_record"](path, path.name)
        expected = dict(value)
        for timestamp_key in ("authorized_at", "rechecked_at", "created_at"):
            if timestamp_key in expected:
                expected[timestamp_key] = record.payload.get(timestamp_key)
        if record.payload != expected:
            raise QuantumFallbackError(f"{path} differs from its frozen value")
        return record
    return context.runtime["write_record"](path, value)


def record_raw(
    context: Context,
    model_key: str,
    request_kind: str,
    intent: Any,
    request: Any,
    response: Any,
) -> Any:
    kind = "preflight-raw" if request_kind == "preflight" else "generation-raw"
    path = path_for(kind, model_key)
    value = context.runtime["raw_response_payload"](
        common=common(context, model_key),
        intent=intent,
        private_root=PRIVATE_ROOT,
        request_kind=request_kind,
        request=request,
        response=response,
    )
    return context.runtime["write_record"](path, value)


async def execute_request(
    context: Context,
    model_key: str,
    request_kind: str,
    secret: str,
    base_transport: Any,
) -> Any:
    runtime = context.runtime
    call = context.call_by_key[model_key]
    intent_kind = (
        "preflight-intent" if request_kind == "preflight" else "generation-intent"
    )
    raw_kind = "preflight-raw" if request_kind == "preflight" else "generation-raw"
    outcome_kind = (
        "preflight-outcome" if request_kind == "preflight" else "generation-outcome"
    )
    intent_path = path_for(intent_kind, model_key)
    raw_path = path_for(raw_kind, model_key)
    outcome_path = path_for(outcome_kind, model_key)
    if outcome_path.exists():
        return runtime["read_record"](outcome_path, f"{request_kind} outcome")
    if intent_path.exists():
        intent = runtime["read_record"](intent_path, f"{request_kind} intent")
        if not raw_path.exists():
            raise QuantumFallbackError(
                f"{model_key} {request_kind} intent is stranded; no replay permitted"
            )
        fake_request = (
            runtime["ProviderAdapter"](
                call.model, ReplayTransport(None)
            ).build_metadata_request(secret)
            if request_kind == "preflight"
            else runtime["ProviderAdapter"](
                call.model, ReplayTransport(None)
            ).build_generation_request(secret, call.answer_messages())
        )
        raw = runtime["read_record"](raw_path, f"{request_kind} raw response")
        response = runtime["validate_raw_response"](
            raw,
            expected_common=common(context, model_key),
            expected_intent=intent,
            private_root=PRIVATE_ROOT,
            request_kind=request_kind,
            expected_request=fake_request,
        )
        transport = ReplayTransport(response)
    else:
        created = runtime["utc_now"]()
        intent = runtime["write_record"](
            intent_path,
            intent_value(context, model_key, request_kind, created),
        )
        transport = CaptureTransport(
            base_transport,
            lambda request, response: record_raw(
                context, model_key, request_kind, intent, request, response
            ),
        )
    adapter = runtime["ProviderAdapter"](call.model, transport)
    try:
        result = (
            await adapter.preflight(secret)
            if request_kind == "preflight"
            else await adapter.generate(secret, call.answer_messages())
        )
        payload = {
            "schema_version": f"concordance-quantum-{request_kind}-outcome-1.0.0",
            "status": "success",
            **common(context, model_key),
            "request_kind": request_kind,
            "intent": runtime["binding"](PRIVATE_ROOT, intent).value(),
            "raw_response": runtime["binding"](
                PRIVATE_ROOT,
                runtime["read_record"](raw_path, f"{request_kind} raw response"),
            ).value(),
            "completed_at": runtime["utc_now"](),
            "result": result_value(result, request_kind),
        }
    except runtime["ProviderError"] as error:
        raw_binding = None
        if raw_path.exists():
            raw_binding = runtime["binding"](
                PRIVATE_ROOT,
                runtime["read_record"](raw_path, f"{request_kind} raw response"),
            ).value()
        payload = {
            "schema_version": f"concordance-quantum-{request_kind}-outcome-1.0.0",
            "status": "error",
            **common(context, model_key),
            "request_kind": request_kind,
            "intent": runtime["binding"](PRIVATE_ROOT, intent).value(),
            "raw_response": raw_binding,
            "completed_at": runtime["utc_now"](),
            "error": {
                "category": error.category,
                "retryable": False,
                "sanitized_summary": runtime["sanitize"](error, (secret,)),
            },
        }
    return runtime["write_record"](outcome_path, payload)


def result_value(result: Any, request_kind: str) -> dict[str, Any]:
    if request_kind == "preflight":
        return {
            "provider_returned_model_id": result.returned_model_id,
            "provider_name": result.provider_name,
            "sanitized_note": result.note,
        }
    return {
        "response_text": result.response_text,
        "provider_returned_model_id": result.returned_model_id,
        "provider_response_id": result.provider_response_id,
        "provider_name": result.provider_name,
        "finish_reason": result.finish_reason,
        "usage": result.usage,
        "effective_params": result.effective_params,
    }


def secrets_for(context: Context) -> dict[str, str]:
    secrets = {
        model.model_key: os.environ.get(model.environment_variable, "")
        for model in context.config.models
    }
    missing = [key for key in MODEL_ORDER if not secrets[key]]
    if missing:
        raise QuantumFallbackError(
            "missing required provider credentials: " + ", ".join(missing)
        )
    return secrets


async def run_live(context: Context) -> dict[str, Any]:
    runtime = context.runtime
    runtime["initialize_private_root"](PRIVATE_ROOT)
    created = runtime["utc_now"]()
    authorization = read_or_write_record(
        context,
        PRIVATE_ROOT / "authorization.json",
        authorization_value(context, created),
    )
    pricing = read_or_write_record(
        context,
        PRIVATE_ROOT / "pricing-recheck.json",
        pricing_value(context, created),
    )
    secrets = secrets_for(context)
    transport = runtime["UrllibTransport"]()
    preflight = await asyncio.gather(
        *(
            execute_request(context, key, "preflight", secrets[key], transport)
            for key in MODEL_ORDER
        )
    )
    failed = [
        key
        for key, record in zip(MODEL_ORDER, preflight, strict=True)
        if record.payload.get("status") != "success"
    ]
    if failed:
        raise QuantumFallbackError(
            "fallback preflight failed; no generation POST was sent: "
            + ", ".join(failed)
        )
    manifest_value = {
        "schema_version": "concordance-quantum-fallback-manifest-1.0.0",
        "status": "exact-eight-route-preflight-complete",
        "created_at": runtime["utc_now"](),
        "git_head": context.head,
        "candidate_id": CANDIDATE_ID,
        "authorization": runtime["binding"](PRIVATE_ROOT, authorization).value(),
        "pricing_recheck": runtime["binding"](PRIVATE_ROOT, pricing).value(),
        "models": [
            {
                "model_key": key,
                "requested_model_id": context.call_by_key[key].model.requested_model_id,
                "route": context.call_by_key[key].model.route,
                "preflight": runtime["binding"](PRIVATE_ROOT, record).value(),
            }
            for key, record in zip(MODEL_ORDER, preflight, strict=True)
        ],
    }
    manifest = read_or_write_record(
        context, PRIVATE_ROOT / "manifest.json", manifest_value
    )
    outcomes = await asyncio.gather(
        *(
            execute_request(context, key, "generation", secrets[key], transport)
            for key in MODEL_ORDER
        )
    )
    failed = [
        key
        for key, record in zip(MODEL_ORDER, outcomes, strict=True)
        if record.payload.get("status") != "success"
    ]
    run_value = {
        "schema_version": "concordance-quantum-fallback-run-1.0.0",
        "status": (
            "complete-eight-successes" if not failed else "incomplete-terminal-stop"
        ),
        "created_at": runtime["utc_now"](),
        "git_head": context.head,
        "pool_id": POOL_ID,
        "candidate_id": CANDIDATE_ID,
        "question_sha256": QUESTION_SHA256,
        "plan_sha256": PLAN_SHA256,
        "authorization": runtime["binding"](PRIVATE_ROOT, authorization).value(),
        "pricing_recheck": runtime["binding"](PRIVATE_ROOT, pricing).value(),
        "manifest": runtime["binding"](PRIVATE_ROOT, manifest).value(),
        "successful_outcome_count": 8 - len(failed),
        "failed_model_keys": failed,
        "outcomes": [
            {
                "model_key": key,
                "semantic_attempt_number": 1,
                **runtime["binding"](PRIVATE_ROOT, record).value(),
            }
            for key, record in zip(MODEL_ORDER, outcomes, strict=True)
        ],
        "budget": {
            "inherited_reserved_microdollars": INHERITED_RESERVED_MICRODOLLARS,
            "new_reserved_microdollars": context.new_reserved_microdollars,
            "combined_reserved_microdollars": (
                INHERITED_RESERVED_MICRODOLLARS + context.new_reserved_microdollars
            ),
            "candidate_cap_microdollars": CANDIDATE_CAP_MICRODOLLARS,
            "pool_cap_microdollars": POOL_CAP_MICRODOLLARS,
        },
        "network_contract": {
            "preflight_requests": 8,
            "generation_posts": 8,
            "tools_enabled": False,
            "web_search_enabled": False,
            "retrieval_enabled": False,
            "external_context_enabled": False,
        },
    }
    run = read_or_write_record(context, PRIVATE_ROOT / "run.json", run_value)
    return {
        "status": run.payload["status"],
        "successful_outcome_count": run.payload["successful_outcome_count"],
        "failed_model_keys": failed,
        "run_sha256": run.sha256,
        "new_reserved_microdollars": context.new_reserved_microdollars,
    }


def check(context: Context) -> dict[str, Any]:
    return {
        "status": "ready-for-approved-live-fallback",
        "candidate_id": CANDIDATE_ID,
        "model_keys": list(MODEL_ORDER),
        "logical_cells": 8,
        "maximum_generation_posts": 8,
        "automatic_generation_retries": 0,
        "new_reserved_microdollars": context.new_reserved_microdollars,
        "combined_reserved_microdollars": (
            INHERITED_RESERVED_MICRODOLLARS + context.new_reserved_microdollars
        ),
        "network_requests": 0,
        "environment_variables_read": 0,
    }


def verify(context: Context) -> dict[str, Any]:
    run_path = PRIVATE_ROOT / "run.json"
    if not run_path.exists():
        raise QuantumFallbackError("Quantum fallback run receipt does not exist")
    run = context.runtime["read_record"](run_path, "Quantum fallback run")
    if (
        run.payload.get("candidate_id") != CANDIDATE_ID
        or run.payload.get("successful_outcome_count") != 8
        or run.payload.get("failed_model_keys") != []
        or run.payload.get("status") != "complete-eight-successes"
        or tuple(item.get("model_key") for item in run.payload.get("outcomes", []))
        != MODEL_ORDER
        or run.payload.get("network_contract")
        != {
            "preflight_requests": 8,
            "generation_posts": 8,
            "tools_enabled": False,
            "web_search_enabled": False,
            "retrieval_enabled": False,
            "external_context_enabled": False,
        }
    ):
        raise QuantumFallbackError("Quantum fallback run is incomplete or changed")
    for item in run.payload["outcomes"]:
        record = context.runtime["read_record"](
            PRIVATE_ROOT / item["path"], f"{item['model_key']} generation outcome"
        )
        if record.sha256 != item["sha256"] or record.payload.get("status") != "success":
            raise QuantumFallbackError(
                f"{item['model_key']} generation outcome changed"
            )
    return {
        "status": "verified-complete-eight-successes",
        "candidate_id": CANDIDATE_ID,
        "run_sha256": run.sha256,
        "tools_enabled": False,
        "web_search_enabled": False,
        "retrieval_enabled": False,
        "external_context_enabled": False,
    }


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser()
    mode = command.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--live", action="store_true")
    mode.add_argument("--verify", action="store_true")
    command.add_argument("--credentials-confirmed", action="store_true")
    return command


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.live != args.credentials_confirmed:
        parser().error("--credentials-confirmed is required exactly with --live")
    try:
        context = load_context()
        if args.check:
            result = check(context)
        elif args.verify:
            result = verify(context)
        else:
            result = asyncio.run(run_live(context))
        print(json.dumps(result, indent=2))
        return 0 if not result.get("failed_model_keys") else 2
    except (QuantumFallbackError, OSError, ValueError, KeyError) as error:
        print(f"Quantum fallback stopped: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
