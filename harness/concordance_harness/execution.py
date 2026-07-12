from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

from . import HARNESS_VERSION
from .config import HarnessConfig, ModelConfig
from .planner import PlannedCall, QuestionInput
from .providers import (
    PreflightResult,
    ProviderAdapter,
    ProviderError,
    ProviderResult,
    Transport,
)
from .util import (
    atomic_write_json,
    estimate_message_tokens,
    estimate_tokens,
    prompt_sha256,
    run_stamp,
    sanitize,
    sha256_bytes,
    sha256_file,
    utc_now,
)


class BudgetExceeded(RuntimeError):
    """Raised before an outbound request would exceed an operator cap."""


class ResumeError(RuntimeError):
    """Raised when an existing checkpoint is incompatible with the current run."""


@dataclass
class AttemptBudget:
    max_calls: int | None
    max_cost_usd: float | None
    attempts: int = 0
    reserved_cost_usd: float = 0.0

    def __post_init__(self) -> None:
        self._lock = asyncio.Lock()

    async def reserve(self, cost_ceiling: float) -> int:
        async with self._lock:
            if self.max_calls is not None and self.attempts + 1 > self.max_calls:
                raise BudgetExceeded(
                    f"outbound attempt cap reached ({self.max_calls}); no request sent"
                )
            if (
                self.max_cost_usd is not None
                and self.reserved_cost_usd + cost_ceiling > self.max_cost_usd
            ):
                raise BudgetExceeded(
                    f"cost ceiling would exceed ${self.max_cost_usd:.4f}; no request sent"
                )
            self.attempts += 1
            self.reserved_cost_usd += cost_ceiling
            return self.attempts


class RateLimiter:
    def __init__(self, requests_per_second: float) -> None:
        self.interval = 1.0 / max(requests_per_second, 0.001)
        self.next_allowed = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self._lock:
            now = time.monotonic()
            delay = max(0.0, self.next_allowed - now)
            if delay:
                await asyncio.sleep(delay)
            self.next_allowed = time.monotonic() + self.interval


@dataclass(frozen=True)
class ExecutionOptions:
    output_root: Path
    run_purpose: str
    attempts_per_cell: int
    concurrency: int
    force: bool


class RunStore:
    def __init__(
        self,
        output_root: Path,
        question: QuestionInput,
        model_manifest: dict[str, Any],
        model_manifest_hash: str,
        config_hash: str,
        run_purpose: str,
        force_new: bool,
    ) -> None:
        self.path = output_root / "runs" / f"{question.question_id}.json"
        self._lock = asyncio.Lock()
        create_new = not self.path.exists()
        if self.path.exists():
            try:
                run = json.loads(self.path.read_bytes())
            except json.JSONDecodeError as error:
                raise ResumeError(f"{self.path.name}: malformed checkpoint") from error
            incompatible = (
                run.get("schema_version") != "1.0.0"
                or run.get("harness_version") != HARNESS_VERSION
                or run.get("run_purpose") != run_purpose
                or run.get("question_id") != question.question_id
                or run.get("question_file_sha256") != question.sha256
                or run.get("harness_config_sha256") != config_hash
                or run.get("model_manifest_file_sha256") != model_manifest_hash
                or run.get("model_manifest_snapshot") != model_manifest
            )
            if incompatible and not force_new:
                raise ResumeError(
                    f"{question.question_id}: checkpoint inputs changed; use --force only after review"
                )
            if incompatible:
                create_new = True
            else:
                self.run = run
        if create_new:
            now = utc_now()
            self.run = {
                "schema_version": "1.0.0",
                "run_id": f"{question.question_id}-{run_purpose}-{run_stamp()}",
                "run_purpose": run_purpose,
                "question_id": question.question_id,
                "question_content_version": question.content_version,
                "question_file_sha256": question.sha256,
                "generated_at": now,
                "updated_at": now,
                "harness_version": HARNESS_VERSION,
                "harness_config_sha256": config_hash,
                "model_manifest_file_sha256": model_manifest_hash,
                "model_manifest_snapshot": model_manifest,
                "cells": [],
            }

    def successful_cell(self, cell_id: str) -> dict[str, Any] | None:
        return next(
            (
                cell
                for cell in self.run["cells"]
                if cell.get("cell_id") == cell_id and cell.get("status") == "success"
            ),
            None,
        )

    async def save_cell(self, cell: dict[str, Any]) -> None:
        async with self._lock:
            remaining = [
                existing
                for existing in self.run["cells"]
                if existing.get("cell_id") != cell["cell_id"]
            ]
            remaining.append(cell)
            remaining.sort(key=lambda value: value["cell_id"])
            self.run["cells"] = remaining
            self.run["updated_at"] = utc_now()
            atomic_write_json(self.path, self.run)

    async def checkpoint(self) -> None:
        async with self._lock:
            atomic_write_json(self.path, self.run)


async def preflight_panel(
    models: tuple[ModelConfig, ...],
    secrets: dict[str, str],
    transport: Transport,
    budget: AttemptBudget,
    attempts: int,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> dict[str, PreflightResult]:
    results: dict[str, PreflightResult] = {}
    for model in models:
        adapter = ProviderAdapter(model, transport)
        last_error: ProviderError | None = None
        for attempt in range(1, attempts + 1):
            await budget.reserve(0.0)
            try:
                results[model.model_key] = await adapter.preflight(
                    secrets[model.environment_variable]
                )
                last_error = None
                break
            except ProviderError as error:
                last_error = error
                if not error.retryable or attempt >= attempts:
                    break
                await sleep(0.5 * (2 ** (attempt - 1)))
        if last_error is not None:
            # In particular, xAI unavailability reaches here and terminates the run.
            raise last_error
    return results


def create_model_manifest(
    config: HarnessConfig,
    preflight: dict[str, PreflightResult],
    data_class: str,
) -> dict[str, Any]:
    captured = utc_now()
    return {
        "schema_version": "1.0.0",
        "manifest_id": f"model-panel-{run_stamp()}",
        "captured_at": captured,
        "harness_version": HARNESS_VERSION,
        "config_sha256": config.sha256,
        "data_class": data_class,
        "models": [
            {
                "model_key": model.model_key,
                "family": model.family,
                "provider": model.provider,
                "requested_model_id": model.requested_model_id,
                "route": model.route,
                "environment_variable": model.environment_variable,
                "fallback_allowed": False,
                "capabilities": {
                    "tools": False,
                    "web_search": False,
                    "retrieval": False,
                },
                "policy": model.manifest_policy(),
                "pricing": {
                    "currency": model.planning_pricing["currency"],
                    "input_per_million": model.planning_pricing["input_per_million"],
                    "output_per_million": model.planning_pricing["output_per_million"],
                    "pricing_as_of": model.planning_pricing["pricing_as_of"],
                },
                "preflight": {
                    "status": "available",
                    "checked_at": captured,
                    "provider_returned_model_id": preflight[
                        model.model_key
                    ].returned_model_id,
                    "sanitized_note": (
                        preflight[model.model_key].note
                        or (
                            "Provider endpoint: "
                            + preflight[model.model_key].provider_name
                            if preflight[model.model_key].provider_name
                            else None
                        )
                    ),
                },
            }
            for model in config.models
        ],
    }


class HarnessRunner:
    def __init__(
        self,
        config: HarnessConfig,
        plan: tuple[PlannedCall, ...],
        secrets: dict[str, str],
        transport: Transport,
        budget: AttemptBudget,
        options: ExecutionOptions,
        model_manifest: dict[str, Any],
        model_manifest_hash: str,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        log: Callable[[str], None] = print,
    ) -> None:
        self.config = config
        self.plan = plan
        self.secrets = secrets
        self.transport = transport
        self.budget = budget
        self.options = options
        self.model_manifest = model_manifest
        self.model_manifest_hash = model_manifest_hash
        self.sleep = sleep
        self.log = log
        self._semaphore = asyncio.Semaphore(options.concurrency)
        self._limiters = {
            model.model_key: RateLimiter(model.requests_per_second)
            for model in config.models
        }
        questions = {call.question.question_id: call.question for call in plan}
        self._stores = {
            question_id: RunStore(
                options.output_root,
                question,
                model_manifest,
                model_manifest_hash,
                config.sha256,
                options.run_purpose,
                options.force,
            )
            for question_id, question in questions.items()
        }

    async def run(self) -> None:
        for store in self._stores.values():
            await store.checkpoint()
        answers = tuple(call for call in self.plan if call.call_type == "answer")
        challenges = tuple(call for call in self.plan if call.call_type == "challenge")
        await self._run_phase(answers)
        await self._run_phase(challenges)

    async def _run_phase(self, calls: tuple[PlannedCall, ...]) -> None:
        tasks = [asyncio.create_task(self._run_one(call)) for call in calls]
        if not tasks:
            return
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, BudgetExceeded):
                raise result
            if isinstance(result, BaseException):
                raise result

    async def _run_one(self, call: PlannedCall) -> None:
        store = self._stores[call.question.question_id]
        if not self.options.force and store.successful_cell(call.cell_id):
            self.log(f"SKIP {call.cell_id} (successful checkpoint)")
            return
        messages = call.answer_messages()
        parent_response_id: str | None = None
        if call.call_type == "challenge":
            parent = store.successful_cell(call.parent_cell_id or "")
            if not parent:
                self.log(f"SKIP {call.cell_id} (successful parent unavailable)")
                return
            parent_response_id = parent["response_id"]
            messages = [
                *parent["messages"],
                {"role": "assistant", "content": parent["response_text"]},
                {"role": "user", "content": call.challenge_prompt},
            ]
        async with self._semaphore:
            cell = await self._attempt(call, messages, parent_response_id)
            await store.save_cell(cell)
            self.log(f"{cell['status'].upper()} {call.cell_id}")

    async def _attempt(
        self,
        call: PlannedCall,
        messages: list[dict[str, str]],
        parent_response_id: str | None,
    ) -> dict[str, Any]:
        adapter = ProviderAdapter(call.model, self.transport)
        secret = self.secrets[call.model.environment_variable]
        first_attempted_at = utc_now()
        last_error: ProviderError | None = None
        for attempt in range(1, self.options.attempts_per_cell + 1):
            await self.budget.reserve(call.cost_ceiling())
            await self._limiters[call.model.model_key].wait()
            started = time.monotonic()
            try:
                result = await adapter.generate(secret, messages)
                latency_ms = int((time.monotonic() - started) * 1000)
                return self._success_cell(
                    call,
                    messages,
                    parent_response_id,
                    result,
                    attempt,
                    first_attempted_at,
                    latency_ms,
                )
            except ProviderError as error:
                last_error = error
                if not error.retryable or attempt >= self.options.attempts_per_cell:
                    break
                await self.sleep(0.5 * (2 ** (attempt - 1)))
        assert last_error is not None
        return self._error_cell(
            call,
            messages,
            parent_response_id,
            last_error,
            attempt,
            first_attempted_at,
        )

    def _common_cell(
        self,
        call: PlannedCall,
        messages: list[dict[str, str]],
        parent_response_id: str | None,
        attempt_count: int,
        attempted_at: str,
    ) -> dict[str, Any]:
        return {
            "cell_id": call.cell_id,
            "question_id": call.question.question_id,
            "model_key": call.model.model_key,
            "model_family": call.model.family,
            "provider": call.model.provider,
            "requested_model_id": call.model.requested_model_id,
            "variant_id": call.variant_id,
            "call_type": call.call_type,
            "parent_response_id": parent_response_id,
            "messages": messages,
            "prompt_sha256": prompt_sha256(messages),
            "requested_params": call.model.requested_params_receipt(),
            "attempted_at": attempted_at,
            "attempt_count": attempt_count,
        }

    def _success_cell(
        self,
        call: PlannedCall,
        messages: list[dict[str, str]],
        parent_response_id: str | None,
        result: ProviderResult,
        attempt_count: int,
        attempted_at: str,
        latency_ms: int,
    ) -> dict[str, Any]:
        response_hash = sha256_bytes(result.response_text.encode("utf-8"))[:12]
        usage = result.usage
        input_tokens = (
            usage["input_tokens"]
            if usage["input_tokens"] is not None
            else estimate_message_tokens(messages)
        )
        output_tokens = billed_output_tokens(call.model, usage, result.response_text)
        pricing = call.model.planning_pricing
        cost = (
            input_tokens * float(pricing["input_per_million"])
            + output_tokens * float(pricing["output_per_million"])
        ) / 1_000_000
        return {
            "status": "success",
            **self._common_cell(
                call,
                messages,
                parent_response_id,
                attempt_count,
                attempted_at,
            ),
            "response_id": (
                f"{call.question.question_id}-{call.model.model_key}-{call.variant_id}-"
                f"{call.call_type}-{response_hash}"
            ),
            "provider_returned_model_id": result.returned_model_id,
            "provider_response_id": result.provider_response_id,
            "effective_params": result.effective_params,
            "response_text": result.response_text,
            "generated_at": utc_now(),
            "latency_ms": latency_ms,
            "finish_reason": result.finish_reason,
            "usage": usage,
            "cost": {
                "usd": cost,
                "source": "estimated",
                "pricing_as_of": pricing["pricing_as_of"],
            },
        }

    def _error_cell(
        self,
        call: PlannedCall,
        messages: list[dict[str, str]],
        parent_response_id: str | None,
        error: ProviderError,
        attempt_count: int,
        attempted_at: str,
    ) -> dict[str, Any]:
        return {
            "status": "error",
            **self._common_cell(
                call,
                messages,
                parent_response_id,
                attempt_count,
                attempted_at,
            ),
            "error": {
                "category": error.category,
                "retryable": error.retryable,
                "sanitized_summary": sanitize(error, self.secrets.values()),
            },
            "failed_at": utc_now(),
        }


def billed_output_tokens(
    model: ModelConfig, usage: dict[str, int | None], response_text: str
) -> int:
    """Return provider-billed output without double-counting inclusive totals."""
    reported_output = usage["output_tokens"]
    output_tokens = (
        reported_output
        if reported_output is not None
        else estimate_tokens(response_text)
    )
    if model.api_style == "google":
        return output_tokens + (usage["reasoning_tokens"] or 0)
    return output_tokens


def write_model_manifest(
    output_root: Path, manifest: dict[str, Any]
) -> tuple[Path, str]:
    path = output_root / "manifests" / "models.json"
    atomic_write_json(path, manifest)
    return path, sha256_file(path)
