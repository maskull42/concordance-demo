"""Frozen public contract for the narrow Rule 3 successor recovery.

This module contains no provider or credential access.  It deliberately lives
outside the original ``harness/rule3`` discovery namespace so adding the
successor cannot alter the already committed parent lock.
"""

from __future__ import annotations

import ast
import os
import re
from pathlib import Path, PurePosixPath
from typing import Any

from rule3.contract import (
    canonical_json_bytes as canonical_json_bytes,
    parse_json_bytes as parse_json_bytes,
    read_regular_file,
    repository_root,
    sha256_bytes,
)


RECOVERY_LOCK_SCHEMA_VERSION = "concordance-rule3-recovery-lock-1.0.0"
RECOVERY_LOCK_STATUS = "immutable-successor-recovery-lock-no-spending-authorized"
RECOVERY_ID = "cohere-v2-model-id-1"
RECOVERY_LOCK_PATH = "candidate/concordance-recovery-lock.json"
RECOVERY_LOCK_SCHEMA_PATH = "candidate/concordance-recovery-lock.schema.json"

POOL_ID = "concordance-divergence-supplement-1"
RULE_VERSION = "pilot-rule-3"
PRIORITY_CANDIDATE_ID = "galatians-pistis-christou"
PRIORITY_PHASE = "priority"
PARENT_LOCK_PATH = "candidate/rule3-lock.json"
PARENT_LOCK_SCHEMA_VERSION = "rule3-lock-1.0.0"
PARENT_LOCK_SHA256 = "8f4daf2ae53d07c7c53fc3f38d3ccd11aa18420185db632467fc9c280be523cc"
PARENT_GIT_HEAD = "3f77bf7456a94d18fe2d0d0780a8d0602b4b486b"
PARENT_PLAN_SHA256 = "c1cdda59dcda1331344a8bc10188913dfcaa06a62f74cc3344fe1f2edb5f6c94"
PARENT_PRIVATE_ROOT = ".pilot/rule3/concordance-divergence-supplement-1"

# Stable aliases form the small import surface used by the runtime modules.
LOCK_PATH = RECOVERY_LOCK_PATH
CANDIDATE_ID = PRIORITY_CANDIDATE_ID
PARENT_PRIVATE_ROOT_RELATIVE = PARENT_PRIVATE_ROOT
PRIVATE_ROOT_RELATIVE = f".pilot/concordance-recovery/{RECOVERY_ID}"
CLAIM_ROOT_RELATIVE = ".pilot/concordance-recovery/claims"

PARENT_AUTHORIZATION_PATH = "paid-authorization.json"
PARENT_AUTHORIZATION_SHA256 = (
    "30ecdca710d05786bff0b07f632d9208016a605983078d30d27f9547dc5186c1"
)
PARENT_PRICING_EVIDENCE_PATH = "pricing-evidence.json"
PARENT_PRICING_EVIDENCE_SHA256 = (
    "918e7e904ad3ba13eeb077ec44d0cb34722f2ff9c11d24941d2da6e729cff49a"
)
PARENT_PRICING_RECHECK_PATH = "pricing-recheck.json"
PARENT_PRICING_RECHECK_SHA256 = (
    "285d2624ac3f636e58a25646a1fd255266f9c6d6b03e1c13ba9d4294fbc79483"
)
PARENT_MANIFEST_PATH = "manifests/galatians-pistis-christou.json"
PARENT_MANIFEST_SHA256 = (
    "7dedec143467eebd3e489515cdb23686bd011aa5ae663999a5bc9ceafc37c135"
)

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
PRESERVED_MODEL_KEYS = ("gemini", "claude")
RECOVERY_TARGET_MODEL_KEYS = (
    "cohere",
    "qwen",
    "deepseek",
    "mistral",
    "grok",
    "gpt",
)
TARGET_MODEL_KEYS = RECOVERY_TARGET_MODEL_KEYS
UNTOUCHED_MODEL_KEYS = RECOVERY_TARGET_MODEL_KEYS[1:]

PARENT_ARTIFACT_SHA256 = {
    "budget/intents/galatians-pistis-christou/claude/attempt-1.json": "bfb84f1367209b52b1490459d1a1ab079fab15ca5a5059177002372ca5a78101",
    "budget/intents/galatians-pistis-christou/cohere/attempt-1.json": "ee2b4d0b0c3ae1eaa0ea694f6ae04b158766012e9d6fec6ba938f7f352182bb9",
    "budget/intents/galatians-pistis-christou/gemini/attempt-1.json": "c1a828b4be8d8909ce23d64f7128b85b176f020f1f564418d07b7454daaf128c",
    PARENT_MANIFEST_PATH: PARENT_MANIFEST_SHA256,
    "outcomes/galatians-pistis-christou/claude/attempt-1.json": "30d1481e3cd12946dcfede4e15984ed2fa3969aeff41e12af2666dafc833f41b",
    "outcomes/galatians-pistis-christou/gemini/attempt-1.json": "dc0a96587db718f2014f6e17631447dbafa6970ff5e379f1f29965c63f0dc0e1",
    PARENT_AUTHORIZATION_PATH: PARENT_AUTHORIZATION_SHA256,
    "preflight/intents/galatians-pistis-christou/claude/attempt-1.json": "a2e7d2de1d8b6b05c19362a07f78f58448d868e949d329592605f138b66acb4a",
    "preflight/intents/galatians-pistis-christou/cohere/attempt-1.json": "f132e2061486d7c38a11aef170026a16873daf9191aee6638c083b269bc60b7c",
    "preflight/intents/galatians-pistis-christou/deepseek/attempt-1.json": "507f9ae5a5061c2beef4d969cc9f4093b1d5f9000fa95f6d75a4ffc59349fcd4",
    "preflight/intents/galatians-pistis-christou/gemini/attempt-1.json": "289c13ea0c0128401a07095bb339be490cac91805784fbeedbaf11a799dfbb4c",
    "preflight/intents/galatians-pistis-christou/gpt/attempt-1.json": "564288ff9cf8a3a3a5aae789cfc71c783b7780c293dfcf744509109cec35548c",
    "preflight/intents/galatians-pistis-christou/grok/attempt-1.json": "665df8d9f8ef0bd3114ce31b8359ce46c1f7e7cdf3d18210a207c5f7d1cd3569",
    "preflight/intents/galatians-pistis-christou/mistral/attempt-1.json": "34c0bb2c81f5b3d6dd73f915fe6ded905c006356d81a5df0713be5c5d661301a",
    "preflight/intents/galatians-pistis-christou/qwen/attempt-1.json": "d10e4690fa59a7b6540dc0633994e237cfe3e4184373af25b5b63bf3635b78a8",
    "preflight/outcomes/galatians-pistis-christou/claude/attempt-1.json": "ed1d59ca52451a231f9c5347c94426e40af5ea2e5ed69253e9b55e3b8ff73f26",
    "preflight/outcomes/galatians-pistis-christou/cohere/attempt-1.json": "c31894629d425b5036236091656830000da4a692ee130078ad86cb802426064e",
    "preflight/outcomes/galatians-pistis-christou/deepseek/attempt-1.json": "8a7b3ef5ef88e23deddbbc12807f08e79a48d667bb263e39343939441bd1fcec",
    "preflight/outcomes/galatians-pistis-christou/gemini/attempt-1.json": "12abb1eaa6e7e40db42d6a16d6a732f1137a8f08275b20e6895264eccac1b4e9",
    "preflight/outcomes/galatians-pistis-christou/gpt/attempt-1.json": "4ee748319a84be5c9d35e65d1abc3e8332b511774cb2667661479d03aa13eda5",
    "preflight/outcomes/galatians-pistis-christou/grok/attempt-1.json": "f8d56a543c7344fb4e174f7c13286b0190388d248b098ba8406ae2b8ab6d52d9",
    "preflight/outcomes/galatians-pistis-christou/mistral/attempt-1.json": "04e13ea8bda72092000a0a66c20539f6cf258883039c63b5aa3e754dbe327dab",
    "preflight/outcomes/galatians-pistis-christou/qwen/attempt-1.json": "8a04e394e0b5dc7c144935d45cf87c551e80b4de058eafb66eac79804d1ed534",
    PARENT_PRICING_EVIDENCE_PATH: PARENT_PRICING_EVIDENCE_SHA256,
    PARENT_PRICING_RECHECK_PATH: PARENT_PRICING_RECHECK_SHA256,
}

PARENT_GENERATION_INTENT_PATHS = (
    "budget/intents/galatians-pistis-christou/gemini/attempt-1.json",
    "budget/intents/galatians-pistis-christou/claude/attempt-1.json",
    "budget/intents/galatians-pistis-christou/cohere/attempt-1.json",
)
PARENT_GENERATION_OUTCOME_PATHS = (
    "outcomes/galatians-pistis-christou/gemini/attempt-1.json",
    "outcomes/galatians-pistis-christou/claude/attempt-1.json",
)
PARENT_PREFLIGHT_INTENT_PATHS = tuple(
    f"preflight/intents/{PRIORITY_CANDIDATE_ID}/{key}/attempt-1.json"
    for key in MODEL_ORDER
)
PARENT_PREFLIGHT_OUTCOME_PATHS = tuple(
    f"preflight/outcomes/{PRIORITY_CANDIDATE_ID}/{key}/attempt-1.json"
    for key in MODEL_ORDER
)
PARENT_REQUIRED_ABSENT_PATHS = (
    f"outcomes/{PRIORITY_CANDIDATE_ID}/cohere/attempt-1.json",
    f"runs/{PRIORITY_CANDIDATE_ID}.json",
)
PARENT_CONCURRENCY_LOCK_PATHS = (
    "budget/.reservation.lock",
    f"execution-locks/{PRIORITY_CANDIDATE_ID}.lock",
)

PRESERVED_SUCCESSES = (
    {
        "model_key": "gemini",
        "intent_path": PARENT_GENERATION_INTENT_PATHS[0],
        "intent_sha256": PARENT_ARTIFACT_SHA256[PARENT_GENERATION_INTENT_PATHS[0]],
        "outcome_path": PARENT_GENERATION_OUTCOME_PATHS[0],
        "outcome_sha256": PARENT_ARTIFACT_SHA256[PARENT_GENERATION_OUTCOME_PATHS[0]],
        "response_sha256": "e28a4290cd45152287bc415368cbefff4e6dca9e33d429a86fabd37c8b68de0e",
        "semantic_attempt_number": 1,
        "reserved_cost_microdollars": 197_012,
        "actual_estimate_microdollars": 34_676,
    },
    {
        "model_key": "claude",
        "intent_path": PARENT_GENERATION_INTENT_PATHS[1],
        "intent_sha256": PARENT_ARTIFACT_SHA256[PARENT_GENERATION_INTENT_PATHS[1]],
        "outcome_path": PARENT_GENERATION_OUTCOME_PATHS[1],
        "outcome_sha256": PARENT_ARTIFACT_SHA256[PARENT_GENERATION_OUTCOME_PATHS[1]],
        "response_sha256": "ed9f71cf839d90cc54b0a53282c99e546d7bea79d9a05ae3ed4926f74386ded2",
        "semantic_attempt_number": 1,
        "reserved_cost_microdollars": 821_220,
        "actual_estimate_microdollars": 131_580,
    },
)

STRANDED_COHERE = {
    "model_key": "cohere",
    "cell_id": f"{PRIORITY_CANDIDATE_ID}:cohere:default:answer",
    "intent_path": PARENT_GENERATION_INTENT_PATHS[2],
    "intent_sha256": PARENT_ARTIFACT_SHA256[PARENT_GENERATION_INTENT_PATHS[2]],
    "expected_outcome_path": PARENT_REQUIRED_ABSENT_PATHS[0],
    "expected_outcome_required_absent": True,
    "semantic_attempt_number": 1,
    "reserved_cost_microdollars": 0,
    "disposition": "consumed-no-usable-outcome-authorized-single-replacement",
}
STRANDED_COHERE_INTENT_SHA256 = STRANDED_COHERE["intent_sha256"]

RESERVED_COST_MICRODOLLARS = {
    "cohere": 0,
    "qwen": 49_243,
    "deepseek": 14_342,
    "mistral": 24_677,
    "grok": 98_708,
    "gpt": 492_530,
}
PARENT_RESERVED_MICRODOLLARS = 1_018_232
MAX_NEW_RECOVERY_RESERVED_MICRODOLLARS = 2_038_500
MAX_PRIORITY_RESERVED_MICRODOLLARS = 3_056_732
CANDIDATE_CAP_MICRODOLLARS = 6_000_000
POOL_CAP_MICRODOLLARS = 12_000_000
OUTPUT_TOKEN_CAP = 16_384
MAX_PREFLIGHT_ATTEMPTS_PER_MODEL = 3
MAX_UNTOUCHED_GENERATION_ATTEMPTS = 3
MAX_COHERE_REPLACEMENT_POSTS = 1
MAX_PREFLIGHT_REQUESTS = 18
MAX_GENERATION_POSTS = 16
MAX_OUTBOUND_REQUESTS = MAX_PREFLIGHT_REQUESTS + MAX_GENERATION_POSTS

NEW_RESERVED_CAP_MICRODOLLARS = MAX_NEW_RECOVERY_RESERVED_MICRODOLLARS
COMBINED_RESERVED_CAP_MICRODOLLARS = MAX_PRIORITY_RESERVED_MICRODOLLARS
PREFLIGHT_ATTEMPTS_PER_MODEL = MAX_PREFLIGHT_ATTEMPTS_PER_MODEL

TARGET_TRANSPORTS = {
    "cohere": {
        "requested_model_id": "command-a-plus-05-2026",
        "provider": "cohere",
        "route": "cohere-direct",
        "environment_variable": "COHERE_API_KEY",
        "api_style": "cohere",
        "base_url": "https://api.cohere.com",
        "generation_path": "/v2/chat",
        "metadata_path": "/v1/models/{model}",
        "metadata_mode": "single",
        "auth_kind": "bearer",
        "fallback_allowed": False,
    },
    "qwen": {
        "requested_model_id": "Qwen/Qwen3.5-397B-A17B",
        "provider": "deepinfra",
        "route": "deepinfra",
        "environment_variable": "DEEPINFRA_API_KEY",
        "api_style": "openai",
        "base_url": "https://api.deepinfra.com",
        "generation_path": "/v1/openai/chat/completions",
        "metadata_path": "/v1/models",
        "metadata_mode": "list",
        "auth_kind": "bearer",
        "fallback_allowed": False,
    },
    "deepseek": {
        "requested_model_id": "deepseek-v4-pro",
        "provider": "deepseek",
        "route": "deepseek-direct",
        "environment_variable": "DEEPSEEK_API_KEY",
        "api_style": "openai",
        "base_url": "https://api.deepseek.com",
        "generation_path": "/chat/completions",
        "metadata_path": "/models",
        "metadata_mode": "list",
        "auth_kind": "bearer",
        "fallback_allowed": False,
    },
    "mistral": {
        "requested_model_id": "mistral-large-2512",
        "provider": "mistral",
        "route": "mistral-direct",
        "environment_variable": "MISTRAL_API_KEY",
        "api_style": "openai",
        "base_url": "https://api.mistral.ai",
        "generation_path": "/v1/chat/completions",
        "metadata_path": "/v1/models/{model}",
        "metadata_mode": "single",
        "auth_kind": "bearer",
        "fallback_allowed": False,
    },
    "grok": {
        "requested_model_id": "grok-4.5",
        "provider": "xai",
        "route": "xai-direct",
        "environment_variable": "XAI_API_KEY",
        "api_style": "xai-responses",
        "base_url": "https://api.x.ai",
        "generation_path": "/v1/responses",
        "metadata_path": "/v1/models/{model}",
        "metadata_mode": "single",
        "auth_kind": "bearer",
        "fallback_allowed": False,
    },
    "gpt": {
        "requested_model_id": "openai/gpt-5.6-sol",
        "provider": "openrouter",
        "route": "openrouter-openai-pinned",
        "environment_variable": "OPENROUTER_API_KEY",
        "api_style": "openai",
        "base_url": "https://openrouter.ai",
        "generation_path": "/api/v1/chat/completions",
        "metadata_path": "/api/v1/models/{model}/endpoints",
        "metadata_mode": "openrouter-endpoints",
        "auth_kind": "bearer",
        "fallback_allowed": False,
    },
}

OFFICIAL_PRICING_HOSTS = {
    "cohere": ("docs.cohere.com",),
    "qwen": ("deepinfra.com",),
    "deepseek": ("api-docs.deepseek.com",),
    "mistral": ("docs.mistral.ai",),
    "grok": ("docs.x.ai",),
    "gpt": ("openrouter.ai",),
}

TARGET_ATTEMPT_RECORDS = tuple(
    {
        "ordinal": ordinal,
        "model_key": model_key,
        "cell_id": f"{PRIORITY_CANDIDATE_ID}:{model_key}:default:answer",
        "semantic_attempt_start": 2 if model_key == "cohere" else 1,
        "maximum_generation_posts": (
            MAX_COHERE_REPLACEMENT_POSTS
            if model_key == "cohere"
            else MAX_UNTOUCHED_GENERATION_ATTEMPTS
        ),
        "reserved_cost_microdollars_per_post": RESERVED_COST_MICRODOLLARS[model_key],
        "preflight_attempts": MAX_PREFLIGHT_ATTEMPTS_PER_MODEL,
        "fresh_preflight_required_before_any_generation": True,
        "identity_mode": (
            "request-body-plus-fresh-preflight-generation-id-optional"
            if model_key == "cohere"
            else "generation-returned-id-plus-fresh-preflight"
        ),
        **TARGET_TRANSPORTS[model_key],
    }
    for ordinal, model_key in enumerate(RECOVERY_TARGET_MODEL_KEYS, start=1)
)

RECOVERY_AUTHORIZATION_STATEMENT = (
    "A.G. Elrod authorizes this exact committed Concordance Rule 3 successor "
    "recovery lock for one private recovery run: preserve the sealed Gemini and "
    "Claude successes; treat the original Cohere generation intent as consumed "
    "and unusable; authenticate and freshly preflight exactly Cohere, Qwen, "
    "DeepSeek, Mistral, Grok, and GPT before any generation; make at most one "
    "replacement Cohere generation; only after it succeeds, continue Qwen, "
    "DeepSeek, Mistral, Grok, and GPT with no more than three safe attempts per "
    "untouched cell; make no Gemini or Claude generation call; do not run the "
    "fallback or a third candidate; retain the original $6.00 candidate and "
    "$12.00 pool reserved-cost caps; and use no tools, web search, or retrieval."
)
RECOVERY_AUTHORIZATION_STATEMENT_SHA256 = sha256_bytes(
    RECOVERY_AUTHORIZATION_STATEMENT.encode("utf-8")
)
PAID_AUTHORIZATION_STATEMENT = RECOVERY_AUTHORIZATION_STATEMENT
PAID_AUTHORIZATION_STATEMENT_SHA256 = RECOVERY_AUTHORIZATION_STATEMENT_SHA256


def authorization_scope() -> dict[str, Any]:
    """Return the exact JSON scope an eventual private authority must bind."""
    return {
        "recovery_id": RECOVERY_ID,
        "pool_id": POOL_ID,
        "candidate_id": PRIORITY_CANDIDATE_ID,
        "phase": PRIORITY_PHASE,
        "private_root": PRIVATE_ROOT_RELATIVE,
        "claim_root": CLAIM_ROOT_RELATIVE,
        "preserved_model_keys": list(PRESERVED_MODEL_KEYS),
        "target_model_keys": list(RECOVERY_TARGET_MODEL_KEYS),
        "fresh_preflight_model_keys": list(RECOVERY_TARGET_MODEL_KEYS),
        "preflight_attempts_per_model": MAX_PREFLIGHT_ATTEMPTS_PER_MODEL,
        "cohere_semantic_attempt_number": 2,
        "cohere_maximum_replacement_posts": MAX_COHERE_REPLACEMENT_POSTS,
        "untouched_maximum_safe_attempts_per_cell": (MAX_UNTOUCHED_GENERATION_ATTEMPTS),
        "parent_reserved_microdollars": PARENT_RESERVED_MICRODOLLARS,
        "new_reserved_cap_microdollars": MAX_NEW_RECOVERY_RESERVED_MICRODOLLARS,
        "combined_reserved_cap_microdollars": MAX_PRIORITY_RESERVED_MICRODOLLARS,
        "candidate_reserved_cap_microdollars": CANDIDATE_CAP_MICRODOLLARS,
        "pool_reserved_cap_microdollars": POOL_CAP_MICRODOLLARS,
        "fallback_allowed": False,
        "third_candidate_allowed": False,
        "tools_enabled": False,
        "web_search_enabled": False,
        "retrieval_enabled": False,
    }


RECOVERY_REQUIRED_SOURCES = (
    "harness/authorize_concordance_recovery.py",
    "harness/review_concordance_recovery.py",
    "harness/run_concordance_recovery.py",
    "harness/concordance_recovery/__init__.py",
    "harness/concordance_recovery/authorization.py",
    "harness/concordance_recovery/composite.py",
    "harness/concordance_recovery/contract.py",
    "harness/concordance_recovery/execute.py",
    "harness/concordance_recovery/journal.py",
    "harness/concordance_recovery/lock.py",
    "harness/concordance_recovery/parent.py",
    "harness/concordance_recovery/state.py",
    "harness/concordance_recovery/transport.py",
    "harness/create_concordance_recovery_lock.py",
)
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")


class RecoveryLockError(RuntimeError):
    """Raised when the successor lock or its exact parent differs."""


def require_relative_path(value: object, label: str = "path") -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise RecoveryLockError(f"{label} must be a nonempty POSIX relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise RecoveryLockError(f"{label} must remain inside the repository")
    if path.as_posix() != value:
        raise RecoveryLockError(f"{label} is not canonically normalized")
    return value


def _excluded_source_path(relative: PurePosixPath) -> bool:
    return (
        any(part in {"tests", "__pycache__"} for part in relative.parts)
        or relative.suffix == ".pyc"
        or relative.name == Path(RECOVERY_LOCK_PATH).name
    )


def _walk_recovery_package(root: Path) -> set[str]:
    subtree = root / "harness/concordance_recovery"
    if not subtree.is_dir() or subtree.is_symlink():
        raise RecoveryLockError("harness/concordance_recovery must be a real directory")
    paths: set[str] = set()
    for directory, directory_names, file_names in os.walk(
        subtree, topdown=True, followlinks=False
    ):
        directory_path = Path(directory)
        kept: list[str] = []
        for name in sorted(directory_names):
            child = directory_path / name
            relative = PurePosixPath(child.relative_to(root).as_posix())
            if _excluded_source_path(relative):
                continue
            if child.is_symlink():
                raise RecoveryLockError(
                    f"{relative}: recovery source directory may not be a symlink"
                )
            kept.append(name)
        directory_names[:] = kept
        for name in sorted(file_names):
            child = directory_path / name
            relative = PurePosixPath(child.relative_to(root).as_posix())
            if _excluded_source_path(relative):
                continue
            read_regular_file(root, relative.as_posix())
            paths.add(relative.as_posix())
    return paths


def _module_parts(relative: str) -> tuple[str, ...] | None:
    pure = PurePosixPath(relative)
    if len(pure.parts) < 3 or pure.parts[0] != "harness" or pure.suffix != ".py":
        return None
    parts = list(pure.parts[1:])
    if parts[-1] == "__init__.py":
        parts.pop()
    else:
        parts[-1] = PurePosixPath(parts[-1]).stem
    return tuple(parts)


def _local_module_paths(
    root: Path,
    parts: tuple[str, ...],
    *,
    required: bool,
    label: str,
) -> set[str]:
    if not parts:
        return set()
    harness = root / "harness"
    top_file = harness / f"{parts[0]}.py"
    top_directory = harness / parts[0]
    if not top_file.is_file() and not top_directory.is_dir():
        return set()
    paths: set[str] = set()
    for index in range(1, len(parts) + 1):
        package_init = harness.joinpath(*parts[:index], "__init__.py")
        if package_init.is_file():
            relative = package_init.relative_to(root).as_posix()
            read_regular_file(root, relative)
            paths.add(relative)
    module_file = harness.joinpath(*parts).with_suffix(".py")
    package_init = harness.joinpath(*parts, "__init__.py")
    if module_file.is_file():
        relative = module_file.relative_to(root).as_posix()
        read_regular_file(root, relative)
        paths.add(relative)
        return paths
    if package_init.is_file():
        return paths
    if required:
        raise RecoveryLockError(f"{label}: unresolved local import {'.'.join(parts)}")
    return set()


def _relative_import_parts(
    source: str, module: str | None, level: int
) -> tuple[str, ...]:
    source_parts = _module_parts(source)
    if source_parts is None:
        raise RecoveryLockError(f"{source}: cannot resolve a relative import")
    package = (
        source_parts
        if PurePosixPath(source).name == "__init__.py"
        else source_parts[:-1]
    )
    parents = level - 1
    if parents > len(package):
        raise RecoveryLockError(f"{source}: relative import escapes its package")
    base = package[: len(package) - parents]
    return base + (tuple(module.split(".")) if module else ())


def _python_local_imports(root: Path, relative: str) -> set[str]:
    payload = read_regular_file(root, relative)
    try:
        tree = ast.parse(payload.decode("utf-8"), filename=relative)
    except (UnicodeDecodeError, SyntaxError) as error:
        raise RecoveryLockError(
            f"{relative}: recovery source cannot be parsed"
        ) from error
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.update(
                    _local_module_paths(
                        root,
                        tuple(alias.name.split(".")),
                        required=True,
                        label=relative,
                    )
                )
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = _relative_import_parts(relative, node.module, node.level)
            elif node.module:
                base = tuple(node.module.split("."))
            else:
                continue
            imports.update(
                _local_module_paths(root, base, required=True, label=relative)
            )
            for alias in node.names:
                if alias.name != "*":
                    imports.update(
                        _local_module_paths(
                            root,
                            base + tuple(alias.name.split(".")),
                            required=False,
                            label=relative,
                        )
                    )
        elif isinstance(node, ast.Call):
            name = None
            if isinstance(node.func, ast.Name) and node.func.id == "__import__":
                name = "__import__"
            elif (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "import_module"
            ):
                name = "import_module"
            if name is None:
                continue
            if not node.args or not isinstance(node.args[0], ast.Constant):
                raise RecoveryLockError(
                    f"{relative}: non-literal {name} cannot be source-bound"
                )
            imported = node.args[0].value
            if (
                not isinstance(imported, str)
                or not imported
                or imported.startswith(".")
            ):
                raise RecoveryLockError(
                    f"{relative}: unsupported dynamic import cannot be source-bound"
                )
            imports.update(
                _local_module_paths(
                    root,
                    tuple(imported.split(".")),
                    required=True,
                    label=relative,
                )
            )
    return imports


def discover_recovery_source_paths(
    root: Path | str, parent_execution_sources: tuple[str, ...]
) -> tuple[str, ...]:
    repository = repository_root(root)
    discovered = set(parent_execution_sources)
    discovered.update(_walk_recovery_package(repository))
    for child in sorted((repository / "harness").glob("*concordance_recovery*.py")):
        relative = child.relative_to(repository).as_posix()
        read_regular_file(repository, relative)
        discovered.add(relative)
    missing = sorted(set(RECOVERY_REQUIRED_SOURCES) - discovered)
    if missing:
        raise RecoveryLockError(
            "recovery implementation is incomplete; missing: " + ", ".join(missing)
        )
    pending = sorted(path for path in discovered if PurePosixPath(path).suffix == ".py")
    parsed: set[str] = set()
    while pending:
        relative = pending.pop(0)
        if relative in parsed:
            continue
        parsed.add(relative)
        for imported in sorted(_python_local_imports(repository, relative)):
            if imported not in discovered:
                discovered.add(imported)
                if PurePosixPath(imported).suffix == ".py":
                    pending.append(imported)
    return tuple(sorted(discovered))


def parent_artifact_bindings() -> list[dict[str, str]]:
    if len(PARENT_ARTIFACT_SHA256) != 25:
        raise RecoveryLockError(
            "parent evidence register must contain exactly 25 files"
        )
    return [
        {"path": path, "sha256": digest}
        for path, digest in sorted(PARENT_ARTIFACT_SHA256.items())
    ]


def exact_type_equal(actual: Any, expected: Any) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(actual) == set(expected) and all(
            exact_type_equal(actual[key], expected[key]) for key in expected
        )
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            exact_type_equal(left, right)
            for left, right in zip(actual, expected, strict=True)
        )
    return actual == expected
