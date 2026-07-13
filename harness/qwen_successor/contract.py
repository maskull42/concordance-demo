"""Frozen public contract for the Qwen successor recovery."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


SCHEMA_VERSION = "concordance-qwen-successor-lock-1.0.0"
LOCK_STATUS = "immutable-qwen-successor-lock-no-spending-authorized"
RECOVERY_ID = "qwen-deepinfra-no-capture-1"
LOCK_PATH = "candidate/qwen-successor-lock.json"
PRIVATE_ROOT_RELATIVE = f".pilot/qwen-successor/{RECOVERY_ID}"
CLAIM_ROOT_RELATIVE = ".pilot/qwen-successor/claims"

POOL_ID = "concordance-divergence-supplement-1"
CANDIDATE_ID = "galatians-pistis-christou"
PHASE = "priority"
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
PRESERVED_MODEL_KEYS = ("gemini", "claude", "cohere")
TARGET_MODEL_KEYS = ("qwen", "deepseek", "mistral", "grok", "gpt")
UNTOUCHED_MODEL_KEYS = TARGET_MODEL_KEYS[1:]
PREFLIGHT_ROUTE_KEYS = (
    "qwen",
    "qwen-openrouter",
    "deepseek",
    "mistral",
    "grok",
    "gpt",
)

RULE3_LOCK_PATH = "candidate/rule3-lock.json"
RULE3_LOCK_SHA256 = "8f4daf2ae53d07c7c53fc3f38d3ccd11aa18420185db632467fc9c280be523cc"
RULE3_PLAN_SHA256 = "c1cdda59dcda1331344a8bc10188913dfcaa06a62f74cc3344fe1f2edb5f6c94"
FIRST_LOCK_PATH = "candidate/concordance-recovery-lock.json"
FIRST_LOCK_SHA256 = "6bee69c1a553af8ff68528bb344d002d33ac8ce4f5d75506463d29152c6950e8"
FIRST_EXECUTION_HEAD = "90447d63f63a4dd727862ec7056151773b50379b"
FIRST_PRIVATE_ROOT = ".pilot/concordance-recovery/cohere-v2-model-id-1"
FIRST_CLAIM_PATH = (
    ".pilot/concordance-recovery/claims/"
    "ee2b4d0b0c3ae1eaa0ea694f6ae04b158766012e9d6fec6ba938f7f352182bb9.json"
)
FIRST_CLAIM_LOCK_PATH = FIRST_CLAIM_PATH[:-5] + ".lock"
FIRST_CLAIM_SHA256 = "47c7c65d649cdd63b560fe1a774370389c665b613528f35385ac8374f82d45d5"
FIRST_AUTHORIZATION_PATH = "paid-authorization.json"
FIRST_AUTHORIZATION_SHA256 = (
    "2836b5142d34b7f5927b7b13b9331e781c88d7ea5d31f2197df496a77f6b6d8f"
)
FIRST_PRICING_EVIDENCE_SHA256 = (
    "65735124ca596a47c8f26ba07bbe0753831800490cf62b0ddf2359d09c732539"
)
FIRST_PRICING_RECHECK_SHA256 = (
    "ea4fe4430f6923da304d9e18865d03a5443bad89a82e262010cce373faa09691"
)
FIRST_MANIFEST_PATH = "manifests/six-model-preflight.json"
FIRST_MANIFEST_SHA256 = (
    "a46d5982382f78afe3436954bd49fa4edccc716989f1846d74bb5460713e3934"
)
COHERE_OUTCOME_PATH = "generation/outcomes/cohere/attempt-2.json"
COHERE_OUTCOME_SHA256 = (
    "012070830df40d8e40f704675d8fbae78f6e6261d4d5340b92bac49133f77011"
)
COHERE_RESPONSE_SHA256 = (
    "1570b742209c75e18da16b593164acad85210dc8633a9baceab3bd98b7e278a6"
)
QWEN_STRANDED_INTENT_PATH = "generation/intents/qwen/attempt-1.json"
QWEN_STRANDED_INTENT_SHA256 = (
    "1bfb995e380308c5adc1e549d6c0b0ef87ecf663a6e60d1af6a6c30d00e435da"
)

FIRST_PRIVATE_SHA256 = {
    "generation/intents/cohere/attempt-2.json": "227532e92c4c41e8496220daf1b0821e28824fb0b0df7aa74f0d6439a99ec927",
    QWEN_STRANDED_INTENT_PATH: QWEN_STRANDED_INTENT_SHA256,
    COHERE_OUTCOME_PATH: COHERE_OUTCOME_SHA256,
    "generation/raw-responses/cohere/attempt-2.json": "4f681943cade57e1ff26d9e23b62046e769714893a2953de77dbcc46426b61f0",
    FIRST_MANIFEST_PATH: FIRST_MANIFEST_SHA256,
    FIRST_AUTHORIZATION_PATH: FIRST_AUTHORIZATION_SHA256,
    "preflight/intents/cohere/attempt-1.json": "90e0ae752c627e37ffbfe11b367f5467fabb23c196469fca727fcbc16f486e04",
    "preflight/intents/deepseek/attempt-1.json": "3f145ca7c09eba7af91c007b94db353bf21521f9b15655975fdd77b815f5afb6",
    "preflight/intents/gpt/attempt-1.json": "5285232f7a6b503dd5497f0def0fc730226490bdc9f3c3e71adaece603fec978",
    "preflight/intents/grok/attempt-1.json": "23263d0d8b9a8f423d357420dd92a657e86797098f61b33b7b47a69fcad78f7e",
    "preflight/intents/mistral/attempt-1.json": "45e5ec590ae1684ee4e60eda8d650b06a6b96008a1a1644893249be873f0f7cd",
    "preflight/intents/qwen/attempt-1.json": "f1f77ea1bc9a616542a451a660647d3956fcb7b928e084d73e454ccb2156e554",
    "preflight/outcomes/cohere/attempt-1.json": "013bea3acea7043e94ba736922dd29f9022706e4de488649caeb57371f9a51d6",
    "preflight/outcomes/deepseek/attempt-1.json": "3f4765bb8eb5399d07ea1c03967aadbef53ddfdc90515efe214e185add784fbd",
    "preflight/outcomes/gpt/attempt-1.json": "b7cdb97278e4b8047c01672d85ed4d7990da77c5952a41a989507e0b456c7688",
    "preflight/outcomes/grok/attempt-1.json": "77a5463c22bfd840bd913f5aae60984a9b39320d300d9daca4ff6a25118d45c1",
    "preflight/outcomes/mistral/attempt-1.json": "2e3c619d942b280e53edc0eab53bf5958924c4f545d3f16e2921b5bf8e954682",
    "preflight/outcomes/qwen/attempt-1.json": "2d7c57487ff5432b5361f8f732adf4a8dee30edd8b4d1b6f38604ee586cda70c",
    "preflight/raw-responses/cohere/attempt-1.json": "d1d2fdb1f32beac41a1fca6d6ca0ed2ee782715f4e5627b6daf018c96ed2df00",
    "preflight/raw-responses/deepseek/attempt-1.json": "8abe037089eda3a9a402f01b03f5ec52f5c5823525c2b00da891730a40f8dae4",
    "preflight/raw-responses/gpt/attempt-1.json": "502b5b21ea50fc7a9608debd5d3e8d922df5f408d23e7771d276048aae1c393c",
    "preflight/raw-responses/grok/attempt-1.json": "e20542ff36262008c3ee13f175d0f918e1828f74d5faa70b3373885233abff30",
    "preflight/raw-responses/mistral/attempt-1.json": "5fe436bb3f5c67ecae373780e53611ea3e61024b4725b4b4b8db33c7b15ebee9",
    "preflight/raw-responses/qwen/attempt-1.json": "741b335b0bb3b7c84c1b370b7a1236382b8337964b642e4ab0cc06a9bb6ec561",
    "pricing-evidence.json": FIRST_PRICING_EVIDENCE_SHA256,
    "pricing-recheck.json": FIRST_PRICING_RECHECK_SHA256,
}

FIRST_REQUIRED_ABSENT = (
    "generation/raw-responses/qwen/attempt-1.json",
    "generation/outcomes/qwen/attempt-1.json",
    f"runs/{CANDIDATE_ID}.json",
    *(f"generation/intents/{key}/attempt-1.json" for key in UNTOUCHED_MODEL_KEYS),
    *(f"generation/raw-responses/{key}/attempt-1.json" for key in UNTOUCHED_MODEL_KEYS),
    *(f"generation/outcomes/{key}/attempt-1.json" for key in UNTOUCHED_MODEL_KEYS),
)
FIRST_EXTRA_EMPTY_DIRECTORIES = ("generation/raw-responses/qwen",)

USER_AMENDMENT = (
    "It's cheap enough. You can abort it and either try again at Deepinfra or "
    "through openrouter."
)
USER_AMENDMENT_SHA256 = sha256_bytes(USER_AMENDMENT.encode("utf-8"))
PRIOR_AUTHORIZATION_STATEMENT = (
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
PRIOR_AUTHORIZATION_STATEMENT_SHA256 = sha256_bytes(
    PRIOR_AUTHORIZATION_STATEMENT.encode("utf-8")
)
AUTHORIZATION_STATEMENT = (
    "A.G. Elrod authorizes this exact Qwen successor recovery after directing "
    "that the stalled Qwen request be aborted and retried: preserve the sealed "
    "Gemini, Claude, and Cohere successes; treat DeepInfra Qwen attempt 1, whose "
    "intent exists without a captured response, as consumed, possibly delivered, "
    "and possibly billed; freshly preflight the DeepInfra and OpenRouter Qwen "
    "routes plus DeepSeek, Mistral, Grok, and GPT; make exactly one replacement "
    "Qwen generation as semantic attempt 2 "
    "through the same DeepInfra route, model, prompt, parameters, and request body; "
    "if that replacement does not produce a durably captured successful response "
    "for any reason, including an ambiguous timeout or missing capture, make exactly "
    "one OpenRouter Qwen fallback as semantic attempt 3 using model "
    "qwen/qwen3.5-397b-a17b, accepting only that model ID or its dated alias "
    "qwen/qwen3.5-397b-a17b-20260216, excluding DeepInfra, sorting by throughput, "
    "requiring parameter support, allowing OpenRouter internal provider failover, "
    "and capping route price at $0.45 input and $3.00 output per million tokens; "
    "if that fallback does not produce a durably captured successful response, stop "
    "without another Qwen call; only after a Qwen route succeeds, continue DeepSeek, "
    "Mistral, Grok, and GPT in order with no more than three safe attempts per "
    "untouched cell; make no Gemini, Claude, or Cohere generation call; use no "
    "Qwen call beyond those two successor routes, no third candidate, and no tools, web search, "
    "retrieval, or external context; count the stranded Qwen attempt 1 and every "
    "successor Qwen reservation; preserve the "
    "original $6.00 candidate and $12.00 pool caps."
)
AUTHORIZATION_STATEMENT_SHA256 = sha256_bytes(AUTHORIZATION_STATEMENT.encode("utf-8"))

RESERVED_PER_POST = {
    "qwen": 49_243,
    "deepseek": 14_342,
    "mistral": 24_677,
    "grok": 98_708,
    "gpt": 492_530,
}
QWEN_OPENROUTER_RESERVED_MICRODOLLARS = 49_243
INHERITED_RESERVED_MICRODOLLARS = 1_067_475
NEW_RESERVED_CAP_MICRODOLLARS = 1_989_257
COMBINED_RESERVED_CAP_MICRODOLLARS = 3_056_732
CANDIDATE_CAP_MICRODOLLARS = 6_000_000
POOL_CAP_MICRODOLLARS = 12_000_000
OUTPUT_TOKEN_CAP = 16_384
PREFLIGHT_ATTEMPTS_PER_MODEL = 3
UNTOUCHED_ATTEMPTS_PER_MODEL = 3
QWEN_REPLACEMENT_POSTS = 1
MAX_PREFLIGHT_REQUESTS = 18
MAX_GENERATION_POSTS = 14
MAX_OUTBOUND_REQUESTS = 32

QWEN_OPENROUTER = {
    "route_key": "qwen-openrouter",
    "model_key": "qwen",
    "family": "Qwen",
    "provider": "openrouter",
    "requested_model_id": "qwen/qwen3.5-397b-a17b",
    "accepted_returned_model_ids": [
        "qwen/qwen3.5-397b-a17b",
        "qwen/qwen3.5-397b-a17b-20260216",
    ],
    "route": "openrouter-qwen-nondeepinfra-fallback",
    "environment_variable": "OPENROUTER_API_KEY",
    "api_style": "openai",
    "base_url": "https://openrouter.ai",
    "generation_path": "/api/v1/chat/completions",
    "metadata_path": "/api/v1/models/{model}/endpoints",
    "metadata_mode": "qwen-openrouter-endpoints",
    "auth_kind": "bearer",
    "fallback_allowed": True,
    "provider_options": {
        "provider": {
            "ignore": ["deepinfra"],
            "sort": "throughput",
            "allow_fallbacks": True,
            "require_parameters": True,
            "max_price": {"prompt": 0.45, "completion": 3.0},
        }
    },
    "headline_pricing": {"input_per_million": 0.385, "output_per_million": 2.45},
    "reservation_pricing": {"input_per_million": 0.45, "output_per_million": 3.0},
    "pricing_as_of": "2026-07-13",
    "official_source_url": "https://openrouter.ai/qwen/qwen3.5-397b-a17b",
}

OFFICIAL_PRICING_HOSTS = {
    "qwen": ("deepinfra.com",),
    "qwen-openrouter": ("openrouter.ai",),
    "deepseek": ("api-docs.deepseek.com",),
    "mistral": ("docs.mistral.ai",),
    "grok": ("docs.x.ai",),
    "gpt": ("openrouter.ai",),
}

NEW_SOURCE_PATHS = (
    "harness/authorize_qwen_successor.py",
    "harness/create_qwen_successor_lock.py",
    "harness/review_qwen_successor.py",
    "harness/run_qwen_successor.py",
    "harness/qwen_successor/__init__.py",
    "harness/qwen_successor/authorization.py",
    "harness/qwen_successor/composite.py",
    "harness/qwen_successor/contract.py",
    "harness/qwen_successor/execute.py",
    "harness/qwen_successor/lock.py",
    "harness/qwen_successor/parent.py",
    "harness/qwen_successor/state.py",
)


def authorization_scope() -> dict[str, Any]:
    return {
        "recovery_id": RECOVERY_ID,
        "candidate_id": CANDIDATE_ID,
        "private_root": PRIVATE_ROOT_RELATIVE,
        "preserved_model_keys": list(PRESERVED_MODEL_KEYS),
        "target_model_keys": list(TARGET_MODEL_KEYS),
        "fresh_preflight_model_keys": list(TARGET_MODEL_KEYS),
        "fresh_preflight_route_keys": list(PREFLIGHT_ROUTE_KEYS),
        "qwen_semantic_attempt_number": 2,
        "qwen_maximum_replacement_posts": 1,
        "qwen_route": "deepinfra",
        "qwen_openrouter_fallback_allowed": True,
        "qwen_openrouter_fallback_semantic_attempt_number": 3,
        "qwen_openrouter_fallback_maximum_posts": 1,
        "qwen_openrouter_model_id": QWEN_OPENROUTER["requested_model_id"],
        "qwen_openrouter_deepinfra_excluded": True,
        "qwen_openrouter_internal_provider_failover_allowed": True,
        "untouched_maximum_safe_attempts_per_cell": 3,
        "inherited_reserved_microdollars": INHERITED_RESERVED_MICRODOLLARS,
        "new_reserved_cap_microdollars": NEW_RESERVED_CAP_MICRODOLLARS,
        "combined_reserved_cap_microdollars": COMBINED_RESERVED_CAP_MICRODOLLARS,
        "candidate_reserved_cap_microdollars": CANDIDATE_CAP_MICRODOLLARS,
        "pool_reserved_cap_microdollars": POOL_CAP_MICRODOLLARS,
        "non_qwen_model_fallback_allowed": False,
        "third_candidate_allowed": False,
        "tools_enabled": False,
        "web_search_enabled": False,
        "retrieval_enabled": False,
        "external_context_enabled": False,
    }


def repository_root(value: Path | str) -> Path:
    return Path(value).resolve()
