"""Frozen public contract for the one-call xAI Grok retry."""

from __future__ import annotations

import hashlib
from typing import Any

from qwen_successor import contract as qwen_contract


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


SCHEMA_VERSION = "concordance-grok-retry-lock-1.0.0"
LOCK_STATUS = "immutable-grok-retry-lock-no-spending-authorized"
RECOVERY_ID = "grok-xai-403-retry-1"
LOCK_PATH = "candidate/grok-retry-lock.json"
PRIVATE_ROOT_RELATIVE = f".pilot/grok-retry/{RECOVERY_ID}"
CLAIM_ROOT_RELATIVE = ".pilot/grok-retry/claims"

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
PRESERVED_MODEL_KEYS = MODEL_ORDER[:6]
TARGET_MODEL_KEYS = MODEL_ORDER[6:]
PREFLIGHT_ROUTE_KEYS = TARGET_MODEL_KEYS

RULE3_LOCK_PATH = "candidate/rule3-lock.json"
RULE3_LOCK_SHA256 = qwen_contract.RULE3_LOCK_SHA256
RULE3_PLAN_SHA256 = qwen_contract.RULE3_PLAN_SHA256
FIRST_LOCK_PATH = "candidate/concordance-recovery-lock.json"
FIRST_LOCK_SHA256 = qwen_contract.FIRST_LOCK_SHA256
COHERE_OUTCOME_PATH = qwen_contract.COHERE_OUTCOME_PATH
COHERE_OUTCOME_SHA256 = qwen_contract.COHERE_OUTCOME_SHA256
COHERE_RESPONSE_SHA256 = qwen_contract.COHERE_RESPONSE_SHA256
QWEN_LOCK_PATH = "candidate/qwen-successor-lock.json"
QWEN_LOCK_SHA256 = "5894de7e035dfdccde79fddcb9424ff621556efadbc1d8762e033c7e77f6c03a"
QWEN_EXECUTION_HEAD = "7a0720da52acb08a4eabca95acc2185c95386e80"
QWEN_PRIVATE_ROOT = ".pilot/qwen-successor/qwen-deepinfra-no-capture-1"
QWEN_PARENT_CLAIM_PATH = (
    ".pilot/qwen-successor/claims/"
    "1bfb995e380308c5adc1e549d6c0b0ef87ecf663a6e60d1af6a6c30d00e435da.json"
)
QWEN_PARENT_PHASE_LOCK_PATH = QWEN_PARENT_CLAIM_PATH[:-5] + ".lock"
QWEN_PARENT_CLAIM_SHA256 = (
    "465a98f6062005c51d5310660b540db7bb295944e14ad42ab160b8368cca5958"
)
QWEN_AUTHORIZATION_PATH = "paid-authorization.json"
QWEN_AUTHORIZATION_SHA256 = (
    "37d2dae295b18699d626d05c1c075825b33e23d3359039ebf104b8312433a079"
)
QWEN_PRICING_EVIDENCE_SHA256 = (
    "b11cf2d94004b96252d8d0b23e4e98474a41b009819ba806f9d4c5ac2d652fe7"
)
QWEN_PRICING_RECHECK_SHA256 = (
    "06787378a5996be4b313f3622dfefb7652ed9becd758e0ca342f285967bc6712"
)
QWEN_MANIFEST_PATH = "manifests/six-route-preflight.json"
QWEN_MANIFEST_SHA256 = (
    "a32f34ea708d217d47ec3344348de0534e0ac88d41d1f7273718afecd87c4bea"
)

QWEN_OUTCOME_PATH = "generation/outcomes/qwen/attempt-2.json"
QWEN_OUTCOME_SHA256 = "de45c92a054672dc4e41c23b22f58d3da25736644fe8cd2ac192f7ef6e416e45"
QWEN_RESPONSE_SHA256 = (
    "22d6179530dbee4b26fd41f9e50e8db4a7fe291366c42f810db069e0cc788f74"
)
DEEPSEEK_OUTCOME_PATH = "generation/outcomes/deepseek/attempt-1.json"
DEEPSEEK_OUTCOME_SHA256 = (
    "28f87e9c43bee041a5e169ff870f6f1294506a7f488ebfc220f2a242096f0be7"
)
DEEPSEEK_RESPONSE_SHA256 = (
    "018a92e4160d6d6912fad16ec8a5bc9cef8e944f08c6a228fd6707cce2fae743"
)
MISTRAL_OUTCOME_PATH = "generation/outcomes/mistral/attempt-1.json"
MISTRAL_OUTCOME_SHA256 = (
    "49b715a5687c81e0e5b6437d92f087b4c81c06c3c446179b9605c2898c969de8"
)
MISTRAL_RESPONSE_SHA256 = (
    "44a75e1314cec96aa1c1d60fe9cdb5ae981e71198541246dcf548e7929a295dc"
)
GROK_ERROR_INTENT_PATH = "generation/intents/grok/attempt-1.json"
GROK_ERROR_INTENT_SHA256 = (
    "0eff589d196a1327f28247eeaeeb774c975a59b7c0d79b1cc30e7572950cd558"
)
GROK_ERROR_RAW_PATH = "generation/raw-responses/grok/attempt-1.json"
GROK_ERROR_RAW_SHA256 = (
    "11f79f667cf851797c9d1323d5787ef3134e49c94b0a255ad1dfdb980f6c79e8"
)
GROK_ERROR_OUTCOME_PATH = "generation/outcomes/grok/attempt-1.json"
GROK_ERROR_OUTCOME_SHA256 = (
    "4d121d1d9682fe6866a6272797c629161d102c9e56219e7501663aaf36a21b55"
)
GROK_REQUEST_BODY_SHA256 = (
    "d9a5b1994fc18a4dbc4e3f42f6617a97e63f5988f49eef1f64c3fc47aa394de5"
)
GROK_PROMPT_SHA256 = "687ae39f93d9400776b9d143d7553c1d609f1eb77997870fd7d0ddb2235b934d"
GROK_MESSAGES_SHA256 = (
    "eeb688915fcf2bd8412dbc61e67c5cb7013757262217d119c811630761db319c"
)
GROK_REQUESTED_PARAMS_SHA256 = (
    "1739628a5488c2a87bce3a96f94c5f76b53d2b8dc9f2387d3d9253fc838ec757"
)
GROK_PREFLIGHT_OUTCOME_PATH = "preflight/outcomes/grok/attempt-1.json"
GROK_PREFLIGHT_OUTCOME_SHA256 = (
    "eb8ca8f05b2fca0f2a75f2ea57379d1230a4c427a56e9e68d5ce672262c8b73d"
)
GPT_PREFLIGHT_OUTCOME_PATH = "preflight/outcomes/gpt/attempt-1.json"
GPT_PREFLIGHT_OUTCOME_SHA256 = (
    "58b2ef44347babe570de022ffea4b8e8a438e9f2ffc2749fd82a7fd61d8052b9"
)

QWEN_PRIVATE_SHA256 = {
    "generation/intents/deepseek/attempt-1.json": "ad10a913b3a0b86683730d36f56624a2569ceabcedf3e16b1b56ada7d71c951c",
    GROK_ERROR_INTENT_PATH: GROK_ERROR_INTENT_SHA256,
    "generation/intents/mistral/attempt-1.json": "6dd01b032d0f2236d5f76ed4aa5fa8835293ace999b81b3b7008f6c0a2450f97",
    "generation/intents/qwen/attempt-2.json": "cbccd7158c790b9e0fb8669c5b02676b60c4eabb316a9918ddf57e3507a6b64c",
    DEEPSEEK_OUTCOME_PATH: DEEPSEEK_OUTCOME_SHA256,
    GROK_ERROR_OUTCOME_PATH: GROK_ERROR_OUTCOME_SHA256,
    MISTRAL_OUTCOME_PATH: MISTRAL_OUTCOME_SHA256,
    QWEN_OUTCOME_PATH: QWEN_OUTCOME_SHA256,
    "generation/raw-responses/deepseek/attempt-1.json": "0e291cd0f4bafd8ae120ec0c6a6fbb671bc3f0ec5dda3b72fbecca42df629e3e",
    GROK_ERROR_RAW_PATH: GROK_ERROR_RAW_SHA256,
    "generation/raw-responses/mistral/attempt-1.json": "dab2b4c978f39e66a46e62fdee30bc9e54ed911d511ca10aad8b36a5e285d33c",
    "generation/raw-responses/qwen/attempt-2.json": "a42a8737a9380a4b7a8e9d7c8c420265824db5e0fbe48471eb394806cbb98226",
    QWEN_MANIFEST_PATH: QWEN_MANIFEST_SHA256,
    QWEN_AUTHORIZATION_PATH: QWEN_AUTHORIZATION_SHA256,
    "preflight/intents/deepseek/attempt-1.json": "10a1e16747604e3419f00a00305987532e9b3d274e0deb2417a17941176a8375",
    "preflight/intents/gpt/attempt-1.json": "e615d5a6e7a2cf23a85ee7c66b353e266ebff94b811f7d809c0de9aaa29493c5",
    "preflight/intents/grok/attempt-1.json": "f852f0e1d3dc117dd1490b027415474051f27a69c7a167f8f083a29f2da72934",
    "preflight/intents/mistral/attempt-1.json": "bd676bd756d76bf3ddcb03ed6371d9113ea9d6fcceaaed22671facf4ac26e93e",
    "preflight/intents/qwen-openrouter/attempt-1.json": "6b77dfc8d0a658310e74f2151f03d3b3bce5b4dccf0b15d78993b9982df42274",
    "preflight/intents/qwen/attempt-1.json": "85fcc67492917cb00e9cd2fc81afe8e6c3877cbe0aa63201fc9e29be66a48e19",
    "preflight/outcomes/deepseek/attempt-1.json": "5e7ec0df1310b175448c22a26bce51c92bd68c163a5356a74d3ef344e1c14626",
    GPT_PREFLIGHT_OUTCOME_PATH: GPT_PREFLIGHT_OUTCOME_SHA256,
    GROK_PREFLIGHT_OUTCOME_PATH: GROK_PREFLIGHT_OUTCOME_SHA256,
    "preflight/outcomes/mistral/attempt-1.json": "4009fda485649bb9e871b2b22e52cf40f5553b963bd13323f0545a4e51b56be0",
    "preflight/outcomes/qwen-openrouter/attempt-1.json": "089f639c84e8fd40b71348b63e6f44ad2111ea17cd1dbe71bb62e4693e44fe3a",
    "preflight/outcomes/qwen/attempt-1.json": "b23b2fb044361f12c0aad96c92fb44417eb7d18dfa3819219579fc26576d943e",
    "preflight/raw-responses/deepseek/attempt-1.json": "34d86be483c1c583751fd3cfbfa8eb280d2164541d873b52abd31efcc96946e8",
    "preflight/raw-responses/gpt/attempt-1.json": "3802a80c2ea62bd7653860c447bc1de5f90038430b7ec88a54ea7877189b512c",
    "preflight/raw-responses/grok/attempt-1.json": "526aea008eb5c1532e9332cd5790d2b00eaa719f4fe19a2bfb5674449f7fe8ce",
    "preflight/raw-responses/mistral/attempt-1.json": "b0c2e52f3eae4edbda650fbc4a27febcfc375b7fa5414fdae33c8a1b8d4b2f57",
    "preflight/raw-responses/qwen-openrouter/attempt-1.json": "82f2b30b812039ad1b974ca0b64e2ae87632ac2c71e6198544d9655db2178776",
    "preflight/raw-responses/qwen/attempt-1.json": "e58b100e190a49dc2a9a2d88184c4047ed0d57eaa353a2dd90bb07aec240c19e",
    "pricing-evidence.json": QWEN_PRICING_EVIDENCE_SHA256,
    "pricing-recheck.json": QWEN_PRICING_RECHECK_SHA256,
}

# The exact inventory makes these absences redundant but public and reviewable.
QWEN_REQUIRED_ABSENT = (
    f"runs/{CANDIDATE_ID}.json",
    *(
        f"generation/{kind}/grok/attempt-{attempt}.json"
        for kind in ("intents", "raw-responses", "outcomes")
        for attempt in (2, 3)
    ),
    *(
        f"generation/{kind}/gpt/attempt-{attempt}.json"
        for kind in ("intents", "raw-responses", "outcomes")
        for attempt in (1, 2, 3)
    ),
)

PRIOR_AUTHORIZATION_STATEMENT = qwen_contract.AUTHORIZATION_STATEMENT
PRIOR_AUTHORIZATION_STATEMENT_SHA256 = qwen_contract.AUTHORIZATION_STATEMENT_SHA256
USER_AMENDMENT = "Try Grok 4.5 again through xAI."
USER_AMENDMENT_SHA256 = sha256_bytes(USER_AMENDMENT.encode("utf-8"))
AUTHORIZATION_STATEMENT = (
    'A.G. Elrod authorizes this exact Grok retry after directing, "Try Grok '
    '4.5 again through xAI.": preserve the sealed Gemini, Claude, Cohere, Qwen, '
    "DeepSeek, and Mistral successes; treat the durably captured xAI Grok attempt "
    "1 HTTP 403 as consumed and count its reservation; reuse the sealed parent "
    "Grok and GPT preflight successes without another metadata request; make exactly "
    "one replacement Grok generation as semantic attempt 2 through xAI direct with "
    "model grok-4.5 and the identical prompt, messages, parameters, and request body; "
    "if that call does not produce a durably captured successful response for any "
    "reason, including another captured error or a missing capture, stop without "
    "another Grok call or any GPT call; only after Grok succeeds, generate GPT through "
    "the pinned OpenRouter-to-OpenAI route with no more than three safe attempts; "
    "make no generation call for a preserved model, use no alternative provider or "
    "third candidate, and use no tools, web search, retrieval, or external context; "
    "count every prior and retry reservation and preserve the original $6.00 candidate "
    "and $12.00 pool caps."
)
AUTHORIZATION_STATEMENT_SHA256 = sha256_bytes(AUTHORIZATION_STATEMENT.encode("utf-8"))

RESERVED_PER_POST = {"grok": 98_708, "gpt": 492_530}
INHERITED_RESERVED_MICRODOLLARS = 1_254_445
NEW_RESERVED_CAP_MICRODOLLARS = 1_576_298
COMBINED_RESERVED_CAP_MICRODOLLARS = 2_830_743
CANDIDATE_CAP_MICRODOLLARS = 6_000_000
POOL_CAP_MICRODOLLARS = 12_000_000
OUTPUT_TOKEN_CAP = 16_384
GROK_SEMANTIC_ATTEMPT_NUMBER = 2
GROK_MAXIMUM_POSTS = 1
GPT_MAXIMUM_SAFE_ATTEMPTS = 3
MAX_PREFLIGHT_REQUESTS = 0
MAX_GENERATION_POSTS = 4
MAX_OUTBOUND_REQUESTS = 4

OFFICIAL_PRICING_HOSTS = {
    "grok": ("docs.x.ai",),
    "gpt": ("openrouter.ai",),
}

NEW_SOURCE_PATHS = (
    "harness/authorize_grok_retry.py",
    "harness/create_grok_retry_lock.py",
    "harness/review_grok_retry.py",
    "harness/run_grok_retry.py",
    "harness/grok_retry/__init__.py",
    "harness/grok_retry/authorization.py",
    "harness/grok_retry/composite.py",
    "harness/grok_retry/contract.py",
    "harness/grok_retry/execute.py",
    "harness/grok_retry/lock.py",
    "harness/grok_retry/parent.py",
    "harness/grok_retry/state.py",
)


def authorization_scope() -> dict[str, Any]:
    return {
        "recovery_id": RECOVERY_ID,
        "candidate_id": CANDIDATE_ID,
        "private_root": PRIVATE_ROOT_RELATIVE,
        "preserved_model_keys": list(PRESERVED_MODEL_KEYS),
        "target_model_keys": list(TARGET_MODEL_KEYS),
        "reused_preflight_route_keys": list(PREFLIGHT_ROUTE_KEYS),
        "reused_preflight_manifest_sha256": QWEN_MANIFEST_SHA256,
        "fresh_metadata_requests_allowed": False,
        "maximum_preflight_requests": MAX_PREFLIGHT_REQUESTS,
        "captured_parent_grok_semantic_attempt_number": 1,
        "captured_parent_grok_http_status": 403,
        "grok_semantic_attempt_number": GROK_SEMANTIC_ATTEMPT_NUMBER,
        "grok_maximum_posts": GROK_MAXIMUM_POSTS,
        "grok_provider": "xai",
        "grok_route": "xai-direct",
        "grok_requested_model_id": "grok-4.5",
        "gpt_requires_grok_success": True,
        "gpt_maximum_safe_attempts": GPT_MAXIMUM_SAFE_ATTEMPTS,
        "gpt_provider": "openrouter",
        "gpt_route": "openrouter-openai-pinned",
        "alternative_provider_allowed": False,
        "grok_failure_is_terminal": True,
        "grok_no_capture_is_consumed_and_terminal": True,
        "gpt_no_capture_is_consumed_and_terminal": True,
        "maximum_generation_posts": MAX_GENERATION_POSTS,
        "maximum_outbound_requests": MAX_OUTBOUND_REQUESTS,
        "inherited_reserved_microdollars": INHERITED_RESERVED_MICRODOLLARS,
        "new_reserved_cap_microdollars": NEW_RESERVED_CAP_MICRODOLLARS,
        "combined_reserved_cap_microdollars": COMBINED_RESERVED_CAP_MICRODOLLARS,
        "candidate_reserved_cap_microdollars": CANDIDATE_CAP_MICRODOLLARS,
        "pool_reserved_cap_microdollars": POOL_CAP_MICRODOLLARS,
        "third_candidate_allowed": False,
        "tools_enabled": False,
        "web_search_enabled": False,
        "retrieval_enabled": False,
        "external_context_enabled": False,
    }


__all__ = (
    "AUTHORIZATION_STATEMENT",
    "AUTHORIZATION_STATEMENT_SHA256",
    "LOCK_PATH",
    "PRIVATE_ROOT_RELATIVE",
    "RECOVERY_ID",
    "USER_AMENDMENT",
    "USER_AMENDMENT_SHA256",
    "authorization_scope",
)
