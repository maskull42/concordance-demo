from __future__ import annotations

import ast
import hashlib
import json
import math
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Any


LOCK_SCHEMA_VERSION = "rule3-lock-1.0.0"
LOCK_STATUS = "immutable-preexecution-lock-no-spending-authorized"
POOL_ID = "concordance-divergence-supplement-1"
POOL_SIZE = 2
RULE_VERSION = "pilot-rule-3"
CONTENT_VERSION = "rule3-candidate-1.0.0"

LOCK_PATH = "candidate/rule3-lock.json"
LOCK_SCHEMA_PATH = "candidate/rule3-lock.schema.json"
DOSSIER_PATH = "candidate/DIVERGENCE_SUPPLEMENT_RESEARCH.md"
SOURCE_FREEZE_PATH = "candidate/rule3/source-freeze.json"
MAPPING_RUBRIC_PATH = "candidate/MAPPING_RUBRIC.md"
PROTOCOL_PATH = "config/rule3-protocol.json"
MODELS_CONFIG_PATH = "harness/config/models.json"
PRICING_REVIEW_PATH = "harness/PRICING_REVIEW.md"

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
EXPECTED_MODELS = {
    "gemini": ("gemini-3.1-pro-preview", "google", "google-direct"),
    "claude": ("claude-fable-5", "anthropic", "anthropic-direct"),
    "cohere": ("command-a-plus-05-2026", "cohere", "cohere-direct"),
    "qwen": ("Qwen/Qwen3.5-397B-A17B", "deepinfra", "deepinfra"),
    "deepseek": ("deepseek-v4-pro", "deepseek", "deepseek-direct"),
    "mistral": ("mistral-large-2512", "mistral", "mistral-direct"),
    "grok": ("grok-4.5", "xai", "xai-direct"),
    "gpt": ("openai/gpt-5.6-sol", "openrouter", "openrouter-openai-pinned"),
}

# This is an independently hardcoded approval boundary, not a projection of
# models.json.  A changed endpoint, credential name, authentication mechanism,
# rate, route, or price therefore cannot silently become the contract during
# lock construction.
APPROVED_MODEL_TRANSPORTS: dict[str, dict[str, Any]] = {
    "gemini": {
        "family": "Gemini",
        "provider": "google",
        "requested_model_id": "gemini-3.1-pro-preview",
        "route": "google-direct",
        "environment_variable": "GOOGLE_API_KEY",
        "api_style": "google",
        "base_url": "https://generativelanguage.googleapis.com",
        "generation_path": "/v1beta/models/{model}:generateContent",
        "metadata_path": "/v1beta/models/{model}",
        "metadata_mode": "single",
        "auth_kind": "google-query",
        "fallback_allowed": False,
        "requests_per_second": 1.0,
    },
    "claude": {
        "family": "Claude",
        "provider": "anthropic",
        "requested_model_id": "claude-fable-5",
        "route": "anthropic-direct",
        "environment_variable": "ANTHROPIC_API_KEY",
        "api_style": "anthropic",
        "base_url": "https://api.anthropic.com",
        "generation_path": "/v1/messages",
        "metadata_path": "/v1/models/{model}",
        "metadata_mode": "single",
        "auth_kind": "anthropic-key",
        "fallback_allowed": False,
        "requests_per_second": 1.0,
    },
    "cohere": {
        "family": "Cohere",
        "provider": "cohere",
        "requested_model_id": "command-a-plus-05-2026",
        "route": "cohere-direct",
        "environment_variable": "COHERE_API_KEY",
        "api_style": "cohere",
        "base_url": "https://api.cohere.com",
        "generation_path": "/v2/chat",
        "metadata_path": "/v1/models/{model}",
        "metadata_mode": "single",
        "auth_kind": "bearer",
        "fallback_allowed": False,
        "requests_per_second": 1.0,
    },
    "qwen": {
        "family": "Qwen",
        "provider": "deepinfra",
        "requested_model_id": "Qwen/Qwen3.5-397B-A17B",
        "route": "deepinfra",
        "environment_variable": "DEEPINFRA_API_KEY",
        "api_style": "openai",
        "base_url": "https://api.deepinfra.com",
        "generation_path": "/v1/openai/chat/completions",
        "metadata_path": "/v1/models",
        "metadata_mode": "list",
        "auth_kind": "bearer",
        "fallback_allowed": False,
        "requests_per_second": 1.0,
    },
    "deepseek": {
        "family": "DeepSeek",
        "provider": "deepseek",
        "requested_model_id": "deepseek-v4-pro",
        "route": "deepseek-direct",
        "environment_variable": "DEEPSEEK_API_KEY",
        "api_style": "openai",
        "base_url": "https://api.deepseek.com",
        "generation_path": "/chat/completions",
        "metadata_path": "/models",
        "metadata_mode": "list",
        "auth_kind": "bearer",
        "fallback_allowed": False,
        "requests_per_second": 1.0,
    },
    "mistral": {
        "family": "Mistral",
        "provider": "mistral",
        "requested_model_id": "mistral-large-2512",
        "route": "mistral-direct",
        "environment_variable": "MISTRAL_API_KEY",
        "api_style": "openai",
        "base_url": "https://api.mistral.ai",
        "generation_path": "/v1/chat/completions",
        "metadata_path": "/v1/models/{model}",
        "metadata_mode": "single",
        "auth_kind": "bearer",
        "fallback_allowed": False,
        "requests_per_second": 1.0,
    },
    "grok": {
        "family": "Grok",
        "provider": "xai",
        "requested_model_id": "grok-4.5",
        "route": "xai-direct",
        "environment_variable": "XAI_API_KEY",
        "api_style": "xai-responses",
        "base_url": "https://api.x.ai",
        "generation_path": "/v1/responses",
        "metadata_path": "/v1/models/{model}",
        "metadata_mode": "single",
        "auth_kind": "bearer",
        "fallback_allowed": False,
        "requests_per_second": 1.0,
    },
    "gpt": {
        "family": "GPT",
        "provider": "openrouter",
        "requested_model_id": "openai/gpt-5.6-sol",
        "route": "openrouter-openai-pinned",
        "environment_variable": "OPENROUTER_API_KEY",
        "api_style": "openai",
        "base_url": "https://openrouter.ai",
        "generation_path": "/api/v1/chat/completions",
        "metadata_path": "/api/v1/models/{model}/endpoints",
        "metadata_mode": "openrouter-endpoints",
        "auth_kind": "bearer",
        "fallback_allowed": False,
        "requests_per_second": 1.0,
    },
}

APPROVED_PLANNING_PRICING_NOTE = (
    "Official standard synchronous rates researched and approved by A.G. Elrod "
    "on 2026-07-12. Documented in harness/PRICING_REVIEW.md and subject to an "
    "immediate pre-run recheck."
)
APPROVED_PLANNING_PRICING: dict[str, dict[str, Any]] = {
    "gemini": {
        "currency": "USD",
        "input_per_million": 2.0,
        "output_per_million": 12.0,
        "pricing_as_of": "2026-07-12",
        "review_status": "author-verified",
    },
    "claude": {
        "currency": "USD",
        "input_per_million": 10.0,
        "output_per_million": 50.0,
        "pricing_as_of": "2026-07-12",
        "review_status": "author-verified",
    },
    "cohere": {
        "currency": "USD",
        "input_per_million": 0.0,
        "output_per_million": 0.0,
        "pricing_as_of": "2026-07-12",
        "review_status": "author-verified",
    },
    "qwen": {
        "currency": "USD",
        "input_per_million": 0.45,
        "output_per_million": 3.0,
        "pricing_as_of": "2026-07-12",
        "review_status": "author-verified",
    },
    "deepseek": {
        "currency": "USD",
        "input_per_million": 0.435,
        "output_per_million": 0.87,
        "pricing_as_of": "2026-07-12",
        "review_status": "author-verified",
    },
    "mistral": {
        "currency": "USD",
        "input_per_million": 0.5,
        "output_per_million": 1.5,
        "pricing_as_of": "2026-07-12",
        "review_status": "author-verified",
    },
    "grok": {
        "currency": "USD",
        "input_per_million": 2.0,
        "output_per_million": 6.0,
        "pricing_as_of": "2026-07-12",
        "review_status": "author-verified",
    },
    "gpt": {
        "currency": "USD",
        "input_per_million": 5.0,
        "output_per_million": 30.0,
        "pricing_as_of": "2026-07-12",
        "review_status": "author-verified",
    },
}

CANDIDATES = (
    {
        "id": "galatians-pistis-christou",
        "role": "priority",
        "kind": "divergent",
        "path": "candidate/rule3/questions/galatians-pistis-christou.json",
        "prompt": (
            "In Galatians 3:22-26, what does Paul most likely mean by πίστις "
            "Χριστοῦ in verse 22 when the phrase is read within its immediate "
            "argument? State one best-supported primary interpretation and explain "
            "the decisive grammatical, lexical, and contextual evidence."
        ),
    },
    {
        "id": "quantum-measurement-realist-strategies",
        "role": "fallback",
        "kind": "divergent",
        "path": (
            "candidate/rule3/questions/" "quantum-measurement-realist-strategies.json"
        ),
        "prompt": (
            "Among Everettian unitary quantum mechanics, Bohmian mechanics, and "
            "objective-collapse theories, which offers the best overall resolution "
            "of the nonrelativistic quantum measurement problem? State one primary "
            "answer and explain which empirical and theoretical considerations are "
            "decisive."
        ),
    },
)
EXPECTED_SOURCE_IDS = (
    (
        "matlock-rhetoric-pistis",
        "sblgnt-galatians-three",
        "hooker-pistis-christou",
        "grasso-linguistic-analysis",
        "schliesser-christ-faith-event",
    ),
    (
        "maudlin-three-measurement-problems",
        "everett-relative-state",
        "sep-everettian-quantum-mechanics",
        "bohm-hidden-variables-part-one",
        "bohm-hidden-variables-part-two",
        "sep-bohmian-mechanics",
        "grw-unified-dynamics",
        "sep-collapse-theories",
    ),
)

# These digests identify the exact candidate records A.G. approved. The lock
# builder also validates their semantics field by field, but may never silently
# bless a reformatted or otherwise altered successor as the approved record.
APPROVED_QUESTION_SHA256 = {
    "galatians-pistis-christou": (
        "4bdd90ee9134dac142a1e1a0df689d8dc29dbb0b673107bbad9721200b7543f6"
    ),
    "quantum-measurement-realist-strategies": (
        "d1516759687b491d39c6bd2f33dfc0e6a92cc02ffc0b75fd691bfd83d42a8350"
    ),
}
APPROVED_SOURCE_FREEZE_SHA256 = (
    "2ee5bc2d754b3e2bb199a45de26f2eb4b12cd72f41fd27e4efc3544118a5b8b2"
)

PROPOSED_VERIFICATION = {
    "status": "proposed",
    "verified_by": None,
    "verified_at": None,
}

EXPECTED_CONTEXT_NOTES = {
    "galatians-pistis-christou": (
        "The map distinguishes an objective reading, a Christ-centered subjective "
        "or participatory reading, an attributive system reading, and an "
        "eschatological-event reading. Grasso's system and Schliesser's event "
        "remain distinct. An answer maps here only if it clearly makes Christ’s "
        "faith the semantic and explanatory center. A merely plenary, "
        "intentionally ambiguous, or evenly combined subjective-objective answer "
        "remains null. Coding follows the phrase's semantic referent, not the "
        "response's wider soteriology."
    ),
    "quantum-measurement-realist-strategies": (
        "The map compares three realist strategies at the level of their core "
        "physical proposals. Objective collapse changes the dynamics and can "
        "differ empirically from standard quantum mechanics. An answer that "
        "selects an excluded approach, claims decoherence alone solves the "
        "measurement problem, or refuses the prompt's realist comparison remains "
        "null. Disputes internal to Everettian probability, Bohmian ontology, or "
        "collapse-model variants do not create new positions after output."
    ),
}

EXPECTED_POSITION_DEFINITIONS = (
    (
        {
            "id": "believers-faith-in-christ",
            "label": "Believers' faith in Christ",
            "summary": (
                "The phrase denotes believers' faith or trust directed toward "
                "Christ."
            ),
            "attestation": (
                "Matlock's direct analysis of Galatians 3:22 argues that the "
                "Christ-faith phrase and the clause about those who believe both "
                "concern believers' faith, selecting the objective-genitive "
                "reading. The SBL Greek New Testament supplies the base text for "
                "the immediate argument."
            ),
            "source_ids": (
                "matlock-rhetoric-pistis",
                "sblgnt-galatians-three",
            ),
        },
        {
            "id": "christs-own-faithfulness",
            "label": "Christ's own faith or faithfulness",
            "summary": (
                "The phrase primarily denotes Christ’s own faith or faithfulness. "
                "This includes concentric or participatory accounts in which "
                "believers’ answering faith derives from and shares in Christ’s "
                "faith."
            ),
            "attestation": (
                "Hooker argues directly from Galatians 3:22 that the phrase refers "
                "to Christ's faith, then develops a concentric and participatory "
                "account in which Christ's faith remains primary while believers' "
                "answering faith derives from and shares in it."
            ),
            "source_ids": ("hooker-pistis-christou",),
        },
        {
            "id": "christ-faith-system",
            "label": "Christ-defined system of faith",
            "summary": (
                "The phrase denotes the Christ-defined or Christ-centered faith, "
                "understood as a system or body of belief, not a disposition "
                "exercised by either believer or Christ."
            ),
            "attestation": (
                "Grasso defines a third view as the Christ-centered content or "
                "system of faith, applies it directly to Galatians 3:22, and "
                "concludes that this attributive analysis is the most "
                "linguistically plausible reading."
            ),
            "source_ids": ("grasso-linguistic-analysis",),
        },
        {
            "id": "christ-faith-event",
            "label": "Christ-faith as eschatological event",
            "summary": (
                "In the immediate argument, faith is a newly arrived and revealed "
                "reality, not an individual disposition or a belief system."
            ),
            "attestation": (
                "Schliesser reads the coming and revelation of faith in Galatians "
                "3:23-26 as a trans-subjective eschatological event. He applies "
                "that account back to Christ-faith in verse 22 and distinguishes "
                "it from Christ's or believers' individual dispositions."
            ),
            "source_ids": ("schliesser-christ-faith-event",),
        },
    ),
    (
        {
            "id": "everettian-unitary-branching",
            "label": "Everettian unitary branching",
            "summary": (
                "Retain a complete wavefunction and universal unitary dynamics; "
                "account for determinate experience through relative states or "
                "branching rather than one globally unique outcome."
            ),
            "attestation": (
                "Maudlin identifies the measurement trilemma and the multiverse "
                "response. Everett's primary formulation treats linear wave "
                "mechanics as complete, removes discontinuous observation "
                "dynamics, and represents measurement through correlated relative "
                "states. The Stanford overview records the modern branching family "
                "and its internal probability and ontology problems."
            ),
            "source_ids": (
                "maudlin-three-measurement-problems",
                "everett-relative-state",
                "sep-everettian-quantum-mechanics",
            ),
        },
        {
            "id": "bohmian-added-configuration",
            "label": "Bohmian added configuration",
            "summary": (
                "Retain unitary wavefunction evolution but reject its completeness "
                "by adding a definite particle configuration or comparable "
                "beables, yielding one actual outcome."
            ),
            "attestation": (
                "Bohm's two-part primary account supplements the wave field with "
                "actual particle and apparatus coordinates. During measurement, "
                "the occupied nonoverlapping apparatus packet determines a single "
                "recorded result. The Stanford overview situates this "
                "added-configuration strategy and its equivariance, nonlocality, "
                "and ontology questions."
            ),
            "source_ids": (
                "bohm-hidden-variables-part-one",
                "bohm-hidden-variables-part-two",
                "sep-bohmian-mechanics",
            ),
        },
        {
            "id": "objective-collapse-dynamics",
            "label": "Objective-collapse dynamics",
            "summary": (
                "Retain a complete physical state and unique outcomes but modify "
                "linear dynamics with genuine stochastic collapse."
            ),
            "attestation": (
                "GRW replaces universal linear evolution with spontaneous "
                "stochastic localization, leaving microscopic predictions "
                "practically intact while rapidly suppressing macroscopic "
                "superpositions and producing definite pointer positions. The "
                "Stanford overview records the broader dynamical-reduction family "
                "and its empirical constraints."
            ),
            "source_ids": (
                "grw-unified-dynamics",
                "sep-collapse-theories",
            ),
        },
    ),
)

EXPECTED_SOURCE_ARTIFACTS = {
    "matlock-rhetoric-pistis": (
        "supplied-complete-file",
        "b8f36f800c78f0a30c0cb2ead834d4e141ceff18e710717adca307899aca8d2c",
    ),
    "sblgnt-galatians-three": (
        "hash-frozen-external-snapshot",
        "3d6cf6dd7ee9624167fde1ebc0ba2a1464c2aea6b630f52db436e2aee1c2f49b",
    ),
    "hooker-pistis-christou": (
        "supplied-complete-file",
        "7acb7d20cb2bdddbe3568530d14a8117a4c8ba522d6757dba2f959e12cd132b2",
    ),
    "grasso-linguistic-analysis": ("integrity-limited-no-raw-snapshot", None),
    "schliesser-christ-faith-event": (
        "supplied-complete-file",
        "b3e4cbe547c111d8382b230bdc376e08b7306f38b31584e4140b8a41a6723fb8",
    ),
    "maudlin-three-measurement-problems": (
        "hash-frozen-external-artifact",
        "e8de5c3dfef6210bae6c5866f38979f2e70490253712fecdbab0487c189ee988",
    ),
    "everett-relative-state": (
        "hash-frozen-external-artifact",
        "016afb29545d5e1475f660f694e5f7eea8f06f4682e7c0ed3430fe1adcf6b8f8",
    ),
    "sep-everettian-quantum-mechanics": (
        "hash-frozen-external-snapshot",
        "00cc0e9a903456bfb59f92fa823f830c15edfc1bf7e4ffccbbd68a79e6fc58c6",
    ),
    "bohm-hidden-variables-part-one": (
        "hash-frozen-external-artifact",
        "a322064233554b472d486a4b38b80a54e4e85d7b9761f283d8b77ff304f68615",
    ),
    "bohm-hidden-variables-part-two": (
        "hash-frozen-external-artifact",
        "161da4cb4e1341d823fdf4eb0b6504e15086018d59532d86fa048370bd751241",
    ),
    "sep-bohmian-mechanics": (
        "hash-frozen-external-snapshot",
        "f1465138a4fc510d93667132d5e58db8a06491ccd3b2fbcb9435a8ff43adb0a4",
    ),
    "grw-unified-dynamics": (
        "hash-frozen-external-artifact",
        "655efa13b585709b309028476cdfaebd2aa17902e35696496efdf5ff56ce40da",
    ),
    "sep-collapse-theories": (
        "hash-frozen-external-snapshot",
        "4403377309688fafc6aebae176c97d812d14cf05377c8b5b9c944b77be2b1cbb",
    ),
}

REQUIRED_EXECUTION_SOURCES = (
    "harness/rule3/__init__.py",
    "harness/rule3/authorization.py",
    "harness/rule3/budget.py",
    "harness/rule3/contract.py",
    "harness/rule3/execute.py",
    "harness/rule3/lock.py",
    "harness/rule3/review.py",
    "harness/rule3/evaluate.py",
    "harness/rule3/review_assets/review.css",
    "harness/rule3/review_assets/review.js",
    "harness/create_rule3_lock.py",
    "harness/authorize_rule3.py",
    "harness/run_rule3.py",
    "harness/prepare_rule3_review.py",
    "harness/finalize_rule3_review.py",
    "harness/evaluate_rule3.py",
)
SHARED_EXECUTION_SOURCES = (
    "harness/private_directory_publication.py",
    "harness/concordance_harness/__init__.py",
    "harness/concordance_harness/config.py",
    "harness/concordance_harness/execution.py",
    "harness/concordance_harness/pilot_lock.py",
    "harness/concordance_harness/planner.py",
    "harness/concordance_harness/providers.py",
    "harness/concordance_harness/util.py",
)

SYSTEM_PROMPT = (
    "Answer the user's question directly and identify the interpretation you judge "
    "best supported. Explain the decisive reasons and acknowledge serious "
    "alternatives. Do not use tools, web search, retrieval, or external context. "
    "Keep the visible answer under 900 tokens. Do not identify yourself, your "
    "model or model family, your provider, your developer, your training process, "
    "your service route, or your status as an AI anywhere in the answer."
)

EXPECTED_REQUEST_PARAMS: dict[str, dict[str, Any]] = {
    "gemini": {
        "temperature": {
            "sent": False,
            "value": None,
            "reason": "Gemini 3.1 Pro documented default",
        },
        "output_limit": {
            "sent": True,
            "parameter": "max_output_tokens",
            "value": 16_384,
        },
        "reasoning": {
            "sent": False,
            "setting": None,
            "reason": "Provider default reasoning behavior",
        },
        "tools_enabled": False,
        "web_search_enabled": False,
        "retrieval_enabled": False,
        "provider_options": {},
    },
    "claude": {
        "temperature": {
            "sent": False,
            "value": None,
            "reason": "Temperature omitted for Claude Fable 5",
        },
        "output_limit": {
            "sent": True,
            "parameter": "max_tokens",
            "value": 16_384,
        },
        "reasoning": {
            "sent": False,
            "setting": None,
            "reason": ("Always-on adaptive reasoning; no reasoning parameter sent"),
        },
        "tools_enabled": False,
        "web_search_enabled": False,
        "retrieval_enabled": False,
        "provider_options": {},
    },
    "cohere": {
        "temperature": {"sent": True, "value": 0.2},
        "output_limit": {
            "sent": True,
            "parameter": "max_tokens",
            "value": 16_384,
        },
        "reasoning": {
            "sent": False,
            "setting": None,
            "reason": "No separate reasoning parameter sent",
        },
        "tools_enabled": False,
        "web_search_enabled": False,
        "retrieval_enabled": False,
        "provider_options": {},
    },
    "qwen": {
        "temperature": {"sent": True, "value": 0.2},
        "output_limit": {
            "sent": True,
            "parameter": "max_tokens",
            "value": 16_384,
        },
        "reasoning": {
            "sent": False,
            "setting": None,
            "reason": "No separate reasoning parameter sent",
        },
        "tools_enabled": False,
        "web_search_enabled": False,
        "retrieval_enabled": False,
        "provider_options": {},
    },
    "deepseek": {
        "temperature": {"sent": True, "value": 0.2},
        "output_limit": {
            "sent": True,
            "parameter": "max_tokens",
            "value": 16_384,
        },
        "reasoning": {
            "sent": False,
            "setting": None,
            "reason": "No separate reasoning parameter sent",
        },
        "tools_enabled": False,
        "web_search_enabled": False,
        "retrieval_enabled": False,
        "provider_options": {},
    },
    "mistral": {
        "temperature": {"sent": True, "value": 0.2},
        "output_limit": {
            "sent": True,
            "parameter": "max_tokens",
            "value": 16_384,
        },
        "reasoning": {
            "sent": False,
            "setting": None,
            "reason": "No separate reasoning parameter sent",
        },
        "tools_enabled": False,
        "web_search_enabled": False,
        "retrieval_enabled": False,
        "provider_options": {},
    },
    "grok": {
        "temperature": {"sent": True, "value": 0.2},
        "output_limit": {
            "sent": True,
            "parameter": "max_output_tokens",
            "value": 16_384,
        },
        "reasoning": {
            "sent": False,
            "setting": None,
            "reason": (
                "Mandatory provider-default reasoning shares the "
                "max_output_tokens ceiling"
            ),
        },
        "tools_enabled": False,
        "web_search_enabled": False,
        "retrieval_enabled": False,
        "provider_options": {"store": False, "service_tier": "default"},
    },
    "gpt": {
        "temperature": {
            "sent": False,
            "value": None,
            "reason": "Temperature omitted for GPT-5.6 Sol",
        },
        "output_limit": {
            "sent": True,
            "parameter": "max_tokens",
            "value": 16_384,
        },
        "reasoning": {
            "sent": False,
            "setting": None,
            "reason": (
                "Provider default reasoning behavior; no reasoning parameter sent"
            ),
        },
        "tools_enabled": False,
        "web_search_enabled": False,
        "retrieval_enabled": False,
        "provider_options": {
            "service_tier": "default",
            "provider": {
                "only": ["openai"],
                "allow_fallbacks": False,
                "require_parameters": True,
            },
        },
    },
}

OUTPUT_TOKEN_CAP = 16_384
ATTEMPTS_PER_CELL = 3
CANDIDATE_COST_CAP_MICRODOLLARS = 6_000_000
TOTAL_COST_CAP_MICRODOLLARS = 12_000_000
REQUIRED_COMPLETED_RESPONSES = 8
MINIMUM_NON_NULL_ENDORSEMENTS = 6
MINIMUM_DISTINCT_POSITIONS = 3
MAXIMUM_ENDORSEMENTS_PER_POSITION = 4


class Rule3LockError(ValueError):
    """Raised when a file or value cannot belong to the Rule 3 contract."""


ContractError = Rule3LockError


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def prompt_sha256(messages: list[dict[str, str]]) -> str:
    digest = hashlib.sha256()
    for message in messages:
        digest.update(message["role"].encode("utf-8"))
        digest.update(b"\0")
        digest.update(message["content"].encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def require_relative_path(value: object, label: str = "path") -> str:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{label} must be a nonempty repository-relative path")
    if "\\" in value:
        raise ContractError(f"{label} must use POSIX separators")
    pure = PurePosixPath(value)
    if pure.is_absolute() or str(pure) != value:
        raise ContractError(f"{label} must be a normalized repository-relative path")
    if any(part in {"", ".", ".."} for part in pure.parts):
        raise ContractError(f"{label} may not traverse outside the repository")
    return value


def repository_root(path: Path | str) -> Path:
    root = Path(path).absolute()
    try:
        metadata = root.lstat()
    except OSError as error:
        raise ContractError(f"repository root cannot be inspected: {error}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ContractError("repository root must be a real directory, not a symlink")
    return root.resolve()


def read_regular_file(root: Path, relative: str) -> bytes:
    relative = require_relative_path(relative)
    root = repository_root(root)
    current = root
    for part in PurePosixPath(relative).parts[:-1]:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as error:
            raise ContractError(
                f"{relative}: path cannot be inspected: {error}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ContractError(f"{relative}: parent path must be a real directory")

    path = root / relative
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ContractError(f"{relative}: cannot open regular file: {error}") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ContractError(f"{relative}: must be a regular non-symlink file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            return handle.read()
    finally:
        os.close(descriptor)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ContractError(f"non-finite JSON number is forbidden: {value}")


def _require_finite_json_numbers(value: Any, label: str) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ContractError(f"{label}: non-finite JSON numbers are forbidden")
    if isinstance(value, list):
        for item in value:
            _require_finite_json_numbers(item, label)
    elif isinstance(value, dict):
        for item in value.values():
            _require_finite_json_numbers(item, label)


def parse_json_bytes(payload: bytes, label: str) -> Any:
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except UnicodeDecodeError as error:
        raise ContractError(f"{label}: JSON must be UTF-8") from error
    except json.JSONDecodeError as error:
        raise ContractError(f"{label}: malformed JSON: {error.msg}") from error
    _require_finite_json_numbers(value, label)
    return value


def read_json_file(root: Path, relative: str) -> tuple[Any, bytes]:
    payload = read_regular_file(root, relative)
    return parse_json_bytes(payload, relative), payload


def requested_params_receipt(model: dict[str, Any]) -> dict[str, Any]:
    temperature = model.get("temperature")
    if not isinstance(temperature, dict):
        raise ContractError(f"{model.get('model_key')}: invalid temperature policy")
    if temperature.get("mode") == "fixed":
        if set(temperature) != {"mode", "value"}:
            raise ContractError(f"{model.get('model_key')}: invalid fixed temperature")
        temperature_receipt: dict[str, Any] = {
            "sent": True,
            "value": temperature["value"],
        }
    elif temperature.get("mode") == "provider-default":
        if set(temperature) != {"mode", "reason"}:
            raise ContractError(
                f"{model.get('model_key')}: invalid default temperature"
            )
        temperature_receipt = {
            "sent": False,
            "value": None,
            "reason": temperature["reason"],
        }
    else:
        raise ContractError(f"{model.get('model_key')}: unsupported temperature mode")

    output_limit = model.get("output_limit")
    if not isinstance(output_limit, dict) or set(output_limit) != {
        "parameter",
        "value",
    }:
        raise ContractError(f"{model.get('model_key')}: invalid output limit")
    if output_limit["value"] != OUTPUT_TOKEN_CAP:
        raise ContractError(
            f"{model.get('model_key')}: output limit must be {OUTPUT_TOKEN_CAP}"
        )

    reasoning = model.get("reasoning")
    if not isinstance(reasoning, dict):
        raise ContractError(f"{model.get('model_key')}: invalid reasoning policy")
    if reasoning.get("mode") == "fixed":
        if set(reasoning) != {"mode", "setting"}:
            raise ContractError(f"{model.get('model_key')}: invalid fixed reasoning")
        reasoning_receipt: dict[str, Any] = {
            "sent": True,
            "setting": reasoning["setting"],
        }
    elif reasoning.get("mode") == "provider-default":
        if set(reasoning) != {"mode", "description"}:
            raise ContractError(f"{model.get('model_key')}: invalid default reasoning")
        reasoning_receipt = {
            "sent": False,
            "setting": None,
            "reason": reasoning["description"],
        }
    else:
        raise ContractError(f"{model.get('model_key')}: unsupported reasoning mode")

    provider_options = model.get("provider_options")
    if not isinstance(provider_options, dict):
        raise ContractError(f"{model.get('model_key')}: invalid provider options")
    return {
        "temperature": temperature_receipt,
        "output_limit": {
            "sent": True,
            "parameter": output_limit["parameter"],
            "value": output_limit["value"],
        },
        "reasoning": reasoning_receipt,
        "tools_enabled": False,
        "web_search_enabled": False,
        "retrieval_enabled": False,
        "provider_options": provider_options,
    }


def _excluded_execution_path(relative: PurePosixPath) -> bool:
    return (
        any(part in {"tests", "__pycache__"} for part in relative.parts)
        or relative.suffix == ".pyc"
        or relative.name == "rule3-lock.json"
    )


def _walk_execution_files(
    root: Path,
    subtree: str,
    *,
    python_only: bool,
) -> set[str]:
    subtree_path = root / subtree
    if not subtree_path.is_dir() or subtree_path.is_symlink():
        raise ContractError(f"{subtree} must be a real directory")
    discovered: set[str] = set()
    for directory, directory_names, file_names in os.walk(
        subtree_path, topdown=True, followlinks=False
    ):
        directory_path = Path(directory)
        kept_directories: list[str] = []
        for name in sorted(directory_names):
            child = directory_path / name
            relative = PurePosixPath(child.relative_to(root).as_posix())
            if _excluded_execution_path(relative):
                continue
            if child.is_symlink():
                raise ContractError(
                    f"{relative}: execution source directory may not be a symlink"
                )
            kept_directories.append(name)
        directory_names[:] = kept_directories
        for name in sorted(file_names):
            child = directory_path / name
            relative = PurePosixPath(child.relative_to(root).as_posix())
            if _excluded_execution_path(relative):
                continue
            if python_only and relative.suffix != ".py":
                continue
            read_regular_file(root, relative.as_posix())
            discovered.add(relative.as_posix())
    return discovered


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
    is_local = top_file.is_file() or top_directory.is_dir()
    if not is_local:
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
        raise ContractError(f"{label}: unresolved local import {'.'.join(parts)}")
    return set()


def _relative_import_parts(
    source: str,
    module: str | None,
    level: int,
) -> tuple[str, ...]:
    source_parts = _module_parts(source)
    if source_parts is None:
        raise ContractError(f"{source}: cannot resolve a relative import")
    if PurePosixPath(source).name == "__init__.py":
        package = source_parts
    else:
        package = source_parts[:-1]
    parents = level - 1
    if parents > len(package):
        raise ContractError(f"{source}: relative import escapes its local package")
    base = package[: len(package) - parents]
    if module:
        base += tuple(module.split("."))
    return base


def _python_local_imports(root: Path, relative: str) -> set[str]:
    payload = read_regular_file(root, relative)
    try:
        source = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ContractError(f"{relative}: Python source must be UTF-8") from error
    try:
        tree = ast.parse(source, filename=relative)
    except SyntaxError as error:
        raise ContractError(
            f"{relative}: Python source cannot be parsed: {error}"
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
                base = _relative_import_parts(
                    relative,
                    node.module,
                    node.level,
                )
                imports.update(
                    _local_module_paths(root, base, required=True, label=relative)
                )
            elif node.module:
                base = tuple(node.module.split("."))
                imports.update(
                    _local_module_paths(root, base, required=True, label=relative)
                )
            else:
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                imports.update(
                    _local_module_paths(
                        root,
                        base + tuple(alias.name.split(".")),
                        required=False,
                        label=relative,
                    )
                )
        elif isinstance(node, ast.Call):
            dynamic_name: str | None = None
            if isinstance(node.func, ast.Name) and node.func.id == "__import__":
                dynamic_name = "__import__"
            elif (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "import_module"
            ):
                dynamic_name = "import_module"
            if dynamic_name is None:
                continue
            if not node.args or not isinstance(node.args[0], ast.Constant):
                raise ContractError(
                    f"{relative}: non-literal {dynamic_name} cannot be source-bound"
                )
            imported = node.args[0].value
            if (
                not isinstance(imported, str)
                or not imported
                or imported.startswith(".")
            ):
                raise ContractError(
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


def discover_execution_source_paths(root: Path | str) -> tuple[str, ...]:
    root = repository_root(root)
    discovered = _walk_execution_files(root, "harness/rule3", python_only=False)
    discovered.update(
        _walk_execution_files(
            root,
            "harness/concordance_harness",
            python_only=True,
        )
    )

    harness_root = root / "harness"
    for child in sorted(harness_root.glob("*rule3*.py")):
        relative = child.relative_to(root).as_posix()
        read_regular_file(root, relative)
        discovered.add(relative)

    missing = sorted(set(REQUIRED_EXECUTION_SOURCES) - discovered)
    if missing:
        raise ContractError(
            "Rule 3 execution implementation is incomplete; missing: "
            + ", ".join(missing)
        )
    for relative in SHARED_EXECUTION_SOURCES:
        read_regular_file(root, relative)
        discovered.add(relative)

    # Follow every statically resolvable local import from the mandatory roots.
    # This makes a newly imported helper part of the lock automatically.  An old
    # lock then fails structural validation instead of running unbound code.
    pending = sorted(
        relative for relative in discovered if PurePosixPath(relative).suffix == ".py"
    )
    parsed: set[str] = set()
    while pending:
        relative = pending.pop(0)
        if relative in parsed:
            continue
        parsed.add(relative)
        for imported in sorted(_python_local_imports(root, relative)):
            if imported not in discovered:
                discovered.add(imported)
                if PurePosixPath(imported).suffix == ".py":
                    pending.append(imported)
    return tuple(sorted(discovered))
