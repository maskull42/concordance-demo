"""Immutable contract for withdrawing the Quantum fallback from publication.

This module contains metadata and digests only.  It does not import provider
code, inspect credentials, or expose any sampled response text.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any


SCHEMA_VERSION = "concordance-quantum-disposition-1.0.0"
STATUS = "withdrawn-private-stress-test-nonpublication"
POOL_ID = "concordance-divergence-supplement-1"
CANDIDATE_ID = "quantum-measurement-realist-strategies"
PRIORITY_CANDIDATE_ID = "galatians-pistis-christou"

PRIVATE_ROOT_RELATIVE = ".pilot/quantum-fallback/quantum-fallback-1"
DISPOSITION_ROOT_RELATIVE = ".pilot/quantum-disposition/quantum-withdrawal-1"
DISPOSITION_FILE = "disposition.json"
DISPOSITION_CLAIM_NAME = ".quantum-withdrawal-1.publish-claim"

RUN_EXECUTION_COMMIT = "170fc8ab022b12a7dd8808d7cb1d7c40610d0e28"
REVIEW_PREPARATION_COMMIT = "b166d3e321128843a1f95e9f8fb65fce3898eec5"
RUN_CREATED_AT = "2026-07-14T08:53:31.666+00:00"

RULE3_LOCK_SHA256 = "8f4daf2ae53d07c7c53fc3f38d3ccd11aa18420185db632467fc9c280be523cc"
QUESTION_SHA256 = "d1516759687b491d39c6bd2f33dfc0e6a92cc02ffc0b75fd691bfd83d42a8350"
PLAN_SHA256 = "a553e6ea4c0447cc9ab7bf8772d564279bc7370bf7b0500f2fcc23790c2cf456"
RUN_SHA256 = "1d2d8f9bee1a5c503912de9ad3556947f50f5a0b2f7e08a678cbfe8fdffb870f"
AUTHORIZATION_SHA256 = "628d7a00065acda37b3cd6392dbf4da708b63c5025e411a9ab2bf1917ea22767"
PRICING_RECHECK_SHA256 = "f75980a6f298880d643f9beb99eaf071fb48af210894c02689796b0b38ae09ce"
MANIFEST_SHA256 = "935ea486bc6e2c21c9fe9bc147369f1b881bc9d99f47fec622a3fff35562ef54"

USER_INSTRUCTION = (
    "I agree with your replacement recommendation. Please find the relevant "
    "sources and build it out. While that task is underway, if you need me to "
    "find any books or paywalled sources from my university library, please let "
    "me know."
)
USER_INSTRUCTION_SHA256 = (
    "5cef11c0d64145e7d681d754fb32aaff19426bb7c0276296aa3779e688a0d043"
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

OUTCOME_SHA256 = {
    "gemini": "31367172ff1e0ddc8c18036e621cb6a06e9c5900aff2be0dd37962ed62d2e447",
    "claude": "79cd0fea03f1e99fd8bea3db770f191bf5cbb2d8c1b6c9888550ab44c842c27f",
    "cohere": "b967091924a5d4ed225b0894dad9476eff43e345d25dd5eadff5a193194ceb23",
    "qwen": "c809f263e9a24df37577ef17858a7ad16658c2822ff3acc487a87b34a55e2257",
    "deepseek": "11d620cd687a6c5fdbdcd66551090c61c2cc71634dbac86ddccc504c97b7c99b",
    "mistral": "ae7799a85aa5c52da984a9af3d46e6e65d72e4cc81b025f0757db2065733b828",
    "grok": "6382d3e3e0fbe479879e42856311060df041aa661eac0e6117d1a261a03c3e0e",
    "gpt": "d9102b09a5d8d0f8d6b0858ba05574261c28bebc24d053be546242cfa4ed281c",
}

JOURNAL_TREE_SHA256 = (
    "1a49582c165a90d7a203ca11c765c79b929b51de5cad59db8817c07b3d72c9a7"
)
REVIEW_TREE_SHA256 = (
    "27925127409b54e4d80a88ef8da5c9c254ce6d56a3e5bbf6d5740211f621aff8"
)

BUDGET = {
    "inherited_reserved_microdollars": 1_845_683,
    "new_reserved_microdollars": 1_697_814,
    "combined_reserved_microdollars": 3_543_497,
    "candidate_cap_microdollars": 6_000_000,
    "pool_cap_microdollars": 12_000_000,
}
NETWORK_CONTRACT = {
    "preflight_requests": 8,
    "generation_posts": 8,
    "tools_enabled": False,
    "web_search_enabled": False,
    "retrieval_enabled": False,
    "external_context_enabled": False,
}

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class ArtifactSpec:
    """One path-and-digest binding outside the Quantum journal tree."""

    path: str
    sha256: str

    def __post_init__(self) -> None:
        relative = PurePosixPath(self.path)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or relative.as_posix() != self.path
            or not SHA256_RE.fullmatch(self.sha256)
        ):
            raise ValueError("artifact binding is malformed")

    def value(self) -> dict[str, str]:
        return {"path": self.path, "sha256": self.sha256}


PUBLIC_BINDINGS = (
    ArtifactSpec("candidate/rule3-lock.json", RULE3_LOCK_SHA256),
    ArtifactSpec(
        "candidate/rule3/questions/quantum-measurement-realist-strategies.json",
        QUESTION_SHA256,
    ),
)

UPSTREAM_PRIVATE_BINDINGS = (
    ArtifactSpec(
        ".pilot/grok-retry/grok-xai-403-retry-1/runs/galatians-pistis-christou.json",
        "e16c4b364a60e18b6554db5fc35b8e46e446a094fe346476084b4e9eb4516b7d",
    ),
    ArtifactSpec(
        ".pilot/grok-review-amendment/galatians-local-handle-correction-1/amendment.json",
        "40f13ca059cf66960cac77f0132742567a42dc1184d4b330116d0d7285c2dff9",
    ),
    ArtifactSpec(
        ".pilot/grok-review-amendment/galatians-local-handle-correction-1/fallback-eligibility.json",
        "aae3f6cb0b2b8ed01935c3ef443d1d5491f8fdf0276783b68423031e386e6f30",
    ),
    ArtifactSpec(
        ".pilot/grok-review-amendment/galatians-local-handle-correction-1/superseding-evaluation.json",
        "0caf412b77113d5b87d8d8cc971da06e0a95fc83987ba3b76248ef6ef1b64743",
    ),
)

REVIEW_PATHS = (
    "candidates/quantum-measurement-realist-strategies/blind/hmac.key",
    "candidates/quantum-measurement-realist-strategies/blind/packet.json",
    "candidates/quantum-measurement-realist-strategies/blind/crosswalk.json",
    "candidates/quantum-measurement-realist-strategies/first-pass-draft.json",
    "candidates/quantum-measurement-realist-strategies/first-pass/mapping.json",
    "candidates/quantum-measurement-realist-strategies/first-pass/receipt.json",
    "candidates/quantum-measurement-realist-strategies/author-packet/manifest.json",
    "candidates/quantum-measurement-realist-strategies/author-packet/review.html",
)

CANDIDATE_REVIEW_ROOT = (
    "candidates/quantum-measurement-realist-strategies"
)
FORBIDDEN_REVIEW_PREFIXES = (
    "author-review",
    ".author-review.",
    "evaluation",
    ".evaluation.",
)

SOURCE_PATHS = (
    "candidate/QUANTUM_DISPOSITION.md",
    "harness/concordance_harness/util.py",
    "harness/private_directory_publication.py",
    "harness/quantum_disposition/__init__.py",
    "harness/quantum_disposition/contract.py",
    "harness/quantum_disposition/parent.py",
    "harness/quantum_disposition/record.py",
    "harness/record_quantum_disposition.py",
)


def journal_paths() -> tuple[str, ...]:
    paths = ["authorization.json", "pricing-recheck.json", "manifest.json", "run.json"]
    for stage in ("preflight", "generation"):
        for kind in ("intents", "raw-responses", "outcomes"):
            paths.extend(
                f"{stage}/{kind}/{model_key}/attempt-1.json"
                for model_key in MODEL_ORDER
            )
    return tuple(paths)


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


if sha256_bytes(USER_INSTRUCTION.encode("utf-8")) != USER_INSTRUCTION_SHA256:
    raise RuntimeError("Quantum disposition instruction binding is inconsistent")

if len(journal_paths()) != 52 or len(set(journal_paths())) != 52:
    raise RuntimeError("Quantum journal path contract is inconsistent")
