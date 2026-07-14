"""Exact public constants for the append-only successor continuation.

The continuation preserves the first attempt byte for byte.  Its only new
network authority is one generation POST for each member of the frozen panel.
"""

from __future__ import annotations

from pathlib import Path

from divergence_successor import contract as parent_contract


LOCK_SCHEMA_VERSION = "rule3-successor-continuation-lock-1.0.0"
LOCK_STATUS = "immutable-offline-correction-continuation-lock"
POOL_ID = "frontier-ai-preflight-correction-1"
CANDIDATE_ID = parent_contract.CANDIDATE_ID
MODEL_KEYS = parent_contract.MODEL_KEYS
EXPECTED_MODELS = parent_contract.EXPECTED_MODELS
OUTPUT_TOKEN_CAP = parent_contract.OUTPUT_TOKEN_CAP
GENERATION_POSTS = len(MODEL_KEYS)
AUTOMATIC_RETRIES = 0
CANDIDATE_COST_CAP_MICRODOLLARS = parent_contract.CANDIDATE_COST_CAP_MICRODOLLARS
POOL_COST_CAP_MICRODOLLARS = parent_contract.POOL_COST_CAP_MICRODOLLARS

LOCK_PATH = "candidate/rule3-successor-continuation-lock.json"
LOCK_SCHEMA_PATH = "candidate/rule3-successor-continuation-lock.schema.json"
ORIGINAL_LOCK_PATH = parent_contract.LOCK_PATH
ORIGINAL_PRIVATE_ROOT = parent_contract.PRIVATE_ROOT_RELATIVE
PRIVATE_ROOT_RELATIVE = (
    ".pilot/divergence-successor-continuation/frontier-ai-preflight-correction-1"
)
REVIEW_ROOT_RELATIVE = (
    ".pilot/divergence-successor-continuation-review/frontier-ai-preflight-correction-1"
)
CORRECTION_RECEIPT_RELATIVE = f"{PRIVATE_ROOT_RELATIVE}/offline-correction.json"

ORIGINAL_LOCK_SHA256 = (
    "08cbaa1963d88cc0c1b0fe32ac7e74fbd553b4dc9f7a6a1de0cc6866129f8ab9"
)
ORIGINAL_GIT_HEAD = "ed17b8f6832a6b338996e3a0d56105958177739d"
ORIGINAL_PARENT_CONTRACT_SHA256 = (
    "85713b5b7c722a327c852f945b083cceaaa01eedcf9ef362fd81b4516a49d678"
)
ORIGINAL_AUTHORIZATION_SHA256 = (
    "78f9fc695d5f976b9720f3c35d3134f0b3bbb79472094abc07d16f87473f51b1"
)
ORIGINAL_PRICING_SHA256 = (
    "d224925e86fedf330246de094278a84065a652ecce32931c8a7e870fefae3f2d"
)
ORIGINAL_PREFLIGHT_SHA256 = {
    "gemini": {
        "intent": "79635e08682937ee48d8bde70a8d1e091f3343f4682a200b897749bd7cba7fb8",
        "raw_response": "2b4ef6cf8ae3681042a77904ccf129b392f2e5ffd397292bc03bc1d600af0ef2",
        "outcome": "6132085f11deb9c85aedaa52f6e50f120054c9fc402e8cf924280a72d9829ed7",
    },
    "claude": {
        "intent": "a1757bd857221b1498136690177c010c09787dd08ded504624ed9c069695d05e",
        "raw_response": "e11c32187baac8985219c3c423763e1c7644e73a5bdef6d8c3c9a6830346312b",
        "outcome": "d281464d2c182aed642e7ecb9fc99ab1b64c61c49913847d9199bef1d611c551",
    },
    "cohere": {
        "intent": "51b5c66551328aa09fa5289b2ee4d5c9167ac754e4b9fe4a47f3d1a90a5dbd58",
        "raw_response": "06c618c26c28583a54e92e764ae3df5de301ab1d788ce2150bba91ac008e251c",
        "outcome": "4be7398c926aa0e9f02d9eb3e01800d731a38037f304df2cc2c769ae963f30dc",
    },
    "qwen": {
        "intent": "e0bcc73206d8c05f48e20d66378dcdb8d7b98783969a3d69d5a966b2a265a098",
        "raw_response": "ca89ae699c5de0040969268a9b677f096c947360de979550fb278331ffc16d5c",
        "outcome": "7821b18ef64c7198c3b250474f60b8f0106e4d562fd799b0692cba01a56bbb8a",
    },
    "deepseek": {
        "intent": "fc31ab5898d2c8008bbc19edb4f11dc2fcb2ce2863feafe0e7d6b167aa451315",
        "raw_response": "8d49f2e665769d97dcd8c8a80cfd92fdcfceaa9ee3707729cfd67c741fa7df32",
        "outcome": "21de2fface3da50a09adeca2dd46bdf632e6af4f85fdd6c242503661ea4dff5d",
    },
    "mistral": {
        "intent": "278c8526117af3210cb47a4f96acfbb5367458603462c07244a037e0883f1089",
        "raw_response": "936ca8e9b24224a63e12c6f1d4607d5abac6732b19996a6e2087146ce39beaea",
        "outcome": "b31edb16b4f1c8c0f5405106794706b3e4651e23d83eae71741b21704b7a6ede",
    },
    "grok": {
        "intent": "dc976f881a4f5a299709f4ed03ff738975adbdebea988d86ca753afef1762d13",
        "raw_response": "a87459f0027759c9b971b584e1254ec577ea90021af8f0067895d644a63c7604",
        "outcome": "97f6e944760e8ca9cfbd40823559f762b9430086cc6a83e77a0969d706292e69",
    },
    "gpt": {
        "intent": "5b29ef296beed0db81179bd8aa1c7d927c36b24ff95987fc7ec373b15a084327",
        "raw_response": "af4a164370720295248bfc5ade7ab1a04f7c5cec06d532689f62698ceb9c7162",
        "outcome": "6b916ccc2be81316ee0466545a6063f0832538424882c713cf0219ffdbf939d0",
    },
}

APPROVAL_STATEMENT = (
    "I approve option 2 and authorize the offline preflight correction followed "
    "by the eight generation calls."
)
APPROVAL_STATEMENT_SHA256 = (
    "2e0d22554b2e092a3ed2deb2c749c6371964e56d14c29df5c739bf9aee095ac6"
)

# Every imported source that can affect correction, authority, request
# construction, durable capture, response validation, or review loading is
# committed into the continuation lock.
EXECUTION_SOURCE_PATHS = (
    "harness/divergence_successor_continuation/__init__.py",
    "harness/divergence_successor_continuation/contract.py",
    "harness/divergence_successor_continuation/state.py",
    "harness/divergence_successor_continuation/correction.py",
    "harness/divergence_successor_continuation/lock.py",
    "harness/divergence_successor_continuation/authorization.py",
    "harness/divergence_successor_continuation/execute.py",
    "harness/divergence_successor_continuation/transport.py",
    "harness/divergence_successor_continuation/composite.py",
    "harness/divergence_successor_continuation/review.py",
    "harness/divergence_successor/contract.py",
    "harness/divergence_successor/parent.py",
    "harness/divergence_successor/state.py",
    "harness/divergence_successor/lock.py",
    "harness/divergence_successor/authorization.py",
    "harness/divergence_successor/execute.py",
    "harness/divergence_successor/engine.py",
    "harness/divergence_successor/review.py",
    "harness/divergence_successor/review_assets/review.css",
    "harness/divergence_successor/review_assets/review.js",
    "harness/concordance_harness/config.py",
    "harness/concordance_harness/planner.py",
    "harness/concordance_harness/providers.py",
    "harness/concordance_harness/execution.py",
    "harness/concordance_harness/util.py",
    "harness/concordance_recovery/journal.py",
    "harness/concordance_recovery/transport.py",
    "harness/rule3/budget.py",
    "harness/private_directory_publication.py",
    "harness/run_divergence_successor_continuation.py",
    "harness/record_divergence_successor_correction.py",
    "harness/create_divergence_successor_continuation_lock.py",
    "harness/authorize_divergence_successor_continuation.py",
    "harness/prepare_divergence_successor_continuation_review.py",
)


class ContinuationContractError(RuntimeError):
    """The append-only continuation contract is incomplete or changed."""


def repository_root(value: Path | str) -> Path:
    """Resolve a repository root through the frozen parent's strict helper."""

    try:
        return parent_contract.repository_root(value)
    except parent_contract.ContractError as error:
        raise ContinuationContractError(str(error)) from error


def require_approval(statement: str | None = None) -> str:
    if parent_contract.sha256_bytes(APPROVAL_STATEMENT.encode("utf-8")) != (
        APPROVAL_STATEMENT_SHA256
    ):
        raise ContinuationContractError("the exact option-2 approval hash changed")
    if statement is not None and statement != APPROVAL_STATEMENT:
        raise ContinuationContractError("the exact option-2 approval is required")
    return APPROVAL_STATEMENT


__all__ = (
    "APPROVAL_STATEMENT",
    "APPROVAL_STATEMENT_SHA256",
    "CANDIDATE_ID",
    "ContinuationContractError",
    "EXECUTION_SOURCE_PATHS",
    "LOCK_PATH",
    "LOCK_SCHEMA_PATH",
    "MODEL_KEYS",
    "ORIGINAL_LOCK_PATH",
    "ORIGINAL_LOCK_SHA256",
    "ORIGINAL_PRIVATE_ROOT",
    "OUTPUT_TOKEN_CAP",
    "POOL_ID",
    "PRIVATE_ROOT_RELATIVE",
    "require_approval",
    "repository_root",
)
