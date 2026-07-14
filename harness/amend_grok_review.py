#!/usr/bin/env python3
"""Publish the approved four-item Galatians local-handle correction."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from private_directory_publication import (
    PrivateDirectoryPublicationError,
    PublicationSpec,
    publish_private_directory,
)


ROOT = Path(__file__).resolve().parent.parent
BASE = ROOT / ".pilot/grok-retry/grok-xai-403-retry-1"
CANDIDATE = BASE / "candidates/galatians-pistis-christou"
OUTPUT = ROOT / ".pilot/grok-review-amendment/galatians-local-handle-correction-1"
POOL_ID = "concordance-divergence-supplement-1"
CANDIDATE_ID = "galatians-pistis-christou"
FALLBACK_ID = "quantum-measurement-realist-strategies"
APPROVAL = "Yes, I approve. And please ensure that this same error did not occur in other items as well."

BASE_HASHES = {
    "blind_packet": (
        CANDIDATE / "blind/packet.json",
        "68cc924f5856c46317d4060139e358dcdf1447f3c03874c6cefcbf8b27fa241b",
    ),
    "private_crosswalk": (
        CANDIDATE / "blind/crosswalk.json",
        "d8034172f4db3da3aff7bc0ee78c5c4677f7242fda70a2dd4d75be4e0b43e78a",
    ),
    "first_pass_mapping": (
        CANDIDATE / "first-pass/mapping.json",
        "68eb60767c7d46b8b91574a6b009452170db799393442f74f1e167c38b977856",
    ),
    "first_pass_receipt": (
        CANDIDATE / "first-pass/receipt.json",
        "56ed1c10495f48daaf2217269b501a11ec5bb8c53ce68465939292bfa4cade9d",
    ),
    "author_packet_manifest": (
        CANDIDATE / "author-packet/manifest.json",
        "593196b6ccc84f21890623aa6e053925e05de2cb52311bef458d02be9dda9959",
    ),
    "author_review": (
        CANDIDATE / "author-review/review.json",
        "d0c3c3ff91caef07edde076b1adffb50f398461c743b2ac5f75a290c6bb54e35",
    ),
    "author_review_receipt": (
        CANDIDATE / "author-review/receipt.json",
        "eafd414e145d23b6f3025aa5b7628d79411db937ee648374b7990dcb2c9f6c27",
    ),
    "base_evaluation": (
        CANDIDATE / "evaluation/receipt.json",
        "2e9691a748aa80e3f620f39b044822f270197e0c2cf8710b894ce43fb4336a02",
    ),
}

RULE2_BINDINGS = {
    "first_pass": (
        ROOT / ".pilot/aggregates/rule2-pilot-1/mapping-batches-1/first-pass.json",
        "9926c2c58eb37f9dba6b34bbc1cb22d66b1a1fd4d4fa4cbffc0882800cf22f63",
    ),
    "active_amendment": (
        ROOT / ".pilot/aggregates/rule2-pilot-1/author-review-2/amendment.json",
        "e77fb63d80c9988c0f6cc63d54876ba2d93383e6be5c80ba818f88bcf5eae5c3",
    ),
    "active_review": (
        ROOT
        / ".pilot/aggregates/rule2-pilot-1/author-review-2/sealed-primary-review/review.json",
        "d22193ecc5ec589cc081ca497c5bedcc2353b6ea640affa1b652c2d2bfa01728",
    ),
    "active_selection": (
        ROOT / ".pilot/aggregates/rule2-pilot-1/selection-rule2-2.json",
        "7a2b1587ebd0daa160870a2948482c3fc17f122829c1311cacb778f49427de13",
    ),
}
RULE2_TABLE_SHA256 = "8d61d76a6dd7b22a1dbf98f753d6f0a7a1c74f0858cc0578d593a83e89610791"
RULE2_RESOLVED_BLIND_ID = "blind-ac30c39602d53eaa198433fe611f57e0"

ITEMS = (
    (
        "B-D87EE0D12EA2CEF55D7B811C422CDA1F",
        "018a92e4160d6d6912fad16ec8a5bc9cef8e944f08c6a228fd6707cce2fae743",
        "Christ's own faith or faithfulness",
        "christs-own-faithfulness",
        "P4",
        "P4",
    ),
    (
        "B-22A61D6416C9CAAD9E3126E5A3C12A82",
        "5b38f93851647ff09f6b7df4650bca0ecf43cc28e7fc9071a197bdd87a8d9338",
        "Believers' faith in Christ",
        "believers-faith-in-christ",
        "P1",
        "P2",
    ),
    (
        "B-088482D22ADDD9E57899817F778472D2",
        "649eec6c7e80438d189c31f434b63d51da1ff514e28bae4ab959805580fa4ba5",
        "Believers' faith in Christ",
        "believers-faith-in-christ",
        "P1",
        "P2",
    ),
    (
        "B-242BB2E4515BBA8CB73623E333B7087F",
        "1570b742209c75e18da16b593164acad85210dc8633a9baceab3bd98b7e278a6",
        "Believers' faith in Christ",
        "believers-faith-in-christ",
        "P1",
        "P1",
    ),
    (
        "B-CED4707A504126DE2388734FB074F3E0",
        "e28a4290cd45152287bc415368cbefff4e6dca9e33d429a86fabd37c8b68de0e",
        "Christ's own faith or faithfulness",
        "christs-own-faithfulness",
        "P4",
        "P4",
    ),
    (
        "B-0ED94474A8E9F0F98D3A82031884AA48",
        "44a75e1314cec96aa1c1d60fe9cdb5ae981e71198541246dcf548e7929a295dc",
        "Christ's own faith or faithfulness",
        "christs-own-faithfulness",
        "P4",
        "P2",
    ),
    (
        "B-968585869FF2FD0FCC8728ADA222E457",
        "ed9f71cf839d90cc54b0a53282c99e546d7bea79d9a05ae3ed4926f74386ded2",
        "Christ's own faith or faithfulness",
        "christs-own-faithfulness",
        "P4",
        "P3",
    ),
    (
        "B-6F23B2153EC1C55940A95FEA5DFFE081",
        "22d6179530dbee4b26fd41f9e50e8db4a7fe291366c42f810db069e0cc788f74",
        "Believers' faith in Christ",
        "believers-faith-in-christ",
        "P1",
        "P1",
    ),
)

SOURCE_PATHS = (
    "candidate/GALATIANS_REVIEW_AMENDMENT.md",
    "harness/amend_grok_review.py",
    "harness/private_directory_publication.py",
)
EXPECTED_FILES = (
    "amendment.json",
    "fallback-eligibility.json",
    "rule2-local-handle-audit.json",
    "superseding-evaluation.json",
)


class AmendmentError(RuntimeError):
    pass


def canonical(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def file_sha(path: Path) -> str:
    return sha(path.read_bytes())


def read_object(path: Path, expected_sha: str, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or file_sha(path) != expected_sha:
        raise AmendmentError(f"{label} differs from the approved immutable artifact")
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AmendmentError(f"{label} is malformed: {error}") from error
    if not isinstance(value, dict):
        raise AmendmentError(f"{label} must be an object")
    return value


def git(args: list[str]) -> bytes:
    result = subprocess.run(
        ["/usr/bin/git", *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": "/var/empty",
            "LANG": "C",
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
        },
    )
    if result.returncode:
        raise AmendmentError(
            result.stderr.decode(errors="replace").strip() or "git failed"
        )
    return result.stdout


def source_bindings(execution_commit: str, *, require_current: bool) -> dict[str, str]:
    if require_current:
        head = git(["rev-parse", "HEAD"]).decode().strip()
        if (
            head != execution_commit
            or git(["status", "--porcelain", "--untracked-files=no"]).strip()
        ):
            raise AmendmentError(
                "amendment sources must be committed and tracked-clean"
            )
    git(["cat-file", "-e", f"{execution_commit}^{{commit}}"])
    bindings: dict[str, str] = {}
    for relative in SOURCE_PATHS:
        payload = (ROOT / relative).read_bytes()
        if git(["show", f"{execution_commit}:{relative}"]) != payload:
            raise AmendmentError(
                f"{relative} differs from the amendment execution commit"
            )
        bindings[relative] = sha(payload)
    return bindings


def threshold(primaries: list[str]) -> dict[str, Any]:
    counts = Counter(primaries)
    failures = []
    if len(primaries) < 6:
        failures.append("fewer-than-six-non-null-primary-endorsements")
    if len(counts) < 3:
        failures.append("fewer-than-three-represented-positions")
    if max(counts.values(), default=0) > 4:
        failures.append("one-position-has-more-than-four-primary-endorsements")
    return {
        "evidence_complete": True,
        "author_review_complete": True,
        "qualifies": not failures,
        "non_null_primary_count": len(primaries),
        "represented_position_count": len(counts),
        "maximum_position_primary_count": max(counts.values(), default=0),
        "failure_reasons": failures,
    }


def rule2_audit() -> dict[str, Any]:
    for label, (path, digest) in RULE2_BINDINGS.items():
        read_object(path, digest, f"Rule 2 {label}")
    rows = []
    batches = ROOT / ".pilot/aggregates/rule2-pilot-1/mapping-batches-1/batches"
    for mapping_path in sorted(batches.glob("batch-*/mapping.json")):
        mapping = json.loads(mapping_path.read_bytes())
        for assignment in mapping["assignments"]:
            item_path = (
                mapping_path.parent / "items" / f"{assignment['blind_item_id']}.json"
            )
            item = json.loads(item_path.read_bytes())
            positions = {position["handle"]: position for position in item["positions"]}
            handle = assignment["primary_endorsed"]
            rows.append(
                {
                    "blind_item_id": assignment["blind_item_id"],
                    "mapping_sha256": file_sha(mapping_path),
                    "item_sha256": file_sha(item_path),
                    "assignment": assignment,
                    "selected_position": None if handle is None else positions[handle],
                }
            )
    rows.sort(key=lambda item: item["blind_item_id"])
    table_sha = sha(
        (
            json.dumps(rows, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode()
    )
    if len(rows) != 64 or table_sha != RULE2_TABLE_SHA256:
        raise AmendmentError("Rule 2 semantic-audit table changed")
    selection = read_object(
        *RULE2_BINDINGS["active_selection"], "Rule 2 active selection"
    )
    target = [
        item
        for item in selection["unblinded_reviewed_assignments"]
        if item["blind_item_id"] == RULE2_RESOLVED_BLIND_ID
    ]
    if (
        len(target) != 1
        or target[0]["reviewed_primary_handle"] is not None
        or target[0]["reviewed_primary_reason_code"] != "outside_map"
    ):
        raise AmendmentError("Rule 2's one prior semantic exception is not resolved")
    return {
        "schema_version": "concordance-rule2-local-handle-audit-1.0.0",
        "status": "complete-no-unresolved-local-handle-errors",
        "item_count": 64,
        "manually_aligned_count": 63,
        "previously_resolved_count": 1,
        "unresolved_count": 0,
        "manual_semantic_table_sha256": table_sha,
        "resolved_item": {
            "blind_item_id": RULE2_RESOLVED_BLIND_ID,
            "active_primary": None,
            "active_reason": "outside_map",
        },
        "bindings": {
            label: {"path": str(path.relative_to(ROOT)), "sha256": digest}
            for label, (path, digest) in RULE2_BINDINGS.items()
        },
    }


def base_context() -> dict[str, Any]:
    values = {
        label: read_object(path, digest, label)
        for label, (path, digest) in BASE_HASHES.items()
    }
    packet_items = values["blind_packet"]["items"]
    first_items = values["first_pass_mapping"]["assignments"]
    decisions = values["author_review"]["decisions"]
    lineage = values["base_evaluation"]["reviewed_lineage"]
    if not all(
        len(items) == 8 for items in (packet_items, first_items, decisions, lineage)
    ):
        raise AmendmentError("Galatians review lineage is not exactly eight items")
    audit = []
    corrected_lineage = []
    corrected_primaries = []
    for index, expected in enumerate(ITEMS):
        blind_id, response_sha, label, canonical_id, old_handle, new_handle = expected
        packet, first, decision, old_lineage = (
            packet_items[index],
            first_items[index],
            decisions[index],
            lineage[index],
        )
        local = {
            position["handle"]: position["label"] for position in packet["position_map"]
        }
        if (
            packet["blind_id"] != blind_id
            or packet["response_sha256"] != response_sha
            or first["blind_id"] != blind_id
            or first["primary_position_handle"] != old_handle
            or decision["blind_id"] != blind_id
            or decision["decision"] != "confirm"
            or decision["reviewed_primary_position_handle"] != old_handle
            or local.get(new_handle) != label
        ):
            raise AmendmentError(
                f"approved correction lineage changed for response {index + 1}"
            )
        changed = old_handle != new_handle
        audit.append(
            {
                "response_number": index + 1,
                "blind_id": blind_id,
                "response_sha256": response_sha,
                "semantic_primary": label,
                "canonical_position_id": canonical_id,
                "old_local_handle": old_handle,
                "corrected_local_handle": new_handle,
                "action": "correct" if changed else "preserve",
            }
        )
        revised = dict(old_lineage)
        revised["reviewed_primary_position_id"] = canonical_id
        corrected_lineage.append(revised)
        corrected_primaries.append(canonical_id)
    if sum(item["action"] == "correct" for item in audit) != 4:
        raise AmendmentError("the approved amendment must change exactly four items")
    return {
        "values": values,
        "audit": audit,
        "lineage": corrected_lineage,
        "primaries": corrected_primaries,
    }


def payloads(
    created_at: str, execution_commit: str, *, require_current: bool
) -> dict[str, bytes]:
    context = base_context()
    rule2 = rule2_audit()
    sources = source_bindings(execution_commit, require_current=require_current)
    counts = Counter(context["primaries"])
    corrected_threshold = threshold(context["primaries"])
    if corrected_threshold != {
        "evidence_complete": True,
        "author_review_complete": True,
        "qualifies": False,
        "non_null_primary_count": 8,
        "represented_position_count": 2,
        "maximum_position_primary_count": 4,
        "failure_reasons": ["fewer-than-three-represented-positions"],
    }:
        raise AmendmentError(
            "corrected Galatians threshold differs from the approved result"
        )
    contract_value = {
        "candidate_id": CANDIDATE_ID,
        "approval_statement": APPROVAL,
        "corrections": context["audit"],
        "threshold_contract": context["values"]["base_evaluation"][
            "threshold_contract"
        ],
    }
    contract_sha = sha(canonical(contract_value))
    evaluation = {
        "schema_version": "rule3-evaluation-amendment-1.0.0",
        "status": "superseding-reviewed-threshold-evaluation",
        "created_at": created_at,
        "pool_id": POOL_ID,
        "candidate_id": CANDIDATE_ID,
        "candidate_role": "priority",
        "correction_contract_sha256": contract_sha,
        "supersedes": {
            "path": str(BASE_HASHES["base_evaluation"][0].relative_to(ROOT)),
            "sha256": BASE_HASHES["base_evaluation"][1],
            "historical_artifact_preserved": True,
            "invalid_for_selection": True,
        },
        "reviewed_lineage": context["lineage"],
        "position_primary_counts": {
            key: counts.get(key, 0)
            for key in context["values"]["base_evaluation"]["position_primary_counts"]
        },
        "threshold_contract": context["values"]["base_evaluation"][
            "threshold_contract"
        ],
        "threshold_result": corrected_threshold,
        "offline_attestation": {
            "network_requests": 0,
            "environment_variables_read": 0,
            "model_calls": 0,
        },
    }
    evaluation_payload = canonical(evaluation)
    fallback = {
        "schema_version": "rule3-fallback-eligibility-amendment-1.0.0",
        "status": "fallback-eligible-after-superseding-reviewed-priority-failure",
        "created_at": created_at,
        "pool_id": POOL_ID,
        "priority_candidate_id": CANDIDATE_ID,
        "fallback_candidate_id": FALLBACK_ID,
        "correction_contract_sha256": contract_sha,
        "superseding_evaluation": {
            "path": "superseding-evaluation.json",
            "sha256": sha(evaluation_payload),
        },
        "threshold_result": corrected_threshold,
    }
    rule2_payload = canonical(rule2)
    fallback_payload = canonical(fallback)
    amendment = {
        "schema_version": "rule3-author-review-amendment-1.0.0",
        "status": "approved-four-item-local-handle-correction",
        "created_at": created_at,
        "execution_commit": execution_commit,
        "execution_sources": sources,
        "pool_id": POOL_ID,
        "candidate_id": CANDIDATE_ID,
        "approval_statement": APPROVAL,
        "diagnosis": "Response-local handles were incorrectly treated as globally stable during recommendation preparation.",
        "correction_contract": contract_value,
        "correction_contract_sha256": contract_sha,
        "base_bindings": {
            label: {"path": str(path.relative_to(ROOT)), "sha256": digest}
            for label, (path, digest) in BASE_HASHES.items()
        },
        "rule2_audit": {
            "path": "rule2-local-handle-audit.json",
            "sha256": sha(rule2_payload),
        },
        "superseding_evaluation": {
            "path": "superseding-evaluation.json",
            "sha256": sha(evaluation_payload),
        },
        "fallback_eligibility": {
            "path": "fallback-eligibility.json",
            "sha256": sha(fallback_payload),
        },
        "historical_artifacts_preserved": True,
        "network_requests": 0,
        "environment_variables_read": 0,
        "model_calls": 0,
    }
    return {
        "amendment.json": canonical(amendment),
        "fallback-eligibility.json": fallback_payload,
        "rule2-local-handle-audit.json": rule2_payload,
        "superseding-evaluation.json": evaluation_payload,
    }


def verify_output() -> dict[str, Any]:
    if (
        OUTPUT.is_symlink()
        or not OUTPUT.is_dir()
        or stat.S_IMODE(OUTPUT.stat().st_mode) != 0o700
    ):
        raise AmendmentError("amendment output must be a mode-0700 real directory")
    actual = {item.name for item in OUTPUT.iterdir()}
    if actual != set(EXPECTED_FILES):
        raise AmendmentError("amendment output inventory changed")
    amendment = json.loads((OUTPUT / "amendment.json").read_bytes())
    created_at = amendment.get("created_at")
    execution_commit = amendment.get("execution_commit")
    if not isinstance(created_at, str) or not isinstance(execution_commit, str):
        raise AmendmentError("amendment identity is malformed")
    expected = payloads(created_at, execution_commit, require_current=False)
    for name, value in expected.items():
        path = OUTPUT / name
        if (
            path.is_symlink()
            or not path.is_file()
            or stat.S_IMODE(path.stat().st_mode) != 0o600
            or path.read_bytes() != value
        ):
            raise AmendmentError(f"{name} differs from the approved amendment")
    evaluation = json.loads(expected["superseding-evaluation.json"])
    return {
        "status": "verified-superseding-priority-failure",
        "threshold_result": evaluation["threshold_result"],
        "output_sha256": {name: sha(value) for name, value in expected.items()},
    }


def write_output() -> dict[str, Any]:
    if OUTPUT.exists():
        return verify_output()
    execution_commit = git(["rev-parse", "HEAD"]).decode().strip()
    created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    values = payloads(created_at, execution_commit, require_current=True)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(OUTPUT.parent, 0o700)
    spec = PublicationSpec(
        target_root=OUTPUT,
        claim_path=OUTPUT.parent / ".galatians-local-handle-correction-1.publish-claim",
        staging_parent=OUTPUT.parent,
        claim_schema_version="galatians-review-amendment-publication-1.0.0",
        owner_schema_version="galatians-review-amendment-owner-1.0.0",
        expected_files=EXPECTED_FILES,
    )
    publish_private_directory(spec, values, lambda _: verify_output())
    return verify_output()


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    try:
        if args.check:
            commit = git(["rev-parse", "HEAD"]).decode().strip()
            values = payloads("2026-07-14T00:00:00Z", commit, require_current=False)
            evaluation = json.loads(values["superseding-evaluation.json"])
            result = {
                "status": "ready",
                "correction_count": 4,
                "galatians_item_count": 8,
                "rule2_item_count": 64,
                "rule2_unresolved_count": 0,
                "threshold_result": evaluation["threshold_result"],
            }
        elif args.write:
            result = write_output()
        else:
            result = verify_output()
        print(json.dumps(result, indent=2))
        return 0
    except (
        AmendmentError,
        OSError,
        ValueError,
        KeyError,
        PrivateDirectoryPublicationError,
    ) as error:
        print(f"Galatians review amendment stopped: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
