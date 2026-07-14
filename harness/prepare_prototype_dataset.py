#!/usr/bin/env python3
"""Project the three approved real cases into an offline candidate dataset."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

import validate_frontier_ai_prototype_inclusion as inclusion_policy


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / ".pilot/prototype-data"
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
SELECTED_IDS = ("junia-romans-16-7", "john-brown-harpers-ferry")
FRONTIER_ID = "frontier-ai-lifecycle-licensing"
DISPLAY_IDS = (SELECTED_IDS[0], FRONTIER_ID, SELECTED_IDS[1])
SUCCESSOR_MANIFEST = (
    "candidate/successors/candidate-1.1.2/manifest.json",
    "1e37ddaf47d7ac56add2be79081b545269d6c1a9f1cde331fd5dabff93600715",
)
SELECTION_RECEIPT = (
    ".pilot/aggregates/rule2-pilot-1/selection-rule2-2.json",
    "7a2b1587ebd0daa160870a2948482c3fc17f122829c1311cacb778f49427de13",
)
FRONTIER_QUESTION = (
    "candidate/rule3-successor/questions/frontier-ai-lifecycle-licensing.json",
    "8c8c066e625b50d441f998e3c316a6e293bbed7dffea5aa47c87f77257b91eb5",
)
CONTINUATION_ROOT = Path(
    ".pilot/divergence-successor-continuation/frontier-ai-preflight-correction-1"
)
FRONTIER_COMPOSITE = (
    str(CONTINUATION_ROOT / "runs/frontier-ai-lifecycle-licensing.json"),
    "cf485da16667638b82e00c3d091d2c04eac9e061a9c37761a7314851bed3fc63",
)
FRONTIER_EVALUATION = (
    ".pilot/divergence-successor-continuation-author-review/"
    "frontier-ai-preflight-correction-1/candidates/"
    "frontier-ai-lifecycle-licensing/evaluation-v2/receipt.json",
    "c6b384d8bbeb9934d38e05bc1a353ad53ac63f33be162f67f1a3425be4cc19a4",
)
VERIFIED = {
    "status": "author-verified",
    "verified_by": "A.G. Elrod",
    "verified_at": "2026-07-14T17:07:28.300Z",
}
EXPECTED_OUTPUT_FILES = {
    "index.json",
    "manifests/models.json",
    *(f"questions/{question_id}.json" for question_id in DISPLAY_IDS),
    *(f"runs/{question_id}.json" for question_id in DISPLAY_IDS),
    *(f"mappings/{question_id}.json" for question_id in DISPLAY_IDS),
}
EXPECTED_OUTPUT_DIRECTORIES = {"manifests", "questions", "runs", "mappings"}


class PrototypeDatasetError(ValueError):
    """A sealed source or projected dataset invariant failed."""


def _validate_destination(root: Path, requested: Path) -> Path:
    if requested.is_symlink():
        raise PrototypeDatasetError("prototype output cannot be a symbolic link")
    destination = requested.resolve()
    private_root = root / ".pilot"
    if destination == root or (
        root in destination.parents
        and destination != private_root
        and private_root not in destination.parents
    ):
        raise PrototypeDatasetError(
            "repository-local prototype output must stay under .pilot/"
        )
    if destination == private_root:
        raise PrototypeDatasetError("prototype output cannot replace .pilot/")
    if not destination.exists():
        return destination
    if not destination.is_dir():
        raise PrototypeDatasetError("prototype output must be a directory")
    entries = list(destination.rglob("*"))
    if any(entry.is_symlink() for entry in entries):
        raise PrototypeDatasetError(
            "existing prototype output contains a symbolic link"
        )
    files = {
        entry.relative_to(destination).as_posix()
        for entry in entries
        if entry.is_file()
    }
    directories = {
        entry.relative_to(destination).as_posix() for entry in entries if entry.is_dir()
    }
    if files != EXPECTED_OUTPUT_FILES or directories != EXPECTED_OUTPUT_DIRECTORIES:
        raise PrototypeDatasetError(
            "refusing to replace a directory that is not the generated prototype dataset"
        )
    try:
        index = json.loads((destination / "index.json").read_bytes())
    except (OSError, json.JSONDecodeError) as error:
        raise PrototypeDatasetError("existing prototype index is invalid") from error
    expected_records = [
        {
            "question": f"questions/{question_id}.json",
            "run": f"runs/{question_id}.json",
            "mapping": f"mappings/{question_id}.json",
        }
        for question_id in DISPLAY_IDS
    ]
    actual_records = index.get("questions") if isinstance(index, dict) else None
    records_match = isinstance(actual_records, list) and all(
        isinstance(record, dict) for record in actual_records
    )
    if records_match:
        records_match = {
            (record.get("question"), record.get("run"), record.get("mapping"))
            for record in actual_records
        } == {
            (record["question"], record["run"], record["mapping"])
            for record in expected_records
        }
    if (
        not isinstance(index, dict)
        or index.get("dataset_id") != "concordance-prototype-real-data"
        or index.get("mode") != "candidate"
        or index.get("model_manifest") != "manifests/models.json"
        or not records_match
    ):
        raise PrototypeDatasetError("existing prototype index identity differs")
    return destination


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _load(root: Path, relative: str, expected_sha: str) -> dict[str, Any]:
    path = root / relative
    payload = path.read_bytes()
    if _sha(payload) != expected_sha:
        raise PrototypeDatasetError(f"sealed source changed: {relative}")
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as error:
        raise PrototypeDatasetError(
            f"sealed source is invalid JSON: {relative}"
        ) from error
    if not isinstance(value, dict):
        raise PrototypeDatasetError(f"sealed source is not an object: {relative}")
    return value


def _artifact_bindings(selection: dict[str, Any]) -> dict[str, str]:
    records = selection.get("run_input_artifacts")
    if not isinstance(records, list):
        raise PrototypeDatasetError("selection run bindings are missing")
    bindings = {
        record["path"]: record["sha256"]
        for record in records
        if isinstance(record, dict)
        and isinstance(record.get("path"), str)
        and isinstance(record.get("sha256"), str)
    }
    if len(bindings) != len(records):
        raise PrototypeDatasetError("selection run bindings are malformed")
    return bindings


def _load_artifact(
    root: Path, bindings: dict[str, str], relative: str
) -> dict[str, Any]:
    expected = bindings.get(relative)
    if expected is None:
        raise PrototypeDatasetError(
            f"source is absent from sealed selection: {relative}"
        )
    return _load(root, relative, expected)


def _questions(root: Path) -> dict[str, dict[str, Any]]:
    manifest = _load(root, *SUCCESSOR_MANIFEST)
    records = manifest.get("questions")
    if manifest.get("content_version") != "candidate-1.1.2" or not isinstance(
        records, list
    ):
        raise PrototypeDatasetError("author-verified successor manifest differs")
    questions: dict[str, dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict) or record.get("id") not in SELECTED_IDS:
            raise PrototypeDatasetError("successor question index differs")
        binding = record.get("successor")
        if not isinstance(binding, dict):
            raise PrototypeDatasetError("successor question binding is malformed")
        question = _load(root, binding["path"], binding["sha256"])
        if (
            question.get("id") != record["id"]
            or question.get("verification", {}).get("status") != "author-verified"
        ):
            raise PrototypeDatasetError("successor question is not author-verified")
        questions[record["id"]] = question
    if set(questions) != set(SELECTED_IDS):
        raise PrototypeDatasetError("successor questions are incomplete")
    return questions


def _manifest(
    root: Path,
    bindings: dict[str, str],
    captured_at: str,
) -> dict[str, Any]:
    parent_path = ".pilot/stages/without-mistral/manifests/models.json"
    mistral_path = ".pilot/stages/mistral-completion/manifests/models.json"
    parent = _load_artifact(root, bindings, parent_path)
    mistral = _load_artifact(root, bindings, mistral_path)
    models = [*parent.get("models", []), *mistral.get("models", [])]
    by_key = {
        model.get("model_key"): model for model in models if isinstance(model, dict)
    }
    if set(by_key) != set(MODEL_ORDER):
        raise PrototypeDatasetError("sealed model snapshots do not form the panel")
    if parent.get("config_sha256") != mistral.get("config_sha256"):
        raise PrototypeDatasetError("model source configurations differ")
    return {
        "schema_version": "1.0.0",
        "manifest_id": "concordance-prototype-eight-model-panel",
        "captured_at": captured_at,
        "harness_version": "prototype-assembler-1",
        "config_sha256": parent["config_sha256"],
        "data_class": "research",
        "models": [copy.deepcopy(by_key[key]) for key in MODEL_ORDER],
    }


def _selected_cells(
    root: Path,
    bindings: dict[str, str],
    question_id: str,
) -> list[dict[str, Any]]:
    parent_path = f".pilot/stages/without-mistral/runs/{question_id}.json"
    mistral_path = f".pilot/stages/mistral-completion/runs/{question_id}.json"
    parent = _load_artifact(root, bindings, parent_path)
    mistral = _load_artifact(root, bindings, mistral_path)
    cells = {
        cell["cell_id"]: copy.deepcopy(cell)
        for cell in parent.get("cells", [])
        if isinstance(cell, dict)
    }
    for relative in sorted(bindings):
        if not relative.startswith(
            ".pilot/repairs/gpt-alias-deepseek-network-1/outcomes/"
        ):
            continue
        outcome = _load_artifact(root, bindings, relative)
        cell = outcome.get("cell")
        if isinstance(cell, dict) and cell.get("question_id") == question_id:
            if cell.get("cell_id") not in cells or cell.get("status") != "success":
                raise PrototypeDatasetError("repair does not replace a planned cell")
            cells[cell["cell_id"]] = copy.deepcopy(cell)
    for cell in mistral.get("cells", []):
        if not isinstance(cell, dict) or cell.get("cell_id") in cells:
            raise PrototypeDatasetError("Mistral completion cell differs")
        cells[cell["cell_id"]] = copy.deepcopy(cell)
    variant_order = (
        {"default": 0}
        if question_id == "junia-romans-16-7"
        else {"slavery-and-resistance-frame": 0, "methods-and-violence-frame": 1}
    )
    ordered = sorted(
        cells.values(),
        key=lambda cell: (
            variant_order.get(cell.get("variant_id"), 99),
            MODEL_ORDER.index(cell.get("model_key")),
        ),
    )
    expected = 8 if question_id == "junia-romans-16-7" else 16
    if len(ordered) != expected or any(
        cell.get("status") != "success" or cell.get("call_type") != "answer"
        for cell in ordered
    ):
        raise PrototypeDatasetError(f"{question_id} lacks its answer-only panel")
    return ordered


def _frontier_question(root: Path) -> dict[str, Any]:
    question = copy.deepcopy(_load(root, *FRONTIER_QUESTION))
    original_prompt = copy.deepcopy(question["prompt_variants"])
    original_map = copy.deepcopy(question["position_map"])
    question["content_version"] = "prototype-post-result-1.0.0"
    question["context_note"] = (
        "The map distinguishes licensing before training, licensing before broad "
        "deployment or release, binding frontier supervision without a licensing "
        "gate, and use-centered or generally applicable law. Full classification "
        "rules remain in the frozen source record."
    )
    question["what_this_shows"] = [
        "How eight sampled model answers divide 5-3 between two primary legal architectures.",
        "How bimodal disagreement appears when a stricter multipolar threshold is unmet.",
    ]
    question["what_this_does_not_show"] = [
        "The best legal regime, public or expert prevalence, a validated measure, enacted law, production readiness, or legal advice."
    ]
    question["selection"] = {
        "status": "selected",
        "pool_id": "frontier-ai-preflight-correction-1",
        "pool_size": 1,
        "rule_version": "post-result-prototype-inclusion-1",
        "candidate_role": "replacement",
        "disclosure": (
            "Selected for prototype display under a post-result bimodal-divergence "
            "policy after the sealed 5-3 result failed the precommitted multipolar "
            "Rule 3 threshold. The original Rule 3 failure remains preserved. This "
            "prototype classification supports no prevalence, validated-measurement, "
            "or production-readiness claim."
        ),
    }
    if (
        question["prompt_variants"] != original_prompt
        or question["position_map"] != original_map
    ):
        raise PrototypeDatasetError("frontier prompt or position map changed")
    return question


def _frontier_cells(root: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    composite = _load(root, *FRONTIER_COMPOSITE)
    evaluation = _load(root, *FRONTIER_EVALUATION)
    outcomes = composite.get("outcomes")
    if (
        composite.get("successful_outcome_count") != 8
        or composite.get("failed_model_keys") != []
        or not isinstance(outcomes, list)
    ):
        raise PrototypeDatasetError("frontier composite is incomplete")
    cells: list[dict[str, Any]] = []
    outcome_by_path: dict[str, dict[str, Any]] = {}
    for binding in outcomes:
        if not isinstance(binding, dict):
            raise PrototypeDatasetError("frontier outcome binding is malformed")
        relative = str(CONTINUATION_ROOT / binding["path"])
        outcome = _load(root, relative, binding["sha256"])
        intent_binding = outcome.get("intent")
        if not isinstance(intent_binding, dict):
            raise PrototypeDatasetError("frontier intent binding is malformed")
        intent = _load(
            root,
            str(CONTINUATION_ROOT / intent_binding["path"]),
            intent_binding["sha256"],
        )
        result = outcome.get("result")
        if outcome.get("status") != "success" or not isinstance(result, dict):
            raise PrototypeDatasetError("frontier outcome is not successful")
        response_sha = result.get("response_sha256")
        response_text = result.get("response_text")
        if (
            not isinstance(response_text, str)
            or _sha(response_text.encode()) != response_sha
        ):
            raise PrototypeDatasetError("frontier response hash differs")
        cost = result.get("cost")
        if not isinstance(cost, dict):
            raise PrototypeDatasetError("frontier cost is malformed")
        cell = {
            "status": "success",
            "cell_id": outcome["cell_id"],
            "question_id": FRONTIER_ID,
            "model_key": outcome["model_key"],
            "model_family": outcome["model_family"],
            "provider": outcome["provider"],
            "requested_model_id": outcome["requested_model_id"],
            "variant_id": "default",
            "call_type": "answer",
            "parent_response_id": None,
            "messages": copy.deepcopy(intent["messages"]),
            "prompt_sha256": outcome["prompt_sha256"],
            "requested_params": copy.deepcopy(intent["requested_params"]),
            "attempted_at": outcome["attempted_at"],
            "attempt_count": outcome["attempt_number"],
            "response_id": (
                f"{FRONTIER_ID}-{outcome['model_key']}-default-answer-"
                f"{response_sha[:12]}"
            ),
            "provider_returned_model_id": result["provider_returned_model_id"],
            "provider_response_id": result["provider_response_id"],
            "effective_params": copy.deepcopy(result["effective_params"]),
            "response_text": response_text,
            "generated_at": outcome["completed_at"],
            "latency_ms": outcome["latency_ms"],
            "finish_reason": result["finish_reason"],
            "usage": copy.deepcopy(result["usage"]),
            "cost": {
                "usd": cost["actual_estimate_microdollars"] / 1_000_000,
                "source": "estimated",
                "pricing_as_of": cost["pricing_checked_at"][:10],
            },
        }
        cells.append(cell)
        outcome_by_path[relative] = outcome
    cells.sort(key=lambda cell: MODEL_ORDER.index(cell["model_key"]))
    if [cell["model_key"] for cell in cells] != list(MODEL_ORDER):
        raise PrototypeDatasetError("frontier cells differ from the frozen panel")
    for item in evaluation.get("reviewed_lineage", []):
        outcome = outcome_by_path.get(item.get("outcome_path"))
        if (
            outcome is None
            or item.get("outcome_sha256") != _sha(_json_bytes(outcome))
            or item.get("response_sha256")
            != outcome.get("result", {}).get("response_sha256")
        ):
            raise PrototypeDatasetError("frontier reviewed lineage differs")
    return cells, evaluation


def _run(
    question: dict[str, Any],
    cells: list[dict[str, Any]],
    manifest: dict[str, Any],
    manifest_sha: str,
    question_sha: str,
) -> dict[str, Any]:
    generated = min(cell["attempted_at"] for cell in cells)
    updated = max(cell["generated_at"] for cell in cells)
    return {
        "schema_version": "1.0.0",
        "run_id": f"{question['id']}-prototype-answer-run",
        "run_purpose": "pilot",
        "question_id": question["id"],
        "question_content_version": question["content_version"],
        "question_file_sha256": question_sha,
        "generated_at": generated,
        "updated_at": updated,
        "harness_version": "prototype-assembler-1",
        "harness_config_sha256": manifest["config_sha256"],
        "model_manifest_file_sha256": manifest_sha,
        "model_manifest_snapshot": copy.deepcopy(manifest),
        "cells": cells,
    }


def _selected_mapping(
    question_id: str,
    cells: list[dict[str, Any]],
    selection: dict[str, Any],
    run_id: str,
    run_sha: str,
) -> dict[str, Any]:
    records = {
        item["cell_id"]: item
        for item in selection.get("unblinded_reviewed_assignments", [])
        if isinstance(item, dict) and item.get("question_id") == question_id
    }
    assignments = []
    for cell in cells:
        item = records.get(cell["cell_id"])
        if (
            item is None
            or item.get("model_key") != cell["model_key"]
            or item.get("response_sha256") != _sha(cell["response_text"].encode())
        ):
            raise PrototypeDatasetError(f"{question_id} reviewed mapping differs")
        primary = item.get("reviewed_primary_position_id")
        assignments.append(
            {
                "response_id": cell["response_id"],
                "primary_endorsed": primary,
                "also_endorsed": [],
                "mentioned": [],
                "audit_note": (
                    "Author-reviewed primary from the sealed Rule 2 record; secondary "
                    "fields are intentionally omitted in this prototype projection."
                ),
                "verification": {
                    "status": "author-verified",
                    "verified_by": "A.G. Elrod",
                    "verified_at": item["reviewed_at"]
                    if "reviewed_at" in item
                    else "2026-07-13T06:01:40.004+00:00",
                },
            }
        )
    if len(records) != len(cells):
        raise PrototypeDatasetError(f"{question_id} reviewed mapping count differs")
    return {
        "schema_version": "1.0.0",
        "mapping_version": "prototype-primary-1",
        "mapping_id": f"{question_id}-prototype-primary-mapping",
        "question_id": question_id,
        "run_id": run_id,
        "run_file_sha256": run_sha,
        "rubric_version": "mapping-rubric-1",
        "assignments": assignments,
        "verification": {
            "status": "author-verified",
            "verified_by": "A.G. Elrod",
            "verified_at": "2026-07-13T06:01:40.004+00:00",
        },
    }


def _frontier_mapping(
    cells: list[dict[str, Any]],
    evaluation: dict[str, Any],
    run_id: str,
    run_sha: str,
) -> dict[str, Any]:
    by_response_sha = {
        item["response_sha256"]: item for item in evaluation["reviewed_lineage"]
    }
    assignments = []
    for cell in cells:
        item = by_response_sha.get(_sha(cell["response_text"].encode()))
        if item is None:
            raise PrototypeDatasetError("frontier reviewed mapping is incomplete")
        assignments.append(
            {
                "response_id": cell["response_id"],
                "primary_endorsed": item["reviewed_primary_position_id"],
                "also_endorsed": [],
                "mentioned": [],
                "audit_note": (
                    "Author-reviewed primary from the sealed frontier record; "
                    "secondary fields are intentionally omitted in this prototype projection."
                ),
                "verification": {
                    "status": "author-verified",
                    "verified_by": "A.G. Elrod",
                    "verified_at": item["reviewed_at"],
                },
            }
        )
    return {
        "schema_version": "1.0.0",
        "mapping_version": "prototype-primary-1",
        "mapping_id": f"{FRONTIER_ID}-prototype-primary-mapping",
        "question_id": FRONTIER_ID,
        "run_id": run_id,
        "run_file_sha256": run_sha,
        "rubric_version": "mapping-rubric-1",
        "assignments": assignments,
        "verification": copy.deepcopy(VERIFIED),
    }


def assemble(repository_root: Path | str, output: Path | str) -> dict[str, Any]:
    """Build the deterministic candidate projection and return its file hashes."""

    root = Path(repository_root).resolve()
    destination = _validate_destination(root, Path(output).expanduser())
    if destination == root / "data" or root / "data" in destination.parents:
        raise PrototypeDatasetError("prototype assembler cannot write into data/")
    inclusion_policy.verify(root)
    selection = _load(root, *SELECTION_RECEIPT)
    if selection.get("selected_candidate_ids") != list(SELECTED_IDS):
        raise PrototypeDatasetError("sealed Rule 2 selection differs")
    bindings = _artifact_bindings(selection)
    questions = _questions(root)
    frontier_question = _frontier_question(root)
    frontier_cells, evaluation = _frontier_cells(root)
    composite = _load(root, *FRONTIER_COMPOSITE)
    manifest = _manifest(root, bindings, composite["sealed_at"])

    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".prototype-data-", dir=destination.parent))
    hashes: dict[str, str] = {}

    def write(relative: str, value: dict[str, Any]) -> str:
        payload = _json_bytes(value)
        path = staging / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        hashes[relative] = _sha(payload)
        return hashes[relative]

    try:
        manifest_sha = write("manifests/models.json", manifest)
        question_values = {**questions, FRONTIER_ID: frontier_question}
        index_records = []
        counts: dict[str, int] = {}
        for question_id in DISPLAY_IDS:
            question = question_values[question_id]
            question_path = f"questions/{question_id}.json"
            run_path = f"runs/{question_id}.json"
            mapping_path = f"mappings/{question_id}.json"
            question_sha = write(question_path, question)
            cells = (
                _selected_cells(root, bindings, question_id)
                if question_id in SELECTED_IDS
                else frontier_cells
            )
            run = _run(question, cells, manifest, manifest_sha, question_sha)
            run_sha = write(run_path, run)
            mapping = (
                _selected_mapping(question_id, cells, selection, run["run_id"], run_sha)
                if question_id in SELECTED_IDS
                else _frontier_mapping(cells, evaluation, run["run_id"], run_sha)
            )
            write(mapping_path, mapping)
            index_records.append(
                {
                    "question": question_path,
                    "run": run_path,
                    "mapping": mapping_path,
                }
            )
            counts[question_id] = len(cells)
        index = {
            "schema_version": "1.0.0",
            "dataset_id": "concordance-prototype-real-data",
            "mode": "candidate",
            "model_manifest": "manifests/models.json",
            "questions": index_records,
        }
        write("index.json", index)
        if destination.exists():
            shutil.rmtree(destination)
        os.replace(staging, destination)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return {
        "status": "prepared-prototype-candidate-dataset",
        "output": str(destination),
        "question_count": 3,
        "response_count": sum(counts.values()),
        "response_counts": counts,
        "model_count": len(MODEL_ORDER),
        "files": [
            {"path": path, "sha256": digest} for path, digest in sorted(hashes.items())
        ],
        "network_requests": 0,
        "environment_variables_read": 0,
        "provider_calls": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--write",
        action="store_true",
        help="confirm that the generated candidate dataset should be written",
    )
    args = parser.parse_args()
    if not args.write:
        print(
            json.dumps(
                {
                    "status": "blocked",
                    "error": "Pass --write to assemble the prototype dataset.",
                },
                indent=2,
            )
        )
        return 2
    try:
        result = assemble(args.repository_root, args.output)
    except (OSError, RuntimeError, ValueError) as error:
        print(json.dumps({"status": "blocked", "error": str(error)}, indent=2))
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
