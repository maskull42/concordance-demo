from __future__ import annotations

import json
import os
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jsonschema import Draft202012Validator

from divergence_successor_continuation_author_review import anchor
from divergence_successor_continuation_evaluation import contract, evaluate
from divergence_successor_continuation_evaluation import lock as evaluation_lock


ROOT = Path(__file__).resolve().parents[2]


class ThresholdTests(unittest.TestCase):
    def setUp(self) -> None:
        self.allowed = tuple(f"synthetic-{index}" for index in range(4))

    def test_exact_qualifying_boundary(self) -> None:
        primaries = [self.allowed[index % 3] for index in range(8)]
        result, counts = evaluate.evaluate_threshold(
            primaries, self.allowed, contract.FROZEN_THRESHOLD
        )
        self.assertTrue(result["qualifies"])
        self.assertEqual(sum(counts.values()), len(primaries))

    def test_every_failure_boundary_is_recorded(self) -> None:
        cases = (
            (
                [self.allowed[index % 3] if index < 5 else None for index in range(8)],
                "fewer-than-six-non-null-primary-endorsements",
            ),
            (
                [self.allowed[index % 2] for index in range(8)],
                "fewer-than-three-represented-positions",
            ),
            (
                [
                    self.allowed[0] if index < 5 else self.allowed[1 + (index % 2)]
                    for index in range(8)
                ],
                "one-position-has-more-than-four-primary-endorsements",
            ),
        )
        for primaries, reason in cases:
            with self.subTest(reason=reason):
                result, _ = evaluate.evaluate_threshold(
                    primaries, self.allowed, contract.FROZEN_THRESHOLD
                )
                self.assertIn(reason, result["failure_reasons"])

    def test_exact_non_null_and_concentration_boundaries_pass(self) -> None:
        primaries = [
            self.allowed[0],
            self.allowed[0],
            self.allowed[0],
            self.allowed[0],
            self.allowed[1],
            self.allowed[2],
            None,
            None,
        ]
        result, _ = evaluate.evaluate_threshold(
            primaries, self.allowed, contract.FROZEN_THRESHOLD
        )
        self.assertTrue(result["qualifies"])

    def test_wrong_threshold_and_unknown_position_are_rejected(self) -> None:
        changed = dict(contract.FROZEN_THRESHOLD)
        changed["minimum_distinct_primary_positions"] += 1
        with self.assertRaises(evaluate.EvaluationError):
            evaluate.evaluate_threshold([None] * 8, self.allowed, changed)
        with self.assertRaises(evaluate.EvaluationError):
            evaluate.evaluate_threshold(
                ["foreign"] * 8, self.allowed, contract.FROZEN_THRESHOLD
            )

    def test_offline_tripwires_remain_unused(self) -> None:
        primaries = [self.allowed[index % 3] for index in range(8)]
        with (
            mock.patch.object(socket, "socket", side_effect=AssertionError("network")),
            mock.patch.object(os, "getenv", side_effect=AssertionError("environment")),
        ):
            result, _ = evaluate.evaluate_threshold(
                primaries, self.allowed, contract.FROZEN_THRESHOLD
            )
        self.assertTrue(result["qualifies"])

    def test_terminal_results_are_exact_and_final(self) -> None:
        self.assertEqual(
            evaluate._terminal_result(True),
            {
                "terminal": True,
                "candidate_order": [contract.CANDIDATE_ID],
                "selected_candidate_id": contract.CANDIDATE_ID,
                "reason": "sole-successor-qualified-terminal-selected",
                "additional_candidates_allowed": False,
                "fallback_allowed": False,
                "third_candidate_allowed": False,
            },
        )
        failed = evaluate._terminal_result(False)
        self.assertIsNone(failed["selected_candidate_id"])
        self.assertEqual(
            failed["reason"], "sole-successor-completed-and-failed-no-selection"
        )
        self.assertFalse(failed["additional_candidates_allowed"])


class TranslationTests(unittest.TestCase):
    def _fixture(self) -> tuple[dict, dict, dict]:
        positions = [{"id": f"canonical-{index}"} for index in range(4)]
        decisions = []
        private = []
        for index in range(8):
            blind_id = f"blind-{index}"
            response_sha = f"{index:064x}"
            decisions.append(
                {
                    "blind_id": blind_id,
                    "response_sha256": response_sha,
                    "first_pass_assignment_sha256": f"{index + 10:064x}",
                    "decision": "confirm",
                    "reviewed_at": "2026-01-01T00:00:00Z",
                    "reviewed_primary_position_handle": "P1",
                    "reviewed_reason_code": "clear_preference",
                }
            )
            private.append(
                {
                    "blind_id": blind_id,
                    "response_sha256": response_sha,
                    "position_crosswalk": {
                        f"P{offset + 1}": positions[(index + offset) % len(positions)][
                            "id"
                        ]
                        for offset in range(len(positions))
                    },
                    "outcome_path": f"private/outcome-{index}.json",
                    "outcome_sha256": f"{index + 20:064x}",
                }
            )
        return {"decisions": decisions}, {"items": private}, {"position_map": positions}

    def test_local_handles_translate_per_item(self) -> None:
        review, crosswalk, question = self._fixture()
        lineage, primaries, allowed = evaluate._reviewed_lineage(
            review, crosswalk, question
        )
        self.assertEqual(len(lineage), len(review["decisions"]))
        self.assertEqual(set(primaries), set(allowed))

    def test_unknown_handle_and_response_tamper_are_rejected(self) -> None:
        review, crosswalk, question = self._fixture()
        review["decisions"][0]["reviewed_primary_position_handle"] = "P9"
        with self.assertRaises(evaluate.EvaluationError):
            evaluate._reviewed_lineage(review, crosswalk, question)

    def test_reordered_subset_and_duplicate_decisions_are_rejected(self) -> None:
        for mutation in ("reorder", "subset", "duplicate"):
            review, crosswalk, question = self._fixture()
            if mutation == "reorder":
                review["decisions"][0], review["decisions"][1] = (
                    review["decisions"][1],
                    review["decisions"][0],
                )
            elif mutation == "subset":
                review["decisions"].pop()
            else:
                review["decisions"][-1] = dict(review["decisions"][0])
            with (
                self.subTest(mutation=mutation),
                self.assertRaises(evaluate.EvaluationError),
            ):
                evaluate._reviewed_lineage(review, crosswalk, question)

    def test_null_reason_pairing_is_enforced(self) -> None:
        review, crosswalk, question = self._fixture()
        review["decisions"][0]["reviewed_primary_position_handle"] = None
        with self.assertRaises(evaluate.EvaluationError):
            evaluate._reviewed_lineage(review, crosswalk, question)
        review, crosswalk, question = self._fixture()
        review["decisions"][0]["response_sha256"] = "f" * 64
        with self.assertRaises(evaluate.EvaluationError):
            evaluate._reviewed_lineage(review, crosswalk, question)


class PublicGateTests(unittest.TestCase):
    def test_schema_has_no_result_or_review_sequence_fields(self) -> None:
        schema = json.loads(
            (ROOT / contract.LOCK_SCHEMA_PATH).read_text(encoding="utf-8")
        )
        serialized = json.dumps(schema, sort_keys=True)
        for forbidden in (
            "reviewed_lineage",
            "position_primary_counts",
            "threshold_result",
            "failure_reasons",
            "reviewed_primary_position_id",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_duplicate_keys_are_rejected(self) -> None:
        with self.assertRaises(evaluation_lock.EvaluationLockError):
            evaluation_lock._json(b'{"status":"a","status":"b"}', "duplicate fixture")
        with self.assertRaises(evaluate.EvaluationError):
            evaluate._json(b'{"status":"a","status":"b"}', "duplicate receipt")

    def test_both_schemas_are_valid_draft_2020_12(self) -> None:
        for relative in (contract.LOCK_SCHEMA_PATH, contract.RECEIPT_SCHEMA_PATH):
            schema = json.loads((ROOT / relative).read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)

    def test_no_actual_blind_id_leaks_into_public_evaluator_sources(self) -> None:
        anchored = anchor.verify_anchor(ROOT)["anchor"]
        crosswalk_payload = anchor._private_bytes(
            ROOT, anchored["blind_crosswalk"]["path"], "test crosswalk"
        )
        crosswalk = evaluate._json(crosswalk_payload, "test crosswalk")
        blind_ids = {item["blind_id"] for item in crosswalk["items"]}
        public_text = "\n".join(
            (ROOT / relative).read_text(encoding="utf-8")
            for relative in contract.SOURCE_PATHS
        )
        self.assertTrue(blind_ids)
        self.assertTrue(all(blind_id not in public_text for blind_id in blind_ids))

    def test_real_anchored_hmac_crosswalk_verifies_without_threshold_work(self) -> None:
        anchored = anchor.verify_anchor(ROOT)["anchor"]
        successor = json.loads(
            (ROOT / contract.SUCCESSOR_LOCK_PATH).read_text(encoding="utf-8")
        )
        lock_value = {
            "lineage": {
                "blind_packet": anchored["blind_packet"],
                "blind_crosswalk": anchored["blind_crosswalk"],
                "blind_key_sha256": anchored["blind_key"]["sha256"],
                "question": successor["bindings"]["question"],
            },
            "threshold_contract": dict(contract.FROZEN_THRESHOLD),
        }
        packet, crosswalk, question = evaluate._anchored_inputs(ROOT, lock_value)
        self.assertEqual(len(packet["items"]), len(crosswalk["items"]))
        self.assertEqual(
            len(question["position_map"]),
            len(crosswalk["items"][0]["position_crosswalk"]),
        )


class CommitGateTests(unittest.TestCase):
    def _git(self, root: Path, *arguments: str) -> str:
        result = subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    def test_sources_then_direct_child_lock_are_required(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._git(root, "init", "-q")
            self._git(root, "config", "user.name", "Test")
            self._git(root, "config", "user.email", "test@example.invalid")
            source = root / "source.py"
            source.write_text("VALUE = 1\n", encoding="utf-8")
            self._git(root, "add", "source.py")
            self._git(root, "commit", "-qm", "sources")
            source_head = self._git(root, "rev-parse", "HEAD")
            with mock.patch.object(contract, "SOURCE_PATHS", ("source.py",)):
                evaluation_lock._require_paths_at_commit(
                    root, ["source.py"], source_head
                )
                source.write_text("VALUE = 2\n", encoding="utf-8")
                with self.assertRaises(evaluation_lock.EvaluationLockError):
                    evaluation_lock._require_paths_at_commit(
                        root, ["source.py"], source_head
                    )
                source.write_text("VALUE = 1\n", encoding="utf-8")
                gate = root / "gate.json"
                payload = b'{"gate":true}\n'
                gate.write_bytes(payload)
                self._git(root, "add", "gate.json")
                self._git(root, "commit", "-qm", "gate")
                with mock.patch.object(contract, "LOCK_PATH", "gate.json"):
                    lock_head = evaluation_lock._require_lock_committed(
                        root, payload, source_head
                    )
                    self.assertEqual(lock_head, self._git(root, "rev-parse", "HEAD"))
                    (root / "later").write_text("unrelated\n", encoding="utf-8")
                    self._git(root, "add", "later")
                    self._git(root, "commit", "-qm", "later unrelated commit")
                    descendant = self._git(root, "rev-parse", "HEAD")
                    self.assertEqual(
                        evaluation_lock._require_lock_committed(
                            root, payload, source_head
                        ),
                        lock_head,
                    )
                    with self.assertRaises(evaluate.EvaluationError):
                        evaluate._require_exact_lock_commit(descendant, lock_head)
                    gate.write_bytes(b'{"gate":false}\n')
                    with self.assertRaises(evaluation_lock.EvaluationLockError):
                        evaluation_lock._require_lock_committed(
                            root, payload, source_head
                        )

    def test_wrong_parent_lock_commit_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._git(root, "init", "-q")
            self._git(root, "config", "user.name", "Test")
            self._git(root, "config", "user.email", "test@example.invalid")
            (root / "source.py").write_text("VALUE = 1\n", encoding="utf-8")
            self._git(root, "add", "source.py")
            self._git(root, "commit", "-qm", "sources")
            source_head = self._git(root, "rev-parse", "HEAD")
            (root / "unrelated").write_text("x\n", encoding="utf-8")
            self._git(root, "add", "unrelated")
            self._git(root, "commit", "-qm", "intervening")
            payload = b'{"gate":true}\n'
            (root / "gate.json").write_bytes(payload)
            self._git(root, "add", "gate.json")
            self._git(root, "commit", "-qm", "gate")
            with (
                mock.patch.object(contract, "SOURCE_PATHS", ("source.py",)),
                mock.patch.object(contract, "LOCK_PATH", "gate.json"),
                self.assertRaises(evaluation_lock.EvaluationLockError),
            ):
                evaluation_lock._require_lock_committed(root, payload, source_head)


class PrivateFilesystemTests(unittest.TestCase):
    def test_recovery_reader_rejects_symlink_mode_and_excess_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "evaluation-v2"
            directory.mkdir(mode=0o700)
            receipt = directory / "receipt.json"
            receipt.write_bytes(b"{}\n")
            receipt.chmod(0o600)
            self.assertEqual(evaluate._recovery_directory_payload(directory), b"{}\n")
            receipt.chmod(0o644)
            with self.assertRaises(evaluate.EvaluationError):
                evaluate._recovery_directory_payload(directory)
            receipt.chmod(0o600)
            second = root / "second"
            third = root / "third"
            os.link(receipt, second)
            os.link(receipt, third)
            with self.assertRaises(evaluate.EvaluationError):
                evaluate._recovery_directory_payload(directory)
            second.unlink()
            third.unlink()
            receipt.unlink()
            target = root / "target"
            target.write_bytes(b"{}\n")
            target.chmod(0o600)
            receipt.symlink_to(target)
            with self.assertRaises(evaluate.EvaluationError):
                evaluate._recovery_directory_payload(directory)

    def test_recovery_reader_rejects_extra_file_and_directory_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "evaluation-v2"
            directory.mkdir(mode=0o700)
            receipt = directory / "receipt.json"
            receipt.write_bytes(b"{}\n")
            receipt.chmod(0o600)
            extra = directory / "extra"
            extra.write_bytes(b"x")
            extra.chmod(0o600)
            with self.assertRaises(evaluate.EvaluationError):
                evaluate._recovery_directory_payload(directory)
            extra.unlink()
            directory.chmod(0o755)
            with self.assertRaises(evaluate.EvaluationError):
                evaluate._recovery_directory_payload(directory)

    def test_public_lock_parser_requires_exact_mode_and_single_link(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "gate.json"
            path.write_bytes(b'{"gate":true}\n')
            with mock.patch.object(contract, "LOCK_PATH", "gate.json"):
                path.chmod(0o600)
                with self.assertRaises(evaluation_lock.EvaluationLockError):
                    evaluation_lock._parse_lock(root)
                path.chmod(0o644)
                linked = root / "linked"
                os.link(path, linked)
                with self.assertRaises(evaluation_lock.EvaluationLockError):
                    evaluation_lock._parse_lock(root)

    def test_public_lock_writer_overrides_restrictive_umask(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            context = object()
            with (
                mock.patch.object(contract, "repository_root", return_value=root),
                mock.patch.object(contract, "LOCK_PATH", "gate.json"),
                mock.patch.object(
                    evaluation_lock, "build_lock", return_value={"gate": True}
                ),
                mock.patch.object(
                    evaluation_lock,
                    "load_and_validate_lock",
                    return_value=context,
                ),
            ):
                previous = os.umask(0o077)
                try:
                    self.assertIs(evaluation_lock.write_lock(root), context)
                finally:
                    os.umask(previous)
            self.assertEqual((root / "gate.json").stat().st_mode & 0o777, 0o644)


if __name__ == "__main__":
    unittest.main()
