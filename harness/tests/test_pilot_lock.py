from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from concordance_harness.pilot_lock import (
    PILOT_CANDIDATES,
    PILOT_CONTENT_VERSION,
    PILOT_LOCK_PATH,
    PILOT_LOCK_SCHEMA_VERSION,
    PILOT_MAPPING_RUBRIC_PATH,
    PILOT_POOL_DOCUMENT_PATH,
    PILOT_POOL_ID,
    PILOT_POOL_SIZE,
    PILOT_PROTOCOL_PATH,
    PILOT_RULE_VERSION,
    load_and_validate_pilot_lock,
    require_exact_pilot_candidates,
)
from concordance_harness.planner import PlanError, load_questions
from concordance_harness.util import sha256_file

from support import repository_root


class PilotLockTests(unittest.TestCase):
    def make_repository(self, root: Path) -> None:
        source = repository_root()
        question_root = root / "candidate" / "questions"
        question_root.mkdir(parents=True)
        for candidate in PILOT_CANDIDATES:
            shutil.copy2(source / candidate.path, root / candidate.path)
        protocol_path = root / PILOT_PROTOCOL_PATH
        protocol_path.parent.mkdir(parents=True)
        shutil.copy2(source / PILOT_PROTOCOL_PATH, protocol_path)
        shutil.copy2(source / PILOT_POOL_DOCUMENT_PATH, root / PILOT_POOL_DOCUMENT_PATH)
        shutil.copy2(source / PILOT_MAPPING_RUBRIC_PATH, root / PILOT_MAPPING_RUBRIC_PATH)

    def write_lock(self, root: Path, *, bad_hash_id: str | None = None) -> Path:
        protocol_path = root / PILOT_PROTOCOL_PATH
        protocol = json.loads(protocol_path.read_bytes())
        candidates = []
        for candidate in PILOT_CANDIDATES:
            digest = sha256_file(root / candidate.path)
            if candidate.question_id == bad_hash_id:
                digest = "0" * 64 if digest != "0" * 64 else "1" * 64
            candidates.append(
                {
                    "id": candidate.question_id,
                    "kind": candidate.kind,
                    "role": candidate.role,
                    "path": candidate.path,
                    "sha256": digest,
                }
            )
        lock = {
            "schema_version": PILOT_LOCK_SCHEMA_VERSION,
            "pool_id": PILOT_POOL_ID,
            "pool_size": PILOT_POOL_SIZE,
            "rule_version": PILOT_RULE_VERSION,
            "content_version": PILOT_CONTENT_VERSION,
            "pool_document": {
                "path": PILOT_POOL_DOCUMENT_PATH,
                "sha256": sha256_file(root / PILOT_POOL_DOCUMENT_PATH),
            },
            "mapping_rubric": {
                "path": PILOT_MAPPING_RUBRIC_PATH,
                "sha256": sha256_file(root / PILOT_MAPPING_RUBRIC_PATH),
            },
            "protocol": {
                "path": PILOT_PROTOCOL_PATH,
                "protocol_version": protocol["protocol_version"],
                "sha256": sha256_file(protocol_path),
            },
            "candidates": candidates,
        }
        lock_path = root / PILOT_LOCK_PATH
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
        return lock_path

    def commit_all(self, root: Path) -> None:
        commands = [
            ["git", "init", "-q"],
            ["git", "config", "user.name", "Pilot Lock Test"],
            ["git", "config", "user.email", "pilot-lock@example.invalid"],
            ["git", "add", "."],
            ["git", "commit", "-qm", "freeze pilot inputs"],
        ]
        for command in commands:
            subprocess.run(command, cwd=root, check=True, capture_output=True)

    def load(self, root: Path, *, require_committed: bool = False) -> dict:
        return load_and_validate_pilot_lock(
            root / PILOT_LOCK_PATH,
            root,
            root / PILOT_PROTOCOL_PATH,
            load_questions(root / "candidate/questions"),
            require_committed_inputs=require_committed,
        )

    def test_exact_contract_rejects_candidate_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            substitute = root / PILOT_CANDIDATES[0].path
            raw = json.loads(substitute.read_bytes())
            raw["id"] = "substituted-candidate"
            substitute.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaisesRegex(
                PlanError, "six canonical Rule 2 candidate IDs"
            ):
                require_exact_pilot_candidates(
                    load_questions(root / "candidate/questions")
                )

    def test_missing_and_malformed_lock_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            with self.assertRaisesRegex(PlanError, "requires the approved, committed"):
                self.load(root)

            lock_path = root / PILOT_LOCK_PATH
            lock_path.write_text("{not-json", encoding="utf-8")
            with self.assertRaisesRegex(PlanError, "malformed JSON"):
                self.load(root)

    def test_question_hash_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            self.write_lock(root, bad_hash_id=PILOT_CANDIDATES[0].question_id)
            with self.assertRaisesRegex(PlanError, "hash mismatch"):
                self.load(root)

    def test_pool_document_hash_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            lock_path = self.write_lock(root)
            lock = json.loads(lock_path.read_bytes())
            lock["pool_document"]["sha256"] = "0" * 64
            lock_path.write_text(json.dumps(lock), encoding="utf-8")
            with self.assertRaisesRegex(
                PlanError, "hash mismatch for candidate/PILOT_POOL.md"
            ):
                self.load(root)

    def test_mapping_rubric_hash_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            lock_path = self.write_lock(root)
            lock = json.loads(lock_path.read_bytes())
            lock["mapping_rubric"]["sha256"] = "0" * 64
            lock_path.write_text(json.dumps(lock), encoding="utf-8")
            with self.assertRaisesRegex(
                PlanError, "hash mismatch for candidate/MAPPING_RUBRIC.md"
            ):
                self.load(root)

    def test_clean_committed_freeze_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            self.write_lock(root)
            self.commit_all(root)
            lock = self.load(root, require_committed=True)
            self.assertEqual(lock["rule_version"], PILOT_RULE_VERSION)

    def test_uncommitted_lock_and_dirty_locked_content_are_rejected(self) -> None:
        with self.subTest(state="uncommitted lock"):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.make_repository(root)
                self.commit_all(root)
                self.write_lock(root)
                with self.assertRaisesRegex(PlanError, "not committed at HEAD"):
                    self.load(root, require_committed=True)

        with self.subTest(state="dirty locked content"):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.make_repository(root)
                self.write_lock(root)
                self.commit_all(root)
                question_path = root / PILOT_CANDIDATES[0].path
                question_path.write_text(
                    question_path.read_text(encoding="utf-8") + "\n",
                    encoding="utf-8",
                )
                self.write_lock(root)
                with self.assertRaisesRegex(PlanError, "differ from Git HEAD"):
                    self.load(root, require_committed=True)

        with self.subTest(state="dirty mapping rubric with committed matching lock"):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.make_repository(root)
                self.write_lock(root)
                self.commit_all(root)
                rubric_path = root / PILOT_MAPPING_RUBRIC_PATH
                rubric_path.write_text(
                    rubric_path.read_text(encoding="utf-8") + "\n",
                    encoding="utf-8",
                )
                lock_path = self.write_lock(root)
                subprocess.run(
                    ["git", "add", str(lock_path.relative_to(root))],
                    cwd=root,
                    check=True,
                    capture_output=True,
                )
                subprocess.run(
                    ["git", "commit", "-qm", "update lock only"],
                    cwd=root,
                    check=True,
                    capture_output=True,
                )
                with self.assertRaisesRegex(
                    PlanError, "candidate/MAPPING_RUBRIC.md"
                ):
                    self.load(root, require_committed=True)


if __name__ == "__main__":
    unittest.main()
