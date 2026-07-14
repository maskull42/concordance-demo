from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
HARNESS = ROOT / "harness"
TESTS = Path(__file__).resolve().parent
for path in (HARNESS, TESTS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from quantum_disposition import contract, parent, record  # noqa: E402
from test_quantum_disposition import (  # noqa: E402
    FIXED_COMMIT,
    SyntheticQuantumFixture,
    _private_directory,
    _tree,
    _write_private,
    fake_history,
    fake_sources,
)


class QuantumHistoryAdversarialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = SyntheticQuantumFixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def verify(self) -> parent.QuantumHistory:
        return parent.verify_quantum_history(
            self.fixture.root, require_git=False
        )

    def test_mutated_journal_file_is_rejected(self) -> None:
        path = self.fixture.private / "generation/intents/grok/attempt-1.json"
        path.write_bytes(path.read_bytes() + b"changed")
        os.chmod(path, 0o600)
        with self.assertRaisesRegex(parent.QuantumDispositionError, "journal differs"):
            self.verify()

    def test_mutated_review_file_is_rejected(self) -> None:
        path = self.fixture.private / contract.REVIEW_PATHS[-1]
        path.write_bytes(path.read_bytes() + b"changed")
        os.chmod(path, 0o600)
        with self.assertRaisesRegex(
            parent.QuantumDispositionError, "review stage differs"
        ):
            self.verify()

    def test_missing_bound_file_is_rejected(self) -> None:
        (self.fixture.private / "preflight/intents/qwen/attempt-1.json").unlink()
        with self.assertRaisesRegex(parent.QuantumDispositionError, "cannot be inspected"):
            self.verify()

    def test_private_symlink_is_rejected(self) -> None:
        path = self.fixture.private / "generation/outcomes/grok/attempt-1.json"
        target = path.with_name("target.json")
        path.rename(target)
        path.symlink_to(target.name)
        with self.assertRaisesRegex(parent.QuantumDispositionError, "non-symlink"):
            self.verify()

    def test_private_hardlink_is_rejected(self) -> None:
        path = self.fixture.private / "generation/outcomes/grok/attempt-1.json"
        os.link(path, path.with_name("second-link.json"))
        with self.assertRaisesRegex(parent.QuantumDispositionError, "single-link"):
            self.verify()

    def test_private_file_mode_is_rejected(self) -> None:
        path = self.fixture.private / "manifest.json"
        os.chmod(path, 0o644)
        with self.assertRaisesRegex(parent.QuantumDispositionError, "mode-0600"):
            self.verify()

    def test_private_parent_mode_is_rejected(self) -> None:
        path = self.fixture.private / "generation/raw-responses"
        os.chmod(path, 0o755)
        with self.assertRaisesRegex(parent.QuantumDispositionError, "mode-0700"):
            self.verify()

    def test_public_binding_mutation_is_rejected(self) -> None:
        path = self.fixture.root / contract.PUBLIC_BINDINGS[0].path
        path.write_bytes(path.read_bytes() + b"changed")
        with self.assertRaisesRegex(parent.QuantumDispositionError, "immutable binding"):
            self.verify()

    def test_upstream_private_binding_mutation_is_rejected(self) -> None:
        path = self.fixture.root / contract.UPSTREAM_PRIVATE_BINDINGS[0].path
        path.write_bytes(path.read_bytes() + b"changed")
        os.chmod(path, 0o600)
        with self.assertRaisesRegex(parent.QuantumDispositionError, "immutable binding"):
            self.verify()

    def test_author_review_directory_after_withdrawal_is_rejected(self) -> None:
        path = self.fixture.private / contract.CANDIDATE_REVIEW_ROOT / "author-review"
        path.mkdir(mode=0o700)
        with self.assertRaisesRegex(parent.QuantumDispositionError, "author review"):
            self.verify()

    def test_incomplete_evaluation_publication_claim_is_rejected(self) -> None:
        path = (
            self.fixture.private
            / contract.CANDIDATE_REVIEW_ROOT
            / ".evaluation.publish-claim"
        )
        _write_private(path, b"claim")
        with self.assertRaisesRegex(parent.QuantumDispositionError, "author review"):
            self.verify()

    def test_ds_store_is_ignored_without_deletion(self) -> None:
        extra = self.fixture.private / ".DS_Store"
        extra.write_bytes(b"finder metadata")
        before = extra.read_bytes()
        self.verify()
        self.assertEqual(extra.read_bytes(), before)

    def test_semantic_run_change_is_rejected_even_with_rebound_hashes(self) -> None:
        run_path = self.fixture.private / "run.json"
        value = json.loads(run_path.read_bytes())
        value["successful_outcome_count"] = 7
        payload = contract.canonical_json_bytes(value)
        run_path.write_bytes(payload)
        os.chmod(run_path, 0o600)
        self.fixture.stack.enter_context(
            mock.patch.object(contract, "RUN_SHA256", contract.sha256_bytes(payload))
        )
        self.fixture.stack.enter_context(
            mock.patch.object(
                contract,
                "JOURNAL_TREE_SHA256",
                _tree(self.fixture.private, contract.journal_paths()),
            )
        )
        with self.assertRaisesRegex(parent.QuantumDispositionError, "semantics"):
            self.verify()

    def test_git_ancestry_is_mandatory_in_production_mode(self) -> None:
        failure = subprocess.CompletedProcess([], 1, b"", b"missing")
        with (
            mock.patch.object(parent, "_git", return_value=failure),
            self.assertRaisesRegex(parent.QuantumDispositionError, "not an ancestor"),
        ):
            parent.verify_quantum_history(self.fixture.root, require_git=True)


class DispositionReceiptAdversarialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        os.chmod(self.root, 0o700)
        _private_directory(self.root / ".pilot")
        self.history = fake_history(self.root)
        self.sources = fake_sources()
        self.stack = ExitStack()
        self.stack.enter_context(
            mock.patch.object(
                record,
                "committed_source_bindings",
                return_value=(FIXED_COMMIT, self.sources),
            )
        )
        self.source_mock = self.stack.enter_context(
            mock.patch.object(
                record, "source_bindings_at_commit", return_value=self.sources
            )
        )
        self.history_mock = self.stack.enter_context(
            mock.patch.object(
                record, "verify_quantum_history", return_value=self.history
            )
        )
        record.write_disposition(self.root)
        self.output = self.root / contract.DISPOSITION_ROOT_RELATIVE
        self.receipt = self.output / contract.DISPOSITION_FILE

    def tearDown(self) -> None:
        self.stack.close()
        self.temporary.cleanup()

    def test_receipt_semantic_tamper_is_rejected(self) -> None:
        value = json.loads(self.receipt.read_bytes())
        value["disposition"]["publication_eligible"] = True
        self.receipt.write_bytes(contract.canonical_json_bytes(value))
        os.chmod(self.receipt, 0o600)
        with self.assertRaisesRegex(record.QuantumDispositionError, "differs"):
            record.verify_disposition(self.root)

    def test_receipt_extra_file_is_rejected(self) -> None:
        _write_private(self.output / "extra.json", b"{}\n")
        with self.assertRaisesRegex(record.QuantumDispositionError, "inventory"):
            record.verify_disposition(self.root)

    def test_receipt_mode_is_rejected(self) -> None:
        os.chmod(self.receipt, 0o644)
        with self.assertRaisesRegex(record.QuantumDispositionError, "mode-0600"):
            record.verify_disposition(self.root)

    def test_receipt_hardlink_is_rejected(self) -> None:
        os.link(self.receipt, self.output.parent / "receipt-second-link.json")
        with self.assertRaisesRegex(record.QuantumDispositionError, "single-link"):
            record.verify_disposition(self.root)

    def test_receipt_directory_symlink_is_rejected(self) -> None:
        moved = self.output.with_name("moved-output")
        self.output.rename(moved)
        self.output.symlink_to(moved.name)
        with self.assertRaisesRegex(record.QuantumDispositionError, "real mode-0700"):
            record.verify_disposition(self.root)

    def test_historical_source_binding_change_is_rejected(self) -> None:
        changed = list(self.sources)
        changed[0] = {**changed[0], "sha256": "0" * 64}
        with (
            mock.patch.object(
                record, "source_bindings_at_commit", return_value=tuple(changed)
            ),
            self.assertRaisesRegex(record.QuantumDispositionError, "differs"),
        ):
            record.verify_disposition(self.root)

    def test_parent_history_change_is_rejected(self) -> None:
        changed = parent.QuantumHistory(
            **{
                **self.history.__dict__,
                "journal_tree_sha256": "0" * 64,
            }
        )
        with (
            mock.patch.object(
                record, "verify_quantum_history", return_value=changed
            ),
            self.assertRaisesRegex(record.QuantumDispositionError, "differs"),
        ):
            record.verify_disposition(self.root)


class SourceBindingAdversarialTests(unittest.TestCase):
    def test_historical_source_bindings_are_ordered_and_content_addressed(self) -> None:
        def fake_git_output(
            _root: Path, arguments: list[str], _label: str
        ) -> bytes:
            if arguments[0] == "cat-file":
                return b""
            relative = arguments[-1].split(":", 1)[1]
            return f"historical:{relative}".encode()

        with mock.patch.object(record, "_git_output", side_effect=fake_git_output):
            bindings = record.source_bindings_at_commit("/tmp", FIXED_COMMIT)
        self.assertEqual(
            [item["path"] for item in bindings], list(contract.SOURCE_PATHS)
        )
        for item in bindings:
            self.assertEqual(
                item["sha256"],
                contract.sha256_bytes(f"historical:{item['path']}".encode()),
            )

    def test_dirty_execution_source_prevents_publication(self) -> None:
        calls = 0

        def fake_git_output(
            _root: Path, _arguments: list[str], _label: str
        ) -> bytes:
            nonlocal calls
            calls += 1
            return (FIXED_COMMIT + "\n").encode() if calls == 1 else b" M harness/file.py\n"

        with (
            mock.patch.object(record, "_git_output", side_effect=fake_git_output),
            self.assertRaisesRegex(
                record.QuantumDispositionError, "tracked, committed, and clean"
            ),
        ):
            record.committed_source_bindings("/tmp")


if __name__ == "__main__":
    unittest.main()
