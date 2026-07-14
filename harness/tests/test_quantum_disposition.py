from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
HARNESS = ROOT / "harness"
if str(HARNESS) not in sys.path:
    sys.path.insert(0, str(HARNESS))

import record_quantum_disposition as command  # noqa: E402
from quantum_disposition import contract, parent, record  # noqa: E402


LIVE_PRIVATE_AVAILABLE = (
    ROOT / contract.PRIVATE_ROOT_RELATIVE / "run.json"
).is_file()
FIXED_TIME = "2026-07-14T12:00:00Z"
FIXED_COMMIT = "f" * 40


def _private_directory(path: Path) -> None:
    missing: list[Path] = []
    cursor = path
    while not cursor.exists():
        missing.append(cursor)
        cursor = cursor.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700)
    os.chmod(path, 0o700)


def _write_private(path: Path, payload: bytes) -> None:
    _private_directory(path.parent)
    path.write_bytes(payload)
    os.chmod(path, 0o600)


def _tree(root: Path, paths: tuple[str, ...]) -> str:
    values = [
        {
            "path": relative,
            "sha256": hashlib.sha256((root / relative).read_bytes()).hexdigest(),
        }
        for relative in paths
    ]
    return contract.sha256_bytes(contract.canonical_json_bytes(values))


def fake_history(repository_root: Path) -> parent.QuantumHistory:
    journal = tuple(
        {"path": relative, "sha256": "1" * 64}
        for relative in contract.journal_paths()
    )
    review = tuple(
        {"path": relative, "sha256": "2" * 64}
        for relative in contract.REVIEW_PATHS
    )
    return parent.QuantumHistory(
        repository_root=repository_root,
        private_root=repository_root / contract.PRIVATE_ROOT_RELATIVE,
        public_bindings=tuple(spec.value() for spec in contract.PUBLIC_BINDINGS),
        upstream_private_bindings=tuple(
            spec.value() for spec in contract.UPSTREAM_PRIVATE_BINDINGS
        ),
        journal_bindings=journal,
        journal_tree_sha256="3" * 64,
        review_bindings=review,
        review_tree_sha256="4" * 64,
    )


def fake_sources() -> tuple[dict[str, str], ...]:
    return tuple(
        {"path": path, "sha256": hashlib.sha256(path.encode()).hexdigest()}
        for path in contract.SOURCE_PATHS
    )


class SyntheticQuantumFixture:
    """A fully private synthetic tree governed by patched expected digests."""

    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        os.chmod(self.root, 0o700)
        _private_directory(self.root / ".pilot")
        self.private = self.root / contract.PRIVATE_ROOT_RELATIVE
        self.stack = ExitStack()

        for relative in contract.journal_paths():
            if relative == "run.json":
                continue
            payload = f"opaque fixture bytes for {relative}\n".encode()
            _write_private(self.private / relative, payload)

        outcome_hashes = {
            key: hashlib.sha256(
                (self.private / f"generation/outcomes/{key}/attempt-1.json").read_bytes()
            ).hexdigest()
            for key in contract.MODEL_ORDER
        }
        authorization_sha = hashlib.sha256(
            (self.private / "authorization.json").read_bytes()
        ).hexdigest()
        pricing_sha = hashlib.sha256(
            (self.private / "pricing-recheck.json").read_bytes()
        ).hexdigest()
        manifest_sha = hashlib.sha256(
            (self.private / "manifest.json").read_bytes()
        ).hexdigest()
        self.stack.enter_context(
            mock.patch.object(contract, "OUTCOME_SHA256", outcome_hashes)
        )
        self.stack.enter_context(
            mock.patch.object(contract, "AUTHORIZATION_SHA256", authorization_sha)
        )
        self.stack.enter_context(
            mock.patch.object(contract, "PRICING_RECHECK_SHA256", pricing_sha)
        )
        self.stack.enter_context(
            mock.patch.object(contract, "MANIFEST_SHA256", manifest_sha)
        )
        run_payload = contract.canonical_json_bytes(parent.expected_run())
        _write_private(self.private / "run.json", run_payload)
        self.stack.enter_context(
            mock.patch.object(
                contract, "RUN_SHA256", hashlib.sha256(run_payload).hexdigest()
            )
        )
        self.stack.enter_context(
            mock.patch.object(
                contract,
                "JOURNAL_TREE_SHA256",
                _tree(self.private, contract.journal_paths()),
            )
        )

        for relative in contract.REVIEW_PATHS:
            _write_private(
                self.private / relative,
                f"opaque review fixture for {relative}\n".encode(),
            )
        self.stack.enter_context(
            mock.patch.object(
                contract,
                "REVIEW_TREE_SHA256",
                _tree(self.private, contract.REVIEW_PATHS),
            )
        )

        public_specs = []
        for index, spec in enumerate(contract.PUBLIC_BINDINGS):
            payload = f"public fixture {index}\n".encode()
            path = self.root / spec.path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            public_specs.append(
                contract.ArtifactSpec(spec.path, hashlib.sha256(payload).hexdigest())
            )
        self.stack.enter_context(
            mock.patch.object(contract, "PUBLIC_BINDINGS", tuple(public_specs))
        )

        upstream_specs = []
        for index, spec in enumerate(contract.UPSTREAM_PRIVATE_BINDINGS):
            payload = f"upstream fixture {index}\n".encode()
            _write_private(self.root / spec.path, payload)
            upstream_specs.append(
                contract.ArtifactSpec(spec.path, hashlib.sha256(payload).hexdigest())
            )
        self.stack.enter_context(
            mock.patch.object(
                contract, "UPSTREAM_PRIVATE_BINDINGS", tuple(upstream_specs)
            )
        )

    def close(self) -> None:
        self.stack.close()
        self.temporary.cleanup()


@unittest.skipUnless(
    LIVE_PRIVATE_AVAILABLE,
    "private Quantum lineage is intentionally absent from a clean checkout",
)
class LiveQuantumHistoryTests(unittest.TestCase):
    def test_exact_history_verifies_without_mutation(self) -> None:
        required = [
            ROOT / contract.PRIVATE_ROOT_RELATIVE / relative
            for relative in (*contract.journal_paths(), *contract.REVIEW_PATHS)
        ]
        before = {
            path: (path.stat().st_mode, path.stat().st_size, path.stat().st_mtime_ns)
            for path in required
        }
        history = parent.verify_quantum_history(ROOT)
        after = {
            path: (path.stat().st_mode, path.stat().st_size, path.stat().st_mtime_ns)
            for path in required
        }
        self.assertEqual(before, after)
        self.assertEqual(len(history.journal_bindings), 52)
        self.assertEqual(len(history.review_bindings), 8)
        self.assertEqual(history.journal_tree_sha256, contract.JOURNAL_TREE_SHA256)
        self.assertEqual(history.review_tree_sha256, contract.REVIEW_TREE_SHA256)

    def test_preview_is_read_only_and_does_not_change_receipt_state(self) -> None:
        output = ROOT / contract.DISPOSITION_ROOT_RELATIVE
        existed_before = os.path.lexists(output)
        before = None
        if existed_before:
            receipt = output / contract.DISPOSITION_FILE
            before = (
                output.stat().st_mode,
                output.stat().st_mtime_ns,
                receipt.stat().st_mode,
                receipt.stat().st_size,
                receipt.stat().st_mtime_ns,
                hashlib.sha256(receipt.read_bytes()).hexdigest(),
            )
        result = record.preview_disposition(ROOT)
        self.assertEqual(result["status"], "ready-to-record-withdrawal")
        self.assertIs(result["receipt_exists"], existed_before)
        self.assertIs(os.path.lexists(output), existed_before)
        if existed_before:
            receipt = output / contract.DISPOSITION_FILE
            after = (
                output.stat().st_mode,
                output.stat().st_mtime_ns,
                receipt.stat().st_mode,
                receipt.stat().st_size,
                receipt.stat().st_mtime_ns,
                hashlib.sha256(receipt.read_bytes()).hexdigest(),
            )
            self.assertEqual(before, after)


class QuantumDispositionValueTests(unittest.TestCase):
    def test_instruction_binding_is_exact(self) -> None:
        self.assertEqual(
            hashlib.sha256(contract.USER_INSTRUCTION.encode()).hexdigest(),
            contract.USER_INSTRUCTION_SHA256,
        )

    def test_disposition_is_explicit_and_contains_no_response_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            value = record.disposition_value(
                history=fake_history(root),
                recorded_at=FIXED_TIME,
                execution_commit=FIXED_COMMIT,
                execution_sources=fake_sources(),
            )
        self.assertEqual(value["status"], contract.STATUS)
        self.assertEqual(value["user_instruction"]["verbatim"], contract.USER_INSTRUCTION)
        self.assertEqual(
            value["disposition"],
            {
                "classification": "private-stress-test",
                "selection_eligible": False,
                "publication_eligible": False,
                "production_eligible": False,
                "author_review_complete": False,
                "threshold_evaluation_performed": False,
                "historical_artifacts_preserved": True,
                "responses_preserved": True,
                "deletion_authorized": False,
                "replacement_research_and_build_authorized": True,
                "successor_provider_calls_authorized": False,
            },
        )
        forbidden = {"response_text", "body_base64", "result"}

        def keys(item: object) -> set[str]:
            if isinstance(item, dict):
                return set(item) | set().union(*(keys(value) for value in item.values()))
            if isinstance(item, list):
                return set().union(*(keys(value) for value in item))
            return set()

        self.assertFalse(forbidden & keys(value))

    def test_private_publication_is_write_once_and_verifiable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            os.chmod(root, 0o700)
            _private_directory(root / ".pilot")
            history = fake_history(root)
            sources = fake_sources()
            with (
                mock.patch.object(
                    record,
                    "committed_source_bindings",
                    return_value=(FIXED_COMMIT, sources),
                ),
                mock.patch.object(
                    record, "source_bindings_at_commit", return_value=sources
                ),
                mock.patch.object(
                    record, "verify_quantum_history", return_value=history
                ),
            ):
                first = record.write_disposition(root)
                output = root / contract.DISPOSITION_ROOT_RELATIVE
                receipt = output / contract.DISPOSITION_FILE
                self.assertEqual(
                    first["status"],
                    "verified-withdrawn-private-stress-test-nonpublication",
                )
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o600)
                before = receipt.read_bytes()
                second = record.write_disposition(root)
                self.assertEqual(first, second)
                self.assertEqual(receipt.read_bytes(), before)

    def test_preview_with_mocked_history_never_creates_private_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with mock.patch.object(
                record, "verify_quantum_history", return_value=fake_history(root)
            ):
                result = record.preview_disposition(root)
            self.assertFalse(result["receipt_exists"])
            self.assertFalse((root / ".pilot").exists())

    def test_cli_check_delegates_without_writing(self) -> None:
        expected = {"status": "ready-to-record-withdrawal"}
        with (
            mock.patch.object(command, "preview_disposition", return_value=expected),
            mock.patch("builtins.print") as printer,
        ):
            status = command.main(["--check", "--repository-root", "/tmp/fixture"])
        self.assertEqual(status, 0)
        printer.assert_called_once_with(json.dumps(expected, indent=2))


class SyntheticQuantumHistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = SyntheticQuantumFixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def test_synthetic_exact_history_verifies(self) -> None:
        history = parent.verify_quantum_history(
            self.fixture.root, require_git=False
        )
        self.assertEqual(len(history.journal_bindings), 52)
        self.assertEqual(len(history.review_bindings), 8)

    def test_response_bearing_files_are_not_decoded(self) -> None:
        raw = self.fixture.private / "generation/raw-responses/gemini/attempt-1.json"
        raw.write_bytes(b'not-json: {"response_text":"opaque"}\n')
        os.chmod(raw, 0o600)
        self.fixture.stack.enter_context(
            mock.patch.object(
                contract,
                "JOURNAL_TREE_SHA256",
                _tree(self.fixture.private, contract.journal_paths()),
            )
        )
        history = parent.verify_quantum_history(
            self.fixture.root, require_git=False
        )
        self.assertEqual(len(history.journal_bindings), 52)


if __name__ == "__main__":
    unittest.main()
