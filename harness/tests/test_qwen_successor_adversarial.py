from __future__ import annotations

import asyncio
import copy
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from concordance_recovery import contract as first_contract  # noqa: E402
from concordance_recovery import execute as first_execute  # noqa: E402
from concordance_recovery.journal import (  # noqa: E402
    JournalRecord,
    RecoveryJournalError,
    StrandedGenerationIntent,
)
from concordance_recovery.lock import (  # noqa: E402
    load_and_validate_recovery_lock,
)
from qwen_successor import contract  # noqa: E402
from qwen_successor import execute as successor_execute  # noqa: E402
from qwen_successor import parent as parent_module  # noqa: E402
from qwen_successor.lock import build_lock  # noqa: E402
from qwen_successor.state import SuccessorPaths, phase_lock  # noqa: E402
from run_qwen_successor import (  # noqa: E402
    PreImportSuccessorError,
    _bindings,
    _load_lock,
    _preimport_bootstrap,
)


GIT = "/usr/bin/git"


def git_environment(home: Path) -> dict[str, str]:
    return {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def run_git(
    root: Path,
    arguments: list[str],
    *,
    home: Path,
    text: bool = False,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        [GIT, *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=text,
        env=git_environment(home),
    )


def record(path: Path, payload: dict, seed: int = 1) -> JournalRecord:
    return JournalRecord(path=path, payload=payload, sha256=f"{seed:064x}")


def make_private_tree(root: Path, relative_files: set[str]) -> None:
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    directories: set[str] = set()
    for relative in contract.FIRST_EXTRA_EMPTY_DIRECTORIES:
        parent_module._add_directory_with_parents(directories, relative)
    for relative in relative_files:
        parent = PurePosixPath(relative).parent
        while parent != PurePosixPath("."):
            directories.add(parent.as_posix())
            parent = parent.parent
    for relative in sorted(directories, key=lambda item: (item.count("/"), item)):
        path = root / relative
        path.mkdir(exist_ok=True)
        path.chmod(0o700)
    for relative in relative_files:
        path = root / relative
        path.write_bytes(b"{}\n")
        path.chmod(0o600)


def chmod_private_ancestors(path: Path, root: Path) -> None:
    current = path
    while current != root:
        current.chmod(0o700)
        current = current.parent


class QwenSuccessorContractTests(unittest.TestCase):
    def test_preserved_and_target_models_are_disjoint_and_complete(self) -> None:
        self.assertEqual(contract.PRESERVED_MODEL_KEYS, ("gemini", "claude", "cohere"))
        self.assertEqual(
            tuple((*contract.PRESERVED_MODEL_KEYS, *contract.TARGET_MODEL_KEYS)),
            contract.MODEL_ORDER,
        )
        self.assertFalse(
            set(contract.PRESERVED_MODEL_KEYS) & set(contract.TARGET_MODEL_KEYS)
        )

    def test_tools_search_retrieval_and_external_context_remain_disabled(self) -> None:
        scope = contract.authorization_scope()
        self.assertIs(scope["tools_enabled"], False)
        self.assertIs(scope["web_search_enabled"], False)
        self.assertIs(scope["retrieval_enabled"], False)
        self.assertIs(scope["external_context_enabled"], False)

    def test_six_route_preflight_and_request_ceilings_are_exact(self) -> None:
        self.assertEqual(len(contract.PREFLIGHT_ROUTE_KEYS), 6)
        self.assertEqual(len(set(contract.PREFLIGHT_ROUTE_KEYS)), 6)
        self.assertEqual(
            contract.MAX_PREFLIGHT_REQUESTS,
            len(contract.PREFLIGHT_ROUTE_KEYS) * contract.PREFLIGHT_ATTEMPTS_PER_MODEL,
        )
        self.assertEqual(successor_execute._attempt_range("qwen"), (2, 3))
        self.assertEqual(contract.MAX_GENERATION_POSTS, 2 + 4 * 3)
        self.assertEqual(
            contract.MAX_OUTBOUND_REQUESTS,
            contract.MAX_PREFLIGHT_REQUESTS + contract.MAX_GENERATION_POSTS,
        )

    def test_first_recovery_sources_and_lock_remain_byte_bound(self) -> None:
        context = load_and_validate_recovery_lock(
            Path(__file__).resolve().parents[2], require_committed=False
        )
        self.assertEqual(context.lock_sha256, contract.FIRST_LOCK_SHA256)
        source_paths = {
            item["path"] for item in context.lock.get("execution_sources", [])
        }
        self.assertTrue(source_paths)
        self.assertFalse(
            any(path.startswith("harness/qwen_successor/") for path in source_paths)
        )
        self.assertFalse(any("qwen_successor" in path for path in source_paths))

    def test_new_source_names_do_not_enter_first_recovery_discovery_namespace(
        self,
    ) -> None:
        self.assertTrue(contract.NEW_SOURCE_PATHS)
        for path in contract.NEW_SOURCE_PATHS:
            with self.subTest(path=path):
                self.assertNotIn("concordance_recovery", path)

    def test_inherited_budget_counts_the_stranded_qwen_reservation(self) -> None:
        self.assertEqual(first_contract.PARENT_RESERVED_MICRODOLLARS, 1_018_232)
        self.assertEqual(contract.RESERVED_PER_POST["qwen"], 49_243)
        self.assertEqual(
            first_contract.PARENT_RESERVED_MICRODOLLARS
            + contract.RESERVED_PER_POST["qwen"],
            contract.INHERITED_RESERVED_MICRODOLLARS,
        )

    def test_successor_parent_contract_is_exact_and_type_sensitive(self) -> None:
        expected = parent_module._expected_parent_contract()
        parent_module._validate_successor_parent_contract({"parent": expected})

        changed = copy.deepcopy(expected)
        changed["first_private_binding_count"] = True
        with self.assertRaisesRegex(RecoveryJournalError, "parent contract changed"):
            parent_module._validate_successor_parent_contract({"parent": changed})


class QwenSuccessorStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.paths = SuccessorPaths.for_repository(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_paths_are_isolated_and_claim_exactly_the_stranded_qwen(self) -> None:
        self.assertEqual(
            self.paths.private_root,
            self.root / contract.PRIVATE_ROOT_RELATIVE,
        )
        self.assertEqual(
            self.paths.claim,
            self.root
            / contract.CLAIM_ROOT_RELATIVE
            / f"{contract.QWEN_STRANDED_INTENT_SHA256}.json",
        )
        self.assertEqual(
            self.paths.phase_lock,
            self.paths.claim.with_suffix(".lock"),
        )
        self.assertEqual(
            self.paths.generation_intent("qwen", 2)
            .relative_to(self.paths.private_root)
            .as_posix(),
            "generation/intents/qwen/attempt-2.json",
        )

    def test_path_builder_rejects_traversal_and_nonpositive_attempts(self) -> None:
        with self.assertRaisesRegex(RecoveryJournalError, "safe canonical"):
            self.paths.generation_intent("../qwen", 2)
        for attempt in (0, -1, True):
            with self.subTest(attempt=attempt):
                with self.assertRaisesRegex(RecoveryJournalError, "positive integer"):
                    self.paths.generation_intent("qwen", attempt)

    def test_every_preflight_route_key_is_a_safe_journal_path_component(self) -> None:
        for route_key in contract.PREFLIGHT_ROUTE_KEYS:
            with self.subTest(route_key=route_key):
                path = self.paths.preflight_intent(route_key, 1)
                self.assertEqual(
                    path.relative_to(self.paths.private_root).as_posix(),
                    f"preflight/intents/{route_key}/attempt-1.json",
                )

    def test_phase_lock_is_private_empty_and_single_flight_capable(self) -> None:
        async def exercise() -> None:
            async with phase_lock(self.paths.phase_lock):
                metadata = self.paths.phase_lock.lstat()
                self.assertTrue(stat.S_ISREG(metadata.st_mode))
                self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
                self.assertEqual(metadata.st_size, 0)
                self.assertEqual(metadata.st_nlink, 1)

        asyncio.run(exercise())

    def test_phase_lock_rejects_nonempty_existing_file(self) -> None:
        self.paths.phase_lock.parent.mkdir(parents=True, mode=0o700)
        self.paths.phase_lock.write_text("not empty", encoding="utf-8")
        self.paths.phase_lock.chmod(0o600)

        async def exercise() -> None:
            async with phase_lock(self.paths.phase_lock):
                self.fail("unsafe phase lock was accepted")

        with self.assertRaisesRegex(RecoveryJournalError, "must remain an empty"):
            asyncio.run(exercise())


class QwenSuccessorParentInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve() / "first"
        self.expected = {
            "generation/intents/cohere/attempt-2.json",
            "generation/intents/qwen/attempt-1.json",
            "manifests/six-model-preflight.json",
        }
        make_private_tree(self.root, self.expected)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_exact_tree_accepts_only_bound_files_directories_and_empty_capture_dir(
        self,
    ) -> None:
        parent_module._inspect_exact_private_tree(self.root, self.expected)

    def test_exact_tree_rejects_an_extra_file(self) -> None:
        extra = self.root / "generation/outcomes/qwen/attempt-1.json"
        extra.parent.mkdir(parents=True, mode=0o700)
        chmod_private_ancestors(extra.parent, self.root)
        extra.write_bytes(b"{}\n")
        extra.chmod(0o600)
        with self.assertRaisesRegex(RecoveryJournalError, "inventory changed"):
            parent_module._inspect_exact_private_tree(self.root, self.expected)

    def test_exact_tree_rejects_an_extra_empty_directory(self) -> None:
        extra = self.root / "generation/outcomes/qwen"
        extra.mkdir(parents=True, mode=0o700)
        chmod_private_ancestors(extra, self.root)
        with self.assertRaisesRegex(RecoveryJournalError, "inventory changed"):
            parent_module._inspect_exact_private_tree(self.root, self.expected)

    def test_exact_tree_rejects_a_missing_bound_file(self) -> None:
        (self.root / "generation/intents/qwen/attempt-1.json").unlink()
        with self.assertRaisesRegex(RecoveryJournalError, "inventory changed"):
            parent_module._inspect_exact_private_tree(self.root, self.expected)

    def test_required_absence_rejects_even_a_broken_symlink(self) -> None:
        first_root = Path(self.temporary.name).resolve() / "absence"
        first_root.mkdir(mode=0o700)
        parent_module._validate_required_absences(first_root)
        forbidden = first_root / contract.FIRST_REQUIRED_ABSENT[0]
        forbidden.parent.mkdir(parents=True, mode=0o700)
        os.symlink("missing-target", forbidden)
        with self.assertRaisesRegex(RecoveryJournalError, "absence changed"):
            parent_module._validate_required_absences(first_root)

    def test_generation_reserve_inventory_includes_qwen_attempt_one(self) -> None:
        records = {
            "generation/intents/cohere/attempt-2.json": record(
                self.root / "cohere.json", {"reserved_cost_microdollars": 0}
            ),
            contract.QWEN_STRANDED_INTENT_PATH: record(
                self.root / "qwen.json",
                {"reserved_cost_microdollars": contract.RESERVED_PER_POST["qwen"]},
                2,
            ),
        }
        self.assertEqual(
            parent_module._first_generation_reserve(records),
            contract.RESERVED_PER_POST["qwen"],
        )
        records.pop(contract.QWEN_STRANDED_INTENT_PATH)
        with self.assertRaisesRegex(RecoveryJournalError, "intent inventory changed"):
            parent_module._first_generation_reserve(records)


class QwenSuccessorBootstrapTests(unittest.TestCase):
    seed_temporary: tempfile.TemporaryDirectory
    seed_root: Path
    seed_home: Path
    sealed_lock: dict

    @classmethod
    def setUpClass(cls) -> None:
        cls.seed_temporary = tempfile.TemporaryDirectory()
        temporary = Path(cls.seed_temporary.name).resolve()
        cls.seed_root = temporary / "seed"
        cls.seed_home = temporary / "seed-home"
        cls.seed_root.mkdir()
        cls.seed_home.mkdir()

        source = Path(__file__).resolve().parents[2]
        cls.sealed_lock = build_lock(source)
        declared, paths = _bindings(cls.sealed_lock)
        for relative in declared:
            destination = cls.seed_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source / relative, destination)
        lock_path = cls.seed_root / contract.LOCK_PATH
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path.write_bytes(
            (json.dumps(cls.sealed_lock, ensure_ascii=False, indent=2) + "\n").encode(
                "utf-8"
            )
        )

        run_git(cls.seed_root, ["init", "--quiet"], home=cls.seed_home)
        run_git(cls.seed_root, ["add", "--", *paths], home=cls.seed_home)
        run_git(
            cls.seed_root,
            [
                "-c",
                "user.name=Qwen Successor Bootstrap Test",
                "-c",
                "user.email=successor@example.invalid",
                "commit",
                "--quiet",
                "--no-gpg-sign",
                "-m",
                "seal synthetic successor",
            ],
            home=cls.seed_home,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.seed_temporary.cleanup()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        temporary = Path(self.temporary.name).resolve()
        self.root = temporary / "repo"
        self.home = temporary / "home"
        self.home.mkdir()
        run_git(
            temporary,
            [
                "clone",
                "--quiet",
                "--no-hardlinks",
                str(self.seed_root),
                str(self.root),
            ],
            home=self.home,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def head(self) -> str:
        result = run_git(
            self.root,
            ["rev-parse", "--verify", "HEAD"],
            home=self.home,
            text=True,
        )
        return result.stdout.strip()

    def run_runner(self, *, isolated: bool) -> subprocess.CompletedProcess:
        command = [sys.executable]
        if isolated:
            command.append("-I")
        command.extend(["harness/run_qwen_successor.py", "--dry-run"])
        return subprocess.run(
            command,
            cwd=self.root,
            check=False,
            capture_output=True,
            text=True,
            env={
                "HOME": str(self.home),
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
            },
        )

    def test_accepts_exact_clean_committed_successor_bindings(self) -> None:
        self.assertEqual(_preimport_bootstrap(self.root), self.head())

    def test_every_below_gate_source_is_mandatory(self) -> None:
        lock = copy.deepcopy(self.sealed_lock)
        missing = "harness/qwen_successor/state.py"
        lock["execution_sources"] = [
            item for item in lock["execution_sources"] if item["path"] != missing
        ]
        with self.assertRaisesRegex(
            PreImportSuccessorError, "omits project code imported below the gate"
        ) as raised:
            _bindings(lock)
        self.assertIn(missing, str(raised.exception))

    def test_malformed_top_binding_fails_closed_without_attribute_error(self) -> None:
        for malformed in ("not-a-binding", [], None):
            with self.subTest(malformed=malformed):
                lock = copy.deepcopy(self.sealed_lock)
                lock["bindings"]["first_recovery_lock"] = malformed
                with self.assertRaisesRegex(
                    PreImportSuccessorError, "malformed binding"
                ):
                    _bindings(lock)

    def test_tampered_bound_source_is_rejected_before_import(self) -> None:
        sentinel = self.root / "tampered-source-imported"
        source = self.root / "harness/qwen_successor/execute.py"
        source.write_bytes(
            source.read_bytes()
            + (
                "\nfrom pathlib import Path\n"
                f"Path({str(sentinel)!r}).write_text('ran')\n"
            ).encode("utf-8")
        )
        with self.assertRaisesRegex(
            PreImportSuccessorError, "working bytes differ from the successor lock"
        ):
            _preimport_bootstrap(self.root)
        self.assertFalse(sentinel.exists())

    def test_duplicate_or_noncanonical_lock_is_rejected(self) -> None:
        with self.assertRaisesRegex(PreImportSuccessorError, "duplicate successor"):
            _load_lock(b'{"status":"one","status":"two"}\n')
        canonical = (json.dumps(self.sealed_lock, ensure_ascii=False) + "\n").encode(
            "utf-8"
        )
        with self.assertRaisesRegex(PreImportSuccessorError, "not canonical JSON"):
            _load_lock(canonical)

    def test_nonisolated_runner_stops_before_project_imports(self) -> None:
        result = self.run_runner(isolated=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("use python3 -I", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_isolated_gate_rejects_import_shadow_without_executing_it(self) -> None:
        sentinel = self.root / "shadow-imported"
        (self.root / "harness/json.py").write_text(
            "from pathlib import Path\n" f"Path({str(sentinel)!r}).write_text('ran')\n",
            encoding="utf-8",
        )
        result = self.run_runner(isolated=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("local import shadow", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertFalse(sentinel.exists())


class FirstRunnerTerminalityTests(unittest.TestCase):
    def test_stranded_old_qwen_intent_stops_before_capture_or_validation(self) -> None:
        intent = record(
            Path("synthetic-qwen-intent.json"),
            {"semantic_attempt_number": 1},
        )
        call = SimpleNamespace(
            cell_id=f"{contract.CANDIDATE_ID}:qwen:default:answer",
            model=SimpleNamespace(model_key="qwen"),
        )
        finalize = mock.AsyncMock(
            side_effect=AssertionError("capture finalization must not run")
        )
        validate = mock.AsyncMock(
            side_effect=AssertionError("outcome validation must not run")
        )
        with (
            mock.patch.object(
                first_execute,
                "_generation_history",
                return_value=[(intent, None, None)],
            ),
            mock.patch.object(first_execute, "_finalize_generation_capture", finalize),
            mock.patch.object(first_execute, "_validate_generation_outcome", validate),
        ):
            with self.assertRaisesRegex(StrandedGenerationIntent, "no replay allowed"):
                asyncio.run(
                    first_execute._reconcile_generation(
                        SimpleNamespace(),
                        SimpleNamespace(),
                        SimpleNamespace(),
                        record(Path("manifest.json"), {}, 3),
                        record(Path("preflight.json"), {}, 4),
                        call,
                    )
                )
        finalize.assert_not_awaited()
        validate.assert_not_awaited()


class SuccessorGenerationStateTests(unittest.TestCase):
    class Paths:
        def __init__(self, root: Path) -> None:
            self.root = root

        def generation_intent(self, model_key: str, attempt: int) -> Path:
            return self.root / f"intents/{model_key}/attempt-{attempt}.json"

        def generation_raw(self, model_key: str, attempt: int) -> Path:
            return self.root / f"raw/{model_key}/attempt-{attempt}.json"

        def generation_outcome(self, model_key: str, attempt: int) -> Path:
            return self.root / f"outcomes/{model_key}/attempt-{attempt}.json"

    class RouteSelected(RuntimeError):
        pass

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.paths = self.Paths(self.root)
        self.deepinfra = SimpleNamespace(
            cell_id=f"{contract.CANDIDATE_ID}:qwen:default:answer",
            model=SimpleNamespace(
                model_key="qwen",
                route="deepinfra",
                environment_variable="DEEPINFRA_API_KEY",
            ),
        )
        self.openrouter = SimpleNamespace(
            cell_id=self.deepinfra.cell_id,
            model=SimpleNamespace(
                model_key="qwen",
                route=contract.QWEN_OPENROUTER["route"],
                environment_variable="OPENROUTER_API_KEY",
            ),
        )
        self.prepared = SimpleNamespace(
            fallback_call=self.openrouter,
            paths=self.paths,
        )
        self.intent2 = record(
            self.paths.generation_intent("qwen", 2),
            {"semantic_attempt_number": 2},
            20,
        )
        self.intent3 = record(
            self.paths.generation_intent("qwen", 3),
            {"semantic_attempt_number": 3},
            30,
        )
        self.preflight2 = record(self.root / "preflight-deepinfra.json", {}, 21)
        self.preflight3 = record(self.root / "preflight-openrouter.json", {}, 31)
        self.raw2 = record(self.paths.generation_raw("qwen", 2), {}, 22)
        self.error2 = record(
            self.paths.generation_outcome("qwen", 2),
            {"status": "error", "error": {"retryable": False}},
            23,
        )
        self.consumed2 = record(
            self.paths.generation_outcome("qwen", 2),
            {"status": "consumed-without-capture"},
            24,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def reconcile(self, history: list[tuple]) -> tuple:
        with (
            mock.patch.object(
                successor_execute, "_generation_history", return_value=history
            ),
            mock.patch.object(
                successor_execute,
                "_validate_generation_outcome",
                new=mock.AsyncMock(return_value=None),
            ),
        ):
            return asyncio.run(
                successor_execute._reconcile_generation(
                    self.prepared,
                    SimpleNamespace(),
                    SimpleNamespace(),
                    record(self.root / "manifest.json", {}, 40),
                    {},
                    self.deepinfra,
                )
            )

    def assert_next_post_is_openrouter_attempt_three(
        self, history: list[tuple]
    ) -> None:
        reserve = mock.Mock(side_effect=self.RouteSelected("selected"))
        with (
            mock.patch.object(
                successor_execute, "_generation_history", return_value=history
            ),
            mock.patch.object(successor_execute, "_reserve_generation", reserve),
        ):
            with self.assertRaisesRegex(self.RouteSelected, "selected"):
                asyncio.run(
                    successor_execute._run_generation(
                        self.prepared,
                        SimpleNamespace(),
                        SimpleNamespace(),
                        record(self.root / "manifest.json", {}, 40),
                        {"qwen-openrouter": self.preflight3},
                        self.deepinfra,
                        secrets={},
                        transport=SimpleNamespace(),
                        limiters={},
                    )
                )
        reserve.assert_called_once()
        arguments = reserve.call_args.args
        self.assertIs(arguments[5], self.openrouter)
        self.assertEqual(arguments[6], 3)

    def test_deepinfra_no_capture_is_consumed_then_selects_openrouter_once(
        self,
    ) -> None:
        no_capture = (
            self.deepinfra,
            self.preflight2,
            self.intent2,
            None,
            None,
        )
        write = mock.Mock(return_value=self.consumed2)
        validate = mock.AsyncMock(return_value=None)
        with (
            mock.patch.object(
                successor_execute,
                "_generation_history",
                return_value=[no_capture],
            ),
            mock.patch.object(
                successor_execute,
                "_consumed_without_capture_payload",
                return_value=self.consumed2.payload,
            ),
            mock.patch.object(successor_execute, "write_record", write),
            mock.patch.object(
                successor_execute, "_validate_generation_outcome", validate
            ),
        ):
            result = asyncio.run(
                successor_execute._reconcile_generation(
                    self.prepared,
                    SimpleNamespace(),
                    SimpleNamespace(),
                    record(self.root / "manifest.json", {}, 40),
                    {},
                    self.deepinfra,
                )
            )
        self.assertEqual(result, (None, True, None))
        write.assert_called_once_with(
            self.paths.generation_outcome("qwen", 2), self.consumed2.payload
        )
        validate.assert_awaited_once()

        consumed_history = [
            (
                self.deepinfra,
                self.preflight2,
                self.intent2,
                None,
                self.consumed2,
            )
        ]
        self.assert_next_post_is_openrouter_attempt_three(consumed_history)

        full_history = [
            *consumed_history,
            (self.openrouter, self.preflight3, self.intent3, None, None),
        ]
        reserve = mock.Mock()
        with (
            mock.patch.object(
                successor_execute, "_generation_history", return_value=full_history
            ),
            mock.patch.object(successor_execute, "_reserve_generation", reserve),
        ):
            with self.assertRaisesRegex(
                successor_execute.SuccessorExecutionError, "POST ceiling exceeded"
            ):
                asyncio.run(
                    successor_execute._run_generation(
                        self.prepared,
                        SimpleNamespace(),
                        SimpleNamespace(),
                        record(self.root / "manifest.json", {}, 40),
                        {"qwen-openrouter": self.preflight3},
                        self.deepinfra,
                        secrets={},
                        transport=SimpleNamespace(),
                        limiters={},
                    )
                )
        reserve.assert_not_called()

    def test_captured_deepinfra_error_advances_to_openrouter(self) -> None:
        history = [
            (
                self.deepinfra,
                self.preflight2,
                self.intent2,
                self.raw2,
                self.error2,
            )
        ]
        self.assertEqual(self.reconcile(history), (None, True, None))
        self.assert_next_post_is_openrouter_attempt_three(history)

    def test_openrouter_no_capture_is_terminal_on_every_restart(self) -> None:
        history = [
            (
                self.deepinfra,
                self.preflight2,
                self.intent2,
                None,
                self.consumed2,
            ),
            (self.openrouter, self.preflight3, self.intent3, None, None),
        ]
        for restart in range(2):
            with self.subTest(restart=restart):
                result = self.reconcile(history)
                self.assertIsNone(result[0])
                self.assertIs(result[1], False)
                self.assertIn("stranded successor intent is terminal", result[2])

        reserve = mock.Mock()
        with (
            mock.patch.object(
                successor_execute, "_generation_history", return_value=history
            ),
            mock.patch.object(successor_execute, "_reserve_generation", reserve),
        ):
            with self.assertRaisesRegex(
                successor_execute.SuccessorExecutionError, "POST ceiling exceeded"
            ):
                asyncio.run(
                    successor_execute._run_generation(
                        self.prepared,
                        SimpleNamespace(),
                        SimpleNamespace(),
                        record(self.root / "manifest.json", {}, 40),
                        {"qwen-openrouter": self.preflight3},
                        self.deepinfra,
                        secrets={},
                        transport=SimpleNamespace(),
                        limiters={},
                    )
                )
        reserve.assert_not_called()

    def test_deepinfra_success_rejects_any_openrouter_generation_state(self) -> None:
        success2 = record(
            self.paths.generation_outcome("qwen", 2), {"status": "success"}, 25
        )
        raw3 = record(self.paths.generation_raw("qwen", 3), {}, 32)
        outcome3 = record(
            self.paths.generation_outcome("qwen", 3), {"status": "success"}, 33
        )
        history = [
            (
                self.deepinfra,
                self.preflight2,
                self.intent2,
                self.raw2,
                success2,
            ),
            (self.openrouter, self.preflight3, self.intent3, raw3, outcome3),
        ]
        with (
            mock.patch.object(
                successor_execute, "_generation_history", return_value=history
            ),
            mock.patch.object(
                successor_execute,
                "_validate_generation_outcome",
                new=mock.AsyncMock(return_value=SimpleNamespace()),
            ),
        ):
            with self.assertRaisesRegex(
                successor_execute.SuccessorExecutionError,
                "generation attempt follows success",
            ):
                asyncio.run(
                    successor_execute._reconcile_generation(
                        self.prepared,
                        SimpleNamespace(),
                        SimpleNamespace(),
                        record(self.root / "manifest.json", {}, 40),
                        {},
                        self.deepinfra,
                    )
                )

    def test_downstream_reconciliation_requires_qwen_success(self) -> None:
        deepseek = SimpleNamespace(
            cell_id=f"{contract.CANDIDATE_ID}:deepseek:default:answer",
            model=SimpleNamespace(model_key="deepseek"),
        )
        prepared = SimpleNamespace(
            target_plan=(self.deepinfra, deepseek),
            paths=self.paths,
        )
        terminal = mock.AsyncMock(return_value=(None, False, "Qwen fallback terminal"))
        with mock.patch.object(successor_execute, "_reconcile_generation", terminal):
            result = asyncio.run(
                successor_execute._reconcile_composite(
                    prepared,
                    SimpleNamespace(),
                    SimpleNamespace(),
                    record(self.root / "manifest.json", {}, 40),
                    {},
                )
            )
        self.assertEqual(result, (None, False, "Qwen fallback terminal"))
        terminal.assert_awaited_once()
        self.assertIs(terminal.call_args.args[5], self.deepinfra)

        qwen_success = record(
            self.paths.generation_outcome("qwen", 2), {"status": "success"}, 50
        )
        gate = mock.AsyncMock(
            side_effect=[
                (qwen_success, False, None),
                (None, True, None),
            ]
        )
        with mock.patch.object(successor_execute, "_reconcile_generation", gate):
            result = asyncio.run(
                successor_execute._reconcile_composite(
                    prepared,
                    SimpleNamespace(),
                    SimpleNamespace(),
                    record(self.root / "manifest.json", {}, 40),
                    {},
                )
            )
        self.assertEqual(result, (None, True, None))
        self.assertEqual(gate.await_count, 2)
        self.assertIs(gate.await_args_list[0].args[5], self.deepinfra)
        self.assertIs(gate.await_args_list[1].args[5], deepseek)


if __name__ == "__main__":
    unittest.main()
