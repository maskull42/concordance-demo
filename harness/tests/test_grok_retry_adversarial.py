from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from concordance_harness.config import load_harness_config  # noqa: E402
from concordance_harness.providers import (  # noqa: E402
    HttpResponse,
    ProviderAdapter,
    ProviderError,
)
from concordance_recovery.journal import (  # noqa: E402
    JournalRecord,
    RecoveryJournalError,
    raw_response_payload,
    read_record,
    write_record,
)
from grok_retry import contract  # noqa: E402
from grok_retry import execute  # noqa: E402
from grok_retry import parent as parent_module  # noqa: E402
from grok_retry.authorization import ReceiptBinding  # noqa: E402
from grok_retry.lock import build_lock  # noqa: E402
from grok_retry.state import GrokRetryPaths, phase_lock  # noqa: E402
from qwen_successor import execute as qwen_execute  # noqa: E402
from run_grok_retry import (  # noqa: E402
    PreImportRetryError,
    _bindings,
    _load_lock,
    _preimport_bootstrap,
)


GIT = "/usr/bin/git"
T0 = "2026-07-13T17:00:00+00:00"
T1 = "2026-07-13T17:01:00+00:00"


def record(path: Path, payload: dict, seed: int = 1) -> JournalRecord:
    return JournalRecord(path=path, payload=payload, sha256=f"{seed:064x}")


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


def make_private_tree(root: Path, relative_files: set[str]) -> None:
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    directories: set[str] = set()
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


class GrokRetryContractTests(unittest.TestCase):
    def test_preserved_and_target_models_are_exact_disjoint_and_complete(self) -> None:
        self.assertEqual(
            contract.PRESERVED_MODEL_KEYS,
            ("gemini", "claude", "cohere", "qwen", "deepseek", "mistral"),
        )
        self.assertEqual(contract.TARGET_MODEL_KEYS, ("grok", "gpt"))
        self.assertEqual(
            tuple((*contract.PRESERVED_MODEL_KEYS, *contract.TARGET_MODEL_KEYS)),
            contract.MODEL_ORDER,
        )
        self.assertFalse(
            set(contract.PRESERVED_MODEL_KEYS) & set(contract.TARGET_MODEL_KEYS)
        )

    def test_scope_allows_only_one_direct_xai_grok_then_pinned_gpt(self) -> None:
        scope = contract.authorization_scope()
        self.assertEqual(scope["grok_semantic_attempt_number"], 2)
        self.assertEqual(scope["grok_maximum_posts"], 1)
        self.assertEqual(scope["grok_provider"], "xai")
        self.assertEqual(scope["grok_route"], "xai-direct")
        self.assertEqual(scope["grok_requested_model_id"], "grok-4.5")
        self.assertIs(scope["gpt_requires_grok_success"], True)
        self.assertEqual(scope["gpt_maximum_safe_attempts"], 3)
        self.assertEqual(scope["gpt_provider"], "openrouter")
        self.assertEqual(scope["gpt_route"], "openrouter-openai-pinned")
        self.assertIs(scope["alternative_provider_allowed"], False)
        self.assertIs(scope["fresh_metadata_requests_allowed"], False)
        self.assertEqual(contract.MAX_PREFLIGHT_REQUESTS, 0)
        self.assertEqual(contract.MAX_GENERATION_POSTS, 4)
        self.assertEqual(contract.MAX_OUTBOUND_REQUESTS, 4)

    def test_tools_search_retrieval_and_external_context_remain_disabled(self) -> None:
        scope = contract.authorization_scope()
        self.assertIs(scope["tools_enabled"], False)
        self.assertIs(scope["web_search_enabled"], False)
        self.assertIs(scope["retrieval_enabled"], False)
        self.assertIs(scope["external_context_enabled"], False)

    def test_exact_user_amendment_and_resolved_authority_are_bound(self) -> None:
        self.assertEqual(
            contract.USER_AMENDMENT,
            "Try Grok 4.5 again through xAI.",
        )
        self.assertIn(
            "exactly one replacement Grok generation", contract.AUTHORIZATION_STATEMENT
        )
        self.assertIn("through xAI direct", contract.AUTHORIZATION_STATEMENT)
        self.assertIn("only after Grok succeeds", contract.AUTHORIZATION_STATEMENT)
        self.assertIn(
            "no tools, web search, retrieval", contract.AUTHORIZATION_STATEMENT
        )

    def test_parent_inventory_and_critical_grok_hashes_are_exact(self) -> None:
        self.assertEqual(len(contract.QWEN_PRIVATE_SHA256), 34)
        self.assertEqual(
            len(parent_module._expected_directories(set(contract.QWEN_PRIVATE_SHA256))),
            39,
        )
        self.assertEqual(
            contract.QWEN_PRIVATE_SHA256[contract.GROK_ERROR_INTENT_PATH],
            contract.GROK_ERROR_INTENT_SHA256,
        )
        self.assertEqual(
            contract.QWEN_PRIVATE_SHA256[contract.GROK_ERROR_RAW_PATH],
            contract.GROK_ERROR_RAW_SHA256,
        )
        self.assertEqual(
            contract.QWEN_PRIVATE_SHA256[contract.GROK_ERROR_OUTCOME_PATH],
            contract.GROK_ERROR_OUTCOME_SHA256,
        )
        self.assertEqual(
            contract.GROK_REQUEST_BODY_SHA256,
            "d9a5b1994fc18a4dbc4e3f42f6617a97e63f5988f49eef1f64c3fc47aa394de5",
        )
        self.assertIn(
            f"runs/{contract.CANDIDATE_ID}.json",
            contract.QWEN_REQUIRED_ABSENT,
        )
        for attempt in (2, 3):
            for kind in ("intents", "raw-responses", "outcomes"):
                self.assertIn(
                    f"generation/{kind}/grok/attempt-{attempt}.json",
                    contract.QWEN_REQUIRED_ABSENT,
                )
        for attempt in (1, 2, 3):
            for kind in ("intents", "raw-responses", "outcomes"):
                self.assertIn(
                    f"generation/{kind}/gpt/attempt-{attempt}.json",
                    contract.QWEN_REQUIRED_ABSENT,
                )

    def test_budget_counts_every_prior_and_possible_new_post(self) -> None:
        self.assertEqual(contract.INHERITED_RESERVED_MICRODOLLARS, 1_254_445)
        self.assertEqual(contract.RESERVED_PER_POST, {"grok": 98_708, "gpt": 492_530})
        maximum_new = (
            contract.RESERVED_PER_POST["grok"] + 3 * contract.RESERVED_PER_POST["gpt"]
        )
        self.assertEqual(maximum_new, contract.NEW_RESERVED_CAP_MICRODOLLARS)
        self.assertEqual(
            contract.INHERITED_RESERVED_MICRODOLLARS + maximum_new,
            contract.COMBINED_RESERVED_CAP_MICRODOLLARS,
        )
        self.assertLessEqual(
            contract.COMBINED_RESERVED_CAP_MICRODOLLARS,
            contract.CANDIDATE_CAP_MICRODOLLARS,
        )
        self.assertLessEqual(
            contract.COMBINED_RESERVED_CAP_MICRODOLLARS,
            contract.POOL_CAP_MICRODOLLARS,
        )

    def test_grok_retry_body_is_identical_direct_xai_and_tool_free(self) -> None:
        root = Path(__file__).resolve().parents[2]
        prepared = qwen_execute.prepare_successor(root, require_committed=False)
        call = prepared.target_by_key["grok"]
        request = ProviderAdapter(call.model, object()).build_generation_request(
            "redacted-offline-secret", call.answer_messages()
        )
        body_sha256 = hashlib.sha256(
            json.dumps(request.json_body, ensure_ascii=False).encode("utf-8")
        ).hexdigest()

        self.assertEqual(request.method, "POST")
        self.assertEqual(request.url, "https://api.x.ai/v1/responses")
        self.assertEqual(body_sha256, contract.GROK_REQUEST_BODY_SHA256)
        self.assertEqual(request.json_body["model"], "grok-4.5")
        self.assertEqual(request.json_body["tools"], [])
        self.assertEqual(request.json_body["max_output_tokens"], 16_384)
        self.assertEqual(request.json_body["temperature"], 0.2)
        self.assertEqual(request.json_body["store"], False)
        self.assertEqual(request.json_body["service_tier"], "default")
        self.assertFalse(
            {
                "web_search",
                "retrieval",
                "plugins",
                "attachments",
                "files",
                "tool_choice",
            }
            & set(request.json_body)
        )

    def test_gpt_remains_pinned_to_openai_without_fallbacks(self) -> None:
        config = load_harness_config(
            Path(__file__).resolve().parents[2] / "harness/config/models.json"
        )
        gpt = config.by_key()["gpt"]
        self.assertEqual(gpt.provider, "openrouter")
        self.assertEqual(gpt.route, "openrouter-openai-pinned")
        self.assertEqual(gpt.requested_model_id, "openai/gpt-5.6-sol")
        self.assertIs(gpt.fallback_allowed, False)
        self.assertEqual(
            gpt.provider_options["provider"],
            {
                "only": ["openai"],
                "allow_fallbacks": False,
                "require_parameters": True,
            },
        )


class GrokRetryStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.paths = GrokRetryPaths.for_repository(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_paths_are_isolated_and_claim_the_captured_grok_error(self) -> None:
        self.assertEqual(
            self.paths.private_root,
            self.root / contract.PRIVATE_ROOT_RELATIVE,
        )
        self.assertEqual(
            self.paths.claim,
            self.root
            / contract.CLAIM_ROOT_RELATIVE
            / f"{contract.GROK_ERROR_OUTCOME_SHA256}.json",
        )
        self.assertEqual(self.paths.phase_lock, self.paths.claim.with_suffix(".lock"))
        self.assertEqual(
            self.paths.generation_intent("grok", 2)
            .relative_to(self.paths.private_root)
            .as_posix(),
            "generation/intents/grok/attempt-2.json",
        )
        self.assertEqual(
            self.paths.generation_intent("gpt", 1)
            .relative_to(self.paths.private_root)
            .as_posix(),
            "generation/intents/gpt/attempt-1.json",
        )

    def test_path_builder_rejects_traversal_bad_kind_and_nonpositive_attempts(
        self,
    ) -> None:
        with self.assertRaisesRegex(RecoveryJournalError, "safe canonical"):
            self.paths.generation_intent("../grok", 2)
        with self.assertRaisesRegex(RecoveryJournalError, "not approved"):
            self.paths._attempt_path("unlocked", "grok", 2)
        for attempt in (0, -1, True):
            with self.subTest(attempt=attempt):
                with self.assertRaisesRegex(RecoveryJournalError, "positive integer"):
                    self.paths.generation_intent("grok", attempt)

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


class GrokRetryParentInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve() / "parent"
        self.expected = {
            contract.GROK_ERROR_INTENT_PATH,
            contract.GROK_ERROR_RAW_PATH,
            contract.GROK_ERROR_OUTCOME_PATH,
            contract.QWEN_MANIFEST_PATH,
        }
        make_private_tree(self.root, self.expected)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_exact_tree_accepts_only_bound_files_and_directories(self) -> None:
        parent_module._inspect_exact_private_tree(self.root, self.expected)

    def test_exact_tree_rejects_extra_file_directory_and_missing_file(self) -> None:
        extra = self.root / "generation/outcomes/gpt/attempt-1.json"
        extra.parent.mkdir(parents=True, mode=0o700)
        chmod_private_ancestors(extra.parent, self.root)
        extra.write_bytes(b"{}\n")
        extra.chmod(0o600)
        with self.assertRaisesRegex(RecoveryJournalError, "inventory changed"):
            parent_module._inspect_exact_private_tree(self.root, self.expected)

        extra.unlink()
        extra.parent.rmdir()
        empty = self.root / "generation/outcomes/gpt"
        empty.mkdir(parents=True, mode=0o700)
        chmod_private_ancestors(empty, self.root)
        with self.assertRaisesRegex(RecoveryJournalError, "inventory changed"):
            parent_module._inspect_exact_private_tree(self.root, self.expected)

        empty.rmdir()
        (self.root / contract.GROK_ERROR_RAW_PATH).unlink()
        with self.assertRaisesRegex(RecoveryJournalError, "inventory changed"):
            parent_module._inspect_exact_private_tree(self.root, self.expected)

    def test_exact_tree_rejects_symlinks_bad_modes_and_hardlinks(self) -> None:
        target = self.root / contract.GROK_ERROR_RAW_PATH
        target.unlink()
        os.symlink("missing-target", target)
        with self.assertRaisesRegex(RecoveryJournalError, "symlink"):
            parent_module._inspect_exact_private_tree(self.root, self.expected)

        target.unlink()
        target.write_bytes(b"{}\n")
        target.chmod(0o644)
        with self.assertRaisesRegex(RecoveryJournalError, "single-link mode-0600"):
            parent_module._inspect_exact_private_tree(self.root, self.expected)

        target.chmod(0o600)
        hardlink = Path(self.temporary.name).resolve() / "hardlink.json"
        os.link(target, hardlink)
        with self.assertRaisesRegex(RecoveryJournalError, "single-link mode-0600"):
            parent_module._inspect_exact_private_tree(self.root, self.expected)

    def test_required_absence_rejects_even_a_broken_symlink(self) -> None:
        absence = Path(self.temporary.name).resolve() / "absence"
        absence.mkdir(mode=0o700)
        parent_module._validate_required_absences(absence)
        forbidden = absence / contract.QWEN_REQUIRED_ABSENT[0]
        forbidden.parent.mkdir(parents=True, mode=0o700)
        os.symlink("missing-target", forbidden)
        with self.assertRaisesRegex(RecoveryJournalError, "absence changed"):
            parent_module._validate_required_absences(absence)

    def test_parent_contract_is_exact_and_type_sensitive(self) -> None:
        expected = parent_module._expected_parent_contract()
        parent_module._validate_retry_parent_contract({"parent": expected})

        changed = copy.deepcopy(expected)
        changed["qwen_private_binding_count"] = True
        with self.assertRaisesRegex(RecoveryJournalError, "parent contract changed"):
            parent_module._validate_retry_parent_contract({"parent": changed})

    def test_generation_reserve_inventory_is_exact_and_rejects_bool(self) -> None:
        expected = {
            "generation/intents/qwen/attempt-2.json": 49_243,
            "generation/intents/deepseek/attempt-1.json": 14_342,
            "generation/intents/mistral/attempt-1.json": 24_677,
            contract.GROK_ERROR_INTENT_PATH: 98_708,
        }
        records = {
            path: record(self.root / path, {"reserved_cost_microdollars": reserve})
            for path, reserve in expected.items()
        }
        self.assertEqual(parent_module._generation_reserve(records), 186_970)

        changed = dict(records)
        changed[contract.GROK_ERROR_INTENT_PATH] = record(
            self.root / contract.GROK_ERROR_INTENT_PATH,
            {"reserved_cost_microdollars": True},
            2,
        )
        with self.assertRaisesRegex(RecoveryJournalError, "reservations changed"):
            parent_module._generation_reserve(changed)

    def test_real_parent_snapshot_semantically_validates_successes_and_403(
        self,
    ) -> None:
        root = Path(__file__).resolve().parents[2]
        evidence = parent_module.validate_parent_snapshot(root)
        self.assertEqual(evidence.reserved_microdollars, 1_254_445)
        self.assertEqual(
            tuple(
                outcome.payload["model_key"] for outcome in evidence.preserved_outcomes
            ),
            contract.PRESERVED_MODEL_KEYS,
        )
        self.assertEqual(evidence.grok_error_outcome.payload["status"], "error")
        self.assertEqual(
            evidence.grok_error_outcome.payload["error"],
            {
                "category": "authorization",
                "retryable": False,
                "sanitized_summary": "generation request failed (authorization)",
            },
        )
        self.assertEqual(evidence.grok_error_raw.payload["response"]["status"], 403)

    def test_grok_403_validator_rejects_changed_status_or_retryability(self) -> None:
        root = Path(__file__).resolve().parents[2] / contract.QWEN_PRIVATE_ROOT
        intent = read_record(root / contract.GROK_ERROR_INTENT_PATH, "Grok intent")
        raw = read_record(root / contract.GROK_ERROR_RAW_PATH, "Grok raw")
        outcome = read_record(root / contract.GROK_ERROR_OUTCOME_PATH, "Grok outcome")
        parent_module._validate_grok_error(intent, raw, outcome)

        changed_raw = copy.deepcopy(raw.payload)
        changed_raw["response"]["status"] = 200
        with self.assertRaisesRegex(RecoveryJournalError, "HTTP 403"):
            parent_module._validate_grok_error(
                intent,
                record(raw.path, changed_raw, 90),
                outcome,
            )

        changed_outcome = copy.deepcopy(outcome.payload)
        changed_outcome["error"]["retryable"] = True
        with self.assertRaisesRegex(RecoveryJournalError, "lineage changed"):
            parent_module._validate_grok_error(
                intent,
                raw,
                record(outcome.path, changed_outcome, 91),
            )


class GrokRetryBootstrapTests(unittest.TestCase):
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
                "user.name=Grok Retry Bootstrap Test",
                "-c",
                "user.email=grok-retry@example.invalid",
                "commit",
                "--quiet",
                "--no-gpg-sign",
                "-m",
                "seal synthetic Grok retry",
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
        command.extend(["harness/run_grok_retry.py", "--dry-run"])
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
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )

    def test_accepts_exact_clean_committed_retry_bindings(self) -> None:
        self.assertEqual(_preimport_bootstrap(self.root), self.head())

    def test_every_below_gate_source_is_mandatory(self) -> None:
        changed = copy.deepcopy(self.sealed_lock)
        missing = "harness/grok_retry/execute.py"
        changed["execution_sources"] = [
            item for item in changed["execution_sources"] if item["path"] != missing
        ]
        with self.assertRaisesRegex(
            PreImportRetryError,
            "omits project code imported below the gate",
        ) as raised:
            _bindings(changed)
        self.assertIn(missing, str(raised.exception))

    def test_duplicate_noncanonical_and_malformed_locks_fail_closed(self) -> None:
        with self.assertRaisesRegex(PreImportRetryError, "duplicate retry lock key"):
            _load_lock(b'{"status":"one","status":"two"}\n')
        compact = (json.dumps(self.sealed_lock, ensure_ascii=False) + "\n").encode(
            "utf-8"
        )
        with self.assertRaisesRegex(PreImportRetryError, "not canonical JSON"):
            _load_lock(compact)

        changed = copy.deepcopy(self.sealed_lock)
        changed["bindings"]["qwen_successor_lock"] = None
        with self.assertRaisesRegex(PreImportRetryError, "malformed binding"):
            _bindings(changed)

    def test_tampered_bound_source_is_rejected_before_import(self) -> None:
        sentinel = self.root / "tampered-source-imported"
        source = self.root / "harness/grok_retry/execute.py"
        source.write_bytes(
            source.read_bytes()
            + (
                "\nfrom pathlib import Path\n"
                f"Path({str(sentinel)!r}).write_text('ran')\n"
            ).encode("utf-8")
        )
        with self.assertRaisesRegex(
            PreImportRetryError, "working bytes differ from the retry lock"
        ):
            _preimport_bootstrap(self.root)
        self.assertFalse(sentinel.exists())

    def test_nonisolated_runner_stops_before_project_imports(self) -> None:
        result = self.run_runner(isolated=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("use python3 -I", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_isolated_gate_rejects_stdlib_and_project_package_shadows(self) -> None:
        attacks = (
            ("harness/json.py", "stdlib-shadow-imported"),
            ("harness/grok_retry.py", "project-shadow-imported"),
        )
        for relative, sentinel_name in attacks:
            with self.subTest(relative=relative):
                sentinel = self.root / sentinel_name
                path = self.root / relative
                path.write_text(
                    "from pathlib import Path\n"
                    f"Path({str(sentinel)!r}).write_text('ran')\n",
                    encoding="utf-8",
                )
                result = self.run_runner(isolated=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn("local import shadow", result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertFalse(sentinel.exists())
                path.unlink()

    def test_isolated_gate_rejects_unbound_module_pycache_and_symlink(self) -> None:
        package = self.root / "harness/grok_retry"
        module = package / "unbound_attack.py"
        sentinel = self.root / "unbound-module-imported"
        module.write_text(
            "from pathlib import Path\n" f"Path({str(sentinel)!r}).write_text('ran')\n",
            encoding="utf-8",
        )
        result = self.run_runner(isolated=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("package contains an unbound import shadow", result.stderr)
        self.assertFalse(sentinel.exists())
        module.unlink()

        cache = package / "__pycache__"
        cache.mkdir()
        (cache / "attack.pyc").write_bytes(b"not-bytecode")
        result = self.run_runner(isolated=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("package contains an unbound import shadow", result.stderr)
        shutil.rmtree(cache)

        target = self.root / "symlink-target.py"
        target.write_text(
            "from pathlib import Path\n" f"Path({str(sentinel)!r}).write_text('ran')\n",
            encoding="utf-8",
        )
        os.symlink(target, package / "linked_attack.py")
        result = self.run_runner(isolated=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("package contains an unbound import shadow", result.stderr)
        self.assertFalse(sentinel.exists())


class GrokRetryExecutionFixture(unittest.TestCase):
    parent: parent_module.ParentEvidence | None = None
    qwen_prepared: qwen_execute.PreparedSuccessor | None = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.repository = Path(__file__).resolve().parents[2]
        if GrokRetryExecutionFixture.parent is None:
            GrokRetryExecutionFixture.parent = parent_module.validate_parent_snapshot(
                cls.repository
            )
            GrokRetryExecutionFixture.qwen_prepared = qwen_execute.prepare_successor(
                cls.repository, require_committed=False
            )
        cls.parent = GrokRetryExecutionFixture.parent
        cls.qwen_prepared = GrokRetryExecutionFixture.qwen_prepared

    def setUp(self) -> None:
        assert self.parent is not None
        assert self.qwen_prepared is not None
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.paths = GrokRetryPaths.for_repository(self.root)
        targets = {
            key: self.qwen_prepared.target_by_key[key]
            for key in contract.TARGET_MODEL_KEYS
        }
        self.prepared = SimpleNamespace(
            repository_root=self.repository,
            paths=self.paths,
            target_plan=tuple(targets.values()),
            target_by_key=targets,
            question=self.qwen_prepared.question,
            lock_context=SimpleNamespace(
                git_head="a" * 40,
                lock_sha256="b" * 64,
            ),
        )
        self.authority = execute.Authority(
            ReceiptBinding(self.root / "authorization.json", {}, "c" * 64),
            ReceiptBinding(self.root / "pricing.json", {}, "d" * 64),
        )
        self.grok = targets["grok"]
        self.gpt = targets["gpt"]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def intent(self, call, attempt: int, *, created_at: str = T0) -> JournalRecord:
        return write_record(
            self.paths.generation_intent(call.model.model_key, attempt),
            execute._generation_intent_payload(
                self.prepared,
                self.authority,
                self.parent,
                call,
                attempt,
                created_at=created_at,
            ),
        )

    def raw(
        self,
        call,
        intent: JournalRecord,
        response: HttpResponse,
    ) -> JournalRecord:
        attempt = intent.payload["semantic_attempt_number"]
        request = execute._generation_request(call, "redacted-offline-secret")
        return write_record(
            self.paths.generation_raw(call.model.model_key, attempt),
            raw_response_payload(
                common=execute._raw_common(
                    self.prepared,
                    self.authority,
                    call.model.model_key,
                    attempt,
                ),
                intent=intent,
                private_root=self.paths.private_root,
                request_kind="generation",
                request=request,
                response=response,
                received_at=T1,
            ),
        )

    @staticmethod
    def grok_success_body(*, artifact: dict | None = None) -> dict:
        value = {
            "id": "synthetic-grok-retry",
            "model": "grok-4.5",
            "status": "completed",
            "output": [
                {
                    "type": "message",
                    "role": "assistant",
                    "content": [
                        {"type": "output_text", "text": "Synthetic Grok answer."}
                    ],
                }
            ],
            "usage": {
                "input_tokens": 10,
                "output_tokens": 8,
                "total_tokens": 18,
            },
        }
        if artifact:
            value.update(artifact)
        return value


class GrokRetryRequestAndResponseTests(GrokRetryExecutionFixture):
    def test_attempt_ranges_are_exact_and_preserved_models_are_rejected(self) -> None:
        self.assertEqual(execute._attempt_range("grok"), (2,))
        self.assertEqual(execute._attempt_range("gpt"), (1, 2, 3))
        for key in contract.PRESERVED_MODEL_KEYS:
            with self.subTest(model_key=key):
                with self.assertRaisesRegex(
                    execute.GrokRetryExecutionError, "outside the Grok retry lane"
                ):
                    execute._attempt_range(key)

    def test_attempt_two_is_identical_to_consumed_request_and_binds_403(self) -> None:
        payload = execute._generation_intent_payload(
            self.prepared,
            self.authority,
            self.parent,
            self.grok,
            2,
            created_at=T0,
        )
        self.assertEqual(payload["semantic_attempt_number"], 2)
        self.assertEqual(payload["provider"], "xai")
        self.assertEqual(payload["route"], "xai-direct")
        self.assertEqual(payload["requested_model_id"], "grok-4.5")
        self.assertEqual(
            payload["request_json_body_sha256"], contract.GROK_REQUEST_BODY_SHA256
        )
        self.assertEqual(payload["prompt_sha256"], contract.GROK_PROMPT_SHA256)
        self.assertEqual(payload["messages_sha256"], contract.GROK_MESSAGES_SHA256)
        self.assertEqual(
            payload["requested_params_sha256"],
            contract.GROK_REQUESTED_PARAMS_SHA256,
        )
        self.assertIs(payload["requested_params"]["tools_enabled"], False)
        self.assertIs(payload["requested_params"]["web_search_enabled"], False)
        self.assertIs(payload["requested_params"]["retrieval_enabled"], False)
        replacement = payload["replacement_of_parent_attempt"]
        self.assertEqual(
            replacement["intent"]["sha256"], contract.GROK_ERROR_INTENT_SHA256
        )
        self.assertEqual(
            replacement["raw_response"]["sha256"], contract.GROK_ERROR_RAW_SHA256
        )
        self.assertEqual(
            replacement["outcome"]["sha256"], contract.GROK_ERROR_OUTCOME_SHA256
        )

        for forbidden_attempt in (1, 3):
            with self.subTest(attempt=forbidden_attempt):
                with self.assertRaisesRegex(
                    execute.GrokRetryExecutionError,
                    "differs from the consumed xAI request",
                ):
                    execute._generation_intent_payload(
                        self.prepared,
                        self.authority,
                        self.parent,
                        self.grok,
                        forbidden_attempt,
                        created_at=T0,
                    )

    def test_changed_parent_request_hash_blocks_retry_intent(self) -> None:
        changed = copy.deepcopy(self.parent.grok_error_intent.payload)
        changed["request_json_body_sha256"] = "0" * 64
        forged_parent = replace(
            self.parent,
            grok_error_intent=record(
                self.parent.grok_error_intent.path,
                changed,
                801,
            ),
        )
        with self.assertRaisesRegex(
            execute.GrokRetryExecutionError,
            "differs from the consumed xAI request",
        ):
            execute._generation_intent_payload(
                self.prepared,
                self.authority,
                forged_parent,
                self.grok,
                2,
                created_at=T0,
            )

    def test_nested_tool_and_retrieval_artifacts_are_rejected(self) -> None:
        forbidden = (
            {"tool_calls": [{"name": "lookup"}]},
            {"output": [{"type": "web_search_call"}]},
            {"annotations": [{"type": "url_citation"}]},
            {"nested": {"sources": ["https://example.invalid"]}},
            {"result": {"type": "function-call"}},
        )
        for artifact in forbidden:
            with self.subTest(artifact=artifact):
                self.assertIs(execute._has_tool_artifact(artifact), True)
        self.assertIs(execute._has_tool_artifact({"annotations": []}), False)

        adapter = execute._RetryAdapter(self.grok.model, execute._NeverTransport())
        with self.assertRaisesRegex(ProviderError, "forbidden tool") as raised:
            adapter._parse_generation(
                self.grok_success_body(
                    artifact={"output_tool": {"type": "web_search_call"}}
                )
            )
        self.assertEqual(raised.exception.category, "response-validation")
        self.assertIs(raised.exception.retryable, False)

    def test_gpt_response_must_identify_openai_and_valid_usage(self) -> None:
        base = {
            "id": "synthetic-gpt",
            "model": "openai/gpt-5.6-sol",
            "choices": [
                {
                    "message": {"content": "Synthetic GPT answer."},
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 5,
                "total_tokens": 15,
            },
        }
        adapter = execute._RetryAdapter(self.gpt.model, execute._NeverTransport())
        for provider in (None, "Anthropic"):
            with self.subTest(provider=provider):
                body = {**base, "provider": provider}
                with self.assertRaisesRegex(ProviderError, "pinned OpenAI"):
                    adapter._parse_generation(body)

        malformed_usage = {**base, "provider": "OpenAI", "usage": {}}
        with self.assertRaisesRegex(ProviderError, "invalid usage"):
            adapter._parse_generation(malformed_usage)

        parsed = adapter._parse_generation({**base, "provider": "OpenAI"})
        self.assertEqual(parsed.provider_name, "OpenAI")


class GrokRetryRestartAndGateTests(GrokRetryExecutionFixture):
    def test_intent_without_capture_is_consumed_and_never_replayed(self) -> None:
        self.intent(self.grok, 2)
        for restart in range(2):
            with self.subTest(restart=restart):
                success, network, reason = asyncio.run(
                    execute._reconcile_generation(
                        self.prepared,
                        self.authority,
                        self.parent,
                        self.grok,
                    )
                )
                self.assertIsNone(success)
                self.assertIs(network, False)
                self.assertIn("without durable capture", reason)
        disposition = read_record(
            self.paths.generation_outcome("grok", 2), "Grok no-capture"
        )
        self.assertEqual(disposition.payload["status"], "consumed-without-capture")
        self.assertEqual(
            disposition.payload["disposition"],
            {
                "category": "ambiguous-no-capture",
                "possibly_delivered": True,
                "possibly_billed": True,
                "replay_allowed": False,
                "later_attempt_allowed": False,
            },
        )

        reserve = mock.Mock()
        with mock.patch.object(execute, "_reserve_generation", reserve):
            with self.assertRaisesRegex(
                execute.GrokRetryExecutionError, "POST ceiling exceeded"
            ):
                asyncio.run(
                    execute._run_generation(
                        self.prepared,
                        self.authority,
                        self.parent,
                        self.grok,
                        secret="unused",
                        transport=SimpleNamespace(),
                        limiter=SimpleNamespace(),
                    )
                )
        reserve.assert_not_called()

    def test_transport_timeout_is_consumed_once_and_terminal_on_restart(self) -> None:
        class TimeoutTransport:
            def __init__(self) -> None:
                self.requests = 0

            async def send(self, request) -> HttpResponse:
                del request
                self.requests += 1
                raise ProviderError(
                    "synthetic timeout",
                    category="timeout",
                    retryable=True,
                )

        transport = TimeoutTransport()
        limiter = SimpleNamespace(wait=mock.AsyncMock(return_value=None))
        outcome = asyncio.run(
            execute._run_generation(
                self.prepared,
                self.authority,
                self.parent,
                self.grok,
                secret="synthetic-secret",
                transport=transport,
                limiter=limiter,
            )
        )
        self.assertEqual(outcome.payload["status"], "consumed-without-capture")
        self.assertEqual(transport.requests, 1)
        self.assertTrue(self.paths.generation_intent("grok", 2).exists())
        self.assertFalse(self.paths.generation_raw("grok", 2).exists())

        with self.assertRaisesRegex(
            execute.GrokRetryExecutionError, "POST ceiling exceeded"
        ):
            asyncio.run(
                execute._run_generation(
                    self.prepared,
                    self.authority,
                    self.parent,
                    self.grok,
                    secret="synthetic-secret",
                    transport=transport,
                    limiter=limiter,
                )
            )
        self.assertEqual(transport.requests, 1)

    def test_captured_403_is_terminal_and_does_not_unlock_gpt(self) -> None:
        intent = self.intent(self.grok, 2)
        self.raw(
            self.grok,
            intent,
            HttpResponse(
                403,
                {},
                json.dumps(
                    {
                        "code": "permission-denied",
                        "error": "model unavailable in region",
                    }
                ).encode("utf-8"),
            ),
        )
        success, network, reason = asyncio.run(
            execute._reconcile_generation(
                self.prepared,
                self.authority,
                self.parent,
                self.grok,
            )
        )
        self.assertIsNone(success)
        self.assertIs(network, False)
        self.assertIn("no GPT call", reason)
        outcome = read_record(
            self.paths.generation_outcome("grok", 2), "Grok retry error"
        )
        self.assertEqual(outcome.payload["status"], "error")
        self.assertEqual(outcome.payload["error"]["category"], "authorization")
        self.assertIs(outcome.payload["error"]["retryable"], False)
        self.assertFalse(self.paths.generation_intent("gpt", 1).exists())

    def test_captured_success_is_finalized_offline_and_unlocks_gpt(self) -> None:
        intent = self.intent(self.grok, 2)
        self.raw(
            self.grok,
            intent,
            HttpResponse(
                200,
                {},
                json.dumps(self.grok_success_body()).encode("utf-8"),
            ),
        )
        success, network, reason = asyncio.run(
            execute._reconcile_generation(
                self.prepared,
                self.authority,
                self.parent,
                self.grok,
            )
        )
        self.assertIsNotNone(success)
        self.assertIs(network, False)
        self.assertIsNone(reason)
        self.assertEqual(success.payload["status"], "success")
        self.assertEqual(success.payload["provider_returned_model_id"], "grok-4.5")
        self.assertTrue(self.paths.generation_outcome("grok", 2).exists())

        gpt_pending = mock.AsyncMock(
            side_effect=[
                (success, False, None),
                (None, True, None),
            ]
        )
        with mock.patch.object(execute, "_reconcile_generation", gpt_pending):
            composite, needs, terminal = asyncio.run(
                execute._reconcile_composite(
                    self.prepared,
                    self.authority,
                    self.parent,
                )
            )
        self.assertIsNone(composite)
        self.assertIs(needs, True)
        self.assertIsNone(terminal)
        self.assertEqual(gpt_pending.await_count, 2)
        self.assertIs(gpt_pending.await_args_list[0].args[3], self.grok)
        self.assertIs(gpt_pending.await_args_list[1].args[3], self.gpt)

    def test_gpt_state_before_grok_success_fails_closed(self) -> None:
        write_record(
            self.paths.generation_intent("gpt", 1),
            {"reserved_cost_microdollars": contract.RESERVED_PER_POST["gpt"]},
        )
        stopped = mock.AsyncMock(return_value=(None, False, "Grok failed"))
        with mock.patch.object(execute, "_reconcile_generation", stopped):
            with self.assertRaisesRegex(
                execute.GrokRetryExecutionError,
                "GPT state exists before Grok success",
            ):
                asyncio.run(
                    execute._reconcile_composite(
                        self.prepared,
                        self.authority,
                        self.parent,
                    )
                )
        stopped.assert_awaited_once()
        self.assertIs(stopped.await_args.args[3], self.grok)

    def test_success_followed_by_later_attempt_is_rejected(self) -> None:
        intent1 = self.intent(self.gpt, 1)
        raw1 = record(self.paths.generation_raw("gpt", 1), {}, 701)
        success1 = record(
            self.paths.generation_outcome("gpt", 1),
            {"status": "success", "semantic_attempt_number": 1},
            702,
        )
        intent2 = record(
            self.paths.generation_intent("gpt", 2),
            {"semantic_attempt_number": 2},
            703,
        )
        history = [(intent1, raw1, success1), (intent2, None, None)]
        with (
            mock.patch.object(execute, "_generation_history", return_value=history),
            mock.patch.object(
                execute,
                "_validate_generation_outcome",
                new=mock.AsyncMock(return_value=SimpleNamespace()),
            ),
        ):
            with self.assertRaisesRegex(
                execute.GrokRetryExecutionError, "generation attempt follows success"
            ):
                asyncio.run(
                    execute._reconcile_generation(
                        self.prepared,
                        self.authority,
                        self.parent,
                        self.gpt,
                    )
                )


class GrokRetryBudgetTests(GrokRetryExecutionFixture):
    def test_exact_maximum_reservation_is_accepted(self) -> None:
        reservations = {
            ("grok", 2): contract.RESERVED_PER_POST["grok"],
            ("gpt", 1): contract.RESERVED_PER_POST["gpt"],
            ("gpt", 2): contract.RESERVED_PER_POST["gpt"],
            ("gpt", 3): contract.RESERVED_PER_POST["gpt"],
        }
        for (model_key, attempt), reserve in reservations.items():
            write_record(
                self.paths.generation_intent(model_key, attempt),
                {"reserved_cost_microdollars": reserve},
            )
        self.assertEqual(
            execute._reserved_total(self.prepared),
            contract.NEW_RESERVED_CAP_MICRODOLLARS,
        )
        self.assertEqual(
            contract.INHERITED_RESERVED_MICRODOLLARS
            + execute._reserved_total(self.prepared),
            contract.COMBINED_RESERVED_CAP_MICRODOLLARS,
        )

    def test_malformed_undercounted_unknown_and_over_cap_reservations_fail(
        self,
    ) -> None:
        path = self.paths.generation_intent("grok", 2)
        write_record(path, {"reserved_cost_microdollars": True})
        with self.assertRaisesRegex(
            execute.GrokRetryExecutionError, "reservation is malformed"
        ):
            execute._reserved_total(self.prepared)

        path.unlink()
        write_record(path, {"reserved_cost_microdollars": 1})
        with self.assertRaisesRegex(
            execute.GrokRetryExecutionError, "reserved cost changed"
        ):
            execute._reserved_total(self.prepared)

        path.unlink()
        write_record(
            self.paths.generation_intent("grok", 3),
            {"reserved_cost_microdollars": contract.RESERVED_PER_POST["grok"]},
        )
        with self.assertRaisesRegex(
            execute.GrokRetryExecutionError,
            "reservation path changed",
        ):
            execute._reserved_total(self.prepared)

        self.paths.generation_intent("grok", 3).unlink()
        write_record(
            self.paths.generation_intent("grok", 2),
            {"reserved_cost_microdollars": contract.RESERVED_PER_POST["grok"]},
        )
        with (
            mock.patch.object(
                contract,
                "NEW_RESERVED_CAP_MICRODOLLARS",
                contract.RESERVED_PER_POST["grok"] - 1,
            ),
            self.assertRaisesRegex(
                execute.GrokRetryExecutionError, "reserved-cost cap exceeded"
            ),
        ):
            execute._reserved_total(self.prepared)


if __name__ == "__main__":
    unittest.main()
