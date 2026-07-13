from __future__ import annotations

import copy
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rule3.contract import (
    APPROVED_MODEL_TRANSPORTS,
    APPROVED_PLANNING_PRICING,
    CANDIDATES,
    DOSSIER_PATH,
    EXPECTED_REQUEST_PARAMS,
    LOCK_PATH,
    LOCK_SCHEMA_PATH,
    MAPPING_RUBRIC_PATH,
    MODELS_CONFIG_PATH,
    PRICING_REVIEW_PATH,
    PROTOCOL_PATH,
    SOURCE_FREEZE_PATH,
    SYSTEM_PROMPT,
    canonical_json_bytes,
    discover_execution_source_paths,
    parse_json_bytes,
    sha256_bytes,
)
from run_rule3 import _preimport_bootstrap
from rule3.lock import (
    Rule3LockError,
    build_rule3_lock,
    load_and_validate_rule3_lock,
    validate_rule3_lock,
    write_rule3_lock,
)

from support import repository_root


CORE_INPUTS = (
    DOSSIER_PATH,
    SOURCE_FREEZE_PATH,
    MAPPING_RUBRIC_PATH,
    PROTOCOL_PATH,
    MODELS_CONFIG_PATH,
    PRICING_REVIEW_PATH,
    LOCK_SCHEMA_PATH,
    *(candidate["path"] for candidate in CANDIDATES),
)


class Rule3LockTests(unittest.TestCase):
    def make_repository(self, root: Path) -> None:
        source = repository_root()
        for relative in CORE_INPUTS:
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source / relative, destination)
        for relative in discover_execution_source_paths(source):
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source / relative, destination)
        unrelated = root / "unrelated.txt"
        unrelated.write_text("tracked but not bound\n", encoding="utf-8")

    def write_lock(self, root: Path) -> dict:
        lock = build_rule3_lock(root)
        path = root / LOCK_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(canonical_json_bytes(lock))
        return lock

    def commit_all(self, root: Path) -> str:
        commands = [
            ["git", "init", "-q"],
            ["git", "config", "user.name", "Rule 3 Lock Test"],
            ["git", "config", "user.email", "rule3-lock@example.invalid"],
            ["git", "add", "."],
            ["git", "commit", "-qm", "freeze Rule 3 contract"],
        ]
        for command in commands:
            subprocess.run(command, cwd=root, check=True, capture_output=True)
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def mutate_json(self, root: Path, relative: str, mutation) -> None:
        path = root / relative
        value = parse_json_bytes(path.read_bytes(), relative)
        mutation(value)
        path.write_bytes(canonical_json_bytes(value))

    def test_builds_exact_ordered_contract_and_plan_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            lock = build_rule3_lock(root)

            self.assertEqual(
                [candidate["id"] for candidate in lock["candidates"]],
                [candidate["id"] for candidate in CANDIDATES],
            )
            self.assertEqual(
                [candidate["role"] for candidate in lock["candidates"]],
                ["priority", "fallback"],
            )
            self.assertEqual(
                [model["model_key"] for model in lock["models"]],
                [
                    "gemini",
                    "claude",
                    "cohere",
                    "qwen",
                    "deepseek",
                    "mistral",
                    "grok",
                    "gpt",
                ],
            )
            for model in lock["models"]:
                expected_key = model["model_key"]
                self.assertEqual(
                    {
                        field: model[field]
                        for field in APPROVED_MODEL_TRANSPORTS[expected_key]
                    },
                    APPROVED_MODEL_TRANSPORTS[expected_key],
                )
                self.assertEqual(
                    model["requested_params"],
                    EXPECTED_REQUEST_PARAMS[expected_key],
                )
                self.assertEqual(
                    model["planning_pricing"],
                    APPROVED_PLANNING_PRICING[expected_key],
                )

            candidate_plans = lock["plans"]["candidate_plans"]
            self.assertEqual([plan["cell_count"] for plan in candidate_plans], [8, 8])
            for plan in candidate_plans:
                self.assertEqual(
                    plan["plan_sha256"],
                    sha256_bytes(canonical_json_bytes(plan["cells"])),
                )
                self.assertTrue(
                    all(
                        cell["cell_id"].endswith(":default:answer")
                        for cell in plan["cells"]
                    )
                )
            universe = [cell for plan in candidate_plans for cell in plan["cells"]]
            self.assertEqual(
                lock["plans"]["ordered_universe_plan_sha256"],
                sha256_bytes(canonical_json_bytes(universe)),
            )
            self.assertEqual(lock["execution_policy"]["output_token_cap"], 16_384)
            self.assertEqual(lock["execution_policy"]["attempts_per_cell"], 3)
            self.assertEqual(
                lock["execution_policy"]["candidate_cost_cap_microdollars"],
                6_000_000,
            )
            self.assertEqual(
                lock["execution_policy"]["total_cost_cap_microdollars"],
                12_000_000,
            )
            self.assertFalse(lock["paid_authorization"]["lock_authorizes_spending"])

            protocol = parse_json_bytes(
                (root / PROTOCOL_PATH).read_bytes(), PROTOCOL_PATH
            )
            self.assertEqual(protocol["system_prompt"], SYSTEM_PROMPT)
            self.assertEqual(
                SYSTEM_PROMPT,
                "Answer the user's question directly and identify the "
                "interpretation you judge best supported. Explain the decisive "
                "reasons and acknowledge serious alternatives. Do not use tools, "
                "web search, retrieval, or external context. Keep the visible "
                "answer under 900 tokens. Do not identify yourself, your model or "
                "model family, your provider, your developer, your training "
                "process, your service route, or your status as an AI anywhere in "
                "the answer.",
            )

    def test_generation_rejects_every_changed_transport_and_pricing_field(self) -> None:
        mutations = (
            ("family", lambda model: model.__setitem__("family", "Substitute")),
            ("provider", lambda model: model.__setitem__("provider", "proxy")),
            (
                "model ID",
                lambda model: model.__setitem__("requested_model_id", "latest"),
            ),
            ("route", lambda model: model.__setitem__("route", "fallback-route")),
            (
                "environment variable",
                lambda model: model.__setitem__(
                    "environment_variable", "ATTACKER_API_KEY"
                ),
            ),
            ("API style", lambda model: model.__setitem__("api_style", "openai")),
            (
                "base URL",
                lambda model: model.__setitem__("base_url", "https://proxy.invalid"),
            ),
            (
                "generation path",
                lambda model: model.__setitem__(
                    "generation_path", "/v1/fallback/generate"
                ),
            ),
            (
                "metadata path",
                lambda model: model.__setitem__("metadata_path", "/v1/models"),
            ),
            (
                "metadata mode",
                lambda model: model.__setitem__("metadata_mode", "list"),
            ),
            ("auth kind", lambda model: model.__setitem__("auth_kind", "bearer")),
            (
                "fallback",
                lambda model: model.__setitem__("fallback_allowed", True),
            ),
            (
                "request rate",
                lambda model: model.__setitem__("requests_per_second", 2.0),
            ),
            (
                "price",
                lambda model: model["planning_pricing"].__setitem__(
                    "output_per_million", 0.0
                ),
            ),
            (
                "price date",
                lambda model: model["planning_pricing"].__setitem__(
                    "pricing_as_of", "2026-07-13"
                ),
            ),
        )
        for label, mutation in mutations:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    self.make_repository(root)
                    self.mutate_json(
                        root,
                        MODELS_CONFIG_PATH,
                        lambda value: mutation(value["models"][0]),
                    )
                    with self.assertRaisesRegex(
                        Rule3LockError, "transport contract|planning pricing"
                    ):
                        build_rule3_lock(root)

    def test_generation_rejects_changed_position_definitions_and_null_boundary(
        self,
    ) -> None:
        priority = CANDIDATES[0]["path"]
        mutations = (
            (
                "position ID",
                lambda value: value["position_map"][0].__setitem__(
                    "id", "renamed-after-approval"
                ),
            ),
            (
                "position order",
                lambda value: value["position_map"].reverse(),
            ),
            (
                "Hooker-inclusive definition",
                lambda value: value["position_map"][1].__setitem__(
                    "summary", "Christ's faith alone, excluding answering faith."
                ),
            ),
            (
                "Hooker null boundary",
                lambda value: value.__setitem__(
                    "context_note",
                    value["context_note"].replace(
                        "A merely plenary, intentionally ambiguous, or evenly "
                        "combined subjective-objective answer remains null.",
                        "A plenary answer maps to Christ's own faithfulness.",
                    ),
                ),
            ),
        )
        for label, mutation in mutations:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    self.make_repository(root)
                    self.mutate_json(root, priority, mutation)
                    with self.assertRaises(Rule3LockError):
                        build_rule3_lock(root)

    def test_generation_rejects_nonproposed_verification_at_every_content_level(
        self,
    ) -> None:
        priority = CANDIDATES[0]["path"]
        mutations = (
            (
                "question",
                priority,
                lambda value: value["verification"].__setitem__(
                    "verified_by", "post-approval-reviewer"
                ),
            ),
            (
                "position",
                priority,
                lambda value: value["position_map"][0]["verification"].__setitem__(
                    "status", "verified"
                ),
            ),
            (
                "question source",
                priority,
                lambda value: value["position_map"][0]["sources"][0][
                    "verification"
                ].__setitem__("verified_at", "2026-07-13T00:00:00Z"),
            ),
            (
                "source freeze",
                SOURCE_FREEZE_PATH,
                lambda value: value["verification"].__setitem__("status", "verified"),
            ),
            (
                "frozen source",
                SOURCE_FREEZE_PATH,
                lambda value: value["questions"][0]["sources"][0][
                    "verification"
                ].__setitem__("verified_by", "post-approval-reviewer"),
            ),
        )
        for label, relative, mutation in mutations:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    self.make_repository(root)
                    self.mutate_json(root, relative, mutation)
                    with self.assertRaises(Rule3LockError):
                        build_rule3_lock(root)

    def test_generation_rejects_changed_source_freeze_lineage_and_hashes(self) -> None:
        mutations = (
            (
                "question ID",
                lambda value: value["questions"][0].__setitem__(
                    "question_id", "another-question"
                ),
            ),
            (
                "question path",
                lambda value: value["questions"][0].__setitem__(
                    "question_path", CANDIDATES[1]["path"]
                ),
            ),
            (
                "source order",
                lambda value: value["questions"][0]["sources"].reverse(),
            ),
            (
                "source URL",
                lambda value: value["questions"][0]["sources"][0].__setitem__(
                    "source_url", "https://example.invalid/substitute"
                ),
            ),
            (
                "source claim",
                lambda value: value["questions"][0]["sources"][0].__setitem__(
                    "claim_binding", "A materially different claim."
                ),
            ),
            (
                "artifact status",
                lambda value: value["questions"][0]["sources"][0][
                    "artifact"
                ].__setitem__("status", "unfrozen"),
            ),
            (
                "retained artifact hash",
                lambda value: value["questions"][0]["sources"][0][
                    "artifact"
                ].__setitem__("sha256", "0" * 64),
            ),
            (
                "unretained artifact invented hash",
                lambda value: value["questions"][0]["sources"][3][
                    "artifact"
                ].__setitem__("sha256", "0" * 64),
            ),
        )
        for label, mutation in mutations:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    self.make_repository(root)
                    self.mutate_json(root, SOURCE_FREEZE_PATH, mutation)
                    with self.assertRaises(Rule3LockError):
                        build_rule3_lock(root)

    def test_generation_rejects_reformatted_approved_content_bytes(self) -> None:
        for relative in (CANDIDATES[0]["path"], SOURCE_FREEZE_PATH):
            with self.subTest(path=relative):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    self.make_repository(root)
                    path = root / relative
                    path.write_bytes(path.read_bytes() + b" ")
                    with self.assertRaisesRegex(Rule3LockError, "exact approved"):
                        build_rule3_lock(root)

    def test_structural_and_hash_validation_accepts_precommit_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            lock = self.write_lock(root)
            context = validate_rule3_lock(lock, root)
            loaded = load_and_validate_rule3_lock(root)
            self.assertIsNone(context.git_head)
            self.assertEqual(context.lock_sha256, loaded.lock_sha256)
            self.assertEqual(
                context.candidate_plan_sha256,
                {
                    plan["candidate_id"]: plan["plan_sha256"]
                    for plan in lock["plans"]["candidate_plans"]
                },
            )

    def test_every_bound_file_tamper_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            lock = self.write_lock(root)
            bound = [LOCK_PATH]
            bound.extend(item["path"] for item in lock["bindings"].values())
            bound.extend(item["path"] for item in lock["candidates"])
            bound.extend(item["path"] for item in lock["execution_sources"])
            self.assertEqual(len(bound), len(set(bound)))

            for relative in bound:
                with self.subTest(path=relative):
                    path = root / relative
                    original = path.read_bytes()
                    path.write_bytes(original + b" ")
                    with self.assertRaises(Rule3LockError):
                        load_and_validate_rule3_lock(root)
                    path.write_bytes(original)
                    load_and_validate_rule3_lock(root)

    def test_rejects_candidate_model_source_and_plan_order_tamper(self) -> None:
        mutations = (
            lambda lock: lock["candidates"].reverse(),
            lambda lock: lock["models"].reverse(),
            lambda lock: lock["execution_sources"].reverse(),
            lambda lock: lock["plans"]["candidate_plans"].reverse(),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            original = build_rule3_lock(root)
            for mutate in mutations:
                with self.subTest(mutation=mutate):
                    lock = copy.deepcopy(original)
                    mutate(lock)
                    with self.assertRaises(Rule3LockError):
                        validate_rule3_lock(lock, root)

    def test_rejects_hash_path_receipt_and_numeric_type_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            original = build_rule3_lock(root)
            mutated: list[dict] = []

            lock = copy.deepcopy(original)
            lock["bindings"]["dossier"]["sha256"] = "0" * 64
            mutated.append(lock)
            lock = copy.deepcopy(original)
            lock["candidates"][0]["path"] = "../escape.json"
            mutated.append(lock)
            lock = copy.deepcopy(original)
            lock["models"][0]["requested_params"]["tools_enabled"] = True
            mutated.append(lock)
            lock = copy.deepcopy(original)
            lock["plans"]["candidate_plans"][0]["plan_sha256"] = "f" * 64
            mutated.append(lock)
            lock = copy.deepcopy(original)
            lock["execution_policy"]["candidate_cost_cap_microdollars"] = 6_000_000.0
            mutated.append(lock)

            for index, lock in enumerate(mutated):
                with self.subTest(index=index):
                    with self.assertRaises(Rule3LockError):
                        validate_rule3_lock(lock, root)

    def test_rejects_alternate_live_lock_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            lock = build_rule3_lock(root)
            with self.assertRaisesRegex(Rule3LockError, "lock path must be"):
                validate_rule3_lock(
                    lock,
                    root,
                    lock_path=root / "candidate/alternate-rule3-lock.json",
                )

    def test_rejects_symlinked_bound_input_and_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            lock = self.write_lock(root)
            question_path = root / CANDIDATES[0]["path"]
            target = root / "question-copy.json"
            target.write_bytes(question_path.read_bytes())
            question_path.unlink()
            question_path.symlink_to(target)
            with self.assertRaisesRegex(Rule3LockError, "regular file|cannot open"):
                validate_rule3_lock(lock, root)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            self.write_lock(root)
            lock_path = root / LOCK_PATH
            target = root / "lock-copy.json"
            target.write_bytes(lock_path.read_bytes())
            lock_path.unlink()
            lock_path.symlink_to(target)
            with self.assertRaises(Rule3LockError):
                load_and_validate_rule3_lock(root)

    def test_discovery_is_sorted_recursive_and_excludes_nonexecution_paths(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            extension = root / "harness/rule3/nested/extension.py"
            extension.parent.mkdir(parents=True)
            extension.write_text("EXTENSION = True\n", encoding="utf-8")
            excluded = (
                root / "harness/rule3/tests/hostile.py",
                root / "harness/rule3/__pycache__/cache.pyc",
                root / "harness/rule3/rule3-lock.json",
            )
            for path in excluded:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"excluded\n")
            paths = discover_execution_source_paths(root)
            self.assertEqual(paths, tuple(sorted(paths)))
            self.assertIn("harness/rule3/nested/extension.py", paths)
            for path in excluded:
                self.assertNotIn(path.relative_to(root).as_posix(), paths)

    def test_discovery_binds_full_shared_package_and_future_imported_helper(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            original = build_rule3_lock(root)
            paths = discover_execution_source_paths(root)
            expected_shared = {
                path.relative_to(root).as_posix()
                for path in (root / "harness/concordance_harness").rglob("*.py")
                if "tests" not in path.parts and "__pycache__" not in path.parts
            }
            self.assertTrue(expected_shared.issubset(paths))
            self.assertIn("harness/concordance_harness/pilot_lock.py", paths)

            helper = root / "harness/future_execution_helper.py"
            helper.write_text("BOUND_FUTURE_HELPER = True\n", encoding="utf-8")
            run_cli = root / "harness/run_rule3.py"
            run_cli.write_text(
                run_cli.read_text(encoding="utf-8")
                + "\nimport future_execution_helper\n",
                encoding="utf-8",
            )
            changed_paths = discover_execution_source_paths(root)
            self.assertIn("harness/future_execution_helper.py", changed_paths)
            with self.assertRaises(Rule3LockError):
                validate_rule3_lock(original, root)

    def test_discovery_rejects_unresolvable_or_dynamic_local_import(self) -> None:
        mutations = (
            "\nimport rule3.future_missing_helper\n",
            "\n__import__(LOCAL_MODULE_NAME)\n",
        )
        for source in mutations:
            with self.subTest(source=source.strip()):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    self.make_repository(root)
                    run_cli = root / "harness/run_rule3.py"
                    run_cli.write_text(
                        run_cli.read_text(encoding="utf-8") + source,
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(
                        Rule3LockError, "unresolved local import|cannot be source-bound"
                    ):
                        discover_execution_source_paths(root)

    def test_preimport_bootstrap_accepts_clean_commit_and_stops_dirty_code(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            self.write_lock(root)
            head = self.commit_all(root)
            self.assertEqual(_preimport_bootstrap(root), head)
            with patch.dict(
                "os.environ",
                {
                    "PATH": str(root / "attacker-bin"),
                    "GIT_DIR": str(root / "attacker-git-dir"),
                    "GIT_CONFIG_GLOBAL": str(root / "attacker-gitconfig"),
                    "GIT_ASKPASS": str(root / "attacker-askpass"),
                    "LC_ALL": "attacker-locale",
                },
                clear=False,
            ):
                self.assertEqual(_preimport_bootstrap(root), head)

            shadow_sentinel = root / "shadow-json-imported"
            (root / "harness/json.py").write_text(
                "from pathlib import Path\n"
                f"Path({str(shadow_sentinel)!r}).write_text('shadowed')\n",
                encoding="utf-8",
            )
            unisolated = subprocess.run(
                [
                    sys.executable,
                    "harness/run_rule3.py",
                    "--dry-run",
                    "--phase",
                    "priority",
                ],
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(unisolated.returncode, 2)
            self.assertIn("python3 -I", unisolated.stderr)
            self.assertFalse(shadow_sentinel.exists())
            isolated = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "harness/run_rule3.py",
                    "--dry-run",
                    "--phase",
                    "priority",
                ],
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(isolated.returncode, 2)
            self.assertIn("before project imports", isolated.stderr)
            self.assertIn("dependency shadow", isolated.stderr)
            self.assertFalse(shadow_sentinel.exists())
            (root / "harness/json.py").unlink()

            sentinel = root / "import-time-code-ran"
            config = root / "harness/concordance_harness/config.py"
            config.write_text(
                "from pathlib import Path\n"
                f"Path({str(sentinel)!r}).write_text('ran')\n"
                + config.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "harness/run_rule3.py",
                    "--dry-run",
                    "--phase",
                    "priority",
                ],
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("before project imports", result.stderr)
            self.assertFalse(sentinel.exists())

    def test_preimport_bootstrap_requires_every_below_gate_project_source(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            lock = self.write_lock(root)
            lock["execution_sources"] = [
                source
                for source in lock["execution_sources"]
                if source["path"] != "harness/run_rule3.py"
            ]
            (root / LOCK_PATH).write_bytes(canonical_json_bytes(lock))
            self.commit_all(root)
            with self.assertRaisesRegex(
                RuntimeError, "omits project code imported below the gate"
            ):
                _preimport_bootstrap(root)

    def test_preimport_bootstrap_requires_rule3_specific_protocol_binding(self) -> None:
        mutations = (
            lambda binding: binding.__setitem__("path", "config/protocol.json"),
            lambda binding: binding.__setitem__("protocol_version", "1.0.0"),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    self.make_repository(root)
                    lock = self.write_lock(root)
                    mutation(lock["bindings"]["protocol"])
                    (root / LOCK_PATH).write_bytes(canonical_json_bytes(lock))
                    self.commit_all(root)
                    with self.assertRaisesRegex(
                        RuntimeError, "Rule 3-specific protocol"
                    ):
                        _preimport_bootstrap(root)

    def test_missing_required_execution_source_blocks_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            (root / "harness/rule3/evaluate.py").unlink()
            with self.assertRaisesRegex(Rule3LockError, "implementation is incomplete"):
                build_rule3_lock(root)

    def test_third_question_file_blocks_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            extra = root / "candidate/rule3/questions/third-candidate.json"
            extra.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(Rule3LockError, "exactly the two"):
                build_rule3_lock(root)

    def test_write_is_create_once_and_never_overwrites(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            first = write_rule3_lock(root)
            self.assertEqual(first.lock_bytes, (root / LOCK_PATH).read_bytes())
            with self.assertRaisesRegex(Rule3LockError, "never overwritten"):
                write_rule3_lock(root)

    def test_generation_does_not_read_environment_or_network(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            with patch("os.getenv", side_effect=AssertionError("environment read")):
                with patch(
                    "urllib.request.urlopen", side_effect=AssertionError("network call")
                ):
                    build_rule3_lock(root)

    def test_runtime_accepts_exact_committed_bytes_and_returns_head(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            self.write_lock(root)
            head = self.commit_all(root)
            context = load_and_validate_rule3_lock(root, require_committed=True)
            self.assertEqual(context.git_head, head)

    def test_runtime_rejects_lock_absent_from_head(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            lock = build_rule3_lock(root)
            self.commit_all(root)
            (root / LOCK_PATH).write_bytes(canonical_json_bytes(lock))
            with self.assertRaisesRegex(Rule3LockError, "not present in HEAD"):
                load_and_validate_rule3_lock(root, require_committed=True)

    def test_runtime_rejects_bound_input_absent_from_head(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            self.write_lock(root)
            self.commit_all(root)
            relative = "harness/rule3/review_assets/review.css"
            subprocess.run(
                ["git", "rm", "--cached", relative],
                cwd=root,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "commit", "-qm", "remove bound file from HEAD"],
                cwd=root,
                check=True,
                capture_output=True,
            )
            self.assertTrue((root / relative).is_file())
            with self.assertRaisesRegex(Rule3LockError, "not present in HEAD"):
                load_and_validate_rule3_lock(root, require_committed=True)

    def test_runtime_rejects_staged_bound_path_even_when_worktree_matches_head(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            self.write_lock(root)
            self.commit_all(root)
            path = root / DOSSIER_PATH
            original = path.read_bytes()
            path.write_bytes(original + b"staged-only\n")
            subprocess.run(
                ["git", "add", DOSSIER_PATH],
                cwd=root,
                check=True,
                capture_output=True,
            )
            path.write_bytes(original)
            with self.assertRaisesRegex(Rule3LockError, "staged changes"):
                load_and_validate_rule3_lock(root, require_committed=True)

    def test_runtime_rejects_dirty_bound_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            self.write_lock(root)
            self.commit_all(root)
            (root / PRICING_REVIEW_PATH).write_bytes(
                (root / PRICING_REVIEW_PATH).read_bytes() + b"tampered\n"
            )
            with self.assertRaises(Rule3LockError):
                load_and_validate_rule3_lock(root, require_committed=True)

    def test_runtime_git_cleanliness_is_scoped_to_bound_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            self.write_lock(root)
            head = self.commit_all(root)
            (root / "unrelated.txt").write_text("dirty unrelated\n", encoding="utf-8")
            (root / "untracked-notes.txt").write_text("untracked\n", encoding="utf-8")
            context = load_and_validate_rule3_lock(root, require_committed=True)
            self.assertEqual(context.git_head, head)


if __name__ == "__main__":
    unittest.main()
