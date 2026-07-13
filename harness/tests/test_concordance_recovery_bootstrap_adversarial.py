from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from concordance_recovery.contract import (  # noqa: E402
    RECOVERY_LOCK_PATH,
    RECOVERY_LOCK_SCHEMA_PATH,
    canonical_json_bytes,
    discover_recovery_source_paths,
)
from concordance_recovery.lock import build_recovery_lock  # noqa: E402
from run_concordance_recovery import (  # noqa: E402
    _REQUIRED_SOURCES,
    PreImportRecoveryError,
    _preimport_bootstrap,
)

GIT = "/usr/bin/git"
RUNNER_PATH = "harness/run_concordance_recovery.py"


def repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


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
) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [GIT, *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=text,
        env=git_environment(home),
    )


def parent_public_paths(parent: dict[str, object]) -> set[str]:
    paths = {"candidate/rule3-lock.json"}
    bindings = parent["bindings"]
    candidates = parent["candidates"]
    sources = parent["execution_sources"]
    if not isinstance(bindings, dict):
        raise AssertionError("test fixture parent bindings are malformed")
    if not isinstance(candidates, list) or not isinstance(sources, list):
        raise AssertionError("test fixture parent inventory is malformed")
    paths.update(item["path"] for item in bindings.values())
    paths.update(item["path"] for item in candidates)
    paths.update(item["path"] for item in sources)
    if not all(isinstance(path, str) for path in paths):
        raise AssertionError("test fixture parent path is malformed")
    return paths


class ConcordanceRecoveryBootstrapAdversarialTests(unittest.TestCase):
    seed_temporary: tempfile.TemporaryDirectory[str]
    seed_root: Path
    seed_home: Path

    @classmethod
    def setUpClass(cls) -> None:
        cls.seed_temporary = tempfile.TemporaryDirectory()
        temporary = Path(cls.seed_temporary.name)
        cls.seed_root = temporary / "public-seed"
        cls.seed_home = temporary / "home"
        cls.seed_root.mkdir()
        cls.seed_home.mkdir()

        source = repository_root()
        parent = json.loads((source / "candidate/rule3-lock.json").read_bytes())
        parent_sources = tuple(item["path"] for item in parent["execution_sources"])
        paths = parent_public_paths(parent)
        paths.add(RECOVERY_LOCK_SCHEMA_PATH)
        paths.update(discover_recovery_source_paths(source, parent_sources))
        for relative in sorted(paths):
            destination = cls.seed_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source / relative, destination)

        lock = build_recovery_lock(cls.seed_root)
        lock_path = cls.seed_root / RECOVERY_LOCK_PATH
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path.write_bytes(canonical_json_bytes(lock))
        paths.add(RECOVERY_LOCK_PATH)

        run_git(cls.seed_root, ["init", "--quiet"], home=cls.seed_home)
        run_git(
            cls.seed_root,
            ["add", "--", *sorted(paths)],
            home=cls.seed_home,
        )
        run_git(
            cls.seed_root,
            [
                "-c",
                "user.name=Concordance Bootstrap Test",
                "-c",
                "user.email=bootstrap@example.invalid",
                "commit",
                "--quiet",
                "--no-gpg-sign",
                "-m",
                "seal public recovery fixture",
            ],
            home=cls.seed_home,
        )
        if (cls.seed_root / ".pilot").exists():
            raise AssertionError("bootstrap fixture must contain no private state")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.seed_temporary.cleanup()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        temporary = Path(self.temporary.name)
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
        self.assertFalse((self.root / ".pilot").exists())

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def read_lock(self) -> dict[str, object]:
        return json.loads((self.root / RECOVERY_LOCK_PATH).read_bytes())

    def write_lock(self, lock: dict[str, object]) -> None:
        (self.root / RECOVERY_LOCK_PATH).write_bytes(canonical_json_bytes(lock))

    def commit(self, paths: list[str], message: str) -> str:
        run_git(self.root, ["add", "--", *paths], home=self.home)
        run_git(
            self.root,
            [
                "-c",
                "user.name=Concordance Bootstrap Test",
                "-c",
                "user.email=bootstrap@example.invalid",
                "commit",
                "--quiet",
                "--no-gpg-sign",
                "-m",
                message,
            ],
            home=self.home,
        )
        return self.head()

    def head(self) -> str:
        result = run_git(
            self.root,
            ["rev-parse", "HEAD"],
            home=self.home,
            text=True,
        )
        return result.stdout.strip()

    def run_runner(self, *, isolated: bool) -> subprocess.CompletedProcess[str]:
        command = [sys.executable]
        if isolated:
            command.append("-I")
        command.extend([RUNNER_PATH, "--dry-run"])
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

    def test_accepts_exact_clean_committed_public_lock(self) -> None:
        self.assertEqual(_preimport_bootstrap(self.root), self.head())
        self.assertFalse((self.root / ".pilot").exists())

    def test_requires_isolated_mode_before_import_shadow_can_execute(self) -> None:
        sentinel = self.root / "shadow-import-ran"
        (self.root / "harness/json.py").write_text(
            f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('ran')\n",
            encoding="utf-8",
        )

        result = self.run_runner(isolated=False)

        self.assertEqual(result.returncode, 2)
        self.assertIn("use python3 -I", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertFalse(sentinel.exists())

    def test_isolated_gate_rejects_import_shadow_before_project_imports(self) -> None:
        shadow_sentinel = self.root / "shadow-import-ran"
        project_sentinel = self.root / "project-import-ran"
        (self.root / "harness/json.py").write_text(
            "from pathlib import Path\n"
            f"Path({str(shadow_sentinel)!r}).write_text('ran')\n",
            encoding="utf-8",
        )
        config = self.root / "harness/concordance_harness/config.py"
        config.write_text(
            "from pathlib import Path\n"
            f"Path({str(project_sentinel)!r}).write_text('ran')\n"
            + config.read_text(encoding="utf-8"),
            encoding="utf-8",
        )

        result = self.run_runner(isolated=True)

        self.assertEqual(result.returncode, 2)
        self.assertIn("stopped before project imports", result.stderr)
        self.assertIn("local import shadow", result.stderr)
        self.assertFalse(shadow_sentinel.exists())
        self.assertFalse(project_sentinel.exists())

    def test_tampered_project_source_is_rejected_before_its_import(self) -> None:
        sentinel = self.root / "project-import-ran"
        config = self.root / "harness/concordance_harness/config.py"
        config.write_text(
            "from pathlib import Path\n"
            f"Path({str(sentinel)!r}).write_text('ran')\n"
            + config.read_text(encoding="utf-8"),
            encoding="utf-8",
        )

        result = self.run_runner(isolated=True)

        self.assertEqual(result.returncode, 2)
        self.assertIn("stopped before project imports", result.stderr)
        self.assertIn("working bytes differ from the recovery lock", result.stderr)
        self.assertFalse(sentinel.exists())

    def test_every_mandatory_below_gate_source_must_be_bound(self) -> None:
        original = self.read_lock()
        sources = original["execution_sources"]
        self.assertIsInstance(sources, list)
        source_paths = {item["path"] for item in sources}
        self.assertTrue(_REQUIRED_SOURCES.issubset(source_paths))

        for missing in sorted(_REQUIRED_SOURCES):
            with self.subTest(path=missing):
                lock = json.loads(canonical_json_bytes(original))
                lock["execution_sources"] = [
                    item
                    for item in lock["execution_sources"]
                    if item["path"] != missing
                ]
                self.write_lock(lock)
                with self.assertRaisesRegex(
                    PreImportRecoveryError,
                    "omits project code imported below the gate",
                ) as raised:
                    _preimport_bootstrap(self.root)
                self.assertIn(missing, str(raised.exception))
        self.write_lock(original)

    def test_rejects_uncommitted_bound_source_even_when_lock_hash_matches(self) -> None:
        relative = "harness/concordance_recovery/authorization.py"
        source = self.root / relative
        source.write_bytes(source.read_bytes() + b"\n# uncommitted mutation\n")
        lock = self.read_lock()
        for binding in lock["execution_sources"]:
            if binding["path"] == relative:
                binding["sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
                break
        else:
            self.fail(f"missing recovery source binding: {relative}")
        self.write_lock(lock)
        self.commit([RECOVERY_LOCK_PATH], "commit lock but not changed source")

        with self.assertRaisesRegex(
            PreImportRecoveryError, "working bytes differ from HEAD"
        ):
            _preimport_bootstrap(self.root)

    def test_rejects_new_bound_file_absent_from_head(self) -> None:
        relative = "harness/concordance_recovery/uncommitted_helper.py"
        helper = self.root / relative
        helper.write_text("VALUE = 'uncommitted'\n", encoding="utf-8")
        lock = self.read_lock()
        lock["execution_sources"].append(
            {
                "path": relative,
                "sha256": hashlib.sha256(helper.read_bytes()).hexdigest(),
            }
        )
        self.write_lock(lock)
        self.commit([RECOVERY_LOCK_PATH], "bind but do not commit helper")

        with self.assertRaisesRegex(
            PreImportRecoveryError, "file is not committed in HEAD"
        ):
            _preimport_bootstrap(self.root)

    def test_rejects_dirty_staged_bound_path(self) -> None:
        relative = "harness/concordance_recovery/authorization.py"
        run_git(
            self.root,
            ["update-index", "--chmod=+x", "--", relative],
            home=self.home,
        )

        with self.assertRaisesRegex(PreImportRecoveryError, "bound-path check failed"):
            _preimport_bootstrap(self.root)

    def test_rejects_tampered_lock_before_git_or_project_imports(self) -> None:
        lock = self.read_lock()
        lock["status"] = "tampered"
        self.write_lock(lock)

        with self.assertRaisesRegex(PreImportRecoveryError, "not preexecution-sealed"):
            _preimport_bootstrap(self.root)

    def test_rejects_symlinked_lock_bound_file_and_parent_directory(self) -> None:
        mutations = ("lock", "source", "source-parent")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory() as temporary:
                    clone_parent = Path(temporary)
                    root = clone_parent / "repo"
                    home = clone_parent / "home"
                    home.mkdir()
                    run_git(
                        clone_parent,
                        [
                            "clone",
                            "--quiet",
                            "--no-hardlinks",
                            str(self.seed_root),
                            str(root),
                        ],
                        home=home,
                    )
                    if mutation == "lock":
                        path = root / RECOVERY_LOCK_PATH
                        target = root / "lock-copy.json"
                        target.write_bytes(path.read_bytes())
                        path.unlink()
                        path.symlink_to(target)
                    elif mutation == "source":
                        path = root / "harness/concordance_recovery/authorization.py"
                        target = root / "authorization-copy.py"
                        target.write_bytes(path.read_bytes())
                        path.unlink()
                        path.symlink_to(target)
                    else:
                        path = root / "harness/concordance_recovery"
                        target = root / "recovery-package-copy"
                        path.rename(target)
                        path.symlink_to(target, target_is_directory=True)

                    with self.assertRaisesRegex(
                        PreImportRecoveryError,
                        "regular file|real directory|cannot open",
                    ):
                        _preimport_bootstrap(root)


if __name__ == "__main__":
    unittest.main()
