#!/usr/bin/env python3
from __future__ import annotations

import sys

if __name__ == "__main__" and not sys.flags.isolated:
    sys.stderr.write(
        "Qwen successor stopped before imports: use "
        "python3 -I harness/run_qwen_successor.py\n"
    )
    raise SystemExit(2)

import argparse
import asyncio
import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path, PurePosixPath


REPOSITORY_ROOT = Path(__file__).absolute().parent.parent
_LOCK_PATH = "candidate/qwen-successor-lock.json"
_SCHEMA_VERSION = "concordance-qwen-successor-lock-1.0.0"
_LOCK_STATUS = "immutable-qwen-successor-lock-no-spending-authorized"
_PARENT_LOCK_PATH = "candidate/concordance-recovery-lock.json"
_RULE3_LOCK_PATH = "candidate/rule3-lock.json"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PATH_RE = re.compile(r"^[A-Za-z0-9._/-]+$")
_GIT_HEAD_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_GIT = "/usr/bin/git"
_REQUIRED_SOURCES = frozenset(
    {
        "harness/authorize_concordance_recovery.py",
        "harness/authorize_qwen_successor.py",
        "harness/authorize_rule3.py",
        "harness/concordance_harness/__init__.py",
        "harness/concordance_harness/config.py",
        "harness/concordance_harness/execution.py",
        "harness/concordance_harness/pilot_lock.py",
        "harness/concordance_harness/planner.py",
        "harness/concordance_harness/providers.py",
        "harness/concordance_harness/util.py",
        "harness/concordance_recovery/__init__.py",
        "harness/concordance_recovery/authorization.py",
        "harness/concordance_recovery/composite.py",
        "harness/concordance_recovery/contract.py",
        "harness/concordance_recovery/execute.py",
        "harness/concordance_recovery/journal.py",
        "harness/concordance_recovery/lock.py",
        "harness/concordance_recovery/parent.py",
        "harness/concordance_recovery/state.py",
        "harness/concordance_recovery/transport.py",
        "harness/create_concordance_recovery_lock.py",
        "harness/create_qwen_successor_lock.py",
        "harness/create_rule3_lock.py",
        "harness/evaluate_rule3.py",
        "harness/finalize_rule3_review.py",
        "harness/prepare_rule3_review.py",
        "harness/private_directory_publication.py",
        "harness/qwen_successor/__init__.py",
        "harness/qwen_successor/authorization.py",
        "harness/qwen_successor/composite.py",
        "harness/qwen_successor/contract.py",
        "harness/qwen_successor/execute.py",
        "harness/qwen_successor/lock.py",
        "harness/qwen_successor/parent.py",
        "harness/qwen_successor/state.py",
        "harness/review_concordance_recovery.py",
        "harness/review_qwen_successor.py",
        "harness/rule3/__init__.py",
        "harness/rule3/authorization.py",
        "harness/rule3/budget.py",
        "harness/rule3/contract.py",
        "harness/rule3/evaluate.py",
        "harness/rule3/execute.py",
        "harness/rule3/lock.py",
        "harness/rule3/review.py",
        "harness/rule3/review_assets/review.css",
        "harness/rule3/review_assets/review.js",
        "harness/run_concordance_recovery.py",
        "harness/run_qwen_successor.py",
        "harness/run_rule3.py",
    }
)
_PROJECT_IMPORT_PACKAGES = frozenset(
    {
        "concordance_harness",
        "concordance_recovery",
        "qwen_successor",
        "rule3",
    }
)
_PROTECTED_IMPORT_NAMES = (
    frozenset(sys.stdlib_module_names) | {"certifi"} | _PROJECT_IMPORT_PACKAGES
)
_UNBOUND_IMPORT_SUFFIXES = (".py", ".pyc", ".pyo", ".so", ".dylib", ".pyd")


class PreImportSuccessorError(RuntimeError):
    """Raised before project imports when the committed successor seal fails."""


def _relative_path(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or not _PATH_RE.fullmatch(value)
    ):
        raise PreImportSuccessorError("successor lock contains an invalid bound path")
    pure = PurePosixPath(value)
    if (
        pure.is_absolute()
        or pure.as_posix() != value
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise PreImportSuccessorError(
            "successor lock contains a non-normalized bound path"
        )
    return value


def _read_regular(root: Path, relative: str) -> bytes:
    relative = _relative_path(relative)
    current = root
    for part in PurePosixPath(relative).parts[:-1]:
        current /= part
        try:
            metadata = current.lstat()
        except OSError as error:
            raise PreImportSuccessorError(
                f"{relative}: parent path cannot be inspected: {error}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise PreImportSuccessorError(
                f"{relative}: parent path must be a real directory"
            )
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(root / relative, flags)
    except OSError as error:
        raise PreImportSuccessorError(
            f"{relative}: cannot open a regular file: {error}"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise PreImportSuccessorError(
                f"{relative}: bound path must be a regular file"
            )
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            return handle.read()
    finally:
        os.close(descriptor)


def _load_lock(payload: bytes) -> dict:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise PreImportSuccessorError(f"duplicate successor lock key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise PreImportSuccessorError(f"non-finite successor lock number: {value}")

    try:
        parsed = json.loads(
            payload,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PreImportSuccessorError(
            f"successor lock is not valid UTF-8 JSON: {error}"
        ) from error
    if not isinstance(parsed, dict):
        raise PreImportSuccessorError("successor lock must be a JSON object")
    canonical = (json.dumps(parsed, ensure_ascii=False, indent=2) + "\n").encode(
        "utf-8"
    )
    if payload != canonical:
        raise PreImportSuccessorError("successor lock is not canonical JSON")
    return parsed


def _git(
    root: Path, arguments: list[str], operation: str
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            [_GIT, *arguments],
            cwd=root,
            check=False,
            capture_output=True,
            env={
                "HOME": "/var/empty",
                "PATH": "/usr/bin:/bin",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_TERMINAL_PROMPT": "0",
                "LANG": "C",
                "LC_ALL": "C",
            },
        )
    except OSError as error:
        raise PreImportSuccessorError(
            f"{operation}: git cannot run: {error}"
        ) from error
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise PreImportSuccessorError(
            f"{operation} failed: {detail or 'unknown git error'}"
        )
    return result


def _bindings(lock: dict) -> tuple[dict[str, str], tuple[str, ...]]:
    if lock.get("schema_version") != _SCHEMA_VERSION:
        raise PreImportSuccessorError("successor lock schema version is not approved")
    if lock.get("status") != _LOCK_STATUS:
        raise PreImportSuccessorError("successor lock is not preexecution-sealed")
    declared: dict[str, str] = {}

    def add(value: object) -> None:
        if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
            raise PreImportSuccessorError("successor lock contains a malformed binding")
        relative = _relative_path(value["path"])
        digest = value["sha256"]
        if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
            raise PreImportSuccessorError(f"{relative}: invalid bound SHA-256")
        if relative in declared or relative == _LOCK_PATH:
            raise PreImportSuccessorError(
                "successor lock contains duplicate bound paths"
            )
        declared[relative] = digest

    top = lock.get("bindings")
    sources = lock.get("execution_sources")
    if (
        not isinstance(top, dict)
        or set(top) != {"first_recovery_lock", "rule3_lock"}
        or not isinstance(sources, list)
    ):
        raise PreImportSuccessorError("successor lock bindings are malformed")
    for value in top.values():
        add(value)
    if top["first_recovery_lock"]["path"] != _PARENT_LOCK_PATH:
        raise PreImportSuccessorError("successor lock does not bind its first parent")
    if top["rule3_lock"]["path"] != _RULE3_LOCK_PATH:
        raise PreImportSuccessorError("successor lock does not bind its Rule 3 parent")
    source_paths: set[str] = set()
    for source in sources:
        add(source)
        if isinstance(source, dict) and isinstance(source.get("path"), str):
            source_paths.add(source["path"])
    missing = sorted(_REQUIRED_SOURCES - source_paths)
    if missing:
        raise PreImportSuccessorError(
            "successor lock omits project code imported below the gate: "
            + ", ".join(missing)
        )
    return declared, (_LOCK_PATH, *declared)


def _reject_import_shadows(root: Path, bound_paths: frozenset[str]) -> None:
    harness = root / "harness"
    try:
        children = tuple(harness.iterdir())
    except OSError as error:
        raise PreImportSuccessorError(
            f"harness import root cannot be inspected: {error}"
        ) from error
    shadows = []
    for child in children:
        base = child.name.split(".", 1)[0]
        if child.name in _PROJECT_IMPORT_PACKAGES:
            metadata = child.lstat()
            if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
                continue
        if base in _PROTECTED_IMPORT_NAMES:
            shadows.append(child.name)
    if shadows:
        raise PreImportSuccessorError(
            "harness contains a local import shadow: " + ", ".join(sorted(shadows))
        )
    package_shadows = []
    for package in sorted(_PROJECT_IMPORT_PACKAGES):
        package_root = harness / package
        for directory, directory_names, file_names in os.walk(
            package_root, topdown=True, followlinks=False
        ):
            directory_path = Path(directory)
            kept = []
            for name in sorted(directory_names):
                child = directory_path / name
                metadata = child.lstat()
                if stat.S_ISLNK(metadata.st_mode) or name == "__pycache__":
                    package_shadows.append(child.relative_to(root).as_posix())
                    continue
                kept.append(name)
            directory_names[:] = kept
            for name in sorted(file_names):
                child = directory_path / name
                metadata = child.lstat()
                relative = child.relative_to(root).as_posix()
                if stat.S_ISLNK(metadata.st_mode) or (
                    name.endswith(_UNBOUND_IMPORT_SUFFIXES)
                    and relative not in bound_paths
                ):
                    package_shadows.append(relative)
    if package_shadows:
        raise PreImportSuccessorError(
            "harness package contains an unbound import shadow: "
            + ", ".join(sorted(package_shadows))
        )


def _preimport_bootstrap(repository_root: Path | str) -> str:
    root = Path(repository_root).absolute()
    try:
        metadata = root.lstat()
    except OSError as error:
        raise PreImportSuccessorError(
            f"repository root cannot be inspected: {error}"
        ) from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise PreImportSuccessorError("repository root must be a real directory")
    root = root.resolve()
    lock_payload = _read_regular(root, _LOCK_PATH)
    lock = _load_lock(lock_payload)
    declared, paths = _bindings(lock)
    _reject_import_shadows(root, frozenset(declared))
    snapshots = {_LOCK_PATH: lock_payload}
    for relative, expected in declared.items():
        payload = _read_regular(root, relative)
        if hashlib.sha256(payload).hexdigest() != expected:
            raise PreImportSuccessorError(
                f"{relative}: working bytes differ from the successor lock"
            )
        snapshots[relative] = payload
    top = _git(root, ["rev-parse", "--show-toplevel"], "worktree check")
    try:
        git_root = Path(top.stdout.decode("utf-8", errors="strict").strip()).resolve()
    except (UnicodeDecodeError, OSError) as error:
        raise PreImportSuccessorError(
            "Git returned an invalid worktree root"
        ) from error
    if git_root != root:
        raise PreImportSuccessorError(
            "run_qwen_successor.py must run from its Git worktree root"
        )
    head = (
        _git(root, ["rev-parse", "--verify", "HEAD"], "HEAD check")
        .stdout.decode("ascii", errors="strict")
        .strip()
    )
    if not _GIT_HEAD_RE.fullmatch(head):
        raise PreImportSuccessorError("Git HEAD is not a full object ID")
    for relative in paths:
        tree = _git(
            root,
            ["ls-tree", "-z", head, "--", relative],
            f"HEAD tree check for {relative}",
        )
        entries = [entry for entry in tree.stdout.split(b"\0") if entry]
        if len(entries) != 1 or b"\t" not in entries[0]:
            raise PreImportSuccessorError(f"{relative}: file is not committed in HEAD")
        fields, recorded = entries[0].split(b"\t", 1)
        metadata_fields = fields.split()
        if (
            len(metadata_fields) != 3
            or metadata_fields[0] not in {b"100644", b"100755"}
            or metadata_fields[1] != b"blob"
            or recorded.decode("utf-8", errors="strict") != relative
        ):
            raise PreImportSuccessorError(
                f"{relative}: HEAD entry is not the required regular blob"
            )
        committed = _git(
            root,
            ["cat-file", "blob", f"{head}:{relative}"],
            f"HEAD blob read for {relative}",
        )
        if committed.stdout != snapshots[relative]:
            raise PreImportSuccessorError(f"{relative}: working bytes differ from HEAD")
    _git(
        root,
        ["diff", "--no-ext-diff", "--quiet", "--", *paths],
        "unstaged bound-path check",
    )
    _git(
        root,
        ["diff", "--no-ext-diff", "--cached", "--quiet", head, "--", *paths],
        "staged bound-path check",
    )
    final_head = (
        _git(root, ["rev-parse", "--verify", "HEAD"], "final HEAD check")
        .stdout.decode("ascii", errors="strict")
        .strip()
    )
    if final_head != head:
        raise PreImportSuccessorError("Git HEAD changed during pre-import verification")
    for relative, snapshot in snapshots.items():
        if _read_regular(root, relative) != snapshot:
            raise PreImportSuccessorError(
                f"{relative}: bound bytes changed during pre-import verification"
            )
    return head


if __name__ == "__main__":
    try:
        _preimport_bootstrap(REPOSITORY_ROOT)
    except (PreImportSuccessorError, OSError, ValueError) as error:
        print(
            f"Qwen successor stopped before project imports: {error}",
            file=sys.stderr,
        )
        raise SystemExit(2) from None
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(REPOSITORY_ROOT / "harness"))

from concordance_harness.config import ConfigError  # noqa: E402
from concordance_harness.planner import PlanError  # noqa: E402
from concordance_harness.providers import ProviderError  # noqa: E402
from concordance_recovery.authorization import (  # noqa: E402
    RecoveryAuthorizationError,
)
from concordance_recovery.execute import RecoveryExecutionError  # noqa: E402
from concordance_recovery.journal import RecoveryJournalError  # noqa: E402
from qwen_successor.authorization import AuthorizationError  # noqa: E402
from qwen_successor.execute import (  # noqa: E402
    SuccessorExecutionError,
    dry_run_summary,
    execute_prepared,
    prepare_successor,
)
from qwen_successor.lock import QwenSuccessorLockError  # noqa: E402


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(
        description="Plan or execute the exact Qwen successor recovery."
    )
    mode = command.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--live", action="store_true")
    command.add_argument("--credentials-confirmed", action="store_true")
    return command


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.dry_run and args.credentials_confirmed:
        parser().error("--credentials-confirmed is valid only with --live")
    if args.live and not args.credentials_confirmed:
        print(
            "Qwen successor stopped: live mode requires --credentials-confirmed",
            file=sys.stderr,
        )
        return 2
    try:
        prepared = prepare_successor(REPOSITORY_ROOT, require_committed=True)
        if args.dry_run:
            print(json.dumps(dry_run_summary(prepared), indent=2))
            return 0
        result = asyncio.run(execute_prepared(prepared))
        print(f"Status: {result.payload['status']}")
        if result.sha256:
            print(f"Receipt: {result.path.relative_to(REPOSITORY_ROOT)}")
            print(f"Receipt SHA-256: {result.sha256}")
        print(f"Outbound requests this invocation: {result.network_requests}")
        return 0 if result.payload["status"].startswith("complete-eight") else 2
    except (
        AuthorizationError,
        ConfigError,
        OSError,
        PlanError,
        ProviderError,
        QwenSuccessorLockError,
        RecoveryAuthorizationError,
        RecoveryExecutionError,
        RecoveryJournalError,
        SuccessorExecutionError,
        ValueError,
    ) as error:
        print(f"Qwen successor stopped: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
