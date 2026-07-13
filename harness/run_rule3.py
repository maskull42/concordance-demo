#!/usr/bin/env python3
from __future__ import annotations

import sys

if __name__ == "__main__" and not sys.flags.isolated:
    sys.stderr.write(
        "Rule 3 execution stopped before imports: use "
        "python3 -I harness/run_rule3.py\n"
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
_BOOTSTRAP_LOCK_PATH = "candidate/rule3-lock.json"
_BOOTSTRAP_SCHEMA_VERSION = "rule3-lock-1.0.0"
_BOOTSTRAP_LOCK_STATUS = "immutable-preexecution-lock-no-spending-authorized"
_BOOTSTRAP_PROTOCOL_PATH = "config/rule3-protocol.json"
_BOOTSTRAP_PROTOCOL_VERSION = "rule3-1.0.0"
_BOOTSTRAP_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_BOOTSTRAP_PATH_RE = re.compile(r"^[A-Za-z0-9._/-]+$")
_BOOTSTRAP_GIT_HEAD_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_BOOTSTRAP_GIT = "/usr/bin/git"
_BOOTSTRAP_REQUIRED_PROJECT_SOURCES = frozenset(
    {
        "harness/run_rule3.py",
        "harness/concordance_harness/__init__.py",
        "harness/concordance_harness/config.py",
        "harness/concordance_harness/execution.py",
        "harness/concordance_harness/planner.py",
        "harness/concordance_harness/providers.py",
        "harness/concordance_harness/util.py",
        "harness/rule3/__init__.py",
        "harness/rule3/authorization.py",
        "harness/rule3/budget.py",
        "harness/rule3/contract.py",
        "harness/rule3/execute.py",
        "harness/rule3/lock.py",
    }
)
_BOOTSTRAP_PROTECTED_IMPORT_NAMES = frozenset(sys.stdlib_module_names) | {"certifi"}


class PreImportBootstrapError(RuntimeError):
    """Raised before project imports when the committed execution seal fails."""


def _bootstrap_relative_path(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or not _BOOTSTRAP_PATH_RE.fullmatch(value)
    ):
        raise PreImportBootstrapError("lock contains an invalid bound path")
    pure = PurePosixPath(value)
    if (
        pure.is_absolute()
        or pure.as_posix() != value
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise PreImportBootstrapError("lock contains a non-normalized bound path")
    return value


def _bootstrap_read_regular(root: Path, relative: str) -> bytes:
    relative = _bootstrap_relative_path(relative)
    current = root
    for part in PurePosixPath(relative).parts[:-1]:
        current /= part
        try:
            metadata = current.lstat()
        except OSError as error:
            raise PreImportBootstrapError(
                f"{relative}: parent path cannot be inspected: {error}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise PreImportBootstrapError(
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
        raise PreImportBootstrapError(
            f"{relative}: cannot open a regular file: {error}"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise PreImportBootstrapError(
                f"{relative}: bound path must be a regular file"
            )
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            return handle.read()
    finally:
        os.close(descriptor)


def _bootstrap_json(payload: bytes) -> dict:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        parsed: dict[str, object] = {}
        for key, value in pairs:
            if key in parsed:
                raise PreImportBootstrapError(f"duplicate lock key: {key}")
            parsed[key] = value
        return parsed

    def reject_constant(value: str) -> None:
        raise PreImportBootstrapError(f"non-finite lock number: {value}")

    try:
        parsed = json.loads(
            payload,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PreImportBootstrapError(f"Rule 3 lock is not valid UTF-8 JSON: {error}")
    if not isinstance(parsed, dict):
        raise PreImportBootstrapError("Rule 3 lock must be a JSON object")
    canonical = (json.dumps(parsed, ensure_ascii=False, indent=2) + "\n").encode(
        "utf-8"
    )
    if payload != canonical:
        raise PreImportBootstrapError("Rule 3 lock is not canonical JSON")
    return parsed


def _bootstrap_git(
    root: Path,
    arguments: list[str],
    operation: str,
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            [_BOOTSTRAP_GIT, *arguments],
            cwd=root,
            check=False,
            capture_output=True,
            env={"HOME": "/var/empty", "PATH": "/usr/bin:/bin"},
        )
    except OSError as error:
        raise PreImportBootstrapError(
            f"{operation}: git cannot run: {error}"
        ) from error
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise PreImportBootstrapError(
            f"{operation} failed: {detail or 'unknown git error'}"
        )
    return result


def _bootstrap_lock_bindings(lock: dict) -> tuple[dict[str, str], tuple[str, ...]]:
    if lock.get("schema_version") != _BOOTSTRAP_SCHEMA_VERSION:
        raise PreImportBootstrapError("Rule 3 lock schema version is not approved")
    if lock.get("status") != _BOOTSTRAP_LOCK_STATUS:
        raise PreImportBootstrapError("Rule 3 lock status is not preexecution-sealed")

    declared: dict[str, str] = {}

    def add_binding(value: object) -> None:
        if not isinstance(value, dict) or not {"path", "sha256"}.issubset(value):
            raise PreImportBootstrapError("Rule 3 lock contains a malformed binding")
        relative = _bootstrap_relative_path(value["path"])
        digest = value["sha256"]
        if not isinstance(digest, str) or not _BOOTSTRAP_SHA256_RE.fullmatch(digest):
            raise PreImportBootstrapError(f"{relative}: invalid bound SHA-256")
        if relative in declared or relative == _BOOTSTRAP_LOCK_PATH:
            raise PreImportBootstrapError("Rule 3 lock contains duplicate bound paths")
        declared[relative] = digest

    bindings = lock.get("bindings")
    candidates = lock.get("candidates")
    sources = lock.get("execution_sources")
    if not isinstance(bindings, dict):
        raise PreImportBootstrapError("Rule 3 lock bindings are malformed")
    protocol_binding = bindings.get("protocol")
    if (
        not isinstance(protocol_binding, dict)
        or protocol_binding.get("path") != _BOOTSTRAP_PROTOCOL_PATH
        or protocol_binding.get("protocol_version") != _BOOTSTRAP_PROTOCOL_VERSION
    ):
        raise PreImportBootstrapError(
            "Rule 3 lock does not bind the approved Rule 3-specific protocol"
        )
    if not isinstance(candidates, list) or not isinstance(sources, list):
        raise PreImportBootstrapError("Rule 3 lock source lists are malformed")
    for binding in bindings.values():
        add_binding(binding)
    for candidate in candidates:
        add_binding(candidate)
    execution_source_paths: set[str] = set()
    for source in sources:
        add_binding(source)
        if isinstance(source, dict) and isinstance(source.get("path"), str):
            execution_source_paths.add(source["path"])
    missing_project_sources = sorted(
        _BOOTSTRAP_REQUIRED_PROJECT_SOURCES - execution_source_paths
    )
    if missing_project_sources:
        raise PreImportBootstrapError(
            "Rule 3 lock omits project code imported below the gate: "
            + ", ".join(missing_project_sources)
        )
    paths = (_BOOTSTRAP_LOCK_PATH, *declared)
    return declared, paths


def _bootstrap_reject_import_shadows(root: Path) -> None:
    harness = root / "harness"
    try:
        children = tuple(harness.iterdir())
    except OSError as error:
        raise PreImportBootstrapError(
            f"harness import root cannot be inspected: {error}"
        ) from error
    shadows = sorted(
        child.name
        for child in children
        if child.name.split(".", 1)[0] in _BOOTSTRAP_PROTECTED_IMPORT_NAMES
    )
    if shadows:
        raise PreImportBootstrapError(
            "harness contains a local standard-library or dependency shadow: "
            + ", ".join(shadows)
        )


def _preimport_bootstrap(repository_root: Path | str) -> str:
    """Verify committed bound bytes using only the Python standard library."""
    root = Path(repository_root).absolute()
    try:
        root_metadata = root.lstat()
    except OSError as error:
        raise PreImportBootstrapError(f"repository root cannot be inspected: {error}")
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise PreImportBootstrapError("repository root must be a real directory")
    root = root.resolve()

    lock_payload = _bootstrap_read_regular(root, _BOOTSTRAP_LOCK_PATH)
    lock = _bootstrap_json(lock_payload)
    declared, paths = _bootstrap_lock_bindings(lock)
    _bootstrap_reject_import_shadows(root)
    snapshots = {_BOOTSTRAP_LOCK_PATH: lock_payload}
    for relative, expected_sha256 in declared.items():
        payload = _bootstrap_read_regular(root, relative)
        if hashlib.sha256(payload).hexdigest() != expected_sha256:
            raise PreImportBootstrapError(
                f"{relative}: working bytes differ from the canonical lock"
            )
        snapshots[relative] = payload

    top = _bootstrap_git(root, ["rev-parse", "--show-toplevel"], "worktree check")
    try:
        git_root = Path(top.stdout.decode("utf-8", errors="strict").strip()).resolve()
    except (UnicodeDecodeError, OSError) as error:
        raise PreImportBootstrapError(
            "Git returned an invalid worktree root"
        ) from error
    if git_root != root:
        raise PreImportBootstrapError(
            "run_rule3.py must run from its Git worktree root"
        )
    head_result = _bootstrap_git(root, ["rev-parse", "--verify", "HEAD"], "HEAD check")
    try:
        git_head = head_result.stdout.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise PreImportBootstrapError("Git HEAD is not ASCII") from error
    if not _BOOTSTRAP_GIT_HEAD_RE.fullmatch(git_head):
        raise PreImportBootstrapError("Git HEAD is not a full object ID")

    for relative in paths:
        tree = _bootstrap_git(
            root,
            ["ls-tree", "-z", git_head, "--", relative],
            f"HEAD tree check for {relative}",
        )
        entries = [entry for entry in tree.stdout.split(b"\0") if entry]
        if len(entries) != 1 or b"\t" not in entries[0]:
            raise PreImportBootstrapError(f"{relative}: file is not committed in HEAD")
        metadata, recorded_path = entries[0].split(b"\t", 1)
        fields = metadata.split()
        if (
            len(fields) != 3
            or fields[0] not in {b"100644", b"100755"}
            or fields[1] != b"blob"
            or recorded_path.decode("utf-8", errors="strict") != relative
        ):
            raise PreImportBootstrapError(
                f"{relative}: HEAD entry is not the required regular blob"
            )
        committed = _bootstrap_git(
            root,
            ["cat-file", "blob", f"{git_head}:{relative}"],
            f"HEAD blob read for {relative}",
        )
        if committed.stdout != snapshots[relative]:
            raise PreImportBootstrapError(f"{relative}: working bytes differ from HEAD")

    _bootstrap_git(
        root,
        ["diff", "--no-ext-diff", "--quiet", "--", *paths],
        "unstaged bound-path check",
    )
    _bootstrap_git(
        root,
        ["diff", "--no-ext-diff", "--cached", "--quiet", git_head, "--", *paths],
        "staged bound-path check",
    )
    final_head = (
        _bootstrap_git(root, ["rev-parse", "--verify", "HEAD"], "final HEAD check")
        .stdout.decode("ascii", errors="strict")
        .strip()
    )
    if final_head != git_head:
        raise PreImportBootstrapError("Git HEAD changed during pre-import verification")
    for relative, snapshot in snapshots.items():
        if _bootstrap_read_regular(root, relative) != snapshot:
            raise PreImportBootstrapError(
                f"{relative}: bound bytes changed during pre-import verification"
            )
    return git_head


if __name__ == "__main__":
    try:
        _preimport_bootstrap(REPOSITORY_ROOT)
    except (PreImportBootstrapError, OSError, ValueError) as error:
        print(
            f"Rule 3 execution stopped before project imports: {error}",
            file=sys.stderr,
        )
        raise SystemExit(2) from None
    sys.path.insert(0, str(REPOSITORY_ROOT / "harness"))

from concordance_harness.config import ConfigError  # noqa: E402
from concordance_harness.planner import PlanError  # noqa: E402
from concordance_harness.providers import ProviderError  # noqa: E402
from rule3.authorization import AuthorizationError  # noqa: E402
from rule3.budget import BudgetError  # noqa: E402
from rule3.execute import (  # noqa: E402
    Rule3ExecutionError,
    dry_run_summary,
    execute_prepared,
    prepare_execution,
)


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(
        description="Plan or execute one exact phase of the private Rule 3 supplement."
    )
    mode = command.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--live", action="store_true")
    command.add_argument("--phase", choices=("priority", "fallback"), required=True)
    command.add_argument("--credentials-rotated", action="store_true")
    return command


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.dry_run and args.credentials_rotated:
        parser().error("--credentials-rotated is valid only with --live")
    if args.live and not args.credentials_rotated:
        print(
            "Rule 3 execution stopped: live mode requires --credentials-rotated",
            file=sys.stderr,
        )
        return 2
    try:
        prepared = prepare_execution(REPOSITORY_ROOT, args.phase, live=args.live)
        if args.dry_run:
            print(json.dumps(dry_run_summary(prepared), indent=2))
            return 0
        result = asyncio.run(execute_prepared(prepared))
        print(
            f"Rule 3 {args.phase} result: "
            f"{result.path.relative_to(REPOSITORY_ROOT)}"
        )
        print(f"Status: {result.payload['status']}")
        print(f"Outbound requests this invocation: {result.network_requests}")
        return 0 if result.payload["status"] == "complete-eight-successes" else 2
    except (
        AuthorizationError,
        BudgetError,
        ConfigError,
        PlanError,
        ProviderError,
        Rule3ExecutionError,
        OSError,
        ValueError,
    ) as error:
        print(f"Rule 3 execution stopped: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
