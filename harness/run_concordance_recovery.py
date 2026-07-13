#!/usr/bin/env python3
from __future__ import annotations

import sys

if __name__ == "__main__" and not sys.flags.isolated:
    sys.stderr.write(
        "Concordance recovery stopped before imports: use "
        "python3 -I harness/run_concordance_recovery.py\n"
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
_LOCK_PATH = "candidate/concordance-recovery-lock.json"
_SCHEMA_VERSION = "concordance-rule3-recovery-lock-1.0.0"
_LOCK_STATUS = "immutable-successor-recovery-lock-no-spending-authorized"
_PARENT_LOCK_PATH = "candidate/rule3-lock.json"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PATH_RE = re.compile(r"^[A-Za-z0-9._/-]+$")
_GIT_HEAD_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_GIT = "/usr/bin/git"
_REQUIRED_SOURCES = frozenset(
    {
        "harness/run_concordance_recovery.py",
        "harness/concordance_recovery/__init__.py",
        "harness/concordance_recovery/authorization.py",
        "harness/concordance_recovery/contract.py",
        "harness/concordance_recovery/execute.py",
        "harness/concordance_recovery/journal.py",
        "harness/concordance_recovery/lock.py",
        "harness/concordance_recovery/parent.py",
        "harness/concordance_recovery/state.py",
        "harness/concordance_recovery/transport.py",
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
_PROTECTED_IMPORT_NAMES = frozenset(sys.stdlib_module_names) | {"certifi"}


class PreImportRecoveryError(RuntimeError):
    """Raised before project imports when the committed recovery seal fails."""


def _relative_path(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or not _PATH_RE.fullmatch(value)
    ):
        raise PreImportRecoveryError("recovery lock contains an invalid bound path")
    pure = PurePosixPath(value)
    if (
        pure.is_absolute()
        or pure.as_posix() != value
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise PreImportRecoveryError(
            "recovery lock contains a non-normalized bound path"
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
            raise PreImportRecoveryError(
                f"{relative}: parent path cannot be inspected: {error}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise PreImportRecoveryError(
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
        raise PreImportRecoveryError(
            f"{relative}: cannot open a regular file: {error}"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise PreImportRecoveryError(
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
                raise PreImportRecoveryError(f"duplicate recovery lock key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise PreImportRecoveryError(f"non-finite recovery lock number: {value}")

    try:
        parsed = json.loads(
            payload,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PreImportRecoveryError(
            f"recovery lock is not valid UTF-8 JSON: {error}"
        ) from error
    if not isinstance(parsed, dict):
        raise PreImportRecoveryError("recovery lock must be a JSON object")
    canonical = (json.dumps(parsed, ensure_ascii=False, indent=2) + "\n").encode(
        "utf-8"
    )
    if payload != canonical:
        raise PreImportRecoveryError("recovery lock is not canonical JSON")
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
        raise PreImportRecoveryError(f"{operation}: git cannot run: {error}") from error
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise PreImportRecoveryError(
            f"{operation} failed: {detail or 'unknown git error'}"
        )
    return result


def _bindings(lock: dict) -> tuple[dict[str, str], tuple[str, ...]]:
    if lock.get("schema_version") != _SCHEMA_VERSION:
        raise PreImportRecoveryError("recovery lock schema version is not approved")
    if lock.get("status") != _LOCK_STATUS:
        raise PreImportRecoveryError("recovery lock is not preexecution-sealed")
    declared: dict[str, str] = {}

    def add(value: object) -> None:
        if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
            raise PreImportRecoveryError("recovery lock contains a malformed binding")
        relative = _relative_path(value["path"])
        digest = value["sha256"]
        if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
            raise PreImportRecoveryError(f"{relative}: invalid bound SHA-256")
        if relative in declared or relative == _LOCK_PATH:
            raise PreImportRecoveryError("recovery lock contains duplicate bound paths")
        declared[relative] = digest

    top_bindings = lock.get("bindings")
    sources = lock.get("execution_sources")
    if not isinstance(top_bindings, dict) or not isinstance(sources, list):
        raise PreImportRecoveryError("recovery lock bindings are malformed")
    if top_bindings.get("parent_lock", {}).get("path") != _PARENT_LOCK_PATH:
        raise PreImportRecoveryError("recovery lock does not bind the parent lock")
    for value in top_bindings.values():
        add(value)
    source_paths: set[str] = set()
    for source in sources:
        add(source)
        if isinstance(source, dict) and isinstance(source.get("path"), str):
            source_paths.add(source["path"])
    missing = sorted(_REQUIRED_SOURCES - source_paths)
    if missing:
        raise PreImportRecoveryError(
            "recovery lock omits project code imported below the gate: "
            + ", ".join(missing)
        )
    return declared, (_LOCK_PATH, *declared)


def _reject_import_shadows(root: Path) -> None:
    harness = root / "harness"
    try:
        children = tuple(harness.iterdir())
    except OSError as error:
        raise PreImportRecoveryError(
            f"harness import root cannot be inspected: {error}"
        ) from error
    shadows = sorted(
        child.name
        for child in children
        if child.name.split(".", 1)[0] in _PROTECTED_IMPORT_NAMES
    )
    if shadows:
        raise PreImportRecoveryError(
            "harness contains a local import shadow: " + ", ".join(shadows)
        )


def _preimport_bootstrap(repository_root: Path | str) -> str:
    root = Path(repository_root).absolute()
    try:
        metadata = root.lstat()
    except OSError as error:
        raise PreImportRecoveryError(
            f"repository root cannot be inspected: {error}"
        ) from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise PreImportRecoveryError("repository root must be a real directory")
    root = root.resolve()
    lock_payload = _read_regular(root, _LOCK_PATH)
    lock = _load_lock(lock_payload)
    declared, paths = _bindings(lock)
    _reject_import_shadows(root)
    snapshots = {_LOCK_PATH: lock_payload}
    for relative, expected in declared.items():
        payload = _read_regular(root, relative)
        if hashlib.sha256(payload).hexdigest() != expected:
            raise PreImportRecoveryError(
                f"{relative}: working bytes differ from the recovery lock"
            )
        snapshots[relative] = payload
    top = _git(root, ["rev-parse", "--show-toplevel"], "worktree check")
    try:
        git_root = Path(top.stdout.decode("utf-8", errors="strict").strip()).resolve()
    except (UnicodeDecodeError, OSError) as error:
        raise PreImportRecoveryError("Git returned an invalid worktree root") from error
    if git_root != root:
        raise PreImportRecoveryError(
            "run_concordance_recovery.py must run from its Git worktree root"
        )
    head = (
        _git(root, ["rev-parse", "--verify", "HEAD"], "HEAD check")
        .stdout.decode("ascii", errors="strict")
        .strip()
    )
    if not _GIT_HEAD_RE.fullmatch(head):
        raise PreImportRecoveryError("Git HEAD is not a full object ID")
    for relative in paths:
        tree = _git(
            root,
            ["ls-tree", "-z", head, "--", relative],
            f"HEAD tree check for {relative}",
        )
        entries = [entry for entry in tree.stdout.split(b"\0") if entry]
        if len(entries) != 1 or b"\t" not in entries[0]:
            raise PreImportRecoveryError(f"{relative}: file is not committed in HEAD")
        fields, recorded = entries[0].split(b"\t", 1)
        metadata_fields = fields.split()
        if (
            len(metadata_fields) != 3
            or metadata_fields[0] not in {b"100644", b"100755"}
            or metadata_fields[1] != b"blob"
            or recorded.decode("utf-8", errors="strict") != relative
        ):
            raise PreImportRecoveryError(
                f"{relative}: HEAD entry is not the required regular blob"
            )
        committed = _git(
            root,
            ["cat-file", "blob", f"{head}:{relative}"],
            f"HEAD blob read for {relative}",
        )
        if committed.stdout != snapshots[relative]:
            raise PreImportRecoveryError(f"{relative}: working bytes differ from HEAD")
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
        raise PreImportRecoveryError("Git HEAD changed during pre-import verification")
    for relative, snapshot in snapshots.items():
        if _read_regular(root, relative) != snapshot:
            raise PreImportRecoveryError(
                f"{relative}: bound bytes changed during pre-import verification"
            )
    return head


if __name__ == "__main__":
    try:
        _preimport_bootstrap(REPOSITORY_ROOT)
    except (PreImportRecoveryError, OSError, ValueError) as error:
        print(
            f"Concordance recovery stopped before project imports: {error}",
            file=sys.stderr,
        )
        raise SystemExit(2) from None
    sys.path.insert(0, str(REPOSITORY_ROOT / "harness"))

from concordance_harness.config import ConfigError  # noqa: E402
from concordance_harness.planner import PlanError  # noqa: E402
from concordance_harness.providers import ProviderError  # noqa: E402
from concordance_recovery.authorization import (  # noqa: E402
    RecoveryAuthorizationError,
)
from concordance_recovery.execute import (  # noqa: E402
    RecoveryExecutionError,
    dry_run_summary,
    execute_prepared,
    prepare_recovery,
)
from concordance_recovery.journal import RecoveryJournalError  # noqa: E402
from concordance_recovery.lock import RecoveryLockError  # noqa: E402


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(
        description="Plan or execute the exact Concordance successor recovery."
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
            "Concordance recovery stopped: live mode requires --credentials-confirmed",
            file=sys.stderr,
        )
        return 2
    try:
        prepared = prepare_recovery(REPOSITORY_ROOT, require_committed=True)
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
        ConfigError,
        OSError,
        PlanError,
        ProviderError,
        RecoveryAuthorizationError,
        RecoveryExecutionError,
        RecoveryJournalError,
        RecoveryLockError,
        ValueError,
    ) as error:
        print(f"Concordance recovery stopped: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
