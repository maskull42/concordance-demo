"""Crash-safe publication for small private, write-once directory trees."""

from __future__ import annotations

import fcntl
import json
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from concordance_harness.util import canonical_json_bytes, sha256_bytes


CLAIM_QUARANTINE_INFIX = ".quarantine."
CLAIM_PREPARATION_INFIX = ".prepare."
OUTPUT_CLEANUP_INFIX = ".cleanup."
STAGING_CLEANUP_INFIX = ".cleanup."
STAGING_OWNER_NAME = ".publication-owner.json"


class PrivateDirectoryPublicationError(RuntimeError):
    pass


@dataclass(frozen=True)
class PublicationSpec:
    target_root: Path
    claim_path: Path
    staging_parent: Path
    claim_schema_version: str
    owner_schema_version: str
    expected_files: tuple[str, ...]


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise PrivateDirectoryPublicationError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _private_directory(path: Path, label: str) -> None:
    if (
        path.is_symlink()
        or not path.is_dir()
        or stat.S_IMODE(path.stat().st_mode) != 0o700
    ):
        raise PrivateDirectoryPublicationError(f"{label} must remain mode 0700")


def _validate_spec(spec: PublicationSpec) -> None:
    expected = tuple(sorted(spec.expected_files))
    if (
        not expected
        or expected != spec.expected_files
        or len(set(expected)) != len(expected)
    ):
        raise PrivateDirectoryPublicationError(
            "publication expected files must be unique and sorted"
        )
    for name in expected:
        if Path(name).name != name or name in {"", ".", "..", STAGING_OWNER_NAME}:
            raise PrivateDirectoryPublicationError(
                "publication supports only flat, named payload files"
            )
    if (
        not spec.claim_schema_version
        or not spec.owner_schema_version
        or spec.claim_path.parent == spec.target_root
        or spec.staging_parent == spec.target_root
        or spec.claim_path.parent.resolve() != spec.staging_parent.resolve()
    ):
        raise PrivateDirectoryPublicationError("publication specification is malformed")


def _run_exclusively(spec: PublicationSpec, operation: Callable[[], Any]) -> Any:
    """Serialize publication and recovery without leaving another artifact."""

    descriptor = os.open(spec.claim_path.parent, os.O_RDONLY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        return operation()
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _write_private(path: Path, payload: bytes) -> tuple[int, int, int]:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise PrivateDirectoryPublicationError(
            f"write-once private artifact exists: {path}"
        ) from error
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
        metadata = os.fstat(handle.fileno())
    return (metadata.st_dev, metadata.st_ino, stat.S_IMODE(metadata.st_mode))


def _read_private_json(
    path: Path, label: str
) -> tuple[dict[str, Any], bytes, tuple[int, int, int]]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise PrivateDirectoryPublicationError(
            f"{label} cannot be opened safely: {error}"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise PrivateDirectoryPublicationError(
                f"{label} must be a private regular file"
            )
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, 65_536)
            if not chunk:
                break
            size += len(chunk)
            if size > 1_048_576:
                raise PrivateDirectoryPublicationError(f"{label} is unexpectedly large")
            chunks.append(chunk)
        payload = b"".join(chunks)
    finally:
        os.close(descriptor)
    try:
        value = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except (
        json.JSONDecodeError,
        UnicodeError,
        RecursionError,
        PrivateDirectoryPublicationError,
    ) as error:
        raise PrivateDirectoryPublicationError(
            f"{label} is malformed: {error}"
        ) from error
    if not isinstance(value, dict):
        raise PrivateDirectoryPublicationError(f"{label} must be a JSON object")
    identity = (metadata.st_dev, metadata.st_ino, stat.S_IMODE(metadata.st_mode))
    return value, payload, identity


def _valid_operation_token(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _staging_name(spec: PublicationSpec) -> str:
    return f".{spec.target_root.name}.{secrets.token_hex(8)}.tmp"


def _staging_path(spec: PublicationSpec, staging_name: str) -> Path:
    if (
        Path(staging_name).name != staging_name
        or not staging_name.startswith(f".{spec.target_root.name}.")
        or not staging_name.endswith(".tmp")
    ):
        raise PrivateDirectoryPublicationError("publication staging name is invalid")
    return spec.staging_parent / staging_name


def _preparation_name(spec: PublicationSpec, operation_token: str) -> str:
    return f"{spec.claim_path.name}{CLAIM_PREPARATION_INFIX}{operation_token}"


def _preparation_path(spec: PublicationSpec, preparation_name: str) -> Path:
    prefix = f"{spec.claim_path.name}{CLAIM_PREPARATION_INFIX}"
    operation_token = preparation_name.removeprefix(prefix)
    if (
        Path(preparation_name).name != preparation_name
        or not preparation_name.startswith(prefix)
        or not _valid_operation_token(operation_token)
    ):
        raise PrivateDirectoryPublicationError(
            "publication claim preparation name is invalid"
        )
    return spec.claim_path.parent / preparation_name


def _preparation_candidates(spec: PublicationSpec) -> list[Path]:
    if not spec.claim_path.parent.is_dir():
        return []
    prefix = f"{spec.claim_path.name}{CLAIM_PREPARATION_INFIX}"
    return [
        entry
        for entry in spec.claim_path.parent.iterdir()
        if entry.name.startswith(prefix)
    ]


def _orphan_preparation(spec: PublicationSpec) -> Path | None:
    candidates = _preparation_candidates(spec)
    if len(candidates) > 1:
        raise PrivateDirectoryPublicationError(
            "multiple claim preparations exist; preserve them for inspection"
        )
    if not candidates:
        return None
    candidate = candidates[0]
    if (
        _preparation_path(spec, candidate.name) != candidate
        or candidate.is_symlink()
        or not candidate.is_file()
        or stat.S_IMODE(candidate.stat().st_mode) != 0o600
    ):
        raise PrivateDirectoryPublicationError(
            "claim preparation is unexpected; preserve it for inspection"
        )
    return candidate


def _remove_orphan_preparation(path: Path) -> None:
    path.unlink()
    _fsync_directory(path.parent)


def _remove_linked_preparation(
    preparation_path: Path,
    claim_path: Path,
    *,
    expected_payload: bytes,
    expected_identity: tuple[int, int, int],
) -> None:
    if not os.path.lexists(preparation_path):
        return
    _, payload, identity = _read_private_json(
        preparation_path, "publication claim preparation"
    )
    try:
        same_claim = os.path.samefile(preparation_path, claim_path)
    except OSError:
        same_claim = False
    if payload != expected_payload or identity != expected_identity or not same_claim:
        raise PrivateDirectoryPublicationError(
            "claim preparation changed; preserve it for inspection"
        )
    preparation_path.unlink()
    _fsync_directory(preparation_path.parent)


def _owner_payload(
    spec: PublicationSpec, staging_name: str, operation_token: str
) -> bytes:
    return canonical_json_bytes(
        {
            "schema_version": spec.owner_schema_version,
            "target_name": spec.target_root.name,
            "staging_name": staging_name,
            "operation_token": operation_token,
        }
    )


def _claim_value(
    spec: PublicationSpec,
    *,
    staging_name: str,
    operation_token: str,
    preparation_name: str,
    file_sha256: Mapping[str, str],
) -> dict[str, Any]:
    return {
        "schema_version": spec.claim_schema_version,
        "target_name": spec.target_root.name,
        "staging_name": staging_name,
        "operation_token": operation_token,
        "preparation_name": preparation_name,
        "expected_files": list(spec.expected_files),
        "file_sha256": dict(file_sha256),
    }


def _validate_claim(spec: PublicationSpec, value: dict[str, Any]) -> None:
    expected_keys = {
        "schema_version",
        "target_name",
        "staging_name",
        "operation_token",
        "preparation_name",
        "expected_files",
        "file_sha256",
    }
    hashes = value.get("file_sha256")
    if (
        set(value) != expected_keys
        or value.get("schema_version") != spec.claim_schema_version
        or value.get("target_name") != spec.target_root.name
        or value.get("expected_files") != list(spec.expected_files)
        or not _valid_operation_token(value.get("operation_token"))
        or not isinstance(value.get("staging_name"), str)
        or not isinstance(value.get("preparation_name"), str)
        or not isinstance(hashes, dict)
        or set(hashes) != set(spec.expected_files)
        or any(
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            for digest in hashes.values()
        )
    ):
        raise PrivateDirectoryPublicationError("publication claim is not recognized")
    _staging_path(spec, value["staging_name"])
    _preparation_path(spec, value["preparation_name"])


def _locate_live_or_quarantined(path: Path, *, infix: str, label: str) -> Path | None:
    candidates: list[Path] = []
    if os.path.lexists(path):
        candidates.append(path)
    if path.parent.is_dir():
        prefix = f"{path.name}{infix}"
        candidates.extend(
            entry for entry in path.parent.iterdir() if entry.name.startswith(prefix)
        )
    if len(candidates) > 1:
        raise PrivateDirectoryPublicationError(
            f"multiple {label} paths exist; preserve them for inspection"
        )
    return candidates[0] if candidates else None


def _claim_blocker_exists(spec: PublicationSpec) -> bool:
    return _locate_live_or_quarantined(
        spec.claim_path,
        infix=CLAIM_QUARANTINE_INFIX,
        label="publication claim",
    ) is not None or bool(_preparation_candidates(spec))


def _restore_quarantined_claim(quarantine: Path, claim_path: Path) -> None:
    if os.path.lexists(claim_path):
        return
    try:
        os.link(quarantine, claim_path, follow_symlinks=False)
    except (FileExistsError, NotImplementedError, OSError):
        return
    _fsync_directory(claim_path.parent)


def _unlink_owned_claim(
    path: Path,
    *,
    expected_payload: bytes,
    expected_identity: tuple[int, int, int],
) -> None:
    quarantine = path.parent / (
        f"{path.name}{CLAIM_QUARANTINE_INFIX}{secrets.token_hex(16)}"
    )
    os.rename(path, quarantine)
    _fsync_directory(path.parent)
    try:
        _, payload, identity = _read_private_json(
            quarantine, "quarantined publication claim"
        )
    except PrivateDirectoryPublicationError:
        _restore_quarantined_claim(quarantine, path)
        raise
    if payload != expected_payload or identity != expected_identity:
        _restore_quarantined_claim(quarantine, path)
        raise PrivateDirectoryPublicationError(
            "publication claim changed; preserve its quarantine for inspection"
        )
    quarantine.unlink()
    _fsync_directory(path.parent)


def _assert_owned_staging(
    spec: PublicationSpec,
    path: Path,
    *,
    expected_owner_payload: bytes,
    expected_hashes: Mapping[str, str],
    require_final_hashes: bool,
) -> None:
    _private_directory(path, "publication staging directory")
    owner_path = path / STAGING_OWNER_NAME
    _, owner_payload, _ = _read_private_json(owner_path, "staging owner marker")
    if owner_payload != expected_owner_payload:
        raise PrivateDirectoryPublicationError(
            "publication staging owner changed; preserve it for inspection"
        )
    allowed = {owner_path, *(path / name for name in spec.expected_files)}
    actual = set(path.iterdir())
    if not actual <= allowed:
        raise PrivateDirectoryPublicationError(
            "publication staging contains unexpected entries"
        )
    for entry in actual - {owner_path}:
        if (
            entry.is_symlink()
            or not entry.is_file()
            or stat.S_IMODE(entry.stat().st_mode) != 0o600
            or (
                require_final_hashes
                and sha256_bytes(entry.read_bytes()) != expected_hashes[entry.name]
            )
        ):
            raise PrivateDirectoryPublicationError(
                "publication staging payload changed; preserve it for inspection"
            )


def _remove_private_staging(
    spec: PublicationSpec,
    path: Path,
    *,
    expected_owner_payload: bytes,
    expected_hashes: Mapping[str, str],
) -> None:
    located = _locate_live_or_quarantined(
        path, infix=STAGING_CLEANUP_INFIX, label="publication staging"
    )
    if located is None:
        return
    if (
        not located.is_symlink()
        and located.is_dir()
        and stat.S_IMODE(located.stat().st_mode) == 0o700
        and not any(located.iterdir())
    ):
        located.rmdir()
        _fsync_directory(located.parent)
        return
    owner_path = located / STAGING_OWNER_NAME
    if (
        not located.is_symlink()
        and located.is_dir()
        and stat.S_IMODE(located.stat().st_mode) == 0o700
        and set(located.iterdir()) == {owner_path}
        and not owner_path.is_symlink()
        and owner_path.is_file()
        and stat.S_IMODE(owner_path.stat().st_mode) == 0o600
    ):
        owner_path.unlink()
        _fsync_directory(located)
        located.rmdir()
        _fsync_directory(located.parent)
        return
    if located == path:
        _assert_owned_staging(
            spec,
            located,
            expected_owner_payload=expected_owner_payload,
            expected_hashes=expected_hashes,
            require_final_hashes=False,
        )
        quarantine = path.parent / (
            f"{path.name}{STAGING_CLEANUP_INFIX}{secrets.token_hex(16)}"
        )
        os.rename(path, quarantine)
        _fsync_directory(path.parent)
        located = quarantine
    _assert_owned_staging(
        spec,
        located,
        expected_owner_payload=expected_owner_payload,
        expected_hashes=expected_hashes,
        require_final_hashes=False,
    )
    owner_path = located / STAGING_OWNER_NAME
    for name in spec.expected_files:
        payload_path = located / name
        if payload_path.exists():
            payload_path.unlink()
    _fsync_directory(located)
    if set(located.iterdir()) != {owner_path}:
        raise PrivateDirectoryPublicationError(
            "publication staging changed during cleanup; preserve it"
        )
    owner_path.unlink()
    _fsync_directory(located)
    located.rmdir()
    _fsync_directory(located.parent)


def _safe_owned_partial_output(
    spec: PublicationSpec,
    output_root: Path,
    staging_root: Path,
    *,
    expected_owner_payload: bytes,
    expected_hashes: Mapping[str, str],
) -> bool:
    try:
        _private_directory(output_root, "partial publication output")
        _assert_owned_staging(
            spec,
            staging_root,
            expected_owner_payload=expected_owner_payload,
            expected_hashes=expected_hashes,
            require_final_hashes=True,
        )
    except (PrivateDirectoryPublicationError, OSError):
        return False
    expected = {output_root / name for name in spec.expected_files}
    actual = set(output_root.iterdir())
    if not actual < expected:
        return False
    for published in actual:
        staged = staging_root / published.name
        if (
            published.is_symlink()
            or not published.is_file()
            or stat.S_IMODE(published.stat().st_mode) != 0o600
            or not staged.is_file()
        ):
            return False
        try:
            if not os.path.samefile(published, staged):
                return False
        except OSError:
            return False
    return True


def _discard_partial_output(
    spec: PublicationSpec,
    staging_root: Path,
    *,
    expected_owner_payload: bytes,
    expected_hashes: Mapping[str, str],
) -> None:
    located = _locate_live_or_quarantined(
        spec.target_root,
        infix=OUTPUT_CLEANUP_INFIX,
        label="partial publication output",
    )
    if located is None:
        return
    if located == spec.target_root:
        if not _safe_owned_partial_output(
            spec,
            located,
            staging_root,
            expected_owner_payload=expected_owner_payload,
            expected_hashes=expected_hashes,
        ):
            raise PrivateDirectoryPublicationError(
                "partial publication output is not owned; preserve its claim"
            )
        quarantine = spec.target_root.parent / (
            f"{spec.target_root.name}{OUTPUT_CLEANUP_INFIX}{secrets.token_hex(16)}"
        )
        os.rename(spec.target_root, quarantine)
        _fsync_directory(spec.target_root.parent)
        located = quarantine
    if not _safe_owned_partial_output(
        spec,
        located,
        staging_root,
        expected_owner_payload=expected_owner_payload,
        expected_hashes=expected_hashes,
    ):
        raise PrivateDirectoryPublicationError(
            "partial publication output is not owned; preserve its claim"
        )
    for entry in list(located.iterdir()):
        staged = staging_root / entry.name
        if not os.path.samefile(entry, staged):
            raise PrivateDirectoryPublicationError(
                "partial publication file changed during cleanup"
            )
        entry.unlink()
    _fsync_directory(located)
    located.rmdir()
    _fsync_directory(located.parent)


def _publish_private_directory_locked(
    spec: PublicationSpec,
    payloads: Mapping[str, bytes],
    verify: Callable[[Path], Any],
) -> Path:
    """Publish exact flat payloads once, leaving a recoverable claim on hard crash."""

    _validate_spec(spec)
    if tuple(sorted(payloads)) != spec.expected_files:
        raise PrivateDirectoryPublicationError("publication payload names differ")
    spec.target_root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    spec.staging_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _private_directory(spec.target_root.parent, "publication target parent")
    _private_directory(spec.staging_parent, "publication staging parent")
    _private_directory(spec.claim_path.parent, "publication claim parent")
    if _claim_blocker_exists(spec):
        raise PrivateDirectoryPublicationError(
            "incomplete private publication exists; run recovery"
        )
    if os.path.lexists(spec.target_root):
        raise PrivateDirectoryPublicationError("private publication is write-once")

    hashes = {name: sha256_bytes(payloads[name]) for name in spec.expected_files}
    staging_name = _staging_name(spec)
    staging_root = _staging_path(spec, staging_name)
    operation_token = secrets.token_hex(32)
    preparation_name = _preparation_name(spec, operation_token)
    preparation_path = _preparation_path(spec, preparation_name)
    owner_payload = _owner_payload(spec, staging_name, operation_token)
    claim_payload = canonical_json_bytes(
        _claim_value(
            spec,
            staging_name=staging_name,
            operation_token=operation_token,
            preparation_name=preparation_name,
            file_sha256=hashes,
        )
    )
    claim_created = False
    claim_identity: tuple[int, int, int] | None = None
    staging_created = False
    output_created = False
    published = False
    try:
        preparation_identity = _write_private(preparation_path, claim_payload)
        try:
            os.link(preparation_path, spec.claim_path, follow_symlinks=False)
        except FileExistsError as error:
            raise PrivateDirectoryPublicationError(
                "incomplete private publication exists; run recovery"
            ) from error
        claim_created = True
        claim_identity = preparation_identity
        _fsync_directory(spec.claim_path.parent)
        _, stored_payload, stored_identity = _read_private_json(
            spec.claim_path, "private publication claim"
        )
        if stored_payload != claim_payload or stored_identity != claim_identity:
            raise PrivateDirectoryPublicationError("private publication claim changed")
        _remove_linked_preparation(
            preparation_path,
            spec.claim_path,
            expected_payload=claim_payload,
            expected_identity=claim_identity,
        )
        staging_root.mkdir(mode=0o700)
        staging_created = True
        _write_private(staging_root / STAGING_OWNER_NAME, owner_payload)
        _fsync_directory(staging_root)
        for name in spec.expected_files:
            _write_private(staging_root / name, payloads[name])
        _fsync_directory(staging_root)
        spec.target_root.mkdir(mode=0o700)
        output_created = True
        for name in spec.expected_files:
            os.link(staging_root / name, spec.target_root / name)
        _fsync_directory(spec.target_root)
        _fsync_directory(spec.target_root.parent)
        verify(spec.target_root)
        published = True
        _remove_private_staging(
            spec,
            staging_root,
            expected_owner_payload=owner_payload,
            expected_hashes=hashes,
        )
        staging_created = False
        assert claim_identity is not None
        _unlink_owned_claim(
            spec.claim_path,
            expected_payload=claim_payload,
            expected_identity=claim_identity,
        )
        claim_created = False
        return spec.target_root
    except BaseException as original_error:
        cleanup_error: BaseException | None = None
        if not published and output_created:
            try:
                _discard_partial_output(
                    spec,
                    staging_root,
                    expected_owner_payload=owner_payload,
                    expected_hashes=hashes,
                )
                output_created = False
            except (PrivateDirectoryPublicationError, OSError) as error:
                cleanup_error = error
        if not published and cleanup_error is None and staging_created:
            try:
                _remove_private_staging(
                    spec,
                    staging_root,
                    expected_owner_payload=owner_payload,
                    expected_hashes=hashes,
                )
                staging_created = False
            except (PrivateDirectoryPublicationError, OSError) as error:
                cleanup_error = error
        if (
            not published
            and cleanup_error is None
            and os.path.lexists(preparation_path)
        ):
            try:
                if claim_created and claim_identity is not None:
                    _remove_linked_preparation(
                        preparation_path,
                        spec.claim_path,
                        expected_payload=claim_payload,
                        expected_identity=claim_identity,
                    )
                else:
                    orphan = _orphan_preparation(spec)
                    if orphan != preparation_path:
                        raise PrivateDirectoryPublicationError(
                            "claim preparation changed; preserve it for inspection"
                        )
                    _remove_orphan_preparation(preparation_path)
            except (PrivateDirectoryPublicationError, OSError) as error:
                cleanup_error = error
        if (
            not published
            and cleanup_error is None
            and claim_created
            and claim_identity is not None
        ):
            try:
                _unlink_owned_claim(
                    spec.claim_path,
                    expected_payload=claim_payload,
                    expected_identity=claim_identity,
                )
                claim_created = False
            except (PrivateDirectoryPublicationError, OSError) as error:
                cleanup_error = error
        if cleanup_error is not None:
            raise cleanup_error from original_error
        raise


def publish_private_directory(
    spec: PublicationSpec,
    payloads: Mapping[str, bytes],
    verify: Callable[[Path], Any],
) -> Path:
    """Serialize and publish one exact private directory."""

    _validate_spec(spec)
    spec.target_root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    spec.staging_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _private_directory(spec.claim_path.parent, "publication claim parent")
    return _run_exclusively(
        spec,
        lambda: _publish_private_directory_locked(spec, payloads, verify),
    )


def _recover_private_directory_locked(
    spec: PublicationSpec, verify: Callable[[Path], Any]
) -> str:
    """Complete or clear the one publication named by the owned claim."""

    _validate_spec(spec)
    located_claim = _locate_live_or_quarantined(
        spec.claim_path,
        infix=CLAIM_QUARANTINE_INFIX,
        label="publication claim",
    )
    if located_claim is None:
        orphan = _orphan_preparation(spec)
        if orphan is None:
            raise PrivateDirectoryPublicationError("publication claim is missing")
        if os.path.lexists(spec.target_root):
            try:
                verify(spec.target_root)
            except Exception as error:
                raise PrivateDirectoryPublicationError(
                    "orphan claim preparation has an unverified output"
                ) from error
            status = "completed"
        else:
            status = "cleared"
        _remove_orphan_preparation(orphan)
        return status
    claim_path = located_claim
    claim, claim_payload, claim_identity = _read_private_json(
        claim_path, "private publication claim"
    )
    _validate_claim(spec, claim)
    staging_name = claim["staging_name"]
    operation_token = claim["operation_token"]
    hashes = claim["file_sha256"]
    preparation_path = _preparation_path(spec, claim["preparation_name"])
    _remove_linked_preparation(
        preparation_path,
        claim_path,
        expected_payload=claim_payload,
        expected_identity=claim_identity,
    )
    staging_root = _staging_path(spec, staging_name)
    owner_payload = _owner_payload(spec, staging_name, operation_token)
    published_root = _locate_live_or_quarantined(
        spec.target_root,
        infix=OUTPUT_CLEANUP_INFIX,
        label="private publication output",
    )
    if published_root is None:
        _remove_private_staging(
            spec,
            staging_root,
            expected_owner_payload=owner_payload,
            expected_hashes=hashes,
        )
        _unlink_owned_claim(
            claim_path,
            expected_payload=claim_payload,
            expected_identity=claim_identity,
        )
        return "cleared"
    try:
        verify(published_root)
    except (Exception, OSError, ValueError) as error:
        if _safe_owned_partial_output(
            spec,
            published_root,
            staging_root,
            expected_owner_payload=owner_payload,
            expected_hashes=hashes,
        ):
            _discard_partial_output(
                spec,
                staging_root,
                expected_owner_payload=owner_payload,
                expected_hashes=hashes,
            )
            _remove_private_staging(
                spec,
                staging_root,
                expected_owner_payload=owner_payload,
                expected_hashes=hashes,
            )
            _unlink_owned_claim(
                claim_path,
                expected_payload=claim_payload,
                expected_identity=claim_identity,
            )
            return "cleared"
        raise PrivateDirectoryPublicationError(
            "private publication did not verify; preserve it for inspection"
        ) from error
    if published_root != spec.target_root:
        if os.path.lexists(spec.target_root):
            raise PrivateDirectoryPublicationError(
                "publication destination reappeared; preserve both paths"
            )
        os.rename(published_root, spec.target_root)
        _fsync_directory(spec.target_root.parent)
    _remove_private_staging(
        spec,
        staging_root,
        expected_owner_payload=owner_payload,
        expected_hashes=hashes,
    )
    _unlink_owned_claim(
        claim_path,
        expected_payload=claim_payload,
        expected_identity=claim_identity,
    )
    return "completed"


def recover_private_directory(
    spec: PublicationSpec, verify: Callable[[Path], Any]
) -> str:
    """Serialize and recover the one transaction named by its private claim."""

    _validate_spec(spec)
    spec.claim_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _private_directory(spec.claim_path.parent, "publication claim parent")

    def recover_after_lock() -> str:
        if not _claim_blocker_exists(spec) and os.path.lexists(spec.target_root):
            try:
                verify(spec.target_root)
            except Exception as error:
                raise PrivateDirectoryPublicationError(
                    "publication claim is missing and output did not verify"
                ) from error
            return "completed"
        return _recover_private_directory_locked(spec, verify)

    return _run_exclusively(spec, recover_after_lock)
