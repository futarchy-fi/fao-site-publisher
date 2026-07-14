#!/usr/bin/env python3
"""Build reproducible governed-site releases and their execution payloads."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unicodedata
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from Crypto.Hash import keccak

import publisher


SCHEMA_VERSION = 1
MAX_UINT256 = (1 << 256) - 1
GIT = "/usr/bin/git"
ARCHIVE_LIMITS = SimpleNamespace(
    max_archive_bytes=50 * 1024 * 1024,
    max_extracted_bytes=50 * 1024 * 1024,
    max_file_bytes=25 * 1024 * 1024,
    max_files=20_000,
)


class ArtifactError(RuntimeError):
    pass


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(path))


def _output_path(path: Path) -> Path:
    path = _absolute(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ArtifactError("output path cannot be a symlink")
    return path.parent.resolve(strict=True) / path.name


def _same_file(first: Path, second: Path) -> bool:
    if first == second:
        return True
    try:
        same_parent = first.parent == second.parent or os.path.samefile(
            first.parent, second.parent
        )
        if same_parent and unicodedata.normalize("NFC", first.name).casefold() == (
            unicodedata.normalize("NFC", second.name).casefold()
        ):
            return True
        return first.exists() and second.exists() and os.path.samefile(first, second)
    except OSError:
        return False


def _git_environment(home: Path) -> dict[str, str]:
    return {
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TZ": "UTC",
        "XDG_CONFIG_HOME": str(home),
    }


def _git(repo: Path, environment: dict[str, str], *arguments: str) -> str:
    result = subprocess.run(
        [GIT, "--no-replace-objects", "-C", str(repo), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        env=environment,
    )
    if result.returncode:
        detail = result.stderr.strip() or "git command failed"
        raise ArtifactError(detail)
    return result.stdout.strip()


def _commit(repo: Path, ref: str, environment: dict[str, str]) -> str:
    if not ref or ref.startswith("-") or "\0" in ref:
        raise ArtifactError("ref must name a commit")
    commit = _git(repo, environment, "rev-parse", "--verify", f"{ref}^{{commit}}")
    if not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", commit):
        raise ArtifactError("git returned a malformed commit id")
    return commit.lower()


def _archive_commit(
    repo: Path, ref: str, target: Path, workspace: Path
) -> tuple[str, str]:
    home = workspace / "home"
    bare = workspace / "repo.git"
    home.mkdir(mode=0o700)
    bare.mkdir(mode=0o700)
    environment = _git_environment(home)
    commit = _commit(repo, ref, environment)
    object_format = _git(repo, environment, "rev-parse", "--show-object-format")
    if object_format not in ("sha1", "sha256"):
        raise ArtifactError("git returned an unsupported object format")
    _git(
        bare,
        environment,
        "init",
        "--bare",
        "--quiet",
        "--template=",
        f"--object-format={object_format}",
        ".",
    )
    _git(
        bare,
        environment,
        "fetch",
        "--quiet",
        "--no-tags",
        "--depth=1",
        "--no-write-fetch-head",
        str(repo),
        commit,
    )
    # The commit object already contains its parent IDs. Removing only Git's
    # shallow marker preserves those committed export-subst fields without
    # importing history or ambient refs.
    (bare / "shallow").unlink(missing_ok=True)
    modes = _git(
        bare,
        environment,
        "ls-tree",
        "-r",
        "--format=%(objectmode)",
        commit,
    ).splitlines()
    if any(mode not in ("100644", "100755") for mode in modes):
        raise publisher.UnsafeArtifact("archive contains links and special files")
    _git(
        bare,
        environment,
        "-c",
        "core.attributesFile=/dev/null",
        "-c",
        "tar.umask=0022",
        "archive",
        "--format=tar",
        "--prefix=release/",
        f"--output={target}",
        commit,
    )
    git_version = _git(bare, environment, "--version")
    if not git_version.startswith("git version "):
        raise ArtifactError("git returned a malformed version")
    return commit, git_version


def _validate_archive(path: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="fao-release-validate-") as directory:
        publisher.extract_archive(path, Path(directory) / "tree", ARCHIVE_LIMITS)


def _stage_archive(source: Path, directory: Path) -> Path:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    descriptor = -1
    try:
        descriptor = os.open(source, flags)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_size == 0
            or info.st_size > ARCHIVE_LIMITS.max_archive_bytes
        ):
            raise publisher.UnsafeArtifact("artifact archive is not a bounded regular file")
        target = directory / "site.tar"
        input_file = os.fdopen(descriptor, "rb")
        descriptor = -1
        with input_file:
            with target.open("xb") as output_file:
                copied = 0
                while chunk := input_file.read(
                    min(1024 * 1024, ARCHIVE_LIMITS.max_archive_bytes + 1 - copied)
                ):
                    copied += len(chunk)
                    if copied > ARCHIVE_LIMITS.max_archive_bytes:
                        raise publisher.UnsafeArtifact(
                            "artifact archive is not a bounded regular file"
                        )
                    output_file.write(chunk)
        os.chmod(target, 0o600)
        return target
    except OSError as exc:
        raise publisher.UnsafeArtifact(
            "artifact archive is not a bounded regular file"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=f".{path.name}.", dir=path.parent, delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(_json_bytes(value))
            handle.flush()
            os.fsync(handle.fileno())
        assert temporary is not None
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def create_bundle(repo: Path, ref: str, archive: Path, out: Path) -> dict[str, Any]:
    repo = repo.resolve(strict=True)
    archive = _output_path(archive)
    out = _output_path(out)
    if not repo.is_dir():
        raise ArtifactError("repo must be a directory")
    if _same_file(archive, out):
        raise ArtifactError("archive and JSON output must be different files")

    with tempfile.TemporaryDirectory(prefix=".fao-release-", dir=archive.parent) as directory:
        workspace = Path(directory)
        temporary = workspace / "site.tar"
        previous_umask = os.umask(0o022)
        try:
            commit, git_version = _archive_commit(repo, ref, temporary, workspace)
        finally:
            os.umask(previous_umask)

        _validate_archive(temporary)
        result = {
            "schemaVersion": SCHEMA_VERSION,
            "sourceCommit": commit,
            "gitVersion": git_version,
            "archiveBytes": temporary.stat().st_size,
            "artifactDigest": publisher._keccak_file(temporary),
        }
        os.chmod(temporary, 0o644)
        os.replace(temporary, archive)

    _write_json(out, result)
    return result


def _bytes32(value: str, name: str, *, allow_zero: bool) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", value):
        raise ArtifactError(f"{name} must be a 32-byte 0x-prefixed hex value")
    normalized = value.lower()
    if not allow_zero and int(normalized, 16) == 0:
        raise ArtifactError(f"{name} cannot be zero")
    return normalized


def _uri(value: str) -> str:
    try:
        encoded = value.encode("utf-8")
    except (AttributeError, UnicodeEncodeError) as exc:
        raise ArtifactError("artifact URI must be valid UTF-8") from exc
    if not 0 < len(encoded) <= 256:
        raise ArtifactError("artifact URI must contain 1 to 256 UTF-8 bytes")
    try:
        publisher.artifact_url(value, "https://ipfs.example.invalid")
    except publisher.UnsafeArtifact as exc:
        raise ArtifactError(str(exc)) from exc
    return value


def encode_site_release(
    nonce: int,
    expected_current_digest: str,
    artifact_digest: str,
    artifact_uri: str,
) -> str:
    if isinstance(nonce, bool) or not isinstance(nonce, int) or not 0 < nonce <= MAX_UINT256:
        raise ArtifactError("nonce must be an integer from 1 through 2^256-1")
    expected = _bytes32(
        expected_current_digest, "expected current digest", allow_zero=True
    )
    digest = _bytes32(artifact_digest, "artifact digest", allow_zero=False)
    uri_bytes = _uri(artifact_uri).encode("utf-8")
    padding = b"\0" * ((32 - len(uri_bytes) % 32) % 32)
    encoded = b"".join(
        (
            (32).to_bytes(32, "big"),
            nonce.to_bytes(32, "big"),
            bytes.fromhex(expected[2:]),
            bytes.fromhex(digest[2:]),
            (128).to_bytes(32, "big"),
            len(uri_bytes).to_bytes(32, "big"),
            uri_bytes,
            padding,
        )
    )
    return "0x" + encoded.hex()


def _keccak_hex(data: bytes) -> str:
    digest = keccak.new(digest_bits=256)
    digest.update(data)
    return "0x" + digest.hexdigest()


def create_payload(
    archive: Path,
    uri: str,
    nonce: int,
    expected_current_digest: str,
    out: Path,
) -> dict[str, Any]:
    archive = _absolute(archive)
    out = _output_path(out)
    try:
        archive_identity = archive.resolve(strict=True)
    except OSError:
        archive_identity = archive
    if _same_file(archive_identity, out):
        raise ArtifactError("archive and JSON output must be different files")
    with tempfile.TemporaryDirectory(prefix="fao-release-payload-") as directory:
        staged = _stage_archive(archive, Path(directory))
        _validate_archive(staged)
        artifact_digest = _bytes32(
            publisher._keccak_file(staged), "artifact digest", allow_zero=False
        )
    expected_current_digest = _bytes32(
        expected_current_digest, "expected current digest", allow_zero=True
    )
    execution_payload = encode_site_release(
        nonce, expected_current_digest, artifact_digest, uri
    )
    result = {
        "schemaVersion": SCHEMA_VERSION,
        "nonce": nonce,
        "expectedCurrentDigest": expected_current_digest,
        "artifactDigest": artifact_digest,
        "artifactURI": uri,
        "executionPayload": execution_payload,
        "executionPayloadHash": _keccak_hex(bytes.fromhex(execution_payload[2:])),
    }
    _write_json(out, result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    bundle = commands.add_parser("bundle", help="archive one exact Git commit")
    bundle.add_argument("--repo", type=Path, required=True)
    bundle.add_argument("--ref", required=True)
    bundle.add_argument("--archive", type=Path, required=True)
    bundle.add_argument("--out", type=Path, required=True)

    payload = commands.add_parser("payload", help="encode one SiteRelease payload")
    payload.add_argument("--archive", type=Path, required=True)
    payload.add_argument("--uri", required=True)
    payload.add_argument("--nonce", type=int, required=True)
    payload.add_argument("--expected-current-digest", required=True)
    payload.add_argument("--out", type=Path, required=True)

    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "bundle":
            create_bundle(
                arguments.repo, arguments.ref, arguments.archive, arguments.out
            )
        else:
            create_payload(
                arguments.archive,
                arguments.uri,
                arguments.nonce,
                arguments.expected_current_digest,
                arguments.out,
            )
    except (ArtifactError, OSError, publisher.PublisherError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
