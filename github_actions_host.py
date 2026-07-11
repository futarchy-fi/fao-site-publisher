#!/usr/bin/env python3
"""Fail-closed one-shot host for the FAO publisher on GitHub Actions."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unicodedata
from pathlib import Path, PurePosixPath
from typing import Any

import publisher


SOURCE_REPOSITORY = "futarchy-fi/fao-site-publisher"
STATE_REPOSITORY = "futarchy-fi/fao-site-publisher-state"
STATE_REMOTE = f"git@github.com:{STATE_REPOSITORY}.git"
STATE_BRANCH = "publisher-state"
STATE_REF = f"refs/heads/{STATE_BRANCH}"
STATE_METADATA = ".publisher-state.json"
STATE_MAC = ".publisher-state.hmac"
TARGET_REMOTE = publisher.GITHUB_REMOTE
GITHUB_ED25519_HOST_KEY = (
    "github.com ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n"
)


class HostError(RuntimeError):
    pass


def _run(
    command: list[str],
    *,
    env: dict[str, str],
    cwd: Path | None = None,
    input_text: str | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic"
        raise HostError(f"command failed ({command[0]}): {detail}")
    return result


def _git(
    repository: Path,
    *arguments: str,
    env: dict[str, str],
    input_text: str | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return _run(
        [
            "/usr/bin/git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-C",
            str(repository),
            *arguments,
        ],
        env=env,
        input_text=input_text,
        check=check,
    )


def _git_environment(home: Path) -> dict[str, str]:
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    environment = {
        "HOME": str(home),
        "PATH": "/usr/bin:/bin",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C.UTF-8",
    }
    return environment


def _state_identity(config: publisher.Config) -> dict[str, Any]:
    return {
        "version": 1,
        "source_repository": SOURCE_REPOSITORY,
        "state_repository": STATE_REPOSITORY,
        "target_remote": TARGET_REMOTE,
        "chain_id": config.chain_id,
        "strategy_address": config.strategy_address,
        "start_block": config.start_block,
    }


class StateBranch:
    """A complete state tree whose remote history is always one root commit."""

    def __init__(
        self, path: Path, remote: str, git_env: dict[str, str], state_key: bytes
    ):
        self.path = path
        self.remote = remote
        self.git_env = git_env
        if len(state_key) < 32:
            raise HostError("publisher state HMAC key must contain at least 32 bytes")
        self.state_key = state_key
        self.expected: str | None = None

    def restore(self, initialize: bool) -> None:
        _run(["/usr/bin/git", "init", "-q", str(self.path)], env=self.git_env)
        _git(self.path, "remote", "add", "origin", self.remote, env=self.git_env)
        listing = _git(
            self.path, "ls-remote", "origin", STATE_REF, env=self.git_env
        ).stdout.splitlines()
        if len(listing) > 1:
            raise HostError("state remote returned more than one branch tip")
        if not listing:
            if not initialize:
                raise HostError(
                    "publisher-state is absent; explicit workflow_dispatch initialization is required"
                )
            return
        if initialize:
            raise HostError("publisher-state already exists; refusing to initialize over it")

        fields = listing[0].split("\t")
        if len(fields) != 2 or fields[1] != STATE_REF or not _is_object_id(fields[0]):
            raise HostError("state remote returned a malformed branch tip")
        self.expected = fields[0].lower()
        _git(
            self.path,
            "fetch",
            "--no-tags",
            "--depth=1",
            "origin",
            STATE_REF,
            env=self.git_env,
        )
        fetched = _git(self.path, "rev-parse", "FETCH_HEAD", env=self.git_env).stdout.strip()
        if fetched.lower() != self.expected:
            raise HostError("state branch changed while it was fetched")
        commit = _git(
            self.path, "cat-file", "-p", self.expected, env=self.git_env
        ).stdout
        if any(line.startswith("parent ") for line in commit.splitlines()):
            raise HostError("publisher-state must contain exactly one root commit")
        self._materialize_git_tree(self._validate_git_tree(self.expected))
        self._verify_mac()
        cursor = self.path / "cursor.json"
        if cursor.exists():
            os.chmod(cursor, 0o600)

    def bind(self, identity: dict[str, Any]) -> None:
        metadata = self.path / STATE_METADATA
        if self.expected is None:
            metadata.write_text(
                json.dumps(identity, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            os.chmod(metadata, 0o600)
            return
        try:
            actual = json.loads(metadata.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError) as exc:
            raise HostError(f"cannot read state identity: {exc}") from exc
        if actual != identity:
            raise HostError("publisher-state belongs to a different deployment")
        os.chmod(metadata, 0o600)

    def save(self) -> str:
        self._require_complete_state()
        self._write_mac()
        tree = self._index_exact_tree()
        if self.expected is not None:
            old_tree = _git(
                self.path,
                "rev-parse",
                f"{self.expected}^{{tree}}",
                env=self.git_env,
            ).stdout.strip()
            if old_tree == tree:
                if self._remote_tip() != self.expected:
                    raise HostError("publisher-state changed concurrently")
                return self.expected

        commit_env = dict(self.git_env)
        commit_env.update(
            {
                "GIT_AUTHOR_NAME": "FAO Publisher State",
                "GIT_AUTHOR_EMAIL": "publisher@futarchy.ai",
                "GIT_COMMITTER_NAME": "FAO Publisher State",
                "GIT_COMMITTER_EMAIL": "publisher@futarchy.ai",
            }
        )
        new_commit = _git(
            self.path,
            "commit-tree",
            tree,
            env=commit_env,
            input_text="durable publisher state\n",
        ).stdout.strip()
        if not _is_object_id(new_commit):
            raise HostError("git produced a malformed state commit")
        lease = f"--force-with-lease={STATE_REF}:{self.expected or ''}"
        _git(
            self.path,
            "push",
            "--porcelain",
            lease,
            "origin",
            f"{new_commit}:{STATE_REF}",
            env=self.git_env,
        )
        if self._remote_tip() != new_commit:
            raise HostError("state branch did not advance to the saved root commit")
        self.expected = new_commit
        return new_commit

    def _remote_tip(self) -> str | None:
        lines = _git(
            self.path, "ls-remote", "origin", STATE_REF, env=self.git_env
        ).stdout.splitlines()
        if not lines:
            return None
        if len(lines) != 1:
            raise HostError("state remote returned an ambiguous branch tip")
        fields = lines[0].split("\t")
        if len(fields) != 2 or fields[1] != STATE_REF or not _is_object_id(fields[0]):
            raise HostError("state remote returned a malformed branch tip")
        return fields[0].lower()

    def _validate_git_tree(self, commit: str) -> list[tuple[str, str, bool]]:
        encoded = _git(
            self.path, "ls-tree", "-rz", "--full-tree", commit, env=self.git_env
        ).stdout.encode("utf-8", errors="surrogateescape")
        spellings: dict[tuple[str, ...], tuple[str, ...]] = {}
        entries: list[tuple[str, str, bool]] = []
        for record in encoded.split(b"\0"):
            if not record:
                continue
            try:
                header, raw_path = record.split(b"\t", 1)
                mode, object_type, object_id = header.split(b" ", 2)
                path = raw_path.decode("utf-8")
            except (ValueError, UnicodeError) as exc:
                raise HostError("publisher-state contains a malformed Git entry") from exc
            if object_type != b"blob" or mode not in (b"100644", b"100755"):
                raise HostError("publisher-state may contain only regular files")
            try:
                parts = publisher._path_parts(path)
            except publisher.PublisherError as exc:
                raise HostError("publisher-state contains an unsafe path") from exc
            if (
                any(part.casefold() == ".git" for part in parts)
                or parts[0] in ("publisher.lock", "git-home")
            ):
                raise HostError("publisher-state contains a reserved or unsafe path")
            for length in range(1, len(parts) + 1):
                spelling = parts[:length]
                folded = tuple(
                    unicodedata.normalize("NFC", part).casefold() for part in spelling
                )
                previous = spellings.setdefault(folded, spelling)
                if previous != spelling:
                    raise HostError("publisher-state contains case-colliding paths")
            decoded_id = object_id.decode("ascii")
            if not _is_object_id(decoded_id):
                raise HostError("publisher-state contains a malformed blob ID")
            entries.append((path, decoded_id.lower(), mode == b"100755"))
        return entries

    def _materialize_git_tree(self, entries: list[tuple[str, str, bool]]) -> None:
        # Read blobs directly: checkout filters from a governed .gitattributes
        # file must never rewrite the durable cache.
        process = subprocess.Popen(
            [
                "/usr/bin/git",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "-C",
                str(self.path),
                "cat-file",
                "--batch",
            ],
            env=self.git_env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        try:
            for path, object_id, executable in entries:
                process.stdin.write(f"{object_id}\n".encode("ascii"))
                process.stdin.flush()
                header = process.stdout.readline().rstrip(b"\n").split(b" ")
                if (
                    len(header) != 3
                    or header[0].decode("ascii").lower() != object_id
                    or header[1] != b"blob"
                ):
                    raise HostError("git returned an unexpected state object")
                try:
                    remaining = int(header[2])
                except ValueError as exc:
                    raise HostError("git returned a malformed state blob size") from exc
                target = self.path.joinpath(*PurePosixPath(path).parts)
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with target.open("xb") as handle:
                    while remaining:
                        chunk = process.stdout.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise HostError("git truncated a durable state blob")
                        handle.write(chunk)
                        remaining -= len(chunk)
                if process.stdout.read(1) != b"\n":
                    raise HostError("git returned a malformed state blob boundary")
                os.chmod(target, 0o755 if executable else 0o644)
            process.stdin.close()
            error = process.stderr.read().decode("utf-8", errors="replace").strip()
            if process.wait() != 0:
                raise HostError(f"cannot materialize publisher-state: {error or 'git failed'}")
        except BaseException:
            process.kill()
            process.wait()
            raise
        finally:
            for stream in (process.stdin, process.stdout, process.stderr):
                if not stream.closed:
                    stream.close()

    def _state_files(self) -> list[tuple[str, str, Path]]:
        files: list[tuple[str, str, Path]] = []
        spellings: dict[tuple[str, ...], tuple[str, ...]] = {}
        for root, directories, names in os.walk(
            self.path, topdown=True, followlinks=False
        ):
            root_path = Path(root)
            if root_path == self.path:
                directories[:] = [name for name in directories if name != ".git"]
            for directory in directories:
                mode = (root_path / directory).lstat().st_mode
                if not stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
                    raise HostError("publisher-state contains a non-directory entry")
            for name in names:
                path = root_path / name
                mode = path.lstat().st_mode
                if not stat.S_ISREG(mode) or stat.S_ISLNK(mode):
                    raise HostError("publisher-state contains a non-regular file")
                relative = path.relative_to(self.path).as_posix()
                try:
                    parts = publisher._path_parts(relative)
                except publisher.PublisherError as exc:
                    raise HostError("publisher-state contains an unsafe path") from exc
                if any(part.casefold() == ".git" for part in parts):
                    raise HostError("publisher-state contains Git control data")
                for length in range(1, len(parts) + 1):
                    spelling = parts[:length]
                    folded = tuple(
                        unicodedata.normalize("NFC", part).casefold()
                        for part in spelling
                    )
                    previous = spellings.setdefault(folded, spelling)
                    if previous != spelling:
                        raise HostError("publisher-state contains case-colliding paths")
                git_mode = "100755" if mode & 0o111 else "100644"
                files.append((relative, git_mode, path))
        files.sort(key=lambda item: item[0].encode("utf-8"))
        return files

    def _state_mac(self) -> bytes:
        digest = hmac.new(self.state_key, digestmod=hashlib.sha256)
        digest.update(b"FAO publisher-state HMAC v1\0")
        for relative, mode, path in self._state_files():
            if relative == STATE_MAC:
                continue
            encoded_path = relative.encode("utf-8")
            size = path.stat().st_size
            digest.update(b"F")
            digest.update(mode.encode("ascii"))
            digest.update(len(encoded_path).to_bytes(8, "big"))
            digest.update(encoded_path)
            digest.update(size.to_bytes(8, "big"))
            actual_size = 0
            with path.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    digest.update(chunk)
                    actual_size += len(chunk)
            if actual_size != size:
                raise HostError("publisher-state changed while it was authenticated")
        digest.update(b"END")
        return digest.digest()

    def _verify_mac(self) -> None:
        path = self.path / STATE_MAC
        try:
            info = path.lstat()
        except OSError as exc:
            raise HostError(f"cannot read publisher-state HMAC: {exc}") from exc
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_mode & 0o111
            or info.st_size != len("hmac-sha256-v1:") + 64 + 1
        ):
            raise HostError("publisher-state HMAC file is malformed")
        try:
            encoded = path.read_text(encoding="ascii")
        except (OSError, UnicodeError) as exc:
            raise HostError(f"cannot read publisher-state HMAC: {exc}") from exc
        if not encoded.startswith("hmac-sha256-v1:") or not encoded.endswith("\n"):
            raise HostError("publisher-state HMAC file is malformed")
        value = encoded.removeprefix("hmac-sha256-v1:").removesuffix("\n")
        if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
            raise HostError("publisher-state HMAC value is malformed")
        if not hmac.compare_digest(bytes.fromhex(value), self._state_mac()):
            raise HostError("publisher-state HMAC verification failed")

    def _write_mac(self) -> None:
        path = self.path / STATE_MAC
        try:
            info = path.lstat()
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise HostError("publisher-state HMAC file is unsafe")
        path.write_text(f"hmac-sha256-v1:{self._state_mac().hex()}\n", encoding="ascii")
        os.chmod(path, 0o644)

    def _require_complete_state(self) -> None:
        for path, label in (
            (self.path / STATE_METADATA, "state identity"),
            (self.path / "cursor.json", "durable cursor"),
        ):
            try:
                info = path.lstat()
            except OSError as exc:
                raise HostError(f"{label} is missing: {exc}") from exc
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise HostError(f"{label} must be a regular file")
        genesis = self.path / "trees" / "genesis"
        if not genesis.is_dir() or genesis.is_symlink():
            raise HostError("complete state requires the canonical genesis tree")
        if (self.path / "publisher.lock").exists() or (self.path / "git-home").exists():
            raise HostError("ephemeral lock and Git HOME must be removed before state save")

    def _index_exact_tree(self) -> str:
        files = self._state_files()
        paths = [relative for relative, _, _ in files]
        hashed = _git(
            self.path,
            "hash-object",
            "-w",
            "--no-filters",
            "--stdin-paths",
            env=self.git_env,
            input_text="".join(f"{path}\n" for path in paths),
        ).stdout.splitlines()
        if len(hashed) != len(paths):
            raise HostError("git hashed an unexpected number of state files")
        _git(self.path, "read-tree", "--empty", env=self.git_env)
        index = "".join(
            f"{mode} {object_id}\t{path}\n"
            for (path, mode, _), object_id in zip(files, hashed)
        )
        _git(
            self.path,
            "update-index",
            "--index-info",
            env=self.git_env,
            input_text=index,
        )
        return _git(self.path, "write-tree", env=self.git_env).stdout.strip()


def _is_object_id(value: str) -> bool:
    return len(value) == 40 and all(character in "0123456789abcdefABCDEF" for character in value)


def _initialize_requested(value: str, event_name: str) -> bool:
    if value not in ("", "false", "true"):
        raise HostError("initialize input must be true or false")
    requested = value == "true"
    if requested and event_name != "workflow_dispatch":
        raise HostError("state initialization is allowed only through workflow_dispatch")
    return requested


def _load_deployment(path: Path) -> dict[str, Any]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise HostError(f"cannot inspect deployment config: {exc}") from exc
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise HostError("deployment config must be a tracked regular file")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise HostError(f"cannot read deployment config: {exc}") from exc
    if not isinstance(raw, dict):
        raise HostError("deployment config must be a JSON object")
    forbidden = {
        "rpc_url",
        "witness_rpc_url",
        "state_dir",
        "worktree",
        "git_commit",
        "git_push",
        "git_ssh",
    }
    if forbidden.intersection(raw):
        raise HostError("deployment config contains host-controlled fields")
    return raw


def _decode_state_key(encoded: str) -> bytes:
    try:
        raw = encoded.encode("ascii")
        key = base64.b64decode(raw, validate=True)
    except (UnicodeError, ValueError) as exc:
        raise HostError("publisher state HMAC key must be canonical base64") from exc
    if base64.b64encode(key) != raw:
        raise HostError("publisher state HMAC key must be canonical base64")
    if len(key) < 32:
        raise HostError("publisher state HMAC key must encode at least 32 random bytes")
    return key


def _write_ssh(
    session: Path, deploy_key: str, label: str, secret_name: str
) -> Path:
    if not deploy_key.strip() or "\0" in deploy_key:
        raise HostError(f"{secret_name} is empty or malformed")
    ssh_dir = session / f"{label}-ssh"
    ssh_dir.mkdir(mode=0o700)
    key = ssh_dir / "deploy-key"
    key.write_text(deploy_key.replace("\r\n", "\n").rstrip("\n") + "\n")
    os.chmod(key, 0o600)
    known_hosts = ssh_dir / "known-hosts"
    known_hosts.write_text(GITHUB_ED25519_HOST_KEY, encoding="ascii")
    os.chmod(known_hosts, 0o600)
    wrapper = session / f"{label}-git-ssh"
    wrapper.write_text(
        "#!/bin/sh\n"
        "unset SSH_AUTH_SOCK\n"
        "exec /usr/bin/ssh -F /dev/null "
        f"-i {shlex.quote(str(key))} "
        "-o IdentitiesOnly=yes -o IdentityAgent=none -o BatchMode=yes "
        "-o PasswordAuthentication=no -o KbdInteractiveAuthentication=no "
        "-o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 "
        f"-o UserKnownHostsFile={shlex.quote(str(known_hosts))} "
        "-o ProxyCommand=none -o ProxyJump=none -o ClearAllForwardings=yes \"$@\"\n",
        encoding="utf-8",
    )
    os.chmod(wrapper, 0o700)
    return wrapper


def _remove_ephemeral_state(state: Path) -> None:
    lock = state / "publisher.lock"
    try:
        lock.unlink()
    except FileNotFoundError:
        pass
    git_home = state / "git-home"
    try:
        info = git_home.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise HostError("publisher git-home has an unsafe type")
    shutil.rmtree(git_home)


def _require_environment(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise HostError(f"required environment value {name} is missing")
    return value


def _publisher_child_environment(
    environment: dict[str, str] | None = None,
) -> dict[str, str]:
    child = dict(os.environ if environment is None else environment)
    for name in (
        "GITHUB_TOKEN",
        "FAO_GOVERNED_SITE_DEPLOY_KEY",
        "FAO_PUBLISHER_STATE_DEPLOY_KEY",
        "FAO_PUBLISHER_STATE_HMAC_KEY",
        "FAO_RPC_URL",
        "FAO_WITNESS_RPC_URL",
        "SSH_AUTH_SOCK",
        "GIT_ASKPASS",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
    ):
        child.pop(name, None)
    return child


def main() -> int:
    try:
        if _require_environment("GITHUB_REPOSITORY") != SOURCE_REPOSITORY:
            raise HostError("refusing to run outside the canonical publisher repository")
        if _require_environment("GITHUB_REF") != "refs/heads/main":
            raise HostError("refusing to expose publisher authority to a non-main ref")
        github_sha = _require_environment("GITHUB_SHA").lower()
        if not _is_object_id(github_sha):
            raise HostError("GITHUB_SHA is not an exact commit object ID")
        if _require_environment("FAO_TARGET_ACTIONS_DISABLED") != "true":
            raise HostError("target Actions-disabled operator attestation is missing")
        initialize = _initialize_requested(
            os.environ.get("FAO_INITIALIZE", ""),
            _require_environment("GITHUB_EVENT_NAME"),
        )

        publisher_dir = Path(__file__).resolve().parent
        source_home = Path(_require_environment("RUNNER_TEMP")).resolve() / "source-git-home"
        unauthenticated_git = _git_environment(source_home)
        actual_sha = _git(
            publisher_dir, "rev-parse", "HEAD", env=unauthenticated_git
        ).stdout.strip().lower()
        if actual_sha != github_sha:
            raise HostError("publisher checkout is not the exact GITHUB_SHA")

        trusted_files = (
            "deployment.json",
            "github_actions_host.py",
            "publisher.py",
            "requirements.linux-x86_64.txt",
        )
        _git(
            publisher_dir,
            "ls-files",
            "--error-unmatch",
            *trusted_files,
            env=unauthenticated_git,
        )
        clean = _git(
            publisher_dir,
            "diff",
            "--quiet",
            "HEAD",
            "--",
            *trusted_files,
            env=unauthenticated_git,
            check=False,
        )
        if clean.returncode != 0:
            raise HostError("publisher inputs differ from the exact GITHUB_SHA")

        deployment = _load_deployment(publisher_dir / "deployment.json")
        session = Path(tempfile.mkdtemp(prefix="fao-publisher-", dir=os.environ["RUNNER_TEMP"]))
        os.chmod(session, 0o700)
        state_wrapper = _write_ssh(
            session,
            _require_environment("FAO_PUBLISHER_STATE_DEPLOY_KEY"),
            "state",
            "FAO_PUBLISHER_STATE_DEPLOY_KEY",
        )
        state_git = _git_environment(session / "state-git-home")
        state_git.update({"GIT_SSH": str(state_wrapper), "GIT_SSH_VARIANT": "ssh"})
        state = StateBranch(
            session / "state",
            STATE_REMOTE,
            state_git,
            _decode_state_key(_require_environment("FAO_PUBLISHER_STATE_HMAC_KEY")),
        )
        state.restore(initialize)

        wrapper = _write_ssh(
            session,
            _require_environment("FAO_GOVERNED_SITE_DEPLOY_KEY"),
            "target",
            "FAO_GOVERNED_SITE_DEPLOY_KEY",
        )
        target_env = _git_environment(session / "target-git-home")
        target_env.update({"GIT_SSH": str(wrapper), "GIT_SSH_VARIANT": "ssh"})
        target = session / "governed-site"
        _run(
            [
                "/usr/bin/git",
                "-c",
                "core.hooksPath=/dev/null",
                "clone",
                "--no-tags",
                "--single-branch",
                "--branch",
                "main",
                TARGET_REMOTE,
                str(target),
            ],
            env=target_env,
        )

        config_values = dict(deployment)
        config_values.update(
            {
                "rpc_url": _require_environment("FAO_RPC_URL"),
                "witness_rpc_url": _require_environment("FAO_WITNESS_RPC_URL"),
                "state_dir": str(state.path),
                "worktree": str(target),
                "git_commit": True,
                "git_push": True,
                "git_ssh": str(wrapper),
            }
        )
        config_path = session / "config.json"
        config_path.write_text(json.dumps(config_values), encoding="utf-8")
        os.chmod(config_path, 0o600)
        config = publisher.Config.from_file(config_path)
        state.bind(_state_identity(config))

        result = subprocess.run(
            [sys.executable, str(publisher_dir / "publisher.py"), "--config", str(config_path), "--once"],
            env=_publisher_child_environment(),
        )
        if result.returncode:
            raise HostError("publisher one-shot failed; durable state was not advanced")

        store = publisher.StateStore(config, config.chain_id)
        if not store.path.exists():
            store.save(store.load())
        _remove_ephemeral_state(state.path)
        commit = state.save()
        print(f"durable publisher state: {commit}")
        return 0
    except (HostError, publisher.PublisherError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
