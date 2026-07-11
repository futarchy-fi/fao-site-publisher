#!/usr/bin/env python3
"""Confirmed, reorg-aware publisher for FAO SiteReleaseSelected archives."""

from __future__ import annotations

import argparse
import configparser
import dataclasses
import fcntl
import http.client
import ipaddress
import json
import math
import os
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unicodedata
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Iterator, Protocol

try:
    from Crypto.Hash import keccak
except ImportError as exc:  # pragma: no cover - exercised by deployment, not tests
    raise SystemExit("pycryptodome is required; install requirements.txt") from exc


EVENT_TOPIC = "0xaffbde70f75832d02e5dbcd327043d2219b0247708b9e4075944c364a402779a"
ZERO_DIGEST = "0x" + ("00" * 32)
STATE_VERSION = 2
GITHUB_REMOTE = "git@github.com:futarchy-fi/fao-governed-site.git"
MAX_RPC_RESPONSE = 16 * 1024 * 1024
MAX_CONFIG_BYTES = 1024 * 1024
MAX_CURSOR_BYTES = 1024 * 1024
MAX_PATH_BYTES = 4096
MAX_COMPONENT_BYTES = 255


class PublisherError(RuntimeError):
    """Expected fail-closed publisher error."""


class RpcError(PublisherError):
    pass


class UnsafeArtifact(PublisherError):
    pass


class ReorgDetected(PublisherError):
    pass


def _require_int(value: Any, name: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise PublisherError(f"{name} must be an integer >= {minimum}")
    return value


def _require_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise PublisherError(f"{name} must be a JSON boolean")
    return value


def _normalize_address(value: str) -> str:
    if not isinstance(value, str) or len(value) != 42 or not value.startswith("0x"):
        raise PublisherError("strategy_address must be a 20-byte hex address")
    try:
        int(value[2:], 16)
    except ValueError as exc:
        raise PublisherError("strategy_address must be hexadecimal") from exc
    if int(value[2:], 16) == 0:
        raise PublisherError("strategy_address cannot be zero")
    return value.lower()


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def _private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        info = path.lstat()
    except OSError as exc:
        raise PublisherError(f"cannot inspect private directory {path}: {exc}") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
    ):
        raise PublisherError(f"private directory has unsafe type or owner: {path}")
    os.chmod(path, 0o700)


def _require_trusted_ancestors(path: Path, label: str) -> None:
    ancestor = path.parent
    while True:
        try:
            info = ancestor.lstat()
        except OSError as exc:
            raise PublisherError(f"cannot stat {label} ancestor {ancestor}: {exc}") from exc
        sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid not in (0, os.getuid())
            or (info.st_mode & 0o022 and not sticky_root)
        ):
            raise PublisherError(f"{label} has an unsafe ancestor directory: {ancestor}")
        if ancestor == ancestor.parent:
            return
        ancestor = ancestor.parent


@dataclass(frozen=True)
class Config:
    rpc_url: str
    witness_rpc_url: str
    chain_id: int
    strategy_address: str
    start_block: int
    state_dir: Path
    worktree: Path
    confirmations: int = 12
    poll_seconds: float = 15.0
    log_chunk_size: int = 1000
    ipfs_gateway: str = "https://cloudflare-ipfs.com"
    max_archive_bytes: int = 50 * 1024 * 1024
    max_extracted_bytes: int = 50 * 1024 * 1024
    max_file_bytes: int = 25 * 1024 * 1024
    max_files: int = 20_000
    http_timeout: float = 30.0
    git_commit: bool = False
    git_push: bool = False
    git_ssh: Path | None = None

    @classmethod
    def from_file(cls, path: Path) -> "Config":
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid not in (0, os.getuid())
                or info.st_mode & 0o077
            ):
                raise PublisherError(
                    "config must be a root/publisher-owned regular file with mode 0600 or stricter"
                )
            with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
                descriptor = -1
                encoded = handle.read(MAX_CONFIG_BYTES + 1)
            if len(encoded.encode("utf-8")) > MAX_CONFIG_BYTES:
                raise PublisherError("config exceeds size limit")
            raw = json.loads(encoded)
        except (OSError, UnicodeError, ValueError) as exc:
            raise PublisherError(f"cannot read config {path}: {exc}") from exc
        finally:
            if "descriptor" in locals() and descriptor >= 0:
                os.close(descriptor)
        if not isinstance(raw, dict):
            raise PublisherError("config must be a JSON object")
        unknown = set(raw) - {field.name for field in dataclasses.fields(cls)}
        if unknown:
            raise PublisherError(f"config contains unknown fields: {', '.join(sorted(unknown))}")

        def optional_path(name: str) -> Path | None:
            value = raw.get(name)
            return None if value in (None, "") else Path(value).expanduser()

        try:
            cfg = cls(
                rpc_url=str(raw["rpc_url"]),
                witness_rpc_url=str(raw["witness_rpc_url"]),
                chain_id=_require_int(raw["chain_id"], "chain_id", 1),
                strategy_address=_normalize_address(raw["strategy_address"]),
                start_block=_require_int(raw["start_block"], "start_block"),
                state_dir=Path(raw["state_dir"]).expanduser(),
                worktree=Path(raw["worktree"]).expanduser(),
                confirmations=_require_int(raw.get("confirmations", 12), "confirmations", 1),
                poll_seconds=float(raw.get("poll_seconds", 15)),
                log_chunk_size=_require_int(
                    raw.get("log_chunk_size", 1000), "log_chunk_size", 1
                ),
                ipfs_gateway=str(raw.get("ipfs_gateway", "https://cloudflare-ipfs.com")),
                max_archive_bytes=_require_int(
                    raw.get("max_archive_bytes", 50 * 1024 * 1024),
                    "max_archive_bytes",
                    1,
                ),
                max_extracted_bytes=_require_int(
                    raw.get("max_extracted_bytes", 50 * 1024 * 1024),
                    "max_extracted_bytes",
                    1,
                ),
                max_file_bytes=_require_int(
                    raw.get("max_file_bytes", 25 * 1024 * 1024),
                    "max_file_bytes",
                    1,
                ),
                max_files=_require_int(raw.get("max_files", 20_000), "max_files", 1),
                http_timeout=float(raw.get("http_timeout", 30)),
                git_commit=_require_bool(raw.get("git_commit", False), "git_commit"),
                git_push=_require_bool(raw.get("git_push", False), "git_push"),
                git_ssh=optional_path("git_ssh"),
            )
        except KeyError as exc:
            raise PublisherError(f"config is missing required field {exc.args[0]}") from exc
        except (TypeError, ValueError) as exc:
            raise PublisherError(f"config contains an invalid value: {exc}") from exc
        cfg.validate()
        if _inside(path, cfg.worktree):
            raise PublisherError("config cannot live under the governed worktree")
        return cfg

    def validate(self) -> None:
        try:
            rpc = urllib.parse.urlsplit(self.rpc_url)
            witness_rpc = urllib.parse.urlsplit(self.witness_rpc_url)
            gateway = urllib.parse.urlsplit(self.ipfs_gateway)
            rpc.port
            witness_rpc.port
            gateway.port
        except ValueError as exc:
            raise PublisherError("an RPC URL or ipfs_gateway has an invalid host or port") from exc
        if any(
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            for parsed in (rpc, witness_rpc)
        ):
            raise PublisherError("rpc_url and witness_rpc_url must be HTTPS without userinfo")
        if rpc.hostname.rstrip(".").casefold() == witness_rpc.hostname.rstrip(".").casefold():
            raise PublisherError("RPC endpoints must use different provider hostnames")
        if (
            gateway.scheme != "https"
            or not gateway.hostname
            or gateway.username
            or gateway.password
            or gateway.query
            or gateway.fragment
        ):
            raise PublisherError("ipfs_gateway must be HTTPS")
        if any(
            character.isspace()
            or ord(character) < 32
            or ord(character) == 127
            or character == "\\"
            for value in (self.rpc_url, self.witness_rpc_url, self.ipfs_gateway)
            for character in value
        ):
            raise PublisherError("RPC URLs and ipfs_gateway contain unsafe characters")
        if (
            not math.isfinite(self.poll_seconds)
            or not math.isfinite(self.http_timeout)
            or self.poll_seconds <= 0
            or self.http_timeout <= 0
        ):
            raise PublisherError("poll_seconds and http_timeout must be positive")
        if not self.state_dir.is_absolute() or not self.worktree.is_absolute():
            raise PublisherError("state_dir and worktree must be absolute")
        if self.state_dir.exists() and (
            self.state_dir.is_symlink() or not self.state_dir.is_dir()
        ):
            raise PublisherError("state_dir must be a real directory when it exists")
        try:
            worktree_info = self.worktree.lstat()
        except OSError as exc:
            raise PublisherError(f"cannot inspect worktree: {exc}") from exc
        if (
            not stat.S_ISDIR(worktree_info.st_mode)
            or stat.S_ISLNK(worktree_info.st_mode)
            or worktree_info.st_uid != os.getuid()
            or worktree_info.st_mode & 0o022
        ):
            raise PublisherError(
                "worktree must be a publisher-owned, non-writable-by-others real directory"
            )
        _require_trusted_ancestors(self.worktree.resolve(), "worktree")
        git_control = self.worktree / ".git"
        try:
            git_info = git_control.lstat()
        except OSError as exc:
            raise PublisherError(f"cannot inspect worktree .git directory: {exc}") from exc
        if (
            not stat.S_ISDIR(git_info.st_mode)
            or stat.S_ISLNK(git_info.st_mode)
            or git_info.st_uid != os.getuid()
            or git_info.st_mode & 0o022
        ):
            raise PublisherError(
                "worktree .git must be a publisher-owned, non-writable-by-others real directory"
            )
        if self.max_file_bytes > self.max_extracted_bytes:
            raise PublisherError("max_file_bytes cannot exceed max_extracted_bytes")
        if _inside(self.state_dir, self.worktree) or _inside(self.worktree, self.state_dir):
            raise PublisherError("state_dir and worktree must be separate trees")
        publisher_dir = Path(__file__).resolve().parent
        if _inside(publisher_dir, self.worktree) or _inside(publisher_dir, self.state_dir):
            raise PublisherError("publisher code must be outside worktree and state_dir")
        if not self.git_commit or not self.git_push:
            raise PublisherError("Git commit and push publication must both be enabled")
        if self.git_ssh is None:
            raise PublisherError("Git publication requires a repository-scoped git_ssh executable")
        if self.git_ssh is not None:
            _trusted_executable(self.git_ssh, self)


def _trusted_executable(path: Path, cfg: Config) -> Path:
    if not path.is_absolute():
        raise PublisherError(f"trusted executable must be absolute: {path}")
    resolved = path.resolve()
    try:
        info = resolved.stat()
    except OSError as exc:
        raise PublisherError(f"cannot stat trusted executable {resolved}: {exc}") from exc
    if not stat.S_ISREG(info.st_mode) or not os.access(resolved, os.X_OK):
        raise PublisherError(f"trusted executable is not an executable file: {resolved}")
    if info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
        raise PublisherError(f"trusted executable has unsafe owner or mode: {resolved}")
    _require_trusted_ancestors(resolved, "trusted executable")
    if _inside(resolved, cfg.worktree) or _inside(resolved, cfg.state_dir):
        raise PublisherError("trusted executable cannot live under worktree or state_dir")
    return resolved


def _hex_quantity(value: int) -> str:
    return hex(value)


def _parse_quantity(value: Any, name: str) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise RpcError(f"invalid JSON-RPC quantity for {name}")
    try:
        return int(value, 16)
    except ValueError as exc:
        raise RpcError(f"invalid JSON-RPC quantity for {name}") from exc


class RpcLike(Protocol):
    def chain_id(self) -> int: ...
    def head(self) -> int: ...
    def block(self, number: int) -> dict[str, Any]: ...
    def logs(self, start: int, end: int) -> list[dict[str, Any]]: ...


class JsonRpc:
    def __init__(self, url: str, strategy_address: str, timeout: float = 30.0):
        self.url = url
        self.strategy_address = strategy_address
        self.timeout = timeout
        self._request_id = 0
        context = ssl.create_default_context()
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context)
        )

    def _call(self, method: str, params: list[Any]) -> Any:
        self._request_id += 1
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": self._request_id, "method": method, "params": params},
            separators=(",", ":"),
        ).encode()
        request = urllib.request.Request(
            self.url,
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "fao-site-publisher/1"},
            method="POST",
        )
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                body = response.read(MAX_RPC_RESPONSE + 1)
        except OSError as exc:
            raise RpcError(f"JSON-RPC transport failed: {exc}") from exc
        if len(body) > MAX_RPC_RESPONSE:
            raise RpcError("JSON-RPC response exceeds limit")
        try:
            decoded = json.loads(body)
        except ValueError as exc:
            raise RpcError("JSON-RPC returned invalid JSON") from exc
        if not isinstance(decoded, dict) or decoded.get("id") != self._request_id:
            raise RpcError("JSON-RPC response id mismatch")
        if decoded.get("error") is not None:
            raise RpcError(f"JSON-RPC {method} failed: {decoded['error']}")
        if "result" not in decoded:
            raise RpcError("JSON-RPC response has no result")
        return decoded["result"]

    def chain_id(self) -> int:
        return _parse_quantity(self._call("eth_chainId", []), "chain id")

    def head(self) -> int:
        return _parse_quantity(self._call("eth_blockNumber", []), "head")

    def block(self, number: int) -> dict[str, Any]:
        result = self._call("eth_getBlockByNumber", [_hex_quantity(number), False])
        if not isinstance(result, dict) or not isinstance(result.get("hash"), str):
            raise RpcError(f"block {number} is unavailable")
        if _parse_quantity(result.get("number"), "block number") != number:
            raise RpcError("JSON-RPC returned the wrong block")
        return result

    def logs(self, start: int, end: int) -> list[dict[str, Any]]:
        result = self._call(
            "eth_getLogs",
            [
                {
                    "fromBlock": _hex_quantity(start),
                    "toBlock": _hex_quantity(end),
                    "address": self.strategy_address,
                    "topics": [EVENT_TOPIC],
                }
            ],
        )
        if not isinstance(result, list) or not all(isinstance(item, dict) for item in result):
            raise RpcError("eth_getLogs returned an invalid result")
        return result


_RPC_LOG_FIELDS = (
    "address",
    "topics",
    "data",
    "blockNumber",
    "blockHash",
    "transactionHash",
    "transactionIndex",
    "logIndex",
    "removed",
)


def _normalized_rpc_value(value: Any) -> Any:
    if isinstance(value, str) and value.startswith("0x"):
        return value.lower()
    if isinstance(value, list):
        return [_normalized_rpc_value(item) for item in value]
    return value


def _log_fingerprints(logs: list[dict[str, Any]]) -> list[str]:
    fingerprints = [
        json.dumps(
            {
                field: _normalized_rpc_value(log.get(field))
                for field in _RPC_LOG_FIELDS
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        for log in logs
    ]
    return sorted(fingerprints)


class WitnessedRpc:
    """Require two independently configured RPC providers to agree on chain truth."""

    def __init__(self, primary: RpcLike, witness: RpcLike):
        self.primary = primary
        self.witness = witness

    def chain_id(self) -> int:
        primary = self.primary.chain_id()
        witness = self.witness.chain_id()
        if primary != witness:
            raise RpcError("RPC providers disagree on chain id")
        return primary

    def head(self) -> int:
        # A lagging or malicious provider may stop publication, but cannot advance it alone.
        return min(self.primary.head(), self.witness.head())

    def block(self, number: int) -> dict[str, Any]:
        primary = self.primary.block(number)
        witness = self.witness.block(number)
        primary_hash = str(primary.get("hash", "")).lower()
        witness_hash = str(witness.get("hash", "")).lower()
        if primary_hash != witness_hash:
            raise RpcError(f"RPC providers disagree on block {number}")
        return primary

    def logs(self, start: int, end: int) -> list[dict[str, Any]]:
        primary = self.primary.logs(start, end)
        witness = self.witness.logs(start, end)
        if _log_fingerprints(primary) != _log_fingerprints(witness):
            raise RpcError(f"RPC providers disagree on logs for blocks {start}-{end}")
        return primary


@dataclass(frozen=True)
class ReleaseEvent:
    proposal_id: int
    arbitration_id: int
    digest: str
    nonce: int
    previous_digest: str
    uri: str
    block_number: int
    block_hash: str
    transaction_hash: str
    transaction_index: int
    log_index: int

    def __post_init__(self) -> None:
        for name in ("digest", "previous_digest", "block_hash", "transaction_hash"):
            value = getattr(self, name)
            if not isinstance(value, str) or len(value) != 66 or not value.startswith("0x"):
                raise PublisherError(f"release event has malformed {name}")
            try:
                int(value[2:], 16)
            except ValueError as exc:
                raise PublisherError(f"release event has malformed {name}") from exc
        if self.digest.lower() == ZERO_DIGEST:
            raise PublisherError("release event has a zero artifact digest")
        for name in (
            "proposal_id",
            "arbitration_id",
            "nonce",
            "block_number",
            "transaction_index",
            "log_index",
        ):
            _require_int(getattr(self, name), f"release event {name}")
        if not isinstance(self.uri, str) or not 0 < len(self.uri.encode("utf-8")) <= 256:
            raise PublisherError("release event has malformed artifact URI")

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ReleaseEvent":
        try:
            return cls(**value)
        except TypeError as exc:
            raise PublisherError("cursor contains a malformed release event") from exc

    @property
    def identity(self) -> tuple[int, str, str, int]:
        return (self.nonce, self.digest, self.block_hash, self.log_index)


def _word(data: bytes, index: int) -> bytes:
    start = index * 32
    result = data[start : start + 32]
    if len(result) != 32:
        raise RpcError("event data is truncated")
    return result


def decode_release_log(log: dict[str, Any]) -> ReleaseEvent:
    topics = log.get("topics")
    if (
        not isinstance(topics, list)
        or len(topics) != 4
        or not all(
            isinstance(topic, str) and len(topic) == 66 and topic.startswith("0x")
            for topic in topics
        )
        or topics[0].lower() != EVENT_TOPIC
    ):
        raise RpcError("unexpected SiteReleaseSelected topics")
    try:
        topic_bytes = [bytes.fromhex(topic[2:]) for topic in topics[1:]]
        data_hex = log["data"]
        if not isinstance(data_hex, str) or not data_hex.startswith("0x"):
            raise ValueError("event data is not hex")
        data = bytes.fromhex(data_hex[2:])
    except (KeyError, TypeError, ValueError) as exc:
        raise RpcError("malformed SiteReleaseSelected log") from exc
    if any(len(item) != 32 for item in topic_bytes) or len(data) < 128 or len(data) % 32:
        raise RpcError("malformed SiteReleaseSelected ABI")

    nonce = int.from_bytes(_word(data, 0), "big")
    previous_digest = "0x" + _word(data, 1).hex()
    offset = int.from_bytes(_word(data, 2), "big")
    if offset != 96:
        raise RpcError("invalid artifactURI ABI offset")
    uri_length = int.from_bytes(data[offset : offset + 32], "big")
    uri_start = offset + 32
    uri_end = uri_start + uri_length
    padded_end = (uri_end + 31) // 32 * 32
    if (
        uri_length == 0
        or uri_length > 256
        or padded_end != len(data)
        or any(data[uri_end:padded_end])
    ):
        raise RpcError("invalid artifactURI ABI length")
    try:
        uri = data[uri_start:uri_end].decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise RpcError("artifactURI is not UTF-8") from exc

    block_hash = str(log.get("blockHash", "")).lower()
    tx_hash = str(log.get("transactionHash", "")).lower()
    if len(block_hash) != 66 or len(tx_hash) != 66 or log.get("removed") is not False:
        raise RpcError("log is removed or missing canonical hashes")
    return ReleaseEvent(
        proposal_id=int.from_bytes(topic_bytes[0], "big"),
        arbitration_id=int.from_bytes(topic_bytes[1], "big"),
        digest="0x" + topic_bytes[2].hex(),
        nonce=nonce,
        previous_digest=previous_digest,
        uri=uri,
        block_number=_parse_quantity(log.get("blockNumber"), "log block"),
        block_hash=block_hash,
        transaction_hash=tx_hash,
        transaction_index=_parse_quantity(log.get("transactionIndex"), "transaction index"),
        log_index=_parse_quantity(log.get("logIndex"), "log index"),
    )


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


class StateStore:
    def __init__(self, cfg: Config, chain_id: int):
        self.cfg = cfg
        self.chain_id = chain_id
        self.path = cfg.state_dir / "cursor.json"
        _private_directory(cfg.state_dir)

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {
                "version": STATE_VERSION,
                "chain_id": self.chain_id,
                "strategy_address": self.cfg.strategy_address,
                "start_block": self.cfg.start_block,
                "next_block": self.cfg.start_block,
                "checkpoint": None,
                "canonical": None,
                "applied": None,
            }
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = -1
        try:
            descriptor = os.open(self.path, flags)
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_mode & 0o077
            ):
                raise PublisherError(
                    "durable cursor must be publisher-owned mode 0600 or stricter"
                )
            with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
                descriptor = -1
                encoded = handle.read(MAX_CURSOR_BYTES + 1)
            if len(encoded.encode("utf-8")) > MAX_CURSOR_BYTES:
                raise PublisherError("durable cursor exceeds size limit")
            state = json.loads(encoded)
        except (OSError, UnicodeError, ValueError) as exc:
            raise PublisherError(f"cannot read durable cursor: {exc}") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if not isinstance(state, dict):
            raise PublisherError("durable cursor must be a JSON object")
        expected = (self.chain_id, self.cfg.strategy_address, self.cfg.start_block)
        actual = (state.get("chain_id"), state.get("strategy_address"), state.get("start_block"))
        if state.get("version") != STATE_VERSION or actual != expected:
            raise PublisherError("cursor belongs to a different chain, strategy, or start block")
        return state

    def save(self, state: dict[str, Any]) -> None:
        _atomic_json(self.path, state)


def _https_endpoint(url: str) -> tuple[str, int]:
    if not isinstance(url, str) or any(
        character.isspace() or ord(character) < 32 or ord(character) == 127 or character == "\\"
        for character in url
    ):
        raise UnsafeArtifact("artifact URL contains unsafe characters")
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port or 443
    except ValueError as exc:
        raise UnsafeArtifact("artifact URL has an invalid host or port") from exc
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise UnsafeArtifact("artifact URL must be public HTTPS without userinfo")
    return parsed.hostname.rstrip(".").lower(), port


def _public_socket_addresses(host: str, port: int) -> list[tuple[Any, ...]]:
    if host == "localhost" or host.endswith(".localhost"):
        raise UnsafeArtifact("localhost artifact URLs are forbidden")
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise UnsafeArtifact(f"artifact hostname cannot be resolved: {host}") from exc
    if not addresses:
        raise UnsafeArtifact("artifact hostname resolved to no addresses")
    for address in {item[4][0] for item in addresses}:
        try:
            ip = ipaddress.ip_address(address.split("%", 1)[0])
        except ValueError as exc:
            raise UnsafeArtifact("artifact hostname resolved to a malformed address") from exc
        if not ip.is_global:
            raise UnsafeArtifact(f"artifact hostname resolves to non-public address {ip}")
    return addresses


def _assert_public_https(url: str) -> None:
    host, port = _https_endpoint(url)
    _public_socket_addresses(host, port)


class _PublicHTTPSConnection(http.client.HTTPSConnection):
    """Resolve once, reject every non-public answer, and connect to that exact address."""

    def connect(self) -> None:
        if self._tunnel_host:
            raise UnsafeArtifact("artifact HTTP proxies are forbidden")
        last_error: OSError | None = None
        for family, socktype, protocol, _, address in _public_socket_addresses(
            self.host, self.port
        ):
            sock = socket.socket(family, socktype, protocol)
            try:
                if self.timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                    sock.settimeout(self.timeout)
                if self.source_address:
                    sock.bind(self.source_address)
                sock.connect(address)
                self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
                return
            except OSError as exc:
                last_error = exc
                sock.close()
        raise last_error or OSError("artifact hostname has no reachable public address")


class _PublicHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, request: urllib.request.Request) -> Any:
        return self.do_open(
            _PublicHTTPSConnection,
            request,
            context=self._context,
            check_hostname=self._check_hostname,
        )


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> urllib.request.Request | None:
        _https_endpoint(new_url)
        return super().redirect_request(request, file_pointer, code, message, headers, new_url)


def artifact_url(uri: str, gateway: str) -> str:
    if not isinstance(uri, str) or any(
        character.isspace() or ord(character) < 32 or ord(character) == 127 or character == "\\"
        for character in uri
    ):
        raise UnsafeArtifact("artifact URI contains unsafe characters")
    try:
        parsed = urllib.parse.urlsplit(uri)
        port = parsed.port
    except ValueError as exc:
        raise UnsafeArtifact("artifact URI has an invalid host or port") from exc
    if parsed.fragment:
        raise UnsafeArtifact("artifact URI fragments are forbidden")
    if parsed.scheme == "https":
        _https_endpoint(uri)
        return uri
    if parsed.scheme != "ipfs":
        raise UnsafeArtifact("artifact URI must use https or ipfs")
    if (
        parsed.query
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or port is not None
    ):
        raise UnsafeArtifact("malformed ipfs artifact URI")
    cid = parsed.netloc
    if len(cid) > 128 or not cid.isascii() or not cid.isalnum():
        raise UnsafeArtifact("malformed IPFS CID")
    if "%" in parsed.path or any(part in (".", "..") for part in parsed.path.split("/")):
        raise UnsafeArtifact("malformed IPFS artifact path")
    encoded_path = urllib.parse.quote(parsed.path, safe="/-._~")
    return f"{gateway.rstrip('/')}/ipfs/{urllib.parse.quote(cid, safe='')}{encoded_path}"


def _keccak_file(path: Path) -> str:
    digest = keccak.new(digest_bits=256)
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return "0x" + digest.hexdigest()


def fetch_artifact(uri: str, destination: Path, cfg: Config) -> tuple[str, int]:
    url = artifact_url(uri, cfg.ipfs_gateway)
    _https_endpoint(url)
    context = ssl.create_default_context()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _SafeRedirectHandler(),
        _PublicHTTPSHandler(context=context),
    )
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/x-tar, application/octet-stream",
            "User-Agent": "fao-site-publisher/1",
        },
        method="GET",
    )
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    total = 0
    digest = keccak.new(digest_bits=256)
    deadline = time.monotonic() + cfg.http_timeout
    try:
        with opener.open(request, timeout=cfg.http_timeout) as response:
            _https_endpoint(response.geturl())
            length = response.headers.get("Content-Length")
            if length is not None:
                try:
                    declared = int(length)
                except ValueError as exc:
                    raise UnsafeArtifact("invalid artifact Content-Length") from exc
                if declared < 0 or declared > cfg.max_archive_bytes:
                    raise UnsafeArtifact("artifact Content-Length exceeds limit")
            with destination.open("xb") as output:
                while True:
                    if time.monotonic() >= deadline:
                        raise UnsafeArtifact("artifact download exceeded total time limit")
                    chunk = response.read(
                        min(1024 * 1024, cfg.max_archive_bytes + 1 - total)
                    )
                    if time.monotonic() >= deadline:
                        raise UnsafeArtifact("artifact download exceeded total time limit")
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > cfg.max_archive_bytes:
                        raise UnsafeArtifact("downloaded artifact exceeds limit")
                    digest.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
    except FileExistsError as exc:
        raise PublisherError(f"temporary artifact already exists: {destination}") from exc
    except OSError as exc:
        raise UnsafeArtifact(f"artifact download failed: {exc}") from exc
    if total == 0:
        raise UnsafeArtifact("artifact is empty")
    return "0x" + digest.hexdigest(), total


@dataclass(frozen=True)
class ArchiveEntry:
    archive_name: str
    relative_path: PurePosixPath
    size: int
    is_directory: bool
    source: Any


class ArchiveLimits:
    def __init__(self, cfg: Config):
        self.max_files = cfg.max_files
        self.max_file_bytes = cfg.max_file_bytes
        self.max_total_bytes = cfg.max_extracted_bytes


def _path_parts(name: str) -> tuple[str, ...]:
    if not name or "\x00" in name or "\\" in name or name.startswith("/"):
        raise UnsafeArtifact(f"unsafe archive path: {name!r}")
    parts = name.split("/")
    if parts[-1] == "":
        parts = parts[:-1]
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise UnsafeArtifact(f"unsafe archive path: {name!r}")
    if len(parts[0]) == 2 and parts[0][0].isalpha() and parts[0][1] == ":":
        raise UnsafeArtifact(f"Windows-absolute archive path is forbidden: {name!r}")
    if any(any(ord(character) < 32 or ord(character) == 127 for character in part) for part in parts):
        raise UnsafeArtifact("archive paths cannot contain control characters")
    if len(name.encode("utf-8")) > MAX_PATH_BYTES:
        raise UnsafeArtifact("archive path exceeds byte limit")
    for part in parts:
        if len(part.encode("utf-8")) > MAX_COMPONENT_BYTES:
            raise UnsafeArtifact("archive path component exceeds byte limit")
    return tuple(parts)


def _collision_key(parts: Iterable[str]) -> str:
    return "/".join(unicodedata.normalize("NFC", part).casefold() for part in parts)


def _validate_entries(raw: list[tuple[str, int, bool, Any]], limits: ArchiveLimits) -> list[ArchiveEntry]:
    if not raw:
        raise UnsafeArtifact("archive has no entries")
    parsed: list[tuple[tuple[str, ...], int, bool, Any, str]] = []
    roots: set[str] = set()
    for name, size, is_directory, source in raw:
        parts = _path_parts(name)
        roots.add(_collision_key(parts[:1]))
        parsed.append((parts, size, is_directory, source, name))
    if len(roots) != 1:
        raise UnsafeArtifact("archive must contain exactly one top-level directory")

    entries: list[ArchiveEntry] = []
    seen: dict[str, bool] = {}
    total = 0
    files = 0
    root_entries = 0
    for parts, size, is_directory, source, name in parsed:
        if len(parts) == 1:
            if not is_directory:
                raise UnsafeArtifact("archive root must be a directory")
            root_entries += 1
            if root_entries > 1:
                raise UnsafeArtifact("duplicate archive root directory")
            continue
        relative_parts = parts[1:]
        key = _collision_key(relative_parts)
        if any(unicodedata.normalize("NFC", part).casefold() == ".git" for part in relative_parts):
            raise UnsafeArtifact("archive cannot contain .git control data")
        if key in seen:
            raise UnsafeArtifact(f"duplicate or filesystem-colliding archive path: {name}")
        for index in range(1, len(relative_parts)):
            parent_key = _collision_key(relative_parts[:index])
            if seen.get(parent_key) is False:
                raise UnsafeArtifact("archive path places a child below a regular file")
        if not is_directory:
            prefix = key + "/"
            if any(existing.startswith(prefix) for existing in seen):
                raise UnsafeArtifact("archive path replaces a directory with a regular file")
            if size < 0 or size > limits.max_file_bytes:
                raise UnsafeArtifact("archive member exceeds per-file limit")
            total += size
            files += 1
            if total > limits.max_total_bytes or files > limits.max_files:
                raise UnsafeArtifact("archive expanded size or file count exceeds limit")
        seen[key] = is_directory
        entries.append(
            ArchiveEntry(name, PurePosixPath(*relative_parts), size, is_directory, source)
        )
    if files == 0:
        raise UnsafeArtifact("archive contains no regular files")
    return entries


def _tar_entries(archive: tarfile.TarFile, limits: ArchiveLimits) -> list[ArchiveEntry]:
    raw: list[tuple[str, int, bool, Any]] = []
    for index, member in enumerate(archive):
        if index > limits.max_files:
            raise UnsafeArtifact("archive entry count exceeds limit")
        if member.isdir():
            raw.append((member.name, 0, True, member))
        elif member.isreg():
            raw.append((member.name, member.size, False, member))
        else:
            raise UnsafeArtifact("tar links and special members are forbidden")
    return _validate_entries(raw, limits)


def _write_member(stream: Any, target: Path, expected_size: int) -> None:
    target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    written = 0
    with target.open("xb") as output:
        while chunk := stream.read(min(1024 * 1024, expected_size + 1 - written)):
            written += len(chunk)
            if written > expected_size:
                raise UnsafeArtifact("archive member exceeded declared size")
            output.write(chunk)
    if written != expected_size:
        raise UnsafeArtifact("archive member was shorter than declared size")
    os.chmod(target, 0o644)


def extract_archive(archive_path: Path, destination: Path, cfg: Config) -> None:
    try:
        archive_info = archive_path.lstat()
    except OSError as exc:
        raise UnsafeArtifact(f"cannot inspect artifact archive: {exc}") from exc
    if (
        not stat.S_ISREG(archive_info.st_mode)
        or stat.S_ISLNK(archive_info.st_mode)
        or archive_info.st_size == 0
        or archive_info.st_size > cfg.max_archive_bytes
    ):
        raise UnsafeArtifact("artifact archive is not a bounded regular file")
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    limits = ArchiveLimits(cfg)
    try:
        with tarfile.open(archive_path, mode="r:") as archive:
            entries = _tar_entries(archive, limits)
            for entry in entries:
                target = destination.joinpath(*entry.relative_path.parts)
                if entry.is_directory:
                    target.mkdir(mode=0o755, parents=True, exist_ok=True)
                else:
                    source = archive.extractfile(entry.source)
                    if source is None:
                        raise UnsafeArtifact("tar regular member has no data")
                    with source:
                        _write_member(source, target, entry.size)
    except (tarfile.TarError, OSError, UnicodeError, ValueError) as exc:
        raise UnsafeArtifact(f"artifact is not a valid tar archive: {exc}") from exc


def _remove_no_follow(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return
    if stat.S_ISDIR(mode) and not stat.S_ISLNK(mode):
        shutil.rmtree(path)
    else:
        path.unlink()


def _copy_regular_tree(source: Path, destination: Path) -> None:
    destination.mkdir(mode=0o755, parents=True, exist_ok=True)
    for root, directories, files in os.walk(source, topdown=True, followlinks=False):
        root_path = Path(root)
        relative = root_path.relative_to(source)
        safe_directories: list[str] = []
        for name in directories:
            item = root_path / name
            mode = item.lstat().st_mode
            if not stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
                raise UnsafeArtifact(f"tree contains a non-directory entry: {item}")
            safe_directories.append(name)
            (destination / relative / name).mkdir(mode=0o755, parents=True, exist_ok=True)
        directories[:] = safe_directories
        for name in files:
            item = root_path / name
            mode = item.lstat().st_mode
            if not stat.S_ISREG(mode) or stat.S_ISLNK(mode):
                raise UnsafeArtifact(f"tree contains a non-regular file: {item}")
            target = destination / relative / name
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            with item.open("rb") as input_handle, target.open("xb") as output_handle:
                shutil.copyfileobj(input_handle, output_handle, 1024 * 1024)
            os.chmod(target, 0o644)


def _validate_release_tree(source: Path, cfg: Config) -> None:
    if not source.is_dir() or source.is_symlink():
        raise UnsafeArtifact("release tree must be a real directory")
    raw: list[tuple[str, int, bool, Any]] = [("release", 0, True, None)]
    for root, directories, files in os.walk(source, topdown=True, followlinks=False):
        root_path = Path(root)
        relative = root_path.relative_to(source)
        safe_directories: list[str] = []
        for name in directories:
            item = root_path / name
            mode = item.lstat().st_mode
            if not stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
                raise UnsafeArtifact("release tree contains a non-directory entry")
            safe_directories.append(name)
            raw.append(
                ("/".join(("release", *(relative / name).parts)), 0, True, None)
            )
        directories[:] = safe_directories
        for name in files:
            item = root_path / name
            info = item.lstat()
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise UnsafeArtifact("release tree contains a non-regular file")
            raw.append(
                (
                    "/".join(("release", *(relative / name).parts)),
                    info.st_size,
                    False,
                    None,
                )
            )
        if len(raw) > cfg.max_files + 1:
            raise UnsafeArtifact("release tree entry count exceeds limit")
    _validate_entries(raw, ArchiveLimits(cfg))


def replace_worktree(source: Path, worktree: Path) -> None:
    if not worktree.is_absolute() or not worktree.is_dir() or worktree.is_symlink():
        raise PublisherError("worktree must be an existing absolute real directory")
    git_control = worktree / ".git"
    if not git_control.is_dir() or git_control.is_symlink():
        raise PublisherError("worktree must contain a real .git directory")
    for child in worktree.iterdir():
        if child.name != ".git":
            _remove_no_follow(child)
    _copy_regular_tree(source, worktree)


class ReleaseActions:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.archives = cfg.state_dir / "archives"
        self.trees = cfg.state_dir / "trees"
        _private_directory(cfg.state_dir)
        _private_directory(self.archives)
        _private_directory(self.trees)
        self._ensure_genesis()

    def _ensure_genesis(self) -> None:
        genesis = self.trees / "genesis"
        if genesis.exists():
            return
        self._validate_git_config()
        for arguments in (
            ("diff", "--quiet", "--no-ext-diff", "--no-textconv"),
            ("diff", "--cached", "--quiet", "--no-ext-diff", "--no-textconv"),
        ):
            result = self._git(*arguments, check=False)
            if result.returncode not in (0, 1):
                raise PublisherError(f"cannot verify genesis Git state: {result.stderr.strip()}")
            if result.returncode == 1:
                raise PublisherError("refusing to capture genesis with tracked Git changes")

        tracked = self._git("ls-files", "-z", "--cached").stdout.split("\0")
        tracked = [path for path in tracked if path]
        if not tracked:
            raise PublisherError("governed repository has no tracked genesis files")
        temporary = Path(tempfile.mkdtemp(prefix=".genesis.", dir=self.trees))
        try:
            for relative in tracked:
                parts = _path_parts(relative)
                source = self.cfg.worktree.joinpath(*parts)
                mode = source.lstat().st_mode
                if not stat.S_ISREG(mode) or stat.S_ISLNK(mode):
                    raise PublisherError("genesis contains a non-regular tracked entry")
                target = temporary.joinpath(*parts)
                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                with source.open("rb") as input_handle, target.open("xb") as output_handle:
                    shutil.copyfileobj(input_handle, output_handle, 1024 * 1024)
                os.chmod(target, 0o644)
            _validate_release_tree(temporary, self.cfg)
            os.replace(temporary, genesis)
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)

    def _cached_tree(self, event: ReleaseEvent) -> Path:
        digest_name = event.digest[2:]
        tree = self.trees / digest_name
        if tree.exists():
            if not tree.is_dir() or tree.is_symlink():
                raise PublisherError("artifact cache tree is unsafe")
            return tree

        archive_path = self.archives / f"{digest_name}.archive"
        if not archive_path.exists():
            fd, temporary_name = tempfile.mkstemp(prefix=f".{digest_name}.", dir=self.archives)
            os.close(fd)
            os.unlink(temporary_name)
            temporary_archive = Path(temporary_name)
            try:
                actual_digest, _ = fetch_artifact(event.uri, temporary_archive, self.cfg)
                if actual_digest.lower() != event.digest.lower():
                    raise UnsafeArtifact(
                        f"artifact digest mismatch: event {event.digest}, fetched {actual_digest}"
                    )
                os.replace(temporary_archive, archive_path)
                os.chmod(archive_path, 0o600)
            finally:
                try:
                    temporary_archive.unlink()
                except FileNotFoundError:
                    pass
        else:
            archive_mode = archive_path.lstat().st_mode
            if not stat.S_ISREG(archive_mode) or stat.S_ISLNK(archive_mode):
                raise PublisherError("cached raw artifact is not a regular file")
            if _keccak_file(archive_path).lower() != event.digest.lower():
                raise PublisherError("cached raw artifact digest is corrupt")

        temporary_tree = Path(tempfile.mkdtemp(prefix=f".{digest_name}.", dir=self.trees))
        temporary_tree.rmdir()
        try:
            extract_archive(archive_path, temporary_tree, self.cfg)
            os.replace(temporary_tree, tree)
        finally:
            if temporary_tree.exists():
                shutil.rmtree(temporary_tree)
        return tree

    def apply(self, event: ReleaseEvent | None) -> None:
        tree = self.trees / "genesis" if event is None else self._cached_tree(event)
        # Revalidate cached trees before every replacement.
        _validate_release_tree(tree, self.cfg)
        replace_worktree(tree, self.cfg.worktree)
        if self.cfg.git_commit:
            self._git_publish(event)

    def _git(
        self, *arguments: str, check: bool = True, input_text: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        command = [
            "/usr/bin/git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "user.name=FAO Governed Publisher",
            "-c",
            "user.email=publisher@futarchy.ai",
        ]
        command += ["-C", str(self.cfg.worktree), *arguments]
        home = self.cfg.state_dir / "git-home"
        _private_directory(home)
        environment = {
            "HOME": str(home),
            "PATH": "/usr/bin:/bin",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "LANG": "C.UTF-8",
        }
        if self.cfg.git_ssh is not None:
            environment["GIT_SSH"] = str(_trusted_executable(self.cfg.git_ssh, self.cfg))
            environment["GIT_SSH_VARIANT"] = "ssh"
        return subprocess.run(
            command,
            check=check,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            input=input_text,
        )

    def _validate_git_config(self) -> None:
        config_path = self.cfg.worktree / ".git" / "config"
        parser = configparser.RawConfigParser()
        try:
            info = config_path.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_mode & 0o022
            ):
                raise PublisherError("repository config has unsafe type, owner, or mode")
            with config_path.open(encoding="utf-8") as handle:
                parser.read_file(handle)
        except (OSError, configparser.Error) as exc:
            raise PublisherError(f"cannot audit repository config: {exc}") from exc
        for section in parser.sections():
            lowered = section.casefold()
            options = set(parser.options(section))
            if lowered == "core":
                allowed = {
                    "repositoryformatversion",
                    "filemode",
                    "bare",
                    "logallrefupdates",
                    "ignorecase",
                    "precomposeunicode",
                    "symlinks",
                }
                if options - allowed:
                    raise PublisherError("repository core config contains unsafe options")
                try:
                    if parser.getboolean(section, "bare", fallback=False):
                        raise PublisherError("repository cannot be bare")
                except ValueError as exc:
                    raise PublisherError("repository bare setting is malformed") from exc
            elif lowered == 'remote "origin"':
                if options - {"url", "fetch"}:
                    raise PublisherError("origin remote contains unsafe publication options")
            elif lowered.startswith('branch "'):
                if options - {"remote", "merge"}:
                    raise PublisherError("branch config contains unexpected options")
            else:
                raise PublisherError(f"repository config section is not allowed: {section}")
        fetch_urls = self._git("remote", "get-url", "--all", "origin").stdout.splitlines()
        push_urls = self._git(
            "remote", "get-url", "--push", "--all", "origin"
        ).stdout.splitlines()
        if fetch_urls != [GITHUB_REMOTE] or push_urls != [GITHUB_REMOTE]:
            raise PublisherError("refusing unexpected Git fetch or push remote")

    def _index_exact_tree(self) -> None:
        paths: list[str] = []
        for root, directories, files in os.walk(
            self.cfg.worktree, topdown=True, followlinks=False
        ):
            root_path = Path(root)
            if root_path == self.cfg.worktree:
                directories[:] = [name for name in directories if name != ".git"]
            for name in files:
                path = root_path / name
                mode = path.lstat().st_mode
                if not stat.S_ISREG(mode) or stat.S_ISLNK(mode):
                    raise PublisherError("worktree changed to contain a non-regular file")
                relative = path.relative_to(self.cfg.worktree).as_posix()
                if "\n" in relative or "\t" in relative:
                    raise PublisherError("worktree contains a Git-unsafe path")
                paths.append(relative)
        paths.sort()
        path_input = "".join(path + "\n" for path in paths)
        try:
            hashed = self._git(
                "hash-object", "-w", "--no-filters", "--stdin-paths", input_text=path_input
            )
            object_ids = hashed.stdout.splitlines()
            if len(object_ids) != len(paths):
                raise PublisherError("git hash-object returned an unexpected object count")
            self._git("read-tree", "--empty")
            index_info = "".join(
                f"100644 {object_id}\t{path}\n"
                for path, object_id in zip(paths, object_ids)
            )
            self._git("update-index", "--index-info", input_text=index_info)
        except subprocess.CalledProcessError as exc:
            raise PublisherError(f"exact Git index construction failed: {exc.stderr.strip()}") from exc

    def _git_publish(self, event: ReleaseEvent | None) -> None:
        self._validate_git_config()
        self._index_exact_tree()
        staged = self._git(
            "diff", "--cached", "--quiet", "--no-ext-diff", "--no-textconv", check=False
        )
        if staged.returncode not in (0, 1):
            raise PublisherError(f"git diff failed: {staged.stderr.strip()}")
        if staged.returncode == 1:
            message = (
                "release: canonical genesis rollback"
                if event is None
                else f"release: nonce {event.nonce} {event.digest}"
            )
            try:
                self._git("commit", "--no-gpg-sign", "-m", message)
            except subprocess.CalledProcessError as exc:
                raise PublisherError(f"git commit failed: {exc.stderr.strip()}") from exc
        if self.cfg.git_push:
            try:
                self._git("push", "origin", "HEAD:refs/heads/main")
            except subprocess.CalledProcessError as exc:
                raise PublisherError(
                    f"git push failed with exit status {exc.returncode}"
                ) from exc

class EventApplier(Protocol):
    def apply(self, event: ReleaseEvent | None) -> None: ...


def _event_from_state(value: Any) -> ReleaseEvent | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise PublisherError("cursor contains malformed event state")
    return ReleaseEvent.from_dict(value)


def _validate_sequence(previous: ReleaseEvent | None, event: ReleaseEvent) -> None:
    expected_nonce = 1 if previous is None else previous.nonce + 1
    expected_digest = ZERO_DIGEST if previous is None else previous.digest
    if event.nonce != expected_nonce:
        raise PublisherError(
            f"release nonce is not contiguous: expected {expected_nonce}, got {event.nonce}"
        )
    if event.previous_digest.lower() != expected_digest.lower():
        raise PublisherError(
            f"release digest chain mismatch at nonce {event.nonce}: "
            f"expected {expected_digest}, got {event.previous_digest}"
        )


class ReleaseWatcher:
    def __init__(self, cfg: Config, rpc: RpcLike, applier: EventApplier):
        self.cfg = cfg
        self.rpc = rpc
        self.applier = applier
        chain_id = rpc.chain_id()
        if chain_id != cfg.chain_id:
            raise RpcError(f"wrong RPC chain: expected {cfg.chain_id}, got {chain_id}")
        self.store = StateStore(cfg, chain_id)
        self.state = self.store.load()

    def _checkpoint_is_canonical(self) -> bool:
        checkpoint = self.state.get("checkpoint")
        if checkpoint is None:
            return True
        if not isinstance(checkpoint, dict):
            raise PublisherError("cursor contains a malformed checkpoint")
        try:
            block = self.rpc.block(_require_int(checkpoint.get("number"), "checkpoint number"))
        except RpcError:
            return False
        return str(block.get("hash", "")).lower() == str(checkpoint.get("hash", "")).lower()

    def _ordered_logs(self, start: int, end: int) -> list[ReleaseEvent]:
        logs = self.rpc.logs(start, end)
        if any(
            not isinstance(log.get("address"), str)
            or log["address"].lower() != self.cfg.strategy_address
            for log in logs
        ):
            raise RpcError("eth_getLogs returned an event from the wrong strategy")
        events = [decode_release_log(log) for log in logs]
        events.sort(key=lambda item: (item.block_number, item.transaction_index, item.log_index))
        for event in events:
            if event.block_number < start or event.block_number > end:
                raise RpcError("eth_getLogs returned an out-of-range event")
            canonical_hash = str(self.rpc.block(event.block_number)["hash"]).lower()
            if canonical_hash != event.block_hash.lower():
                raise ReorgDetected("event block changed while processing logs")
        return events

    def _scan_events(self, start: int, end: int) -> Iterator[ReleaseEvent]:
        if end < start:
            return
        cursor = start
        while cursor <= end:
            chunk_end = min(end, cursor + self.cfg.log_chunk_size - 1)
            yield from self._ordered_logs(cursor, chunk_end)
            cursor = chunk_end + 1

    def _save_progress(
        self, end: int, canonical: ReleaseEvent | None, applied: ReleaseEvent | None
    ) -> None:
        block = self.rpc.block(end)
        if canonical is not None:
            current_event_block = self.rpc.block(canonical.block_number)
            if str(current_event_block["hash"]).lower() != canonical.block_hash.lower():
                raise ReorgDetected("chain changed before durable cursor commit")
        self.state["next_block"] = end + 1
        self.state["checkpoint"] = {"number": end, "hash": str(block["hash"]).lower()}
        self.state["canonical"] = None if canonical is None else canonical.to_dict()
        self.state["applied"] = None if applied is None else applied.to_dict()
        self.store.save(self.state)

    def _rescan(self, safe_head: int) -> None:
        canonical: ReleaseEvent | None = None
        for event in self._scan_events(self.cfg.start_block, safe_head):
            _validate_sequence(canonical, event)
            canonical = event
        applied = _event_from_state(self.state.get("applied"))
        if (canonical is None) != (applied is None) or (
            canonical is not None and applied is not None and canonical.identity != applied.identity
        ):
            self.applier.apply(canonical)
            applied = canonical
        self._save_progress(safe_head, canonical, applied)

    def sync_once(self) -> int:
        head = self.rpc.head()
        safe_head = head - self.cfg.confirmations
        if safe_head < self.cfg.start_block:
            return 0
        checkpoint = self.state.get("checkpoint")
        if checkpoint is not None:
            if not isinstance(checkpoint, dict):
                raise PublisherError("cursor contains a malformed checkpoint")
            checkpoint_number = _require_int(
                checkpoint.get("number"), "checkpoint number"
            )
            if safe_head < checkpoint_number:
                # Provider lag must never look like a deep reorg and roll back a
                # release that was already confirmed at a higher chain height.
                return 0
        if not self._checkpoint_is_canonical():
            self._rescan(safe_head)
            return 1
        next_block = _require_int(self.state.get("next_block"), "next_block")
        if next_block > safe_head:
            return 0

        applied_count = 0
        canonical = _event_from_state(self.state.get("canonical"))
        applied = _event_from_state(self.state.get("applied"))
        try:
            for event in self._scan_events(next_block, safe_head):
                _validate_sequence(canonical, event)
                canonical = event
        except ReorgDetected:
            self._rescan(safe_head)
            return 1
        if (canonical is None) != (applied is None) or (
            canonical is not None
            and applied is not None
            and canonical.identity != applied.identity
        ):
            # Only current canonical state is externally meaningful. This also
            # prevents a broken superseded artifact from blocking a later release.
            self.applier.apply(canonical)
            applied = canonical
            applied_count = 1
        try:
            self._save_progress(safe_head, canonical, applied)
        except ReorgDetected:
            self._rescan(safe_head)
            return applied_count + 1
        return applied_count


def _acquire_lock(cfg: Config) -> int:
    _private_directory(cfg.state_dir)
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(cfg.state_dir / "publisher.lock", flags, 0o600)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise PublisherError("publisher lock must be a publisher-owned regular file")
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except BlockingIOError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise PublisherError("another publisher process already holds the state lock") from exc
    except PublisherError:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise PublisherError(f"cannot acquire publisher state lock: {exc}") from exc


def _run(cfg: Config, once: bool) -> None:
    lock = _acquire_lock(cfg)
    try:
        rpc = WitnessedRpc(
            JsonRpc(cfg.rpc_url, cfg.strategy_address, cfg.http_timeout),
            JsonRpc(cfg.witness_rpc_url, cfg.strategy_address, cfg.http_timeout),
        )
        actions = ReleaseActions(cfg)
        watcher = ReleaseWatcher(cfg, rpc, actions)
        while True:
            try:
                count = watcher.sync_once()
                if count:
                    print(f"applied/reconciled {count} confirmed release(s)", flush=True)
            except PublisherError as exc:
                if once:
                    raise
                print(f"publisher retrying safely: {exc}", file=sys.stderr, flush=True)
                time.sleep(cfg.poll_seconds)
                continue
            if once:
                return
            time.sleep(cfg.poll_seconds)
    finally:
        os.close(lock)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--once", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        config = Config.from_file(arguments.config)
        _run(config, arguments.once)
    except PublisherError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
