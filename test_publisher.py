from __future__ import annotations

import io
import json
import os
import socket
import stat
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import Any
from unittest import mock

from Crypto.Hash import keccak

import publisher


def hash32(label: str) -> str:
    return "0x" + label.encode().hex().ljust(64, "0")[:64]


def quantity(value: int) -> str:
    return hex(value)


def event_log(
    nonce: int,
    digest: str,
    previous: str,
    uri: str | bytes,
    block: int,
    block_hash: str,
    log_index: int = 0,
) -> dict[str, Any]:
    encoded_uri = uri if isinstance(uri, bytes) else uri.encode()
    padded_uri = encoded_uri + (b"\0" * ((32 - len(encoded_uri) % 32) % 32))
    data = b"".join(
        [
            nonce.to_bytes(32, "big"),
            bytes.fromhex(previous[2:]),
            (96).to_bytes(32, "big"),
            len(encoded_uri).to_bytes(32, "big"),
            padded_uri,
        ]
    )
    return {
        "address": "0x" + "11" * 20,
        "topics": [
            publisher.EVENT_TOPIC,
            "0x" + (1).to_bytes(32, "big").hex(),
            "0x" + (2).to_bytes(32, "big").hex(),
            digest,
        ],
        "data": "0x" + data.hex(),
        "blockNumber": quantity(block),
        "blockHash": block_hash,
        "transactionHash": hash32(f"tx-{block}-{log_index}"),
        "transactionIndex": "0x0",
        "logIndex": quantity(log_index),
        "removed": False,
    }


class FakeRpc:
    def __init__(self, head: int, logs: list[dict[str, Any]] | None = None):
        self.head_value = head
        self.chain = 11155111
        self.log_values = logs or []
        self.hashes = {number: hash32(f"block-{number}-a") for number in range(head + 20)}

    def chain_id(self) -> int:
        return self.chain

    def head(self) -> int:
        return self.head_value

    def block(self, number: int) -> dict[str, Any]:
        if number not in self.hashes:
            raise publisher.RpcError("missing block")
        return {"number": quantity(number), "hash": self.hashes[number]}

    def logs(self, start: int, end: int) -> list[dict[str, Any]]:
        return [
            item
            for item in self.log_values
            if start <= int(item["blockNumber"], 16) <= end
        ]


class FakeApplier:
    def __init__(self):
        self.applied: list[publisher.ReleaseEvent | None] = []

    def apply(self, event: publisher.ReleaseEvent | None) -> None:
        self.applied.append(event)


class PublisherTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.worktree = self.root / "worktree"
        self.state = self.root / "state"
        self.worktree.mkdir()
        (self.worktree / "index.html").write_text("genesis", encoding="utf-8")
        subprocess.run(["/usr/bin/git", "init", "-q", str(self.worktree)], check=True)
        subprocess.run(
            [
                "/usr/bin/git",
                "-C",
                str(self.worktree),
                "remote",
                "add",
                "origin",
                publisher.GITHUB_REMOTE,
            ],
            check=True,
        )
        subprocess.run(
            ["/usr/bin/git", "-C", str(self.worktree), "add", "index.html"], check=True
        )
        subprocess.run(
            [
                "/usr/bin/git",
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "-C",
                str(self.worktree),
                "commit",
                "-q",
                "-m",
                "genesis",
            ],
            check=True,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def config(self, **overrides: Any) -> publisher.Config:
        values: dict[str, Any] = {
            "rpc_url": "https://rpc.example.invalid",
            "witness_rpc_url": "https://witness.example.invalid",
            "chain_id": 11155111,
            "strategy_address": "0x" + "11" * 20,
            "start_block": 1,
            "state_dir": self.state,
            "worktree": self.worktree,
            "confirmations": 2,
            "poll_seconds": 1,
            "log_chunk_size": 100,
            "max_archive_bytes": 1024 * 1024,
            "max_extracted_bytes": 1024 * 1024,
            "max_file_bytes": 1024 * 1024,
            "max_files": 100,
        }
        values.update(overrides)
        return publisher.Config(**values)

    def tar_archive(self, entries: list[tuple[str, bytes]], path: Path) -> None:
        with tarfile.open(path, "w") as archive:
            root = tarfile.TarInfo("release")
            root.type = tarfile.DIRTYPE
            archive.addfile(root)
            for name, body in entries:
                member = tarfile.TarInfo(name)
                member.size = len(body)
                archive.addfile(member, io.BytesIO(body))

    def test_event_topic_and_decode_match_contract_abi(self) -> None:
        signature = keccak.new(digest_bits=256)
        signature.update(
            b"SiteReleaseSelected(uint256,uint256,bytes32,uint256,bytes32,string)"
        )
        self.assertEqual(publisher.EVENT_TOPIC, "0x" + signature.hexdigest())
        digest = hash32("digest")
        block_hash = hash32("block")
        decoded = publisher.decode_release_log(
            event_log(1, digest, publisher.ZERO_DIGEST, "ipfs://bafy/test.tar", 7, block_hash)
        )
        self.assertEqual(decoded.proposal_id, 1)
        self.assertEqual(decoded.arbitration_id, 2)
        self.assertEqual(decoded.digest, digest)
        self.assertEqual(decoded.nonce, 1)
        self.assertEqual(decoded.uri, "ipfs://bafy/test.tar")
        self.assertEqual(decoded.block_hash, block_hash)

        noncanonical = event_log(
            1, digest, publisher.ZERO_DIGEST, "ipfs://bafy/test.tar", 7, block_hash
        )
        noncanonical["data"] += "00" * 32
        with self.assertRaises(publisher.RpcError):
            publisher.decode_release_log(noncanonical)

        malformed_topic = event_log(
            1, digest, publisher.ZERO_DIGEST, "ipfs://bafy/test.tar", 7, block_hash
        )
        malformed_topic["topics"][0] = None
        with self.assertRaises(publisher.RpcError):
            publisher.decode_release_log(malformed_topic)

    def test_ipfs_uri_maps_to_configured_https_gateway(self) -> None:
        self.assertEqual(
            publisher.artifact_url("ipfs://bafy123/site.tar", "https://ipfs.example"),
            "https://ipfs.example/ipfs/bafy123/site.tar",
        )
        with self.assertRaises(publisher.UnsafeArtifact):
            publisher.artifact_url("file:///tmp/site.tar", "https://ipfs.example")
        for uri in (
            "https://example.com/bad\nname.tar",
            "https://user@example.com/site.tar",
            "https://example.com:bad/site.tar",
            "ipfs://bafy123/../site.tar",
            "ipfs://bafy123/%2e%2e/site.tar",
            "ipfs://bafy123:0/site.tar",
            "ipfs://bafé123/site.tar",
        ):
            with self.subTest(uri=uri), self.assertRaises(publisher.UnsafeArtifact):
                publisher.artifact_url(uri, "https://ipfs.example")

    def test_config_is_private_and_rejects_unknown_fields(self) -> None:
        path = self.root / "publisher.json"
        path.write_text("{}", encoding="utf-8")
        path.chmod(0o644)
        with self.assertRaisesRegex(publisher.PublisherError, "mode 0600"):
            publisher.Config.from_file(path)

        path.chmod(0o600)
        path.write_text('{"unexpected":true}', encoding="utf-8")
        with self.assertRaisesRegex(publisher.PublisherError, "unknown fields"):
            publisher.Config.from_file(path)

    def test_https_connection_pins_a_validated_public_address(self) -> None:
        public = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443))
        private = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))
        with mock.patch("publisher.socket.getaddrinfo", return_value=[public, private]):
            with self.assertRaises(publisher.UnsafeArtifact):
                publisher._assert_public_https("https://artifact.example/site.tar")

        context = mock.Mock()
        raw_socket = mock.Mock()
        context.wrap_socket.return_value = mock.sentinel.tls_socket
        connection = publisher._PublicHTTPSConnection(
            "artifact.example", 443, timeout=3, context=context
        )
        with (
            mock.patch("publisher.socket.getaddrinfo", return_value=[public]),
            mock.patch("publisher.socket.socket", return_value=raw_socket),
        ):
            connection.connect()
        raw_socket.connect.assert_called_once_with(("1.1.1.1", 443))
        context.wrap_socket.assert_called_once_with(
            raw_socket, server_hostname="artifact.example"
        )
        self.assertIs(connection.sock, mock.sentinel.tls_socket)

    def test_artifact_download_has_a_total_time_limit(self) -> None:
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.geturl.return_value = "https://artifact.example/site.tar"
        response.headers = {}
        response.read.return_value = b"slow byte"
        opener = mock.Mock()
        opener.open.return_value = response
        with (
            mock.patch("publisher.urllib.request.build_opener", return_value=opener),
            mock.patch("publisher.time.monotonic", side_effect=[0, 0, 31]),
        ):
            with self.assertRaisesRegex(publisher.UnsafeArtifact, "total time"):
                publisher.fetch_artifact(
                    "https://artifact.example/site.tar",
                    self.root / "slow-artifact",
                    self.config(http_timeout=30),
                )

    def test_extracts_regular_tar_under_single_stripped_root(self) -> None:
        archive = self.root / "site.tar"
        self.tar_archive(
            [("release/index.html", b"hello"), ("release/assets/app.js", b"data")], archive
        )
        target = self.root / "extracted"
        publisher.extract_archive(archive, target, self.config())
        self.assertEqual((target / "index.html").read_bytes(), b"hello")
        self.assertEqual((target / "assets/app.js").read_bytes(), b"data")
        self.assertFalse((target / "release").exists())

    def test_preserves_only_the_git_executable_bit(self) -> None:
        archive_path = self.root / "executable.tar"
        with tarfile.open(archive_path, "w") as archive:
            root = tarfile.TarInfo("release")
            root.type = tarfile.DIRTYPE
            archive.addfile(root)
            script = tarfile.TarInfo("release/deploy.sh")
            script.mode = 0o6751
            script.size = 10
            archive.addfile(script, io.BytesIO(b"#!/bin/sh\n"))

        extracted = self.root / "executable-tree"
        publisher.extract_archive(archive_path, extracted, self.config())
        self.assertEqual(stat.S_IMODE((extracted / "deploy.sh").stat().st_mode), 0o755)

        actions = publisher.ReleaseActions(self.config(git_commit=True))
        publisher.replace_worktree(extracted, self.worktree)
        actions._index_exact_tree()
        index = subprocess.run(
            ["/usr/bin/git", "-C", str(self.worktree), "ls-files", "--stage", "deploy.sh"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout
        self.assertTrue(index.startswith("100755 "))

    def test_rejects_path_traversal_absolute_duplicates_and_case_collisions(self) -> None:
        cases = [
            [("release/../escape", b"x")],
            [("/release/escape", b"x")],
            [("release/A.txt", b"x"), ("release/a.txt", b"y")],
        ]
        for index, entries in enumerate(cases):
            with self.subTest(index=index):
                archive = self.root / f"bad-{index}.tar"
                self.tar_archive(entries, archive)
                with self.assertRaises(publisher.UnsafeArtifact):
                    publisher.extract_archive(archive, self.root / f"target-{index}", self.config())

        duplicate = self.root / "duplicate.tar"
        self.tar_archive([("release/a", b"x"), ("release/a", b"y")], duplicate)
        with self.assertRaises(publisher.UnsafeArtifact):
            publisher.extract_archive(duplicate, self.root / "target-duplicate", self.config())

        duplicate_root = self.root / "duplicate-root.tar"
        with tarfile.open(duplicate_root, "w") as archive:
            for name in ("release", "Release"):
                root = tarfile.TarInfo(name)
                root.type = tarfile.DIRTYPE
                archive.addfile(root)
            member = tarfile.TarInfo("release/index.html")
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))
        with self.assertRaises(publisher.UnsafeArtifact):
            publisher.extract_archive(
                duplicate_root, self.root / "target-duplicate-root", self.config()
            )
        with self.assertRaises(publisher.UnsafeArtifact):
            publisher._path_parts("C:/release/index.html")

        nested_git = self.root / "nested-git.tar"
        self.tar_archive([("release/assets/.git/config", b"unsafe")], nested_git)
        with self.assertRaises(publisher.UnsafeArtifact):
            publisher.extract_archive(nested_git, self.root / "nested-git", self.config())

    def test_rejects_tar_links_devices_and_non_tar_archives(self) -> None:
        tar_path = self.root / "link.tar"
        with tarfile.open(tar_path, "w") as archive:
            directory = tarfile.TarInfo("release")
            directory.type = tarfile.DIRTYPE
            archive.addfile(directory)
            regular = tarfile.TarInfo("release/a")
            regular.size = 1
            archive.addfile(regular, io.BytesIO(b"a"))
            link = tarfile.TarInfo("release/b")
            link.type = tarfile.LNKTYPE
            link.linkname = "release/a"
            archive.addfile(link)
        with self.assertRaises(publisher.UnsafeArtifact):
            publisher.extract_archive(tar_path, self.root / "tar-target", self.config())

        symlink_path = self.root / "symlink.tar"
        with tarfile.open(symlink_path, "w") as archive:
            directory = tarfile.TarInfo("release")
            directory.type = tarfile.DIRTYPE
            archive.addfile(directory)
            link = tarfile.TarInfo("release/link")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            archive.addfile(link)
        with self.assertRaises(publisher.UnsafeArtifact):
            publisher.extract_archive(
                symlink_path, self.root / "symlink-target", self.config()
            )

        device_path = self.root / "device.tar"
        with tarfile.open(device_path, "w") as archive:
            directory = tarfile.TarInfo("release")
            directory.type = tarfile.DIRTYPE
            archive.addfile(directory)
            device = tarfile.TarInfo("release/device")
            device.type = tarfile.CHRTYPE
            archive.addfile(device)
        with self.assertRaises(publisher.UnsafeArtifact):
            publisher.extract_archive(device_path, self.root / "device-target", self.config())

        zip_path = self.root / "unsupported.zip"
        with zipfile.ZipFile(zip_path, "w") as archive:
            archive.writestr("release/index.html", b"no")
        with self.assertRaises(publisher.UnsafeArtifact):
            publisher.extract_archive(zip_path, self.root / "zip-target", self.config())

        compressed = self.root / "compressed.tar.gz"
        with tarfile.open(compressed, "w:gz") as archive:
            root = tarfile.TarInfo("release")
            root.type = tarfile.DIRTYPE
            archive.addfile(root)
            member = tarfile.TarInfo("release/index.html")
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))
        with self.assertRaises(publisher.UnsafeArtifact):
            publisher.extract_archive(
                compressed, self.root / "compressed-target", self.config()
            )

    def test_rejects_expansion_and_excessive_entries(self) -> None:
        archive = self.root / "large.tar"
        self.tar_archive([("release/big", b"x" * 20)], archive)
        small = self.config(max_file_bytes=10, max_extracted_bytes=10)
        with self.assertRaises(publisher.UnsafeArtifact):
            publisher.extract_archive(archive, self.root / "large-target", small)

        entries = self.root / "too-many-entries.tar"
        with tarfile.open(entries, "w") as archive:
            for name in ("release", "release/a", "release/b"):
                directory = tarfile.TarInfo(name)
                directory.type = tarfile.DIRTYPE
                archive.addfile(directory)
            file_info = tarfile.TarInfo("release/index.html")
            file_info.size = 1
            archive.addfile(file_info, io.BytesIO(b"x"))
        with self.assertRaises(publisher.UnsafeArtifact):
            publisher.extract_archive(
                entries,
                self.root / "too-many-target",
                self.config(max_files=2),
            )

    def test_governance_can_replace_workflows_and_server_code(self) -> None:
        archive = self.root / "governed-code.tar"
        self.tar_archive(
            [
                ("release/.github/workflows/pwn.yml", b"on: push"),
                ("release/functions/api.js", b"export function onRequest() {}"),
                ("release/_worker.js", b"export default {}"),
            ],
            archive,
        )
        digest = publisher._keccak_file(archive)
        actions = publisher.ReleaseActions(self.config())
        cached_archive = actions.archives / f"{digest[2:]}.archive"
        cached_archive.write_bytes(archive.read_bytes())
        cached_archive.chmod(0o600)
        event = publisher.ReleaseEvent(
            1,
            2,
            digest,
            1,
            publisher.ZERO_DIGEST,
            "https://example.com/release.tar",
            5,
            hash32("block-5"),
            hash32("tx-5"),
            0,
            0,
        )
        actions.apply(event)
        self.assertTrue((self.worktree / ".github/workflows/pwn.yml").is_file())
        self.assertTrue((self.worktree / "functions/api.js").is_file())
        self.assertTrue((self.worktree / "_worker.js").is_file())

    def test_digest_named_tree_is_rebuilt_from_the_verified_archive(self) -> None:
        archive = self.root / "verified.tar"
        self.tar_archive([("release/index.html", b"verified")], archive)
        digest = publisher._keccak_file(archive)
        actions = publisher.ReleaseActions(self.config())
        cached_archive = actions.archives / f"{digest[2:]}.archive"
        cached_archive.write_bytes(archive.read_bytes())
        cached_archive.chmod(0o600)
        preseeded = actions.trees / digest[2:]
        preseeded.mkdir()
        (preseeded / "index.html").write_text("malicious", encoding="utf-8")
        (preseeded / "backdoor.js").write_text("malicious", encoding="utf-8")
        event = publisher.ReleaseEvent(
            1,
            2,
            digest,
            1,
            publisher.ZERO_DIGEST,
            "https://example.com/release.tar",
            5,
            hash32("block-5"),
            hash32("tx-5"),
            0,
            0,
        )

        actions.apply(event)

        self.assertEqual((self.worktree / "index.html").read_text(), "verified")
        self.assertFalse((self.worktree / "backdoor.js").exists())

    def test_digest_named_tree_cannot_bypass_a_corrupt_cached_archive(self) -> None:
        digest = hash32("expected-archive")
        actions = publisher.ReleaseActions(self.config())
        (actions.archives / f"{digest[2:]}.archive").write_bytes(b"corrupt")
        preseeded = actions.trees / digest[2:]
        preseeded.mkdir()
        (preseeded / "index.html").write_text("malicious", encoding="utf-8")
        event = publisher.ReleaseEvent(
            1,
            2,
            digest,
            1,
            publisher.ZERO_DIGEST,
            "https://example.com/release.tar",
            5,
            hash32("block-5"),
            hash32("tx-5"),
            0,
            0,
        )

        with self.assertRaisesRegex(publisher.PublisherError, "digest is corrupt"):
            actions.apply(event)

        self.assertEqual((self.worktree / "index.html").read_text(), "genesis")

    def test_genesis_excludes_untracked_local_state(self) -> None:
        (self.worktree / ".wrangler").mkdir()
        (self.worktree / ".wrangler/cache").write_text("local", encoding="utf-8")
        genesis = publisher.ReleaseActions(self.config()).trees / "genesis"
        self.assertFalse((genesis / ".wrangler").exists())
        self.assertEqual((genesis / "index.html").read_text(), "genesis")

    def test_canonical_genesis_reconciliation_repairs_direct_target_drift(self) -> None:
        actions = publisher.ReleaseActions(self.config())
        (self.worktree / "index.html").write_text("drifted", encoding="utf-8")
        (self.worktree / "unapproved.html").write_text("drifted", encoding="utf-8")

        actions.apply(None)

        self.assertEqual((self.worktree / "index.html").read_text(), "genesis")
        self.assertFalse((self.worktree / "unapproved.html").exists())

    def test_hosted_reconciliation_commits_and_pushes_direct_target_drift(self) -> None:
        remote = self.root / "governed.git"
        subprocess.run(["/usr/bin/git", "init", "-q", "--bare", str(remote)], check=True)
        subprocess.run(
            [
                "/usr/bin/git",
                "-C",
                str(self.worktree),
                "remote",
                "set-url",
                "origin",
                str(remote),
            ],
            check=True,
        )
        with mock.patch("publisher.GITHUB_REMOTE", str(remote)):
            actions = publisher.ReleaseActions(
                self.config(git_commit=True, git_push=True)
            )
            (self.worktree / "index.html").write_text("drifted", encoding="utf-8")
            (self.worktree / "unapproved.html").write_text("drifted", encoding="utf-8")

            actions.apply(None)

        pushed = subprocess.run(
            [
                "/usr/bin/git",
                "--git-dir",
                str(remote),
                "show",
                "main:index.html",
            ],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout
        self.assertEqual(pushed, "genesis")
        missing = subprocess.run(
            [
                "/usr/bin/git",
                "--git-dir",
                str(remote),
                "cat-file",
                "-e",
                "main:unapproved.html",
            ],
            stderr=subprocess.DEVNULL,
        )
        self.assertNotEqual(missing.returncode, 0)

    def test_replace_worktree_is_exact_and_preserves_only_git_control(self) -> None:
        (self.worktree / "old.txt").write_text("old", encoding="utf-8")
        (self.worktree / ".wrangler").mkdir()
        (self.worktree / ".wrangler/cache").write_text("cache", encoding="utf-8")
        source = self.root / "source"
        source.mkdir()
        (source / "index.html").write_text("new", encoding="utf-8")
        (source / "README.md").write_text("readme", encoding="utf-8")
        publisher.replace_worktree(source, self.worktree)
        self.assertTrue((self.worktree / ".git").is_dir())
        self.assertEqual((self.worktree / "index.html").read_text(), "new")
        self.assertEqual((self.worktree / "README.md").read_text(), "readme")
        self.assertFalse((self.worktree / "old.txt").exists())
        self.assertFalse((self.worktree / ".wrangler").exists())

    def test_digest_is_ethereum_keccak_not_nist_sha3(self) -> None:
        payload = self.root / "payload"
        payload.write_bytes(b"")
        self.assertEqual(
            publisher._keccak_file(payload),
            "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )

    def test_git_index_preserves_exact_bytes_without_attributes_or_hooks(self) -> None:
        shutil_git = "/usr/bin/git"
        cfg = self.config(git_commit=True)
        actions = publisher.ReleaseActions(cfg)
        (self.worktree / ".gitattributes").write_text("*.txt text eol=lf\n", encoding="utf-8")
        exact = b"line-one\r\nline-two\r\n"
        (self.worktree / "exact.txt").write_bytes(exact)
        event = publisher.ReleaseEvent(
            1,
            2,
            hash32("git-release"),
            1,
            publisher.ZERO_DIGEST,
            "https://example.com/release.tar",
            5,
            hash32("block-5"),
            hash32("tx-5"),
            0,
            0,
        )
        actions._git_publish(event)
        committed = subprocess.run(
            [shutil_git, "-C", str(self.worktree), "show", "HEAD:exact.txt"],
            check=True,
            stdout=subprocess.PIPE,
        ).stdout
        self.assertEqual(committed, exact)

        subprocess.run(
            [
                shutil_git,
                "-C",
                str(self.worktree),
                "remote",
                "set-url",
                "--push",
                "origin",
                "https://example.invalid/wrong.git",
            ],
            check=True,
        )
        with self.assertRaises(publisher.PublisherError):
            actions._validate_git_config()

    def test_privileged_git_failure_does_not_reemit_helper_output(self) -> None:
        actions = publisher.ReleaseActions(
            self.config(git_commit=True, git_push=True)
        )
        clean = subprocess.CompletedProcess([], 0, "", "")
        failure = subprocess.CalledProcessError(
            1, ["git", "push"], stderr="diagnostic contains credential-token"
        )
        with (
            mock.patch.object(actions, "_validate_git_config"),
            mock.patch.object(actions, "_index_exact_tree"),
            mock.patch.object(actions, "_git", side_effect=[clean, failure]),
        ):
            with self.assertRaises(publisher.PublisherError) as error:
                actions._git_publish(None)
        self.assertNotIn("credential-token", str(error.exception))

    def test_git_ssh_executable_cannot_live_below_a_writable_directory(self) -> None:
        unsafe = self.root / "world-writable"
        unsafe.mkdir()
        unsafe.chmod(0o777)
        wrapper = unsafe / "git-ssh"
        wrapper.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        wrapper.chmod(0o700)
        with self.assertRaises(publisher.PublisherError):
            self.config(
                git_commit=True, git_push=True, git_ssh=wrapper
            ).validate()

    def test_worktree_and_git_control_cannot_be_writable_by_other_users(self) -> None:
        self.worktree.chmod(0o777)
        with self.assertRaisesRegex(publisher.PublisherError, "worktree must"):
            self.config().validate()

        self.worktree.chmod(0o755)
        (self.worktree / ".git").chmod(0o777)
        with self.assertRaisesRegex(publisher.PublisherError, "worktree .git"):
            self.config().validate()

    def test_two_rpc_providers_must_agree_on_blocks_and_complete_logs(self) -> None:
        primary = FakeRpc(10)
        witness = FakeRpc(8)
        agreed = publisher.WitnessedRpc(primary, witness)
        self.assertEqual(agreed.chain_id(), 11155111)
        self.assertEqual(agreed.head(), 8)
        self.assertEqual(agreed.block(5)["hash"], primary.hashes[5])

        log = event_log(
            1,
            hash32("agreed-release"),
            publisher.ZERO_DIGEST,
            "https://example.com/release.tar",
            5,
            primary.hashes[5],
        )
        primary.log_values = [log]
        witness.log_values = [dict(log)]
        self.assertEqual(agreed.logs(1, 8), [log])

        witness.log_values = []
        with self.assertRaises(publisher.RpcError):
            agreed.logs(1, 8)
        witness.hashes[5] = hash32("fabricated-block")
        with self.assertRaises(publisher.RpcError):
            agreed.block(5)

    def test_confirmation_cursor_and_restart_are_idempotent(self) -> None:
        rpc = FakeRpc(10)
        digest1 = hash32("release-one")
        first = event_log(1, digest1, publisher.ZERO_DIGEST, "https://example.com/one.zip", 8, rpc.hashes[8])
        digest2 = hash32("release-two")
        second = event_log(2, digest2, digest1, "https://example.com/two.zip", 9, rpc.hashes[9])
        rpc.log_values = [first, second]
        applier = FakeApplier()
        watcher = publisher.ReleaseWatcher(self.config(), rpc, applier)
        self.assertEqual(watcher.sync_once(), 1)
        self.assertEqual([item.nonce for item in applier.applied if item], [1])

        restarted = publisher.ReleaseWatcher(self.config(), rpc, applier)
        self.assertEqual(restarted.sync_once(), 0)
        rpc.head_value = 11
        self.assertEqual(restarted.sync_once(), 1)
        self.assertEqual([item.nonce for item in applier.applied if item], [1, 2])

        durable = json.loads((self.state / "cursor.json").read_text())
        self.assertEqual(durable["next_block"], 10)
        self.assertEqual(durable["canonical"]["nonce"], 2)

    def test_catchup_publishes_only_the_final_release_across_chunks(self) -> None:
        rpc = FakeRpc(10)
        digest1 = hash32("release-one")
        digest2 = hash32("release-two")
        rpc.log_values = [
            event_log(
                1,
                digest1,
                publisher.ZERO_DIGEST,
                "https://example.com/one.tar",
                5,
                rpc.hashes[5],
            ),
            event_log(
                2,
                digest2,
                digest1,
                "https://example.com/two.tar",
                6,
                rpc.hashes[6],
            ),
        ]
        applier = FakeApplier()
        watcher = publisher.ReleaseWatcher(
            self.config(log_chunk_size=1), rpc, applier
        )
        self.assertEqual(watcher.sync_once(), 1)
        self.assertEqual([event.nonce for event in applier.applied if event], [2])

    def test_invalid_utf8_uri_does_not_block_a_later_valid_release(self) -> None:
        class FetchBoundaryApplier(FakeApplier):
            def apply(self, event: publisher.ReleaseEvent | None) -> None:
                if event is not None:
                    publisher.artifact_url(event.uri, "https://ipfs.example")
                super().apply(event)

        rpc = FakeRpc(7)
        digest1 = hash32("invalid-uri")
        digest2 = hash32("recovery")
        rpc.log_values = [
            event_log(
                1,
                digest1,
                publisher.ZERO_DIGEST,
                b"https://example.com/\xff.tar",
                5,
                rpc.hashes[5],
            ),
            event_log(
                2,
                digest2,
                digest1,
                "https://example.com/recovery.tar",
                6,
                rpc.hashes[6],
            ),
        ]
        applier = FetchBoundaryApplier()
        watcher = publisher.ReleaseWatcher(self.config(log_chunk_size=1), rpc, applier)

        with self.assertRaisesRegex(publisher.UnsafeArtifact, "valid UTF-8"):
            watcher.sync_once()
        self.assertFalse((self.state / "cursor.json").exists())

        rpc.head_value = 10
        self.assertEqual(watcher.sync_once(), 1)
        self.assertEqual([event.nonce for event in applier.applied if event], [2])

        invalid = publisher.decode_release_log(rpc.log_values[0])
        restored = publisher.ReleaseEvent.from_dict(
            json.loads(json.dumps(invalid.to_dict()))
        )
        self.assertEqual(
            restored.uri.encode("utf-8", errors="surrogateescape"),
            b"https://example.com/\xff.tar",
        )
        with self.assertRaisesRegex(publisher.UnsafeArtifact, "valid UTF-8"):
            publisher.artifact_url(invalid.uri, "https://ipfs.example")

    def test_wrong_rpc_chain_fails_before_cursor_creation(self) -> None:
        rpc = FakeRpc(10)
        rpc.chain = 1
        with self.assertRaises(publisher.RpcError):
            publisher.ReleaseWatcher(self.config(), rpc, FakeApplier())
        self.assertFalse((self.state / "cursor.json").exists())

    def test_pre_witness_cursor_is_rejected_for_a_full_rescan(self) -> None:
        self.state.mkdir()
        (self.state / "cursor.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "chain_id": 11155111,
                    "strategy_address": "0x" + "11" * 20,
                    "start_block": 1,
                }
            ),
            encoding="utf-8",
        )
        (self.state / "cursor.json").chmod(0o600)
        with self.assertRaises(publisher.PublisherError):
            publisher.ReleaseWatcher(self.config(), FakeRpc(10), FakeApplier())

    def test_cursor_symlink_is_rejected(self) -> None:
        self.state.mkdir()
        target = self.root / "external-cursor.json"
        target.write_text("{}", encoding="utf-8")
        (self.state / "cursor.json").symlink_to(target)
        with self.assertRaises(publisher.PublisherError):
            publisher.ReleaseWatcher(self.config(), FakeRpc(10), FakeApplier())

    def test_state_lock_rejects_a_second_process(self) -> None:
        first = publisher._acquire_lock(self.config())
        child = os.fork()
        if child == 0:
            os.close(first)
            try:
                second = publisher._acquire_lock(self.config())
            except publisher.PublisherError:
                os._exit(0)
            else:
                os.close(second)
                os._exit(1)
        try:
            _, status = os.waitpid(child, 0)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        finally:
            os.close(first)

    def test_daemon_retries_transient_fail_closed_errors(self) -> None:
        watcher = mock.Mock()
        watcher.sync_once.side_effect = publisher.RpcError("temporary disagreement")
        with (
            mock.patch("publisher.JsonRpc", return_value=mock.Mock()),
            mock.patch("publisher.ReleaseActions", return_value=mock.Mock()),
            mock.patch("publisher.ReleaseWatcher", return_value=watcher),
            mock.patch("publisher.time.sleep", side_effect=RuntimeError("stop test")),
            mock.patch("builtins.print"),
        ):
            with self.assertRaisesRegex(RuntimeError, "stop test"):
                publisher._run(self.config(), once=False)
        watcher.sync_once.assert_called_once_with()

    def test_one_shot_reconciles_even_when_no_new_event_exists(self) -> None:
        watcher = mock.Mock()
        watcher.sync_once.return_value = 0
        watcher.state = {"canonical": None}
        actions = mock.Mock()
        with (
            mock.patch("publisher.JsonRpc", return_value=mock.Mock()),
            mock.patch("publisher.ReleaseActions", return_value=actions),
            mock.patch("publisher.ReleaseWatcher", return_value=watcher),
        ):
            publisher._run(self.config(), once=True)
        watcher.sync_once.assert_called_once_with()
        actions.apply.assert_called_once_with(None)

    def test_one_shot_reconciles_the_existing_canonical_release(self) -> None:
        event = publisher.ReleaseEvent(
            1,
            2,
            hash32("canonical"),
            1,
            publisher.ZERO_DIGEST,
            "https://example.com/release.tar",
            5,
            hash32("block-5"),
            hash32("tx-5"),
            0,
            0,
        )
        watcher = mock.Mock()
        watcher.sync_once.return_value = 0
        watcher.state = {"canonical": event.to_dict()}
        actions = mock.Mock()
        with (
            mock.patch("publisher.JsonRpc", return_value=mock.Mock()),
            mock.patch("publisher.ReleaseActions", return_value=actions),
            mock.patch("publisher.ReleaseWatcher", return_value=watcher),
        ):
            publisher._run(self.config(), once=True)
        actions.apply.assert_called_once_with(event)

    def test_runtime_state_and_git_home_must_be_private_real_directories(self) -> None:
        self.state.mkdir(mode=0o777)
        self.state.chmod(0o777)
        lock = publisher._acquire_lock(self.config())
        try:
            self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)
        finally:
            os.close(lock)

        external = self.root / "external-home"
        external.mkdir()
        (self.state / "git-home").symlink_to(external, target_is_directory=True)
        with self.assertRaises(publisher.PublisherError):
            publisher.ReleaseActions(self.config())

    def test_confirmed_deep_reorg_rescans_and_rolls_back(self) -> None:
        rpc = FakeRpc(10)
        digest_a = hash32("release-a")
        rpc.log_values = [
            event_log(1, digest_a, publisher.ZERO_DIGEST, "https://example.com/a.zip", 5, rpc.hashes[5])
        ]
        applier = FakeApplier()
        watcher = publisher.ReleaseWatcher(self.config(), rpc, applier)
        watcher.sync_once()
        self.assertEqual(applier.applied[-1].digest, digest_a)  # type: ignore[union-attr]

        for number in range(5, 9):
            rpc.hashes[number] = hash32(f"block-{number}-b")
        digest_b = hash32("release-b")
        rpc.log_values = [
            event_log(1, digest_b, publisher.ZERO_DIGEST, "https://example.com/b.zip", 6, rpc.hashes[6])
        ]
        watcher.sync_once()
        self.assertEqual(applier.applied[-1].digest, digest_b)  # type: ignore[union-attr]

        for number in range(6, 9):
            rpc.hashes[number] = hash32(f"block-{number}-c")
        rpc.log_values = []
        watcher.sync_once()
        self.assertIsNone(applier.applied[-1])

    def test_lagging_head_cannot_roll_back_an_applied_release(self) -> None:
        rpc = FakeRpc(10)
        digest = hash32("release-before-provider-lag")
        rpc.log_values = [
            event_log(
                1,
                digest,
                publisher.ZERO_DIGEST,
                "https://example.com/release.tar",
                5,
                rpc.hashes[5],
            )
        ]
        applier = FakeApplier()
        watcher = publisher.ReleaseWatcher(self.config(), rpc, applier)
        watcher.sync_once()
        self.assertEqual(applier.applied[-1].digest, digest)  # type: ignore[union-attr]

        rpc.head_value = 6
        self.assertEqual(watcher.sync_once(), 0)
        self.assertEqual(len(applier.applied), 1)

    def test_sequence_break_fails_closed(self) -> None:
        rpc = FakeRpc(10)
        rpc.log_values = [
            event_log(2, hash32("bad"), publisher.ZERO_DIGEST, "https://example.com/bad.zip", 5, rpc.hashes[5])
        ]
        watcher = publisher.ReleaseWatcher(self.config(), rpc, FakeApplier())
        with self.assertRaises(publisher.PublisherError):
            watcher.sync_once()

        wrong_address = event_log(
            1,
            hash32("wrong-address"),
            publisher.ZERO_DIGEST,
            "https://example.com/release.tar",
            5,
            rpc.hashes[5],
        )
        wrong_address["address"] = "0x" + "22" * 20
        rpc.log_values = [wrong_address]
        with self.assertRaises(publisher.RpcError):
            publisher.ReleaseWatcher(self.config(), rpc, FakeApplier()).sync_once()


if __name__ == "__main__":
    unittest.main()
