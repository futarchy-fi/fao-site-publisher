from __future__ import annotations

import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

from Crypto.Hash import keccak

import publisher
import release_artifact


ZERO_DIGEST = "0x" + "00" * 32


class ReleaseArtifactTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "site"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Test")
        self.git("config", "user.email", "test@example.invalid")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git(self, *arguments: str) -> str:
        return subprocess.run(
            ["/usr/bin/git", "-C", str(self.repo), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout.strip()

    def commit_site(self) -> str:
        (self.repo / "index.html").write_text("committed\n", encoding="utf-8")
        script = self.repo / "deploy.sh"
        script.write_text("#!/bin/sh\n", encoding="utf-8")
        script.chmod(0o755)
        self.git("add", "index.html", "deploy.sh")
        self.git("commit", "-q", "-m", "site")
        return self.git("rev-parse", "HEAD")

    def test_bundle_is_reproducible_and_uses_only_the_resolved_commit(self) -> None:
        commit = self.commit_site()
        (self.repo / "index.html").write_text("dirty\n", encoding="utf-8")
        (self.repo / "untracked.txt").write_text("ignored\n", encoding="utf-8")

        first_archive = self.root / "first.tar"
        first_json = self.root / "first.json"
        second_archive = self.root / "second.tar"
        second_json = self.root / "second.json"
        self.assertEqual(
            release_artifact.main(
                [
                    "bundle",
                    "--repo",
                    str(self.repo),
                    "--ref",
                    "HEAD",
                    "--archive",
                    str(first_archive),
                    "--out",
                    str(first_json),
                ]
            ),
            0,
        )
        first = json.loads(first_json.read_text())
        second = release_artifact.create_bundle(
            self.repo, commit, second_archive, second_json
        )

        self.assertEqual(first_archive.read_bytes(), second_archive.read_bytes())
        self.assertEqual(first, second)
        self.assertEqual(
            first,
            {
                "schemaVersion": 1,
                "sourceCommit": commit,
                "archiveBytes": first_archive.stat().st_size,
                "artifactDigest": publisher._keccak_file(first_archive),
            },
        )
        self.assertEqual(json.loads(first_json.read_text()), first)
        self.assertEqual(
            first_json.read_bytes(),
            (json.dumps(first, sort_keys=True, separators=(",", ":")) + "\n").encode(),
        )
        with tarfile.open(first_archive, "r:") as archive:
            self.assertEqual(
                archive.extractfile("release/index.html").read(), b"committed\n"
            )
            with self.assertRaises(KeyError):
                archive.getmember("release/untracked.txt")
            self.assertEqual(archive.getmember("release/index.html").mode, 0o644)
            self.assertEqual(archive.getmember("release/deploy.sh").mode, 0o755)

    def test_bundle_rejects_a_committed_symlink(self) -> None:
        self.commit_site()
        os.symlink("index.html", self.repo / "linked.html")
        self.git("add", "linked.html")
        self.git("commit", "-q", "-m", "symlink")

        archive = self.root / "unsafe.tar"
        out = self.root / "unsafe.json"
        with self.assertRaisesRegex(publisher.UnsafeArtifact, "links and special"):
            release_artifact.create_bundle(self.repo, "HEAD", archive, out)
        self.assertFalse(archive.exists())
        self.assertFalse(out.exists())

    def test_payload_matches_single_dynamic_tuple_abi_and_exact_archive_hash(self) -> None:
        self.commit_site()
        archive = self.root / "site.tar"
        release_artifact.create_bundle(
            self.repo, "HEAD", archive, self.root / "site.json"
        )
        uri = "ipfs://bafy123/site.tar"
        out = self.root / "payload.json"
        self.assertEqual(
            release_artifact.main(
                [
                    "payload",
                    "--archive",
                    str(archive),
                    "--uri",
                    uri,
                    "--nonce",
                    "7",
                    "--expected-current-digest",
                    ZERO_DIGEST,
                    "--out",
                    str(out),
                ]
            ),
            0,
        )
        result = json.loads(out.read_text())

        payload = bytes.fromhex(result["executionPayload"][2:])
        uri_bytes = uri.encode()
        self.assertEqual(int.from_bytes(payload[0:32], "big"), 32)
        self.assertEqual(int.from_bytes(payload[32:64], "big"), 7)
        self.assertEqual(payload[64:96], bytes(32))
        self.assertEqual(payload[96:128], bytes.fromhex(result["artifactDigest"][2:]))
        self.assertEqual(int.from_bytes(payload[128:160], "big"), 128)
        self.assertEqual(int.from_bytes(payload[160:192], "big"), len(uri_bytes))
        self.assertEqual(payload[192 : 192 + len(uri_bytes)], uri_bytes)
        self.assertFalse(any(payload[192 + len(uri_bytes) :]))

        payload_hash = keccak.new(digest_bits=256)
        payload_hash.update(payload)
        self.assertEqual(result["executionPayloadHash"], "0x" + payload_hash.hexdigest())
        self.assertEqual(result["artifactDigest"], publisher._keccak_file(archive))
        self.assertEqual(
            set(result),
            {
                "schemaVersion",
                "nonce",
                "expectedCurrentDigest",
                "artifactDigest",
                "artifactURI",
                "executionPayload",
                "executionPayloadHash",
            },
        )
        self.assertEqual(
            out.read_bytes(),
            (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode(),
        )

    def test_payload_rejects_invalid_fields_and_unsafe_archive(self) -> None:
        self.commit_site()
        archive = self.root / "site.tar"
        release_artifact.create_bundle(
            self.repo, "HEAD", archive, self.root / "site.json"
        )
        out = self.root / "payload.json"
        for nonce, digest, uri in (
            (0, ZERO_DIGEST, "ipfs://bafy123/site.tar"),
            (1 << 256, ZERO_DIGEST, "ipfs://bafy123/site.tar"),
            (1, "0x12", "ipfs://bafy123/site.tar"),
            (1, ZERO_DIGEST, "file:///tmp/site.tar"),
            (1, ZERO_DIGEST, "https://example.com/" + "x" * 240),
        ):
            with self.subTest(nonce=nonce, digest=digest, uri=uri), self.assertRaises(
                release_artifact.ArtifactError
            ):
                release_artifact.create_payload(archive, uri, nonce, digest, out)

        unsafe = self.root / "unsafe.tar"
        with tarfile.open(unsafe, "w") as tar:
            root = tarfile.TarInfo("release")
            root.type = tarfile.DIRTYPE
            tar.addfile(root)
            member = tarfile.TarInfo("release/index.html")
            member.size = 2
            tar.addfile(member, io.BytesIO(b"ok"))
            link = tarfile.TarInfo("release/link")
            link.type = tarfile.SYMTYPE
            link.linkname = "index.html"
            tar.addfile(link)
        with self.assertRaisesRegex(publisher.UnsafeArtifact, "links and special"):
            release_artifact.create_payload(
                unsafe, "ipfs://bafy123/site.tar", 1, ZERO_DIGEST, out
            )

        linked_archive = self.root / "linked.tar"
        linked_archive.symlink_to(archive)
        with self.assertRaisesRegex(publisher.UnsafeArtifact, "bounded regular file"):
            release_artifact.create_payload(
                linked_archive, "ipfs://bafy123/site.tar", 1, ZERO_DIGEST, out
            )


if __name__ == "__main__":
    unittest.main()
