from __future__ import annotations

import io
import json
import os
import stat
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

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
                "gitVersion": self.git("--version"),
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

    def test_bundle_preserves_committed_parent_without_shallow_decorations(self) -> None:
        parent = self.commit_site()
        (self.repo / ".gitattributes").write_text(
            "version.txt export-subst\n", encoding="utf-8"
        )
        (self.repo / "version.txt").write_text(
            "P=$Format:%P$ D=$Format:%D$\n", encoding="utf-8"
        )
        self.git("add", ".gitattributes", "version.txt")
        self.git("commit", "-q", "-m", "version metadata")

        archive = self.root / "parents.tar"
        release_artifact.create_bundle(
            self.repo, "HEAD", archive, self.root / "parents.json"
        )
        with tarfile.open(archive, "r:") as tar:
            version = tar.extractfile("release/version.txt").read().decode()
        self.assertEqual(version, f"P={parent} D=\n")
        self.assertNotIn("grafted", version)

    def test_bundle_rejects_a_committed_gitlink(self) -> None:
        target = self.commit_site()
        self.git("update-index", "--add", "--cacheinfo", f"160000,{target},component")
        self.git("commit", "-q", "-m", "gitlink")

        with self.assertRaisesRegex(publisher.UnsafeArtifact, "links and special"):
            release_artifact.create_bundle(
                self.repo,
                "HEAD",
                self.root / "gitlink.tar",
                self.root / "gitlink.json",
            )

    def test_bundle_is_hermetic_to_replace_refs_attributes_and_tags(self) -> None:
        self.commit_site()
        (self.repo / ".gitattributes").write_text(
            "version.txt export-subst\n", encoding="utf-8"
        )
        (self.repo / "version.txt").write_text("$Format:%D$\n", encoding="utf-8")
        self.git("add", ".gitattributes", "version.txt")
        self.git("commit", "-q", "-m", "versioned site")
        commit = self.git("rev-parse", "HEAD")

        baseline_archive = self.root / "baseline.tar"
        baseline = release_artifact.create_bundle(
            self.repo, commit, baseline_archive, self.root / "baseline.json"
        )

        def assert_same(name: str) -> None:
            archive = self.root / f"{name}.tar"
            result = release_artifact.create_bundle(
                self.repo, commit, archive, self.root / f"{name}.json"
            )
            self.assertEqual(result["sourceCommit"], commit)
            self.assertEqual(result, baseline)
            self.assertEqual(archive.read_bytes(), baseline_archive.read_bytes())

        info_attributes = self.repo / ".git" / "info" / "attributes"
        info_attributes.write_text("index.html export-ignore\n", encoding="utf-8")
        assert_same("local-attributes")
        ambient_attributes = self.root / "ambient.attributes"
        ambient_attributes.write_text("deploy.sh export-ignore\n", encoding="utf-8")
        with mock.patch.dict(
            os.environ,
            {
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.attributesFile",
                "GIT_CONFIG_VALUE_0": str(ambient_attributes),
            },
        ):
            assert_same("ambient-config")
        self.git("tag", "local-only-tag", commit)
        assert_same("local-tag")
        (self.repo / "index.html").write_text("replacement\n", encoding="utf-8")
        self.git("add", "index.html")
        self.git("commit", "-q", "-m", "replacement site")
        replacement = self.git("rev-parse", "HEAD")
        self.git("replace", commit, replacement)
        assert_same("replacement-ref")

    def test_output_paths_collapse_symlinked_parent_aliases(self) -> None:
        self.commit_site()
        real = self.root / "real"
        real.mkdir()
        alias = self.root / "alias"
        alias.symlink_to(real, target_is_directory=True)

        with self.assertRaisesRegex(release_artifact.ArtifactError, "different files"):
            release_artifact.create_bundle(
                self.repo, "HEAD", real / "shared", alias / "shared"
            )
        self.assertFalse((real / "shared").exists())
        with self.assertRaisesRegex(release_artifact.ArtifactError, "different files"):
            release_artifact.create_bundle(
                self.repo, "HEAD", real / "CaseAlias", real / "casealias"
            )

        archive = real / "site.tar"
        release_artifact.create_bundle(
            self.repo, "HEAD", archive, real / "site.json"
        )
        with self.assertRaisesRegex(release_artifact.ArtifactError, "different files"):
            release_artifact.create_payload(
                archive,
                "ipfs://bafy123/site.tar",
                1,
                ZERO_DIGEST,
                alias / "site.tar",
            )
        with tarfile.open(archive, "r:") as tar:
            self.assertIsNotNone(tar.getmember("release/index.html"))

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

        if hasattr(os, "mkfifo"):
            fifo = self.root / "archive.fifo"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(publisher.UnsafeArtifact, "bounded regular file"):
                release_artifact.create_payload(
                    fifo, "ipfs://bafy123/site.tar", 1, ZERO_DIGEST, out
                )

    def test_archive_staging_bounds_growth_after_fstat(self) -> None:
        archive = self.root / "growing.tar"
        archive.write_bytes(b"12345")
        staged = self.root / "staged"
        staged.mkdir()
        fake_info = SimpleNamespace(st_mode=stat.S_IFREG, st_size=1)
        with mock.patch.object(
            release_artifact.os, "fstat", return_value=fake_info
        ):
            with mock.patch.object(
                release_artifact.ARCHIVE_LIMITS, "max_archive_bytes", 4
            ), self.assertRaisesRegex(
                publisher.UnsafeArtifact, "bounded regular file"
            ):
                release_artifact._stage_archive(archive, staged)

        occupied = self.root / "occupied"
        occupied.mkdir()
        (occupied / "site.tar").write_bytes(b"exists")
        with self.assertRaisesRegex(publisher.UnsafeArtifact, "bounded regular file"):
            release_artifact._stage_archive(archive, occupied)

    def test_payload_validates_and_hashes_one_private_staged_copy(self) -> None:
        self.commit_site()
        archive = self.root / "site.tar"
        release_artifact.create_bundle(
            self.repo, "HEAD", archive, self.root / "site.json"
        )
        expected_digest = publisher._keccak_file(archive)
        validate = release_artifact._validate_archive

        def swap_source_after_validation(path: Path) -> None:
            validate(path)
            archive.write_bytes(b"unvalidated replacement")

        with mock.patch.object(
            release_artifact,
            "_validate_archive",
            side_effect=swap_source_after_validation,
        ):
            result = release_artifact.create_payload(
                archive,
                "ipfs://bafy123/site.tar",
                1,
                ZERO_DIGEST,
                self.root / "payload.json",
            )

        self.assertEqual(result["artifactDigest"], expected_digest)
        self.assertEqual(archive.read_bytes(), b"unvalidated replacement")


if __name__ == "__main__":
    unittest.main()
