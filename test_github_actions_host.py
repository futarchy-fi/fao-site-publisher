from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import github_actions_host as host


class StateBranchTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.remote = self.root / "remote.git"
        subprocess.run(
            ["/usr/bin/git", "init", "-q", "--bare", str(self.remote)], check=True
        )
        self.environment = host._git_environment(self.root / "git-home")
        self.state_key = bytes(range(32))
        self.identity = {
            "version": 1,
            "source_repository": host.SOURCE_REPOSITORY,
            "state_repository": host.STATE_REPOSITORY,
            "target_remote": host.TARGET_REMOTE,
            "chain_id": 11155111,
            "strategy_address": "0x" + "11" * 20,
            "start_block": 7,
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def state(self, name: str, initialize: bool) -> host.StateBranch:
        state = host.StateBranch(
            self.root / name,
            str(self.remote),
            self.environment,
            self.state_key,
        )
        state.restore(initialize)
        state.bind(self.identity)
        return state

    def populate(self, state: host.StateBranch, marker: str = "one") -> None:
        genesis = state.path / "trees" / "genesis"
        genesis.mkdir(parents=True, exist_ok=True)
        (genesis / "index.html").write_text("genesis", encoding="utf-8")
        cursor = state.path / "cursor.json"
        cursor.write_text(json.dumps({"marker": marker}), encoding="utf-8")
        os.chmod(cursor, 0o600)
        digest = "ab" * 32
        archives = state.path / "archives"
        archives.mkdir(exist_ok=True)
        (archives / f"{digest}.archive").write_bytes(b"cached archive")
        cached = state.path / "trees" / digest
        cached.mkdir(exist_ok=True)
        (cached / "index.html").write_text("cached tree", encoding="utf-8")

    def test_absent_state_requires_explicit_initialization(self) -> None:
        state = host.StateBranch(
            self.root / "missing",
            str(self.remote),
            self.environment,
            self.state_key,
        )
        with self.assertRaisesRegex(host.HostError, "explicit workflow_dispatch"):
            state.restore(False)
        self.assertTrue(host._initialize_requested("true", "workflow_dispatch"))
        with self.assertRaisesRegex(host.HostError, "only through workflow_dispatch"):
            host._initialize_requested("true", "schedule")

    def test_save_is_one_root_commit_and_restore_is_complete(self) -> None:
        first = self.state("first", True)
        self.populate(first)
        genesis = first.path / "trees" / "genesis"
        (genesis / ".gitattributes").write_text("payload.txt ident\n", encoding="utf-8")
        (genesis / "payload.txt").write_text("$Id$\n", encoding="utf-8")
        (first.path / "publisher.lock").write_text("ephemeral", encoding="utf-8")
        (first.path / "git-home").mkdir()
        host._remove_ephemeral_state(first.path)
        commit = first.save()

        raw = subprocess.run(
            ["/usr/bin/git", "--git-dir", str(self.remote), "cat-file", "-p", commit],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout
        self.assertFalse(any(line.startswith("parent ") for line in raw.splitlines()))
        self.assertEqual(
            subprocess.run(
                [
                    "/usr/bin/git",
                    "--git-dir",
                    str(self.remote),
                    "rev-list",
                    "--count",
                    host.STATE_REF,
                ],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout.strip(),
            "1",
        )
        tree = subprocess.run(
            [
                "/usr/bin/git",
                "--git-dir",
                str(self.remote),
                "ls-tree",
                "-r",
                "--name-only",
                host.STATE_REF,
            ],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.splitlines()
        self.assertIn(host.STATE_MAC, tree)
        self.assertNotIn("publisher.lock", tree)
        self.assertFalse(any(path.startswith("git-home/") for path in tree))

        restored = self.state("restored", False)
        self.assertEqual(
            (restored.path / "trees" / "genesis" / "index.html").read_text(),
            "genesis",
        )
        self.assertEqual(
            (restored.path / "trees" / "genesis" / "payload.txt").read_text(),
            "$Id$\n",
        )
        self.assertEqual(
            stat_mode(restored.path / "cursor.json") & 0o077,
            0,
        )
        self.assertEqual(restored.save(), commit)

    def test_force_with_lease_rejects_a_stale_writer(self) -> None:
        initial = self.state("initial", True)
        self.populate(initial)
        initial.save()
        first = self.state("writer-one", False)
        second = self.state("writer-two", False)
        self.populate(first, "writer-one")
        self.populate(second, "writer-two")
        first.save()
        with self.assertRaisesRegex(host.HostError, "command failed"):
            second.save()

    def test_restore_rejects_state_history_with_a_parent(self) -> None:
        initial = self.state("initial-parent", True)
        self.populate(initial)
        root = initial.save()
        tree = subprocess.run(
            [
                "/usr/bin/git",
                "--git-dir",
                str(self.remote),
                "rev-parse",
                f"{root}^{{tree}}",
            ],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        child = subprocess.run(
            [
                "/usr/bin/git",
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "--git-dir",
                str(self.remote),
                "commit-tree",
                tree,
                "-p",
                root,
            ],
            check=True,
            input="bad history\n",
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        subprocess.run(
            [
                "/usr/bin/git",
                "--git-dir",
                str(self.remote),
                "update-ref",
                host.STATE_REF,
                child,
                root,
            ],
            check=True,
        )
        restored = host.StateBranch(
            self.root / "parented",
            str(self.remote),
            self.environment,
            self.state_key,
        )
        with self.assertRaisesRegex(host.HostError, "one root commit"):
            restored.restore(False)

    def test_hmac_rejects_tree_cache_cursor_genesis_mode_and_mac_tampering(self) -> None:
        initial = self.state("authenticated", True)
        self.populate(initial)
        authentic = initial.save()
        digest = "ab" * 32

        def write(path: Path, value: bytes) -> None:
            path.write_bytes(value)

        tampering = {
            "release tree": lambda path: write(
                path / "trees" / digest / "index.html", b"forged tree"
            ),
            "archive cache": lambda path: write(
                path / "archives" / f"{digest}.archive", b"forged archive"
            ),
            "cursor": lambda path: write(path / "cursor.json", b"{}"),
            "genesis": lambda path: write(
                path / "trees" / "genesis" / "index.html", b"forged genesis"
            ),
            "path": lambda path: (path / "trees" / digest / "index.html").rename(
                path / "trees" / digest / "renamed.html"
            ),
            "mode": lambda path: os.chmod(path / "cursor.json", 0o700),
            "MAC": lambda path: write(
                path / host.STATE_MAC, b"hmac-sha256-v1:" + (b"0" * 64) + b"\n"
            ),
            "MAC mode": lambda path: os.chmod(path / host.STATE_MAC, 0o755),
            "missing MAC": lambda path: (path / host.STATE_MAC).unlink(),
        }
        for index, (label, tamper) in enumerate(tampering.items()):
            with self.subTest(label=label):
                subprocess.run(
                    [
                        "/usr/bin/git",
                        "--git-dir",
                        str(self.remote),
                        "update-ref",
                        host.STATE_REF,
                        authentic,
                    ],
                    check=True,
                )
                forged = self.state(f"forge-{index}", False)
                tamper(forged.path)
                self._push_forged_root(forged)
                rejected = host.StateBranch(
                    self.root / f"rejected-{index}",
                    str(self.remote),
                    self.environment,
                    self.state_key,
                )
                with self.assertRaisesRegex(
                    host.HostError,
                    "HMAC verification failed|cannot read publisher-state HMAC|HMAC file is malformed",
                ):
                    rejected.restore(False)

    def test_older_authentic_state_can_be_replayed_but_wrong_key_cannot(self) -> None:
        state = self.state("replay-initial", True)
        self.populate(state, "old")
        old = state.save()
        self.populate(state, "new")
        new = state.save()
        self.assertNotEqual(old, new)
        subprocess.run(
            [
                "/usr/bin/git",
                "--git-dir",
                str(self.remote),
                "update-ref",
                host.STATE_REF,
                old,
                new,
            ],
            check=True,
        )
        replayed = self.state("replayed", False)
        self.assertEqual(json.loads((replayed.path / "cursor.json").read_text())["marker"], "old")

        wrong_key = host.StateBranch(
            self.root / "wrong-key",
            str(self.remote),
            self.environment,
            b"x" * 32,
        )
        with self.assertRaisesRegex(host.HostError, "HMAC verification failed"):
            wrong_key.restore(False)

    def test_state_hmac_key_requires_canonical_base64_and_32_bytes(self) -> None:
        encoded = host.base64.b64encode(self.state_key).decode()
        self.assertEqual(host._decode_state_key(encoded), self.state_key)
        for invalid in ("not base64!", host.base64.b64encode(b"short").decode()):
            with self.assertRaises(host.HostError):
                host._decode_state_key(invalid)

    def test_publisher_child_does_not_inherit_credentials_or_rpc_urls(self) -> None:
        privileged = (
            "GITHUB_TOKEN",
            "FAO_GOVERNED_SITE_DEPLOY_KEY",
            "FAO_PUBLISHER_STATE_DEPLOY_KEY",
            "FAO_PUBLISHER_STATE_HMAC_KEY",
            "FAO_RPC_URL",
            "FAO_WITNESS_RPC_URL",
        )
        source = {name: "sensitive" for name in privileged}
        source["SAFE"] = "kept"
        child = host._publisher_child_environment(source)
        self.assertEqual(child, {"SAFE": "kept"})

    def _push_forged_root(self, state: host.StateBranch) -> str:
        tree = state._index_exact_tree()
        environment = dict(self.environment)
        environment.update(
            {
                "GIT_AUTHOR_NAME": "Attacker",
                "GIT_AUTHOR_EMAIL": "attacker@example.invalid",
                "GIT_COMMITTER_NAME": "Attacker",
                "GIT_COMMITTER_EMAIL": "attacker@example.invalid",
            }
        )
        commit = host._git(
            state.path,
            "commit-tree",
            tree,
            env=environment,
            input_text="forged state\n",
        ).stdout.strip()
        host._git(
            state.path,
            "push",
            "--force",
            "origin",
            f"{commit}:{host.STATE_REF}",
            env=self.environment,
        )
        return commit

    def test_workflow_has_no_action_dependencies_and_is_fail_closed(self) -> None:
        self.assertEqual(
            host.STATE_REMOTE,
            "git@github.com:futarchy-fi/fao-site-publisher-state.git",
        )
        self.assertNotEqual(host.STATE_REMOTE, host.TARGET_REMOTE)
        workflow = (Path(__file__).parent / ".github/workflows/publish.yml").read_text()
        self.assertNotIn("uses:", workflow)
        self.assertIn('cron: "*/5 * * * *"', workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("vars.PUBLISHER_ENABLED == 'true' ||", workflow)
        self.assertIn(
            "github.event_name == 'workflow_dispatch' && inputs.initialize", workflow
        )
        self.assertIn("permissions: {}", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertIn("--no-tags --depth=1", workflow)
        self.assertIn('"$GITHUB_SHA"', workflow)
        self.assertNotIn("GITHUB_TOKEN", workflow)
        final_step = workflow.index("- name: Run publisher host once")
        self.assertGreater(workflow.index("FAO_RPC_URL:"), final_step)
        self.assertGreater(workflow.index("FAO_GOVERNED_SITE_DEPLOY_KEY:"), final_step)
        self.assertGreater(workflow.index("FAO_PUBLISHER_STATE_DEPLOY_KEY:"), final_step)
        self.assertGreater(workflow.index("FAO_PUBLISHER_STATE_HMAC_KEY:"), final_step)
        self.assertNotIn("CLOUDFLARE", workflow.upper())


def stat_mode(path: Path) -> int:
    return path.stat().st_mode


if __name__ == "__main__":
    unittest.main()
