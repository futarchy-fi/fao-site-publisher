# FAO governed-site publisher

This daemon watches the configured `SXArbitrationExecutionStrategy` for the
confirmed `SiteReleaseSelected` event, verifies the event's raw artifact
Keccak-256, and replaces the governed repository tree. It never imports,
builds, sources, or executes release files.

The configured chain ID, strategy address, and deployment start block are part
of the durable cursor identity. Two RPC endpoints on different provider
hostnames must agree on block hashes and complete log sets; publication uses the
lower reported head so one endpoint can stop liveness but cannot invent a
release alone.

## Artifact contract

- `artifactURI` is either `https://...` or `ipfs://<cid>/<optional-path>`.
  IPFS is fetched through the configured HTTPS gateway. Redirects must also end
  at a public HTTPS address. `http_timeout` bounds both socket waits and the
  overall artifact download so a slow endpoint cannot hold the watcher forever.
- `artifactDigest` is `keccak256` of the exact downloaded archive bytes.
- The archive is an uncompressed tar. Producers should normalize file order,
  ownership, modes, and timestamps so the exact archive bytes are reproducible;
  the publisher hashes the downloaded bytes without normalization.
- The archive has exactly one top-level directory. That directory is stripped;
  its regular files become the repository root. Directories are structural and
  empty directories are not release state. A regular file's executable bit is
  preserved as Git mode `100755` or `100644`; all other archive mode bits are
  normalized.
- Symlinks, hardlinks, devices, FIFOs, absolute/traversing paths, duplicate or
  case-colliding paths, `.git`, oversize archives/files/trees, and excessive
  file or directory-entry counts are rejected. The configured limits must not
  exceed the target host's and deployment platform's limits.
- Everything else is governed release state, including `.github/workflows/`,
  `_worker.js`, `functions/`, build configuration, and server code. None of it
  is imported or executed by the publisher.

Create a reproducible archive from one exact Git commit, then encode the
corresponding `SiteRelease` payload:

```sh
python3 release_artifact.py bundle --repo ../fao-governed-site --ref HEAD \
  --archive dist/site.tar --out dist/site.json
python3 release_artifact.py payload --archive dist/site.tar \
  --uri ipfs://bafy.../site.tar --nonce 1 \
  --expected-current-digest 0x0000000000000000000000000000000000000000000000000000000000000000 \
  --out dist/site.payload.json
```

The bundle command resolves the ref once, uses Git's tar writer with a pinned
umask, validates the result with the publisher's own archive rules, and hashes
the exact archive bytes with Ethereum Keccak-256. The payload command repeats
archive validation and emits the exact `abi.encode(SiteRelease)` bytes and
their Keccak-256 hash.

The worktree is replaced exactly with the validated regular-file tree while
its existing `.git` control path is preserved. A private cache allows a
confirmed deep-reorg rescan to restore the canonical prior release (or the
captured genesis worktree). A state-directory lock prevents two publisher
processes from racing the cursor or worktree.

## Run

Use Python 3.9+ in a small virtual environment:

```sh
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.linux-x86_64.txt
cp config.example.json /etc/fao-site-publisher.json
chmod 600 /etc/fao-site-publisher.json
.venv/bin/python publisher.py --config /etc/fao-site-publisher.json --once
.venv/bin/python publisher.py --config /etc/fao-site-publisher.json
```

On the intended Linux x86-64 publisher host, install
`requirements.linux-x86_64.txt` with pip's `--require-hashes`; it pins the
reviewed CPython ABI3 wheel. `requirements.txt` is the exact-version portable
development fallback.

Replace the example's zero strategy address before running; zero addresses are
rejected deliberately. Configure the primary and witness RPC endpoints through
independent providers; two hostnames operated by one provider do not provide
the intended fault isolation.

The config and state directory are trusted operator data and must be outside
the governed worktree. The daemon pins each artifact HTTPS connection to the
public IP address it validated and refuses private/link-local artifact hosts;
also place it behind an egress policy allowing only the two RPC endpoints,
public HTTPS artifact hosts, and GitHub.

## Git publication and deployment

Git commands have a fixed repository, remote (`origin`), target (`main`),
disabled hooks, no artifact-derived command line, and an isolated HOME. The
remote must be exactly `git@github.com:futarchy-fi/fao-governed-site.git`.
Publication requires both `git_commit` and `git_push`, with `git_ssh`
configured as an absolute trusted wrapper outside the worktree and state tree.
The wrapper must use a write-enabled SSH deploy key attached only to this
repository, pin GitHub's host key, and disable ambient SSH configuration and
agent identities. A deploy key can push workflow-file changes without holding
Actions or repository-administration API authority.
`git-ssh.example` is the intended minimal wrapper; install a reviewed copy at
the absolute `git_ssh` path with its key and `known_hosts` files kept outside
the governed repository and publisher state tree.

GitHub Actions must remain disabled at the repository-settings level. This is
an operational invariant, not an artifact-content veto: accepted releases may
replace workflow files, but pushing them must not execute them in the
publisher's credential domain.
Before daemon activation, verify that setting through the GitHub API, then use
the deploy key to push and delete a temporary branch containing a harmless
`.github/workflows/` file. This proves that workflow paths are not a credential
veto while confirming that no workflow run starts.

Connect the repository to the Pages project through the deployment platform's
Git integration. Build configuration, Functions, Workers, and other accepted
site code may execute there after the commit lands; that downstream execution
is part of governing the whole site. The publisher intentionally has no
Cloudflare credential and never invokes Wrangler, npm, a shell, or release
build commands from governed content.

## GitHub Actions one-shot host

`.github/workflows/publish.yml` is the minimal hosted alternative to the
daemon. It has no third-party Actions dependencies: each run fetches exactly
`GITHUB_SHA`, installs the hash-pinned Linux wheel, reconstructs the complete
publisher state, clones the governed repository through its SSH deploy key,
and runs `publisher.py --once`. The five-minute schedule and ordinary manual
dispatch are both disabled unless the repository variable `PUBLISHER_ENABLED`
is exactly `true`; the sole exception is an explicit manual initialization.
The authority-bearing job also refuses every ref except `refs/heads/main`.

Before enabling it:

1. After the Sepolia contracts exist, copy `deployment.example.json` to the
   tracked `deployment.json` and replace its zero address and start block with
   the immutable deployed chain values. Until that file exists, even an
   authorized run fails closed before publication. RPC URLs deliberately do
   not belong in that file.
2. Add repository variables `FAO_RPC_URL` and `FAO_WITNESS_RPC_URL` for two
   independent HTTPS providers. The publisher still rejects equal hostnames,
   chain disagreement, block-hash disagreement, or log-set disagreement.
3. Keep publisher Actions restricted to `allowed_actions=local_only` (the
   workflow uses no `uses:` dependencies). Disable GitHub Actions entirely in
   `fao-site-publisher-state` and `fao-governed-site`, verify all three settings
   through the GitHub API with an administrator credential, and then set the
   publisher variable `FAO_TARGET_ACTIONS_DISABLED=true`. The workflow holds no
   target-administration credential, so this variable is an operator
   attestation rather than a live settings check; monitor that setting as a
   security invariant. Accepted releases may still contain workflows because
   they are site state, not publisher code.
4. Keep the authority-bearing repository rules active. In the publisher repo,
   all branches are restricted by ruleset `18810514` and all tags by `18810515`,
   with only `krandder` allowed to bypass. In the separate
   `fao-site-publisher-state` repo, rulesets `18810516`, `18810518`, and
   `18810519` reserve `publisher-state` for deploy-key/`krandder` writes and all
   other branches and tags for `krandder`. Governed `main` ruleset `18810227`
   allows only deploy keys to bypass. GitHub's
   [ruleset API documents `DeployKey` as a bypass actor type](https://docs.github.com/en/rest/repos/rules),
   with a null actor ID. Do not remove these rulesets to activate the host.
5. Create two different unencrypted write deploy keys. Attach the target key
   only to `futarchy-fi/fao-governed-site` and store it as
   `FAO_GOVERNED_SITE_DEPLOY_KEY`. Attach the state key only to the secretless,
   Actions-disabled `futarchy-fi/fao-site-publisher-state` repository and store
   it as `FAO_PUBLISHER_STATE_DEPLOY_KEY`. Both SSH wrappers pin GitHub's Ed25519 host
   key. Target and state clones and pushes are fixed SSH remotes and never use
   the workflow token.
6. Generate at least 32 random bytes in canonical base64 without whitespace,
   for example `openssl rand -base64 32 | tr -d '\n'`, and store it as
   `FAO_PUBLISHER_STATE_HMAC_KEY`. It authenticates every durable state path,
   Git mode, and file byte except the MAC file itself. Never reuse either
   deploy key as this HMAC key.
7. Leave `PUBLISHER_ENABLED` unset or false and manually dispatch once with
   `initialize` checked. After that succeeds, set `PUBLISHER_ENABLED=true`.
   A schedule run cannot create missing state, and initialization refuses to
   overwrite existing state.

`publisher-state` is replaced with a single parentless commit using
`--force-with-lease`. It contains the cursor, deployment identity, genesis
tree, raw artifact cache, and extracted rollback trees. The process lock and
isolated Git HOME are removed before authentication and indexing. The separate
publisher-state deploy key writes to the separate state repository through
ruleset `18810518`; the workflow token has no repository permissions and is
never used for state. A compromised state key therefore has no path to a
secret-bearing workflow; the HMAC still limits it to liveness attacks. A valid
older authenticated root may be replayed, but modified cursor, genesis, cache,
tree, path, mode, or content cannot be forged without the HMAC secret.

Publication ordering is deliberately asymmetric: the publisher first pushes
the governed `main`, then the host saves state only after the one-shot exits
successfully. A crash before the target push changes nothing. A crash after the
target push but before state save leaves the old cursor, so the next run
replays the accepted release; the exact-tree commit is idempotent and repairs
the cursor. State can therefore lag the site, but cannot claim a release was
published when it was not. The concurrency group serializes normal runs and
the state branch lease rejects any stale external writer. Every hosted run
also reapplies the current canonical release (or genesis) to the target exact
tree, so direct drift is committed and pushed back to the governed result even
when no new chain event exists. This is reconciliation, not a content veto:
accepted workflows, server code, and every other governed file remain valid
site state. RPC variables and all three secrets are scoped only to the final
host step, after the exact checkout and hash-pinned dependency install.

Do not place RPC credentials, Git credentials, config, publisher code, or state
under the governed repository. Run the daemon and
SSH wrapper as a dedicated OS user with no access to other repositories
or deployment accounts. Back up the private state directory: it contains the
durable cursor, verified archive cache, and canonical genesis rollback tree.

## Tests

```sh
.venv/bin/python -m unittest -v
```
