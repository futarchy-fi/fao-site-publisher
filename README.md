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
  its regular files become the repository root. Directories are structural;
  empty directories and archive modes are not release state.
- Symlinks, hardlinks, devices, FIFOs, absolute/traversing paths, duplicate or
  case-colliding paths, `.git`, oversize archives/files/trees, and excessive
  file or directory-entry counts are rejected. The configured limits must not
  exceed the target host's and deployment platform's limits.
- Everything else is governed release state, including `.github/workflows/`,
  `_worker.js`, `functions/`, build configuration, and server code. None of it
  is imported or executed by the publisher.

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

Do not place RPC credentials, Git credentials, config, publisher code, or state
under the governed repository. Run the daemon and
SSH wrapper as a dedicated OS user with no access to other repositories
or deployment accounts. Back up the private state directory: it contains the
durable cursor, verified archive cache, and canonical genesis rollback tree.

## Tests

```sh
.venv/bin/python -m unittest -v
```
