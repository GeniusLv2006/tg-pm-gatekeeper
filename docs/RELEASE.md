# Release and deployment policy

This document is the authoritative workflow for changing, publishing, and deploying this project.
It keeps high-risk changes reviewable without forcing the full pull-request ceremony onto changes
that cannot affect runtime behavior.

## 1. Classify the change

### Direct-to-main changes

A maintainer may commit and push directly to `main` only when every changed file is limited to:

- prose documentation that does not redefine a security boundary;
- tests or test fixtures that do not change production dependencies;
- comments, formatting, spelling, or repository metadata;
- `.gitignore` entries that do not hide source, configuration examples, or audit evidence.

Direct changes still require a focused diff review and a Conventional Commit. GitHub Actions runs
on the resulting `main` commit and must be checked before any related work continues.

### Pull-request changes

A pull request is required when any change affects or could affect:

- `src/` runtime behavior or Telegram API actions;
- spam rules, challenges, allowlisting, quarantine, or review decisions;
- stored data, schema migrations, retention, encryption, authentication, or logging;
- networking, Unix sockets, SSH behavior, Docker isolation, or host permissions;
- executable files under `scripts/` or `deploy/`;
- dependencies, pinned images, GitHub Actions, build configuration, or deployment commands;
- `SECURITY.md` or a documented security/privacy guarantee.

When classification is uncertain, use a pull request.

## 2. Validate locally

For prose-only direct changes:

```shell
git diff --check
```

For tests, executable scripts, configuration, or runtime changes:

```shell
PYTHONPATH=src .venv/bin/python -m unittest discover -v
PYTHONPATH=src .venv/bin/python -m compileall -q src tests scripts
git diff --check
```

Also run syntax or behavior checks specific to changed executable files. Never use real Telegram
identities, messages, credentials, URLs, databases, or logs as test data.

## 3. Publish

### Direct path

1. Confirm the worktree contains only eligible low-risk changes.
2. Commit on `main` with a Conventional Commit.
3. Push `main` over SSH.
4. Confirm the `test` and `secrets` GitHub Actions jobs pass.

### Pull-request path

1. Branch from current `main` using a narrow `codex/<description>` name.
2. Commit only the intended scope with a Conventional Commit.
3. Push the branch over SSH.
4. Open a ready-for-review PR. Use Draft only when the implementation is genuinely incomplete.
5. For ordinary changes, enable Squash auto-merge once the scope has been reviewed; GitHub merges
   only after the `test` and `secrets` jobs pass. If auto-merge is unavailable, wait for both jobs
   and merge once. Security-sensitive changes require an explicit human review before merge.
7. Keep the squash title in the form `<conventional title> (#<PR>)`.
8. Delete the merged branch and fast-forward local `main`.

Do not bypass a failing check. Test count alone is not a reason to remove coverage; execution time,
signal quality, and maintenance cost are the relevant measures.

## 4. Decide whether deployment is required

No service deployment is required for changes limited to documentation, tests, `.gitignore`, or
repository metadata. Synchronizing the server checkout is optional and must not restart the healthy
container.

Deploy when the merged commit changes runtime code, configuration consumed by the service, Docker
or dependency inputs, database behavior, or an operator workflow that must exist on the host.

Rebuild the image when any of these change:

- `src/`, `Dockerfile`, `compose.yaml`, `pyproject.toml`;
- `requirements.txt` or `requirements-build.txt`.

Host-only scripts and documentation may require a repository pull but not an image rebuild.

## 5. Deploy and verify

Follow [deployment.md](deployment.md) for host preparation. For every live update:

1. Verify the server checkout is clean, record its current commit, and confirm the container is
   healthy.
2. Confirm the service mode before changing anything. Deployment must not silently switch from
   `observe` to `enforce`.
3. Create a remote-only temporary backup only for schema, migration, or persistent-state changes.
4. Fast-forward the server checkout to the reviewed `main` commit.
5. Rebuild and recreate the container only when the file classification above requires it.
6. Verify the exact deployed commit, container health, restart count, mode, redacted status, logs,
   secret permissions, Socket permissions, and absence of unexpected port mappings.
7. Remove temporary backups and tunnels after successful verification.

If verification fails, stop further actions. Restore the prior image or commit only after preserving
the failed state needed for diagnosis; never discard user data with a destructive Git or Docker
command.

## 6. Local operator notes

Machine-specific host aliases, paths, preferred commands, and maintenance notes belong in the
repository-root file `RELEASE.local.md`. That file is ignored by Git and must never contain API
credentials, Telegram Session values, HMAC keys, raw user identifiers, message content, or copies of
the runtime database.

The tracked policy and deployment documentation must remain usable without `RELEASE.local.md`.
