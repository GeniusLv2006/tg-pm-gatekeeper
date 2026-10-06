# Maintainer release policy

> [!NOTE]
> This document is for maintainers publishing changes to the repository. You do not need it to install or run Gatekeeper. Use [deployment.md](deployment.md) for installation, updates, and daily operation.

This policy keeps behavior and security changes reviewable while allowing genuinely low-risk edits to move quickly.

## Choose the publication path

| Change | Pull request? | Service deployment? | Image rebuild? |
| --- | --- | --- | --- |
| Prose, spelling, comments, or repository metadata with no boundary change | Optional | No | No |
| Tests or fixtures with no production dependency change | Optional | No | No |
| Runtime behavior under `src/` | Required | Yes | Yes |
| Configuration consumed by the service | Required | Yes | Usually yes |
| Docker, build, or runtime dependencies | Required | Yes | Yes |
| Executable `scripts/` or `deploy/` changes | Required | Pull to the host when operators need them | Only if image inputs also changed |
| Security, privacy, networking, storage, logging, or authentication boundaries | Required | Depends on affected behavior | Depends on affected files |
| License or contribution terms | Required | No | No |

Use a pull request whenever the classification is uncertain.

### Direct-to-main eligibility

A maintainer may commit directly to `main` only when every changed file is limited to:

- prose that does not redefine security, privacy, deployment, or runtime behavior;
- tests or fixtures that do not change production dependencies;
- comments, formatting, spelling, or repository metadata; or
- `.gitignore` entries that do not hide source, configuration examples, or audit evidence.

Review the complete diff and use a Conventional Commit. After pushing, confirm the `test`, `quality`, `dependencies`, `image`, and `secrets` GitHub Actions jobs pass before related work continues.

### Pull requests required

Use a pull request for changes to:

- Telegram actions, spam rules, challenges, trust, quarantine, suppression, or review decisions;
- stored data, migrations, retention, encryption, authentication, or logging;
- networking, Unix sockets, SSH behavior, Docker isolation, or host permissions;
- executable scripts, dependencies, pinned images, CI, or build configuration;
- `SECURITY.md` or any documented security/privacy guarantee; or
- project licensing and contribution terms.

## Validate the change

For a prose-only direct change:

```shell
git diff --check
```

For runtime, configuration, test, executable, Docker, or dependency changes:

```shell
PYTHONPATH=src .venv/bin/python -m unittest discover -v
PYTHONPATH=src .venv/bin/python -m compileall -q src tests scripts
.venv/bin/ruff check src tests scripts
.venv/bin/mypy
shellcheck scripts/*.sh deploy/*.sh
docker build --tag tg-pm-gatekeeper:test .
git diff --check
```

Install `requirements-quality.txt` as described in [CONTRIBUTING.md](../CONTRIBUTING.md) before running Ruff and mypy. Add checks specific to the changed executable or workflow. Test data must not contain real Telegram identities, messages, credentials, URLs, databases, or logs.

## Publish

### Direct path

1. Confirm the worktree contains only eligible low-risk changes.
2. Commit on `main` with a Conventional Commit.
3. Push `main` over SSH.
4. Confirm all GitHub Actions jobs pass.

### Pull-request path

1. Create a narrow branch from current `main` with a change-type prefix such as `fix/`, `feat/`, `docs/`, `refactor/`, `ci/`, or `chore/`.
2. Commit only the intended scope with a Conventional Commit.
3. Push the branch over SSH.
4. Open a ready-for-review PR. Use Draft only while work is genuinely incomplete.
5. Describe behavior, security/privacy impact, licensing impact when applicable, validation, and deployment requirements.
6. For ordinary changes, enable squash auto-merge after review. Security-sensitive changes require explicit human review.
7. Keep the squash title in the form `<conventional title> (#<PR>)`.
8. After merge, delete the branch and fast-forward local `main`.

Never bypass a failing check.

### Dependency updates and scheduled audits

Dependabot opens weekly pull requests for pinned Python requirements, the Docker base image digest, and GitHub Actions. Base image updates are limited to patch releases and digest refreshes of the current Python minor version; moving to a new minor version is a deliberate pull request that also updates `requires-python`. Telethon updates arrive as their own pull requests because a new Telegram API layer can rename or restructure message types and silently change what the screening code sees. Version updates wait seven days after an upstream release before they are proposed; security updates are not delayed. Dependabot pull requests are security-sensitive dependency changes: review the upstream changes and the regenerated hashes, keep the files consistent where a version is pinned in more than one place, and never enable auto-merge for them.

The CI workflow also runs the `dependencies` and `image` jobs every Monday and can be started manually. The `image` job builds the Docker image and scans it with Grype, failing on high or critical vulnerabilities that have a published fix in the base image's operating-system packages or the installed Python packages. A scheduled failure means a newly published advisory affects a pinned dependency or the base image even though no code changed; treat it as a security fix and resolve it through a pull request, usually by updating the pinned version or base image digest. Do not add a Grype ignore rule unless the pull request documents why the finding does not affect Gatekeeper.

## Deploy a merged change

No deployment is needed for changes limited to documentation, tests, license text, source notices, `.gitignore`, or repository metadata. Pulling those changes to the server is optional and must not restart a healthy container.

Deploy when a merged commit changes runtime code, service configuration, Docker or dependency inputs, database behavior, or an operator workflow needed on the host.

Rebuild the image when executable content changes in:

- `src/`, `Dockerfile`, `compose.yaml`, or `pyproject.toml`; or
- `requirements.txt` or `requirements-build.txt`.

Comments, notices, and metadata-only edits in those files do not require a rebuild.

For every live update:

1. Confirm the server checkout is clean; record its commit, container health, and current mode.
2. Create a private server-local backup for migrations or persistent-state changes.
3. Fast-forward the server to the reviewed `main` commit.
4. Rebuild and recreate the container only when required above.
5. Verify the deployed commit, health, restart count, mode, redacted status, logs, private-file permissions, dashboard socket, and absence of unexpected port mappings.
6. Remove temporary tunnels after successful verification. Remove an ordinary operational backup only after its checks pass. For a schema-incompatible update, retain the private pre-migration backup until the operator explicitly closes the rollback window; successful startup checks alone do not authorize its deletion. Follow the backup and rollback rules in [deployment.md](deployment.md).

If verification fails, preserve the failed state needed for diagnosis before considering a rollback. Do not use destructive Git or Docker commands on user data. The operator commands and security checks are in [deployment.md](deployment.md).

## Local maintainer notes

Machine-specific aliases, paths, and preferred commands belong in the ignored repository-root file `RELEASE.local.md`. It must never contain credentials, Telegram session values, HMAC keys, raw user identifiers, message content, or database copies.

The tracked documentation must remain usable without that file.
