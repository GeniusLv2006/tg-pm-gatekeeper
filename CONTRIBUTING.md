# Contributing

Contributions that make Gatekeeper safer, clearer, or easier to operate are welcome. Documentation,
tests, focused bug fixes, and small usability improvements are good places to start.

Because Gatekeeper controls a Telegram user session, changes involving messages, stored data, or
Telegram actions need extra care. The rules below are intended to keep contributions safe to review
and publish.

## Set up the project

```shell
git clone https://github.com/GeniusLv2006/tg-pm-gatekeeper.git
cd tg-pm-gatekeeper
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes --no-deps -r requirements-build.txt
.venv/bin/python -m pip install --require-hashes --no-deps --no-build-isolation -r requirements.txt
```

Run the tests before and after your change:

```shell
PYTHONPATH=src .venv/bin/python -m unittest discover -v
PYTHONPATH=src .venv/bin/python -m compileall -q src tests scripts
.venv/bin/python -m pip install --require-hashes --no-deps -r requirements-quality.txt
.venv/bin/ruff check src tests scripts
shellcheck scripts/*.sh deploy/*.sh
git diff --check
```

Runtime, Docker, configuration, or dependency changes should also pass:

```shell
docker build --tag tg-pm-gatekeeper:test .
```

## Keep test and review data private

Use synthetic values only. Do not put real API credentials, session strings, phone numbers, user IDs,
usernames, messages, URLs, allowlists, databases, or logs in code, tests, issues, or pull requests.

Report vulnerabilities through [SECURITY.md](SECURITY.md), not a public issue.

## Keep the change focused

- Base work on current `main`.
- Include tests for behavior changes.
- Update documentation when Telegram actions, storage, logging, networking, or deployment behavior
  changes.
- Keep dependency versions and GitHub Actions pinned.
- Do not enable automatic merging for dependency updates.

The [maintainer release policy](docs/RELEASE.md) explains which changes require a pull request. Runtime,
security, networking, deployment, dependency, and executable-script changes always do.

## Check the current direction first

The [project direction](README.md#project-direction) is intentionally provisional. Before investing
in a substantial feature, open a focused discussion to confirm that it still fits the project. The
presence of a type, field, configuration hook, or earlier experiment does not mean that its direction
is committed.

In particular, a local model-training pipeline is not currently planned, the standalone labeling
workflow has been removed, and external AI evaluation remains exploratory. Do not add a
provider SDK, transmit message content, or establish a new storage or authentication boundary without
an agreed design and explicit security and privacy review.

## Commit format

Every commit and pull-request title uses Conventional Commits:

```text
<type>[optional scope]: <description>
```

Common types are `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `build`, `ci`, and `chore`. Use an
imperative, lower-case description and mark breaking changes with `!` or a `BREAKING CHANGE:` footer.

Examples:

```text
feat(challenge): expire pending verification after one minute
fix(store): avoid actions when an audit write fails
docs: clarify session revocation procedure
```

## Pull requests

Explain:

- what behavior or documentation changed;
- the security and privacy impact;
- licensing impact when applicable;
- validation performed; and
- whether the server must be updated or the image rebuilt.

Open a ready PR when the change is complete. Use Draft only for genuinely incomplete work. Keep the
squash title in the form `<conventional title> (#<PR>)`.

## License of contributions

The project uses the [Mozilla Public License 2.0](LICENSE). By submitting a contribution, you agree to
license it under MPL-2.0.

Preserve existing license notices. New Python and shell files must include the standard MPL SPDX
identifier and `Copyright (c) 2026 GeniusLv2006 and contributors`. Keep a shebang on the first line of
an executable shell or Python file. Do not add the Exhibit B “Incompatible With Secondary Licenses”
notice.
