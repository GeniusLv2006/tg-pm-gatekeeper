# Contributing

This project controls a Telegram user session, so security and data minimization take priority over
convenience. Keep changes small, reviewable, and safe to publish.

## Before contributing

- Do not use real API credentials, session strings, phone numbers, user IDs, usernames, messages,
  URLs, allowlists, databases, or logs in code, tests, issues, or pull requests.
- Report vulnerabilities through the process in [SECURITY.md](SECURITY.md), not in a public issue.
- Base work on `main` and follow the risk-based publication rules in
  [docs/RELEASE.md](docs/RELEASE.md). Runtime, security, networking, deployment, dependency, and
  executable-script changes require a pull request.

## License of contributions

The project is licensed under the [Mozilla Public License 2.0](LICENSE). By submitting a contribution,
you agree to license it under MPL-2.0. Preserve existing license notices and add the standard MPL
source notice to new Python and shell files. Do not add the Exhibit B “Incompatible With Secondary
Licenses” notice.

## Commit format

Use [Conventional Commits](https://www.conventionalcommits.org/) for every commit:

```text
<type>[optional scope]: <description>
```

Common types are `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `build`, `ci`, and `chore`.
Use an imperative, lower-case description and mark breaking changes with `!` or a
`BREAKING CHANGE:` footer.

Examples:

```text
feat(challenge): expire pending verification after one minute
fix(store): avoid actions when an audit write fails
docs: clarify session revocation procedure
```

## Validation

Run the same checks used by CI before publishing behavior-affecting changes:

```shell
PYTHONPATH=src .venv/bin/python -m unittest discover -v
PYTHONPATH=src .venv/bin/python -m compileall -q src tests scripts
```

Dependency versions and GitHub Actions must remain pinned. Do not enable automatic merging for
dependency updates.

## Pull requests

Explain the behavior change, its security and privacy impact, licensing impact when applicable, and
the checks performed. Changes to Telegram actions, stored data, logging, networking, or deployment
boundaries require corresponding tests and documentation. Draft PRs are for incomplete work; ready
changes should not add a separate Draft-to-Ready ceremony. See
[docs/RELEASE.md](docs/RELEASE.md) for direct-to-main eligibility, merge titles, and deployment
requirements.
