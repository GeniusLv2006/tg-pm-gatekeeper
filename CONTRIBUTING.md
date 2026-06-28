# Contributing

This project controls a Telegram user session, so security and data minimization take priority over
convenience. Keep changes small, reviewable, and safe to publish.

## Before contributing

- Do not use real API credentials, session strings, phone numbers, user IDs, usernames, messages,
  URLs, allowlists, databases, or logs in code, tests, issues, or pull requests.
- Report vulnerabilities through the process in [SECURITY.md](SECURITY.md), not in a public issue.
- Base work on `main` and submit it through a pull request.

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

Run the same checks used by CI before opening a pull request:

```shell
PYTHONPATH=src python -m unittest discover -v
PYTHONPATH=src python -m compileall -q src tests scripts
```

Dependency versions and GitHub Actions must remain pinned. Do not enable automatic merging for
dependency updates.

## Pull requests

Explain the behavior change, its security and privacy impact, and the checks performed. Changes to
Telegram actions, stored data, logging, networking, or deployment boundaries require corresponding
tests and documentation.
