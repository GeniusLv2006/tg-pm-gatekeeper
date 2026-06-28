# tg-pm-gatekeeper

A safety-first Telegram private-message gatekeeper for screening unsolicited messages.

> [!IMPORTANT]
> This software controls a Telegram user session. A stolen session grants account access. Read
> [SECURITY.md](SECURITY.md) and test with a dedicated account before using a personal account.

## Intended flow

```text
incoming private message
  -> trusted sender? allow
  -> high-confidence spam rule? quarantine
  -> optional risk classification
  -> challenge unknown sender
      -> correct answer: add to local allowlist
      -> incorrect or expired: quarantine
```

The default mode is observation-only. Enforcement is a deliberate CLI action, and v1 enforcement is
limited to archiving and muting. It never deletes, blocks, reports, opens links, or invokes AI.

Observation mode places simulated challenge and quarantine decisions in a local review queue. The
review dashboard is served only through an owner-only Unix socket and is reached with an SSH tunnel;
the container still exposes no TCP port. Opening an item fetches its message and sender directly from
Telegram at that moment. Message bodies and profile data are not written to the local database.

## Implemented hard rules

- URL, login, or WebView button from an unknown sender
- forwarded content containing a link or button
- gambling, crypto-promotion, or VPN/proxy-promotion language combined with a link
- multiple links or domains in one message
- repeated link messages within 60 seconds
- optional locally maintained denied domains
- quoted crypto transfer/service promotions with multiple commercial signals

## Security principles

- Never commit Telegram session files, API credentials, phone numbers, message databases, allowlists, logs, or backups.
- Keep secrets outside the repository and provide only redacted configuration examples.
- Treat a user-session file as an account credential.
- Minimize stored message content and keep an auditable reason for every automated action.
- Expire encrypted review references after at most seven days and erase them immediately after a
  review decision.
- AI-based classification, if added, must not directly trigger irreversible actions.
- Test authorization and rate-limit handling with a dedicated test account before using a personal account.

See [SECURITY.md](SECURITY.md) before reporting a security issue,
[docs/architecture.md](docs/architecture.md) for the design, and
[docs/deployment.md](docs/deployment.md) for the hardened deployment procedure. Contributions must
follow [CONTRIBUTING.md](CONTRIBUTING.md), including the Conventional Commits requirement.

## Local checks

```shell
PYTHONPATH=src python -m unittest discover -v
PYTHONPATH=src python -m compileall -q src tests scripts
```

Runtime dependencies and the Python base image are pinned. The container does not expose a network
port and starts as UID/GID `10001` with a read-only root filesystem.

After installing the pinned dependencies, local credential initialization is a single interactive
command:

```shell
.venv/bin/python scripts/initialize.py
```

The generated files are mode `0600`, ignored by Git, and must never be printed or shared.

## License

No license has been selected. All rights are reserved until a license is added.
