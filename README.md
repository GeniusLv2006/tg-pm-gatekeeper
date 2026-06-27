# tg-pm-gatekeeper

A safety-first Telegram private-message gatekeeper for screening unsolicited messages.

> [!IMPORTANT]
> This project is in the design phase. It is not ready to run against a Telegram account.

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

The default policy is reversible quarantine. Permanent deletion and blocking must be explicit, separately configurable actions.

## Security principles

- Never commit Telegram session files, API credentials, phone numbers, message databases, allowlists, logs, or backups.
- Keep secrets outside the repository and provide only redacted configuration examples.
- Treat a user-session file as an account credential.
- Minimize stored message content and keep an auditable reason for every automated action.
- AI-based classification, if added, must not directly trigger irreversible actions.
- Test authorization and rate-limit handling with a dedicated test account before using a personal account.

See [SECURITY.md](SECURITY.md) before reporting a security issue and [docs/architecture.md](docs/architecture.md) for the current design.

## Status

No implementation language or Telegram client library has been selected yet. That decision will be documented before executable code is added.

## License

No license has been selected. All rights are reserved until a license is added.
