# Security policy

## Reporting a vulnerability

Do not open a public issue containing credentials, session data, personal messages, phone numbers, or exploit details.

Use GitHub's private vulnerability reporting for this repository when available. If private reporting is unavailable, open a public issue containing only a request for a private contact channel and no sensitive technical details.

## Sensitive data

The following must never be committed, including in examples, fixtures, logs, screenshots, or Git history:

- Telegram API IDs, API hashes, login codes, two-factor authentication passwords, and session files
- phone numbers, usernames tied to private conversations, contact lists, and user IDs
- message text, media, allowlists, denylists, moderation databases, and audit logs
- deployment credentials, private keys, environment files, and backups

If a secret is committed, removing it in a later commit is insufficient. Revoke or rotate it immediately, then remove it from the complete Git history.

## Supported versions

The project is not yet released. Security updates will apply only to the latest commit on the default branch until a versioning policy is established.
