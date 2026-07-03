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

## Runtime boundary

- The Telegram StringSession is stored only as a mode `0600` file owned by the service UID.
- The runtime database contains HMAC-derived sender keys, Telegram message IDs, generated challenge
  text during incomplete delivery, and authenticated encrypted short-lived action references. It
  does not contain raw user IDs, private message content, usernames, or profile names.
- Optional training samples are stored only in a separate owner-only database. Authored text and
  structural features are AES-256-GCM encrypted under an independent dataset key; media, quoted
  text, profile data, raw IDs, access hashes, and the dedicated test sender are excluded.
- Arithmetic verification is an interaction check, not a CAPTCHA or proof that a sender is human.
- Challenge delivery, timeout, and review transitions must be serialized per derived sender key;
  outbound-rate exhaustion must not bypass screening.
- Whole-dialog deletion must be represented by a persistent action with an expected state revision.
  It may execute only in `protect` mode; switching to `monitor` cancels pending destructive jobs.
- The application must not expose a listening port or mount the Docker socket.
- Root compromise of the host is considered compromise of the Telegram account. Container isolation
  does not protect a session from the host administrator.
- Two-step verification is required, but it does not invalidate an already stolen session.
- Plaintext dataset exports are sensitive message data. Transfer them only to a trusted workstation
  and remove the server-side export immediately.

## Incident response

1. Stop the gatekeeper container.
2. Terminate the affected session from an official Telegram client.
3. Delete the server-side session file.
4. Generate and provision a new session from a trusted computer.
5. Only then remove leaked material from Git history, logs, or backups.

## Supported versions

The project is not yet released. Security updates will apply only to the latest commit on the default branch until a versioning policy is established.
