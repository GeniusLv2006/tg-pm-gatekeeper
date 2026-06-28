# Architecture outline

## Goals

- Screen first-time private messages from unknown senders.
- Preserve legitimate messages and make automated actions reversible by default.
- Keep Telegram credentials and private message data out of source control.
- Explain every automated decision through a minimal audit record.

## Sender states

```text
unknown -> challenged -> allowed
                     -> quarantined
                     -> expired

unknown -> quarantined (high-confidence rule)
allowed -> quarantined (manual revocation)
```

Transitions must be idempotent and persisted so restarts cannot resend challenges or repeat destructive actions.

## Decision pipeline

1. Accept only incoming private-message events.
2. Exclude contacts, local allowlist entries, service accounts, bots, and peers with a trusted prior conversation.
3. Apply deterministic, high-precision spam rules.
4. Optionally calculate a non-authoritative risk score.
5. Send one expiring challenge to an otherwise ordinary unknown sender.
6. Allow a correct response; quarantine an incorrect or expired challenge.

In enforcement mode the challenge is written in English and expires after 60 seconds. The dialog is
immediately archived and muted while verification is pending. Non-numeric messages do not consume an
attempt or extend the deadline. A correct answer restores the dialog and notifications; timeout or
two incorrect numeric answers leave it archived and muted.

Observation mode records only HMAC-keyed rule outcomes. It sends no challenges and changes no
Telegram dialog. Enforcement must be enabled with the local operator CLI after review.

## Action policy

| Risk | Default action |
| --- | --- |
| Trusted | Allow |
| Low or uncertain | Challenge |
| High-confidence spam | Archive or quarantine |
| Repeated confirmed abuse | Optional block |

Deletion, blocking, and reporting are intentionally outside the default path. A retention job may delete expired quarantined conversations only after a separately configured review period.

## Data boundaries

The persistent store should contain sender state, challenge metadata, rule identifiers, timestamps, and action outcomes. It should avoid storing message bodies. If temporary message content is required for classification, it should have a short, enforced retention period.

Runtime credentials and state belong in a deployment-specific directory outside the repository. Configuration committed to Git must contain placeholders only.

The allowlist and challenge tables use an HMAC-SHA-256 derivation of the Telegram user ID. The HMAC
key is server-local and is never backed up. Audit records contain only the derived sender key, rule
code, outcome, and timestamp and expire after 30 days. Message bodies, usernames, phone numbers,
media, raw URLs, and raw user IDs are not persisted.

The runtime uses a Telethon StringSession rather than its default SQLite session. This keeps the
authorization key without persisting Telethon's entity cache of names, usernames, and phone numbers.

## Failure behavior

- A message update is claimed before any network action, so duplicate updates cannot repeat actions.
- Database, parsing, or Telegram RPC failures result in no further action and a redacted error event.
- Challenge timeout actions are retained only in memory. If the process restarts during a challenge,
  the next message evaluates the persisted expiry; the service does not persist a raw peer solely to
  perform a background action after restart.
- Archiving and muting are the only destructive-adjacent operations in v1. Deletion, blocking, and
  reporting are not implemented.
