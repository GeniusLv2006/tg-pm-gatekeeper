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
