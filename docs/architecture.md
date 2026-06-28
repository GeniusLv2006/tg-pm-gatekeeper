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

unknown -> quarantined (high-confidence rule)
allowed -> unknown (manual revoke)
```

Transitions must be idempotent and persisted so restarts cannot resend challenges or repeat destructive actions.

## Decision pipeline

1. Accept only incoming private-message events.
2. Exclude contacts, local allowlist entries, service accounts, bots, and peers with a trusted prior conversation.
3. Apply deterministic, high-precision spam rules.
   Quoted text and its entities are inspected in memory, but are never persisted.
4. In observation mode, record the simulated result for operator review and take no Telegram action.
5. In enforcement mode, send one expiring challenge to an otherwise ordinary unknown sender.
6. Allow a correct response; quarantine after two incorrect numeric answers or timeout.

In enforcement mode the challenge is written in English and expires after 60 seconds. The dialog is
immediately archived and muted while verification is pending. Non-numeric messages do not consume an
attempt or extend the deadline. A correct answer restores the dialog and notifications; timeout or
two incorrect numeric answers leave it archived and muted.

Observation mode records HMAC-keyed rule outcomes and creates a pending review item for each sender
with a simulated challenge or quarantine. Further messages from that sender update the same item and
increment its message counter. The retained reference normally follows the newest message. If a row
already represents a simulated quarantine, a later lower-risk message increments the counter without
replacing that higher-severity classification or its referenced message. Observation mode sends no
challenges and changes no Telegram dialog.
Enforcement must be enabled with the local operator CLI after review.

## Post-event review

The running process serves a small review dashboard on an owner-only Unix socket. The socket is not
published by Docker and is intended to be reached only through SSH local forwarding. This keeps the
live Telethon client as the only Telegram connection and avoids exposing an administrative TCP
service.

The queue stores one pending row per sender: the simulated decision, rule identifiers, non-content
structural features, a consolidated message count, and one authenticated encrypted reference
containing peer access data and a message ID. It is not a conversation archive. When an operator
opens an item, the running client decrypts that single reference and fetches the referenced message
and sender from Telegram. Those values are rendered in the response but are not persisted or logged.

An operator can mark an item as legitimate, confirmed spam, or dismissed. Legitimate senders enter
the local allowlist. Confirmed spam is explicitly archived and muted; observation mode never performs
that action on its own. A decision immediately removes the encrypted reference. Pending references
expire after no more than seven days, while non-reversible verdicts may remain for the normal audit
retention period.

## Implemented action policy

| Input | Observation mode | Enforcement mode |
| --- | --- | --- |
| Trusted sender | Allow | Allow |
| Ordinary unknown sender | Queue simulated challenge | Temporary archive/mute and challenge |
| High-confidence rule | Queue simulated quarantine | Archive and mute |
| Manual legitimate review | Allow sender | Allow sender |
| Manual spam review | Archive, mute, and quarantine | Archive, mute, and quarantine |

Deletion, blocking, reporting, AI classification, and conversation cleanup are not implemented.

## Data boundaries

The persistent store should contain sender state, challenge metadata, rule identifiers, timestamps,
action outcomes, structural review features, and encrypted short-lived Telegram references. It does
not store message bodies or profile data.

Runtime credentials and state belong in a deployment-specific directory outside the repository. Configuration committed to Git must contain placeholders only.

Sender state, processed-message, review, and challenge records use an HMAC-SHA-256 derivation of the
Telegram user ID. The server-local HMAC key must remain outside general backups. Audit records
contain only the derived sender key, rule code, outcome, and timestamp and default to 30-day
retention. Message bodies, usernames, phone numbers, media, raw URLs, and raw user IDs are not
persisted. Processed Telegram message IDs are retained for idempotency for the same audit-retention
window.

Review references use AES-256-CTR with independent HMAC-SHA-256 authentication and keys derived for
those separate purposes from the server-local HMAC secret. The encrypted envelope is useful only
while that secret and the Telegram authorization remain available. Its lifetime is configurable up
to a hard maximum of seven days and it is erased immediately on a review decision. Runtime state,
including these envelopes, must not be included in general backups.

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
