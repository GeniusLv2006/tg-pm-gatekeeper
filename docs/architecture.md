# Architecture outline

## Goals

- Screen first-time private messages from unknown senders.
- Preserve legitimate messages and make automated actions reversible by default.
- Keep Telegram credentials and private message data out of source control.
- Explain every automated decision through a minimal audit record.

## Sender states

```text
unknown -> challenge_issuing -> challenge_archiving -> challenged
                                                     -> provisional -> allowed
                                                     -> suppressed

unknown -> suppressed (critical deterministic rule)
provisional -> suppressed (critical deterministic rule)
allowed -> unknown (manual revoke)
```

The issuing and archiving states are internal recovery phases. A sender becomes `challenged` only
after the prompt is sent and the dialog is confirmed archived and muted. `provisional` means the
sender passed the interaction check and can message normally while hard rules remain active. Only a
later manual reply from the account owner, an explicit review, or a safe operator allow action grants
`allowed`. The CLI refuses challenge and quarantine states because it cannot restore Telegram state.

## Decision pipeline

1. Accept only incoming private-message events.
2. Exclude contacts, local allowlist entries, service accounts, bots, and peers with a trusted prior conversation.
3. Apply tiered deterministic rules. Critical rules are denylisted domains, multiple interactive
   link buttons, and forwarded interactive link buttons. High-risk rules enter the challenge flow;
   a repeated-link burst is only a signal. Authored text, Telegram-supplied webpage preview
   metadata, and links are kept separate from quoted text and links so quoted content cannot trigger
   generic promotion or link-count rules. The dedicated quoted crypto-service rule still inspects
   quote text in memory.
4. In monitor mode, record the simulated result for operator review and take no Telegram action.
5. In protect mode, persist and silently delete critical-rule dialogs; send one expiring challenge
   to ordinary and high-risk unknown senders and bind it to the outgoing Telegram message ID.
6. Accept only a direct Reply to that message. Restore a correct sender as `provisional` and remove
   the verification exchange. After two incorrect numeric answers, warn that deletion is pending,
   wait 10 seconds, then delete the entire private conversation and suppress the sender for seven
   days. A timeout follows the same warned deletion flow with a 24-hour suppression.

In protect mode the challenge is written in English and defaults to 60 seconds. Its title is
`⚠️ Verification Required`; Telegram-native bold entities emphasize the title, deadline, expression,
and configured attempt count without adding markup to the persisted recovery text. The response
window starts only after Telegram confirms prompt delivery. The dialog is archived and muted before
the challenge becomes active. Replies to another message, standalone answers, and non-numeric replies
do not consume an attempt or extend the deadline. At most one corrective hint is sent per challenge.
Numeric input is NFKC-normalized before comparison. A correct answer restores the dialog and its
previous archive, silent, and mute settings while keeping hard-rule screening active, then deletes
only explicitly indexed challenge, answer, corrective, and success messages in one Telegram request.
Restoration is retried three times; persistent failure creates an exception review instead of
silently treating a correct sender as spam. A timeout sends a deletion warning. Two
incorrect numeric answers send a failure notice with a 10-second countdown, then delete the private
conversation for both sides. If the warning cannot be delivered, deletion is not scheduled; if the
eventual deletion fails, the already archived and muted dialog enters exception review.
The arithmetic is interaction friction rather than a CAPTCHA and is not treated as proof of humanity.
Each challenge independently selects addition, non-negative subtraction, or basic multiplication;
operands are bounded so answers remain suitable for quick mental arithmetic.

An optional single-account test path is enabled only when `TG_TEST_SENDER_ID` is configured. It
bypasses contact, prior-history, hard-rule, monitor-mode, and outbound-quota shortcuts so
repeated tests exercise the actual arithmetic flow. Successful and terminal-failure states are
conditionally reset to `unknown` after 60 seconds; the conditional update prevents an older timer
from resetting a newer challenge. Exhausted attempts use the normal warning plus delayed
whole-dialog deletion policy. A timeout sends a failure notice, then deletes only message IDs
recorded during that challenge after 10 seconds. Delayed test-account cleanup and state reset are
reconstructed after restart.

Monitor mode records HMAC-keyed rule outcomes and creates a pending review item for each sender
with a simulated challenge or quarantine. Further messages from that sender update the same item and
increment its message counter. The retained reference normally follows the newest message. If a row
already represents a simulated quarantine, a later lower-risk message increments the counter without
replacing that higher-severity classification or its referenced message. Monitor mode sends no
challenges and changes no Telegram dialog.
Protection must be enabled with `mode protect`; `mode monitor` cancels pending destructive jobs.

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

The queue page decrypts the same pending references to display Telegram IDs and resolves names and
usernames from Telegram in batches. Profile names are cached only in process memory for five minutes;
failed lookups are retried after 30 seconds. Review decisions evict the matching cached identity.
Responses use `Cache-Control: no-store`, although rendered identity remains visible in the owner's
browser memory and screenshots like any other displayed page.

An operator can mark an item as legitimate, confirmed spam, or dismissed. Legitimate senders enter
the local allowlist and are restored first when Gatekeeper previously archived the dialog. Confirmed
spam is archived and muted unless the sender is already quarantined. Dismiss performs no new action
and therefore leaves a rate-limit fallback quarantine in place. A decision immediately removes the
encrypted reference. Pending references expire after no more than seven days, while non-reversible
verdicts may remain for the normal audit retention period.

## Implemented action policy

| Input | Monitor mode | Protect mode |
| --- | --- | --- |
| Trusted sender | Allow | Allow |
| Ordinary unknown sender | Queue simulated challenge | Temporary archive/mute and challenge |
| Provisional sender | Continue hard-rule screening | Continue hard-rule screening |
| Critical rule | Queue planned deletion | Persist, delete, and suppress |
| High-risk rule | Queue simulated challenge | Challenge |
| Repeated-link signal | Queue simulated challenge | Challenge |
| Challenge send limit reached | Not applicable | Archive, mute, and queue review |
| Manual legitimate review | Allow sender | Allow sender |
| Manual spam review | Archive, mute, and quarantine | Archive, mute, and quarantine |

Whole-dialog deletion is used for critical deterministic rules and warned challenge failure. Pending
deletions persist across restart and execute only when mode, sender status, and state revision still
match. Blocking, reporting, model inference, and unrelated conversation cleanup are not implemented.

## Data boundaries

The persistent store contains sender state, challenge metadata, generated challenge prompts while
delivery is incomplete, rule identifiers, timestamps, action outcomes, structural review features,
automated outgoing message IDs, encrypted short-lived Telegram references, and the prior archive and
notification settings needed to reverse a Gatekeeper action, pending action jobs, suppression state,
and privacy-safe detector decisions. The core state database does not store private message bodies or
profile data. Peer references remain encrypted until a challenge reaches its terminal action.

Runtime credentials and state belong in a deployment-specific directory outside the repository. Configuration committed to Git must contain placeholders only.

Sender state, processed-message, review, and challenge records use an HMAC-SHA-256 derivation of the
Telegram user ID. The server-local HMAC key must remain outside general backups. Audit records
contain only the derived sender key, rule code, outcome, and timestamp and default to 30-day
retention. Message bodies, usernames, phone numbers, media, raw URLs, and raw user IDs are not
persisted. Telegram message IDs are stored only with derived sender keys for idempotency, direct
Reply binding, and identification of automated Gatekeeper messages. Names and usernames may exist
briefly in the review process's bounded memory cache, and
raw user IDs are rendered from authenticated encrypted references without being added to the
database. Processed Telegram message IDs are retained for idempotency for the same audit-retention
window.

Review references use AES-256-CTR with independent HMAC-SHA-256 authentication and keys derived for
those separate purposes from the server-local HMAC secret. The encrypted envelope is useful only
while that secret and the Telegram authorization remain available. Its lifetime is configurable up
to a hard maximum of seven days and it is erased immediately on a review decision. Runtime state,
including these envelopes, must not be included in general backups.

The runtime uses a Telethon StringSession rather than its default SQLite session. This keeps the
authorization key without persisting Telethon's entity cache of names, usernames, and phone numbers.

Optional training samples live in a separate owner-only `training.sqlite3`. Authored text/captions
and structural features are encrypted with AES-256-GCM under an independent dataset key. Dataset-key
derived HMAC tokens enforce per-sender and per-message limits without storing raw identities. Media,
quoted text, names, usernames, raw IDs, access hashes, and the dedicated test sender are excluded.
Samples expire after 30 days by default and no later than 90 days. This release does not train or run
a model.

## Failure behavior

- Incoming messages, timeouts, recovery, and review decisions are serialized per derived sender key.
- Challenge delivery is persisted in issuing and archiving phases. Startup reconciles a sent prompt,
  retries the reversible archive action, and resets incomplete work when it cannot recover safely.
- Activated challenges are already archived, so timeout and restart recovery require only an atomic
  database transition. Normal processing and startup both allow 30 seconds for queued Telegram
  updates while still judging timeliness from the message's send timestamp.
- Sending or archiving failures compensate any confirmed partial Telegram action before rolling an
  incomplete challenge back to `unknown`, and delete a prompt that never became active. If
  restoration itself fails, the recoverable archiving phase is preserved for startup reconciliation
  instead of claiming that the sender is unconfined.
- Exhausted outbound capacity archives the unknown dialog and creates a manual review item instead
  of allowing challenge delivery to fail open.
- Pending deletion jobs include an expected state revision. Switching to monitor cancels them and
  creates exception reviews; restart recovery cannot execute stale work.
