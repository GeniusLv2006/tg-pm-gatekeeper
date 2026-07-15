# Architecture outline

## Goals

- Screen first-time private messages from unknown senders.
- Preserve legitimate messages and make automated actions reversible by default.
- Keep Telegram credentials and private message data out of source control.
- Explain every automated decision through a minimal audit record.

## Terms

- **Unknown**: no local trust decision exists for the sender.
- **Provisional**: the sender passed the arithmetic check; HR screening still applies.
- **Allowed**: the owner, CLI, or review workflow explicitly trusted the sender.
- **Quarantined**: Gatekeeper archived and muted the dialog for manual review; automatic
  whole-dialog deletion has not been scheduled.
- **Suppressed**: later messages are discarded and whole-dialog deletion may be scheduled until a
  temporary suppression expires, or indefinitely after an HR match with `critical` severity. This is
  not Telegram block.
- **Review item**: one sender-level pending decision with a count and one encrypted Telegram reference,
  not a stored conversation transcript.
- **Control identity**: a restriction-lifetime encrypted Telegram user ID and access hash used to
  keep a quarantine or suppression visible and reversible after message evidence expires.
- **HR**: the deterministic Hard Rule identifier family. An HR match has `signal`, `high`, or
  `critical` severity.
- **Critical**: the highest HR severity, not a separate rule family. An HR match with `critical`
  severity can trigger immediate deletion and indefinite suppression in `protect` mode.

### HR severity map

| HR identifier | Meaning | Severity |
| --- | --- | --- |
| `HR-01_MULTIPLE_LINK_BUTTONS` | Multiple interactive link buttons | `critical` |
| `HR-02_FORWARDED_LINK_BUTTON` | Forwarded message with an interactive link button | `critical` |
| `HR-03_PROMOTION_WITH_LINK` | Promotional language combined with a link | `high` |
| `HR-04_MULTIPLE_LINKS` | Multiple links combined with forwarding or promotion | `high` |
| `HR-05_LINK_BURST` | Repeated link-bearing messages from the sender | `signal` |
| `HR-06_DENIED_DOMAIN` | Domain matched by the owner's local denylist | `critical` |
| `HR-07_QUOTED_CRYPTO_SERVICE_PROMOTION` | Quoted crypto-service promotion pattern | `high` |

Only a `critical` match takes the immediate critical-action path. `high` and `signal` matches retain
their HR identifiers for review but follow the normal challenge path.

## Sender states

```text
unknown -> challenge_issuing -> challenge_archiving -> challenged
                                                     -> provisional -> allowed
                                                     -> suppressed (timeout or failed attempts)

unknown -> suppressed (HR match with critical severity)
provisional -> suppressed (HR match with critical severity)
unknown -> quarantined (challenge outbound limit or manual spam review)
challenged -> quarantined (manual spam review or warning failure)
unknown/provisional/challenged/quarantined/suppressed -> allowed (legitimate review)
allowed -> unknown (manual revoke)
```

The issuing and archiving states are internal recovery phases. A sender becomes `challenged` only
after the prompt is sent and the dialog is confirmed archived and muted. `provisional` means the
sender passed the interaction check and can message normally while HR screening remains active. Only a
later manual reply from the account owner, an explicit review, or a safe operator allow action grants
`allowed`. The CLI refuses challenge and quarantine states because it cannot restore Telegram state.

## Decision pipeline

1. Accept only incoming private-message events.
2. Exclude contacts, local allowlist entries, service accounts, bots, and peers with a trusted prior conversation.
3. Apply the deterministic HR family. Matches with `critical` severity are denylisted domains,
   multiple interactive link buttons, and forwarded interactive link buttons. Matches with `high`
   severity enter the challenge flow; a repeated-link burst has only `signal` severity. Authored text,
   Telegram-supplied webpage preview
   metadata, and links are kept separate from quoted text and links so quoted content cannot trigger
   generic promotion or link-count rules. The dedicated quoted crypto-service rule still inspects
   quote text in memory.
4. In monitor mode, record the simulated result for operator review and take no Telegram action,
   except for the explicitly configured dedicated test sender.
5. In protect mode, persist and silently delete dialogs after an HR match with `critical` severity;
   send one expiring challenge to ordinary and high-risk unknown senders and bind it to the outgoing
   Telegram message ID.
6. Accept only a direct Reply to that message. Restore a correct sender as `provisional` and remove
   the verification exchange. After two incorrect numeric answers, warn that deletion is pending,
   wait 10 seconds, then delete the entire private conversation and suppress the sender for 24
   hours. A timeout follows the same warned deletion flow with a two-hour suppression.

In protect mode the challenge is written in English and defaults to 60 seconds. Its title is
`⚠️ Verification Required`; Telegram-native bold entities emphasize the title, deadline, expression,
and configured attempt count without adding markup to the persisted recovery text. The response
window starts only after Telegram confirms prompt delivery. The dialog is archived and muted before
the challenge becomes active. Replies to another message, standalone answers, and non-numeric replies
do not consume an attempt or extend the deadline. At most one corrective hint is sent per challenge.
Numeric input is NFKC-normalized before comparison. A correct answer restores the dialog and its
previous archive, silent, and mute settings while keeping HR screening active. The success notice
remains visible for 10 seconds, then one Telegram request deletes the complete explicitly indexed
challenge flow, including earlier incorrect answers, corrective notices, the correct answer, and the
success notice.
Restoration is retried three times; persistent failure creates an exception review instead of
silently treating a correct sender as spam. A timeout sends a deletion warning. Two
incorrect numeric answers send a failure notice with a 10-second countdown, then delete the private
conversation for both sides. If the warning cannot be delivered, deletion is not scheduled; if the
eventual deletion fails, the already archived and muted dialog enters exception review.
The arithmetic is interaction friction rather than a CAPTCHA and is not treated as proof of humanity.
Each challenge independently selects addition, non-negative subtraction, or basic multiplication;
operands are bounded so answers remain suitable for quick mental arithmetic.

An optional single-account test path is enabled only when `TG_TEST_SENDER_ID` is configured. It
bypasses contact, prior-history, HR, monitor-mode, and outbound-quota shortcuts so
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
challenges and changes no Telegram dialog unless `TG_TEST_SENDER_ID` explicitly selects that sender.
Protection must be enabled with `mode protect`; `mode monitor` cancels pending non-test destructive
jobs.

## Post-event review

The running process serves a small Operations Dashboard on an owner-only Unix socket. The socket is not
published by Docker and is intended to be reached only through SSH local forwarding. This keeps the
live Telethon client as the only Telegram connection and avoids exposing an administrative TCP
service.

The queue stores one pending row per sender: the simulated decision, rule identifiers, non-content
structural features, a consolidated message count, and one authenticated encrypted reference
containing peer access data and a message ID. It is not a conversation archive. When an operator
opens an item, the running client decrypts that single reference and fetches the referenced message
and sender from Telegram. Those values are rendered in the response but are not persisted or logged.

The Pending Reviews and Active Cases pages decrypt their respective references to display Telegram
IDs and resolve names and usernames from Telegram in bounded batches. Both lists use stable
most-recently-updated ordering and 50-row pages. Profile names are cached only in process memory for
five minutes; failed lookups are retried after 30 seconds. Review decisions evict the matching cached
identity. Responses use `Cache-Control: no-store` and `Referrer-Policy: no-referrer`, although
rendered identity and the capability address remain visible in the owner's browser memory and
screenshots like any other displayed page.

The one-time login rotates both the access token and a random 256-bit capability path. No dashboard
authentication cookie is set. A new successful login immediately invalidates the previous capability,
and an absent or incorrect capability receives the same 404 response. Every internal link, form,
script, page refresh, and status request remains beneath that path.

Authenticated dashboard pages load a same-origin script that checks the capability-prefixed status
route every 15 seconds while the tab is visible. The status response contains only an opaque
fingerprint of the current page state and a check time; it contains no message content, Telegram
identity, encrypted reference, or evidence. When a list or overview fingerprint changes, the browser
fetches the current page, including its page number, and replaces only its marked live regions while
preserving current form input and focus. Detail pages instead disable stale decision controls and
require an explicit reload after their underlying record changes. Hidden tabs stop checking until
visible again, and the manual control can request an immediate check. The script and status route
remain behind the same owner-only Unix socket, SSH tunnel, and capability path.

An operator can mark an item as legitimate, confirmed spam, or dismissed. Legitimate senders enter
the local allowlist and are restored first when Gatekeeper previously archived the dialog. Confirmed
spam is archived and muted unless the sender is already quarantined. Dismiss performs no new action
through Telegram and therefore leaves a rate-limit fallback quarantine in place, but it cancels any
pending or failed Gatekeeper deletion jobs for that sender. A decision immediately removes the
encrypted reference. Pending references, including reviews created while changing mode or recording
an action failure, consistently use the configured one-to-seven-day retention. Non-reversible
verdicts may remain for the normal audit retention period.
Deleting a conversation in Telegram does not itself update the local queue. If the referenced
message is no longer available, the detail page still exposes a resolve-only action that dismisses
the local review, erases its reference, and cancels pending or failed Gatekeeper deletion jobs
without changing sender state.

Protect-mode terminal states have a separate **Active Cases** surface. It lists every current
quarantine and suppression, independent of evidence availability. The service captures the
original triggering text/caption, Telegram-provided quote and preview, text-link entities, visible
URL entities, button text, full URLs,
normalized domains, URL shape, matched HR identifiers, and severity before a challenge begins,
encrypts it with the active-case review key, and exposes it only after the sender becomes quarantined
or suppressed. A correct answer, challenge rollback, or manual allowance erases the evidence.
Temporary suppression expiry is reconciled only when that sender next messages; otherwise the
evidence remains until its own deadline. Other evidence expires after the configured Active Case
retention, capped at 30 days.

Each active restriction separately retains an authenticated encrypted control identity containing
only Telegram user ID and access hash. It contains no message ID or evidence and remains until the
restriction is allowed, revoked, or automatically released. Active Cases uses it to resolve the live
identity and restore saved Telegram folder and notification settings even after evidence expires. An
HR case with no dialog snapshot is moved to the main folder and notifications are enabled instead;
failure leaves policy state unchanged. Leaving the restriction unchanged records an operator
decision but does not extend a temporary suppression. A manual numeric-ID recovery form is retained
only for legacy states without a control identity; the ID is HMAC-derived in memory and not stored.

## Implemented action policy

| Input | Monitor mode | Protect mode |
| --- | --- | --- |
| Trusted sender | Allow | Allow |
| Ordinary unknown sender | Queue simulated challenge | Temporary archive/mute and challenge |
| Provisional sender | Continue HR screening | Continue HR screening |
| HR match with `critical` severity | Queue planned deletion | Persist, delete, and suppress |
| HR match with `high` severity | Queue simulated challenge | Challenge |
| HR match with `signal` severity | Queue simulated challenge | Challenge |
| Challenge send limit reached | Not applicable | Archive, mute, and queue review |
| Manual legitimate review | Allow sender | Allow sender |
| Manual spam review | Archive, mute, and quarantine | Archive, mute, and quarantine |
| Dedicated test sender | Run the real challenge flow | Run the real challenge flow |

Whole-dialog deletion is used for HR matches with `critical` severity and warned challenge failure.
Pending deletions persist across restart and execute only when mode, sender status, and state revision still
match. Dedicated-test-sender deletions are intentionally mode-independent; other destructive jobs are
cancelled by `mode monitor`. Blocking, reporting, model inference, and unrelated conversation cleanup
are not implemented.

## Data boundaries

The persistent store contains sender state, challenge metadata, generated challenge prompts while
delivery is incomplete, rule identifiers, timestamps, action outcomes, structural review features,
automated outgoing message IDs, encrypted short-lived Telegram references, the prior archive and
notification settings needed to reverse a Gatekeeper action, encrypted restriction-lifetime control
identities, pending action jobs, suppression state, privacy-safe detector decisions, and encrypted
Active Case envelopes. The state database does not store message bodies, quoted text, raw
identities, or profile data in plaintext.

Runtime credentials and state belong in a deployment-specific directory outside the repository. Configuration committed to Git must contain placeholders only.

Sender state, processed-message, review, and challenge records use an HMAC-SHA-256 derivation of the
Telegram user ID. The server-local HMAC key must remain outside general backups. Audit records
contain only the derived sender key, rule code, outcome, and timestamp and default to 30-day
retention. Usernames, phone numbers, media, hidden URL entity targets, raw URLs, and raw user IDs are
not written to audit records or plaintext state columns. Raw URLs may exist only inside short-lived
encrypted Active Case snapshots. Telegram message IDs
are stored only with derived sender keys for idempotency, direct Reply binding, and identification of
automated Gatekeeper messages. Names and usernames may exist
briefly in the review process's bounded memory cache. Raw user IDs are never stored in plaintext;
they are rendered from authenticated encrypted references. Processed Telegram message IDs are
retained for idempotency for the same audit-retention window.

Review references use AES-256-CTR with independent HMAC-SHA-256 authentication and keys derived for
those separate purposes from the server-local HMAC secret. The encrypted envelope is useful only
while that secret and the Telegram authorization remain available. Its lifetime is configurable up
to a hard maximum of seven days and it is erased immediately on a review decision. Runtime state,
including these envelopes, must not be included in general backups.

Restriction control references use the same authenticated encryption construction with separate
encryption and authentication domains. Their payload contains only Telegram user ID and access hash,
not a message ID. They remain for the lifetime of a quarantine or suppression so evidence retention
cannot remove the owner's ability to identify and allow the sender. They are erased when the
restriction ends.

The runtime uses a Telethon StringSession rather than its default SQLite session. This keeps the
authorization key without persisting Telethon's entity cache of names, usernames, and phone numbers.

Active Case snapshots use AES-256-GCM with a key derived through HKDF from the dedicated owner-only
`review.key` secret. The runtime reads it through `TG_REVIEW_KEY_FILE`. A snapshot includes the
original trigger, quoted context, Telegram preview text, button text, full URLs, normalized domains,
URL shape, matched HR identifiers, severity, and structural features, but never verification
answers, webpage bodies, or media. Snapshots expire after no more than 30 days and are removed sooner
after successful verification, rollback, or manual allowance.

## Failure behavior

- Incoming messages, timeouts, recovery, and review decisions are serialized per derived sender key.
- If Telegram history lookup fails, the sender is treated as having no trusted history and still
  enters normal screening; a privacy-safe audit event records the degraded lookup.
- The heartbeat and pruning loop is supervised with the Telegram connection. An unexpected failure
  terminates the process so the container restart policy can recover it instead of leaving a
  connected but unsupervised client running.
- Challenge delivery is persisted in issuing and archiving phases. Startup reconciles a sent prompt,
  retries the reversible archive action, and resets incomplete work when it cannot recover safely.
- Activated challenges are already archived, so timeout and restart recovery require only an atomic
  database transition. Normal processing and startup both allow 30 seconds for queued Telegram
  updates while still judging timeliness from the message's send timestamp.
- Sending or archiving failures compensate any confirmed partial Telegram action before rolling an
  incomplete challenge back to `unknown`, and delete a prompt that never became active. If
  restoration itself fails, the recoverable archiving phase is preserved for startup reconciliation
  instead of claiming that the sender is unconfined.
- The hourly outbound limit is a hard cap. New challenges can use only the non-reserved portion;
  verification hints, corrections, timeout warnings, and result notices may use the reserved
  portion, subject to a per-sender hourly notice cap. Exhausted new-challenge capacity archives the
  unknown dialog and creates a manual review item instead of allowing challenge delivery to fail
  open. The dedicated test sender bypasses these counters.
- Pending deletion jobs include an expected state revision. Switching to monitor cancels non-test
  jobs and creates exception reviews; restart recovery cannot execute stale work.
