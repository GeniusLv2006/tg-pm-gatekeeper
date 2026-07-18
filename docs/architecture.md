# Architecture outline

## Goals

- Screen first-time private messages from unknown senders.
- Preserve legitimate messages and make automated actions reversible by default.
- Keep Telegram credentials and private message data out of source control.
- Explain every automated decision through a minimal audit record.

## Terms

- **Unknown**: no local trust decision exists for the sender.
- **Provisional**: the sender passed the arithmetic check; adaptive screening still applies to later
  risk-bearing messages.
- **Allowed**: the owner, CLI, or review workflow explicitly trusted the sender.
- **Quarantined**: Gatekeeper could not safely complete normal delivery, archive, restore, quota, or
  warning handling. It is an exception state, not a normal risk tier.
- **Suppressed**: later messages are discarded and whole-dialog deletion may be scheduled until a
  temporary suppression expires, or indefinitely after an `adaptive-v2` destructive evidence gate.
  This is not Telegram block.
- **Review item**: one sender-level pending decision with a count and one encrypted Telegram reference,
  not a stored conversation transcript.
- **Control identity**: a restriction-lifetime encrypted Telegram user ID and access hash used to
  keep a quarantine or suppression visible and reversible after message evidence expires.
- **Evidence signal**: a code, source, fixed weight, and explanation produced from authored text,
  buttons, previews, quoted context, behavior, or owner policy.
- **Risk score**: the sum of evidence-signal weights under a named policy version. It is deterministic,
  not a model confidence estimate.
- **Destructive evidence gate**: the additional evidence requirement that must be met before a score
  can authorize permanent suppression.

### adaptive-v2 signal map

| Evidence | Source | Weight |
| --- | --- | ---: |
| Low-information opener | Authored text | 5 |
| Telegram invitation or one link button | Authored/preview/quoted link or button | 10 |
| Forwarding or a repeated link-bearing message | Behavior | 10 |
| Multiple message, preview, or quoted links | Authored, preview, or quoted context | 15 |
| Quoted promotional language | Quoted context | 15 |
| External landing page plus Telegram invitation | Behavior | 15 |
| Promotional language | Authored text | 20 |
| Promotional language | Telegram webpage preview | 20 |
| Multiple link buttons or forwarded link button | Button | 25 |
| Owner-denied domain in quoted context | Quoted context | 30 |
| Same campaign template across different senders within 7 days | Behavior | 40 |
| Owner-denied domain in authored text, button, or preview | Owner policy plus non-quoted source | 100 |

Scores below 30 use `standard_challenge`; scores from 30 upward use `strict_challenge`. A score of 70
or more uses `permanent_suppression` only when a non-quoted owner-denied domain is present, or when a
cross-sender repeated campaign is promotional, contains multiple links, and is either forwarded or
carried by a promotional Telegram webpage preview containing campaign links. Weak signals cannot
accumulate past this destructive boundary, and a quoted denylist match alone cannot delete a dialog.
Weights, thresholds, the campaign window, and destructive gates are fixed in code under
`adaptive-v2`.

## Sender states

```text
unknown -> challenge_issuing -> challenge_archiving -> challenged
                                                     -> provisional -> allowed
                                                     -> suppressed (timeout or failed attempts)

unknown/provisional -> suppressed (adaptive-v2 destructive evidence gate)
unknown/provisional/challenged -> quarantined (delivery, archive, restore, warning, or quota exception)
unknown/provisional/challenged/quarantined -> suppressed (explicit manual spam decision)
unknown/provisional/challenged/quarantined/suppressed -> allowed (legitimate review)
allowed -> unknown (manual revoke)
```

The issuing and archiving states are internal recovery phases. A sender becomes `challenged` only
after the prompt is sent and the dialog is confirmed archived and muted. `provisional` means the
sender passed the interaction check and can message normally while adaptive screening remains active.
Only a later manual reply from the account owner, an explicit review, or a safe operator allow action
grants `allowed`. The CLI refuses challenge and quarantine states because it cannot restore Telegram
state.

## Decision pipeline

1. Accept only incoming private-message events.
2. Exclude contacts, local allowlist entries, service accounts, bots, and peers with a trusted prior conversation.
3. Extract structured evidence signals and sum their fixed `adaptive-v2` weights. Authored text,
   Telegram-supplied webpage previews, buttons, quoted context, behavior, and owner policy remain
   separate sources in the decision record. URLs found inside webpage-preview metadata participate
   as preview evidence and are deduplicated with the Telegram webpage URL.
4. For promotional payloads containing at least two distinct URLs, create a keyed HMAC campaign
   template fingerprint. Prefer quoted promotional content, exclude an outer low-information opener,
   normalize text in memory, and replace URL domains, paths, queries, and Telegram invitation tokens
   with link-type placeholders. Count different derived sender keys seen during the last 7 days.
   Store no campaign template, plaintext, raw URL, or reversible digest. The dedicated test sender
   never participates.
5. In monitor mode, record the simulated result for operator review and take no Telegram action,
   except for the explicitly configured dedicated test sender.
6. In protect mode, permanently suppress only after the score and destructive gate both pass. Use a
   strict one-attempt challenge at score 30 or above; otherwise use the configured standard challenge.
7. Accept only a direct Reply to that message. Restore a correct sender as `provisional` and remove
   the verification exchange. After two incorrect numeric answers, warn that deletion is pending,
   wait 10 seconds, then delete the entire private conversation and suppress the sender for 24
   hours. A standard timeout follows the same warned deletion flow with a two-hour suppression. A
   strict timeout or first wrong numeric answer uses a 24-hour suppression.

In protect mode the challenge is written in English and defaults to 60 seconds. Its title is
`⚠️ Verification Required`; Telegram-native bold entities emphasize the title, deadline, expression,
and configured attempt count without adding markup to the persisted recovery text. The response
window starts only after Telegram confirms prompt delivery. The dialog is archived and muted before
the challenge becomes active. Replies to another message, standalone answers, and non-numeric replies
do not consume an attempt or extend the deadline. At most one corrective hint is sent per challenge.
Numeric input is NFKC-normalized before comparison. A correct answer restores the dialog and its
previous archive, silent, and mute settings while keeping adaptive screening active. A later
risk-bearing provisional message can trigger another challenge or permanent suppression. The success
notice remains visible for 10 seconds, then one Telegram request deletes the complete explicitly indexed
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
bypasses contact, prior-history, adaptive detection, monitor-mode, and outbound-quota shortcuts so
repeated tests exercise the actual arithmetic flow. Successful and terminal-failure states are
conditionally reset to `unknown` after 60 seconds; the conditional update prevents an older timer
from resetting a newer challenge. Exhausted attempts use the normal warning plus delayed
whole-dialog deletion policy. A timeout sends a failure notice, then deletes only message IDs
recorded during that challenge after 10 seconds. Delayed test-account cleanup and state reset are
reconstructed after restart.

Monitor mode records HMAC-keyed decisions and creates a pending review item for each sender with a
simulated standard challenge, strict challenge, or permanent suppression. Further messages from that
sender update the same item and
increment its message counter. The retained reference normally follows the newest message. If a row
already represents a simulated quarantine, a later lower-risk message increments the counter without
replacing the higher-impact classification or its referenced message. Monitor mode sends no
challenges and changes no Telegram dialog unless `TG_TEST_SENDER_ID` explicitly selects that sender.
Protection must be enabled with `mode protect`; `mode monitor` cancels automatically generated
destructive jobs but not explicit manual spam decisions or dedicated-test cleanup.

## Post-event review

The running process serves a small Operations Dashboard on an owner-only Unix socket. The socket is not
published by Docker and is intended to be reached only through SSH local forwarding. This keeps the
live Telethon client as the only Telegram connection and avoids exposing an administrative TCP
service.

The queue stores one pending row per sender: the simulated decision, evidence signals, non-content
structural features, a consolidated message count, and one authenticated encrypted reference
containing peer access data and a message ID. It is not a conversation archive. When an operator
opens an item, the running client decrypts that single reference and fetches the referenced message
and sender from Telegram. Those values are rendered in the response but are not persisted or logged.

The Pending Reviews and Active Cases pages decrypt their respective references to display Telegram
IDs and resolve names and usernames from Telegram in bounded batches. Both lists use stable
most-recently-updated ordering and 50-row pages. Profile names are cached only in process memory for
five minutes; failed lookups are retried after 30 seconds. Review decisions evict the matching cached
identity. Responses use `Cache-Control: no-store` and `Referrer-Policy: no-referrer`, although
rendered identity remains visible in the owner's browser memory and screenshots like any other
displayed page.

The one-time login rotates the access token, a random 256-bit capability path, and an independent
256-bit browser session token. The session token is stored only in process memory and a host-only,
path-scoped HttpOnly cookie with `SameSite=Strict`; the capability remains in the URL. Both credentials
are required, so copying the URL into another browser does not transfer access. A new login or
CSRF-protected logout immediately invalidates both credentials. The server also rejects a session
after 30 minutes without a dashboard request or eight hours from login. Missing, incorrect, expired,
or superseded credentials receive the same 404 response. Every internal link, form, script, page
refresh, and status request remains beneath the capability path.

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
spam becomes a manual permanent suppression with a persistent, mode-independent deletion job. Dismiss
performs no new action through Telegram and therefore leaves a rate-limit fallback quarantine in
place, but it cancels any
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
URL entities, button text, full URLs, normalized domains, URL shape, evidence-signal breakdown, risk
score, challenge profile, planned action, decision basis, and policy version before a challenge begins,
encrypts it with the active-case review key, and exposes it only after the sender becomes quarantined
or suppressed. A correct answer, challenge rollback, or manual allowance erases the evidence.
Temporary suppression expiry is reconciled only when that sender next messages; otherwise the
evidence remains until its own deadline. Other evidence expires after the configured Active Case
retention, capped at 30 days.

Each active restriction separately retains an authenticated encrypted control identity containing
only Telegram user ID and access hash. It contains no message ID or evidence and remains until the
restriction is allowed, revoked, or automatically released. Active Cases uses it to resolve the live
identity and restore saved Telegram folder and notification settings even after evidence expires. A
permanently suppressed case with no dialog snapshot is moved to the main folder and notifications
are enabled instead; failure leaves policy state unchanged. Leaving the restriction unchanged records an operator
decision but does not extend a temporary suppression. A manual numeric-ID recovery form is retained
only for legacy states without a control identity; the ID is HMAC-derived in memory and not stored.

When `TG_TELEGRAM_OPERATOR_CONTROLS_ENABLED=true`, the same restriction-release operation is available
through owner commands in Telegram Saved Messages. The default is `false`; disabled runtimes do not
register the outgoing event handler. When enabled, the handler accepts outgoing commands only when
the chat matches the logged-in account. `/gatekeeper cases` resolves at most five live identities and
sends metadata-only case cards; it does not decrypt or copy Active Case message evidence. Each
actionable card's Telegram message ID maps to a derived sender key in process memory for 15 minutes.
Replying to that exact card with `/gatekeeper allow` consumes the mapping, rechecks the restriction
under the sender lock, restores the dialog, allows the sender, and cancels pending work. Restart,
expiry, or a newer case listing invalidates earlier mappings. Because Telegram may not deliver
another device's outgoing Saved Messages as a real-time update, the enabled runtime also advances an
in-memory message-ID cursor by polling only messages newer than its startup baseline every three
seconds. Real-time and polled paths share a 15-minute message-ID deduplication map, so a delayed update
cannot execute a command twice. The cursor is never persisted, preventing pre-start commands from
replaying after a restart.

Each processed command and every reply or case card created for it are collected as one artifact set.
Schema 7 persists only the Telegram message IDs, deletion deadlines, and retry counts. A maintenance
loop deletes due batches after 15 minutes, removes rows only after Telegram confirms deletion, and
uses capped exponential backoff after failures. Restarting the service recovers the queue. To repair
artifacts left by the older process-local implementation, startup performs a seven-day bounded search
using only `/gatekeeper`, `Gatekeeper`, and `restriction`; it schedules only outgoing, non-forwarded
messages whose complete text matches a known command or generated-response template. Fetched text is
not persisted or logged, and general Saved Messages are not enumerated.

## Implemented action policy

| Input | Monitor mode | Protect mode |
| --- | --- | --- |
| Trusted sender | Allow | Allow |
| Score below 30 | Queue simulated standard challenge | Standard challenge |
| Score at least 30 without destructive gate | Queue simulated strict challenge | Strict one-attempt challenge |
| Score at least 70 with destructive gate | Queue planned permanent suppression | Persist, delete, and suppress indefinitely |
| Provisional sender without new evidence | Retain provisional state | Retain provisional state |
| Provisional sender with new evidence | Reapply adaptive policy | Reapply adaptive policy |
| Challenge send limit reached | Not applicable | Archive, mute, and queue review |
| Manual legitimate review | Allow sender | Allow sender |
| Manual spam review | Explicit permanent suppression and deletion | Explicit permanent suppression and deletion |
| Dedicated test sender | Run the real challenge flow | Run the real challenge flow |

Whole-dialog deletion is used for permanent suppression and warned challenge failure.
Pending deletions persist across restart and execute only when mode, sender status, and state revision still
match. Dedicated-test-sender deletions and explicit manual spam decisions are intentionally
mode-independent; automatic policy jobs are cancelled by `mode monitor`. Blocking, reporting, model
inference, and unrelated conversation cleanup are not implemented.

## Data boundaries

The persistent store contains sender state, challenge metadata, generated challenge prompts while
delivery is incomplete, evidence-signal metadata, timestamps, action outcomes, structural review
features,
automated outgoing message IDs, encrypted short-lived Telegram references, the prior archive and
notification settings needed to reverse a Gatekeeper action, encrypted restriction-lifetime control
identities, pending action jobs, suppression state, privacy-safe detector decisions, and encrypted
Active Case envelopes. The state database does not store message bodies, quoted text, raw
identities, or profile data in plaintext.

The `campaign_events` table contains only a keyed HMAC fingerprint, an already-derived sender key,
and an observation time. A candidate is created only for promotional content containing at least two
distinct URLs. The canonical template preserves normalized surrounding text and link kinds while
discarding domains, paths, queries, and invitation tokens. Matching rows are pruned after 7 days and
count distinct senders through a composite primary key. The canonical template exists only in memory
before HMAC derivation.

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
URL shape, evidence signals, risk score, challenge profile, decision basis, policy version, and
structural features, but never verification answers, webpage bodies, or media. Snapshots expire after
no more than 30 days and are removed sooner after successful verification, rollback, or manual
allowance.

Schema 1 through 4 Active Case snapshots remain read-only compatible. The dashboard labels them
`Legacy HR Decision · recorded under rules-v2; not recalculated`; migration does not recalculate
their scores, replace their evidence, or schedule any new action.

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
