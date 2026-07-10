# Security

Gatekeeper controls a Telegram user session. Protect that session as you would protect the account
itself: Telegram two-step verification does not invalidate a session that has already been stolen.

## If you run Gatekeeper

- Use a dedicated server and restrict administrator access.
- Keep the Telegram session, HMAC key, evidence key, configuration, state, and backups out of source
  control and general backup jobs.
- Keep the dashboard behind the supplied SSH tunnel. Do not publish its Unix socket through Docker or
  a reverse proxy.
- Start in `monitor` and use a dedicated account for the first destructive-flow test.
- Run the [post-install security checks](docs/deployment.md#confirm-the-security-settings) before
  enabling `protect`.

Root access to the server is equivalent to access to the Telegram account. Container isolation cannot
protect the session from the host administrator.

## Report a vulnerability

Use GitHub's private vulnerability reporting for this repository when available. Do not open a public
issue containing credentials, session data, personal messages, phone numbers, or exploit details.

If private reporting is unavailable, open a public issue that requests a private contact channel but
contains no sensitive technical details.

## Keep sensitive data out of GitHub

Never commit these values, including in examples, fixtures, logs, screenshots, or Git history:

- Telegram API IDs, API hashes, login codes, two-factor passwords, or session files;
- phone numbers, private-conversation usernames, contact lists, or user IDs;
- message text, media, real deployment allowlists or denylists, moderation databases, or audit logs;
  and
- deployment credentials, private keys, environment files, or backups.

If a secret is committed, deleting it in a later commit is not enough. Revoke or rotate it first,
then remove it from the complete Git history.

## If a Telegram session may have leaked

1. Stop the Gatekeeper container.
2. Terminate the affected session from an official Telegram client.
3. Delete the server-side session file.
4. Generate and provision a new session from a trusted computer.
5. Confirm the old Telegram authorization is gone before restarting Gatekeeper.
6. Remove leaked material from Git history, logs, or backups only after access has been revoked.

Exact operator commands are in
[Emergency session revocation](docs/deployment.md#emergency-session-revocation).

## Technical security model

This section documents guarantees that contributors must preserve. For the full state and decision
flow, see [Architecture](docs/architecture.md).

### Credentials and identities

- The Telegram StringSession is a mode `0600` file owned by the service UID.
- The runtime uses a Telethon StringSession instead of its SQLite session, so names, usernames, and
  phone numbers are not retained in a Telethon entity cache.
- Sender state uses an HMAC-derived identifier rather than a raw Telegram user ID.
- The runtime database may store Telegram message IDs, generated challenge text while delivery is
  incomplete, and authenticated encrypted short-lived references needed for review and recovery.
- Raw user IDs, usernames, profile names, and message content are not stored in plaintext.

### Encrypted review content

- Active quarantines and suppressions may retain an AES-256-GCM encrypted snapshot for at most seven
  days. It can include text/caption, Telegram-provided quoted and preview text, button text, full URLs,
  normalized domains, URL shape, matched rules, and structural features.
- Optional Evidence Log records use a separate owner-only database and independent evidence key.
  Eligible encrypted content can include message/caption, Telegram-provided quote and preview text,
  button text, full URLs, normalized domains, Telegram link kind, URL-shape metadata, detector signals,
  and structural features.
- Webpage bodies, media, profile data, raw IDs, access hashes, and the dedicated test sender are not
  included in Evidence Log records.
- The evidence key derives a separate Active Case review key through HKDF. Evidence Log and Active
  Case records use different authenticated-data domains and tables.
- Evidence collection is capped per anonymous sender, defaults to seven-day retention, and is bounded
  to 90 days. Daily collection statistics contain counts only.
- Plaintext evidence export is not provided. Dashboard responses use `Cache-Control: no-store`, but
  decrypted content is still visible to the owner and can be captured by browser memory, screenshots,
  or a compromised workstation.

### Actions and failure handling

- Arithmetic verification adds interaction friction; it is not a CAPTCHA or proof that a sender is
  human.
- Message handling, challenge timeout, recovery, and review transitions are serialized per derived
  sender identifier.
- Exhausting the outbound-message limit must not bypass screening.
- Whole-dialog deletion is represented by a persistent action tied to an expected sender-state
  revision. Normal deletion jobs run only in `protect`; switching to `monitor` cancels them.
- `TG_TEST_SENDER_ID` is the only mode-independent exception: exhausted attempts can delete that
  dedicated test dialog in either mode. Never assign a real correspondent to this setting.
- The application must not expose a listening TCP port or mount the Docker socket.

## Supported versions

The project has not reached a stable release. Security fixes apply only to the latest commit on the
default branch until a versioning policy is established.
