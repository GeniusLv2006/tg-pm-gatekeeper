# tg-pm-gatekeeper

A self-hosted Telegram userbot that screens unsolicited private messages with deterministic local
rules, an owner-only review queue, and optional arithmetic challenges.

> [!IMPORTANT]
> This software controls a Telegram user session. A stolen session grants account access. Read
> [SECURITY.md](SECURITY.md) before deployment and use a dedicated Telegram account for the first
> end-to-end test.

## What it does

Gatekeeper watches incoming private messages from senders who are not already trusted. It does not
open links, send message content to third parties, call an AI service, block users, or expose a public
administration port.

The project is pre-release and tracks the latest commit on `main`.

| Mode | Unknown senders | Critical deterministic rules | Telegram changes |
| --- | --- | --- | --- |
| `monitor` (default) | Add a simulated challenge to the review queue | Add a planned deletion to the review queue | None |
| `protect` | Archive, mute, and send an arithmetic challenge | Delete the private dialog and suppress the sender | Yes |

`monitor` has one explicit exception: if `TG_TEST_SENDER_ID` names a dedicated test account, that
account follows the real challenge and cleanup path in either mode. Leave this setting empty in a
normal deployment.

The arithmetic check is interaction friction, not a CAPTCHA or proof that a sender is human.

`quarantined` and `suppressed` are local enforcement states, not Telegram blocks. Quarantine means
the dialog is archived and muted for manual review. Suppression additionally discards later messages
and may delete the whole dialog; it lasts 24 hours after a timeout, seven days after exhausted
attempts, or indefinitely after a critical rule.

## Safe quick start

These steps assume a trusted workstation with Git, SSH, `curl`, and Python 3.14, plus a dedicated
Debian-compatible host with Docker Engine and the Compose plugin.

1. Enable Telegram two-step verification and create an application API ID and hash through
   [Telegram's developer tools](https://my.telegram.org/apps).
2. Clone the repository on the trusted workstation and install the pinned dependencies:

   ```shell
   git clone https://github.com/GeniusLv2006/tg-pm-gatekeeper.git
   cd tg-pm-gatekeeper
   python3 -m venv .venv
   .venv/bin/python -m pip install --require-hashes --no-deps -r requirements-build.txt
   .venv/bin/python -m pip install --require-hashes --no-deps --no-build-isolation -r requirements.txt
   ```

3. Create the Telegram session, HMAC key, evidence key, private configuration, and denylist:

   ```shell
   .venv/bin/python scripts/initialize.py
   ```

   The command refuses to overwrite existing output. It hides the API hash, login code, and 2FA
   password while prompting; the API ID and phone number remain visible in the terminal. Never print,
   commit, or share the generated files.

4. Follow [docs/deployment.md](docs/deployment.md) to prepare the host, transfer the generated files,
   build the container, and verify the isolation boundary.
5. Keep the service in its fresh-database default `monitor` mode. Send test messages, inspect the
   redacted status, and open the Operations Dashboard through the SSH tunnel.
6. Enable `protect` on the deployment host only after the monitor results and preflight are
   understood:

   ```shell
   ssh "$DEPLOY_HOST" 'cd /opt/tg-pm-gatekeeper && docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli mode protect'
   ```

An existing state database preserves its current mode across rebuilds. Always check `status` before
and after an update; rebuilding a container does not force it back to `monitor`.

## Runtime flow

```text
incoming private message
  -> service account, bot, contact, allowed sender, or trusted prior conversation? allow
  -> deterministic critical rule matched?
      monitor: queue a planned deletion
      protect: silently delete the dialog and suppress the sender
  -> ordinary or high-risk unknown sender
      monitor: queue a simulated challenge
      protect: send a randomized addition, subtraction, or multiplication check
          -> archive and mute while pending
          -> correct direct Reply: restore the dialog and clear verification messages
          -> account owner replies later: allow the sender permanently
          -> timeout: warn, delete after 10 seconds, suppress for 24 hours
          -> attempts exhausted: warn, delete after 10 seconds, suppress for 7 days
          -> outbound limit reached: archive, mute, and queue manual review
```

The challenge response window starts after Telegram confirms prompt delivery. Replies to another
message and non-numeric input do not consume an attempt. At most one corrective hint is sent per
challenge.

## Operations Dashboard

The dashboard is served on an owner-only Unix socket. Docker publishes no TCP port; access it from a
trusted workstation through the supplied SSH tunnel:

```shell
scripts/dashboard-tunnel.sh root@server.example
```

The home page is an **Operations Dashboard** with three primary areas:

- **Active Cases** for current `quarantined` and `suppressed` senders that may need release;
- **Pending Reviews** for manual review rows created in monitor mode or fallback paths; and
- **Evidence Log** for short-lived encrypted audit evidence.

The pending-review queue is sender-centric, not a conversation archive:

- one pending row represents one sender;
- `Messages observed` is the number of messages consolidated into that row;
- the Telegram ID comes from the encrypted pending reference;
- names and usernames are resolved live and cached only in process memory;
- opening a row fetches exactly one referenced message from Telegram; and
- this pending-review path does not persist the fetched message body or profile data.

A newer message normally becomes the retained reference. An earlier simulated quarantine remains
representative when a later message has lower severity.

Deleting a conversation in Telegram does not automatically remove its pending local review. If the
referenced message is gone, opening the row shows an unavailable-message state with **Resolve deleted
conversation**. Resolving removes the pending review and encrypted reference without allowing,
quarantining, or otherwise changing the sender.

Review decisions apply to all pending entries for that sender:

- **Legitimate** restores a Gatekeeper-archived dialog when necessary and allows the sender.
- **Spam** archives and mutes the dialog, then marks the sender quarantined.
- **Dismiss** records no classification and performs no new Telegram action.

Every decision immediately erases the encrypted Telegram reference. Pending references expire after
at most seven days. See [docs/deployment.md](docs/deployment.md#operations-dashboard) for tunnel options
and operational details.

The **Active Cases** page covers current quarantines and suppressions. For up to seven days it can
decrypt the original triggering text/caption, Telegram-provided quoted context and webpage preview,
button text, full URLs, normalized domains, URL shape, matched rules, and a short-lived peer
reference. Full URLs are collapsed by default in the UI. **Allow now** restores the saved archive and
notification state before allowing the sender; **Keep current restriction** records an operator
decision and changes nothing. Successful verification, manual allowance, suppression expiry, and
rollback erase the encrypted snapshot immediately. Media is never copied into the snapshot, webpage
bodies are never fetched, and the project does not call Telegram's block API. Its summary separates
total local restriction states from reviewable encrypted evidence. Older states without evidence
remain counted, show their best available historical reason, and are explicitly identified as
unavailable for detail review.

## Deterministic rules

Critical rules delete a dialog only in `protect` mode:

- multiple URL, login, or WebView buttons from an unknown sender;
- forwarded content containing a URL, login, or WebView button; and
- an optional locally maintained denied domain, including its subdomains.

High-risk rules follow the normal challenge path:

- gambling, crypto-promotion, or VPN/proxy-promotion language combined with a link;
- multiple normalized links or domains combined with forwarding or promotional language; and
- quoted crypto transfer or service promotions with multiple commercial signals.

A repeated link within 60 seconds is a signal but does not independently trigger deletion. A single
ordinary link button, a forwarded plain link, or multiple links without another risk signal follows
the ordinary unknown-sender path. Use [deny-domains.example.txt](deny-domains.example.txt) as the
format reference for local denied domains.

## Operator commands

Run commands inside the deployed container:

```shell
docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli status
docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli mode monitor
docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli mode protect
docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli allow USER_ID
docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli revoke USER_ID
```

`mode monitor` cancels non-test pending destructive jobs and moves them to the exception queue.
`mode protect` runs a health and active-state preflight. `allow` refuses active challenges and
Gatekeeper quarantines because the CLI cannot restore Telegram state; resolve those senders as
**Legitimate** in the dashboard. A raw user ID supplied as a CLI argument may remain in shell history.

Status includes privacy-safe seven-day counters for prompts, correct answers, invalid replies,
timeouts, exhausted attempts, and restoration failures. It contains no raw sender identity or message
content.

### Dedicated test sender

`TG_TEST_SENDER_ID` may name one dedicated Telegram account for repeated arithmetic-flow testing.
It bypasses contacts, trusted history, hard-rule shortcuts, `monitor`, and the outbound quota.

After a pass, Gatekeeper clears the verification exchange and resets the test sender after 60 seconds.
Exhausted attempts warn and delete the entire test dialog after 10 seconds. A test-account timeout
warns, keeps the dialog archived and muted, deletes only messages recorded for that challenge, and
then resets the state. Never configure a real correspondent as the test sender.

## Optional encrypted Evidence Log

Evidence collection is off by default. When enabled, Gatekeeper retains short-lived encrypted review
evidence for eligible unknown-sender messages containing text/captions, Telegram-provided quoted or
webpage-preview text, or a detector signal. Evidence is for manual review and rule auditing, not
model training. Encrypted records may include text/caption, quoted text, Telegram preview text,
button display text, full URLs, normalized domains, aggregate URL shape, Telegram link kind,
detector signals, structural features, and planned/actual action.

Collection is capped at three unexpired records per sender for seven days by default. This is not a
rolling “latest three”: after a sender reaches the cap, later messages are ignored until a record
expires or is deleted. Monitor mode can gradually reach the cap; protect mode normally collects only
the first message before the sender enters a challenge or enforcement state. Records use
AES-256-GCM under an independent key. Media, webpage bodies, profile data, raw IDs, access hashes,
and the dedicated test sender are excluded. Message bodies, URLs, and button text are not written to
logs or SQLite plaintext columns.

```shell
docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli evidence status
docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli evidence purge --confirm DELETE-ALL-SAMPLES
```

The dashboard reports rolling collection and skip counts, explains structural-only evidence, and
supports operator outcomes: Correct Enforcement, False Positive, and Insufficient Evidence.
Plaintext export is intentionally not provided.

## Documentation

- [Hardened deployment](docs/deployment.md): installation, updates, configuration, and recovery.
- [Architecture](docs/architecture.md): states, decisions, storage, and failure behavior.
- [Security policy](SECURITY.md): data boundaries, vulnerability reporting, and incident response.
- [Release policy](docs/RELEASE.md): validation, publication, and deployment requirements.
- [Contributing](CONTRIBUTING.md): commit, testing, licensing, and pull-request rules.

## Local validation

```shell
PYTHONPATH=src .venv/bin/python -m unittest discover -v
PYTHONPATH=src .venv/bin/python -m compileall -q src tests scripts
docker build --tag tg-pm-gatekeeper:test .
git diff --check
```

Runtime dependencies and the Python base image are pinned. The container runs as UID/GID `10001`,
uses a read-only root filesystem, drops all capabilities, and exposes no network port.

## License

This project is licensed under the [Mozilla Public License 2.0](LICENSE). MPL-2.0 applies copyleft at
the file level: distributed modifications to covered files remain available under MPL-2.0, while
separate files in a larger work may use other terms.
