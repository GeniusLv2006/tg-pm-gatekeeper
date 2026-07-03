# tg-pm-gatekeeper

A self-hosted, monitor-first Telegram userbot for screening unsolicited private messages with
deterministic rules and optional challenge protection.

> [!IMPORTANT]
> This software controls a Telegram user session. A stolen session grants account access. Read
> [SECURITY.md](SECURITY.md) and test with a dedicated account before using a personal account.

## Project status

The project is pre-release and tracks the latest commit on `main`. The implemented runtime:

- starts in `monitor` mode and does not change Telegram dialogs automatically;
- evaluates deterministic, local rules without opening links or sending message content elsewhere;
- groups review work by sender, resolves identity live without database persistence, and serves the
  queue through an SSH-forwarded, owner-only Unix socket;
- can be explicitly switched to `protect` mode to challenge ordinary/high-risk unknown senders and
  silently delete conversations that match critical deterministic rules; and
- deletes only verification-flow messages after a pass or, after a 10-second warning, a failed
  sender's private dialog when attempts are exhausted or time out; it does not block, report, call an AI
  service, or expose a public administration port.
- can optionally retain the first three unknown-sender texts in a separate AES-GCM encrypted,
  expiring local dataset for review, labeling, and offline export.

## Runtime flow

```text
incoming private message
  -> service account, bot, contact, allowed sender, or trusted prior conversation? allow
  -> deterministic critical rule matched?
      monitor: record the planned deletion
      protect: silently delete and suppress the sender
  -> ordinary unknown sender
      monitor: enqueue a simulated challenge for review
      protect: send one randomized addition, subtraction, or multiplication check
          -> archive and mute while pending
          -> direct Reply with the correct answer: restore dialog, clear verification messages,
             and keep screening
          -> account owner replies later: allow sender permanently
          -> timeout: warn, delete after 10 seconds, suppress for 24 hours
          -> two incorrect answers: warn, delete after 10 seconds, suppress for 7 days
          -> challenge send limit reached: archive, mute, and queue for manual review
```

The arithmetic check is interaction friction, not a CAPTCHA. It filters senders that do not respond
to instructions, but it does not claim to distinguish a person from automation. The default mode is
monitor-only. Protection is a deliberate CLI action guarded by a runtime preflight.

The challenge uses Telegram-native bold formatting for its warning title, deadline, expression, and
attempt count. Its configured response window starts after Telegram confirms prompt delivery. A
single corrective hint covers wrong Reply targets or non-numeric input without consuming an attempt
or allowing one sender to exhaust the global outbound budget with repeated hints.

## Review dashboard

Monitor mode places simulated challenge and quarantine decisions in a local review queue. The
review dashboard is served only through an owner-only Unix socket and is reached with an SSH tunnel;
the container exposes no TCP port.

The queue is intentionally sender-centric:

- one pending row represents one sender, not one message;
- `Messages observed` is the number of messages consolidated into that row;
- the detail page fetches and displays exactly one referenced Telegram message, not conversation
  history;
- a newer message normally replaces the retained reference, while an earlier simulated quarantine
  remains the representative item when a later lower-risk message arrives;
- the queue resolves names, usernames, and Telegram IDs live, keeps profile names only in a
  short-lived process-memory cache, and never writes them to the database or application logs; and
- message bodies are rendered from Telegram only when the detail page opens and are not written to
  the database or application logs.

Choosing **Legitimate**, **Spam**, or **Dismiss** resolves the sender's pending work and immediately
erases the reversible Telegram reference. Legitimate also restores a dialog previously archived by
Gatekeeper's challenge-rate fallback. The non-content decision record remains subject to normal
retention.

From a trusted workstation, open the review tunnel with an explicit SSH target:

```shell
scripts/review-tunnel.sh root@server.example
```

The target, local port, remote socket, and alternate SSH configuration are configurable. Run the
helper with `-h` or see [docs/deployment.md](docs/deployment.md) for the complete interface.

When encrypted dataset collection is enabled, the same dashboard exposes a separate **Dataset**
area. Queue pages show only sample metadata; opening a sample decrypts its authored text in memory.
Samples can be labeled Spam, Legitimate, or Uncertain, or deleted individually. The dashboard does
not train a model and does not calculate ML metrics.

## Deterministic rule tiers

Critical rules silently delete in protect mode:

- multiple URL, login, or WebView buttons from an unknown sender
- forwarded content containing a URL, login, or WebView button
- optional locally maintained denied domains; a configured missing or invalid file stops startup

High-risk rules enter the normal challenge flow:

- gambling, crypto-promotion, or VPN/proxy-promotion language combined with a link
- multiple normalized links or domains combined with forwarding or promotional language
- quoted crypto transfer/service promotions with multiple commercial signals

Repeated link messages within 60 seconds are retained as a signal only and do not independently
trigger deletion.

A single ordinary link button, a forwarded plain link, or multiple links without another risk
signal follows the normal unknown-sender challenge path instead of causing immediate quarantine.
Quoted URLs and promotional language do not participate in the generic authored-message rules; the
dedicated quoted crypto-service rule remains intentionally separate.

## Security principles

- Never commit Telegram session files, API credentials, phone numbers, message databases, allowlists, logs, or backups.
- Keep secrets outside the repository and provide only redacted configuration examples.
- Treat a user-session file as an account credential.
- Minimize stored message content and keep an auditable reason for every automated action.
- Treat arithmetic verification as a reversible interaction check, not proof that a sender is human.
- Expire encrypted review references after at most seven days and erase them immediately after a
  review decision.
- AI-based classification, if added, must not directly trigger irreversible actions.
- Test authorization and rate-limit handling with a dedicated test account before using a personal account.

## Operator commands

Run commands inside the deployed container:

```shell
docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli status
docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli mode monitor
docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli mode protect
docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli allow USER_ID
docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli revoke USER_ID
```

`mode monitor` cancels pending destructive jobs and moves them to the exception queue. `mode protect`
runs a health and active-state preflight before enabling Telegram actions. `allow` and `revoke` derive the stored sender
key inside the container, but the raw ID supplied on the command line may still enter shell history.
`allow` refuses senders with an active/incomplete challenge or a Gatekeeper quarantine because the
CLI cannot restore Telegram state; resolve those senders as **Legitimate** in the review dashboard.

For repeated arithmetic-flow testing, `TG_TEST_SENDER_ID` may name one dedicated Telegram account.
That account always follows the real challenge path, even in monitor mode or when it is a
contact with prior outgoing history, and its test notices do not consume the global outbound quota.
After a pass, Gatekeeper clears the verification exchange and resets the test sender state to
unknown after 60 seconds. Exhausting the numeric attempts sends a failure notice stating that the
conversation will be deleted, waits 10 seconds, deletes the entire private conversation for both
sides, and schedules the same state reset. A timeout still sends a failure notice, keeps the dialog
archived and muted, deletes only the messages recorded for that timed-out challenge after 10 seconds,
and resets the sender state after 60 seconds. Leave the setting empty in normal deployments.

The status response includes seven-day aggregate challenge counters for prompts sent, correct
answers, wrong Reply targets, non-numeric replies, timeouts, exhausted attempts, and restoration
failures. These counters contain no sender identity or message content.

## Optional encrypted dataset

Dataset collection is off by default. When enabled, authored text or captions from at most the first
three messages per unknown sender are stored in `/var/lib/tg-pm-gatekeeper/training.sqlite3` for 30
days by default. Payloads use AES-256-GCM under an independent dataset key. Media, quoted text,
names, usernames, raw Telegram IDs, access hashes, and the dedicated test sender are excluded.

```shell
docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli samples status
docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli samples export /var/lib/tg-pm-gatekeeper/training.jsonl
docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli samples purge --confirm DELETE-ALL-SAMPLES
```

Exports are owner-only plaintext JSONL intended for immediate transfer to a trusted workstation and
prompt deletion from the server. This release provides collection, labeling, and export only; it
does not train, load, or execute an ML model.

See [SECURITY.md](SECURITY.md) before reporting a security issue,
[docs/architecture.md](docs/architecture.md) for the design, and
[docs/deployment.md](docs/deployment.md) for the hardened deployment procedure. Release and
deployment decisions are defined in [docs/RELEASE.md](docs/RELEASE.md). Contributions must follow
[CONTRIBUTING.md](CONTRIBUTING.md), including the Conventional Commits requirement.

## Deployment overview

Use Python 3.14 on a trusted workstation to create the Telegram StringSession, server-local HMAC
key, and independent dataset key. The initializer refuses to overwrite existing output files:

```shell
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes --no-deps -r requirements-build.txt
.venv/bin/python -m pip install --require-hashes --no-deps --no-build-isolation -r requirements.txt
.venv/bin/python scripts/initialize.py
```

Provision the generated files onto a Docker host, build with `docker compose`, verify `monitor`
mode, and only then open the review tunnel. Follow
[docs/deployment.md](docs/deployment.md) for exact permissions, transfer commands, boundary checks,
and emergency session revocation. Do not improvise secret paths or publish the review socket.

## Local checks

```shell
PYTHONPATH=src .venv/bin/python -m unittest discover -v
PYTHONPATH=src .venv/bin/python -m compileall -q src tests scripts
docker build --tag tg-pm-gatekeeper:test .
```

Runtime dependencies and the Python base image are pinned. The container does not expose a network
port and starts as UID/GID `10001` with a read-only root filesystem.

After installing the pinned dependencies, local credential initialization is a single interactive
command:

```shell
.venv/bin/python scripts/initialize.py
```

The generated files are mode `0600`, ignored by Git, and must never be printed or shared.

## License

No license has been selected. All rights are reserved until a license is added.
