# tg-pm-gatekeeper

A self-hosted Telegram userbot that screens unsolicited private messages with local rules, an
owner-only review dashboard, and optional arithmetic challenges.

> [!IMPORTANT]
> Gatekeeper controls a Telegram user session. Anyone who steals that session can access the account.
> The project is pre-release and currently follows the latest commit on `main`. Use a dedicated
> Telegram account for your first end-to-end test.

## Is Gatekeeper right for you?

Gatekeeper may be useful if you:

- receive unwanted Telegram private messages;
- are comfortable maintaining a small Docker service over SSH; and
- want screening to stay on infrastructure you control.

It may not be a good fit if you need a hosted or one-click service, are unfamiliar with SSH and
Docker, or cannot test destructive behavior with a dedicated Telegram account.

You need a trusted computer with Git, SSH, `curl`, and Python 3.14, plus a dedicated
Debian-compatible server with Docker Engine and the Compose plugin.

## What it does

Gatekeeper watches incoming private messages from people who are not already trusted. It does not
open links, send message content to third parties, call an AI service, block users, or expose a
public administration port.

| Mode | What happens to unknown senders | Telegram changes |
| --- | --- | --- |
| `monitor` (default) | Records what Gatekeeper would have done for your review | None |
| `protect` | Archives and mutes the dialog, then sends an arithmetic challenge | Yes |

Critical local rules can delete a private dialog in `protect` mode. Gatekeeper warns before deleting
a dialog after failed or expired verification. The arithmetic check adds interaction friction; it is
not a CAPTCHA or proof that a sender is human.

## First installation

1. Enable Telegram two-step verification and create an application API ID and hash through
   [Telegram's developer tools](https://my.telegram.org/apps).
2. Clone the repository on your trusted computer and install the pinned dependencies:

   ```shell
   git clone https://github.com/GeniusLv2006/tg-pm-gatekeeper.git
   cd tg-pm-gatekeeper
   python3 -m venv .venv
   .venv/bin/python -m pip install --require-hashes --no-deps -r requirements-build.txt
   .venv/bin/python -m pip install --require-hashes --no-deps --no-build-isolation -r requirements.txt
   ```

3. Sign in to Telegram and create the private files needed by the server:

   ```shell
   .venv/bin/python scripts/initialize.py
   ```

   The initializer hides your API hash, login code, and 2FA password while prompting. It refuses to
   overwrite existing output. Transfer the generated files only to the intended server over a trusted
   channel; never print, commit, paste, or share their contents.

4. Follow the [installation guide](docs/deployment.md#install-gatekeeper) to prepare the server,
   transfer the files, and start the container.
5. Leave the new installation in `monitor` mode while you send test messages and inspect the
   dashboard.
6. Switch to `protect` only after the installation checks pass and you understand the destructive
   paths:

   ```shell
   ssh "$DEPLOY_HOST" 'cd /opt/tg-pm-gatekeeper && docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli mode protect'
   ```

## How to know it is working

Your first installation is complete when:

- `docker compose ps` shows the `gatekeeper` container as healthy;
- `status` reports `"mode":"monitor"`;
- the Operations Dashboard opens through the supplied SSH tunnel;
- a message from a separate, unknown test account appears under **Pending Reviews**; and
- the deployment checks show no public Gatekeeper port.

The [installation guide](docs/deployment.md#confirm-the-installation) provides the exact commands and
explains what to do when a check fails.

## Operations Dashboard

The dashboard is available only through an SSH tunnel; Docker publishes no Gatekeeper port:

```shell
scripts/dashboard-tunnel.sh root@server.example
```

It has three main areas:

- **Active Cases**: review current restrictions that still have short-lived encrypted evidence;
- **Pending Reviews**: resolve monitor-mode simulations and protect-mode exceptions; and
- **Evidence Log**: review optional encrypted evidence collected for rule auditing.

One Pending Reviews row represents one sender, not a conversation history. Opening a row fetches one
referenced Telegram message. **Legitimate · Allow Sender** allows the sender, **Spam · Archive and
Mute** archives and mutes the dialog, and **Dismiss and Cancel Pending Jobs** closes the review and
cancels pending Gatekeeper deletion jobs without changing the current trust decision.

See [Dashboard and daily operation](docs/deployment.md#dashboard-and-daily-operation) for the detailed
behavior and tunnel options.

## What protect mode does

```text
incoming private message
  -> already trusted? allow
  -> critical local rule? delete the dialog and suppress the sender
  -> otherwise archive and mute, then send an arithmetic challenge
      -> correct direct Reply: restore the dialog
      -> owner replies later: trust the sender
      -> timeout: warn, delete after 10 seconds, suppress for 24 hours
      -> attempts exhausted: warn, delete after 10 seconds, suppress for 7 days
      -> outbound limit reached: keep archived and send to manual review
```

Critical rules currently cover multiple interactive link buttons, forwarded interactive link
buttons, and optional locally denied domains. High-risk promotional and multi-link patterns follow
the normal challenge path. The full rule and state behavior is documented in
[Architecture](docs/architecture.md).

## Common operator commands

Run these inside the deployed repository:

```shell
docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli status
docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli mode monitor
docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli mode protect
docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli allow USER_ID
docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli revoke USER_ID
```

Returning to `monitor` cancels non-test pending destructive jobs. The CLI refuses `allow` for active
challenges, quarantines, and suppressions because it cannot safely restore the Telegram dialog; use
**Legitimate · Allow Sender** in the dashboard instead. A raw user ID supplied on the command line
may remain in shell history.

## Optional features

### Dedicated test sender

`TG_TEST_SENDER_ID` lets one dedicated account exercise the real challenge and cleanup flow even in
`monitor`. It can delete the test dialog after exhausted attempts. Do not assign a real correspondent;
remove the setting when testing is complete. See
[Dedicated test sender](docs/deployment.md#dedicated-test-sender).

### Encrypted Evidence Log

Evidence collection is off by default. When enabled, it stores a small number of short-lived encrypted
records for manual rule review. It does not fetch webpages, copy media, export plaintext, train a
model, or include the dedicated test sender. See
[Encrypted Evidence Log](docs/deployment.md#optional-encrypted-evidence-log) before enabling it.

## Documentation

### I want to run Gatekeeper

- [Install, update, and troubleshoot](docs/deployment.md)
- [Security checklist and incident response](SECURITY.md)
- [Architecture and detailed behavior](docs/architecture.md)

### I maintain or contribute to Gatekeeper

- [Contributing](CONTRIBUTING.md)
- [Maintainer release policy](docs/RELEASE.md)
- [Local validation](#local-validation)

## Local validation

Maintainers and contributors can run the same checks used by CI:

```shell
PYTHONPATH=src .venv/bin/python -m unittest discover -v
PYTHONPATH=src .venv/bin/python -m compileall -q src tests scripts
docker build --tag tg-pm-gatekeeper:test .
git diff --check
```

Runtime dependencies and the Python image are pinned. The container runs as UID/GID `10001`, uses a
read-only root filesystem, drops all capabilities, and exposes no network port.

## License

This project is licensed under the [Mozilla Public License 2.0](LICENSE). MPL-2.0 applies copyleft at
the file level: distributed modifications to covered files remain available under MPL-2.0, while
separate files in a larger work may use other terms.
