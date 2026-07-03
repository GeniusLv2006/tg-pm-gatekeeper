# Hardened deployment

This runbook covers a first installation, routine updates, schema migrations, dashboard access, and
emergency session revocation on a dedicated Debian-compatible Docker host. Read
[RELEASE.md](RELEASE.md) before publishing or deploying a change.

Examples use a root maintenance login. Set the target once for the current shell and verify it before
every operation:

```shell
export DEPLOY_HOST=root@server.example
```

## Prerequisites

Trusted workstation:

- Git, SSH, `curl`, and Python 3.14;
- Telegram two-step verification enabled;
- an application API ID and hash from [Telegram's developer tools](https://my.telegram.org/apps); and
- a dedicated Telegram account for the first end-to-end test.

Deployment host:

- a dedicated Debian-compatible Linux system; and
- Docker Engine with the Compose plugin.

Never paste credentials into shell commands, issues, pull requests, CI variables, or chat. Resource
and network observations are point-in-time facts and must be checked again at deployment.

## First installation

### Clone and initialize on the trusted workstation

```shell
git clone https://github.com/GeniusLv2006/tg-pm-gatekeeper.git
cd tg-pm-gatekeeper
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes --no-deps -r requirements-build.txt
.venv/bin/python -m pip install --require-hashes --no-deps --no-build-isolation -r requirements.txt
.venv/bin/python scripts/initialize.py
```

The initializer prompts visibly for the API ID and phone number and uses hidden prompts for the API
hash, login code, and 2FA password. It creates these owner-only files and refuses to overwrite any of
them:

- `telegram.session.secret`: the Telegram authorization session;
- `hmac.key`: sender-identity and review-reference protection;
- `dataset.key`: independent optional-dataset encryption;
- `config.env`: environment entries consumed by Compose; and
- `deny-domains.txt`: one normalized denied domain per line.

The files initially use mode `0600`. Never print, commit, or share their contents. The dataset key is
required at startup even while collection is disabled, so that enabling collection never reuses the
state HMAC key. See [the example denylist](../deny-domains.example.txt) for the accepted format.

### Prepare the host

Run the bootstrap script as root. It creates a non-login UID/GID `10001` and the fixed directories,
but no credentials:

```shell
ssh "$DEPLOY_HOST" 'sh -s' < deploy/bootstrap-host.sh
```

Clone the public repository anonymously:

```shell
ssh "$DEPLOY_HOST" 'git clone https://github.com/GeniusLv2006/tg-pm-gatekeeper.git /opt/tg-pm-gatekeeper'
```

Transfer the generated files to temporary root-only locations, install them with the required
ownership, and remove the temporary copies:

```shell
scp telegram.session.secret hmac.key dataset.key config.env deny-domains.txt "$DEPLOY_HOST":/tmp/
ssh "$DEPLOY_HOST" 'install -o 10001 -g 10001 -m 0600 /tmp/telegram.session.secret /etc/tg-pm-gatekeeper/telegram.session.secret && install -o 10001 -g 10001 -m 0600 /tmp/hmac.key /etc/tg-pm-gatekeeper/hmac.key && install -o 10001 -g 10001 -m 0600 /tmp/dataset.key /etc/tg-pm-gatekeeper/dataset.key && install -o root -g 10001 -m 0640 /tmp/config.env /etc/tg-pm-gatekeeper/config.env && install -o root -g 10001 -m 0640 /tmp/deny-domains.txt /etc/tg-pm-gatekeeper/deny-domains.txt && rm -f /tmp/telegram.session.secret /tmp/hmac.key /tmp/dataset.key /tmp/config.env /tmp/deny-domains.txt'
```

Do not include these files in a general server backup job.

### Build and start

Record the exact commit, then build and start the service:

```shell
ssh "$DEPLOY_HOST" 'cd /opt/tg-pm-gatekeeper && git checkout main && git pull --ff-only && git rev-parse HEAD && docker compose build --pull && docker compose up -d'
```

A fresh database starts in `monitor`. An existing database preserves its current mode across rebuilds.
Check health, mode, and redacted status explicitly:

```shell
ssh "$DEPLOY_HOST" 'cd /opt/tg-pm-gatekeeper && docker compose ps && docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli status'
```

Open the [review dashboard](#review-dashboard), exercise the intended rules with a dedicated account,
and verify the [deployment boundary](#verify-the-boundary). Enable protection only after those checks:

```shell
ssh "$DEPLOY_HOST" 'cd /opt/tg-pm-gatekeeper && docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli mode protect'
```

Return to `monitor` at any time to cancel non-test pending destructive jobs without stopping update
processing:

```shell
ssh "$DEPLOY_HOST" 'cd /opt/tg-pm-gatekeeper && docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli mode monitor'
```

## Routine updates

Before updating, confirm the checkout is clean, record the current commit, check container health, and
record the current mode. Do not assume that a rebuild changes the mode.

For runtime, dependency, Docker, or configuration changes:

```shell
ssh "$DEPLOY_HOST" 'cd /opt/tg-pm-gatekeeper && git status --short && git rev-parse HEAD && docker compose ps && docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli status && git pull --ff-only origin main && git rev-parse HEAD && docker compose up -d --build'
```

For host-only scripts or documentation, pull the reviewed commit without restarting a healthy
container. Follow [RELEASE.md](RELEASE.md) for the authoritative rebuild classification.

After any runtime update, verify the deployed commit, health, restart count, mode, redacted status,
logs, file permissions, Unix socket, and absence of unexpected port mappings.

### Schema-changing updates

Before a state-schema migration:

1. switch to `monitor`;
2. require `challenged`, `challenge_issuing`, and `challenge_archiving` to be zero; and
3. create a temporary remote-only SQLite backup with the online backup API.

```shell
ssh "$DEPLOY_HOST" 'cd /opt/tg-pm-gatekeeper && docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli mode monitor && docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli status'
ssh "$DEPLOY_HOST" 'cd /opt/tg-pm-gatekeeper && docker compose exec -T gatekeeper python -c '\''import os, sqlite3; source=sqlite3.connect("/var/lib/tg-pm-gatekeeper/state.sqlite3"); backup=sqlite3.connect("/var/lib/tg-pm-gatekeeper/state.pre-migration.sqlite3"); source.backup(backup); backup.close(); source.close(); os.chmod("/var/lib/tg-pm-gatekeeper/state.pre-migration.sqlite3", 0o600)'\'''
```

After rebuilding, verify `PRAGMA user_version`, state counts, and logs. Delete
`state.pre-migration.sqlite3` only after all checks pass. If migration fails, preserve the failed
database for diagnosis and restore the backup together with the prior image.

## Configuration reference

`scripts/initialize.py` writes the production defaults. [.env.example](../.env.example) is the public
reference. Compose overrides the fixed container paths for the state database, session, keys,
dataset, and denylist; host files remain under `/etc/tg-pm-gatekeeper` and
`/var/lib/tg-pm-gatekeeper`.

| Setting | Default | Constraint or purpose |
| --- | --- | --- |
| `TG_CHALLENGE_TTL_SECONDS` | `60` | 30–600 seconds |
| `TG_CHALLENGE_MAX_ATTEMPTS` | `2` | 1–5 numeric attempts |
| `TG_OUTBOUND_LIMIT_PER_HOUR` | `10` | 1–100 Gatekeeper messages per hour |
| `TG_AUDIT_RETENTION_DAYS` | `30` | Positive number of days |
| `TG_REVIEW_RETENTION_DAYS` | `7` | Positive; runtime hard-caps it at 7 days |
| `TG_REVIEW_SOCKET_PATH` | `/var/lib/tg-pm-gatekeeper/review.sock` | Owner-only server Unix socket |
| `TG_MUTE_DAYS` | `3650` | Positive quarantine mute duration |
| `TG_DATASET_COLLECTION` | `off` | `on` or `off` |
| `TG_DATASET_RETENTION_DAYS` | `30` | 1–90 days |
| `TG_DATASET_MAX_MESSAGES_PER_SENDER` | `3` | 1–10 samples |
| `TG_TEST_SENDER_ID` | empty | Positive ID of a dedicated test account only |

Changing private configuration requires recreating the container. Invalid bounded settings stop
startup instead of silently choosing a different value, except review retention above seven days is
clamped to the hard maximum.

### Dedicated test sender

Add a dedicated account's positive numeric ID to `/etc/tg-pm-gatekeeper/config.env`, then recreate
the container:

```shell
TG_TEST_SENDER_ID=REPLACE_WITH_DEDICATED_TEST_ACCOUNT_ID
```

This setting deliberately performs Telegram actions even in `monitor`, bypasses the normal outbound
quota, and can delete the dedicated test dialog after exhausted attempts. Never use a real
correspondent. Remove the value when testing is complete.

### Optional encrypted dataset

Collection is disabled by default. To retain at most three authored texts or captions per unknown
sender for 30 days:

```shell
TG_DATASET_COLLECTION=on
TG_DATASET_RETENTION_DAYS=30
TG_DATASET_MAX_MESSAGES_PER_SENDER=3
```

The Dataset dashboard decrypts text only on a sample detail page. It supports Spam, Legitimate, and
Uncertain labels plus individual deletion. It does not train a model.

Use `samples export` only for a temporary owner-only plaintext JSONL, transfer it immediately to a
trusted workstation, and remove the server copy. `samples purge --confirm DELETE-ALL-SAMPLES`
irreversibly deletes every retained sample.

## Review dashboard

The service has no TCP listener. From the local repository, open the supplied tunnel:

```shell
scripts/review-tunnel.sh "$DEPLOY_HOST"
```

The helper requires `ssh` and `curl`. It reads the short-lived owner-only `review.access-token`,
starts a dedicated local forward with SSH connection sharing disabled, and prints a one-time login URL
only after the authenticated dashboard responds. Keep the terminal open; `Ctrl+C` closes the tunnel.

The SSH target can be an alias or `user@host` and must be able to read the token and reach the remote
socket. Defaults may come from environment variables or flags:

```shell
TG_REVIEW_HOST=root@gatekeeper.example \
TG_REVIEW_PORT=18765 \
TG_REVIEW_SOCKET=/srv/gatekeeper/review.sock \
TG_REVIEW_TOKEN=/srv/gatekeeper/review.access-token \
TG_REVIEW_SSH_CONFIG="$HOME/.ssh/gatekeeper.conf" \
scripts/review-tunnel.sh
```

`TG_REVIEW_SOCKET` configures the workstation helper; `TG_REVIEW_SOCKET_PATH` configures the service.
If the service socket moves, update both values and keep the service path inside a writable mounted
directory. Run `scripts/review-tunnel.sh -h` for all flags.

The default local URL is `http://127.0.0.1:8765/`. The queue checks the server every 10 seconds. The
**Live connection** response timestamp and the next refresh—not a previously rendered page—show that
the tunnel is still connected.

The queue contains one row per sender and no message body. Telegram IDs come from encrypted pending
references; names and usernames are resolved live. Opening a row fetches one referenced message, not
conversation history. Available decisions are:

- **Legitimate**: restore a Gatekeeper archive when necessary and allow the sender.
- **Spam**: archive and mute the dialog, then quarantine the sender.
- **Dismiss**: record no classification and take no new Telegram action.

If the outbound challenge limit caused a quarantine, Legitimate restores the dialog, Spam preserves
the existing quarantine without repeating Telegram actions, and Dismiss leaves it unchanged. Every
decision erases all pending references for that sender. Stop the tunnel after review; never publish
the socket through Docker or a reverse proxy.

## Verify the boundary

The deployment is acceptable only when all checks pass:

```shell
ssh "$DEPLOY_HOST" 'docker inspect tg-gatekeeper --format "user={{.Config.User}} readonly={{.HostConfig.ReadonlyRootfs}} caps={{json .HostConfig.CapDrop}} ports={{json .HostConfig.PortBindings}} security={{json .HostConfig.SecurityOpt}}"'
ssh "$DEPLOY_HOST" 'ss -lnt'
ssh "$DEPLOY_HOST" 'stat -c "%a %u:%g %n" /etc/tg-pm-gatekeeper/telegram.session.secret /etc/tg-pm-gatekeeper/hmac.key /etc/tg-pm-gatekeeper/dataset.key /etc/tg-pm-gatekeeper/config.env /etc/tg-pm-gatekeeper/deny-domains.txt /var/lib/tg-pm-gatekeeper'
ssh "$DEPLOY_HOST" 'stat -c "%F %a %u:%g %n" /var/lib/tg-pm-gatekeeper/review.sock /var/lib/tg-pm-gatekeeper/review.access-token'
```

Expected values:

- user `10001:10001`, read-only root filesystem, all capabilities dropped, and
  `no-new-privileges`;
- no Docker port bindings and no application TCP listener;
- session and key files mode `600`;
- `config.env` and denylist mode `640`, owned by `root:10001`;
- state directory mode `700`, owned by `10001:10001`; and
- review socket and access token mode `600`, owned by `10001:10001`.

The access token is replaced on every service start.

## Emergency revocation

1. Stop the container over SSH: `docker compose stop gatekeeper`.
2. Terminate the session from an official Telegram client.
3. Remove `/etc/tg-pm-gatekeeper/telegram.session.secret`.
4. Generate and provision a new session from a trusted workstation.
5. Start the service only after confirming that the old authorization is absent from Telegram.
