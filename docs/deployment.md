# Install and operate Gatekeeper

This guide is for people installing or running Gatekeeper. You do not need to read the maintainer
[release policy](RELEASE.md) unless you are publishing code changes to the project.

Examples use a root maintenance login. Set your server once in the current shell:

```shell
export DEPLOY_HOST=root@server.example
```

## Before you start

On your trusted computer you need:

- Git, SSH, `curl`, and Python 3.14;
- Telegram two-step verification;
- an application API ID and hash from [Telegram's developer tools](https://my.telegram.org/apps); and
- a dedicated Telegram account for the first end-to-end test.

On the server you need a dedicated Debian-compatible Linux system with Docker Engine and the Compose
plugin.

Gatekeeper controls a Telegram user session and can delete private dialogs in `protect` mode. Start
in `monitor`, test with the dedicated account, and keep the generated session and key files out of
chat, tickets, screenshots, shell commands, and general backups.

## Install Gatekeeper

### 1. Create the private files

Run these commands on your trusted computer:

```shell
git clone https://github.com/GeniusLv2006/tg-pm-gatekeeper.git
cd tg-pm-gatekeeper
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes --no-deps -r requirements-build.txt
.venv/bin/python -m pip install --require-hashes --no-deps --no-build-isolation -r requirements.txt
.venv/bin/python scripts/initialize.py
```

The initializer signs in to Telegram and creates five files:

- `telegram.session.secret`: authorization for the Telegram account;
- `hmac.key`: protects local sender identifiers, review references, and restriction control identities;
- `review.key`: encrypts Active Case snapshots;
- `config.env`: the service configuration; and
- `deny-domains.txt`: your optional local domain denylist.

The files start with owner-only permissions, and the initializer refuses to overwrite them. Transfer
them only to the intended server over a trusted channel. The review key encrypts Active Case
snapshots and must remain separate from the HMAC key. See
[deny-domains.example.txt](../deny-domains.example.txt) for the denylist format.

### 2. Prepare the server

Create the service account and directories, then clone the public repository:

```shell
ssh "$DEPLOY_HOST" 'sh -s' < deploy/bootstrap-host.sh
ssh "$DEPLOY_HOST" 'git clone https://github.com/GeniusLv2006/tg-pm-gatekeeper.git /opt/tg-pm-gatekeeper'
```

The bootstrap script creates a non-login service user with UID/GID `10001`. It does not create or
copy credentials.

### 3. Transfer the private files

Copy the generated files to a temporary root-only location:

```shell
scp telegram.session.secret hmac.key review.key config.env deny-domains.txt "$DEPLOY_HOST":/tmp/
```

Install them with the ownership expected by Compose, then remove the temporary copies:

```shell
ssh "$DEPLOY_HOST" '
set -eu
install -o 10001 -g 10001 -m 0600 /tmp/telegram.session.secret /etc/tg-pm-gatekeeper/telegram.session.secret
install -o 10001 -g 10001 -m 0600 /tmp/hmac.key /etc/tg-pm-gatekeeper/hmac.key
install -o 10001 -g 10001 -m 0600 /tmp/review.key /etc/tg-pm-gatekeeper/review.key
install -o root -g 10001 -m 0640 /tmp/config.env /etc/tg-pm-gatekeeper/config.env
install -o root -g 10001 -m 0640 /tmp/deny-domains.txt /etc/tg-pm-gatekeeper/deny-domains.txt
rm -f /tmp/telegram.session.secret /tmp/hmac.key /tmp/review.key /tmp/config.env /tmp/deny-domains.txt
'
```

Do not include `/etc/tg-pm-gatekeeper` or `/var/lib/tg-pm-gatekeeper` in a general server backup.

### 4. Build and start

Record the commit being installed, build the image, and start the service:

```shell
ssh "$DEPLOY_HOST" '
cd /opt/tg-pm-gatekeeper
git checkout main
git pull --ff-only
git rev-parse HEAD
docker compose build --pull
docker compose up -d
'
```

A new database starts in `monitor`. Rebuilding later does not reset the mode.

## Confirm the installation

### 1. Check container health and mode

```shell
ssh "$DEPLOY_HOST" '
cd /opt/tg-pm-gatekeeper
docker compose ps
docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli status
'
```

Continue when:

- the `gatekeeper` container shows `healthy`;
- the status output includes `"mode":"monitor"`;
- `heartbeat` is a recent Unix timestamp and is not more than five seconds in the future; and
- `action_failures` is `0`.

If the container is not healthy, run:

```shell
ssh "$DEPLOY_HOST" 'cd /opt/tg-pm-gatekeeper && docker compose logs --tail=100 gatekeeper'
```

The logs intentionally use short event names instead of message text or raw sender identities.

### 2. Open the dashboard

From the local repository on your trusted computer:

```shell
scripts/dashboard-tunnel.sh "$DEPLOY_HOST"
```

Keep the terminal open. Press Enter when prompted to open the one-time login link, or pass `-o` to
open it immediately. Login redirects to a random capability path and does not set an authentication
cookie. Treat the entire resulting address as a secret and do not bookmark, share, or paste it into
an untrusted page. Each successful login rotates the capability and invalidates the previous address.
`Ctrl+C` closes the tunnel.

### 3. Send a safe test

While the service remains in `monitor`, send a private message from a separate Telegram account that
is not yet trusted. Do not configure it as `TG_TEST_SENDER_ID` for this first check: that setting
deliberately runs real Telegram actions even in `monitor`. The installation is behaving as expected
when a row appears under **Pending Reviews** and Telegram has not been changed.

### 4. Confirm the server is not exposing Gatekeeper

Run the checks in [Confirm the security settings](#confirm-the-security-settings). They verify that
the dashboard is not public and that the private files have the expected permissions.

### 5. Enable protection when ready

Only after the previous checks pass:

```shell
ssh "$DEPLOY_HOST" 'cd /opt/tg-pm-gatekeeper && docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli mode protect'
```

Return to the safe observation mode at any time:

```shell
ssh "$DEPLOY_HOST" 'cd /opt/tg-pm-gatekeeper && docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli mode monitor'
```

Returning to `monitor` keeps message processing active but cancels automatically generated pending
destructive jobs. Explicit manual spam decisions and dedicated-test cleanup remain mode-independent.

## Dashboard and daily operation

The dashboard has no public TCP listener. The tunnel helper connects local port `8765` to the
owner-only Unix socket on the server and reads a one-time access token. Login rotates that token and
redirects to a process-local 256-bit capability path; the dashboard does not send an authentication
cookie. While the tab is visible, the browser performs a capability-prefixed lightweight connection
check every 15 seconds; checks pause while the tab is hidden. The indicator changes between
**Connected** and **Disconnected**, and its **Checked** timestamp updates without reloading the page.
Use the adjacent refresh control to check immediately.

Overview and list pages update their marked regions in place only when the service reports a changed
state fingerprint. Current form input and focus are preserved during those updates. Detail pages do
not replace evidence or decision controls in the background: if the underlying review or restriction
changes, the dashboard disables the stale actions and asks the operator to load the current state.
Losing the SSH tunnel leaves the current page visible while the connection indicator reports the
failure. List pages retain their current page during refresh and show 50 rows per page in stable
most-recently-updated order.

### Telegram operator controls

This feature is disabled by default. To opt in, set the following deployment value and recreate the
service:

```shell
TG_TELEGRAM_OPERATOR_CONTROLS_ENABLED=true
```

When enabled, Gatekeeper accepts a small owner-only command set in the logged-in account's Telegram
Saved Messages. This provides quick restriction recovery from any Telegram client without exposing
the dashboard or configuring SSH on that device:

```text
/gatekeeper ping
/gatekeeper help
/gatekeeper cases
```

`cases` returns at most five current restrictions as separate case cards. Reply to the intended card
with `/gatekeeper allow` within 15 minutes. A successful allowance restores the saved Telegram folder
and notification settings when available, marks the sender allowed, cancels pending or failed
Gatekeeper deletion jobs, and removes the Active Case evidence. The reply-bound control is single-use
and kept only in process memory; a restart, a newer `cases` command, or expiry invalidates it.

Commands are ignored outside Saved Messages, including messages sent to private users or groups.
Case cards contain the resolved name or username, restriction state, reason, and age. They do not
copy message text, URLs, encrypted evidence, raw Telegram IDs, or internal sender keys into Saved
Messages. The cards themselves remain in Telegram until the owner deletes them. Telegram may omit
real-time outgoing updates created by another client, so Gatekeeper also checks only Saved Messages
newer than its startup cursor every three seconds. Commands are deduplicated across both paths and
are never replayed from before the current service start. The fallback history query searches only
for `/gatekeeper` matches and does not retrieve unrelated Saved Messages.

Processed command messages and all responses or case cards generated for them are automatically
deleted after 15 minutes, matching the reply-control lifetime. Cleanup jobs are held only in process
memory; if the service restarts during that window, delete any remaining artifacts manually.

Legacy restrictions without an encrypted control identity cannot be released this way. Use the
dashboard's **Legacy Recovery** path for those cases. Pending Review decisions and detailed evidence
inspection also remain dashboard-only.

Set `TG_TELEGRAM_OPERATOR_CONTROLS_ENABLED=false` and recreate the service to disable command
handling. Disabled deployments do not register the outgoing Telegram event handler.

### Pending Reviews

One row represents one sender. The row contains a consolidated message count and one encrypted
reference, not a stored conversation history. Opening it fetches one referenced message and the
sender from Telegram.

- **Legitimate** restores a Gatekeeper-managed archive when needed and allows the sender.
- **Spam** records an explicit manual permanent suppression and schedules whole-dialog deletion.
- **Dismiss and Cancel Pending Jobs** records no classification, performs no immediate Telegram
  action, and cancels pending or failed Gatekeeper deletion jobs for that sender.

If the referenced Telegram message has been deleted, use **Resolve and Cancel Pending Jobs**. This
clears the local review without changing the current sender trust or restriction state.

### Active Cases

The table contains every current quarantine and suppression. A separate encrypted control identity
keeps each restriction identifiable and reversible for its full lifetime, even after its evidence
expires. **Allow Now** restores saved dialog settings when available; cases with no saved settings
are moved to the main folder and notifications are enabled. The second action records that the
restriction was left unchanged and does not extend a temporary suppression.

New `adaptive-v1` cases show **Risk Score**, **Policy Decision**, **Decision Basis**, and
**Evidence Signals**, including each signal's source, weight, and explanation. Schema 1 through 4
snapshots show `Legacy HR Decision · recorded under rules-v2; not recalculated`; the migration does
not reclassify them or add an action.

Evidence snapshots last at most 30 days. Successful verification, rollback, or manual allowance
removes them sooner. Evidence expiry changes the detail page to an explicit unavailable state but
does not remove the row, identity, or **Allow Now** action. The minimal encrypted control identity is
removed only when the restriction ends. A temporary suppression is released when that sender next
messages after expiry; the service does not wake up solely to remove it.

**Legacy Recovery** is only for restrictions created before control identities were retained and
which cannot be backfilled from an older encrypted reference. Entering a numeric Telegram User ID
HMAC-derives the existing sender key without storing the ID. A matching quarantine or suppression is
allowed and pending deletion jobs are cancelled, but Telegram settings cannot be restored without a
control identity.

### Tunnel options

The SSH target can be an alias or `user@host`. Run `scripts/dashboard-tunnel.sh -h` for every option.
Common workstation settings are:

```shell
TG_DASHBOARD_HOST=root@gatekeeper.example
TG_DASHBOARD_PORT=18765
TG_DASHBOARD_SOCKET=/srv/gatekeeper/review.sock
TG_DASHBOARD_TOKEN=/srv/gatekeeper/review.access-token
TG_DASHBOARD_SSH_CONFIG="$HOME/.ssh/gatekeeper.conf"
```

`TG_REVIEW_*` remains a deprecated alias. Never publish the Unix socket through Docker or a reverse
proxy.

## Common commands

Run these from `/opt/tg-pm-gatekeeper` on the server:

```shell
docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli status
docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli mode monitor
docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli mode protect
docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli allow USER_ID
docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli revoke USER_ID
docker compose logs --tail=100 gatekeeper
```

Use the dashboard rather than CLI `allow` for active challenges, quarantines, or suppressions because
the CLI cannot restore their Telegram dialog state.

## Update an existing installation

Before updating, confirm that the server checkout is clean and record the current commit, container
health, and mode:

```shell
ssh "$DEPLOY_HOST" '
cd /opt/tg-pm-gatekeeper
git status --short
git rev-parse HEAD
docker compose ps
docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli status
'
```

For a normal runtime update:

```shell
ssh "$DEPLOY_HOST" '
cd /opt/tg-pm-gatekeeper
git pull --ff-only origin main
git rev-parse HEAD
docker compose up -d --build
docker compose ps
docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli status
'
```

Check the logs after the update. The mode stored in the existing database is preserved.

Documentation-only or host-script changes may require only `git pull --ff-only`; do not restart a
healthy container unless runtime, configuration, Docker, or dependency inputs changed. Project
maintainers can use [RELEASE.md](RELEASE.md) for the exact classification.

### Advanced: schema-changing updates

Most updates do not require this procedure. Use it only when release notes explicitly identify a
state-database migration.

1. Switch to `monitor`.
2. Confirm `challenged`, `challenge_issuing`, and `challenge_archiving` are all zero.
3. Create a temporary backup on the server with SQLite's online backup API.

```shell
ssh "$DEPLOY_HOST" '
cd /opt/tg-pm-gatekeeper
docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli mode monitor
docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli status
'

ssh "$DEPLOY_HOST" 'cd /opt/tg-pm-gatekeeper && docker compose exec -T gatekeeper python -' <<'PYTHON'
import os
import sqlite3

source = sqlite3.connect("/var/lib/tg-pm-gatekeeper/state.sqlite3")
backup = sqlite3.connect("/var/lib/tg-pm-gatekeeper/state.pre-migration.sqlite3")
source.backup(backup)
backup.close()
source.close()
os.chmod("/var/lib/tg-pm-gatekeeper/state.pre-migration.sqlite3", 0o600)
PYTHON
```

After rebuilding, verify the schema version, state counts, and logs. Delete the temporary backup only
after every check passes. Preserve the failed database for diagnosis if migration fails.

```shell
ssh "$DEPLOY_HOST" '
cd /opt/tg-pm-gatekeeper
docker compose exec -T gatekeeper python -c "import sqlite3; connection=sqlite3.connect(\"/var/lib/tg-pm-gatekeeper/state.sqlite3\"); print(connection.execute(\"PRAGMA user_version\").fetchone()[0])"
docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli status
docker compose logs --tail=100 gatekeeper
'
```

For this migration, the first command must print `6`.

Schema 6 adds the recoverable challenge profile and backfills every active pre-migration challenge as
`standard`. It renames pending-review rule identifiers to evidence signals, updates decision-event
columns without rewriting their contents, and creates the 24-hour keyed-HMAC campaign-event table.
Existing decision rows and schema 1 through 4 Active Case envelopes remain legacy data; they are not
recalculated and do not schedule a new action.

Schema 6 is not writable by pre-schema-6 code. A code rollback to an earlier commit therefore also
requires the pre-migration database. Record the earlier commit before updating. If startup or live
validation fails, keep the schema 6 database for diagnosis and restore both code and data together:

```shell
ssh "$DEPLOY_HOST" '
set -eu
cd /opt/tg-pm-gatekeeper
previous_commit=REPLACE_WITH_RECORDED_COMMIT
stamp=$(date -u +%Y%m%dT%H%M%SZ)
docker compose down
mv /var/lib/tg-pm-gatekeeper/state.sqlite3 "/var/lib/tg-pm-gatekeeper/state.failed-v6.$stamp.sqlite3"
for suffix in -wal -shm; do
    path="/var/lib/tg-pm-gatekeeper/state.sqlite3$suffix"
    if [ -e "$path" ]; then
        mv "$path" "/var/lib/tg-pm-gatekeeper/state.failed-v6.$stamp.sqlite3$suffix"
    fi
done
cp --preserve=mode,ownership,timestamps /var/lib/tg-pm-gatekeeper/state.pre-migration.sqlite3 /var/lib/tg-pm-gatekeeper/state.sqlite3
chmod 0600 /var/lib/tg-pm-gatekeeper/state.sqlite3
git switch --detach "$previous_commit"
docker compose up -d --build
docker compose ps
docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli status
'
```

Do not substitute the schema 6 database into an older image or delete the failed database before
diagnosis. After a successful rollback, return to reviewed `main` only through a new update attempt;
do not merge the incompatible database files.

## Configuration

`scripts/initialize.py` writes the production defaults. [.env.example](../.env.example) lists every
setting. Changing `/etc/tg-pm-gatekeeper/config.env` requires recreating the container.

| Setting | Default | Purpose |
| --- | --- | --- |
| `TG_CHALLENGE_TTL_SECONDS` | `60` | Time allowed for a direct reply; 30–600 seconds |
| `TG_CHALLENGE_MAX_ATTEMPTS` | `2` | Numeric attempts; 1–5 |
| `TG_OUTBOUND_LIMIT_PER_HOUR` | `10` | Gatekeeper messages per hour; 1–100 |
| `TG_OUTBOUND_NOTICE_RESERVE_PER_HOUR` | `min(3, limit-1)` | Capacity unavailable to new challenges but usable by notices; 0–`limit-1` |
| `TG_OUTBOUND_NOTICE_LIMIT_PER_SENDER_PER_HOUR` | `3` | Notice messages one sender may consume per hour; 1–100 |
| `TG_AUDIT_RETENTION_DAYS` | `30` | Local audit-event retention |
| `TG_PENDING_REVIEW_RETENTION_DAYS` | `7` | Pending Review retention; 1–7 days |
| `TG_ACTIVE_CASE_RETENTION_DAYS` | `30` | Active Case snapshot retention; 1–30 days |
| `TG_MUTE_DAYS` | `3650` | Quarantine mute duration |
| `TG_REVIEW_KEY_FILE` | `/run/secrets/review_key` | Active Case snapshot encryption key |
| `TG_TELEGRAM_OPERATOR_CONTROLS_ENABLED` | `false` | Enable owner commands in Telegram Saved Messages |
| `TG_TEST_SENDER_ID` | empty | Dedicated arithmetic-flow test account |
| `TG_DASHBOARD_SOCKET_PATH` | `/var/lib/tg-pm-gatekeeper/review.sock` | Owner-only dashboard Unix socket |

Invalid bounded values stop startup instead of silently changing behavior.

The total limit is always the hard upper bound. New challenges stop at
`limit - notice reserve`; verification hints, corrections, timeout warnings, and result notices can
use the remaining capacity but cannot exceed either the total limit or the per-sender notice limit.
The `status` command reports `outbound_total_1h`, `outbound_challenge_1h`,
`outbound_notice_1h`, and `outbound_quota_rejected_1h` without raw sender identifiers. It also reports
the last seven days through `standard_challenge_7d`, `strict_challenge_7d`,
`permanent_suppression_7d`, and `repeated_campaign_7d` without content or fingerprints.

### Dedicated test sender

Add the dedicated account's positive numeric ID to `config.env`, then recreate the container:

```shell
TG_TEST_SENDER_ID=REPLACE_WITH_DEDICATED_TEST_ACCOUNT_ID
```

This account runs the real arithmetic and cleanup flow even in `monitor`, bypasses the outbound
quota, never contributes a campaign fingerprint, and can lose its entire test dialog after exhausted
attempts. Remove the value after testing.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| `docker compose` is not found | Install Docker Engine and the Compose plugin; the legacy `docker-compose` command is not used. |
| Container stays unhealthy | Run `docker compose logs --tail=100 gatekeeper`; check for a missing private file, broad permissions, or an unauthorized Telegram session. |
| `startup_configuration_failed` | Check required `config.env` values and documented numeric bounds. |
| `startup_private_file_failed` | Confirm the five private files exist, are regular files, and have the documented ownership and permissions. |
| `startup_database_migration_failed` | Keep the database and any pre-migration backup intact; verify the current schema and follow the schema-update procedure. |
| `startup_telegram_session_failed` | Confirm the Telegram session is still authorized from an official client and reprovision it if revoked. |
| `startup_runtime_failed` | Inspect the immediately preceding privacy-safe events and container state; a supervised heartbeat or pruning failure intentionally exits for restart. |
| Dashboard token or socket is missing | Confirm the container is healthy, then inspect `/var/lib/tg-pm-gatekeeper/review.sock` and `review.access-token`. |
| Local port `8765` is already in use | Run the tunnel with another port, for example `scripts/dashboard-tunnel.sh -p 18765 "$DEPLOY_HOST"`. |
| Dashboard says the message is unavailable | The Telegram message may have been deleted; use **Resolve and Cancel Pending Jobs** if the sender decision no longer needs the message. |
| Active Case says evidence is unavailable | The evidence retention window ended; the restriction remains listed and **Allow Now** still uses its encrypted control identity. |
| Active Case says identity is unavailable | Use **Legacy Recovery** with the numeric Telegram User ID; only pre-control-identity states should need this. |
| Mode is still `monitor` after an update | This is expected; mode is stored in the database. Switch explicitly only after checking status. |

If the problem involves a sender action, preserve the current status and logs before changing policy
or deleting local state.

## Confirm the security settings

Run these checks once after installation and after changes to Docker, paths, permissions, or the
dashboard. They confirm that Gatekeeper is not publicly exposed and that other server users cannot
read its private files.

```shell
ssh "$DEPLOY_HOST" 'docker inspect tg-gatekeeper --format "user={{.Config.User}} readonly={{.HostConfig.ReadonlyRootfs}} caps={{json .HostConfig.CapDrop}} ports={{json .HostConfig.PortBindings}} security={{json .HostConfig.SecurityOpt}}"'
ssh "$DEPLOY_HOST" 'ss -lnt'
ssh "$DEPLOY_HOST" 'stat -c "%a %u:%g %n" /etc/tg-pm-gatekeeper/telegram.session.secret /etc/tg-pm-gatekeeper/hmac.key /etc/tg-pm-gatekeeper/review.key /etc/tg-pm-gatekeeper/config.env /etc/tg-pm-gatekeeper/deny-domains.txt /var/lib/tg-pm-gatekeeper'
ssh "$DEPLOY_HOST" 'stat -c "%F %a %u:%g %n" /var/lib/tg-pm-gatekeeper/review.sock /var/lib/tg-pm-gatekeeper/review.access-token'
```

Everything is correct when:

- the container user is `10001:10001`;
- the root filesystem is read-only, all capabilities are dropped, and `no-new-privileges` is set;
- Docker shows no Gatekeeper port bindings;
- session and key files are mode `600`;
- `config.env` and the denylist are mode `640` and owned by `root:10001`;
- the state directory is mode `700` and owned by `10001:10001`; and
- the review socket and access token are mode `600` and owned by `10001:10001`.

Stop and correct any mismatch before enabling `protect`. The dashboard access token is replaced on
every service start.

## Stop or remove Gatekeeper

To stop screening without deleting data:

```shell
ssh "$DEPLOY_HOST" 'cd /opt/tg-pm-gatekeeper && docker compose stop gatekeeper'
```

To permanently disconnect the Telegram session, stop the container, terminate the session from an
official Telegram client, and remove the server-side session file. Remove the repository, state,
configuration, and keys only after deciding whether any local audit information is still needed.

## Emergency session revocation

If the session may have leaked:

1. Stop the container.
2. Terminate the affected session from an official Telegram client.
3. Delete `/etc/tg-pm-gatekeeper/telegram.session.secret` from the server.
4. Generate and provision a new session from a trusted computer.
5. Start the service only after confirming that the old Telegram authorization is gone.

See [SECURITY.md](../SECURITY.md) for the complete incident checklist.
