# Hardened deployment

These instructions target the `bv` host selected for the first deployment. Re-check the host before
every deployment; resource and network observations are not permanent facts.

## 1. Preconditions

- Enable Telegram two-step verification.
- Use a dedicated Telegram test account for the first end-to-end run.
- Use Python 3.14 on the trusted computer used to create the session.
- Obtain an application API ID and API hash from Telegram's developer portal.
- Do not paste credentials into shell commands, issue comments, CI variables, or chat.

Install the pinned local dependencies in an isolated environment, then create the initialization files:

```shell
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes --no-deps -r requirements-build.txt
.venv/bin/python -m pip install --require-hashes --no-deps --no-build-isolation -r requirements.txt
.venv/bin/python scripts/initialize.py
```

The initializer securely prompts for the API ID, API hash, phone number, login code, and 2FA password.
It creates `telegram.session.secret`, `hmac.key`, `config.env`, and `deny-domains.txt` with mode `0600`.
None of these files may be printed, copied into an environment variable, or committed.

## 2. Prepare the host

Run the bootstrap script as root on `bv`. It creates a non-login UID/GID `10001` and the three fixed
directories without creating credentials:

```shell
ssh bv 'sh -s' < deploy/bootstrap-bv.sh
```

Clone the public repository anonymously. No GitHub token or deploy key is needed:

```shell
ssh bv 'git clone https://github.com/GeniusLv2006/tg-pm-gatekeeper.git /opt/tg-pm-gatekeeper'
```

Transfer secrets through SCP to temporary root-only filenames, install them with the service UID,
then remove the temporary copies:

```shell
scp telegram.session.secret hmac.key config.env deny-domains.txt bv:/tmp/
ssh bv 'install -o 10001 -g 10001 -m 0600 /tmp/telegram.session.secret /etc/tg-pm-gatekeeper/telegram.session.secret && install -o 10001 -g 10001 -m 0600 /tmp/hmac.key /etc/tg-pm-gatekeeper/hmac.key && install -o root -g 10001 -m 0640 /tmp/config.env /etc/tg-pm-gatekeeper/config.env && install -o root -g 10001 -m 0640 /tmp/deny-domains.txt /etc/tg-pm-gatekeeper/deny-domains.txt && rm -f /tmp/telegram.session.secret /tmp/hmac.key /tmp/config.env /tmp/deny-domains.txt'
```

Do not add these files to a general server backup job.

## 3. Build and start in observation mode

Record and verify the exact commit before building:

```shell
ssh bv 'cd /opt/tg-pm-gatekeeper && git fetch origin && git checkout main && git pull --ff-only && git rev-parse HEAD && docker compose build --pull && docker compose up -d'
```

The database defaults to `observe`. Check health and redacted status:

```shell
ssh bv 'cd /opt/tg-pm-gatekeeper && docker compose ps && docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli status'
```

After seven days of reviewed observation, enable enforcement explicitly:

```shell
ssh bv 'cd /opt/tg-pm-gatekeeper && docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli resume'
```

Pause immediately without stopping update processing:

```shell
ssh bv 'cd /opt/tg-pm-gatekeeper && docker compose exec -T gatekeeper python -m tg_pm_gatekeeper.cli pause'
```

### Review observation decisions

The dashboard has no TCP listener. From the local repository, run the tunnel helper:

```shell
scripts/review-tunnel.sh
```

It prints `Connected` only after the dashboard responds. Keep that terminal open; `Ctrl+C` closes the
dedicated tunnel. The helper disables SSH connection sharing so the forwarding process cannot be
silently handed to a background ControlMaster. Set `TG_REVIEW_PORT` or `TG_REVIEW_HOST` to override
the default local port `8765` or host `bv`.

Then open `http://127.0.0.1:8765/` locally. The green **Live connection** timestamp comes from each
server response, and the queue automatically checks again every 10 seconds. If the tunnel closes,
the browser will show a connection error on the next check instead of leaving a misleading stale
dashboard. The queue page contains no message content. Opening an
item fetches the message and sender live from Telegram. Available decisions are:

- **Legitimate**: add the HMAC-keyed sender to the local allowlist.
- **Spam**: archive and mute the Telegram dialog, then mark the sender quarantined.
- **Dismiss**: record no classification and perform no Telegram action.

All three decisions erase the encrypted Telegram reference immediately. Pending references expire
after seven days. Stop the SSH command when review is complete; do not publish the socket through a
Docker port mapping or reverse proxy.

The `allow USER_ID` and `revoke USER_ID` commands derive the stored HMAC key inside the container and
never print the raw identifier. Be aware that a user ID typed as a CLI argument can remain in shell
history; use a temporary history-disabled shell when this matters.

## 4. Verify the boundary

The deployment is acceptable only when all checks pass:

```shell
ssh bv 'docker inspect tg-gatekeeper --format "user={{.Config.User}} readonly={{.HostConfig.ReadonlyRootfs}} caps={{json .HostConfig.CapDrop}} ports={{json .HostConfig.PortBindings}} security={{json .HostConfig.SecurityOpt}}"'
ssh bv 'ss -lnt'
ssh bv 'stat -c "%a %u:%g %n" /etc/tg-pm-gatekeeper/telegram.session.secret /etc/tg-pm-gatekeeper/hmac.key /var/lib/tg-pm-gatekeeper'
ssh bv 'stat -c "%F %a %u:%g %n" /var/lib/tg-pm-gatekeeper/review.sock'
```

Expected values are user `10001:10001`, read-only root filesystem, all capabilities dropped, no port
bindings, `no-new-privileges`, secret modes `600`, and state-directory mode `700`. The application
must not add a listening TCP port. The review socket must be a Unix socket with mode `600` owned by
UID/GID `10001:10001`.

## 5. Emergency revocation

1. `docker compose stop gatekeeper` over SSH.
2. Terminate the session from an official Telegram client.
3. Remove `/etc/tg-pm-gatekeeper/telegram.session.secret`.
4. Generate a new local session and provision it as above.
5. Start only after verifying that the old authorization no longer appears in Telegram.
