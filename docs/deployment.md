# Hardened deployment

These instructions target the `bv` host selected for the first deployment. Re-check the host before
every deployment; resource and network observations are not permanent facts.

## 1. Preconditions

- Enable Telegram two-step verification.
- Use a dedicated Telegram test account for the first end-to-end run.
- Use Python 3.14 on the trusted computer used to create the session.
- Obtain an application API ID and API hash from Telegram's developer portal.
- Do not paste credentials into shell commands, issue comments, CI variables, or chat.

Install the pinned local dependencies in an isolated environment, then create the two secret files:

```shell
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes --no-deps -r requirements-build.txt
.venv/bin/python -m pip install --require-hashes --no-deps --no-build-isolation -r requirements.txt
.venv/bin/python scripts/generate_session.py
.venv/bin/python scripts/generate_hmac_key.py
```

The scripts create `telegram.session.secret` and `hmac.key` with mode `0600`. Neither file may be
printed, copied into an environment variable, or committed.

Create `config.env` locally with the real API ID and API hash, using `.env.example` as a field list.
Create `deny-domains.txt` locally if a domain denylist is needed. Both filenames are ignored by Git.

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

The `allow USER_ID` and `revoke USER_ID` commands derive the stored HMAC key inside the container and
never print the raw identifier. Be aware that a user ID typed as a CLI argument can remain in shell
history; use a temporary history-disabled shell when this matters.

## 4. Verify the boundary

The deployment is acceptable only when all checks pass:

```shell
ssh bv 'cd /opt/tg-pm-gatekeeper && docker inspect tg-pm-gatekeeper-gatekeeper-1 --format "user={{.Config.User}} readonly={{.HostConfig.ReadonlyRootfs}} caps={{json .HostConfig.CapDrop}} ports={{json .HostConfig.PortBindings}} security={{json .HostConfig.SecurityOpt}}"'
ssh bv 'ss -lnt'
ssh bv 'stat -c "%a %u:%g %n" /etc/tg-pm-gatekeeper/telegram.session.secret /etc/tg-pm-gatekeeper/hmac.key /var/lib/tg-pm-gatekeeper'
```

Expected values are user `10001:10001`, read-only root filesystem, all capabilities dropped, no port
bindings, `no-new-privileges`, secret modes `600`, and state-directory mode `700`. The application
must not add a listening TCP port.

## 5. Emergency revocation

1. `docker compose stop gatekeeper` over SSH.
2. Terminate the session from an official Telegram client.
3. Remove `/etc/tg-pm-gatekeeper/telegram.session.secret`.
4. Generate a new local session and provision it as above.
5. Start only after verifying that the old authorization no longer appears in Telegram.
