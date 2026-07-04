#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

set -eu

SERVICE_USER=tg-gatekeeper
SERVICE_UID=10001

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root" >&2
  exit 1
fi

if ! getent group "$SERVICE_USER" >/dev/null; then
  groupadd --system --gid "$SERVICE_UID" "$SERVICE_USER"
fi
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --uid "$SERVICE_UID" --gid "$SERVICE_USER" \
    --home-dir /var/lib/tg-pm-gatekeeper --shell /usr/sbin/nologin "$SERVICE_USER"
fi

install -d -o root -g root -m 0755 /opt/tg-pm-gatekeeper
install -d -o root -g "$SERVICE_USER" -m 0750 /etc/tg-pm-gatekeeper
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0700 /var/lib/tg-pm-gatekeeper

echo "Directories and service account are ready. No credentials were created."
