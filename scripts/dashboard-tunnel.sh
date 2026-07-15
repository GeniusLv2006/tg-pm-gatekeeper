#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

set -u

usage() {
    cat <<'EOF'
Usage: dashboard-tunnel.sh [options] [SSH_TARGET]

Open a dedicated local tunnel to the Gatekeeper dashboard.

Arguments:
  SSH_TARGET             SSH host, alias, or user@host. Required unless
                         TG_DASHBOARD_HOST or TG_REVIEW_HOST is set.

Options:
  -o                     Open the dashboard in the default browser after connecting
  -p PORT                Local TCP port (default: TG_DASHBOARD_PORT,
                         TG_REVIEW_PORT, or 8765)
  -s REMOTE_SOCKET       Remote Unix socket path
  -t REMOTE_TOKEN        Remote access-token path
  -F SSH_CONFIG          Alternate OpenSSH config file
  -h                     Show this help

Environment:
  TG_DASHBOARD_HOST      Default SSH target
  TG_DASHBOARD_PORT      Default local port
  TG_DASHBOARD_SOCKET    Default remote Unix socket path
  TG_DASHBOARD_TOKEN     Default remote access-token path
  TG_DASHBOARD_SSH_CONFIG Default alternate OpenSSH config file
  TG_REVIEW_*            Deprecated aliases for TG_DASHBOARD_*
EOF
}

port="${TG_DASHBOARD_PORT:-${TG_REVIEW_PORT:-8765}}"
remote_socket="${TG_DASHBOARD_SOCKET:-${TG_REVIEW_SOCKET:-/var/lib/tg-pm-gatekeeper/review.sock}}"
remote_token="${TG_DASHBOARD_TOKEN:-${TG_REVIEW_TOKEN:-/var/lib/tg-pm-gatekeeper/review.access-token}}"
ssh_config="${TG_DASHBOARD_SSH_CONFIG:-${TG_REVIEW_SSH_CONFIG:-}}"
open_on_connect=false

while getopts "hop:s:t:F:" option; do
    case "$option" in
        h)
            usage
            exit 0
            ;;
        o) open_on_connect=true ;;
        p) port="$OPTARG" ;;
        s) remote_socket="$OPTARG" ;;
        t) remote_token="$OPTARG" ;;
        F) ssh_config="$OPTARG" ;;
        *)
            usage >&2
            exit 2
            ;;
    esac
done
shift $((OPTIND - 1))

if [ "$#" -gt 1 ]; then
    echo "Only one SSH target may be supplied." >&2
    usage >&2
    exit 2
fi

host="${1:-${TG_DASHBOARD_HOST:-${TG_REVIEW_HOST:-}}}"
if [ -z "$host" ]; then
    echo "An SSH target is required." >&2
    echo "Example: scripts/dashboard-tunnel.sh user@server.example" >&2
    echo "Or set TG_DASHBOARD_HOST in your shell environment." >&2
    exit 2
fi
case "$host" in
    -*)
        echo "SSH target must not begin with '-'." >&2
        exit 2
        ;;
esac
case "$remote_token" in
    /*) ;;
    *)
        echo "Remote token must be an absolute path." >&2
        exit 2
        ;;
esac
case "$remote_token" in
    *[!A-Za-z0-9_./-]*)
        echo "Remote token path contains unsupported characters." >&2
        exit 2
        ;;
esac
case "$port" in
    ''|*[!0-9]*)
        echo "Local port must be an integer from 1 to 65535." >&2
        exit 2
        ;;
esac
if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    echo "Local port must be an integer from 1 to 65535." >&2
    exit 2
fi
case "$remote_socket" in
    /*) ;;
    *)
        echo "Remote socket must be an absolute path." >&2
        exit 2
        ;;
esac
if [ -n "$ssh_config" ] && [ ! -r "$ssh_config" ]; then
    echo "SSH config is not readable: ${ssh_config}" >&2
    exit 2
fi
for dependency in ssh curl; do
    if ! command -v "$dependency" >/dev/null 2>&1; then
        echo "Required command is missing: ${dependency}" >&2
        exit 127
    fi
done

url="http://127.0.0.1:${port}/"
tunnel_pid=""
connected=false
closed_reported=false

dashboard_reachable() {
    curl --silent --show-error --max-time 1 "$url" >/dev/null 2>&1
}

read_access_token() {
    # The path is restricted to absolute alphanumeric/underscore/dot/slash/dash values above.
    # shellcheck disable=SC2029
    if [ -n "$ssh_config" ]; then
        ssh -F "$ssh_config" "$host" "cat $remote_token"
    else
        ssh "$host" "cat $remote_token"
    fi
}

report_closed() {
    if [ "$connected" != true ] || [ "$closed_reported" = true ]; then
        return 0
    fi
    closed_reported=true
    attempt=0
    while [ "$attempt" -lt 10 ]; do
        if ! dashboard_reachable; then
            echo "Tunnel closed."
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 0.1
    done
    echo "Tunnel process stopped, but the dashboard is still reachable on ${url}" >&2
    echo "Another SSH forward or local process is still using port ${port}." >&2
    return 1
}

# Invoked by the signal and exit traps below.
# shellcheck disable=SC2329
cleanup() {
    if [ -n "$tunnel_pid" ] && kill -0 "$tunnel_pid" 2>/dev/null; then
        kill "$tunnel_pid" 2>/dev/null || true
        wait "$tunnel_pid" 2>/dev/null || true
    fi
    report_closed || true
}

trap 'cleanup; exit 130' INT TERM HUP
trap cleanup EXIT

open_tunnel() {
    if [ -n "$ssh_config" ]; then
        set -- -F "$ssh_config"
    else
        set --
    fi
    exec ssh "$@" \
        -o ControlMaster=no \
        -o ControlPath=none \
        -o ExitOnForwardFailure=yes \
        -o ServerAliveInterval=15 \
        -o ServerAliveCountMax=2 \
        -N \
        -L "127.0.0.1:${port}:${remote_socket}" \
        "$host"
}

open_dashboard() {
    if command -v open >/dev/null 2>&1; then
        open "$login_url" >/dev/null 2>&1
    elif command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$login_url" >/dev/null 2>&1
    elif command -v gio >/dev/null 2>&1; then
        gio open "$login_url" >/dev/null 2>&1
    else
        return 1
    fi
}

access_token="$(read_access_token)" || {
    echo "Could not read the remote dashboard access token." >&2
    exit 1
}
case "$access_token" in
    ''|*[!A-Za-z0-9_-]*)
        echo "Remote dashboard access token is invalid." >&2
        exit 1
        ;;
esac

echo "Opening a dedicated dashboard tunnel to ${host}..."
open_tunnel &
tunnel_pid=$!

attempt=0
while [ "$attempt" -lt 30 ]; do
    if dashboard_reachable; then
        connected=true
        break
    fi
    if ! kill -0 "$tunnel_pid" 2>/dev/null; then
        wait "$tunnel_pid"
        status=$?
        echo "Tunnel failed before the dashboard became reachable." >&2
        exit "$status"
    fi
    attempt=$((attempt + 1))
    sleep 0.2
done

if [ "$connected" != true ]; then
    echo "Tunnel opened, but the dashboard did not respond at ${url}" >&2
    exit 1
fi

login_url="${url}login?token=${access_token}"
echo "Connected: ${login_url}"
if [ "$open_on_connect" = true ]; then
    if open_dashboard; then
        echo "Dashboard opened in the default browser."
    else
        echo "Could not open a browser automatically; use the Connected URL above." >&2
    fi
elif [ -t 0 ]; then
    printf "Press Enter to open the dashboard, or Ctrl+C to close the tunnel: "
    if IFS= read -r _; then
        if open_dashboard; then
            echo "Dashboard opened in the default browser."
        else
            echo "Could not open a browser automatically; use the Connected URL above." >&2
        fi
    fi
fi
echo "Keep this terminal open. Press Ctrl+C to close the tunnel."

wait "$tunnel_pid"
status=$?
tunnel_pid=""
if ! report_closed; then
    status=1
fi
exit "$status"
