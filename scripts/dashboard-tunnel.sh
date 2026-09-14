#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

set -u

usage() {
    cat <<'EOF'
Usage: dashboard-tunnel.sh [options] [SSH_TARGET]

Start the on-demand Gatekeeper Dashboard sidecar and open a local SSH tunnel.

Arguments:
  SSH_TARGET             SSH host, alias, or user@host. Required unless
                         TG_DASHBOARD_HOST or TG_REVIEW_HOST is set.

Options:
  -d PROJECT_DIR         Remote project directory (default:
                         TG_DASHBOARD_PROJECT_DIR or /opt/tg-pm-gatekeeper)
  -o                     Open the dashboard in the default browser
  -p PORT                Local TCP port (default: 8765)
  -s REMOTE_SOCKET       Remote Dashboard Unix socket
  -t REMOTE_TOKEN        Remote access-token path
  -F SSH_CONFIG          Alternate OpenSSH config file
  -h                     Show this help

TG_REVIEW_* environment names remain deprecated compatibility aliases.
EOF
}

deprecated_alias_used=false
[ -n "${TG_REVIEW_HOST:-}${TG_REVIEW_PORT:-}${TG_REVIEW_SOCKET:-}${TG_REVIEW_TOKEN:-}${TG_REVIEW_SSH_CONFIG:-}" ] && deprecated_alias_used=true

port="${TG_DASHBOARD_PORT:-${TG_REVIEW_PORT:-8765}}"
remote_socket="${TG_DASHBOARD_SOCKET:-${TG_REVIEW_SOCKET:-/run/tg-pm-gatekeeper/dashboard.sock}}"
remote_token="${TG_DASHBOARD_TOKEN:-${TG_REVIEW_TOKEN:-/run/tg-pm-gatekeeper/dashboard.access-token}}"
ssh_config="${TG_DASHBOARD_SSH_CONFIG:-${TG_REVIEW_SSH_CONFIG:-}}"
project_dir="${TG_DASHBOARD_PROJECT_DIR:-/opt/tg-pm-gatekeeper}"
open_on_connect=false

while getopts "hd:op:s:t:F:" option; do
    case "$option" in
        h) usage; exit 0 ;;
        d) project_dir="$OPTARG" ;;
        o) open_on_connect=true ;;
        p) port="$OPTARG" ;;
        s) remote_socket="$OPTARG" ;;
        t) remote_token="$OPTARG" ;;
        F) ssh_config="$OPTARG" ;;
        *) usage >&2; exit 2 ;;
    esac
done
shift $((OPTIND - 1))

[ "$#" -le 1 ] || { echo "Only one SSH target may be supplied." >&2; exit 2; }
host="${1:-${TG_DASHBOARD_HOST:-${TG_REVIEW_HOST:-}}}"
[ -n "$host" ] || { echo "An SSH target is required." >&2; exit 2; }
case "$host" in -*) echo "SSH target must not begin with '-'." >&2; exit 2 ;; esac
case "$port" in ''|*[!0-9]*) echo "Local port must be an integer from 1 to 65535." >&2; exit 2 ;; esac
[ "$port" -ge 1 ] && [ "$port" -le 65535 ] || { echo "Local port must be an integer from 1 to 65535." >&2; exit 2; }

validate_absolute_path() {
    label=$1
    value=$2
    case "$value" in
        /*) ;;
        *) echo "$label must be an absolute path." >&2; exit 2 ;;
    esac
    case "$value" in
        *[!A-Za-z0-9_./-]*|*//*|*/../*|*/./*|*/..|*/.)
            echo "$label contains unsupported or unsafe path components." >&2
            exit 2
            ;;
    esac
}

validate_absolute_path "Remote project directory" "$project_dir"
validate_absolute_path "Remote socket" "$remote_socket"
validate_absolute_path "Remote token" "$remote_token"
[ -z "$ssh_config" ] || [ -r "$ssh_config" ] || { echo "SSH config is not readable: $ssh_config" >&2; exit 2; }

for dependency in ssh curl; do
    command -v "$dependency" >/dev/null 2>&1 || { echo "Required command is missing: $dependency" >&2; exit 127; }
done
[ "$deprecated_alias_used" = false ] || echo "Warning: TG_REVIEW_* variables are deprecated; use TG_DASHBOARD_*." >&2

url="http://127.0.0.1:${port}/"
remote_helper="$project_dir/scripts/dashboard-remote.sh"
tunnel_pid=""
sidecar_started=false
cleaned=false

ssh_remote() {
    action=$1
    # Both values are restricted to safe path/action characters before use.
    # shellcheck disable=SC2029
    if [ -n "$ssh_config" ]; then
        ssh -F "$ssh_config" "$host" "$remote_helper $action"
    else
        ssh "$host" "$remote_helper $action"
    fi
}

read_access_token() {
    # The token path is restricted to safe absolute-path characters above.
    # shellcheck disable=SC2029
    if [ -n "$ssh_config" ]; then
        ssh -F "$ssh_config" "$host" "cat $remote_token"
    else
        ssh "$host" "cat $remote_token"
    fi
}

dashboard_reachable() {
    curl --silent --show-error --max-time 1 "$url" >/dev/null 2>&1
}

# Invoked indirectly by the signal and exit traps below.
# shellcheck disable=SC2329
cleanup() {
    [ "$cleaned" = false ] || return 0
    cleaned=true
    if [ -n "$tunnel_pid" ] && kill -0 "$tunnel_pid" 2>/dev/null; then
        kill "$tunnel_pid" 2>/dev/null || true
        wait "$tunnel_pid" 2>/dev/null || true
    fi
    if [ "$sidecar_started" = true ]; then
        ssh_remote stop >/dev/null 2>&1 || echo "Warning: could not stop the remote Dashboard sidecar." >&2
    fi
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

echo "Starting the on-demand Dashboard sidecar on ${host}..."
ssh_remote start >/dev/null || { echo "Could not start the remote Dashboard sidecar." >&2; exit 1; }
sidecar_started=true
access_token=$(read_access_token) || { echo "Could not read the remote Dashboard access token." >&2; exit 1; }
case "$access_token" in ''|*[!A-Za-z0-9_-]*) echo "Remote Dashboard access token is invalid." >&2; exit 1 ;; esac

echo "Opening a dedicated Dashboard tunnel..."
open_tunnel &
tunnel_pid=$!

attempt=0
while [ "$attempt" -lt 50 ]; do
    if dashboard_reachable; then break; fi
    if ! kill -0 "$tunnel_pid" 2>/dev/null; then
        wait "$tunnel_pid"
        status=$?
        echo "Tunnel failed before the Dashboard became reachable." >&2
        exit "$status"
    fi
    attempt=$((attempt + 1))
    sleep 0.2
done
dashboard_reachable || { echo "Tunnel opened, but the Dashboard did not respond at $url" >&2; exit 1; }

login_url="${url}login?token=${access_token}"
echo "Connected: ${login_url}"
if [ "$open_on_connect" = true ]; then
    open_dashboard && echo "Dashboard opened in the default browser." || echo "Could not open a browser automatically; use the Connected URL above." >&2
elif [ -t 0 ]; then
    printf "Press Enter to open the Dashboard, or Ctrl+C to close the tunnel: "
    if IFS= read -r _; then
        open_dashboard || echo "Could not open a browser automatically; use the Connected URL above." >&2
    fi
fi
echo "The sidecar exits after 10 minutes without authenticated activity. Press Ctrl+C to close now."

misses=0
while kill -0 "$tunnel_pid" 2>/dev/null; do
    sleep 1
    if dashboard_reachable; then
        misses=0
    else
        misses=$((misses + 1))
        if [ "$misses" -ge 3 ]; then
            echo "Dashboard sidecar is no longer available (idle timeout, sign out, or remote stop)."
            kill "$tunnel_pid" 2>/dev/null || true
            break
        fi
    fi
done
wait "$tunnel_pid" 2>/dev/null
status=$?
tunnel_pid=""
[ "$status" -eq 143 ] && status=0
exit "$status"
