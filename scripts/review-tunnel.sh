#!/bin/sh

set -u

usage() {
    cat <<'EOF'
Usage: review-tunnel.sh [options] [SSH_TARGET]

Open a dedicated local tunnel to the gatekeeper review dashboard.

Arguments:
  SSH_TARGET             SSH host, alias, or user@host. Required unless
                         TG_REVIEW_HOST is set.

Options:
  -p PORT                Local TCP port (default: TG_REVIEW_PORT or 8765)
  -s REMOTE_SOCKET       Remote Unix socket path
  -t REMOTE_TOKEN        Remote access-token path
  -F SSH_CONFIG          Alternate OpenSSH config file
  -h                     Show this help

Environment:
  TG_REVIEW_HOST         Default SSH target
  TG_REVIEW_PORT         Default local port
  TG_REVIEW_SOCKET       Default remote Unix socket path
  TG_REVIEW_TOKEN        Default remote access-token path
  TG_REVIEW_SSH_CONFIG   Default alternate OpenSSH config file
EOF
}

port="${TG_REVIEW_PORT:-8765}"
remote_socket="${TG_REVIEW_SOCKET:-/var/lib/tg-pm-gatekeeper/review.sock}"
remote_token="${TG_REVIEW_TOKEN:-/var/lib/tg-pm-gatekeeper/review.access-token}"
ssh_config="${TG_REVIEW_SSH_CONFIG:-}"

while getopts "hp:s:t:F:" option; do
    case "$option" in
        h)
            usage
            exit 0
            ;;
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

host="${1:-${TG_REVIEW_HOST:-}}"
if [ -z "$host" ]; then
    echo "An SSH target is required." >&2
    echo "Example: scripts/review-tunnel.sh user@server.example" >&2
    echo "Or set TG_REVIEW_HOST in your shell environment." >&2
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

echo "Opening a dedicated review tunnel to ${host}..."
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

echo "Connected: ${url}login?token=${access_token}"
echo "Keep this terminal open. Press Ctrl+C to close the tunnel."

wait "$tunnel_pid"
status=$?
tunnel_pid=""
if ! report_closed; then
    status=1
fi
exit "$status"
