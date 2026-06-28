#!/bin/sh

set -u

host="${TG_REVIEW_HOST:-bv}"
port="${TG_REVIEW_PORT:-8765}"
remote_socket="${TG_REVIEW_SOCKET:-/var/lib/tg-pm-gatekeeper/review.sock}"
url="http://127.0.0.1:${port}/"
tunnel_pid=""
connected=false

cleanup() {
    if [ -n "$tunnel_pid" ] && kill -0 "$tunnel_pid" 2>/dev/null; then
        kill "$tunnel_pid" 2>/dev/null || true
        wait "$tunnel_pid" 2>/dev/null || true
        if [ "$connected" = true ]; then
            echo "Tunnel closed."
        fi
    fi
}

trap 'cleanup; exit 130' INT TERM HUP
trap cleanup EXIT

echo "Opening a dedicated review tunnel to ${host}..."
ssh \
    -o ControlMaster=no \
    -o ControlPath=none \
    -o ExitOnForwardFailure=yes \
    -o ServerAliveInterval=15 \
    -o ServerAliveCountMax=2 \
    -N \
    -L "127.0.0.1:${port}:${remote_socket}" \
    "$host" &
tunnel_pid=$!

attempt=0
while [ "$attempt" -lt 30 ]; do
    if curl --fail --silent --show-error --max-time 1 "$url" >/dev/null 2>&1; then
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

echo "Connected: ${url}"
echo "Keep this terminal open. Press Ctrl+C to close the tunnel."

wait "$tunnel_pid"
status=$?
echo "Tunnel closed."
exit "$status"
