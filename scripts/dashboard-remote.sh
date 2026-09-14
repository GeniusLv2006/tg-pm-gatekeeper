#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

set -eu

runtime_dir=/run/tg-pm-gatekeeper
dashboard_socket=$runtime_dir/dashboard.sock
access_token=$runtime_dir/dashboard.access-token
temporary_token=$runtime_dir/dashboard.access-token.tmp
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(dirname -- "$script_dir")

usage() {
    echo "Usage: scripts/dashboard-remote.sh start|stop|status" >&2
}

compose() {
    docker compose --project-directory "$project_dir" -f "$project_dir/compose.yaml" "$@"
}

stop_dashboard() {
    compose --profile dashboard stop -t 30 dashboard >/dev/null 2>&1 || true
}

case "${1:-}" in
    start)
        if [ "$(docker inspect -f '{{.State.Health.Status}}' tg-gatekeeper 2>/dev/null || true)" != healthy ]; then
            echo "Gatekeeper core is not healthy." >&2
            exit 1
        fi
        stop_dashboard
        rm -f "$dashboard_socket" "$access_token" "$temporary_token"
        compose --profile dashboard up -d --no-deps dashboard >&2
        attempt=0
        while [ "$attempt" -lt 100 ]; do
            if [ -S "$dashboard_socket" ] && [ -s "$access_token" ]; then
                cat "$access_token"
                exit 0
            fi
            if [ "$(docker inspect -f '{{.State.Running}}' tg-gatekeeper-dashboard 2>/dev/null || true)" != true ]; then
                compose --profile dashboard logs --tail 20 dashboard >&2 || true
                echo "Dashboard sidecar exited before becoming ready." >&2
                exit 1
            fi
            attempt=$((attempt + 1))
            sleep 0.2
        done
        echo "Dashboard sidecar did not become ready." >&2
        stop_dashboard
        exit 1
        ;;
    stop)
        stop_dashboard
        ;;
    status)
        if [ "$(docker inspect -f '{{.State.Running}}' tg-gatekeeper-dashboard 2>/dev/null || true)" = true ] \
            && [ -S "$dashboard_socket" ] && [ -s "$access_token" ]; then
            echo running
        else
            echo stopped
            exit 1
        fi
        ;;
    *)
        usage
        exit 2
        ;;
esac
