#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
echo "scripts/review-tunnel.sh is deprecated; use scripts/dashboard-tunnel.sh." >&2
exec "$script_dir/dashboard-tunnel.sh" "$@"
