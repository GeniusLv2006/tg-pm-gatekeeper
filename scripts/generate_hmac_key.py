#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import os
import secrets
from pathlib import Path


def main() -> None:
    destination = Path("hmac.key")
    if destination.exists():
        raise SystemExit("refusing to overwrite hmac.key")
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(secrets.token_bytes(32))
    print("HMAC key written to hmac.key with mode 0600; never commit it.")


if __name__ == "__main__":
    main()
