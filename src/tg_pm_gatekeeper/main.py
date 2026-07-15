# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import asyncio
import logging
import os

from .config import ConfigurationError, PrivateFileError, Settings, read_private_file
from .crypto import ActiveCaseProtector, IdentifierProtector
from .logging_config import configure_logging
from .service import GatekeeperService
from .store import StateStore, StoreMigrationError
from .telegram_adapter import (
    TelegramAdapter,
    TelegramAuthorizationError,
    load_denylist,
)


async def async_main() -> None:
    settings = Settings.from_environment()
    protector = IdentifierProtector(
        read_private_file(settings.hmac_key_file, minimum_bytes=32)
    )
    store = StateStore(settings.database_path)
    try:
        review_protector = ActiveCaseProtector(
            read_private_file(settings.review_key_file, minimum_bytes=32)
        )
        service = GatekeeperService(
            store,
            protector,
            challenge_ttl_seconds=settings.challenge_ttl_seconds,
            challenge_max_attempts=settings.challenge_max_attempts,
            outbound_limit_per_hour=settings.outbound_limit_per_hour,
            pending_review_retention_days=settings.pending_review_retention_days,
            active_case_retention_days=settings.active_case_retention_days,
            denylist=load_denylist(settings.denylist_file),
            test_sender_id=settings.test_sender_id,
            active_case_protector=review_protector,
        )
        adapter = TelegramAdapter(settings, store, service)
        await adapter.run()
    finally:
        store.close()


def main() -> None:
    os.umask(0o077)
    configure_logging()
    try:
        asyncio.run(async_main())
    except PrivateFileError:
        logging.getLogger("gatekeeper.main").critical("startup_private_file_failed")
        raise SystemExit(1) from None
    except ConfigurationError:
        logging.getLogger("gatekeeper.main").critical("startup_configuration_failed")
        raise SystemExit(1) from None
    except StoreMigrationError:
        logging.getLogger("gatekeeper.main").critical("startup_database_migration_failed")
        raise SystemExit(1) from None
    except TelegramAuthorizationError:
        logging.getLogger("gatekeeper.main").critical("startup_telegram_session_failed")
        raise SystemExit(1) from None
    except (RuntimeError, OSError, UnicodeError):
        logging.getLogger("gatekeeper.main").critical("startup_runtime_failed")
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
