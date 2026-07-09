# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import asyncio
import logging
import os

from .config import ConfigurationError, Settings, read_private_file
from .crypto import IdentifierProtector
from .evidence import EvidenceProtector, EvidenceStore
from .logging_config import configure_logging
from .service import GatekeeperService
from .store import StateStore
from .telegram_adapter import TelegramAdapter, load_denylist


async def async_main() -> None:
    settings = Settings.from_environment()
    protector = IdentifierProtector(
        read_private_file(settings.hmac_key_file, minimum_bytes=32)
    )
    store = StateStore(settings.database_path)
    evidence_protector = EvidenceProtector(
        read_private_file(settings.evidence_key_file, minimum_bytes=32)
    )
    evidence_store = EvidenceStore(settings.evidence_path, evidence_protector)
    service = GatekeeperService(
        store,
        protector,
        challenge_ttl_seconds=settings.challenge_ttl_seconds,
        challenge_max_attempts=settings.challenge_max_attempts,
        outbound_limit_per_hour=settings.outbound_limit_per_hour,
        review_retention_days=settings.review_retention_days,
        denylist=load_denylist(settings.denylist_file),
        test_sender_id=settings.test_sender_id,
        evidence_store=evidence_store,
        review_content_protector=evidence_protector,
        evidence_collection=settings.evidence_collection,
        evidence_retention_days=settings.evidence_retention_days,
        evidence_max_records_per_sender=settings.evidence_max_records_per_sender,
    )
    adapter = TelegramAdapter(settings, store, service, evidence_store=evidence_store)
    try:
        await adapter.run()
    finally:
        evidence_store.close()
        store.close()


def main() -> None:
    os.umask(0o077)
    configure_logging()
    try:
        asyncio.run(async_main())
    except ConfigurationError, RuntimeError, OSError, UnicodeError:
        logging.getLogger("gatekeeper.main").critical("startup_failed")
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
