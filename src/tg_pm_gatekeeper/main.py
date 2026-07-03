from __future__ import annotations

import asyncio
import logging
import os

from .config import ConfigurationError, Settings, read_private_file
from .crypto import IdentifierProtector
from .dataset import DatasetProtector, TrainingStore
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
    training_store = TrainingStore(
        settings.dataset_path,
        DatasetProtector(
            read_private_file(settings.dataset_key_file, minimum_bytes=32)
        ),
    )
    service = GatekeeperService(
        store,
        protector,
        challenge_ttl_seconds=settings.challenge_ttl_seconds,
        challenge_max_attempts=settings.challenge_max_attempts,
        outbound_limit_per_hour=settings.outbound_limit_per_hour,
        review_retention_days=settings.review_retention_days,
        denylist=load_denylist(settings.denylist_file),
        test_sender_id=settings.test_sender_id,
        training_store=training_store,
        dataset_collection=settings.dataset_collection,
        dataset_retention_days=settings.dataset_retention_days,
        dataset_max_messages_per_sender=settings.dataset_max_messages_per_sender,
    )
    adapter = TelegramAdapter(settings, store, service, training_store=training_store)
    try:
        await adapter.run()
    finally:
        if training_store is not None:
            training_store.close()
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
