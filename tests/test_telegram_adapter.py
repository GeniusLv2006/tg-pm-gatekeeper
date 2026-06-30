from __future__ import annotations

import unittest
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from telethon import types

from tg_pm_gatekeeper.config import ConfigurationError
from tg_pm_gatekeeper.crypto import IdentifierProtector
from tg_pm_gatekeeper.service import GatekeeperService
from tg_pm_gatekeeper.store import StateStore
from tg_pm_gatekeeper.telegram_adapter import (
    TelegramAdapter,
    facts_from_message,
    load_denylist,
    message_timestamp,
    reply_to_message_id,
    write_runtime_heartbeat,
)


class TelegramAdapterTests(unittest.TestCase):
    def message(self, **overrides):
        values = {
            "message": "",
            "entities": [],
            "reply_markup": None,
            "media": None,
            "fwd_from": None,
            "via_bot_id": None,
            "reply_to": None,
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    def test_url_entity_without_scheme_is_detected(self) -> None:
        text = "看看 t.me/spam"
        facts = facts_from_message(
            self.message(
                message=text,
                entities=[types.MessageEntityUrl(offset=3, length=9)],
            )
        )
        self.assertIn("t.me/spam", facts.urls)

    def test_url_button_is_detected_structurally(self) -> None:
        markup = SimpleNamespace(
            rows=[
                SimpleNamespace(
                    buttons=[types.KeyboardButtonUrl("open", "https://bad.invalid")]
                )
            ]
        )
        facts = facts_from_message(self.message(reply_markup=markup))
        self.assertTrue(facts.has_link_button)
        self.assertEqual(facts.link_button_count, 1)
        self.assertIn("bad.invalid", facts.domains)

    def test_quoted_text_and_entities_are_extracted(self) -> None:
        quote = "TRX 服务 click"
        reply_to = SimpleNamespace(
            quote_text=quote,
            quote_entities=[
                types.MessageEntityTextUrl(
                    offset=7, length=5, url="https://bad.invalid"
                )
            ],
        )
        facts = facts_from_message(
            self.message(message="核心在此", reply_to=reply_to)
        )
        self.assertEqual(facts.quote_text, quote)
        self.assertNotIn("https://bad.invalid", facts.urls)
        self.assertNotIn("bad.invalid", facts.domains)
        self.assertIn("https://bad.invalid", facts.quote_urls)
        self.assertIn("bad.invalid", facts.quote_domains)

    def test_unicode_denylist_domain_is_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "denylist.txt"
            path.write_text("例子.测试\n", encoding="utf-8")
            self.assertEqual(
                load_denylist(path), frozenset({"xn--fsqu00a.xn--0zwm56d"})
            )

    def test_configured_missing_denylist_fails_closed(self) -> None:
        with self.assertRaises(ConfigurationError):
            load_denylist(Path("/definitely/missing/denylist.txt"))

    def test_invalid_denylist_domain_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "denylist.txt"
            path.write_text("not a domain\n", encoding="utf-8")
            with self.assertRaises(ConfigurationError):
                load_denylist(path)

    def test_runtime_heartbeat_is_replaced_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "heartbeat"
            write_runtime_heartbeat(path, 100)
            write_runtime_heartbeat(path, 200)
            self.assertEqual(path.read_text(encoding="ascii"), "200")
            self.assertFalse((Path(directory) / ".heartbeat.tmp").exists())

    def test_reply_target_and_message_timestamp_are_extracted(self) -> None:
        date = datetime(2026, 6, 30, tzinfo=timezone.utc)
        message = self.message(
            reply_to=SimpleNamespace(reply_to_msg_id=42), date=date
        )
        self.assertEqual(reply_to_message_id(message), 42)
        self.assertEqual(message_timestamp(message, fallback=1), int(date.timestamp()))


class FakeHistoryClient:
    def __init__(self, messages) -> None:
        self.messages = messages

    async def iter_messages(self, *args, **kwargs):
        for message in self.messages:
            yield message


class TelegramHistoryTests(unittest.IsolatedAsyncioTestCase):
    async def test_automated_outgoing_message_does_not_create_trust(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "state.sqlite3")
            try:
                protector = IdentifierProtector(b"k" * 32)
                service = GatekeeperService(store, protector)
                sender_key = protector.sender_key(123)
                store.record_automated_message(sender_key, 10, 100)
                outgoing = SimpleNamespace(
                    id=10,
                    out=True,
                    message="Verification passed. This conversation has been restored.",
                    date=datetime.fromtimestamp(101, timezone.utc),
                )
                adapter = TelegramAdapter.__new__(TelegramAdapter)
                adapter.store = store
                adapter.service = service
                adapter.client = FakeHistoryClient([outgoing])
                event = SimpleNamespace(
                    input_chat="peer", message=SimpleNamespace(id=11)
                )
                trusted = await adapter._has_prior_outgoing(
                    event, sender_key, since=100
                )
                self.assertFalse(trusted)
            finally:
                store.close()

    async def test_manual_outgoing_message_promotes_trust(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "state.sqlite3")
            try:
                protector = IdentifierProtector(b"k" * 32)
                service = GatekeeperService(store, protector)
                sender_key = protector.sender_key(123)
                outgoing = SimpleNamespace(
                    id=12,
                    out=True,
                    message="Thanks, I will reply shortly.",
                    date=datetime.fromtimestamp(100, timezone.utc),
                )
                adapter = TelegramAdapter.__new__(TelegramAdapter)
                adapter.store = store
                adapter.service = service
                adapter.client = FakeHistoryClient([outgoing])
                event = SimpleNamespace(
                    input_chat="peer", message=SimpleNamespace(id=13)
                )
                trusted = await adapter._has_prior_outgoing(
                    event, sender_key, since=100
                )
                self.assertTrue(trusted)
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
