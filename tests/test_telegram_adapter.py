from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

from telethon import functions, types

from tg_pm_gatekeeper.config import ConfigurationError
from tg_pm_gatekeeper.crypto import IdentifierProtector
from tg_pm_gatekeeper.service import GatekeeperService
from tg_pm_gatekeeper.service import TextStyleSpan
from tg_pm_gatekeeper.store import DialogSnapshot, StateStore
from tg_pm_gatekeeper.telegram_adapter import (
    TelegramAdapter,
    TelegramActions,
    facts_from_message,
    formatting_entities_from_spans,
    input_peer_from_sender,
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

    def test_webpage_preview_text_and_url_are_extracted(self) -> None:
        webpage = SimpleNamespace(
            url="https://t.me/+invite",
            site_name="Telegram",
            title="汇盈社区 高返70% 合约跟单",
            description="免费跟单，交易所返佣",
            author=None,
        )
        facts = facts_from_message(
            self.message(
                message="T.me/+invite",
                media=SimpleNamespace(webpage=webpage),
            )
        )
        self.assertIn("https://t.me/+invite", facts.urls)
        self.assertIn("t.me", facts.domains)
        self.assertIn("高返70%", facts.preview_text)
        self.assertIn("交易所返佣", facts.preview_text)

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

    def test_formatting_spans_use_telegram_utf16_offsets(self) -> None:
        text = "🔐 Verification required"
        entities = formatting_entities_from_spans(
            text, (TextStyleSpan(offset=2, length=12),)
        )
        self.assertEqual(len(entities), 1)
        self.assertIsInstance(entities[0], types.MessageEntityBold)
        self.assertEqual(entities[0].offset, 3)
        self.assertEqual(entities[0].length, 12)

    def test_input_peer_is_rebuilt_from_resolved_sender(self) -> None:
        peer = input_peer_from_sender(SimpleNamespace(id=123, access_hash=456))
        self.assertIsInstance(peer, types.InputPeerUser)
        self.assertEqual((peer.user_id, peer.access_hash), (123, 456))
        self.assertIsNone(input_peer_from_sender(SimpleNamespace(id=123)))


class FakeHistoryClient:
    def __init__(self, messages) -> None:
        self.messages = messages

    async def iter_messages(self, *args, **kwargs):
        for message in self.messages:
            yield message


class PartialArchiveClient:
    def __init__(
        self,
        *,
        fail_first_mute: bool = True,
        folder_id: int = 0,
        silent: bool = False,
        mute_until=None,
    ) -> None:
        self.requests: list[object] = []
        self.fail_first_mute = fail_first_mute
        self.failed_mute = False
        self.folder_id = folder_id
        self.silent = silent
        self.mute_until = mute_until

    async def __call__(self, request):
        self.requests.append(request)
        if isinstance(request, functions.messages.GetPeerDialogsRequest):
            return SimpleNamespace(
                dialogs=[
                    SimpleNamespace(
                        folder_id=self.folder_id,
                        notify_settings=SimpleNamespace(
                            silent=self.silent, mute_until=self.mute_until
                        ),
                    )
                ]
            )
        if (
            isinstance(request, functions.account.UpdateNotifySettingsRequest)
            and self.fail_first_mute
            and not self.failed_mute
        ):
            self.failed_mute = True
            raise RuntimeError("mute failed")


class FakeSnapshotStore:
    def __init__(self) -> None:
        self.snapshot = None

    def dialog_snapshot(self, sender_key: str):
        return self.snapshot

    def save_dialog_snapshot(self, sender_key: str, snapshot) -> None:
        self.snapshot = snapshot

    def clear_dialog_snapshot(self, sender_key: str) -> None:
        self.snapshot = None


class TelegramActionTests(unittest.IsolatedAsyncioTestCase):
    async def test_partial_archive_failure_is_compensated(self) -> None:
        client = PartialArchiveClient()
        adapter = SimpleNamespace(
            client=client,
            settings=SimpleNamespace(mute_days=30),
            store=FakeSnapshotStore(),
        )
        peer = types.InputPeerUser(user_id=123, access_hash=456)
        actions = TelegramActions(adapter, peer, "sender")
        self.assertFalse(await actions.archive_and_mute())
        folder_requests = [
            request
            for request in client.requests
            if isinstance(request, functions.folders.EditPeerFoldersRequest)
        ]
        self.assertEqual(
            [request.folder_peers[0].folder_id for request in folder_requests],
            [1, 0],
        )

    async def test_restore_reinstates_original_dialog_settings(self) -> None:
        original_mute = datetime(2026, 8, 1, tzinfo=timezone.utc)
        client = PartialArchiveClient(
            fail_first_mute=False,
            folder_id=0,
            silent=True,
            mute_until=original_mute,
        )
        store = FakeSnapshotStore()
        adapter = SimpleNamespace(
            client=client,
            settings=SimpleNamespace(mute_days=30),
            store=store,
        )
        peer = types.InputPeerUser(user_id=123, access_hash=456)
        actions = TelegramActions(adapter, peer, "sender")
        self.assertTrue(await actions.archive_and_mute())
        self.assertTrue(await actions.restore_from_pending())
        folder_requests = [
            request
            for request in client.requests
            if isinstance(request, functions.folders.EditPeerFoldersRequest)
        ]
        self.assertEqual(
            [request.folder_peers[0].folder_id for request in folder_requests],
            [1, 0],
        )
        notify_requests = [
            request
            for request in client.requests
            if isinstance(request, functions.account.UpdateNotifySettingsRequest)
        ]
        restored = notify_requests[-1].settings
        self.assertTrue(restored.silent)
        self.assertEqual(restored.mute_until, original_mute)
        self.assertIsNone(store.snapshot)


class TelegramActionDeletionTests(unittest.IsolatedAsyncioTestCase):
    async def test_delete_messages_uses_one_revoked_batch(self) -> None:
        client = SimpleNamespace(delete_messages=AsyncMock())
        adapter = SimpleNamespace(client=client)
        peer = types.InputPeerUser(user_id=123, access_hash=456)
        actions = TelegramActions(adapter, peer, "sender")

        self.assertTrue(await actions.delete_messages((10, 11, 12)))

        client.delete_messages.assert_awaited_once_with(
            peer, [10, 11, 12], revoke=True
        )

    async def test_delete_dialog_revokes_history_and_clears_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "state.sqlite3")
            try:
                store.save_dialog_snapshot(
                    "sender", DialogSnapshot(folder_id=0, silent=False, mute_until=None)
                )
                client = SimpleNamespace(delete_dialog=AsyncMock())
                adapter = SimpleNamespace(client=client, store=store)
                peer = types.InputPeerUser(user_id=123, access_hash=456)
                actions = TelegramActions(adapter, peer, "sender")

                self.assertTrue(await actions.delete_dialog())

                client.delete_dialog.assert_awaited_once_with(peer, revoke=True)
                self.assertIsNone(store.dialog_snapshot("sender"))
            finally:
                store.close()


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
