# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import asyncio
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

from telethon import functions, types

from tg_pm_gatekeeper.config import ConfigurationError
from tg_pm_gatekeeper.crypto import IdentifierProtector
from tg_pm_gatekeeper.restriction_actions import RestrictionReleaseResult
from tg_pm_gatekeeper.service import GatekeeperService, TextStyleSpan
from tg_pm_gatekeeper.store import DialogSnapshot, StateStore
from tg_pm_gatekeeper.telegram_adapter import (
    OperatorCaseControl,
    TelegramActions,
    TelegramAdapter,
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
        facts = facts_from_message(self.message(message="核心在此", reply_to=reply_to))
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
        message = self.message(reply_to=SimpleNamespace(reply_to_msg_id=42), date=date)
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


class OperatorCommandTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = StateStore(Path(self.temp.name) / "state.sqlite3")
        self.protector = IdentifierProtector(b"k" * 32)
        self.service = GatekeeperService(self.store, self.protector)
        self.adapter = TelegramAdapter.__new__(TelegramAdapter)
        self.adapter.store = self.store
        self.adapter.service = self.service
        self.adapter.settings = SimpleNamespace(
            telegram_operator_controls_enabled=True
        )
        self.adapter._self_user_id = 1000
        self.adapter._operator_case_controls = {}
        self.adapter._operator_command_lock = asyncio.Lock()
        self.adapter._restriction_actions = SimpleNamespace(allow=AsyncMock())
        self.adapter.client = SimpleNamespace(
            get_entity=AsyncMock(
                return_value=SimpleNamespace(
                    first_name="Example\n/gatekeeper allow",
                    last_name="Sender\u202e",
                    username="example_sender",
                )
            )
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    @staticmethod
    def event(
        text: str,
        *,
        chat_id: int = 1000,
        outgoing: bool = True,
        reply_to: int | None = None,
        responses: list[object] | None = None,
    ) -> SimpleNamespace:
        reply_header = (
            SimpleNamespace(reply_to_msg_id=reply_to) if reply_to is not None else None
        )
        respond = AsyncMock(
            side_effect=responses
            if responses is not None
            else [SimpleNamespace(id=9000)] * 10
        )
        return SimpleNamespace(
            is_private=True,
            outgoing=outgoing,
            chat_id=chat_id,
            raw_text=text,
            message=SimpleNamespace(reply_to=reply_header),
            respond=respond,
        )

    async def test_ping_works_only_in_saved_messages(self) -> None:
        saved = self.event("/gatekeeper ping")
        await self.adapter._on_operator_message(saved)
        self.assertIn("online", saved.respond.await_args.args[0])

        another_chat = self.event("/gatekeeper ping", chat_id=2000)
        await self.adapter._on_operator_message(another_chat)
        another_chat.respond.assert_not_awaited()

        incoming = self.event("/gatekeeper ping", outgoing=False)
        await self.adapter._on_operator_message(incoming)
        incoming.respond.assert_not_awaited()

    async def test_disabled_operator_controls_ignore_saved_messages(self) -> None:
        self.adapter.settings.telegram_operator_controls_enabled = False
        event = self.event("/gatekeeper ping")

        await self.adapter._on_operator_message(event)

        event.respond.assert_not_awaited()

    async def test_cases_create_reply_bound_controls_without_evidence(self) -> None:
        sender_key = self.protector.sender_key(123456789)
        reference = self.protector.seal_restriction_reference(123456789, -987654321)
        self.store.suppress(
            sender_key,
            "critical_rule",
            until=None,
            restriction_reference=reference,
        )
        event = self.event(
            "/gatekeeper cases",
            responses=[SimpleNamespace(id=10), SimpleNamespace(id=11)],
        )

        await self.adapter._on_operator_message(event)

        self.assertEqual(event.respond.await_count, 2)
        card = event.respond.await_args_list[1].args[0]
        self.assertIn("Example /gatekeeper allow Sender (@example_sender)", card)
        self.assertNotIn("\n/gatekeeper allow", card)
        self.assertNotIn("\u202e", card)
        self.assertIn("Critical Rule", card)
        self.assertIn("Reply to this message with /gatekeeper allow", card)
        self.assertNotIn(sender_key, card)
        self.assertEqual(
            self.adapter._operator_case_controls[11].sender_key,
            sender_key,
        )

    async def test_allow_consumes_reply_control_and_reports_success(self) -> None:
        self.adapter._operator_case_controls[11] = OperatorCaseControl(
            "sender",
            time.monotonic() + 60,
        )
        self.adapter._restriction_actions.allow.return_value = (
            RestrictionReleaseResult.ALLOWED
        )
        event = self.event("/gatekeeper allow", reply_to=11)

        await self.adapter._on_operator_message(event)

        self.adapter._restriction_actions.allow.assert_awaited_once_with("sender")
        self.assertNotIn(11, self.adapter._operator_case_controls)
        self.assertIn("Restriction removed", event.respond.await_args.args[0])

    async def test_allow_rejects_expired_or_unrelated_reply(self) -> None:
        self.adapter._operator_case_controls[11] = OperatorCaseControl(
            "sender",
            time.monotonic() - 1,
        )
        event = self.event("/gatekeeper allow", reply_to=11)

        await self.adapter._on_operator_message(event)

        self.adapter._restriction_actions.allow.assert_not_awaited()
        self.assertIn("current case", event.respond.await_args.args[0])


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

        client.delete_messages.assert_awaited_once_with(peer, [10, 11, 12], revoke=True)

    async def test_delayed_verification_cleanup_deletes_full_batch_and_audits(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "state.sqlite3")
            try:
                client = SimpleNamespace(delete_messages=AsyncMock())
                adapter = TelegramAdapter.__new__(TelegramAdapter)
                adapter.client = client
                adapter.store = store
                peer = types.InputPeerUser(user_id=123, access_hash=456)

                await adapter._verification_message_deletion_worker(
                    peer, "sender", (10, 11, 12, 13, 14), 0
                )

                client.delete_messages.assert_awaited_once_with(
                    peer, [10, 11, 12, 13, 14], revoke=True
                )
                row = store._connection.execute(
                    "SELECT outcome FROM audit WHERE sender_key='sender' "
                    "AND rule_code='CHALLENGE_CLEANUP' ORDER BY id DESC LIMIT 1"
                ).fetchone()
                self.assertEqual(row["outcome"], "messages_deleted")
            finally:
                store.close()

    async def test_delayed_verification_cleanup_records_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "state.sqlite3")
            try:
                client = SimpleNamespace(
                    delete_messages=AsyncMock(side_effect=RuntimeError("delete failed"))
                )
                adapter = TelegramAdapter.__new__(TelegramAdapter)
                adapter.client = client
                adapter.store = store
                peer = types.InputPeerUser(user_id=123, access_hash=456)

                await adapter._verification_message_deletion_worker(
                    peer, "sender", (10, 11), 0
                )

                row = store._connection.execute(
                    "SELECT outcome FROM audit WHERE sender_key='sender' "
                    "AND rule_code='CHALLENGE_CLEANUP' ORDER BY id DESC LIMIT 1"
                ).fetchone()
                self.assertEqual(row["outcome"], "action_failed")
            finally:
                store.close()

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

    async def test_delayed_dialog_worker_deletes_the_dialog_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "state.sqlite3")
            try:
                client = SimpleNamespace(delete_dialog=AsyncMock())
                adapter = TelegramAdapter.__new__(TelegramAdapter)
                adapter.client = client
                adapter.store = store
                protector = IdentifierProtector(b"k" * 32)
                adapter.service = SimpleNamespace(protector=protector)
                peer = types.InputPeerUser(user_id=123, access_hash=456)
                reference = protector.seal_review_reference(123, 456, 1)
                restriction_reference = protector.seal_restriction_reference(123, 456)
                state = store.suppress(
                    "sender",
                    "critical_rule",
                    until=None,
                    reference=reference,
                    restriction_reference=restriction_reference,
                )
                action_id = store.schedule_action(
                    "sender",
                    reason="critical_rule",
                    reference=reference,
                    execute_at=0,
                    expected_revision=state.revision,
                )
                store.set_mode("protect")

                await adapter._dialog_deletion_worker(action_id, 0)

                client.delete_dialog.assert_awaited_once_with(peer, revoke=True)
                retained = store.sender("sender")
                self.assertIsNone(retained.challenge_action_reference)
                self.assertEqual(retained.restriction_reference, restriction_reference)
            finally:
                store.close()

    async def test_invalid_persistent_reference_enters_exception_queue(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "state.sqlite3")
            try:
                adapter = TelegramAdapter.__new__(TelegramAdapter)
                adapter.client = SimpleNamespace(delete_dialog=AsyncMock())
                adapter.store = store
                adapter.service = SimpleNamespace(
                    protector=IdentifierProtector(b"k" * 32)
                )
                state = store.suppress(
                    "sender", "critical_rule", until=None, reference=b"invalid"
                )
                action_id = store.schedule_action(
                    "sender",
                    reason="critical_rule",
                    reference=b"invalid",
                    execute_at=0,
                    expected_revision=state.revision,
                )
                store.set_mode("protect")

                await adapter._dialog_deletion_worker(action_id, 0)

                self.assertEqual(store.statistics()["action_failures"], 1)
                self.assertEqual(store.statistics()["pending_reviews"], 1)
                adapter.client.delete_dialog.assert_not_awaited()
            finally:
                store.close()


class TelegramHistoryTests(unittest.IsolatedAsyncioTestCase):
    async def test_history_lookup_failure_continues_as_untrusted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "state.sqlite3")
            try:
                protector = IdentifierProtector(b"k" * 32)
                service = SimpleNamespace(
                    protector=protector,
                    handle=AsyncMock(return_value="challenged"),
                )
                adapter = TelegramAdapter.__new__(TelegramAdapter)
                adapter.store = store
                adapter.service = service
                adapter.settings = SimpleNamespace(test_sender_id=None)
                adapter._has_prior_outgoing = AsyncMock(
                    side_effect=RuntimeError("telegram lookup failed")
                )
                sender = SimpleNamespace(
                    id=123,
                    access_hash=456,
                    bot=False,
                    contact=False,
                )
                event = SimpleNamespace(
                    is_private=True,
                    message=types.Message(
                        id=1,
                        peer_id=types.PeerUser(123),
                        date=datetime.fromtimestamp(100, timezone.utc),
                        message="hello",
                    ),
                    input_chat=types.InputPeerUser(123, 456),
                    get_sender=AsyncMock(return_value=sender),
                )

                await adapter._on_message(event)

                service.handle.assert_awaited_once()
                incoming = service.handle.await_args.args[0]
                self.assertFalse(incoming.has_trusted_history)
                self.assertEqual(store.statistics()["audit_records"], 1)
            finally:
                store.close()

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


class TelegramRunTests(unittest.IsolatedAsyncioTestCase):
    def make_adapter(self, *, operator_controls: bool = False) -> TelegramAdapter:
        adapter = TelegramAdapter.__new__(TelegramAdapter)
        adapter.client = SimpleNamespace(
            connect=AsyncMock(),
            is_user_authorized=AsyncMock(return_value=True),
            get_me=AsyncMock(return_value=SimpleNamespace(id=1000)),
            add_event_handler=Mock(),
            run_until_disconnected=AsyncMock(),
            disconnect=AsyncMock(),
        )
        adapter._recover_challenges = AsyncMock()
        adapter._recover_test_sender_cleanup = AsyncMock()
        adapter._recover_pending_actions = AsyncMock()
        adapter._review_admin = SimpleNamespace(start=AsyncMock(), stop=AsyncMock())
        adapter._timeout_tasks = {}
        adapter._maintenance_tasks = set()
        adapter._heartbeat_task = None
        adapter.settings = SimpleNamespace(
            telegram_operator_controls_enabled=operator_controls
        )
        return adapter

    async def test_heartbeat_failure_terminates_runtime(self) -> None:
        adapter = self.make_adapter()

        async def wait_for_disconnect() -> None:
            await asyncio.Event().wait()

        adapter.client.run_until_disconnected.side_effect = wait_for_disconnect
        adapter._heartbeat_loop = AsyncMock(
            side_effect=RuntimeError("heartbeat write failed")
        )

        with self.assertRaisesRegex(RuntimeError, "heartbeat write failed"):
            await adapter.run()

        adapter._review_admin.stop.assert_awaited_once()
        adapter.client.disconnect.assert_awaited_once()

    async def test_normal_disconnect_cancels_and_awaits_heartbeat(self) -> None:
        adapter = self.make_adapter()

        async def wait_forever() -> None:
            await asyncio.Event().wait()

        adapter._heartbeat_loop = AsyncMock(side_effect=wait_forever)

        await adapter.run()

        self.assertTrue(adapter._heartbeat_task.done())
        adapter._review_admin.stop.assert_awaited_once()
        adapter.client.disconnect.assert_awaited_once()

    async def test_operator_handler_registration_is_opt_in(self) -> None:
        async def wait_forever() -> None:
            await asyncio.Event().wait()

        disabled = self.make_adapter()
        disabled._heartbeat_loop = AsyncMock(side_effect=wait_forever)
        await disabled.run()
        self.assertEqual(disabled.client.add_event_handler.call_count, 1)

        enabled = self.make_adapter(operator_controls=True)
        enabled._heartbeat_loop = AsyncMock(side_effect=wait_forever)
        await enabled.run()
        self.assertEqual(enabled.client.add_event_handler.call_count, 2)


if __name__ == "__main__":
    unittest.main()
