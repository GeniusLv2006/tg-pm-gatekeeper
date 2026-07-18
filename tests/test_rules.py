# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import unittest

from tg_pm_gatekeeper.policy import EvidenceSignal, PolicyEngine
from tg_pm_gatekeeper.rules import (
    MessageFacts,
    campaign_candidate,
    detect_evidence_signals,
    normalize_text,
    normalized_domain,
    repeated_campaign_signal,
    telegram_link_kind,
    url_evidence,
    url_shape,
)


class RuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = PolicyEngine()

    @staticmethod
    def signal_map(facts: MessageFacts, **kwargs) -> dict[str, EvidenceSignal]:
        return {
            signal.code: signal
            for signal in detect_evidence_signals(facts, **kwargs)
        }

    def test_url_shape_excludes_path_and_query_values(self) -> None:
        shape = url_shape(
            ("http://example.invalid/private/path?token=secret#fragment",)
        )
        self.assertEqual(
            shape,
            {
                "has_fragment": True,
                "has_non_root_path": True,
                "has_query": True,
                "max_path_depth": 2,
                "uses_plain_http": True,
            },
        )

    def test_url_evidence_keeps_full_url_sources_and_telegram_kind(self) -> None:
        records = url_evidence(
            (
                "https://t.me/+syntheticInvite",
                "https://example.invalid/private/path?token=synthetic#fragment",
            ),
            button_urls=("https://t.me/+syntheticInvite",),
            preview_urls=(
                "https://example.invalid/private/path?token=synthetic#fragment",
            ),
        )
        self.assertEqual(records[0]["kind"], "external_web")
        self.assertEqual(records[0]["sources"], ["preview"])
        self.assertEqual(records[1]["kind"], "invite")
        self.assertEqual(records[1]["sources"], ["button"])

    def test_telegram_link_kind_classifies_common_shapes(self) -> None:
        self.assertEqual(telegram_link_kind("https://t.me/joinchat/abc"), "invite")
        self.assertEqual(telegram_link_kind("https://t.me/bot?start=abc"), "bot_start")
        self.assertEqual(
            telegram_link_kind("https://t.me/c/123/456"), "internal_message"
        )
        self.assertEqual(
            telegram_link_kind("https://t.me/public_name"), "public_username"
        )
        self.assertEqual(telegram_link_kind("tg://join?invite=abc"), "invite")

    def test_signal_weights_and_sources_are_explicit(self) -> None:
        signals = self.signal_map(
            MessageFacts(
                text="滴滴",
                quote_text=(
                    "推广联盟 https://landing.invalid "
                    "https://t.me/+syntheticInvite"
                ),
                quote_urls=(
                    "https://landing.invalid",
                    "https://t.me/+syntheticInvite",
                ),
                quote_domains=("landing.invalid", "t.me"),
                is_forwarded=True,
            )
        )
        self.assertEqual(signals["LOW_INFORMATION_OPENER"].weight, 5)
        self.assertEqual(signals["LOW_INFORMATION_OPENER"].source, "authored")
        self.assertEqual(signals["FORWARDED_PAYLOAD"].weight, 10)
        self.assertEqual(signals["QUOTED_MULTIPLE_LINKS"].weight, 15)
        self.assertEqual(signals["QUOTED_PROMOTIONAL_LANGUAGE"].weight, 15)
        self.assertEqual(signals["EXTERNAL_AND_TELEGRAM_LINKS"].weight, 15)

    def test_authored_button_preview_and_owner_policy_sources_are_explicit(self) -> None:
        single_button = self.signal_map(
            MessageFacts(has_link_button=True, link_button_count=1)
        )
        self.assertEqual(single_button["LINK_BUTTON"].weight, 10)
        self.assertEqual(single_button["LINK_BUTTON"].source, "button")

        authored = self.signal_map(
            MessageFacts(
                text="联盟推广",
                urls=("https://one.invalid", "https://two.invalid"),
                domains=("one.invalid", "two.invalid"),
            )
        )
        self.assertEqual(authored["MULTIPLE_LINKS"].weight, 15)
        self.assertEqual(authored["PROMOTIONAL_LANGUAGE"].weight, 20)
        self.assertEqual(authored["PROMOTIONAL_LANGUAGE"].source, "authored")

        preview = self.signal_map(MessageFacts(preview_text="推广联盟"))
        self.assertEqual(
            preview["PREVIEW_PROMOTIONAL_LANGUAGE"].source, "preview"
        )

        forwarded_buttons = self.signal_map(
            MessageFacts(
                has_link_button=True,
                link_button_count=2,
                is_forwarded=True,
            )
        )
        self.assertEqual(forwarded_buttons["FORWARDED_LINK_BUTTON"].weight, 25)
        self.assertNotIn("MULTIPLE_LINK_BUTTONS", forwarded_buttons)

        invite_button = self.signal_map(
            MessageFacts(
                urls=("https://t.me/+syntheticInvite",),
                button_urls=("https://t.me/+syntheticInvite",),
                has_link_button=True,
                link_button_count=1,
            )
        )
        self.assertEqual(invite_button["TELEGRAM_INVITE"].weight, 10)
        self.assertNotIn("LINK_BUTTON", invite_button)

        for source_field, expected_source in (
            ("button_urls", "button"),
            ("preview_urls", "preview"),
        ):
            blocked_url = "https://blocked.invalid/offer"
            facts = MessageFacts(
                urls=(blocked_url,),
                domains=("blocked.invalid",),
                **{source_field: (blocked_url,)},
            )
            denied_signals = self.signal_map(
                facts, denylist=frozenset({"blocked.invalid"})
            )
            code = f"{expected_source.upper()}_DENIED_DOMAIN"
            denied = denied_signals[code]
            self.assertEqual(denied.weight, 100)
            self.assertEqual(denied.source, "owner_policy")

    def test_low_score_uses_standard_challenge(self) -> None:
        decision = self.policy.decide(
            detect_evidence_signals(MessageFacts(text="你好"))
        )
        self.assertEqual(decision.risk_score, 5)
        self.assertEqual(decision.challenge_profile, "standard")
        self.assertEqual(decision.planned_action, "standard_challenge")

    def test_policy_threshold_boundaries_are_exact(self) -> None:
        below_strict = self.policy.decide(
            (EvidenceSignal("SYNTHETIC", "behavior", 29, "Boundary fixture"),)
        )
        at_strict = self.policy.decide(
            (EvidenceSignal("SYNTHETIC", "behavior", 30, "Boundary fixture"),)
        )
        below_permanent = self.policy.decide(
            (
                EvidenceSignal(
                    "AUTHORED_DENIED_DOMAIN",
                    "owner_policy",
                    69,
                    "Boundary fixture",
                ),
            )
        )
        at_permanent = self.policy.decide(
            (
                EvidenceSignal(
                    "AUTHORED_DENIED_DOMAIN",
                    "owner_policy",
                    70,
                    "Boundary fixture",
                ),
            )
        )
        self.assertEqual(below_strict.planned_action, "standard_challenge")
        self.assertEqual(at_strict.planned_action, "strict_challenge")
        self.assertEqual(below_permanent.planned_action, "strict_challenge")
        self.assertEqual(at_permanent.planned_action, "permanent_suppression")

    def test_multiple_link_buttons_use_strict_challenge_not_suppression(self) -> None:
        decision = self.policy.decide(
            detect_evidence_signals(
                MessageFacts(has_link_button=True, link_button_count=3)
            )
        )
        self.assertEqual(decision.risk_score, 25)
        self.assertEqual(decision.challenge_profile, "standard")
        forwarded = self.policy.decide(
            detect_evidence_signals(
                MessageFacts(
                    has_link_button=True,
                    link_button_count=3,
                    is_forwarded=True,
                )
            )
        )
        self.assertGreaterEqual(forwarded.risk_score, 30)
        self.assertEqual(forwarded.challenge_profile, "strict")
        self.assertEqual(forwarded.planned_action, "strict_challenge")

    def test_nonquoted_denied_domain_is_permanent_suppression(self) -> None:
        signals = detect_evidence_signals(
            MessageFacts(
                urls=("https://blocked.invalid/path",),
                domains=("blocked.invalid",),
            ),
            denylist=frozenset({"blocked.invalid"}),
        )
        decision = self.policy.decide(signals)
        denied = {signal.code: signal for signal in signals}[
            "AUTHORED_DENIED_DOMAIN"
        ]
        self.assertEqual(denied.source, "owner_policy")
        self.assertEqual(decision.risk_score, 100)
        self.assertEqual(decision.planned_action, "permanent_suppression")
        self.assertEqual(decision.decision_basis, "owner_denied_domain")

    def test_quoted_denied_domain_cannot_cross_destructive_gate_alone(self) -> None:
        decision = self.policy.decide(
            detect_evidence_signals(
                MessageFacts(
                    quote_urls=("https://blocked.invalid/path",),
                    quote_domains=("blocked.invalid",),
                ),
                denylist=frozenset({"blocked.invalid"}),
            )
        )
        self.assertEqual(decision.risk_score, 30)
        self.assertEqual(decision.challenge_profile, "strict")
        self.assertEqual(decision.planned_action, "strict_challenge")

    def test_weak_signals_cannot_bypass_destructive_gate(self) -> None:
        signals = tuple(
            EvidenceSignal(f"WEAK_{index}", "behavior", 10, "Synthetic weak signal")
            for index in range(8)
        )
        decision = self.policy.decide(signals)
        self.assertEqual(decision.risk_score, 80)
        self.assertEqual(decision.planned_action, "strict_challenge")
        self.assertEqual(decision.challenge_profile, "strict")

    def test_repeated_forwarded_promotional_campaign_can_suppress(self) -> None:
        facts = MessageFacts(
            text="在吗",
            quote_text=(
                "联盟推广 https://landing.invalid "
                "https://t.me/+syntheticInvite"
            ),
            quote_urls=(
                "https://landing.invalid",
                "https://t.me/+syntheticInvite",
            ),
            quote_domains=("landing.invalid", "t.me"),
            is_forwarded=True,
        )
        signals = detect_evidence_signals(facts) + (repeated_campaign_signal(),)
        decision = self.policy.decide(signals)
        self.assertGreaterEqual(decision.risk_score, 70)
        self.assertEqual(decision.planned_action, "permanent_suppression")
        self.assertEqual(
            decision.decision_basis, "corroborated_repeated_campaign"
        )

    def test_campaign_candidate_ignores_outer_low_information_opener(self) -> None:
        quote = (
            "联盟推广 https://landing.invalid "
            "https://t.me/+syntheticInvite"
        )
        first = MessageFacts(
            text="在吗",
            quote_text=quote,
            quote_urls=(
                "https://landing.invalid",
                "https://t.me/+syntheticInvite",
            ),
        )
        second = MessageFacts(
            text="滴滴",
            quote_text=quote,
            quote_urls=(
                "https://landing.invalid",
                "https://t.me/+syntheticInvite",
            ),
        )
        self.assertEqual(
            campaign_candidate(first, detect_evidence_signals(first)),
            campaign_candidate(second, detect_evidence_signals(second)),
        )

    def test_campaign_template_ignores_rotating_domains_and_invite_tokens(self) -> None:
        def campaign(domain: str, first_invite: str, second_invite: str) -> MessageFacts:
            quote = (
                f"888联盟网址 https://{domain}\n"
                f"888联盟频道 https://t.me/+{first_invite}\n"
                f"乔治引流代发 https://t.me/+{second_invite}"
            )
            return MessageFacts(
                text="在吗",
                quote_text=quote,
                quote_urls=(
                    f"https://{domain}",
                    f"https://t.me/+{first_invite}",
                    f"https://t.me/+{second_invite}",
                ),
                quote_domains=(domain, "t.me"),
                is_forwarded=True,
            )

        first = campaign("h4226.invalid", "firstToken", "secondToken")
        second = campaign("h5388.invalid", "thirdToken", "fourthToken")
        self.assertEqual(
            campaign_candidate(first, detect_evidence_signals(first)),
            campaign_candidate(second, detect_evidence_signals(second)),
        )

    def test_campaign_template_preserves_surrounding_text_and_link_shape(self) -> None:
        first = MessageFacts(
            quote_text="联盟推广甲 https://first.invalid https://t.me/+first",
            quote_urls=("https://first.invalid", "https://t.me/+first"),
        )
        different_text = MessageFacts(
            quote_text="联盟推广乙 https://second.invalid https://t.me/+second",
            quote_urls=("https://second.invalid", "https://t.me/+second"),
        )
        different_shape = MessageFacts(
            quote_text="联盟推广甲 https://third.invalid https://fourth.invalid",
            quote_urls=("https://third.invalid", "https://fourth.invalid"),
        )
        first_candidate = campaign_candidate(first, detect_evidence_signals(first))
        self.assertNotEqual(
            first_candidate,
            campaign_candidate(different_text, detect_evidence_signals(different_text)),
        )
        self.assertNotEqual(
            first_candidate,
            campaign_candidate(
                different_shape, detect_evidence_signals(different_shape)
            ),
        )

    def test_campaign_template_normalizes_hidden_entity_targets(self) -> None:
        first = MessageFacts(
            quote_text="联盟推广 click join",
            quote_urls=("https://first.invalid/path", "https://t.me/+first"),
        )
        second = MessageFacts(
            quote_text="联盟推广 click join",
            quote_urls=("https://second.invalid/other", "https://t.me/+second"),
        )
        self.assertEqual(
            campaign_candidate(first, detect_evidence_signals(first)),
            campaign_candidate(second, detect_evidence_signals(second)),
        )

    def test_single_link_promotion_does_not_seed_campaign_detection(self) -> None:
        facts = MessageFacts(
            text="联盟推广 https://single.invalid",
            urls=("https://single.invalid",),
            domains=("single.invalid",),
        )
        self.assertIsNone(campaign_candidate(facts, detect_evidence_signals(facts)))

    def test_richard_preview_scores_strict_without_permanent_suppression(self) -> None:
        post = "https://t.me/hysqguangfang/917"
        invite = "https://t.me/+syntheticInvite"
        facts = MessageFacts(
            text=post,
            preview_text=(
                "Telegram 汇盈俱乐部 七年合约社区交流群: "
                f"{invite} 免费带单 70%返佣 BTC/ETH 行情分析"
            ),
            urls=(post, invite),
            domains=("t.me",),
            preview_urls=(post, invite),
        )
        decision = self.policy.decide(detect_evidence_signals(facts))
        self.assertEqual(
            {signal.code: signal.weight for signal in decision.signals},
            {
                "TELEGRAM_INVITE": 10,
                "MULTIPLE_LINKS": 15,
                "PREVIEW_PROMOTIONAL_LANGUAGE": 20,
            },
        )
        self.assertEqual(decision.risk_score, 45)
        self.assertEqual(decision.planned_action, "strict_challenge")

    def test_nonpromotional_message_has_no_campaign_candidate(self) -> None:
        facts = MessageFacts(
            text="请看文档",
            urls=("https://docs.invalid",),
            domains=("docs.invalid",),
        )
        self.assertIsNone(campaign_candidate(facts, detect_evidence_signals(facts)))

    def test_second_authored_link_message_is_a_behavior_signal(self) -> None:
        signals = self.signal_map(
            MessageFacts(urls=("https://example.invalid",)),
            previous_link_messages=1,
        )
        self.assertEqual(signals["LINK_BURST"].weight, 10)
        self.assertEqual(signals["LINK_BURST"].source, "behavior")

    def test_normalization_and_domain_do_not_fetch(self) -> None:
        self.assertEqual(normalize_text("  ＶＰＮ  Subscription "), "vpn subscription")
        self.assertEqual(
            normalized_domain("https://例子.测试/path"), "xn--fsqu00a.xn--0zwm56d"
        )


if __name__ == "__main__":
    unittest.main()
