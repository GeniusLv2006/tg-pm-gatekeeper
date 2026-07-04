# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import unittest

from tg_pm_gatekeeper.rules import (
    MessageFacts,
    evaluate_hard_rules,
    normalize_text,
    normalized_domain,
)


class RuleTests(unittest.TestCase):
    def test_single_link_button_is_not_a_hard_rule(self) -> None:
        decision = evaluate_hard_rules(MessageFacts(has_link_button=True))
        self.assertFalse(decision.hard_spam)

    def test_multiple_link_buttons_are_a_hard_rule(self) -> None:
        decision = evaluate_hard_rules(
            MessageFacts(has_link_button=True, link_button_count=3)
        )
        self.assertIn("HR-01_MULTIPLE_LINK_BUTTONS", decision.rule_codes)
        self.assertEqual(decision.severity, "critical")

    def test_forwarded_link_button_is_a_hard_rule(self) -> None:
        decision = evaluate_hard_rules(
            MessageFacts(has_link_button=True, is_forwarded=True)
        )
        self.assertIn("HR-02_FORWARDED_LINK_BUTTON", decision.rule_codes)

    def test_forwarded_plain_link_is_not_a_hard_rule(self) -> None:
        decision = evaluate_hard_rules(
            MessageFacts(urls=("https://example.invalid",), is_forwarded=True)
        )
        self.assertFalse(decision.hard_spam)

    def test_topic_without_link_is_not_hard_rule(self) -> None:
        decision = evaluate_hard_rules(MessageFacts(text="你使用什么 VPN？"))
        self.assertFalse(decision.hard_spam)

    def test_quoted_crypto_service_promotion_is_hard_rule(self) -> None:
        decision = evaluate_hard_rules(
            MessageFacts(
                text="核心在此",
                quote_text="0.01TRX 转账 0.01TRX=131K能量+500带宽 @haojia 能量下单地",
            )
        )
        self.assertIn("HR-07_QUOTED_CRYPTO_SERVICE_PROMOTION", decision.rule_codes)

    def test_quoted_crypto_discussion_is_not_hard_rule(self) -> None:
        decision = evaluate_hard_rules(
            MessageFacts(quote_text="TRX 转账为什么需要能量？")
        )
        self.assertFalse(decision.hard_spam)

    def test_promotional_topic_with_link_is_hard_rule(self) -> None:
        decision = evaluate_hard_rules(
            MessageFacts(text="机场推荐 永久套餐", urls=("https://example.invalid",))
        )
        self.assertIn("HR-03_PROMOTION_WITH_LINK", decision.rule_codes)
        self.assertEqual(decision.severity, "high")

    def test_promotional_webpage_preview_with_link_is_hard_rule(self) -> None:
        decision = evaluate_hard_rules(
            MessageFacts(
                text="T.me/+invite",
                preview_text="汇盈社区 高返70% 合约跟单 免费跟单，交易所返佣",
                urls=("https://t.me/+invite",),
            )
        )
        self.assertIn("HR-03_PROMOTION_WITH_LINK", decision.rule_codes)

    def test_ordinary_webpage_preview_with_link_is_not_hard_rule(self) -> None:
        decision = evaluate_hard_rules(
            MessageFacts(
                text="https://example.invalid/article",
                preview_text="Project documentation and release notes",
                urls=("https://example.invalid/article",),
            )
        )
        self.assertFalse(decision.hard_spam)

    def test_quoted_promotion_does_not_pollute_authored_rules(self) -> None:
        decision = evaluate_hard_rules(
            MessageFacts(
                text="这个是什么？",
                quote_text="机场推荐 永久套餐",
                quote_urls=("https://example.invalid",),
                quote_domains=("example.invalid",),
            )
        )
        self.assertFalse(decision.hard_spam)

    def test_equivalent_urls_with_punctuation_are_counted_once(self) -> None:
        decision = evaluate_hard_rules(
            MessageFacts(
                urls=("https://example.invalid", "https://example.invalid。"),
                domains=("example.invalid",),
                is_forwarded=True,
            )
        )
        self.assertFalse(decision.hard_spam)

    def test_multiple_links_require_a_second_risk_signal(self) -> None:
        ordinary = evaluate_hard_rules(
            MessageFacts(
                urls=("https://one.invalid", "https://two.invalid"),
                domains=("one.invalid", "two.invalid"),
            )
        )
        forwarded = evaluate_hard_rules(
            MessageFacts(
                urls=("https://one.invalid", "https://two.invalid"),
                domains=("one.invalid", "two.invalid"),
                is_forwarded=True,
            )
        )
        self.assertFalse(ordinary.hard_spam)
        self.assertIn("HR-04_MULTIPLE_LINKS", forwarded.rule_codes)

    def test_second_link_message_is_burst(self) -> None:
        decision = evaluate_hard_rules(
            MessageFacts(urls=("https://example.invalid",)), previous_link_messages=1
        )
        self.assertIn("HR-05_LINK_BURST", decision.rule_codes)
        self.assertEqual(decision.severity, "signal")

    def test_subdomain_denylist_matches(self) -> None:
        decision = evaluate_hard_rules(
            MessageFacts(domains=("a.bad.invalid",), urls=("https://a.bad.invalid",)),
            denylist=frozenset({"bad.invalid"}),
        )
        self.assertIn("HR-06_DENIED_DOMAIN", decision.rule_codes)
        self.assertEqual(decision.severity, "critical")

    def test_normalization_and_domain_do_not_fetch(self) -> None:
        self.assertEqual(normalize_text("  ＶＰＮ  Subscription "), "vpn subscription")
        self.assertEqual(
            normalized_domain("https://例子.测试/path"), "xn--fsqu00a.xn--0zwm56d"
        )


if __name__ == "__main__":
    unittest.main()
