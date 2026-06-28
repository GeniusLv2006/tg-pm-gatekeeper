from __future__ import annotations

import unittest

from tg_pm_gatekeeper.rules import (
    MessageFacts,
    evaluate_hard_rules,
    normalize_text,
    normalized_domain,
)


class RuleTests(unittest.TestCase):
    def test_link_button_is_hard_rule(self) -> None:
        decision = evaluate_hard_rules(MessageFacts(has_link_button=True))
        self.assertIn("HR-01_LINK_BUTTON", decision.rule_codes)

    def test_forwarded_link_is_hard_rule(self) -> None:
        decision = evaluate_hard_rules(
            MessageFacts(urls=("https://example.invalid",), is_forwarded=True)
        )
        self.assertIn("HR-02_FORWARDED_LINK_OR_BUTTON", decision.rule_codes)

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
        self.assertIn(
            "HR-07_QUOTED_CRYPTO_SERVICE_PROMOTION", decision.rule_codes
        )

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

    def test_second_link_message_is_burst(self) -> None:
        decision = evaluate_hard_rules(
            MessageFacts(urls=("https://example.invalid",)), previous_link_messages=1
        )
        self.assertIn("HR-05_LINK_BURST", decision.rule_codes)

    def test_subdomain_denylist_matches(self) -> None:
        decision = evaluate_hard_rules(
            MessageFacts(domains=("a.bad.invalid",), urls=("https://a.bad.invalid",)),
            denylist=frozenset({"bad.invalid"}),
        )
        self.assertIn("HR-06_DENIED_DOMAIN", decision.rule_codes)

    def test_normalization_and_domain_do_not_fetch(self) -> None:
        self.assertEqual(normalize_text("  ＶＰＮ  Subscription "), "vpn subscription")
        self.assertEqual(
            normalized_domain("https://例子.测试/path"), "xn--fsqu00a.xn--0zwm56d"
        )


if __name__ == "__main__":
    unittest.main()
