from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlsplit


URL_RE = re.compile(r"(?i)(?:https?://|tg://|www\.)[^\s<>()\[\]{}]+")

PROMOTION_TERMS: dict[str, tuple[str, ...]] = {
    "gambling": (
        "博彩",
        "下注",
        "投注",
        "娱乐城",
        "包赢",
        "反水",
        "盘口",
        "betting",
        "casino",
    ),
    "crypto": (
        "带单",
        "稳赚",
        "套利",
        "合约群",
        "空投",
        "搬砖",
        "量化",
        "交易所返佣",
        "crypto signal",
        "guaranteed return",
        "airdrop",
    ),
    "vpn": (
        "机场推荐",
        "机场订阅",
        "节点订阅",
        "专线节点",
        "低倍率",
        "永久套餐",
        "流媒体解锁",
        "翻墙机场",
        "vpn subscription",
        "proxy subscription",
    ),
}


def normalize_text(text: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


def normalized_domain(url: str) -> str | None:
    candidate = url.strip().rstrip(".,;:!?，。；：！？")
    if candidate.lower().startswith("www."):
        candidate = "https://" + candidate
    try:
        hostname = urlsplit(candidate).hostname
    except ValueError:
        return None
    if not hostname:
        return None
    try:
        return hostname.rstrip(".").encode("idna").decode("ascii").casefold()
    except UnicodeError:
        return None


def domain_is_denied(domain: str, denylist: frozenset[str]) -> bool:
    return any(domain == denied or domain.endswith("." + denied) for denied in denylist)


@dataclass(frozen=True, slots=True)
class MessageFacts:
    text: str = ""
    urls: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    has_link_button: bool = False
    has_any_button: bool = False
    is_forwarded: bool = False
    via_bot: bool = False

    @property
    def has_link(self) -> bool:
        return bool(self.urls or self.has_link_button)


@dataclass(frozen=True, slots=True)
class RuleDecision:
    hard_spam: bool
    rule_codes: tuple[str, ...]


def evaluate_hard_rules(
    facts: MessageFacts,
    *,
    previous_link_messages: int = 0,
    denylist: frozenset[str] = frozenset(),
) -> RuleDecision:
    rules: list[str] = []
    normalized = normalize_text(facts.text)
    promotion = any(
        term in normalized for terms in PROMOTION_TERMS.values() for term in terms
    )

    if facts.has_link_button:
        rules.append("HR-01_LINK_BUTTON")
    if facts.is_forwarded and (facts.has_link or facts.has_any_button):
        rules.append("HR-02_FORWARDED_LINK_OR_BUTTON")
    if promotion and facts.has_link:
        rules.append("HR-03_PROMOTION_WITH_LINK")
    if len(set(facts.urls)) >= 2 or len(set(facts.domains)) >= 2:
        rules.append("HR-04_MULTIPLE_LINKS")
    if previous_link_messages >= 1 and facts.has_link:
        rules.append("HR-05_LINK_BURST")
    if denylist and any(domain_is_denied(domain, denylist) for domain in facts.domains):
        rules.append("HR-06_DENIED_DOMAIN")
    return RuleDecision(hard_spam=bool(rules), rule_codes=tuple(rules))
