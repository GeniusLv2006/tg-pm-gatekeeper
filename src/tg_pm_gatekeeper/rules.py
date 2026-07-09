# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit

from .policy import DetectionResult, Severity


URL_RE = re.compile(r"(?i)(?:https?://|tg://|www\.)[^\s<>()\[\]{}]+")
TRAILING_URL_PUNCTUATION = ".,;:!?，。；：！？'\"”’》】）"
ASCII_HOSTNAME_RE = re.compile(
    r"(?i)^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)

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
        "合约跟单",
        "稳赚",
        "套利",
        "合约群",
        "高返",
        "返佣",
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

CRYPTO_SERVICE_TERMS = ("转账", "能量", "带宽", "代付", "gas fee")
COMMERCIAL_TERMS = ("下单", "购买", "出售", "兑换", "客服", "活动", "联系")
CRYPTO_ASSET_RE = re.compile(r"(?<![a-z])(?:trx|usdt|usdc|ton)(?![a-z])")
USERNAME_RE = re.compile(r"(?<![a-z0-9_@])@[a-z0-9_]{5,32}(?![a-z0-9_])", re.IGNORECASE)


def normalize_text(text: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


def normalized_domain(url: str) -> str | None:
    candidate = url.strip().rstrip(TRAILING_URL_PUNCTUATION)
    if "://" not in candidate:
        candidate = "https://" + candidate
    try:
        hostname = urlsplit(candidate).hostname
    except ValueError:
        return None
    if not hostname:
        return None
    try:
        normalized = hostname.rstrip(".").encode("idna").decode("ascii").casefold()
    except UnicodeError:
        return None
    return normalized if ASCII_HOSTNAME_RE.fullmatch(normalized) else None


def normalized_url_key(url: str) -> str | None:
    candidate = url.strip().rstrip(TRAILING_URL_PUNCTUATION)
    if "://" not in candidate:
        candidate = "https://" + candidate
    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        if not hostname:
            return None
        normalized_host = hostname.rstrip(".").encode("idna").decode("ascii").casefold()
        if not ASCII_HOSTNAME_RE.fullmatch(normalized_host):
            return None
        port = f":{parsed.port}" if parsed.port is not None else ""
    except (UnicodeError, ValueError):
        return None
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{normalized_host}{port}{path}{query}"


def url_shape(urls: tuple[str, ...]) -> dict[str, object]:
    has_non_root_path = False
    has_query = False
    has_fragment = False
    uses_plain_http = False
    max_path_depth = 0
    for url in urls:
        candidate = url.strip().rstrip(TRAILING_URL_PUNCTUATION)
        if "://" not in candidate:
            candidate = "https://" + candidate
        try:
            parsed = urlsplit(candidate)
        except ValueError:
            continue
        path_parts = [part for part in parsed.path.split("/") if part]
        has_non_root_path = has_non_root_path or bool(path_parts)
        has_query = has_query or bool(parsed.query)
        has_fragment = has_fragment or bool(parsed.fragment)
        uses_plain_http = uses_plain_http or parsed.scheme.casefold() == "http"
        max_path_depth = max(max_path_depth, min(len(path_parts), 3))
    return {
        "has_fragment": has_fragment,
        "has_non_root_path": has_non_root_path,
        "has_query": has_query,
        "max_path_depth": max_path_depth,
        "uses_plain_http": uses_plain_http,
    }


def telegram_link_kind(url: str) -> str:
    candidate = url.strip().rstrip(TRAILING_URL_PUNCTUATION)
    if "://" not in candidate:
        candidate = "https://" + candidate
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return "unknown"
    scheme = parsed.scheme.casefold()
    try:
        hostname = (
            (parsed.hostname or "").rstrip(".").encode("idna").decode("ascii").casefold()
        )
    except UnicodeError:
        hostname = ""
    query = parse_qs(parsed.query)
    if scheme == "tg":
        if parsed.netloc == "join" or "invite" in query:
            return "invite"
        if "start" in query or "startapp" in query:
            return "bot_start"
        if "domain" in query:
            return "public_username"
        return "unknown"
    if hostname not in {"t.me", "telegram.me"}:
        return "external_web"
    parts = [part for part in parsed.path.split("/") if part]
    if not parts:
        return "unknown"
    first = parts[0].casefold()
    if first == "joinchat" or parts[0].startswith("+"):
        return "invite"
    if first == "c" and len(parts) >= 3:
        return "internal_message"
    if "start" in query or "startapp" in query:
        return "bot_start"
    return "public_username"


def url_evidence(
    urls: tuple[str, ...],
    *,
    button_urls: tuple[str, ...] = (),
    preview_urls: tuple[str, ...] = (),
) -> list[dict[str, object]]:
    button_set = set(button_urls)
    preview_set = set(preview_urls)
    records: list[dict[str, object]] = []
    for url in sorted(set(urls))[:10]:
        sources = ["button"] if url in button_set else []
        if url in preview_set:
            sources.append("preview")
        if url not in button_set and url not in preview_set:
            sources.append("message")
        records.append(
            {
                "url": url,
                "kind": telegram_link_kind(url),
                "sources": sources,
            }
        )
    return records


def domain_is_denied(domain: str, denylist: frozenset[str]) -> bool:
    return any(domain == denied or domain.endswith("." + denied) for denied in denylist)


@dataclass(frozen=True, slots=True)
class MessageFacts:
    text: str = ""
    preview_text: str = ""
    quote_text: str = ""
    urls: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    button_texts: tuple[str, ...] = ()
    button_urls: tuple[str, ...] = ()
    preview_urls: tuple[str, ...] = ()
    quote_urls: tuple[str, ...] = ()
    quote_domains: tuple[str, ...] = ()
    has_link_button: bool = False
    link_button_count: int = 0
    has_any_button: bool = False
    is_forwarded: bool = False
    via_bot: bool = False

    @property
    def has_link(self) -> bool:
        return bool(self.urls or self.has_link_button)


@dataclass(frozen=True, slots=True)
class RuleDecision:
    rule_codes: tuple[str, ...]
    severity: Severity

    @property
    def hard_spam(self) -> bool:
        return self.severity in {"high", "critical"}

    def detection_result(self) -> DetectionResult:
        return DetectionResult(
            detector="hard_rules",
            signals=self.rule_codes,
            severity=self.severity,
        )


def evaluate_hard_rules(
    facts: MessageFacts,
    *,
    previous_link_messages: int = 0,
    denylist: frozenset[str] = frozenset(),
) -> RuleDecision:
    rules: list[str] = []
    normalized = normalize_text(facts.text)
    normalized_preview = normalize_text(facts.preview_text)
    normalized_quote = normalize_text(facts.quote_text)
    promotion = any(
        term in normalized or term in normalized_preview
        for terms in PROMOTION_TERMS.values()
        for term in terms
    )
    quoted_crypto_asset = bool(CRYPTO_ASSET_RE.search(normalized_quote))
    quoted_service_signals = sum(
        term in normalized_quote for term in CRYPTO_SERVICE_TERMS
    )
    quoted_commercial_signal = any(
        term in normalized_quote for term in COMMERCIAL_TERMS
    ) or bool(USERNAME_RE.search(normalized_quote))

    link_button_count = max(facts.link_button_count, int(facts.has_link_button))
    normalized_urls = {
        key for url in facts.urls if (key := normalized_url_key(url)) is not None
    }
    multiple_links = len(normalized_urls) >= 2 or len(set(facts.domains)) >= 2

    if link_button_count >= 2:
        rules.append("HR-01_MULTIPLE_LINK_BUTTONS")
    if facts.is_forwarded and facts.has_link_button:
        rules.append("HR-02_FORWARDED_LINK_BUTTON")
    if promotion and facts.has_link:
        rules.append("HR-03_PROMOTION_WITH_LINK")
    if multiple_links and (facts.is_forwarded or promotion):
        rules.append("HR-04_MULTIPLE_LINKS")
    if previous_link_messages >= 1 and facts.has_link:
        rules.append("HR-05_LINK_BURST")
    if denylist and any(domain_is_denied(domain, denylist) for domain in facts.domains):
        rules.append("HR-06_DENIED_DOMAIN")
    if quoted_crypto_asset and quoted_service_signals >= 2 and quoted_commercial_signal:
        rules.append("HR-07_QUOTED_CRYPTO_SERVICE_PROMOTION")
    critical = {
        "HR-01_MULTIPLE_LINK_BUTTONS",
        "HR-02_FORWARDED_LINK_BUTTON",
        "HR-06_DENIED_DOMAIN",
    }
    high = {
        "HR-03_PROMOTION_WITH_LINK",
        "HR-04_MULTIPLE_LINKS",
        "HR-07_QUOTED_CRYPTO_SERVICE_PROMOTION",
    }
    severity = (
        "critical"
        if critical.intersection(rules)
        else ("high" if high.intersection(rules) else ("signal" if rules else "none"))
    )
    return RuleDecision(rule_codes=tuple(rules), severity=severity)
