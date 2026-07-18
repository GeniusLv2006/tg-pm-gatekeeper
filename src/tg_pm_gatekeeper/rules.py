# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit

from .policy import EvidenceSignal, SignalSource

URL_RE = re.compile(r"(?i)(?:https?://|tg://|www\.)[^\s<>()\[\]{}]+")
TRAILING_URL_PUNCTUATION = ".,;:!?，。；：！？'\"”’》】）"
ASCII_HOSTNAME_RE = re.compile(
    r"(?i)^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)

PROMOTION_TERMS: dict[str, tuple[str, ...]] = {
    "general": (
        "推广",
        "联盟",
        "引流",
        "代发",
        "代理",
        "加盟",
        "promotion",
        "affiliate",
    ),
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
LOW_INFORMATION_OPENERS = frozenset(
    {"在吗", "滴滴", "你好", "您好", "hi", "hello", "hey"}
)


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


def campaign_link_kind(url: str) -> str:
    kind = telegram_link_kind(url)
    return {
        "invite": "telegram-invite",
        "public_username": "telegram-public",
        "internal_message": "telegram-internal",
        "bot_start": "telegram-bot",
        "external_web": "external-web",
    }.get(kind, "unknown-link")


def campaign_template_text(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text).casefold()
    templated = URL_RE.sub(
        lambda match: f"<{campaign_link_kind(match.group(0))}>",
        normalized,
    )
    return " ".join(templated.split())


def campaign_link_kinds(urls: tuple[str, ...]) -> tuple[str, ...]:
    distinct: dict[str, str] = {}
    for url in urls:
        key = normalized_url_key(url)
        if key is not None:
            distinct.setdefault(key, campaign_link_kind(url))
    return tuple(sorted(distinct.values()))


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


def _signal(
    code: str,
    source: SignalSource,
    weight: int,
    explanation: str,
) -> EvidenceSignal:
    return EvidenceSignal(code, source, weight, explanation)


def detect_evidence_signals(
    facts: MessageFacts,
    *,
    previous_link_messages: int = 0,
    denylist: frozenset[str] = frozenset(),
) -> tuple[EvidenceSignal, ...]:
    signals: list[EvidenceSignal] = []
    normalized = normalize_text(facts.text)
    normalized_preview = normalize_text(facts.preview_text)
    normalized_quote = normalize_text(facts.quote_text)
    authored_promotion = any(
        term in normalized
        for terms in PROMOTION_TERMS.values()
        for term in terms
    )
    preview_promotion = any(
        term in normalized_preview
        for terms in PROMOTION_TERMS.values()
        for term in terms
    )
    quoted_promotion = any(
        term in normalized_quote
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
    quoted_promotion = quoted_promotion or (
        quoted_crypto_asset
        and quoted_service_signals >= 2
        and quoted_commercial_signal
    )

    link_button_count = max(facts.link_button_count, int(facts.has_link_button))
    authored_url_keys = {
        key for url in facts.urls if (key := normalized_url_key(url)) is not None
    }
    preview_url_keys = {
        key
        for url in facts.preview_urls
        if (key := normalized_url_key(url)) is not None
    }
    quote_url_keys = {
        key
        for url in facts.quote_urls
        if (key := normalized_url_key(url)) is not None
    }
    all_urls = tuple(facts.urls) + tuple(facts.quote_urls)
    link_kinds = {telegram_link_kind(url) for url in all_urls}

    if normalized in LOW_INFORMATION_OPENERS:
        signals.append(
            _signal(
                "LOW_INFORMATION_OPENER",
                "authored",
                5,
                "The authored message is a low-information opener.",
            )
        )
    if any(kind == "invite" for kind in link_kinds):
        authored_invite = any(
            telegram_link_kind(url) == "invite" and url not in facts.preview_urls
            for url in facts.urls
        )
        preview_invite = any(
            telegram_link_kind(url) == "invite" for url in facts.preview_urls
        )
        source: SignalSource = (
            "authored"
            if authored_invite
            else "preview" if preview_invite else "quoted"
        )
        signals.append(
            _signal(
                "TELEGRAM_INVITE",
                source,
                10,
                "A Telegram invitation link is present.",
            )
        )
    invite_button = any(
        telegram_link_kind(url) == "invite" for url in facts.button_urls
    )
    if link_button_count == 1 and not invite_button:
        signals.append(
            _signal(
                "LINK_BUTTON",
                "button",
                10,
                "The message contains one interactive link button.",
            )
        )
    if facts.is_forwarded:
        signals.append(
            _signal(
                "FORWARDED_PAYLOAD",
                "behavior",
                10,
                "Telegram marks the message as forwarded.",
            )
        )
    if previous_link_messages >= 1 and facts.has_link:
        signals.append(
            _signal(
                "LINK_BURST",
                "behavior",
                10,
                "The sender recently sent another link-bearing message.",
            )
        )
    if len(authored_url_keys) >= 2 or len(set(facts.domains)) >= 2:
        signals.append(
            _signal(
                "MULTIPLE_LINKS",
                "preview" if len(preview_url_keys) >= 2 else "authored",
                15,
                "The message or webpage preview contains multiple distinct links.",
            )
        )
    if len(quote_url_keys) >= 2 or len(set(facts.quote_domains)) >= 2:
        signals.append(
            _signal(
                "QUOTED_MULTIPLE_LINKS",
                "quoted",
                15,
                "The quoted context contains multiple distinct links.",
            )
        )
    if quoted_promotion:
        signals.append(
            _signal(
                "QUOTED_PROMOTIONAL_LANGUAGE",
                "quoted",
                15,
                "The quoted context contains promotional language.",
            )
        )
    if "external_web" in link_kinds and "invite" in link_kinds:
        signals.append(
            _signal(
                "EXTERNAL_AND_TELEGRAM_LINKS",
                "behavior",
                15,
                "External web and Telegram invitation links appear together.",
            )
        )
    if authored_promotion:
        signals.append(
            _signal(
                "PROMOTIONAL_LANGUAGE",
                "authored",
                20,
                "The authored message contains promotional language.",
            )
        )
    elif preview_promotion:
        signals.append(
            _signal(
                "PREVIEW_PROMOTIONAL_LANGUAGE",
                "preview",
                20,
                "Telegram webpage preview metadata contains promotional language.",
            )
        )
    if facts.is_forwarded and facts.has_link_button:
        signals.append(
            _signal(
                "FORWARDED_LINK_BUTTON",
                "button",
                25,
                "A forwarded message contains an interactive link button.",
            )
        )
    elif link_button_count >= 2:
        signals.append(
            _signal(
                "MULTIPLE_LINK_BUTTONS",
                "button",
                25,
                "The message contains multiple interactive link buttons.",
            )
        )
    authored_denied_code: str | None = None
    if denylist and any(
        domain_is_denied(domain, denylist) for domain in facts.domains
    ):
        button_domains = {
            domain
            for url in facts.button_urls
            if (domain := normalized_domain(url)) is not None
        }
        preview_domains = {
            domain
            for url in facts.preview_urls
            if (domain := normalized_domain(url)) is not None
        }
        authored_denied_code = (
            "BUTTON_DENIED_DOMAIN"
            if any(domain_is_denied(domain, denylist) for domain in button_domains)
            else (
                "PREVIEW_DENIED_DOMAIN"
                if any(
                    domain_is_denied(domain, denylist)
                    for domain in preview_domains
                )
                else "AUTHORED_DENIED_DOMAIN"
            )
        )
    if authored_denied_code is not None:
        signals.append(
            _signal(
                authored_denied_code,
                "owner_policy",
                100,
                "A non-quoted link matches the owner's local domain denylist.",
            )
        )
    elif denylist and any(
        domain_is_denied(domain, denylist) for domain in facts.quote_domains
    ):
        signals.append(
            _signal(
                "QUOTED_DENIED_DOMAIN",
                "owner_policy",
                30,
                "A quoted-context link matches the owner's local domain denylist.",
            )
        )

    return tuple(signals)


def campaign_candidate(
    facts: MessageFacts, signals: tuple[EvidenceSignal, ...]
) -> str | None:
    codes = {signal.code for signal in signals}
    quote_link_kinds = campaign_link_kinds(facts.quote_urls)
    authored_link_kinds = campaign_link_kinds(facts.urls)
    preview_link_kinds = campaign_link_kinds(facts.preview_urls)
    if "QUOTED_PROMOTIONAL_LANGUAGE" in codes and len(quote_link_kinds) >= 2:
        text = campaign_template_text(facts.quote_text)
        link_kinds = quote_link_kinds
        source = "quoted"
    elif (
        "PREVIEW_PROMOTIONAL_LANGUAGE" in codes
        and len(preview_link_kinds) >= 2
    ):
        text = campaign_template_text(
            "\n".join((facts.text, facts.preview_text, *facts.button_texts))
        )
        link_kinds = authored_link_kinds
        source = "preview"
    elif "PROMOTIONAL_LANGUAGE" in codes and len(authored_link_kinds) >= 2:
        text = campaign_template_text(
            "\n".join((facts.text, facts.preview_text, *facts.button_texts))
        )
        link_kinds = authored_link_kinds
        source = "authored"
    else:
        return None
    if not text or not link_kinds:
        return None
    return f"adaptive-v2:{source}:{text}:{'|'.join(link_kinds)}"


def repeated_campaign_signal() -> EvidenceSignal:
    return _signal(
        "REPEATED_CAMPAIGN",
        "behavior",
        40,
        "The same promotional template appeared from another sender within 7 days.",
    )
