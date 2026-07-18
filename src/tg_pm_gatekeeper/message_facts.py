# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 GeniusLv2006 and contributors

from __future__ import annotations

from telethon import types

from .rules import URL_RE, MessageFacts, normalized_domain

LINK_BUTTON_TYPES = (
    types.KeyboardButtonUrl,
    types.KeyboardButtonUrlAuth,
    types.KeyboardButtonWebView,
    types.KeyboardButtonSimpleWebView,
)


def _entity_text(text: str, offset: int, length: int) -> str:
    encoded = text.encode("utf-16-le")
    start = offset * 2
    end = (offset + length) * 2
    return encoded[start:end].decode("utf-16-le", errors="ignore")


def _urls_from_text_and_entities(text: str, entities) -> set[str]:
    urls = set(URL_RE.findall(text))
    for entity in entities or []:
        if isinstance(entity, types.MessageEntityTextUrl):
            urls.add(entity.url)
        elif isinstance(entity, types.MessageEntityUrl):
            urls.add(_entity_text(text, entity.offset, entity.length))
    return urls


def facts_from_message(message: types.Message) -> MessageFacts:
    text = message.message or ""
    urls = _urls_from_text_and_entities(text, getattr(message, "entities", None))
    reply_header = getattr(message, "reply_to", None)
    quote_text = getattr(reply_header, "quote_text", None) or ""
    quote_entities = getattr(reply_header, "quote_entities", None) or ()
    quote_urls = _urls_from_text_and_entities(quote_text, quote_entities)

    has_link_button = False
    link_button_count = 0
    has_any_button = False
    button_texts: set[str] = set()
    button_urls: set[str] = set()
    markup = getattr(message, "reply_markup", None)
    for row in getattr(markup, "rows", ()) or ():
        for button in getattr(row, "buttons", ()) or ():
            has_any_button = True
            text_value = getattr(button, "text", None)
            if isinstance(text_value, str) and text_value.strip():
                button_texts.add(text_value.strip())
            url = getattr(button, "url", None)
            if isinstance(button, LINK_BUTTON_TYPES) or isinstance(url, str):
                has_link_button = True
                link_button_count += 1
                if url:
                    urls.add(url)
                    button_urls.add(url)

    webpage = getattr(getattr(message, "media", None), "webpage", None)
    preview_text = "\n".join(
        value
        for attribute in ("site_name", "title", "description", "author")
        if isinstance((value := getattr(webpage, attribute, None)), str) and value
    )
    preview_urls = _urls_from_text_and_entities(preview_text, ())
    webpage_url = getattr(webpage, "url", None)
    if webpage_url:
        preview_urls.add(webpage_url)
    urls.update(preview_urls)
    domains = tuple(
        sorted({domain for url in urls if (domain := normalized_domain(url))})
    )
    quote_domains = tuple(
        sorted({domain for url in quote_urls if (domain := normalized_domain(url))})
    )
    return MessageFacts(
        text=text,
        preview_text=preview_text,
        quote_text=quote_text,
        urls=tuple(sorted(urls)),
        domains=domains,
        button_texts=tuple(sorted(button_texts)),
        button_urls=tuple(sorted(button_urls)),
        preview_urls=tuple(sorted(preview_urls)),
        quote_urls=tuple(sorted(quote_urls)),
        quote_domains=quote_domains,
        has_link_button=has_link_button,
        link_button_count=link_button_count,
        has_any_button=has_any_button,
        is_forwarded=getattr(message, "fwd_from", None) is not None,
        via_bot=getattr(message, "via_bot_id", None) is not None,
    )
