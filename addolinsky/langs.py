"""Canonicalize language identifiers from subtitle sources and user input to base ISO 639 codes."""

from __future__ import annotations

import re

import langcodes

# Non-standard codes used by subtitle sites and common English names.
_SPECIAL = {
    "pob": "pt", "pb": "pt", "pt-br": "pt", "ze": "zh", "zt": "zh", "sp": "es", "ea": "es", "iw": "he",
    "english": "en", "french": "fr", "spanish": "es", "arabic": "ar", "russian": "ru", "hebrew": "he",
    "german": "de", "italian": "it", "portuguese": "pt", "ukrainian": "uk", "polish": "pl", "turkish": "tr",
}


def canonical_lang(tag: str | None) -> str | None:
    """Map 'en', 'eng', 'en-US', 'English', 'fre', 'pob'... to a base ISO 639-1/3 code, or None."""
    if not tag:
        return None
    t = tag.strip().lower().replace("_", "-")
    if not t or len(t) > 35 or not re.fullmatch(r"[a-z0-9-]+", t):
        return None
    if t in _SPECIAL:
        return _SPECIAL[t]
    try:
        lang = langcodes.Language.get(t).language
    except (langcodes.tag_parser.LanguageTagError, ValueError):
        return None
    if not lang or not re.fullmatch(r"[a-z]{2,3}", lang) or not langcodes.tag_is_valid(lang):
        return None
    return _SPECIAL.get(lang, lang)
