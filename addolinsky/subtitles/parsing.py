"""Subtitle decoding, parsing, validation and normalization.

All subtitle input is untrusted. Every limit here is enforced before any expensive work.
Parsing is delegated to pysubs2 (MIT); this module adds validation, normalization and stable IDs.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import unicodedata
import warnings
import zipfile
from dataclasses import dataclass, field

import charset_normalizer
import pysubs2
from pysubs2.formats import autodetect_format

MAX_FILE_BYTES = 2_000_000
MAX_CUES = 5000
MAX_CUE_CHARS = 500
MAX_TIME_MS = 6 * 3600 * 1000
SUPPORTED_FORMATS = {"srt", "vtt", "ass", "ssa"}
SUBTITLE_EXTENSIONS = (".srt", ".vtt", ".ass", ".ssa")
ARCHIVE_MAX_ENTRIES = 20
ARCHIVE_MAX_TOTAL = 5_000_000

BIDI_CONTROLS = re.compile("[‎‏‪-‮⁦-⁩﻿]")
_HTML_TAG = re.compile(r"</?[A-Za-z][^<>]{0,200}>")
_ASS_TAG = re.compile(r"\{[^{}]{0,300}\}")
_TIMESTAMP_ARROW = re.compile(r"-->")


class SubtitleError(ValueError):
    def __init__(self, code: str, message: str = ""):
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code


@dataclass(frozen=True)
class Cue:
    cue_id: str
    index: int
    start_ms: int
    end_ms: int
    text: str

    @property
    def duration_ms(self) -> int:
        return self.end_ms - self.start_ms


@dataclass
class ParsedSubtitle:
    content_hash: str  # hash of normalized cues (encoding/format independent)
    raw_sha256: str
    format: str
    encoding: str
    cues: list[Cue]
    warnings: list[str] = field(default_factory=list)


LEGACY_CODEPAGES = {
    "he": ("cp1255", r"[֐-׿]"), "ar": ("cp1256", r"[؀-ۿ]"), "ru": ("cp1251", r"[Ѐ-ӿ]"),
    "uk": ("cp1251", r"[Ѐ-ӿ]"), "pl": ("cp1250", r"[A-Za-zĀ-ſ]"), "tr": ("cp1254", r"[A-Za-zÀ-ɏ]"),
    "fr": ("cp1252", r"[A-Za-zÀ-ÿ]"), "es": ("cp1252", r"[A-Za-zÀ-ÿ]"),
    "it": ("cp1252", r"[A-Za-zÀ-ÿ]"), "pt": ("cp1252", r"[A-Za-zÀ-ÿ]"),
    "de": ("cp1252", r"[A-Za-zÀ-ÿ]"), "en": ("cp1252", r"[A-Za-zÀ-ÿ]"),
}


def _try_legacy(data: bytes, lang_hint: str | None) -> tuple[str, str] | None:
    if lang_hint not in LEGACY_CODEPAGES:
        return None
    codec, script = LEGACY_CODEPAGES[lang_hint]
    try:
        text = data.decode(codec)
    except UnicodeDecodeError:
        return None
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return None
    in_script = sum(1 for c in letters if re.match(script, c))
    # non-Latin scripts: most letters must be in the expected script (names may be Latin)
    return (text, codec) if in_script / len(letters) >= 0.6 else None


def decode_bytes(data: bytes, lang_hint: str | None = None) -> tuple[str, str]:
    if len(data) > MAX_FILE_BYTES:
        raise SubtitleError("too_large", f"{len(data)} bytes > {MAX_FILE_BYTES}")
    if not data.strip():
        raise SubtitleError("empty", "file is empty")
    if data.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        raise SubtitleError("unsupported_encoding", "UTF-32 is not supported")
    boms = ((b"\xef\xbb\xbf", "utf-8-sig"), (b"\xff\xfe", "utf-16"), (b"\xfe\xff", "utf-16"))
    text = enc = None
    for bom, codec in boms:
        if data.startswith(bom):
            try:
                text, enc = data.decode(codec), codec
            except UnicodeDecodeError as e:
                raise SubtitleError("bad_encoding", f"invalid {codec}") from e
            break
    if text is None:
        try:
            text, enc = data.decode("utf-8"), "utf-8"
        except UnicodeDecodeError:
            legacy = _try_legacy(data, lang_hint)
            if legacy:
                text, enc = legacy
            else:
                best = charset_normalizer.from_bytes(data).best()
                if best is None or best.encoding is None:
                    raise SubtitleError("unsupported_encoding", "could not detect encoding") from None
                text, enc = str(best), best.encoding
    if "\x00" in text:
        raise SubtitleError("binary", "NUL characters found")
    ctrl = sum(1 for ch in text if unicodedata.category(ch) == "Cc" and ch not in "\n\r\t")
    if ctrl > max(3, len(text) // 200):
        raise SubtitleError("binary", "too many control characters")
    return text, enc


def normalize_text(raw: str) -> str:
    t = raw.replace("\\N", "\n").replace("\\n", "\n")
    t = _HTML_TAG.sub("", t)
    t = _ASS_TAG.sub("", t)
    t = BIDI_CONTROLS.sub("", t)
    t = unicodedata.normalize("NFC", t)
    lines = [re.sub(r"[ \t]+", " ", ln).strip() for ln in t.split("\n")]
    return "\n".join(ln for ln in lines if ln)


def _clean_merged_block(text: str) -> tuple[str, bool]:
    """pysubs2 appends a block with a malformed timestamp to the previous cue. Cut it off."""
    lines = text.split("\n")
    for i, ln in enumerate(lines):
        if ln.strip() == "" or _TIMESTAMP_ARROW.search(ln):
            kept = lines[:i]
            while kept and kept[-1].strip().isdigit() and _TIMESTAMP_ARROW.search(ln):
                kept.pop()
            return "\n".join(kept), True
    return text, False


def make_cue_id(content_hash: str, index: int) -> str:
    return f"{content_hash[:6]}-{index + 1:04d}"


def parse_subtitle(data: bytes, lang_hint: str | None = None) -> ParsedSubtitle:
    text, enc = decode_bytes(data, lang_hint)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    try:
        fmt = autodetect_format(text)
    except Exception as e:  # pysubs2 raises several exception types for unknown content
        raise SubtitleError("unknown_format", "not a recognised subtitle file") from e
    if fmt not in SUPPORTED_FORMATS:
        raise SubtitleError("unsupported_format", str(fmt))
    warn: list[str] = []
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        try:
            subs = pysubs2.SSAFile.from_string(text, format_=fmt)
        except Exception as e:
            raise SubtitleError("parse_error", type(e).__name__) from e
    if caught:
        warn.append(f"parser_warnings:{len(caught)}")

    raw_items: list[tuple[int, int, str]] = []
    for ev in subs:
        if getattr(ev, "is_comment", False) or getattr(ev, "is_drawing", False):
            continue
        plain = ev.plaintext if fmt in ("ass", "ssa") else ev.text
        if fmt not in ("ass", "ssa"):
            plain = pysubs2.SSAEvent(text=plain).plaintext
        plain, merged = _clean_merged_block(plain.replace("\r", ""))
        if merged:
            warn.append(f"malformed_block_at:{ev.start}")
        t = normalize_text(plain)
        if not t:
            warn.append(f"empty_cue_at:{ev.start}")
            continue
        if len(t) > MAX_CUE_CHARS:
            warn.append(f"oversized_cue_at:{ev.start}")
            continue
        s, e = int(ev.start), int(ev.end)
        if s < 0 or e > MAX_TIME_MS:
            warn.append(f"out_of_range_at:{s}")
            continue
        if e <= s:
            warn.append(f"non_positive_duration_at:{s}")
            continue
        raw_items.append((s, e, t))

    ordered = sorted(raw_items, key=lambda x: (x[0], x[1]))
    if ordered != raw_items:
        warn.append("reordered_cues")
    deduped: list[tuple[int, int, str]] = []
    seen = set()
    for item in ordered:
        if item in seen:
            warn.append(f"duplicate_cue_at:{item[0]}")
            continue
        seen.add(item)
        deduped.append(item)
    overlaps = sum(1 for a, b in zip(deduped, deduped[1:], strict=False) if b[0] < a[1])
    if overlaps:
        warn.append(f"overlapping_cues:{overlaps}")
    if not deduped:
        raise SubtitleError("no_cues", "no valid cues found")
    if len(deduped) > MAX_CUES:
        raise SubtitleError("too_many_cues", f"{len(deduped)} > {MAX_CUES}")

    content_hash = hashlib.sha256(json.dumps(deduped, ensure_ascii=False).encode()).hexdigest()
    cues = [Cue(make_cue_id(content_hash, i), i, s, e, t) for i, (s, e, t) in enumerate(deduped)]
    return ParsedSubtitle(content_hash, hashlib.sha256(data).hexdigest(), fmt, enc, cues, warn)


def extract_archive(data: bytes) -> list[tuple[str, bytes]]:
    """Return subtitle files from a ZIP held in memory. Nothing is written to disk; names are not used as paths."""
    if len(data) > ARCHIVE_MAX_TOTAL:
        raise SubtitleError("too_large", "archive too large")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, ValueError) as e:
        raise SubtitleError("bad_archive", "not a valid zip") from e
    infos = [i for i in zf.infolist() if not i.is_dir()]
    if len(infos) > ARCHIVE_MAX_ENTRIES:
        raise SubtitleError("bad_archive", "too many entries")
    out: list[tuple[str, bytes]] = []
    total = 0
    for info in infos:
        name = info.filename.replace("\\", "/").rsplit("/", 1)[-1]
        if not name.lower().endswith(SUBTITLE_EXTENSIONS):
            continue
        if info.file_size > MAX_FILE_BYTES:
            raise SubtitleError("too_large", "archive entry too large")
        try:
            with zf.open(info) as fh:
                blob = fh.read(MAX_FILE_BYTES + 1)  # never trust the declared size
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError, EOFError) as e:
            raise SubtitleError("bad_archive", "unreadable entry") from e
        if len(blob) > MAX_FILE_BYTES:
            raise SubtitleError("too_large", "archive entry too large")
        total += len(blob)
        if total > ARCHIVE_MAX_TOTAL:
            raise SubtitleError("too_large", "archive expands too much")
        out.append((name, blob))
    if not out:
        raise SubtitleError("bad_archive", "no subtitle files in archive")
    return out
