"""Render translated Hebrew cues as an SRT file and validate the result before it can be published.

Timings always come from the English cues. Each displayed line is wrapped in RLE (U+202B) ... PDF (U+202C), the
approach used by shaharsha/hebrew-subtitle-translator (MIT), so punctuation renders on the correct side in players
that do not set paragraph direction."""

from __future__ import annotations

import re

from .parsing import BIDI_CONTROLS, Cue, SubtitleError, parse_subtitle

RLE, PDF = "‫", "‬"
MAX_LINE = 42
HEBREW_LETTER_RE = re.compile(r"[֐-׿]")
TIMESTAMP_LIKE_RE = re.compile(r"\d{1,2}:\d{2}:\d{2}[,.]\d{1,3}")


class FinalValidationError(Exception):
    def __init__(self, problems: list[str]):
        super().__init__("; ".join(problems[:10]))
        self.problems = problems


def fmt_ts(ms: int) -> str:
    hours, remainder = divmod(ms, 3_600_000)
    minutes, remainder = divmod(remainder, 60_000)
    seconds, milliseconds = divmod(remainder, 1000)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d},{milliseconds:03d}"


def clean_hebrew(text: str) -> str:
    without_controls = BIDI_CONTROLS.sub("", text.replace("\r", ""))
    lines = [re.sub(r"\s+", " ", line).strip() for line in without_controls.split("\n")]
    return "\n".join(line for line in lines if line)


def wrap_lines(text: str, max_line: int = MAX_LINE) -> list[str]:
    lines = clean_hebrew(text).split("\n")
    if len(lines) == 1 and len(lines[0]) > max_line:
        line = lines[0]
        middle = len(line) // 2
        spaces = [index for index, char in enumerate(line) if char == " "]
        if spaces:
            cut = min(spaces, key=lambda index: abs(index - middle))
            lines = [line[:cut].strip(), line[cut + 1:].strip()]
    return [line for line in lines if line]


def build_srt(cues: list[Cue], texts: dict[str, str]) -> str:
    blocks = []
    for number, cue in enumerate(cues, start=1):
        lines = wrap_lines(texts[cue.cue_id])
        if not lines:
            raise ValueError(f"empty text for cue {cue.cue_id}")
        body = "\n".join(f"{RLE}{line}{PDF}" for line in lines)
        blocks.append(f"{number}\n{fmt_ts(cue.start_ms)} --> {fmt_ts(cue.end_ms)}\n{body}")
    return "\n\n".join(blocks) + "\n"


def hebrew_issue(text: str, source: str) -> str | None:
    """An issue code if a Hebrew candidate for this English source line is unusable, else None."""
    candidate = (text or "").strip()
    if not candidate:
        return "empty"
    if "-->" in candidate or TIMESTAMP_LIKE_RE.search(candidate):
        return "timestamp"
    letters = [char for char in candidate if char.isalpha()]
    if letters:
        hebrew_letters = sum(1 for char in letters if HEBREW_LETTER_RE.match(char))
        if hebrew_letters / len(letters) < 0.5:
            return "non_hebrew"
    elif any(char.isalpha() for char in source):
        return "non_hebrew"
    if len(candidate) > max(90, 3 * len(source) + 40):
        return "too_long"
    if candidate.count("\n") > 2:
        return "too_many_lines"
    return None


def finalize_srt(cues: list[Cue], hebrew_by_cue_id: dict[str, str],
                 english_by_cue_id: dict[str, str]) -> tuple[str, dict]:
    """The final SRT and its validation report. Raises FinalValidationError unless every cue has usable Hebrew and
    the rendered file parses back with the same cue count, timings and text: an invalid result is never published."""
    texts = _validated_texts(cues, hebrew_by_cue_id, english_by_cue_id)
    srt = build_srt(cues, texts)
    _check_round_trip(cues, texts, srt)
    readability_warnings = []
    for cue in cues:
        lines = wrap_lines(texts[cue.cue_id])
        characters_per_second = len(texts[cue.cue_id]) / max(0.5, cue.duration_ms / 1000)
        if characters_per_second > 20 or any(len(line) > MAX_LINE + 8 for line in lines) or len(lines) > 2:
            readability_warnings.append({"cue_id": cue.cue_id, "cps": round(characters_per_second, 1),
                                         "lines": len(lines)})
    report = {"cues": len(cues), "srt_bytes": len(srt.encode("utf-8")), "rtl_wrapped": srt.count(RLE) == srt.count(PDF),
              "readability_warnings": readability_warnings[:50],
              "readability_warning_count": len(readability_warnings)}
    return srt, report


def _validated_texts(cues: list[Cue], hebrew_by_cue_id: dict[str, str],
                     english_by_cue_id: dict[str, str]) -> dict[str, str]:
    problems: list[str] = []
    texts: dict[str, str] = {}
    for cue in cues:
        if cue.cue_id not in hebrew_by_cue_id:
            problems.append(f"missing_translation:{cue.cue_id}")
            continue
        text = clean_hebrew(hebrew_by_cue_id[cue.cue_id])
        issue = hebrew_issue(text, english_by_cue_id.get(cue.cue_id, ""))
        if issue:
            problems.append(f"{issue}:{cue.cue_id}")
            continue
        texts[cue.cue_id] = text
    if problems:
        raise FinalValidationError(problems)
    return texts


def _check_round_trip(cues: list[Cue], texts: dict[str, str], srt: str) -> None:
    try:
        reparsed = parse_subtitle(srt.encode("utf-8"))
    except SubtitleError as error:
        raise FinalValidationError([f"srt_unparseable:{error.code}"]) from error
    if len(reparsed.cues) != len(cues):
        raise FinalValidationError([f"cue_count_mismatch:{len(reparsed.cues)}!={len(cues)}"])
    for original, parsed in zip(cues, reparsed.cues, strict=True):
        if (original.start_ms, original.end_ms) != (parsed.start_ms, parsed.end_ms):
            raise FinalValidationError([f"timing_changed:{original.cue_id}"])
        if parsed.text.replace("\n", " ") != " ".join(wrap_lines(texts[original.cue_id])):
            raise FinalValidationError([f"text_roundtrip:{original.cue_id}"])
