"""Deterministic synthetic subtitle tracks for alignment/selection tests (original content)."""

from __future__ import annotations

import random

from addolinsky.subtitles.parsing import Cue, make_cue_id
from addolinsky.subtitles.rendering import fmt_ts


def timeline(n: int, seed: int, start_ms: int = 5000) -> list[tuple[int, int]]:
    rnd = random.Random(seed)
    out, t = [], start_ms
    for _ in range(n):
        gap = rnd.choice([300, 500, 800, 1200, 2000, 4000]) if rnd.random() > 0.05 else rnd.randint(15000, 40000)
        dur = rnd.randint(900, 4500)
        t += gap
        out.append((t, t + dur))
        t += dur
    return out


def cues_from(times: list[tuple[int, int]], texts: list[str], tag: str) -> list[Cue]:
    h = (tag * 6)[:6]
    return [Cue(make_cue_id(h, i), i, s, e, txt) for i, ((s, e), txt) in enumerate(zip(times, texts, strict=True))]


def transform(times, scale=1.0, offset=0):
    return [(round(s * scale + offset), round(e * scale + offset)) for s, e in times]


def to_srt(times, texts) -> str:
    return "\n".join(f"{i}\n{fmt_ts(s)} --> {fmt_ts(e)}\n{t}\n" for i, ((s, e), t) in enumerate(zip(times, texts, strict=True), 1))


def texts(n: int, prefix: str) -> list[str]:
    return [f"{prefix} line {i} number {i * 7}" for i in range(n)]
