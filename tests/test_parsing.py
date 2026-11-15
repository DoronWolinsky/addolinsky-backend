"""E. Subtitle parsing and formatting."""

import io
import zipfile

import pytest

from addolinsky.subtitles.parsing import MAX_FILE_BYTES, Cue, SubtitleError, extract_archive, parse_subtitle
from addolinsky.subtitles.rendering import PDF, RLE, build_srt, wrap_lines

SRT = "1\n00:00:01,000 --> 00:00:02,500\nHello there.\n\n2\n00:00:03,000 --> 00:00:04,000\nSecond line\nwith two rows.\n"


def test_normal_srt():
    p = parse_subtitle(SRT.encode())
    assert p.format == "srt" and len(p.cues) == 2
    assert (p.cues[0].start_ms, p.cues[0].end_ms) == (1000, 2500)
    assert p.cues[1].text == "Second line\nwith two rows."  # multi-line caption preserved
    assert p.cues[0].cue_id == f"{p.content_hash[:6]}-0001"


def test_vtt():
    p = parse_subtitle(b"WEBVTT\n\n00:01.000 --> 00:02.000\nHi\n\n00:03.000 --> 00:04.500\n<b>Bold</b> text\n")
    assert p.format == "vtt" and [c.text for c in p.cues] == ["Hi", "Bold text"]


def test_bom_crlf_and_lf_give_same_content_hash():
    a = parse_subtitle(SRT.encode())
    b = parse_subtitle(b"\xef\xbb\xbf" + SRT.replace("\n", "\r\n").encode())
    assert a.content_hash == b.content_hash and b.encoding == "utf-8-sig"


def test_utf16_and_legacy_encodings():
    assert parse_subtitle(SRT.encode("utf-16")).cues[0].text == "Hello there."
    for lang, codec, line in (("he", "cp1255", "שלום עולם, מה שלומך היום?"), ("ar", "cp1256", "مرحبا، كيف حالك اليوم؟"),
                              ("ru", "cp1251", "Привет, как дела сегодня?"), ("fr", "cp1252", "Ça va très bien, merci.")):
        data = f"1\n00:00:01,000 --> 00:00:02,000\n{line}\n".encode(codec)
        p = parse_subtitle(data, lang_hint=lang)
        assert p.cues[0].text == line and p.encoding == codec


def test_strips_formatting_and_bidi_markers():
    s = "1\n00:00:01,000 --> 00:00:02,000\n<i>‫Hi</i> {\\an8}<font color=\"red\">you</font>‏\n"
    assert parse_subtitle(s.encode()).cues[0].text == "Hi you"


@pytest.mark.parametrize("data,code", [
    (b"", "empty"), (b"   \n\n", "empty"),
    (b"\x00\x01\x02binary\x00" * 10, "binary"),
    (b"\xff\xfe\x00\x00" + "x".encode("utf-32-le"), "unsupported_encoding"),
    (b"just some prose, not subtitles at all", "unknown_format"),
    (b"x" * (MAX_FILE_BYTES + 1), "too_large"),
])
def test_rejects_bad_input(data, code):
    with pytest.raises(SubtitleError) as e:
        parse_subtitle(data)
    assert e.value.code == code


def test_malformed_timestamp_block_is_dropped_not_merged():
    s = SRT + "\n3\n00:00:0x,000 --> 00:00:06,000\nbroken\n\n4\n00:00:07,000 --> 00:00:08,000\nok\n"
    p = parse_subtitle(s.encode())
    texts = [c.text for c in p.cues]
    assert "broken" not in " ".join(texts) and "-->" not in " ".join(texts)
    assert texts[-1] == "ok"
    assert any(w.startswith("malformed_block") for w in p.warnings)


def test_zero_negative_duration_ordering_duplicates_overlaps():
    s = ("1\n00:00:05,000 --> 00:00:06,000\nlater\n\n"
         "2\n00:00:01,000 --> 00:00:01,000\nzero\n\n"
         "3\n00:00:03,000 --> 00:00:02,000\nnegative\n\n"
         "3\n00:00:02,000 --> 00:00:04,000\nearly\n\n"
         "4\n00:00:02,000 --> 00:00:04,000\nearly\n\n"
         "5\n00:00:03,500 --> 00:00:05,500\noverlap\n")
    p = parse_subtitle(s.encode())
    assert [c.text for c in p.cues] == ["early", "overlap", "later"]
    w = " ".join(p.warnings)
    for tag in ("non_positive_duration", "reordered_cues", "duplicate_cue", "overlapping_cues"):
        assert tag in w


def test_empty_after_tags_and_oversized_cue():
    s = ("1\n00:00:01,000 --> 00:00:02,000\n<i></i>\n\n2\n00:00:03,000 --> 00:00:04,000\n" + "a" * 600 +
         "\n\n3\n00:00:05,000 --> 00:00:06,000\nfine\n")
    p = parse_subtitle(s.encode())
    assert [c.text for c in p.cues] == ["fine"]


def _srt_n(n: int) -> bytes:
    from addolinsky.subtitles.rendering import fmt_ts
    return "".join(f"{i}\n{fmt_ts(i * 1000)} --> {fmt_ts(i * 1000 + 500)}\nline {i}\n\n" for i in range(1, n + 1)).encode()


def test_too_many_cues_rejected_and_limit_accepted():
    assert len(parse_subtitle(_srt_n(5000)).cues) == 5000
    with pytest.raises(SubtitleError) as e:
        parse_subtitle(_srt_n(5001))
    assert e.value.code == "too_many_cues"


def _zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for k, v in entries.items():
            z.writestr(k, v)
    return buf.getvalue()


def test_archive_extracts_only_subtitles_in_memory():
    out = extract_archive(_zip({"../../evil/a.srt": SRT.encode(), "readme.txt": b"x", "dir/b.vtt": b"WEBVTT\n"}))
    assert [n for n, _ in out] == ["a.srt", "b.vtt"]  # path components stripped, never used as paths


@pytest.mark.parametrize("blob", [b"PK\x03\x04garbage", b"not a zip"])
def test_malformed_archive(blob):
    with pytest.raises(SubtitleError):
        extract_archive(blob)


def test_zip_bomb_is_bounded():
    bomb = _zip({"big.srt": b"0" * (MAX_FILE_BYTES + 10)})  # compresses to a few KB
    assert len(bomb) < 50_000
    with pytest.raises(SubtitleError) as e:
        extract_archive(bomb)
    assert e.value.code == "too_large"


def test_too_many_archive_entries():
    with pytest.raises(SubtitleError):
        extract_archive(_zip({f"{i}.srt": SRT.encode() for i in range(25)}))


def test_hebrew_srt_rtl_wrapping_and_roundtrip():
    cues = [Cue("x-0001", 0, 1000, 2500, "Hi."), Cue("x-0002", 1, 3000, 4000, "Who?")]
    long = "זה משפט ארוך מאוד שצריך להתפצל לשתי שורות כדי שיהיה קריא, נכון?"
    srt = build_srt(cues, {"x-0001": "שלום, מה שלומך?", "x-0002": long})
    assert srt.count(RLE) == srt.count(PDF) == 3
    assert len(wrap_lines(long)) == 2
    p = parse_subtitle(srt.encode("utf-8"))
    assert [(c.start_ms, c.end_ms) for c in p.cues] == [(1000, 2500), (3000, 4000)]
    assert p.cues[0].text == "שלום, מה שלומך?"  # punctuation kept; bidi controls stripped on re-read


def test_srt_writer_refuses_empty_text():
    with pytest.raises(ValueError):
        build_srt([Cue("x-0001", 0, 0, 10, "a")], {"x-0001": "  ‫‬ "})
