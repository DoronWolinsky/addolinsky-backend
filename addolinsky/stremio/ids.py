"""Canonical title identity for Stremio video ids and validation of Stremio subtitle requests.

Stremio passes the id of the catalog the viewer opened the title from. Cinemeta uses IMDb ids (`tt123`, `tt123:S:E`);
the Anime Kitsu catalog uses Kitsu ids (`kitsu:50040`, `kitsu:50040:EP`). Everything downstream (cache, source
subtitles, jobs) is keyed by the IMDb id, so Kitsu ids are mapped through the Kitsu addon's public meta endpoint, which
publishes `imdb_id` per title and `imdb_id`/`imdbSeason`/`imdbEpisode` per episode. Results are cached on disk.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from urllib.parse import parse_qs

import httpx

from .. import __version__
from ..config import Settings
from ..jobs import VIDEO_ID_RE

IMDB_RE = re.compile(r"^tt\d{1,10}(:\d{1,4}:\d{1,4})?$")
KITSU_RE = re.compile(r"^kitsu:(\d{1,9})(?::(\d{1,5}))?$")
TTL_S, MISS_TTL_S = 7 * 86400, 3600          # airing shows gain episodes; failed lookups are retried hourly
USER_AGENT = f"Addolinsky/{__version__} (Stremio subtitle addon)"


def _kitsu_meta(base_url: str, kitsu_id: str, cache_dir: Path, http: httpx.Client | None,
                timeout: float) -> dict | None:
    cache_path = cache_dir / f"kitsu_{kitsu_id}.json"
    try:
        cached = json.loads(cache_path.read_text(encoding="utf-8"))
        if time.time() - cached["at"] < (TTL_S if cached["meta"] else MISS_TTL_S):
            return cached["meta"]
    except (OSError, ValueError, KeyError):
        pass
    meta = None
    owns_client = http is None
    http = http or httpx.Client(timeout=timeout, headers={"User-Agent": USER_AGENT}, follow_redirects=True)
    try:
        for meta_type in ("series", "movie", "anime"):
            response = http.get(f"{base_url}/meta/{meta_type}/kitsu:{kitsu_id}.json")
            remote_meta = response.json().get("meta") if response.status_code == 200 else None
            if remote_meta:
                meta = {"type": remote_meta.get("type"), "imdb_id": remote_meta.get("imdb_id"),
                        "videos": {video["id"]: [video.get("imdb_id"), video.get("imdbSeason"),
                                                 video.get("imdbEpisode")]
                                   for video in remote_meta.get("videos") or []
                                   if isinstance(video, dict) and video.get("id")}}
                break
    except (httpx.HTTPError, ValueError, AttributeError):
        return None                               # transient: not cached
    finally:
        if owns_client:
            http.close()
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps({"at": time.time(), "meta": meta}), encoding="utf-8")
    return meta


def canonical(type_: str, video_id: str, *, kitsu_url: str, cache: Path, http: httpx.Client | None = None,
              timeout: float = 4.0) -> tuple[str, str] | None:
    """(type, imdb video id) for a supported Stremio id, or None when it cannot be resolved reliably."""
    if IMDB_RE.fullmatch(video_id):              # keep Stremio's type (a type/id mismatch is rejected downstream)
        return (type_ if type_ in ("movie", "series") else ("series" if ":" in video_id else "movie")), video_id
    kitsu_match = KITSU_RE.fullmatch(video_id)
    if not kitsu_match or not kitsu_url:
        return None
    meta = _kitsu_meta(kitsu_url.rstrip("/"), kitsu_match.group(1), cache, http, timeout)
    if not meta:
        return None
    if kitsu_match.group(2) is None:                        # a whole title: only a film maps to one subtitle file
        imdb_id = meta.get("imdb_id")
        return ("movie", imdb_id) if imdb_id and IMDB_RE.fullmatch(imdb_id) and meta.get("type") == "movie" else None
    imdb_id, season, episode = (meta["videos"].get(video_id) or [None, None, None])
    if imdb_id and season is None and episode is None and meta.get("type") == "movie" and IMDB_RE.fullmatch(imdb_id):
        return "movie", imdb_id                        # a film listed as a single "episode"
    if not (imdb_id and isinstance(season, int) and isinstance(episode, int)):
        return None
    episode_video_id = f"{imdb_id}:{season}:{episode}"
    return ("series", episode_video_id) if IMDB_RE.fullmatch(episode_video_id) else None


def resolve_video_identity(settings: Settings, content_type: str, video_id: str) -> tuple[str, str] | None:
    """IMDb identity for a Stremio id (Cinemeta tt… as is; Anime Kitsu ids through the Kitsu meta mapping)."""
    if content_type not in ("movie", "series", "anime") or len(video_id) > 40:
        return None
    return canonical(content_type, video_id, kitsu_url=settings.kitsu_addon_url, cache=settings.data_dir / "cache")


def is_valid_video_request(content_type: str, video_id: str, extra: str = "") -> bool:
    """A film or episode id of the right shape for its type, with bounded Stremio extra arguments."""
    return (content_type in ("movie", "series") and bool(VIDEO_ID_RE.fullmatch(video_id)) and len(extra) <= 2000
            and (content_type == "series") == (":" in video_id))


def parse_release_hints(extra: str) -> tuple[str, str]:
    """The viewer's release hints from Stremio extra arguments: (lower-cased videoHash as sent, filename)."""
    arguments = parse_qs(extra, max_num_fields=10) if extra else {}
    video_hash = (arguments.get("videoHash", [""])[0] or "").lower()
    filename = (arguments.get("filename", [""])[0] or "")[:255]
    return video_hash, filename
