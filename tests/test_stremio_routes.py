"""Stremio protocol routers mounted on their own: manifests, track listings, request tracks and CORS preflights."""

import hashlib
import secrets

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from addolinsky.api import http
from addolinsky.dependencies import build_app_context
from addolinsky.jobs import create_cloud_job, release_key
from addolinsky.security.auth import hash_install_token
from addolinsky.stremio import manifest, tracks
from addolinsky.subtitles.outputs import write_output_file

BASE = "http://127.0.0.1:7000"
FRIEND_TOKEN = "F" * 24


@pytest.fixture
def stremio(settings, store):
    settings.public_signup = True
    app = FastAPI()
    app.state.context = build_app_context(settings, store)
    for router in (http.router, manifest.router, tracks.router):
        app.include_router(router)
    store.add_user("f1", hash_install_token(FRIEND_TOKEN), "friend", "invite")
    return TestClient(app, base_url=BASE), settings, store


def finished_output(store, settings, video_id, filename=""):
    job_id, _ = create_cloud_job(store, video_id=video_id, type_="series" if ":" in video_id else "movie")
    srt = "1\n00:00:01,000 --> 00:00:02,000\n‫שלום‬\n"
    output_id = secrets.token_hex(16)
    path = write_output_file(settings, output_id, srt)
    store.add_output({"output_id": output_id, "job_id": job_id, "video_id": video_id,
                      "release_key": release_key(filename=filename), "cache_key": output_id, "filename": path.name,
                      "sha256": hashlib.sha256(srt.encode()).hexdigest(), "cue_count": 1})
    store.update_job(job_id, status="READY", stage="done", output_id=output_id)
    return output_id


def test_manifests_public_and_personal(stremio):
    c, *_ = stremio
    public = c.get("/manifest.json")
    assert public.status_code == 200 and public.json()["id"] == "org.addolinsky.hebrew"
    assert public.headers["access-control-allow-origin"] == "*"
    assert c.get(f"/{FRIEND_TOKEN}/manifest.json").json()["id"] == "org.addolinsky.hebrew.auto"
    assert c.get(f"/{'X' * 24}/manifest.json").status_code == 404                # unknown install token


def test_ready_output_listed_only_for_its_release(stremio):
    c, settings, store = stremio
    any_release = finished_output(store, settings, "tt0000042")
    bound = finished_output(store, settings, "tt0000042", filename="Film.1080p.WEB.mkv")
    assert c.get("/subtitles/movie/tt0000042.json").json() == {"subtitles": []}      # unkeyed: never lists files
    unmatched = c.get(f"/{FRIEND_TOKEN}/subtitles/movie/tt0000042.json").json()["subtitles"]   # beta grant: all
    assert [t["id"] for t in unmatched] == [f"addolinsky-{any_release[:12]}"] and unmatched[0]["lang"] == "heb"
    matched = c.get(f"/{FRIEND_TOKEN}/subtitles/movie/tt0000042/filename=Film.1080p.WEB.mkv.json").json()["subtitles"]
    assert [t["id"] for t in matched] == [f"addolinsky-{bound[:12]}", f"addolinsky-{any_release[:12]}"]


def test_personal_listing_offers_info_then_confirm_request_tracks(stremio, monkeypatch):
    c, settings, _ = stremio
    monkeypatch.setattr(settings, "translation_engine_ready", lambda: True)
    first = c.get(f"/{FRIEND_TOKEN}/subtitles/series/tt0000077:1:2.json").json()["subtitles"]
    assert [t["id"].split("-")[1] for t in first] == ["info", "confirm"]
    assert FRIEND_TOKEN not in str(first) and "/r/f1." in first[0]["url"]           # signed token, not the install token
    again = c.get(f"/{FRIEND_TOKEN}/subtitles/series/tt0000077:1:2.json").json()["subtitles"]
    assert again[1]["id"] == first[1]["id"]                                       # same playback: same confirm entry


def test_invalid_ids_list_nothing_and_preflights_allow_any_origin(stremio):
    c, *_ = stremio
    for path in ("/subtitles/movie/nm0000001.json", "/subtitles/movie/tt0000001:1:1.json",
                 f"/{FRIEND_TOKEN}/subtitles/tv/tt0000001.json"):
        assert c.get(path).json() == {"subtitles": []}
    for path in ("/manifest.json", f"/{FRIEND_TOKEN}/subtitles/movie/tt1.json", "/subs/x.srt"):
        r = c.options(path)
        assert r.status_code == 204 and r.headers["access-control-allow-origin"] == "*"
