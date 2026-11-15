"""List Hebrew subtitle tracks for Stremio: finished outputs, plus the info and confirm request tracks that personal
install links show while no translation exists yet."""

from __future__ import annotations

from urllib.parse import quote

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .. import public_text as PT
from ..api.http import CORS_HEADERS, public_base_url
from ..dependencies import AppContext, Context
from ..jobs import VIDEO_HASH_RE, release_key
from ..security.auth import require_authenticated_user
from ..security.capabilities import create_signed_video_token
from ..services.entitlements import accessible_outputs, entitlements_for
from ..subtitles.outputs import output_file_is_intact, servable_outputs
from .ids import is_valid_video_request, parse_release_hints, resolve_video_identity

router = APIRouter()


def list_ready_tracks(context: AppContext, request: Request, content_type: str, video_id: str, extra: str,
                      user_id: str) -> list | None:
    """Tracks of the READY outputs for this video that this user may receive (own creations, or all with Premium or
    a grant), release-matched ones first (None if the request is invalid). Each URL carries the user's signed video
    token; delivery re-checks the user's access on every fetch."""
    if not is_valid_video_request(content_type, video_id, extra):
        return None
    video_hash, filename = parse_release_hints(extra)
    video_hash = video_hash if VIDEO_HASH_RE.fullmatch(video_hash) else ""
    wanted_releases = {release_key(video_hash=video_hash)} if video_hash else set()
    if filename:
        wanted_releases.add(release_key(filename=filename))
    base_url = public_base_url(context, request)
    release_matched, unbound = [], []
    query = [f"t={content_type}", f"x={quote(extra, safe='')}"] if (video_hash or filename) else [f"t={content_type}"]
    query.append(f"u={create_signed_video_token(context.server_secret, user_id, content_type, video_id)}")
    query_string = "?" + "&".join(query)
    entitlements = entitlements_for(context.store, user_id)
    for output in accessible_outputs(context.store, entitlements, servable_outputs(context.store, video_id)):
        if output["release_key"] and output["release_key"] not in wanted_releases:
            continue  # bound to another release: timing may not match this video
        if not output_file_is_intact(context.store, context.settings, context.verified_outputs, output):
            continue
        track = {"id": f"addolinsky-{output['output_id'][:12]}",
                 "url": f"{base_url}/subs/{output['output_id']}.srt{query_string}", "lang": "heb"}
        (release_matched if output["release_key"] else unbound).append(track)
    return release_matched + unbound


def _public_subtitles_response() -> JSONResponse:
    """The shared (unkeyed) addon lists nothing: every translation is delivered to an identified user whose access
    is checked (personal install links)."""
    return JSONResponse({"subtitles": []}, headers={**CORS_HEADERS, "Cache-Control": "max-age=30"})


def _personal_subtitles_response(context: AppContext, request: Request, install_token: str, content_type: str,
                                 video_id: str, extra: str = "") -> JSONResponse:
    user = require_authenticated_user(context.store, install_token)
    headers = {**CORS_HEADERS, "Cache-Control": "no-store"}
    identity = resolve_video_identity(context.settings, content_type, video_id)
    if identity is None:
        return JSONResponse({"subtitles": []}, headers=headers)
    content_type, video_id = identity             # from here on the IMDb identity (cache, sources, jobs)
    tracks = list_ready_tracks(context, request, content_type, video_id, extra, user["user_id"])
    if tracks is None:
        return JSONResponse({"subtitles": []}, headers=headers)
    if tracks:
        return JSONResponse({"subtitles": tracks}, headers=headers)
    if not context.settings.translation_engine_ready():
        return JSONResponse({"subtitles": []}, headers=headers)
    return JSONResponse({"subtitles": _request_tracks(context, request, user["user_id"], content_type, video_id,
                                                      extra)}, headers=headers)


def _request_tracks(context: AppContext, request: Request, user_id: str, content_type: str, video_id: str,
                    extra: str) -> list[dict]:
    """The two request tracks (D-123). Listing never starts work.

    Both are "heb" (Stremio groups by recognised language code) with labels. The info track never starts work and is
    listed first, so preferred-language auto-selection and a click on the "Hebrew" row (both take the first track of
    the language) land on it. The confirm track gets a one-time confirmation token in its id and URL (see
    security/nonces.py): Stremio restores a saved track by id, so a remembered confirm track can never be restored,
    and each token can start or retry a job once."""
    signed_token = create_signed_video_token(context.server_secret, user_id, content_type, video_id)
    url = (f"{public_base_url(context, request)}/r/{signed_token}/{content_type}/{video_id}.srt"
           f"?x={quote(extra, safe='')}")
    confirmation_token = context.confirmation_tokens.get_or_create_confirmation_token(user_id, video_id)
    return [
        {"id": f"addolinsky-info-{video_id}", "lang": "heb", "label": PT.INFO_LABEL, "url": url},
        {"id": f"addolinsky-confirm-{video_id}-{confirmation_token}", "lang": "heb", "label": PT.CONFIRM_LABEL,
         "url": f"{url}&go={confirmation_token}"},
    ]


# Listing handlers are sync (run in the threadpool): resolving an Anime Kitsu id may make blocking HTTP calls.
@router.get("/subtitles/{content_type}/{video_id}.json")
def list_public_subtitles(content_type: str, video_id: str):
    return _public_subtitles_response()


@router.get("/subtitles/{content_type}/{video_id}/{extra}.json")
def list_public_subtitles_for_release(content_type: str, video_id: str, extra: str):
    return _public_subtitles_response()


@router.get("/{install_token}/subtitles/{content_type}/{video_id}.json")
def list_personal_subtitles(request: Request, install_token: str, content_type: str, video_id: str,
                            context: Context):
    return _personal_subtitles_response(context, request, install_token, content_type, video_id)


@router.get("/{install_token}/subtitles/{content_type}/{video_id}/{extra}.json")
def list_personal_subtitles_for_release(request: Request, install_token: str, content_type: str,
                                        video_id: str, extra: str, context: Context):
    return _personal_subtitles_response(context, request, install_token, content_type, video_id, extra)
