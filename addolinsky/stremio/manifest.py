"""Serve the Stremio addon manifests: the shared addon and the per-user manifest of personal install links."""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from .. import __version__
from .. import public_text as PT
from ..api.http import CORS_HEADERS
from ..config import Settings
from ..dependencies import Context
from ..security.auth import require_authenticated_user

MANIFEST = {
    "id": "org.addolinsky.hebrew",
    "version": __version__,
    "name": PT.NAME,
    "description": PT.DESCRIPTION,
    "resources": ["subtitles"],
    "types": ["movie", "series", "anime"],
    "idPrefixes": ["tt", "kitsu"],     # kitsu: Anime Kitsu catalog ids, mapped to IMDb ids (stremio/ids.py)
    "catalogs": [],
    "behaviorHints": {"configurable": False, "configurationRequired": False},
}
PERSONAL_MANIFEST_ID = "org.addolinsky.hebrew.auto"
MANIFEST_CACHE_HEADERS = {**CORS_HEADERS, "Cache-Control": "max-age=300"}

router = APIRouter()


def build_manifest(settings: Settings, personal: bool) -> dict:
    manifest = dict(MANIFEST)
    if settings.contact_email:
        manifest["contactEmail"] = settings.contact_email
    if personal:
        manifest["id"] = PERSONAL_MANIFEST_ID
    elif settings.public_signup:
        manifest["behaviorHints"] = {"configurable": True, "configurationRequired": True}
    return manifest


@router.get("/manifest.json")
async def get_public_manifest(context: Context):
    return JSONResponse(build_manifest(context.settings, personal=False), headers=MANIFEST_CACHE_HEADERS)


# Personal install links: http(s)://<host>/<install token>/manifest.json. A token identifies one user (fair
# queueing, daily limits) and is the only thing that can authorize new paid work. It never appears in subtitle text,
# status pages or listing URLs: the request track carries a per-user, per-video signed token instead.
@router.get("/{install_token}/manifest.json")
async def get_personal_manifest(install_token: str, context: Context):
    require_authenticated_user(context.store, install_token)
    return JSONResponse(build_manifest(context.settings, personal=True), headers=MANIFEST_CACHE_HEADERS)
