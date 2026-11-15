"""HTTP building blocks shared by the Stremio-facing routes: CORS headers and preflights, SRT responses, base URLs."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import Response

from ..dependencies import AppContext

CORS_HEADERS = {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "*",
                "Access-Control-Allow-Methods": "GET, OPTIONS"}

router = APIRouter()


@router.options("/manifest.json")
@router.options("/subtitles/{rest:path}")
@router.options("/subs/{rest:path}")
@router.options("/{install_token}/manifest.json")
@router.options("/{install_token}/subtitles/{rest:path}")
@router.options("/r/{rest:path}")
async def cors_preflight(install_token: str = "", rest: str = ""):
    return Response(status_code=204, headers=CORS_HEADERS)


def srt_response(data: bytes, filename: str = "addolinsky.he.srt") -> Response:
    return Response(data, media_type="application/x-subrip; charset=utf-8",
                    headers={**CORS_HEADERS, "Cache-Control": "private, no-store",
                             "Content-Disposition": f'inline; filename="{filename}"'})


def public_base_url(context: AppContext, request: Request) -> str:
    """Base URL for links handed to clients: the configured public URL behind the proxy, else the request's own."""
    if context.public_mode:
        return context.settings.public_base_url.rstrip("/")
    return str(request.base_url).rstrip("/")
