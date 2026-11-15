"""Translation job lifecycle: video and release identity, single-flight job creation, cancellation and retry."""

from __future__ import annotations

import json
import re
import secrets

from .db import Store

VIDEO_ID_RE = re.compile(r"^tt\d{1,10}(:\d{1,4}:\d{1,4})?$")
VIDEO_HASH_RE = re.compile(r"^[0-9a-f]{16}$")
ACTIVE_JOB_STATUSES = ("QUEUED", "RUNNING")


class InputError(ValueError):
    pass


class JobCancelled(Exception):
    """Raised inside a running job when its cancellation was requested."""


def validate_video_id(video_id: str) -> str:
    normalized_video_id = (video_id or "").strip()
    if not VIDEO_ID_RE.fullmatch(normalized_video_id):
        raise InputError("video_id must look like tt1234567 or tt1234567:1:2")
    return normalized_video_id


def normalize_release(name: str) -> str:
    """Release or file name reduced to lower-case words, without a subtitle or video file extension."""
    normalized_name = name.lower()
    normalized_name = re.sub(r"\.(srt|vtt|ass|ssa|mkv|mp4|avi|zip)$", "", normalized_name)
    return re.sub(r"[^a-z0-9]+", " ", normalized_name).strip()


def release_key(video_hash: str = "", filename: str = "") -> str:
    """Stored release identity: "hash:<video hash>" when known, else "file:<normalized name>", else ""."""
    normalized_video_hash = (video_hash or "").strip().lower()
    if normalized_video_hash:
        if not VIDEO_HASH_RE.fullmatch(normalized_video_hash):
            raise InputError("video_hash must be 16 hex characters")
        return f"hash:{normalized_video_hash}"
    normalized_filename = normalize_release((filename or "")[:255])
    return f"file:{normalized_filename}" if normalized_filename else ""


def create_cloud_job(store: Store, *, video_id: str, type_: str = "series", extra: str = "",
                     user_id: str | None = None, on_create=None) -> tuple[str, bool]:
    """A translation job for one video. Sources are fetched by the worker, not the caller.
    One active job per video (single-flight): a second request for the same video joins the existing job. The
    requester, status id and anything `on_create(connection, job_id)` writes are stored atomically with the job."""
    video_id = validate_video_id(video_id)
    if type_ not in ("movie", "series"):
        raise InputError("type must be movie or series")
    active_job = latest_cloud_job(store, video_id)
    if active_job and active_job["status"] in ACTIVE_JOB_STATUSES:
        return active_job["job_id"], False
    request_payload = json.dumps({"engine": "cloud", "type": type_, "extra": extra[:500]}, sort_keys=True)
    return store.create_job({"job_id": secrets.token_hex(8), "video_id": video_id, "release_key": "",
                             "provider": "cloud", "request": request_payload, "user_id": user_id,
                             "status_id": secrets.token_urlsafe(6)}, on_create)


def latest_cloud_job(store: Store, video_id: str) -> dict | None:
    job_row = store.conn.execute("SELECT * FROM jobs WHERE video_id=? AND provider='cloud' "
                                 "ORDER BY created_at DESC LIMIT 1", (video_id,)).fetchone()
    return dict(job_row) if job_row else None


def cancel_job(store: Store, job_id: str) -> str:
    """Cancel a queued job at once, or ask a running job to stop at its next stage. Returns the resulting status."""
    job = store.get_job(job_id)
    if not job:
        raise InputError("unknown job")
    if job["status"] == "QUEUED":
        store.update_job(job_id, status="CANCELLED", error="cancelled before start")
    elif job["status"] == "RUNNING":
        store.update_job(job_id, cancel_requested=1)
    return store.get_job(job_id)["status"]


def retry_job(store: Store, job_id: str) -> None:
    """Queue a failed or cancelled job again; it resumes from its checkpoints."""
    job = store.get_job(job_id)
    if not job or job["status"] not in ("FAILED", "CANCELLED"):
        raise InputError("only FAILED or CANCELLED jobs can be retried")
    store.update_job(job_id, status="QUEUED", cancel_requested=0, error=None)
