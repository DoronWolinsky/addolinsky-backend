"""Write finished subtitle files atomically, verify them against their recorded SHA-256 and list the outputs that
may be served to viewers."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from ..config import Settings
from ..db import Store

# Only outputs of production translation jobs are served; anything else an existing database may hold (evaluation
# runs, imports) never reaches viewers.
SERVED_JOB_PROVIDERS = ("cloud",)


def write_output_file(settings: Settings, output_id: str, srt: str) -> Path:
    """Write the SRT as UTF-8 through a synced temporary file and an atomic replace."""
    settings.outputs_dir.mkdir(parents=True, exist_ok=True)
    output_path = settings.outputs_dir / f"{output_id}.srt"
    temporary_path = output_path.with_suffix(".tmp")
    with open(temporary_path, "wb") as output_file:
        output_file.write(srt.encode("utf-8"))
        output_file.flush()
        os.fsync(output_file.fileno())
    os.replace(temporary_path, output_path)
    return output_path


def read_verified_output(store: Store, settings: Settings, output: dict) -> bytes | None:
    """Output bytes if the file still matches its recorded SHA-256; otherwise the output is invalidated."""
    try:
        subtitle_bytes = (settings.outputs_dir / output["filename"]).read_bytes()
    except OSError:
        subtitle_bytes = None
    if subtitle_bytes is None or hashlib.sha256(subtitle_bytes).hexdigest() != output["sha256"]:
        store.invalidate_output(output["output_id"])
        return None
    return subtitle_bytes


def servable_outputs(store: Store, video_id: str) -> list[dict]:
    """READY outputs of production jobs for a video (file integrity is checked separately)."""
    return store.ready_outputs(video_id, SERVED_JOB_PROVIDERS)


def output_file_is_intact(store: Store, settings: Settings, verified_outputs: dict[str, tuple[int, int]],
                          output: dict) -> bool:
    """Hash-verify an output file once per (mtime, size) instead of on every listing."""
    try:
        file_status = (settings.outputs_dir / output["filename"]).stat()
    except OSError:
        store.invalidate_output(output["output_id"])
        return False
    file_signature = (file_status.st_mtime_ns, file_status.st_size)
    if verified_outputs.get(output["output_id"]) == file_signature:
        return True
    if read_verified_output(store, settings, output) is None:
        return False
    verified_outputs[output["output_id"]] = file_signature
    return True
