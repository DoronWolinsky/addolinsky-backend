"""Job lifecycle: restart requeue, single-flight creation under concurrency, cancel and retry rules, SQLite
transactions and integrity."""

import sqlite3
import threading

import pytest

from addolinsky.db import Store
from addolinsky.jobs import InputError, cancel_job, create_cloud_job, release_key, retry_job


def test_service_restart_requeues_running_jobs(settings):
    settings.ensure_dirs()
    st = Store(settings.db_path)
    jid, _ = create_cloud_job(st, video_id="tt0000500", type_="movie")
    st.claim_next_job()
    assert st.get_job(jid)["status"] == "RUNNING"
    st.close()
    st2 = Store(settings.db_path)  # "restart"
    assert st2.requeue_interrupted() == 1 and st2.get_job(jid)["status"] == "QUEUED"
    st2.close()


def test_cancel_and_retry_rules(store):
    jid, _ = create_cloud_job(store, video_id="tt0000500", type_="movie")
    with pytest.raises(InputError):
        retry_job(store, jid)                                   # only FAILED or CANCELLED jobs can be retried
    assert cancel_job(store, jid) == "CANCELLED"
    retry_job(store, jid)
    assert store.get_job(jid)["status"] == "QUEUED"
    store.claim_next_job()
    assert cancel_job(store, jid) == "RUNNING" and store.get_job(jid)["cancel_requested"] == 1
    with pytest.raises(InputError):
        cancel_job(store, "unknown")


def test_concurrent_requests_create_one_job(settings, store):
    results, errors = [], []

    def worker():
        try:
            st = Store(settings.db_path)
            results.append(create_cloud_job(st, video_id="tt0000500", type_="movie"))
            st.ready_outputs("tt0000500")
            st.close()
        except Exception as e:  # pragma: no cover
            errors.append(e)
    threads = [threading.Thread(target=worker) for _ in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len({jid for jid, _ in results}) == 1 and sum(created for _, created in results) == 1


def test_transaction_rollback_on_failure(store):
    with pytest.raises(RuntimeError):
        with store.tx() as transaction:
            transaction.execute("INSERT INTO meta(key,value) VALUES('a','1')")
            raise RuntimeError("boom")
    assert store.conn.execute("SELECT COUNT(*) FROM meta WHERE key='a'").fetchone()[0] == 0
    # a failing track insert must not leave partial cues behind
    from addolinsky.subtitles.parsing import Cue
    row = {"track_id": "t1", "video_id": "tt1", "lang": "en", "lang_raw": "en", "provider": "local", "provider_ref": "",
           "release_name": "", "video_hash": "", "format": "srt", "encoding": "utf-8", "content_hash": "h", "raw_sha256": "r",
           "rights": "", "warnings": "[]", "cue_count": 2}
    dup = [Cue("x", 0, 0, 10, "a"), Cue("y", 0, 20, 30, "b")]  # duplicate idx -> PK violation
    with pytest.raises(sqlite3.IntegrityError):
        store.add_track(row, dup)
    assert store.get_track("t1") is None and store.get_cues("t1") == []


def test_sqlite_integrity_check_and_wal(store):
    assert store.conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert store.conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_job_and_release_identity_validation(store):
    with pytest.raises(InputError):
        create_cloud_job(store, video_id="../../etc/passwd", type_="movie")
    with pytest.raises(InputError):
        create_cloud_job(store, video_id="tt0000500", type_="anime")
    with pytest.raises(InputError):
        release_key(video_hash="not-hex")
    assert release_key(video_hash="ABCDEF0123456789") == "hash:abcdef0123456789"
    assert release_key(filename="Show.S01E01.1080p.WEB.mkv") == "file:show s01e01 1080p web"
