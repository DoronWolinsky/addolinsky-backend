"""Access and creation rules at the service layer: who may receive which finished translation (own creations, the
open catalogue, access-all plans and grants) and how creation credits are reserved and settled."""

import time

import pytest

from addolinsky.security.auth import hash_install_token
from addolinsky.services import entitlements as access


def record_creator(creator: str, video_id: str):
    def on_create(connection, job_id):
        connection.execute("INSERT INTO creations(job_id,user_id,video_id,source,created_at) VALUES(?,?,?,'live',?)",
                           (job_id, creator, video_id, time.time()))
    return on_create


def finished_translation(store, job_id: str, creator: str | None, video_id: str = "tt0000001:1:1") -> dict:
    output_id = (job_id * 32)[:32]
    store.create_job({"job_id": job_id, "video_id": video_id, "release_key": "", "provider": "cloud",
                      "request": job_id, "user_id": creator},
                     on_create=record_creator(creator, video_id) if creator else None)
    store.add_output({"output_id": output_id, "job_id": job_id, "video_id": video_id, "release_key": "",
                      "cache_key": job_id, "filename": f"{output_id}.srt", "sha256": "0" * 64, "cue_count": 1})
    store.update_job(job_id, status="READY", output_id=output_id)
    return store.get_output(output_id)


@pytest.fixture
def people(store):
    store.add_user("owner", hash_install_token("O" * 24), "owner", "local")
    store.add_user("free", hash_install_token("F" * 24), "user", "test")
    store.add_user("maker", hash_install_token("M" * 24), "user", "test")
    store.add_user("friend", hash_install_token("B" * 24), "friend", "invite")      # beta invitation grant
    return store


def can_receive(store, user_id, output):
    return access.can_access_output(store.conn, access.entitlements_for(store, user_id), output)


def test_free_users_receive_own_and_open_catalogue_translations_only(people):
    store = people
    catalogue_entry = finished_translation(store, "a1", creator=None)
    store.conn.execute("INSERT INTO open_catalogue_outputs(output_id,video_id,designated_at,reason) "
                       "VALUES(?,?,?,'test')", (catalogue_entry["output_id"], catalogue_entry["video_id"], time.time()))
    own = finished_translation(store, "b2", creator="free")
    private = finished_translation(store, "c3", creator="maker")
    assert can_receive(store, "free", catalogue_entry) and can_receive(store, "free", own)
    assert not can_receive(store, "free", private)
    assert can_receive(store, "maker", private) and can_receive(store, "maker", catalogue_entry)
    assert all(can_receive(store, user, output) for user in ("owner", "friend") for output in (catalogue_entry, private))
    assert not access.can_access_output(store.conn, None, catalogue_entry)                 # unidentified: nothing
    store.set_user_disabled("free", True)
    assert access.entitlements_for(store, "free") is None


def test_free_users_cannot_create_and_grants_are_bounded(people):
    store = people
    assert not access.entitlements_for(store, "free").can_create
    with pytest.raises(ValueError):
        access.create_grant(store, user_id="free", kind="test_premium", actor="op", reason="qa", days=7)
    grant_id = access.create_grant(store, user_id="free", kind="test_premium", actor="op", reason="qa", days=7,
                                   credits_per_period=1)
    assert access.entitlements_for(store, "free").credits_limit == 1
    assert access.revoke_grant(store, grant_id, actor="op", reason="done")
    assert not access.entitlements_for(store, "free").can_create
    actions = [row[0] for row in store.conn.execute("SELECT action FROM audit_log WHERE user_id='free'")]
    assert actions == ["grant_created", "grant_revoked"]


def test_credits_are_reserved_with_the_job_and_released_when_it_fails(people):
    store = people
    access.create_grant(store, user_id="free", kind="test_premium", actor="op", reason="qa", days=7,
                        credits_per_period=1)
    entitlements = access.entitlements_for(store, "free")
    store.create_job({"job_id": "j1", "video_id": "tt0000002", "release_key": "", "provider": "cloud",
                      "request": "r", "user_id": "free"},
                     on_create=lambda connection, job_id: access.reserve_credit(connection, entitlements, job_id))
    with pytest.raises(access.CreditsExhausted):                                    # one credit, already reserved
        with store.tx() as connection:
            access.reserve_credit(connection, entitlements, "j2")
    store.update_job("j1", status="FAILED")
    assert access.credit_summary(store, entitlements)["remaining"] == 1             # a failure costs nothing
    assert access.job_creator(store.conn, "j1") == "free"                           # ownership is kept
