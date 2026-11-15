"""Security primitives: secret files and token formats stay compatible; admin access, admin sessions and
confirmation tokens follow their rules under concurrency."""

import hashlib
import hmac

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from addolinsky.security.auth import (
    ADMIN_SESSION_COOKIE,
    LEGACY_ADMIN_COOKIE,
    find_user_by_install_token,
    hash_install_token,
    require_admin_access,
    require_authenticated_user,
)
from addolinsky.security.capabilities import create_signed_video_token, verify_signed_video_token
from addolinsky.security.secrets import get_admin_token, get_or_create_secret, get_owner_install_token
from addolinsky.security.sessions import AdminSessionRegistry


def test_existing_secret_files_are_read_not_rewritten(settings):
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    for name in ("addon_key", "admin_token", "server_secret"):
        (settings.data_dir / name).write_text(f"existing-{name}\n", encoding="utf-8")
    assert get_owner_install_token(settings) == "existing-addon_key"
    assert get_admin_token(settings) == "existing-admin_token"
    assert get_or_create_secret(settings, "server_secret", 32) == "existing-server_secret"
    for name in ("addon_key", "admin_token", "server_secret"):
        assert (settings.data_dir / name).read_text(encoding="utf-8") == f"existing-{name}\n"


def test_missing_secret_files_are_created_once_with_the_old_sizes(settings):
    owner, admin = get_owner_install_token(settings), get_admin_token(settings)
    assert len(owner) == 24 and len(admin) == 43          # token_urlsafe(18) and token_urlsafe(32), as before
    assert (settings.data_dir / "addon_key").read_text(encoding="utf-8") == owner
    assert (settings.data_dir / "admin_token").read_text(encoding="utf-8") == admin
    assert get_owner_install_token(settings) == owner and get_admin_token(settings) == admin


def test_install_token_hash_is_the_stored_sha256_hex():
    assert hash_install_token("abc") == hashlib.sha256(b"abc").hexdigest()


def test_user_lookup_keeps_length_bounds_and_disabled_check(store):
    token = "t" * 16
    store.add_user("f1", hash_install_token(token), "friend", "invite")
    assert find_user_by_install_token(store, token)["user_id"] == "f1"
    assert find_user_by_install_token(store, "t" * 15) is None
    store.add_user("f2", hash_install_token("u" * 65), "friend", "invite")
    assert find_user_by_install_token(store, "u" * 65) is None
    store.set_user_disabled("f1", True)
    with pytest.raises(HTTPException) as e:
        require_authenticated_user(store, token)
    assert e.value.status_code == 404


def test_signed_video_token_format_is_unchanged():
    secret = b"s" * 32
    old = "f1." + hmac.new(secret, b"f1|series|tt1:1:1", hashlib.sha256).hexdigest()[:24]   # the server.py formula
    assert create_signed_video_token(secret, "f1", "series", "tt1:1:1") == old
    assert verify_signed_video_token(secret, old, "series", "tt1:1:1") == "f1"
    assert verify_signed_video_token(secret, old, "series", "tt1:1:2") is None
    assert verify_signed_video_token(secret, old, "movie", "tt1:1:1") is None
    assert verify_signed_video_token(b"x" * 32, old, "series", "tt1:1:1") is None
    assert verify_signed_video_token(secret, "f2" + old[2:], "series", "tt1:1:1") is None


def test_admin_access_rules():
    sessions = AdminSessionRegistry()
    session = sessions.create()

    def req(method, headers):
        return Request({"type": "http", "method": method, "path": "/api/x", "query_string": b"",
                        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()]})

    def status(method, headers):
        try:
            require_admin_access(req(method, headers), "ADMIN", sessions)
            return 200
        except HTTPException as e:
            return e.status_code
    cookie = {"cookie": f"{ADMIN_SESSION_COOKIE}={session}"}
    assert status("POST", {"x-admin-token": "ADMIN"}) == 200
    assert status("GET", cookie) == 200
    assert status("POST", cookie) == 403                                         # anti-CSRF header required
    assert status("POST", {**cookie, "x-requested-with": "addolinsky"}) == 200
    assert status("GET", {"x-admin-token": "WRONG"}) == 401
    assert status("GET", {"x-admin-token": "WRONG", **cookie}) == 401              # a header decides alone
    assert status("GET", {"cookie": f"{LEGACY_ADMIN_COOKIE}=ADMIN"}) == 401        # master token cookie refused
    assert status("GET", {"cookie": f"{ADMIN_SESSION_COOKIE}=ADMIN"}) == 401       # master token is not a session
    assert status("GET", {}) == 401
    sessions.revoke(session)
    assert status("GET", cookie) == 401


def test_admin_sessions_expire_and_stay_bounded(monkeypatch):
    from addolinsky.security import sessions as S
    now = [1000.0]
    monkeypatch.setattr(S.time, "time", lambda: now[0])
    registry = S.AdminSessionRegistry()
    first = registry.create()
    assert registry.is_valid(first) and not registry.is_valid(first + "x") and not registry.is_valid("")
    now[0] += S.ADMIN_SESSION_TTL_S + 1
    assert not registry.is_valid(first)
    created = [registry.create() for _ in range(S.MAX_ADMIN_SESSIONS + 5)]
    assert len(registry._expiry_by_hash) == S.MAX_ADMIN_SESSIONS and registry.is_valid(created[-1])
    assert all(hashlib.sha256(s.encode()).hexdigest() not in created for s in created)   # only hashes stored


def test_confirmation_tokens_keep_reuse_window_ttl_and_one_time_use(monkeypatch):
    from addolinsky.security import nonces
    now = [1000.0]
    monkeypatch.setattr(nonces.time, "time", lambda: now[0])
    reg = nonces.ConfirmationTokenRegistry()
    first = reg.get_or_create_confirmation_token("u1", "tt1")
    assert reg.get_or_create_confirmation_token("u1", "tt1") == first            # second listing of one playback
    assert reg.get_or_create_confirmation_token("u2", "tt1") != first
    now[0] += nonces.NONCE_REUSE_S + 1
    second = reg.get_or_create_confirmation_token("u1", "tt1")
    assert second != first                                                        # reuse window over: new token
    assert reg.validate_and_consume_confirmation_token(first, "u1", "tt1")        # still valid inside the TTL
    assert not reg.validate_and_consume_confirmation_token(first, "u1", "tt1")    # one time only
    assert not reg.validate_and_consume_confirmation_token("", "u1", "tt1")
    now[0] += nonces.NONCE_TTL_S + 1
    assert not reg.validate_and_consume_confirmation_token(second, "u1", "tt1")   # expired


def test_confirmation_token_survives_mismatched_attempts_and_is_consumed_by_its_owner():
    from addolinsky.security.nonces import ConfirmationTokenRegistry
    reg = ConfirmationTokenRegistry()
    token = reg.get_or_create_confirmation_token("u1", "tt1")
    assert not reg.validate_and_consume_confirmation_token(token, "u2", "tt1")    # another user
    assert not reg.validate_and_consume_confirmation_token(token, "u1", "tt2")    # another video
    assert not reg.validate_and_consume_confirmation_token(token + "x", "u1", "tt1")
    assert reg.get_or_create_confirmation_token("u1", "tt1") == token             # still the listed confirm entry
    assert reg.validate_and_consume_confirmation_token(token, "u1", "tt1")
    assert not reg.validate_and_consume_confirmation_token(token, "u1", "tt1")    # replay refused
    assert reg.get_or_create_confirmation_token("u1", "tt1") != token             # next listing: a fresh token


def test_expired_confirmation_tokens_are_refused_and_pruned(monkeypatch):
    from addolinsky.security import nonces
    now = [1000.0]
    monkeypatch.setattr(nonces.time, "time", lambda: now[0])
    monkeypatch.setattr(nonces, "MAX_TOKENS_BEFORE_PRUNING", 1)
    reg = nonces.ConfirmationTokenRegistry()
    old = [reg.get_or_create_confirmation_token(f"u{i}", "tt1") for i in range(3)]
    now[0] += nonces.NONCE_TTL_S + 1
    assert not reg.validate_and_consume_confirmation_token(old[0], "u0", "tt1")   # expired, removed
    reg.get_or_create_confirmation_token("u9", "tt1")                             # pruning pass
    assert set(reg._records) == {reg._unused_token[("u9", "tt1")]}
    assert list(reg._unused_token) == [("u9", "tt1")]                             # no stale per-user entries


def test_confirmation_token_concurrent_consume_succeeds_once():
    import threading

    from addolinsky.security.nonces import ConfirmationTokenRegistry
    reg = ConfirmationTokenRegistry()
    token = reg.get_or_create_confirmation_token("u1", "tt1")
    results, start = [], threading.Barrier(16)

    def attempt():
        start.wait()
        results.append(reg.validate_and_consume_confirmation_token(token, "u1", "tt1"))
    threads = [threading.Thread(target=attempt) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1


def test_rate_limiter_keeps_window_limit_and_per_client_keys(monkeypatch):
    from addolinsky.security import middleware
    now = [1000.0]
    monkeypatch.setattr(middleware.time, "time", lambda: now[0])
    limiter = middleware.RequestRateLimiter()
    assert [limiter.check_and_record_request("a", 2) for _ in range(3)] == [True, True, False]
    assert limiter.check_and_record_request("b", 2)
    now[0] += 60.0                                                     # default window is 60 s, edge inclusive
    assert limiter.check_and_record_request("a", 2)


def test_client_ip_uses_forwarded_for_only_in_public_mode():
    from addolinsky.security.middleware import get_client_ip_address
    scope = {"type": "http", "method": "GET", "path": "/", "query_string": b"", "client": ("127.0.0.1", 5),
             "headers": [(b"x-forwarded-for", b"203.0.113.9, 10.0.0.1")]}
    assert get_client_ip_address(Request(scope), True) == "203.0.113.9"
    assert get_client_ip_address(Request(scope), False) == "127.0.0.1"
