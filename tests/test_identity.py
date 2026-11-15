"""F1: Firebase ID-token verification and explicit identity linking, fully offline (a local RSA key and certificate
stand in for Google's securetoken certificates). No Firebase project, no network."""

import datetime
import json
import threading

import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from addolinsky.security import identity as I
from addolinsky.security.auth import hash_install_token

PROJECT = "addolinsky-test"
NOW = 1_800_000_000.0


def make_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "securetoken.test")])
    start = datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(start).not_valid_after(start + datetime.timedelta(days=36500))
            .sign(key, hashes.SHA256()))
    return key, cert.public_bytes(serialization.Encoding.PEM).decode()


KEY_A, CERT_A = make_key()
KEY_B, CERT_B = make_key()


class Certs:
    """Fake Google certificate endpoint: counts fetches; can fail or rotate keys."""

    def __init__(self, certs=None, max_age=3600):
        self.certs, self.max_age, self.calls, self.fail = certs or {"ka": CERT_A}, max_age, 0, False

    def __call__(self, url):
        assert url == I.CERTS_URL
        self.calls += 1
        if self.fail:
            raise OSError("network down")
        return 200, {"Cache-Control": f"public, max-age={self.max_age}"}, json.dumps(self.certs).encode()


class Clock:
    def __init__(self, t=NOW):
        self.t = t

    def __call__(self):
        return self.t


def token(key=KEY_A, kid="ka", alg="RS256", **over):
    claims = {"iss": f"https://securetoken.google.com/{PROJECT}", "aud": PROJECT, "sub": "uid-1",
              "iat": int(NOW) - 10, "exp": int(NOW) + 3000, "auth_time": int(NOW) - 60,
              "email": "dana@example.com", "email_verified": True, "firebase": {"sign_in_provider": "google.com"}}
    claims.update(over)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm=alg, headers={"kid": kid})


@pytest.fixture
def verifier():
    certs, clock = Certs(), Clock()
    v = I.FirebaseTokenVerifier(PROJECT, http_get=certs, clock=clock)
    v.certs, v.clock = certs, clock
    return v


def code(fn):
    with pytest.raises(I.IdentityError) as e:
        fn()
    return e.value.code


# ---------------------------------------------------------------- verification
def test_valid_token(verifier):
    ident = verifier.verify(token())
    assert (ident.uid, ident.email, ident.email_verified, ident.sign_in_provider) == \
        ("uid-1", "dana@example.com", True, "google.com")


@pytest.mark.parametrize("over,expected", [
    ({"aud": "other-project"}, "wrong_audience"),
    ({"iss": "https://securetoken.google.com/other-project"}, "wrong_issuer"),
    ({"iss": "https://accounts.google.com"}, "wrong_issuer"),
    ({"exp": int(NOW) - 100}, "expired"),
    ({"iat": int(NOW) + 600}, "issued_in_future"),
    ({"auth_time": int(NOW) + 600}, "issued_in_future"),
    ({"auth_time": None}, "invalid_token"),
    ({"sub": ""}, "invalid_subject"),
    ({"sub": "x" * 129}, "invalid_subject"),
])
def test_claim_checks(verifier, over, expected):
    assert code(lambda: verifier.verify(token(**over))) == expected


def test_signature_algorithm_and_key_checks(verifier):
    assert code(lambda: verifier.verify(token(key=KEY_B))) == "invalid_token"           # signed by another key
    hs = jwt.encode({"sub": "u"}, "secret-secret-secret-secret-32by", algorithm="HS256", headers={"kid": "ka"})
    assert code(lambda: verifier.verify(hs)) == "bad_algorithm_or_key_id"
    none = jwt.encode({"sub": "u"}, None, algorithm="none", headers={"kid": "ka"})
    assert code(lambda: verifier.verify(none)) == "bad_algorithm_or_key_id"
    assert code(lambda: verifier.verify(token(kid="nope"))) == "unknown_key"
    for bad in ("", "abc", "x" * (I.MAX_TOKEN_CHARS + 1), None):
        assert code(lambda b=bad: verifier.verify(b)) == "malformed_token"


def test_certificate_cache_honours_max_age_and_limits_refetches(verifier):
    verifier.verify(token())
    verifier.verify(token())
    assert verifier.certs.calls == 1                                   # cached
    code(lambda: verifier.verify(token(kid="nope")))
    assert verifier.certs.calls == 1                                   # unknown kid within a minute: no refetch
    verifier.clock.t += I.REFETCH_MIN_INTERVAL_S
    verifier.certs.certs = {"ka": CERT_A, "kb": CERT_B}                # Google rotated keys
    assert verifier.verify(token(key=KEY_B, kid="kb", iat=int(verifier.clock.t) - 5)).uid == "uid-1"
    assert verifier.certs.calls == 2
    verifier.clock.t += 3600                                           # max-age elapsed: refetch
    verifier.verify(token(iat=int(verifier.clock.t) - 5, exp=int(verifier.clock.t) + 100))
    assert verifier.certs.calls == 3


def test_expired_certificates_are_never_used_when_refetch_fails(verifier):
    verifier.verify(token())
    verifier.certs.fail = True
    verifier.clock.t += 3601
    t = token(iat=int(verifier.clock.t) - 5, exp=int(verifier.clock.t) + 100)
    assert code(lambda: verifier.verify(t)) == "unknown_key"           # fail closed


def test_feature_is_off_by_default(settings):
    assert I.build_verifier(settings) is None
    settings.firebase_auth = True
    assert I.build_verifier(settings) is None                          # project id still missing
    settings.firebase_project_id = PROJECT
    assert isinstance(I.build_verifier(settings, http_get=Certs()), I.FirebaseTokenVerifier)
    with pytest.raises(ValueError):
        I.FirebaseTokenVerifier("Bad_Project!")


# ---------------------------------------------------------------- linking and authentication
def friend(store, user_id="f1", token_value="T" * 24):
    store.add_user(user_id, hash_install_token(token_value), "friend", "invite")
    return token_value


def test_link_requires_own_install_token_and_keeps_it(store, verifier):
    t = friend(store)
    before = store.get_user("f1")["token_sha256"]
    user = I.link_firebase_identity(store, verifier, t, token())
    assert user["user_id"] == "f1" and store.identity_for_uid("uid-1")["user_id"] == "f1"
    assert store.get_user("f1")["token_sha256"] == before              # the Stremio token never changes
    assert I.link_firebase_identity(store, verifier, t, token())["user_id"] == "f1"   # idempotent
    assert I.authenticate_firebase(store, verifier, token())["user_id"] == "f1"
    assert store.get_user("f1")["token_sha256"] == before              # sign-in never rotates it either


def test_link_refusals(store, verifier):
    t = friend(store)
    assert code(lambda: I.link_firebase_identity(store, None, t, token())) == "disabled"
    assert code(lambda: I.link_firebase_identity(store, verifier, t, token(email_verified=False))) == \
        "email_not_verified"
    assert code(lambda: I.link_firebase_identity(store, verifier, t, token(auth_time=int(NOW) - 3600))) == \
        "reauthentication_required"
    assert code(lambda: I.link_firebase_identity(store, verifier, "W" * 24, token())) == "user_unavailable"
    assert code(lambda: I.link_firebase_identity(store, verifier, "short", token())) == "user_unavailable"
    store.set_user_disabled("f1", True)
    assert code(lambda: I.link_firebase_identity(store, verifier, t, token())) == "user_unavailable"
    assert store.identity_for_user("f1") is None


def test_conflicting_identities_are_never_moved_or_duplicated(store, verifier):
    t1, t2 = friend(store, "f1", "A" * 24), friend(store, "f2", "B" * 24)
    I.link_firebase_identity(store, verifier, t1, token(sub="uid-1"))
    assert code(lambda: I.link_firebase_identity(store, verifier, t2, token(sub="uid-1"))) == "uid_linked_elsewhere"
    assert code(lambda: I.link_firebase_identity(store, verifier, t1, token(sub="uid-2"))) == \
        "user_has_other_identity"
    assert store.identity_for_uid("uid-1")["user_id"] == "f1" and store.identity_for_uid("uid-2") is None


def test_no_account_is_found_or_created_by_email(store, verifier):
    t = friend(store)
    I.link_firebase_identity(store, verifier, t, token(sub="uid-1", email="dana@example.com"))
    users = len(store.list_users())
    same_email = token(sub="uid-other", email="dana@example.com")      # e.g. a second Firebase account, same e-mail
    assert code(lambda: I.authenticate_firebase(store, verifier, same_email)) == "not_linked"
    assert len(store.list_users()) == users and store.identity_for_uid("uid-other") is None


def test_authentication_refuses_unverified_and_disabled(store, verifier):
    t = friend(store)
    I.link_firebase_identity(store, verifier, t, token())
    assert code(lambda: I.authenticate_firebase(store, verifier, token(email_verified=False))) == \
        "email_not_verified"
    store.set_user_disabled("f1", True)
    assert code(lambda: I.authenticate_firebase(store, verifier, token())) == "user_unavailable"
    assert code(lambda: I.authenticate_firebase(store, None, token())) == "disabled"


def test_concurrent_links_of_one_identity_have_one_winner(store, verifier):
    tokens = [friend(store, f"f{i}", chr(65 + i) * 24) for i in range(8)]
    results, start = [], threading.Barrier(len(tokens))

    def attempt(install_token):
        start.wait()
        try:
            results.append(I.link_firebase_identity(store, verifier, install_token, token(sub="uid-race"))["user_id"])
        except I.IdentityError as e:
            results.append(e.code)
    threads = [threading.Thread(target=attempt, args=(t,)) for t in tokens]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    winners = [r for r in results if r.startswith("f")]
    assert len(winners) == 1 and results.count("uid_linked_elsewhere") == len(tokens) - 1
    assert store.identity_for_uid("uid-race")["user_id"] == winners[0]
