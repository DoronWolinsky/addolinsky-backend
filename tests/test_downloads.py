"""Untrusted subtitle downloads: destination checks, re-checked redirects and the streamed size limit."""

import httpx
import pytest

from addolinsky.cloud import downloads
from addolinsky.cloud.downloads import UnsafeDestination, check_destination, download_limited, source_hosts


def fake_dns(table):
    return lambda hostname: table[hostname]


@pytest.mark.parametrize("url", [
    "http://subs.example/a.srt", "ftp://subs.example/a.srt", "https:///a.srt", "https://user:pw@subs.example/a.srt",
    "https://subs.example:8443/a.srt", "https://127.0.0.1/a.srt", "https://[::1]/a.srt", "https://10.0.0.5/a.srt",
    "https://169.254.169.254/latest/meta-data", "https://192.168.1.1/a.srt", "https://[fd00::1]/a.srt",
    "https://0.0.0.0/a.srt", "https://internal.example/a.srt", "https://rebind.example/a.srt",
])
def test_disallowed_destinations(url, monkeypatch):
    monkeypatch.setattr(downloads, "resolve_host_addresses", fake_dns(
        {"subs.example": ["93.184.215.14"], "internal.example": ["10.1.2.3"],
         "rebind.example": ["93.184.215.14", "127.0.0.1"]}))
    with pytest.raises(UnsafeDestination):
        check_destination(url)


def test_public_and_configured_destinations_are_allowed(monkeypatch):
    monkeypatch.setattr(downloads, "resolve_host_addresses", fake_dns(
        {"subs.example": ["93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"], "source.lan": ["10.0.0.7"]}))
    check_destination("https://subs.example/a.srt")
    check_destination("https://subs.example:443/a.srt")
    check_destination("https://source.lan/x.srt", source_hosts("https://source.lan/", ""))  # self-hosted source
    with pytest.raises(UnsafeDestination):
        check_destination("https://source.lan/x.srt")


def test_unresolvable_host_is_refused(monkeypatch):
    def fail(hostname):
        raise OSError("no such host")
    monkeypatch.setattr(downloads, "resolve_host_addresses", fail)
    with pytest.raises(UnsafeDestination):
        check_destination("https://missing.example/a.srt")


def logical_url(request):
    """The URL the caller asked for: requests go to the validated address with the original host in Host."""
    return f"https://{request.headers['host']}{request.url.raw_path.decode()}"


def client(routes):
    return httpx.Client(transport=httpx.MockTransport(lambda request: routes[logical_url(request)]()))


def test_connection_goes_to_the_validated_address_with_the_original_tls_name(monkeypatch):
    monkeypatch.setattr(downloads, "resolve_host_addresses", fake_dns({"subs.example": ["93.184.215.14"]}))
    seen = []

    def handler(request):
        seen.append((request.url.host, request.headers["host"], request.extensions.get("sni_hostname")))
        return httpx.Response(200, content=b"subtitle")
    http = httpx.Client(transport=httpx.MockTransport(handler))
    assert download_limited(http, "https://subs.example/a.srt", 100) == b"subtitle"
    assert seen == [("93.184.215.14", "subs.example", "subs.example")]
    monkeypatch.setattr(downloads, "resolve_host_addresses", fake_dns({"subs.example": ["2606:2800:21f:cb07::1"]}))
    download_limited(http, "https://subs.example/a.srt", 100)
    assert seen[-1] == ("2606:2800:21f:cb07::1", "subs.example", "subs.example")
    trusted = download_limited(http, "https://source.lan/x.srt", 100, source_hosts("https://source.lan"))
    assert trusted == b"subtitle" and seen[-1] == ("source.lan", "source.lan", None)   # configured host by name


def test_redirects_are_followed_only_to_allowed_destinations():
    ok = client({"https://subs.example/a": lambda: httpx.Response(302, headers={"location": "/b"}),
                 "https://subs.example/b": lambda: httpx.Response(200, content=b"subtitle")})
    assert download_limited(ok, "https://subs.example/a", 100) == b"subtitle"
    to_metadata = client({"https://subs.example/a": lambda: httpx.Response(
        302, headers={"location": "https://169.254.169.254/latest/meta-data"})})
    with pytest.raises(UnsafeDestination):
        download_limited(to_metadata, "https://subs.example/a", 100)
    to_http = client({"https://subs.example/a": lambda: httpx.Response(301, headers={"location": "http://x.example/"})})
    with pytest.raises(UnsafeDestination):
        download_limited(to_http, "https://subs.example/a", 100)
    loop = client({"https://subs.example/a": lambda: httpx.Response(302, headers={"location": "/a"})})
    assert download_limited(loop, "https://subs.example/a", 100) is None


def test_size_limit_is_enforced_while_streaming():
    chunks_sent = []

    def endless():
        def body():
            for _ in range(1000):
                chunks_sent.append(1)
                yield b"x" * 1000
        return httpx.Response(200, content=body())
    assert download_limited(client({"https://subs.example/big": endless}), "https://subs.example/big", 5000) is None
    assert len(chunks_sent) <= 7                                       # stopped early, not after a full download
    declared = client({"https://subs.example/d": lambda: httpx.Response(
        200, headers={"content-length": "999999"}, content=b"x")})
    assert download_limited(declared, "https://subs.example/d", 5000) is None
    assert download_limited(client({"https://subs.example/e": lambda: httpx.Response(404)}),
                            "https://subs.example/e", 5000) is None
