"""Download untrusted subtitle files safely: HTTPS only, public destinations (or a configured source host), every
redirect re-checked, and the body size limited while it streams."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urljoin, urlsplit

import httpx

MAX_REDIRECTS = 3


class UnsafeDestination(Exception):
    """The URL is not an allowed download destination."""


def resolve_host_addresses(hostname: str) -> list[str]:
    """IP addresses the host name resolves to (both families)."""
    return sorted({info[4][0] for info in socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)})


def check_destination(url: str, trusted_hosts: frozenset[str] = frozenset()) -> str | None:
    """Raise UnsafeDestination unless the URL is https on the default port, without credentials, and its host is a
    configured source or resolves only to public (globally routable) addresses. Returns the validated address to
    connect to, or None for a configured source host (connected to by name)."""
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise UnsafeDestination("only https URLs with a host name are allowed")
    if parts.username or parts.password:
        raise UnsafeDestination("credentials in the URL are not allowed")
    try:
        port = parts.port
    except ValueError:
        raise UnsafeDestination("invalid port") from None
    if port not in (None, 443):
        raise UnsafeDestination("only the default https port is allowed")
    hostname = parts.hostname.lower().rstrip(".")
    if hostname in trusted_hosts:
        return None
    try:
        addresses = [hostname] if _is_ip_literal(hostname) else resolve_host_addresses(hostname)
    except (OSError, UnicodeError):
        raise UnsafeDestination("host name does not resolve") from None
    if not addresses:
        raise UnsafeDestination("host name does not resolve")
    for address in addresses:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
        if not ip.is_global or ip.is_multicast:
            raise UnsafeDestination("destination is not a public address")
    return addresses[0].split("%", 1)[0]


def download_limited(http: httpx.Client, url: str, max_bytes: int,
                     trusted_hosts: frozenset[str] = frozenset()) -> bytes | None:
    """The response body of a 200 answer, or None for any other status, an oversized body or too many redirects.
    Raises UnsafeDestination for a disallowed URL or redirect target, httpx.HTTPError for transport failures.
    The connection goes to the address that was checked (TLS still verifies the original host name), so a DNS
    answer that changes after the check cannot redirect it."""
    for _ in range(MAX_REDIRECTS + 1):
        validated_address = check_destination(url, trusted_hosts)
        request_url, headers, extensions = _pinned_request(url, validated_address)
        with http.stream("GET", request_url, headers=headers, extensions=extensions,
                         follow_redirects=False) as response:
            if response.is_redirect and response.headers.get("location"):
                url = urljoin(url, response.headers["location"])
                continue
            if response.status_code != 200:
                return None
            declared_length = response.headers.get("content-length", "")
            if declared_length.isdigit() and int(declared_length) > max_bytes:
                return None
            body = bytearray()
            for chunk in response.iter_bytes():
                body += chunk
                if len(body) > max_bytes:
                    return None
            return bytes(body)
    return None


def source_hosts(*base_urls: str) -> frozenset[str]:
    """Host names of configured subtitle sources (trusted by configuration, e.g. a self-hosted addon)."""
    return frozenset(host.lower().rstrip(".") for host in (urlsplit(url).hostname for url in base_urls if url) if host)


def _pinned_request(url: str, address: str | None) -> tuple[str, dict, dict]:
    """(URL to request, headers, httpx extensions): the URL with its host replaced by the validated address, the
    original host in the Host header and as the TLS server name. Unchanged when there is no address to pin."""
    if address is None:
        return url, {}, {}
    parts = urlsplit(url)
    hostname = parts.hostname
    pinned_host = f"[{address}]" if ":" in address else address
    pinned_url = parts._replace(netloc=pinned_host + (f":{parts.port}" if parts.port else "")).geturl()
    # a fresh connection per download: a pooled connection to the same address was verified for another host name
    return pinned_url, {"Host": parts.netloc, "Connection": "close"}, {"sni_hostname": hostname}


def _is_ip_literal(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return True
