# Addolinsky — backend components

Addolinsky is a production web service that delivers Hebrew subtitles for movies and series inside
[Stremio](https://www.stremio.com/). Users sign in on the website, receive a personal Stremio installation link and get
subtitles directly in the player. It runs as a single Python service (FastAPI, worker threads, SQLite) behind a TLS
reverse proxy.

**Live site:** https://addolinsky.com/account

**This repository is a curated subset of the private Addolinsky codebase.** The modules and tests here are real,
unmodified production code, selected to show how the service is engineered. It is not the complete service and cannot
produce subtitles on its own: the translation engine, the subtitle-source acquisition, the admin and request routes,
the application assembly and the deployment configuration are private.

## Engineering highlights

| Area | Where | What it shows |
|---|---|---|
| HTTP API design | `stremio/`, `account.py`, `api/http.py`, `dependencies.py` | FastAPI routers with dependency-injected application state (no globals); strict Pydantic request models; uniform, non-leaking error codes; `no-store` and `no-referrer` on every account response |
| Authentication | `security/identity.py`, `account.py`, `static/account.*` | Firebase ID-token verification implemented from the published JWT rules (RS256 only, key rotation, certificate cache honouring `max-age`, fail-closed refetch, issuer/audience/expiry/auth-time checks); recent sign-in required for sensitive actions; identities keyed by the immutable uid, never by e-mail |
| Account security | `security/auth.py`, `security/capabilities.py`, `security/nonces.py`, `security/sessions.py` | install links stored only as SHA-256; HMAC-signed per-user subtitle URLs re-authorized on every fetch; one-time confirmation tokens with atomic check-and-consume; revocable admin sessions |
| HTTP hardening | `security/middleware.py` | host allow-list against DNS rebinding, per-IP rate limiting with bounded memory, Origin/CSRF checks, strict security headers and a page-specific Content-Security-Policy |
| Entitlements | `services/entitlements.py`, `services/accounts.py` | three independent dimensions — role, plan derived only from provider-verified facts and the server clock, and audited manual grants; ownership of each creation recorded in the same transaction as the job; creation credits reserved atomically and released when a job fails or reuses an existing result |
| Payment-security architecture | `billing/` | provider-agnostic adapter interface; webhook events deduplicated per provider event id, applied inside a savepoint (all or nothing), replayed when they arrive out of order; a payment counts only if amount, currency and period length match the plan and it belongs to an open, unexpired checkout — anything else is held for review; refunds and chargebacks are never reverted; hosted checkout only, no card data on the server |
| Database design | `db.py` | SQLite in WAL mode, one connection per thread, `BEGIN IMMEDIATE` write transactions, idempotent additive migrations, append-only tables enforced by triggers (audit log, open catalogue), validated column names in dynamic SQL |
| Untrusted input | `subtitles/parsing.py`, `cloud/downloads.py`, `stremio/ids.py` | bounded decoding of SRT/VTT/ASS and ZIP archives; SSRF-safe downloads (public destinations only, re-checked redirects, streamed size limits); strict id validation |
| Output integrity | `subtitles/rendering.py`, `subtitles/outputs.py` | deterministic RTL-safe rendering, round-trip validation before publication, atomic writes with `fsync`, SHA-256 verification before serving |
| Stremio integration | `stremio/manifest.py`, `stremio/tracks.py` | public and per-user manifests, release-aware subtitle listings, request tracks that never start work on a listing |
| Legal versioning | `legal.py` | immutable, hash-pinned Terms and Privacy versions; a version is in force only when the owner approves the exact rendered text by its SHA-256; acceptance is recorded with that hash |

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for how the parts fit together.

## Operations (in the private repository)

The service runs on a single Linux host under systemd, bound to loopback behind a TLS reverse proxy. Releases are
installed side by side, smoke-tested on a copy of the database, switched atomically and rolled back automatically
when the health check fails. Nightly consistent SQLite backups are verified and copied off the server; a health timer
checks the service, disk and memory. Paid external work is bounded by hard monthly spending caps.

## Project status

- Website accounts (Google and e-mail/password through Firebase Authentication), personal installation links and the
  Free plan are live.
- Premium plans are designed and implemented against a mock payment provider, with offline end-to-end tests.
  **No real payment provider is connected and no payments are taken.** A real provider adapter will be added after
  sandbox testing.

## Running the tests

Requires Python 3.12.

```
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"      # Windows: .venv\Scripts\python.exe
.venv/bin/python -m pytest
```

The tests are offline: HTTP is served by `httpx.MockTransport`, Firebase certificates come from a locally generated
key, DNS lookups are stubbed and billing uses the mock provider.

## Copyright

Copyright © 2026 DoronWolinsky. All rights reserved. See [`COPYRIGHT`](COPYRIGHT). Published for portfolio review
only; no license is granted.
