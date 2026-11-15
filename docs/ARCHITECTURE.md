# Architecture

Addolinsky is one Python process on a single host: a FastAPI application, a pool of worker threads that run
translation jobs, and a SQLite database. It binds to loopback; a TLS reverse proxy is the only public entry point.
Modules marked *(private)* are part of the service but not of this repository.

```
Stremio ──HTTPS──▶ reverse proxy ──▶ FastAPI app
                                      ├─ middleware: host allow-list, admin isolation, rate limit, Origin, headers
                                      ├─ stremio/manifest, stremio/tracks         manifests and subtitle listings
                                      ├─ request tracks, subtitle files          (private)
                                      ├─ admin API, public pages                 (private)
                                      ├─ account (website sign-in, registration, dashboard)
                                      └─ billing webhook ─▶ billing/service (verified provider events)
worker threads ─▶ translation engine (private) ─▶ subtitles/rendering ─▶ subtitles/outputs
SQLite (db.py): users, jobs, checkpoints, tracks, outputs, deliveries, requests, identities, grants, credits,
                checkouts, subscriptions, payments, billing events, append-only audit log
```

## Shared state and dependency injection

`dependencies.AppContext` is created once per application. It owns the settings, the `Store`, the secrets, the
confirmation-token registry, the admin sessions, the rate limiter, the job-start lock and the cache of verified
output files. Route modules receive it through a FastAPI dependency (`Context`), so each router is a plain module
with no global state and can be mounted on its own (see `tests/test_stremio_routes.py`).

## Request flow on a personal install link

1. `GET /<install token>/subtitles/<type>/<id>.json` (`stremio/tracks.py`): the install token is looked up by its
   SHA-256. Finished translations are listed with URLs that carry a signed per-user video token, never the install
   token.
2. With no finished translation, two Hebrew tracks are listed. The first only reports status; the second carries a
   one-time confirmation token (`security/nonces.py`) in its id and URL. Listing never starts work.
3. Fetching the confirmation track *(private)* consumes the token atomically and, within the viewer's plan, quotas
   and the spending caps, starts or joins a job; the worker publishes the result only after
   `subtitles/rendering.finalize_srt` has re-parsed and compared the rendered file.

## Reliability and cost control

- Jobs are single-flight per video and resumable: every paid step is checkpointed, so a restart never pays twice.
- Paid work is bounded by hard monthly spending caps *(private)*: worst-case costs are reserved before each request,
  in transactions that count all jobs, so concurrent jobs cannot overrun them.
- Output files are written atomically and verified against their SHA-256 before they are listed or served.

## Security boundaries

- Untrusted input: subtitle files (`subtitles/parsing.py`), remote downloads (`cloud/downloads.py`), Stremio ids
  and query arguments (`stremio/ids.py`), Firebase ID tokens (`security/identity.py`).
- Credentials: install tokens and admin sessions are stored only as hashes; the admin token is never placed in a
  browser cookie; secrets are read from files or the environment and never logged.
- HTTP: host allow-list against DNS rebinding, admin routes hidden behind the proxy, per-IP rate limits, Origin
  checks and an anti-CSRF header for cookie-authenticated changes (`security/middleware.py`, `security/auth.py`).

## Plans, entitlements and billing

- `services/entitlements.py` derives what a user may see and create from three independent sources: role, a plan
  computed only from provider-verified subscription facts and the server clock, and audited manual grants. Premium
  gives a fixed number of new translations per allowance month (a yearly plan has twelve); a credit is reserved in the
  same transaction as the job and released when the job fails or reuses an existing translation.
- `billing/` is provider-agnostic: an adapter (`billing/provider.py`) turns a provider's authenticated webhooks into
  normalized events. `billing/service.py` stores each event once (deduplicated per provider event id), applies it in a
  savepoint, replays events that arrived early, and accepts a payment only when amount, currency and period length
  match the plan and it belongs to an open, unexpired checkout; anything else is held for review. Card data never
  reaches the service: checkout is the provider's hosted page, and a browser redirect never activates anything.
