"""SQLite persistence (WAL, one connection per thread, explicit transactions)."""

from __future__ import annotations

import json
import re
import secrets
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .subtitles.parsing import Cue

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tracks(
  track_id TEXT PRIMARY KEY, video_id TEXT NOT NULL, lang TEXT NOT NULL, lang_raw TEXT NOT NULL,
  provider TEXT NOT NULL, provider_ref TEXT, release_name TEXT, video_hash TEXT, format TEXT, encoding TEXT,
  content_hash TEXT NOT NULL, raw_sha256 TEXT NOT NULL, rights TEXT, warnings TEXT NOT NULL,
  cue_count INTEGER NOT NULL, created_at REAL NOT NULL);
CREATE INDEX IF NOT EXISTS tracks_video ON tracks(video_id);
CREATE TABLE IF NOT EXISTS cues(
  track_id TEXT NOT NULL REFERENCES tracks(track_id) ON DELETE CASCADE, idx INTEGER NOT NULL,
  cue_id TEXT NOT NULL, start_ms INTEGER NOT NULL, end_ms INTEGER NOT NULL, text TEXT NOT NULL,
  PRIMARY KEY(track_id, idx));
CREATE TABLE IF NOT EXISTS jobs(
  job_id TEXT PRIMARY KEY, video_id TEXT NOT NULL, release_key TEXT NOT NULL, provider TEXT NOT NULL,
  status TEXT NOT NULL, stage TEXT, error TEXT, cache_key TEXT, request TEXT NOT NULL, selection TEXT,
  output_id TEXT, cancel_requested INTEGER NOT NULL DEFAULT 0, metrics TEXT,
  created_at REAL NOT NULL, updated_at REAL NOT NULL);
CREATE INDEX IF NOT EXISTS jobs_status ON jobs(status);
CREATE TABLE IF NOT EXISTS checkpoints(
  job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE, name TEXT NOT NULL, data TEXT NOT NULL,
  PRIMARY KEY(job_id, name));
CREATE TABLE IF NOT EXISTS outputs(
  output_id TEXT PRIMARY KEY, job_id TEXT NOT NULL, video_id TEXT NOT NULL, release_key TEXT NOT NULL,
  cache_key TEXT NOT NULL, filename TEXT NOT NULL, sha256 TEXT NOT NULL, cue_count INTEGER NOT NULL,
  valid INTEGER NOT NULL DEFAULT 1, created_at REAL NOT NULL);
CREATE INDEX IF NOT EXISTS outputs_video ON outputs(video_id);
CREATE TABLE IF NOT EXISTS ledger(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, account TEXT NOT NULL, job_id TEXT, stage TEXT,
  model TEXT, status TEXT NOT NULL, estimated_usd REAL NOT NULL, charged_usd REAL NOT NULL,
  input_tokens INTEGER, output_tokens INTEGER, cached_tokens INTEGER, note TEXT);
CREATE INDEX IF NOT EXISTS ledger_account ON ledger(account);
CREATE TABLE IF NOT EXISTS users(
  user_id TEXT PRIMARY KEY, token_sha256 TEXT NOT NULL UNIQUE, role TEXT NOT NULL, created_at REAL NOT NULL,
  origin TEXT, disabled INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS deliveries(
  user_id TEXT NOT NULL, output_id TEXT NOT NULL, first_at REAL NOT NULL, last_at REAL NOT NULL,
  n INTEGER NOT NULL DEFAULT 1, PRIMARY KEY(user_id, output_id));
CREATE TABLE IF NOT EXISTS timing_variants(
  output_id TEXT NOT NULL, release_key TEXT NOT NULL, status TEXT NOT NULL, kind TEXT, model TEXT,
  ref TEXT, created_at REAL NOT NULL, PRIMARY KEY(output_id, release_key));
CREATE TABLE IF NOT EXISTS identities(
  uid TEXT PRIMARY KEY, user_id TEXT NOT NULL UNIQUE REFERENCES users(user_id), provider TEXT NOT NULL,
  email TEXT, email_verified INTEGER NOT NULL, sign_in_provider TEXT, linked_at REAL NOT NULL, last_seen_at REAL);
CREATE TABLE IF NOT EXISTS creations(
  job_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, video_id TEXT NOT NULL, source TEXT NOT NULL,
  created_at REAL NOT NULL);
CREATE INDEX IF NOT EXISTS creations_user ON creations(user_id);
CREATE TRIGGER IF NOT EXISTS creations_no_update BEFORE UPDATE ON creations
  BEGIN SELECT RAISE(ABORT, 'creations are immutable'); END;
CREATE TRIGGER IF NOT EXISTS creations_no_delete BEFORE DELETE ON creations
  BEGIN SELECT RAISE(ABORT, 'creations are immutable'); END;
CREATE TABLE IF NOT EXISTS grants(
  grant_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, kind TEXT NOT NULL, access_all INTEGER NOT NULL,
  can_create INTEGER NOT NULL, credits_per_period INTEGER, period_days INTEGER, starts_at REAL NOT NULL, ends_at REAL,
  reason TEXT NOT NULL, actor TEXT NOT NULL, created_at REAL NOT NULL, revoked_at REAL, revoked_by TEXT,
  revoke_reason TEXT);
CREATE INDEX IF NOT EXISTS grants_user ON grants(user_id);
CREATE TABLE IF NOT EXISTS creation_credits(
  credit_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, user_id TEXT NOT NULL, job_id TEXT NOT NULL,
  source TEXT NOT NULL, source_ref TEXT NOT NULL, period_start REAL NOT NULL, period_end REAL NOT NULL,
  status TEXT NOT NULL, created_at REAL NOT NULL, settled_at REAL);
CREATE INDEX IF NOT EXISTS credits_period ON creation_credits(source, source_ref, period_start);
CREATE INDEX IF NOT EXISTS credits_job ON creation_credits(job_id);
CREATE TABLE IF NOT EXISTS checkouts(
  checkout_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, provider TEXT NOT NULL, plan_code TEXT NOT NULL,
  provider_ref TEXT, status TEXT NOT NULL, created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS subscriptions(
  subscription_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, provider TEXT NOT NULL, provider_customer_id TEXT,
  provider_subscription_id TEXT NOT NULL, plan_code TEXT NOT NULL, price_minor INTEGER NOT NULL,
  currency TEXT NOT NULL, interval TEXT NOT NULL, status TEXT NOT NULL, verified_payment INTEGER NOT NULL DEFAULT 0,
  current_period_start REAL, current_period_end REAL, cancel_at_period_end INTEGER NOT NULL DEFAULT 0,
  status_event_at REAL NOT NULL DEFAULT 0, created_at REAL NOT NULL, updated_at REAL NOT NULL,
  UNIQUE(provider, provider_subscription_id));
CREATE INDEX IF NOT EXISTS subscriptions_user ON subscriptions(user_id);
CREATE TABLE IF NOT EXISTS payments(
  payment_id TEXT PRIMARY KEY, provider TEXT NOT NULL, provider_payment_id TEXT NOT NULL, subscription_id TEXT,
  amount_minor INTEGER NOT NULL, currency TEXT NOT NULL, status TEXT NOT NULL, period_start REAL, period_end REAL,
  document_id TEXT, document_status TEXT, occurred_at REAL NOT NULL, created_at REAL NOT NULL,
  UNIQUE(provider, provider_payment_id));
CREATE TABLE IF NOT EXISTS billing_events(
  event_id TEXT PRIMARY KEY, provider TEXT NOT NULL, provider_event_id TEXT NOT NULL, type TEXT NOT NULL,
  occurred_at REAL NOT NULL, payload TEXT NOT NULL, received_at REAL NOT NULL, status TEXT NOT NULL, note TEXT,
  UNIQUE(provider, provider_event_id));
CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, user_id TEXT,
  detail TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS audit_user ON audit_log(user_id);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
  BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
  BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;
CREATE TABLE IF NOT EXISTS consents(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, kind TEXT NOT NULL, version TEXT NOT NULL,
  text_sha256 TEXT NOT NULL, created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS account_invites(
  code_sha256 TEXT PRIMARY KEY, note TEXT NOT NULL, actor TEXT NOT NULL, created_at REAL NOT NULL,
  expires_at REAL NOT NULL, used_at REAL, used_by TEXT);
CREATE TABLE IF NOT EXISTS open_catalogue_outputs(
  output_id TEXT PRIMARY KEY, video_id TEXT NOT NULL, designated_at REAL NOT NULL, reason TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS open_catalogue_no_update BEFORE UPDATE ON open_catalogue_outputs
  BEGIN SELECT RAISE(ABORT, 'open-catalogue designations are permanent'); END;
CREATE TRIGGER IF NOT EXISTS open_catalogue_no_delete BEFORE DELETE ON open_catalogue_outputs
  BEGIN SELECT RAISE(ABORT, 'open-catalogue designations are permanent'); END;
"""
# open_catalogue_outputs (D-141): the translation catalogue that existed before plans, designated once by output id
# (immutable) and viewable by every registered, active user. A takedown invalidates the output itself (valid=0).
OPEN_CATALOGUE_CUTOFF = 1794733200.0      # 2026-11-15 09:00:00 UTC: outputs created before it form the catalogue
# creations (2026-11-14): who created each translation job: written in the same transaction as the job, never updated
# or deleted (triggers). source: live | legacy_job_user (the requester recorded on the job before this table existed).
# The creator of the job that produced an output owns that output; viewing, joining or retrying never confers it.
# grants: manual entitlements (kind beta | test_premium | manual) with actor, reason, period and revocation; never a
# payment. creation_credits: one row per creation attempt (reserved -> consumed | released). subscriptions, payments,
# billing_events and checkouts hold only provider-verified billing facts (no card data ever).
# identities (F1, D-132): a website identity (Firebase uid) explicitly linked to one Addolinsky user. One uid per user
# and one user per uid (both keys unique). Never created by matching e-mail addresses; never touches install tokens.
# requests: who asked for which translation (Batch 1, 2026-11-11). kind: new | join | retry | cached; source: live
# (recorded when it happened) | backfill (the creator recorded on a cloud job before this table existed). Only the
# job creator is a confirmed historical requester: historical joins and receipts stay unknown (deliveries only), and
# no row implies rights or sharing permission. A job row's output is the job's output_id (known once READY).
REQUEST_KINDS = ("new", "join", "retry", "cached")
REQUESTS_TABLE = ("CREATE TABLE requests(request_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, video_id TEXT NOT NULL, "
                  "kind TEXT NOT NULL, job_id TEXT, output_id TEXT, source TEXT NOT NULL, created_at REAL NOT NULL)",
                  "CREATE INDEX requests_user ON requests(user_id)",
                  "CREATE INDEX requests_job ON requests(job_id)")

# Columns added after the first release (applied idempotently on open).
MIGRATIONS = (
    ("jobs", "user_id", "TEXT"),
    ("jobs", "status_id", "TEXT"),
    ("jobs", "progress", "TEXT"),
    ("jobs", "started_at", "REAL"),
    ("outputs", "source_track", "TEXT"),
    ("users", "label", "TEXT"),
    # account status: existing rows become 'active' through the default; only active accounts authenticate
    ("users", "status", "TEXT NOT NULL DEFAULT 'active'"),
    ("users", "status_changed_at", "REAL"),
)


_COLUMN_NAME = re.compile(r"^[a-z_][a-z0-9_]*$")


def _checked_columns(column_names) -> list[str]:
    """Column names that are interpolated into SQL come only from code; refuse anything else."""
    checked = list(column_names)
    for column_name in checked:
        if not _COLUMN_NAME.fullmatch(column_name):
            raise ValueError(f"invalid column name {column_name!r}")
    return checked


def _row_as_dict(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row else None


class Store:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.__thread_local = threading.local()          # one SQLite connection per thread
        self.conn.executescript(SCHEMA)
        self._apply_column_migrations()
        self._create_requests_table_once()
        self._migrate_entitlements_v1()
        self._designate_open_catalogue_v1()
        if self.conn.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise RuntimeError("SQLite integrity check failed")

    def _apply_column_migrations(self) -> None:
        for table, column, column_type in MIGRATIONS:
            existing_columns = {row[1] for row in self.conn.execute(f"PRAGMA table_info({table})")}
            if column not in existing_columns:
                self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {column_type}")
        self.conn.execute(  # outputs created before source_track existed: take it from the job's selection
            "UPDATE outputs SET source_track=(SELECT json_extract(j.selection,'$.english_track') FROM jobs j "
            "WHERE j.job_id=outputs.job_id AND j.provider='cloud') WHERE source_track IS NULL")
        self.conn.execute("CREATE INDEX IF NOT EXISTS jobs_user ON jobs(user_id)")
        self.conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS jobs_status_id ON jobs(status_id)")

    def _create_requests_table_once(self) -> None:
        """Created once, together with its backfill (atomic: both or neither)."""
        with self.tx() as transaction:
            if transaction.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='requests'").fetchone():
                return
            for statement in REQUESTS_TABLE:
                transaction.execute(statement)
            transaction.execute(
                "INSERT INTO requests(request_id,user_id,video_id,kind,job_id,output_id,source,created_at) "
                "SELECT 'backfill-'||job_id, user_id, video_id, 'new', job_id, NULL, 'backfill', created_at "
                "FROM jobs WHERE provider='cloud' AND user_id IS NOT NULL")

    def _migrate_entitlements_v1(self) -> None:
        """Idempotent on every start, atomic: record the creator of each cloud job whose requester was stored on the
        job (the request track sets it at creation and nothing changes it), and give each invited friend who never had
        a beta grant an explicit, open-ended `beta` grant that keeps their current access (all finished translations,
        beta quotas). A revoked grant is never re-created. Jobs without a recorded requester get no creator (unknown,
        never guessed); `addolinsky ownership-review` lists them. Also covers rows an older release created after a
        rollback."""
        with self.tx() as transaction:
            now = time.time()
            backfilled_creations = transaction.execute(
                "INSERT OR IGNORE INTO creations(job_id,user_id,video_id,source,created_at) SELECT job_id, user_id, "
                "video_id, 'legacy_job_user', created_at FROM jobs WHERE provider='cloud' AND user_id IS NOT NULL "
                "AND job_id NOT IN (SELECT job_id FROM creations)").rowcount
            friends_without_grant = transaction.execute(
                "SELECT user_id, created_at FROM users WHERE role='friend' AND user_id NOT IN "
                "(SELECT user_id FROM grants WHERE kind='beta')").fetchall()
            for user_id, created_at in friends_without_grant:
                transaction.execute(
                    "INSERT INTO grants(grant_id,user_id,kind,access_all,can_create,credits_per_period,period_days,"
                    "starts_at,ends_at,reason,actor,created_at) VALUES(?,?,'beta',1,1,NULL,NULL,?,NULL,"
                    "'closed-beta invitation before plans existed (migration)','migration',?)",
                    ("g" + secrets.token_hex(6), user_id, created_at, now))
            if backfilled_creations or friends_without_grant:
                transaction.execute(
                    "INSERT INTO audit_log(ts,actor,action,user_id,detail) VALUES(?,?,?,?,?)",
                    (now, "migration", "entitlements_v1", None,
                     json.dumps({"creations_backfilled": backfilled_creations,
                                 "beta_grants": len(friends_without_grant)})))

    def _designate_open_catalogue_v1(self) -> None:
        """Once per database, atomically: designate every translation that viewers could receive before plans existed
        (a valid output of a READY production job, created before OPEN_CATALOGUE_CUTOFF) as open-catalogue. Later
        outputs are never designated automatically."""
        with self.tx() as transaction:
            if transaction.execute("SELECT 1 FROM meta WHERE key='open_catalogue_v1'").fetchone():
                return
            now = time.time()
            designated = transaction.execute(
                "INSERT OR IGNORE INTO open_catalogue_outputs(output_id,video_id,designated_at,reason) "
                "SELECT DISTINCT o.output_id, o.video_id, ?, 'catalogue before plans (migration)' FROM outputs o "
                "JOIN jobs j ON j.output_id=o.output_id WHERE j.provider='cloud' AND j.status='READY' AND o.valid=1 "
                "AND o.created_at<?", (now, OPEN_CATALOGUE_CUTOFF)).rowcount
            transaction.execute("INSERT INTO meta(key,value) VALUES('open_catalogue_v1',?)", (str(now),))
            transaction.execute("INSERT INTO audit_log(ts,actor,action,user_id,detail) VALUES(?,?,?,?,?)",
                                (now, "migration", "open_catalogue_v1", None,
                                 json.dumps({"outputs_designated": designated, "cutoff": OPEN_CATALOGUE_CUTOFF})))

    @property
    def conn(self) -> sqlite3.Connection:
        """This thread's connection (WAL, autocommit outside explicit transactions)."""
        connection = getattr(self.__thread_local, "connection", None)
        if connection is None:
            connection = sqlite3.connect(self.path, isolation_level=None, timeout=30, check_same_thread=True)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA synchronous=NORMAL")
            self.__thread_local.connection = connection
        return connection

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        """A write transaction (BEGIN IMMEDIATE): committed on success, rolled back on any exception."""
        connection = self.conn
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield connection
        except BaseException:
            connection.execute("ROLLBACK")
            raise
        else:
            connection.execute("COMMIT")

    def close(self) -> None:
        """Close this thread's connection."""
        connection = getattr(self.__thread_local, "connection", None)
        if connection is not None:
            connection.close()
            self.__thread_local.connection = None

    def _fetch_one(self, sql: str, *arguments) -> dict | None:
        return _row_as_dict(self.conn.execute(sql, arguments).fetchone())

    def _fetch_all(self, sql: str, *arguments) -> list[dict]:
        return [dict(row) for row in self.conn.execute(sql, arguments)]

    def _insert_row(self, transaction, table: str, row: dict) -> None:
        columns = _checked_columns(row)
        transaction.execute(f"INSERT INTO {table}({','.join(columns)},created_at) "
                            f"VALUES({','.join('?' * len(columns))},?)", (*row.values(), time.time()))

    # ---- tracks
    def add_track(self, row: dict, cues: list[Cue]) -> bool:
        """Insert a track and its cues atomically. Returns False if it already exists."""
        with self.tx() as transaction:
            if transaction.execute("SELECT 1 FROM tracks WHERE track_id=?", (row["track_id"],)).fetchone():
                return False
            self._insert_row(transaction, "tracks", row)
            transaction.executemany(
                "INSERT INTO cues(track_id,idx,cue_id,start_ms,end_ms,text) VALUES(?,?,?,?,?,?)",
                [(row["track_id"], cue.index, cue.cue_id, cue.start_ms, cue.end_ms, cue.text) for cue in cues])
        return True

    def get_track(self, track_id: str) -> dict | None:
        return self._fetch_one("SELECT * FROM tracks WHERE track_id=?", track_id)

    def list_tracks(self, video_id: str | None = None) -> list[dict]:
        if video_id:
            return self._fetch_all("SELECT * FROM tracks WHERE video_id=? ORDER BY created_at", video_id)
        return self._fetch_all("SELECT * FROM tracks ORDER BY created_at DESC LIMIT 500")

    def get_cues(self, track_id: str) -> list[Cue]:
        rows = self.conn.execute("SELECT * FROM cues WHERE track_id=? ORDER BY idx", (track_id,))
        return [Cue(row["cue_id"], row["idx"], row["start_ms"], row["end_ms"], row["text"]) for row in rows]

    # ---- jobs
    def create_job(self, job: dict, on_create=None) -> tuple[str, bool]:
        """Create a job unless an equivalent one is active (repeated clicks). Returns (job_id, created).
        `on_create(connection, job_id)` runs inside the same transaction (creator record, credit reservation); if it
        raises, nothing is written."""
        with self.tx() as transaction:
            active_job = transaction.execute(
                "SELECT job_id FROM jobs WHERE video_id=? AND release_key=? AND provider=? AND request=? "
                "AND status IN ('QUEUED','RUNNING')",
                (job["video_id"], job["release_key"], job["provider"], job["request"]),
            ).fetchone()
            if active_job:
                return active_job["job_id"], False
            now = time.time()
            transaction.execute(
                "INSERT INTO jobs(job_id,video_id,release_key,provider,status,request,created_at,updated_at,user_id,"
                "status_id) VALUES(?,?,?,?, 'QUEUED', ?,?,?,?,?)",
                (job["job_id"], job["video_id"], job["release_key"], job["provider"], job["request"], now, now,
                 job.get("user_id"), job.get("status_id")))
            if on_create is not None:
                on_create(transaction, job["job_id"])
        return job["job_id"], True

    def get_job(self, job_id: str) -> dict | None:
        return self._fetch_one("SELECT * FROM jobs WHERE job_id=?", job_id)

    def list_jobs(self, limit: int = 100) -> list[dict]:
        return self._fetch_all("SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", limit)

    def update_job(self, job_id: str, **columns) -> None:
        columns["updated_at"] = time.time()
        assignments = ",".join(f"{column}=?" for column in _checked_columns(columns))
        with self.tx() as transaction:
            transaction.execute(f"UPDATE jobs SET {assignments} WHERE job_id=?", (*columns.values(), job_id))

    # Fair order: users with fewer running jobs first, then oldest request first.
    FAIR_ORDER = ("(SELECT COUNT(*) FROM jobs r WHERE r.status='RUNNING' AND r.user_id IS j.user_id), j.created_at")

    def claim_next_job(self) -> str | None:
        with self.tx() as transaction:
            next_job = transaction.execute(
                f"SELECT j.job_id FROM jobs j WHERE j.status='QUEUED' ORDER BY {self.FAIR_ORDER} LIMIT 1").fetchone()
            if not next_job:
                return None
            now = time.time()
            transaction.execute("UPDATE jobs SET status='RUNNING', updated_at=?, started_at=COALESCE(started_at, ?) "
                                "WHERE job_id=?", (now, now, next_job["job_id"]))
            return next_job["job_id"]

    def queue_position(self, job_id: str) -> tuple[int, int, int]:
        """(1-based position among queued jobs in claim order, queued total, running total)."""
        queued_job_ids = [row[0] for row in self.conn.execute(
            f"SELECT j.job_id FROM jobs j WHERE j.status='QUEUED' ORDER BY {self.FAIR_ORDER}")]
        running_count = self.conn.execute("SELECT COUNT(*) FROM jobs WHERE status='RUNNING'").fetchone()[0]
        position = queued_job_ids.index(job_id) + 1 if job_id in queued_job_ids else 0
        return position, len(queued_job_ids), running_count

    def job_by_status_id(self, status_id: str) -> dict | None:
        return self._fetch_one("SELECT * FROM jobs WHERE status_id=?", status_id)

    def jobs_created_since(self, since: float, user_id: str | None = None) -> int:
        sql, arguments = "SELECT COUNT(*) FROM jobs WHERE provider='cloud' AND created_at>=?", [since]
        if user_id:
            sql += " AND user_id=?"
            arguments.append(user_id)
        return self.conn.execute(sql, arguments).fetchone()[0]

    # ---- users (personal install links; only the SHA-256 of a token is stored)
    def add_user(self, user_id: str, token_sha256: str, role: str, origin: str = "") -> None:
        """Create a user. An invited friend gets the closed-beta grant (all finished translations, beta quotas) in
        the same transaction: an invitation is that entitlement."""
        now = time.time()
        with self.tx() as transaction:
            added = transaction.execute("INSERT OR IGNORE INTO users(user_id,token_sha256,role,created_at,origin) "
                                        "VALUES(?,?,?,?,?)", (user_id, token_sha256, role, now, origin[:64])).rowcount
            if added and role == "friend":
                transaction.execute(
                    "INSERT INTO grants(grant_id,user_id,kind,access_all,can_create,credits_per_period,period_days,"
                    "starts_at,ends_at,reason,actor,created_at) VALUES(?,?,'beta',1,1,NULL,NULL,?,NULL,"
                    "'closed-beta invitation','invite',?)", ("g" + secrets.token_hex(6), user_id, now, now))

    def user_by_token_hash(self, token_sha256: str) -> dict | None:
        return self._fetch_one("SELECT * FROM users WHERE token_sha256=? AND disabled=0 AND status='active'",
                               token_sha256)

    def active_user_role(self, user_id: str) -> str | None:
        """The role of an enabled, active user; None for unknown, disabled or not (yet) active users."""
        row = self.conn.execute("SELECT role FROM users WHERE user_id=? AND disabled=0 AND status='active'",
                                (user_id,)).fetchone()
        return row[0] if row else None

    def sync_owner(self, token_sha256: str) -> None:
        """The owner row follows data/addon_key (a rotated key replaces the old hash)."""
        with self.tx() as transaction:
            transaction.execute("INSERT INTO users(user_id,token_sha256,role,created_at,origin) VALUES('owner',?,"
                                "'owner',?,'local') ON CONFLICT(user_id) DO UPDATE SET "
                                "token_sha256=excluded.token_sha256", (token_sha256, time.time()))

    def active_friends(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM users WHERE role='friend' AND disabled=0").fetchone()[0]

    def set_user_label(self, user_id: str, label: str) -> None:
        with self.tx() as transaction:
            transaction.execute("UPDATE users SET label=? WHERE user_id=?", (label[:40], user_id))

    def set_user_disabled(self, user_id: str, disabled: bool) -> bool:
        with self.tx() as transaction:
            return transaction.execute("UPDATE users SET disabled=? WHERE user_id=? AND role!='owner'",
                                       (int(disabled), user_id)).rowcount == 1

    def list_users(self) -> list[dict]:
        return self._fetch_all("SELECT user_id, role, label, origin, created_at, disabled FROM users "
                               "ORDER BY created_at")

    def record_delivery(self, user_id: str, output_id: str) -> None:
        """A finished subtitle file was served to this user (a fetch, not proof that anyone watched)."""
        now = time.time()
        with self.tx() as transaction:
            transaction.execute("INSERT INTO deliveries(user_id,output_id,first_at,last_at) VALUES(?,?,?,?) "
                                "ON CONFLICT(user_id,output_id) DO UPDATE SET last_at=excluded.last_at, n=n+1",
                                (user_id, output_id, now, now))

    def record_request(self, user_id: str, video_id: str, kind: str, job_id: str | None = None,
                       output_id: str | None = None) -> bool:
        """Record a translation request. A join, or a finished translation received through the request track
        ("cached"), is recorded once: not again when this user already has a request for that job or for a job that
        produced that output. Returns True when a row was added."""
        if kind not in REQUEST_KINDS:
            raise ValueError(f"unknown request kind {kind!r}")
        with self.tx() as transaction:
            if kind == "join" and transaction.execute("SELECT 1 FROM requests WHERE user_id=? AND job_id=?",
                                                      (user_id, job_id)).fetchone():
                return False
            if kind == "cached" and transaction.execute(
                    "SELECT 1 FROM requests r LEFT JOIN jobs j ON j.job_id=r.job_id WHERE r.user_id=? "
                    "AND (r.output_id=? OR j.output_id=?)", (user_id, output_id, output_id)).fetchone():
                return False
            transaction.execute(
                "INSERT INTO requests(request_id,user_id,video_id,kind,job_id,output_id,source,created_at) "
                "VALUES(?,?,?,?,?,?,'live',?)",
                (secrets.token_hex(8), user_id, video_id, kind, job_id, output_id, time.time()))
        return True

    def requests_for_user(self, user_id: str) -> list[dict]:
        return self._fetch_all("SELECT * FROM requests WHERE user_id=? ORDER BY created_at", user_id)

    # ---- website identities (Firebase), linked explicitly by a user who proved both credentials
    def get_user(self, user_id: str) -> dict | None:
        return self._fetch_one("SELECT * FROM users WHERE user_id=?", user_id)

    def identity_for_uid(self, uid: str) -> dict | None:
        return self._fetch_one("SELECT * FROM identities WHERE uid=?", uid)

    def identity_for_user(self, user_id: str) -> dict | None:
        return self._fetch_one("SELECT * FROM identities WHERE user_id=?", user_id)

    def link_identity(self, user_id: str, uid: str, provider: str, email: str | None, email_verified: bool,
                      sign_in_provider: str | None) -> str:
        """Link a website identity to an active user in one write transaction (concurrent links are serialized).
        Returns "linked", "already_linked", "user_unavailable", "uid_linked_elsewhere" or "user_has_other_identity";
        an existing link is never replaced or moved."""
        now = time.time()
        stored_email, stored_sign_in = (email or "")[:254], (sign_in_provider or "")[:40]
        with self.tx() as transaction:
            if not transaction.execute("SELECT 1 FROM users WHERE user_id=? AND disabled=0 AND status='active'",
                                       (user_id,)).fetchone():
                return "user_unavailable"
            linked_user = transaction.execute("SELECT user_id FROM identities WHERE uid=?", (uid,)).fetchone()
            if linked_user and linked_user[0] != user_id:
                return "uid_linked_elsewhere"
            linked_uid = transaction.execute("SELECT uid FROM identities WHERE user_id=?", (user_id,)).fetchone()
            if linked_uid and linked_uid[0] != uid:
                return "user_has_other_identity"
            if linked_user:
                transaction.execute("UPDATE identities SET email=?, email_verified=?, sign_in_provider=?, "
                                    "last_seen_at=? WHERE uid=?",
                                    (stored_email, int(email_verified), stored_sign_in, now, uid))
                return "already_linked"
            transaction.execute(
                "INSERT INTO identities(uid,user_id,provider,email,email_verified,sign_in_provider,linked_at,"
                "last_seen_at) VALUES(?,?,?,?,?,?,?,?)",
                (uid, user_id, provider, stored_email, int(email_verified), stored_sign_in, now, now))
        return "linked"

    def touch_identity(self, uid: str, email: str | None, email_verified: bool, sign_in_provider: str | None) -> None:
        with self.tx() as transaction:
            transaction.execute("UPDATE identities SET email=?, email_verified=?, sign_in_provider=?, last_seen_at=? "
                                "WHERE uid=?", ((email or "")[:254], int(email_verified),
                                                (sign_in_provider or "")[:40], time.time(), uid))

    def users_created_since(self, since: float, origin: str) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM users WHERE created_at>=? AND origin=?",
                                 (since, origin)).fetchone()[0]

    # ---- release-specific timing variants of a finished translation
    def get_variant(self, output_id: str, release_key: str) -> dict | None:
        return self._fetch_one("SELECT * FROM timing_variants WHERE output_id=? AND release_key=?", output_id,
                               release_key)

    def put_variant(self, output_id: str, release_key: str, status: str, kind: str | None, model,
                    ref: str = "") -> None:
        with self.tx() as transaction:
            transaction.execute("INSERT OR REPLACE INTO timing_variants VALUES(?,?,?,?,?,?,?)",
                                (output_id, release_key, status, kind,
                                 json.dumps(model) if model is not None else None, ref[:200], time.time()))

    def requeue_interrupted(self) -> int:
        with self.tx() as transaction:
            return transaction.execute("UPDATE jobs SET status='QUEUED', updated_at=? WHERE status='RUNNING'",
                                       (time.time(),)).rowcount

    def is_cancel_requested(self, job_id: str) -> bool:
        row = self.conn.execute("SELECT cancel_requested FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        return bool(row and row[0])

    # ---- checkpoints
    def save_checkpoint(self, job_id: str, name: str, data) -> None:
        with self.tx() as transaction:
            transaction.execute("INSERT OR REPLACE INTO checkpoints(job_id,name,data) VALUES(?,?,?)",
                                (job_id, name, json.dumps(data, ensure_ascii=False)))

    def load_checkpoint(self, job_id: str, name: str):
        row = self.conn.execute("SELECT data FROM checkpoints WHERE job_id=? AND name=?", (job_id, name)).fetchone()
        return json.loads(row[0]) if row else None

    def clear_checkpoints(self, job_id: str) -> None:
        with self.tx() as transaction:
            transaction.execute("DELETE FROM checkpoints WHERE job_id=?", (job_id,))

    # ---- outputs
    def add_output(self, row: dict) -> None:
        with self.tx() as transaction:
            self._insert_row(transaction, "outputs", row)

    def get_output(self, output_id: str) -> dict | None:
        return self._fetch_one("SELECT * FROM outputs WHERE output_id=?", output_id)

    def find_output_by_cache_key(self, cache_key: str) -> dict | None:
        return self._fetch_one("SELECT * FROM outputs WHERE cache_key=? AND valid=1 ORDER BY created_at DESC LIMIT 1",
                               cache_key)

    def ready_outputs(self, video_id: str, job_providers: tuple[str, ...] | None = None) -> list[dict]:
        """Valid outputs of READY jobs for a video, newest first; only jobs of `job_providers` when given."""
        provider_filter, arguments = "", [video_id]
        if job_providers is not None:
            if not job_providers:
                return []
            provider_filter = f" AND j.provider IN ({','.join('?' * len(job_providers))})"
            arguments += job_providers
        return self._fetch_all(
            "SELECT o.* FROM outputs o JOIN jobs j ON j.output_id=o.output_id "
            f"WHERE o.video_id=? AND o.valid=1 AND j.status='READY'{provider_filter} "
            "GROUP BY o.output_id ORDER BY o.created_at DESC", *arguments)

    def invalidate_output(self, output_id: str) -> None:
        with self.tx() as transaction:
            transaction.execute("UPDATE outputs SET valid=0 WHERE output_id=?", (output_id,))
