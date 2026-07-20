"""
core/database.py – SQLite database layer.

All queries are parameterised to prevent SQL injection.
Schema covers: cases, evidence, iocs, events, timelines,
audit_log, threat_intel, reports, settings, plugins.
"""

from __future__ import annotations

import logging
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator, Optional

from core.config import Config

log = logging.getLogger(__name__)

_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- ── Cases ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cases (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    title         TEXT    NOT NULL,
    description   TEXT    DEFAULT '',
    severity      TEXT    DEFAULT 'medium',
    status        TEXT    DEFAULT 'open',
    analyst       TEXT    DEFAULT '',
    tags          TEXT    DEFAULT '',
    created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── Evidence ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS evidence (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id       INTEGER REFERENCES cases(id) ON DELETE CASCADE,
    name          TEXT    NOT NULL,
    file_path     TEXT    NOT NULL,
    file_type     TEXT    DEFAULT '',
    file_size     INTEGER DEFAULT 0,
    sha256        TEXT    DEFAULT '',
    md5           TEXT    DEFAULT '',
    notes         TEXT    DEFAULT '',
    parsed        INTEGER DEFAULT 0,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── Log Events ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS log_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id       INTEGER REFERENCES cases(id) ON DELETE CASCADE,
    evidence_id   INTEGER REFERENCES evidence(id) ON DELETE CASCADE,
    source_type   TEXT    DEFAULT '',
    timestamp     TEXT    DEFAULT '',
    level         TEXT    DEFAULT '',
    event_id      TEXT    DEFAULT '',
    source_host   TEXT    DEFAULT '',
    source_ip     TEXT    DEFAULT '',
    dest_ip       TEXT    DEFAULT '',
    user          TEXT    DEFAULT '',
    process       TEXT    DEFAULT '',
    message       TEXT    DEFAULT '',
    raw           TEXT    DEFAULT '',
    tags          TEXT    DEFAULT '',
    flagged       INTEGER DEFAULT 0,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_log_events_case ON log_events(case_id);
CREATE INDEX IF NOT EXISTS idx_log_events_ts   ON log_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_log_events_src  ON log_events(source_type);

-- ── IOCs ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS iocs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id       INTEGER REFERENCES cases(id) ON DELETE SET NULL,
    ioc_type      TEXT    NOT NULL,
    value         TEXT    NOT NULL,
    confidence    TEXT    DEFAULT 'medium',
    threat_type   TEXT    DEFAULT '',
    source        TEXT    DEFAULT '',
    first_seen    TEXT    DEFAULT '',
    last_seen     TEXT    DEFAULT '',
    notes         TEXT    DEFAULT '',
    enriched      INTEGER DEFAULT 0,
    enrichment    TEXT    DEFAULT '',
    created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(ioc_type, value)
);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
CREATE INDEX IF NOT EXISTS idx_iocs_type  ON iocs(ioc_type);

-- ── Timeline Entries ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS timeline_entries (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id       INTEGER REFERENCES cases(id) ON DELETE CASCADE,
    timestamp     TEXT    NOT NULL,
    event_type    TEXT    DEFAULT '',
    description   TEXT    DEFAULT '',
    source        TEXT    DEFAULT '',
    actor         TEXT    DEFAULT '',
    target        TEXT    DEFAULT '',
    mitre_tactic  TEXT    DEFAULT '',
    mitre_tech    TEXT    DEFAULT '',
    severity      TEXT    DEFAULT 'info',
    evidence_id   INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
    log_event_id  INTEGER REFERENCES log_events(id) ON DELETE SET NULL,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_timeline_case ON timeline_entries(case_id);
CREATE INDEX IF NOT EXISTS idx_timeline_ts   ON timeline_entries(timestamp);

-- ── Threat Intelligence ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS threat_intel (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_type      TEXT    NOT NULL,
    value         TEXT    NOT NULL,
    provider      TEXT    DEFAULT '',
    threat_type   TEXT    DEFAULT '',
    confidence    REAL    DEFAULT 0.0,
    country       TEXT    DEFAULT '',
    asn           TEXT    DEFAULT '',
    malware_family TEXT   DEFAULT '',
    tags          TEXT    DEFAULT '',
    raw_data      TEXT    DEFAULT '',
    fetched_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(ioc_type, value, provider)
);

-- ── YARA Rules ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS yara_rules (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL,
    rule_text     TEXT    NOT NULL,
    description   TEXT    DEFAULT '',
    author        TEXT    DEFAULT '',
    tags          TEXT    DEFAULT '',
    enabled       INTEGER DEFAULT 1,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── Sigma Rules ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sigma_rules (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL,
    rule_yaml     TEXT    NOT NULL,
    description   TEXT    DEFAULT '',
    author        TEXT    DEFAULT '',
    severity      TEXT    DEFAULT 'medium',
    tags          TEXT    DEFAULT '',
    mitre_tags    TEXT    DEFAULT '',
    enabled       INTEGER DEFAULT 1,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── MITRE ATT&CK Cache ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS mitre_techniques (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    technique_id  TEXT    UNIQUE NOT NULL,
    name          TEXT    NOT NULL,
    tactic        TEXT    DEFAULT '',
    description   TEXT    DEFAULT '',
    url           TEXT    DEFAULT '',
    platform      TEXT    DEFAULT '',
    data_sources  TEXT    DEFAULT ''
);

-- ── Reports ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS reports (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id       INTEGER REFERENCES cases(id) ON DELETE SET NULL,
    title         TEXT    NOT NULL,
    format        TEXT    DEFAULT 'pdf',
    file_path     TEXT    DEFAULT '',
    generated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── Audit Log ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    action        TEXT    NOT NULL,
    detail        TEXT    DEFAULT '',
    user          TEXT    DEFAULT 'analyst',
    ip            TEXT    DEFAULT '',
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── Plugins ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS plugins (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    UNIQUE NOT NULL,
    version       TEXT    DEFAULT '',
    description   TEXT    DEFAULT '',
    author        TEXT    DEFAULT '',
    entry_point   TEXT    DEFAULT '',
    enabled       INTEGER DEFAULT 1,
    installed_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── AI Conversations ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ai_conversations (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id       INTEGER REFERENCES cases(id) ON DELETE SET NULL,
    provider      TEXT    DEFAULT '',
    model         TEXT    DEFAULT '',
    prompt        TEXT    NOT NULL,
    response      TEXT    DEFAULT '',
    tokens_used   INTEGER DEFAULT 0,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── PCAP Sessions ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS pcap_sessions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id   INTEGER REFERENCES evidence(id) ON DELETE CASCADE,
    src_ip        TEXT    DEFAULT '',
    dst_ip        TEXT    DEFAULT '',
    src_port      INTEGER DEFAULT 0,
    dst_port      INTEGER DEFAULT 0,
    protocol      TEXT    DEFAULT '',
    start_time    TEXT    DEFAULT '',
    end_time      TEXT    DEFAULT '',
    packet_count  INTEGER DEFAULT 0,
    byte_count    INTEGER DEFAULT 0,
    flags         TEXT    DEFAULT '',
    payload_hint  TEXT    DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_pcap_evidence ON pcap_sessions(evidence_id);

-- ── Memory Artifacts ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS memory_artifacts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id   INTEGER REFERENCES evidence(id) ON DELETE CASCADE,
    artifact_type TEXT    DEFAULT '',
    name          TEXT    DEFAULT '',
    pid           INTEGER DEFAULT 0,
    ppid          INTEGER DEFAULT 0,
    offset        TEXT    DEFAULT '',
    detail        TEXT    DEFAULT '',
    suspicious    INTEGER DEFAULT 0,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);
"""


class Database:
    """
    Thin wrapper around sqlite3 providing a connection pool (single-thread
    model) and helper query methods.

    All public query methods accept only parameterised statements.
    """

    def __init__(self, config: Config) -> None:
        db_path = config.app_data_dir / "sentinelai.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db_path: Path = db_path
        self._conn: Optional[sqlite3.Connection] = None

    # ── Lifecycle ──────────────────────────────────────────────────────────

    def initialise(self) -> None:
        """Create schema and open connection."""
        conn = self._get_conn()
        conn.executescript(_SCHEMA)
        conn.commit()
        log.info("Database initialised at %s", self._db_path)

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    # ── Connection management ─────────────────────────────────────────────

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(
                self._db_path,
                detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
                check_same_thread=False,
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        return self._conn

    @contextmanager
    def transaction(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager that commits on success, rolls back on error."""
        conn = self._get_conn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    # ── Query helpers ──────────────────────────────────────────────────────

    def execute(
        self, sql: str, params: tuple[Any, ...] = ()
    ) -> sqlite3.Cursor:
        """Execute a single parameterised statement."""
        return self._get_conn().execute(sql, params)

    def executemany(
        self, sql: str, param_list: list[tuple[Any, ...]]
    ) -> sqlite3.Cursor:
        return self._get_conn().executemany(sql, param_list)

    def fetchall(
        self, sql: str, params: tuple[Any, ...] = ()
    ) -> list[sqlite3.Row]:
        return self.execute(sql, params).fetchall()

    def fetchone(
        self, sql: str, params: tuple[Any, ...] = ()
    ) -> Optional[sqlite3.Row]:
        return self.execute(sql, params).fetchone()

    def insert(self, sql: str, params: tuple[Any, ...] = ()) -> int:
        """Execute INSERT and return lastrowid."""
        with self.transaction() as conn:
            cur = conn.execute(sql, params)
            return cur.lastrowid or 0

    def update(self, sql: str, params: tuple[Any, ...] = ()) -> int:
        """Execute UPDATE/DELETE and return rowcount."""
        with self.transaction() as conn:
            cur = conn.execute(sql, params)
            return cur.rowcount

    def commit(self) -> None:
        self._get_conn().commit()
