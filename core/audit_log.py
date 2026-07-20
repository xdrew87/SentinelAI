"""
core/audit_log.py – Immutable audit trail for all analyst actions.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.database import Database

log = logging.getLogger(__name__)


class AuditLog:
    """Write-only audit trail persisted to SQLite."""

    def __init__(self, db: "Database") -> None:
        self._db = db

    def record(
        self,
        action: str,
        detail: str = "",
        user: str = "analyst",
        ip: str = "",
    ) -> None:
        """Persist a single audit entry."""
        try:
            self._db.insert(
                """INSERT INTO audit_log (action, detail, user, ip, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (action, detail, user, ip, datetime.now(timezone.utc).isoformat()),
            )
        except Exception as exc:
            log.error("AuditLog.record failed: %s", exc)

    def recent(self, limit: int = 500) -> list:
        """Return most recent audit entries."""
        return self._db.fetchall(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        )
