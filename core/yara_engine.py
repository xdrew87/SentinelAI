"""
core/yara_engine.py – YARA rule compilation and scanning.
"""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from core.database import Database

log = logging.getLogger(__name__)


class YARAEngine:
    """Compile and apply YARA rules against files or byte buffers."""

    def __init__(self, db: "Database") -> None:
        self._db = db
        self._compiled = None  # compiled yara.Rules cache

    # ── Public API ─────────────────────────────────────────────────────────

    def scan_file(self, path: Path) -> list[dict]:
        """Scan a file with all enabled rules. Returns list of matches."""
        rules = self._get_compiled_rules()
        if rules is None:
            return []
        try:
            matches = rules.match(str(path))
            return [self._match_to_dict(m) for m in matches]
        except Exception as exc:
            log.error("YARA scan error on %s: %s", path, exc)
            return []

    def scan_bytes(self, data: bytes, identifier: str = "<buffer>") -> list[dict]:
        """Scan a byte buffer with all enabled rules."""
        rules = self._get_compiled_rules()
        if rules is None:
            return []
        try:
            matches = rules.match(data=data)
            return [self._match_to_dict(m) for m in matches]
        except Exception as exc:
            log.error("YARA scan error on %s: %s", identifier, exc)
            return []

    def compile_rule(self, rule_text: str) -> tuple[bool, str]:
        """
        Attempt to compile a single YARA rule text.
        Returns (success, error_message).
        """
        try:
            import yara
            yara.compile(source=rule_text)
            self._compiled = None  # invalidate cache
            return True, ""
        except Exception as exc:
            return False, str(exc)

    def reload(self) -> None:
        """Force re-compilation of all rules from DB."""
        self._compiled = None

    # ── Internal ──────────────────────────────────────────────────────────

    def _get_compiled_rules(self):
        if self._compiled is not None:
            return self._compiled
        try:
            import yara
        except ImportError:
            log.error("yara-python not installed; YARA scanning unavailable.")
            return None
        rows = self._db.fetchall(
            "SELECT name, rule_text FROM yara_rules WHERE enabled=1"
        )
        if not rows:
            return None
        sources: dict[str, str] = {}
        for row in rows:
            sources[row["name"]] = row["rule_text"]
        try:
            self._compiled = yara.compile(sources=sources)
        except Exception as exc:
            log.error("YARA compile error: %s", exc)
            return None
        return self._compiled

    @staticmethod
    def _match_to_dict(match) -> dict:
        return {
            "rule": match.rule,
            "tags": list(match.tags),
            "meta": dict(match.meta),
            "strings": [
                {"identifier": s.identifier, "offset": s.instances[0].offset
                  if s.instances else 0}
                for s in match.strings
            ],
        }
