"""
core/mitre.py – MITRE ATT&CK technique lookup and mapping.

Embeds a compact technique registry.  For a production deployment the
full ATT&CK STIX bundle can be loaded from disk or fetched via the
MITRE ATT&CK API.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from core.database import Database

log = logging.getLogger(__name__)

# ── Compact built-in technique table ──────────────────────────────────────
_BUILTIN_TECHNIQUES: list[dict] = [
    {"id": "T1059", "name": "Command and Scripting Interpreter",
     "tactic": "Execution", "platform": "Windows,Linux,macOS",
     "url": "https://attack.mitre.org/techniques/T1059/"},
    {"id": "T1059.001", "name": "PowerShell",
     "tactic": "Execution", "platform": "Windows",
     "url": "https://attack.mitre.org/techniques/T1059/001/"},
    {"id": "T1059.003", "name": "Windows Command Shell",
     "tactic": "Execution", "platform": "Windows",
     "url": "https://attack.mitre.org/techniques/T1059/003/"},
    {"id": "T1059.004", "name": "Unix Shell",
     "tactic": "Execution", "platform": "Linux,macOS",
     "url": "https://attack.mitre.org/techniques/T1059/004/"},
    {"id": "T1078", "name": "Valid Accounts",
     "tactic": "Defense Evasion,Persistence,Privilege Escalation,Initial Access",
     "platform": "Windows,Linux,macOS,Cloud",
     "url": "https://attack.mitre.org/techniques/T1078/"},
    {"id": "T1110", "name": "Brute Force",
     "tactic": "Credential Access", "platform": "Windows,Linux,macOS,Cloud",
     "url": "https://attack.mitre.org/techniques/T1110/"},
    {"id": "T1110.001", "name": "Password Guessing",
     "tactic": "Credential Access", "platform": "Windows,Linux,macOS",
     "url": "https://attack.mitre.org/techniques/T1110/001/"},
    {"id": "T1021", "name": "Remote Services",
     "tactic": "Lateral Movement", "platform": "Windows,Linux,macOS",
     "url": "https://attack.mitre.org/techniques/T1021/"},
    {"id": "T1021.001", "name": "Remote Desktop Protocol",
     "tactic": "Lateral Movement", "platform": "Windows",
     "url": "https://attack.mitre.org/techniques/T1021/001/"},
    {"id": "T1021.004", "name": "SSH",
     "tactic": "Lateral Movement", "platform": "Linux,macOS",
     "url": "https://attack.mitre.org/techniques/T1021/004/"},
    {"id": "T1053", "name": "Scheduled Task/Job",
     "tactic": "Execution,Persistence,Privilege Escalation",
     "platform": "Windows,Linux,macOS",
     "url": "https://attack.mitre.org/techniques/T1053/"},
    {"id": "T1055", "name": "Process Injection",
     "tactic": "Defense Evasion,Privilege Escalation", "platform": "Windows,Linux",
     "url": "https://attack.mitre.org/techniques/T1055/"},
    {"id": "T1082", "name": "System Information Discovery",
     "tactic": "Discovery", "platform": "Windows,Linux,macOS",
     "url": "https://attack.mitre.org/techniques/T1082/"},
    {"id": "T1083", "name": "File and Directory Discovery",
     "tactic": "Discovery", "platform": "Windows,Linux,macOS",
     "url": "https://attack.mitre.org/techniques/T1083/"},
    {"id": "T1087", "name": "Account Discovery",
     "tactic": "Discovery", "platform": "Windows,Linux,macOS",
     "url": "https://attack.mitre.org/techniques/T1087/"},
    {"id": "T1040", "name": "Network Sniffing",
     "tactic": "Credential Access,Discovery", "platform": "Windows,Linux,macOS",
     "url": "https://attack.mitre.org/techniques/T1040/"},
    {"id": "T1041", "name": "Exfiltration Over C2 Channel",
     "tactic": "Exfiltration", "platform": "Windows,Linux,macOS",
     "url": "https://attack.mitre.org/techniques/T1041/"},
    {"id": "T1048", "name": "Exfiltration Over Alternative Protocol",
     "tactic": "Exfiltration", "platform": "Windows,Linux,macOS",
     "url": "https://attack.mitre.org/techniques/T1048/"},
    {"id": "T1071", "name": "Application Layer Protocol",
     "tactic": "Command and Control", "platform": "Windows,Linux,macOS",
     "url": "https://attack.mitre.org/techniques/T1071/"},
    {"id": "T1105", "name": "Ingress Tool Transfer",
     "tactic": "Command and Control", "platform": "Windows,Linux,macOS",
     "url": "https://attack.mitre.org/techniques/T1105/"},
    {"id": "T1486", "name": "Data Encrypted for Impact",
     "tactic": "Impact", "platform": "Windows,Linux,macOS",
     "url": "https://attack.mitre.org/techniques/T1486/"},
    {"id": "T1490", "name": "Inhibit System Recovery",
     "tactic": "Impact", "platform": "Windows,Linux",
     "url": "https://attack.mitre.org/techniques/T1490/"},
    {"id": "T1566", "name": "Phishing",
     "tactic": "Initial Access", "platform": "Windows,Linux,macOS",
     "url": "https://attack.mitre.org/techniques/T1566/"},
    {"id": "T1190", "name": "Exploit Public-Facing Application",
     "tactic": "Initial Access", "platform": "Windows,Linux,macOS",
     "url": "https://attack.mitre.org/techniques/T1190/"},
    {"id": "T1133", "name": "External Remote Services",
     "tactic": "Initial Access,Persistence", "platform": "Windows,Linux,macOS",
     "url": "https://attack.mitre.org/techniques/T1133/"},
    {"id": "T1562", "name": "Impair Defenses",
     "tactic": "Defense Evasion", "platform": "Windows,Linux,macOS",
     "url": "https://attack.mitre.org/techniques/T1562/"},
    {"id": "T1140", "name": "Deobfuscate/Decode Files or Information",
     "tactic": "Defense Evasion", "platform": "Windows,Linux,macOS",
     "url": "https://attack.mitre.org/techniques/T1140/"},
    {"id": "T1003", "name": "OS Credential Dumping",
     "tactic": "Credential Access", "platform": "Windows,Linux,macOS",
     "url": "https://attack.mitre.org/techniques/T1003/"},
    {"id": "T1027", "name": "Obfuscated Files or Information",
     "tactic": "Defense Evasion", "platform": "Windows,Linux,macOS",
     "url": "https://attack.mitre.org/techniques/T1027/"},
    {"id": "T1070", "name": "Indicator Removal",
     "tactic": "Defense Evasion", "platform": "Windows,Linux,macOS",
     "url": "https://attack.mitre.org/techniques/T1070/"},
]

_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]


class MITREAttack:
    """ATT&CK technique lookup, search, and event-text auto-mapping."""

    def __init__(self, db: "Database") -> None:
        self._db = db
        self._ensure_seeded()

    # ── Public API ─────────────────────────────────────────────────────────

    def get(self, technique_id: str) -> Optional[dict]:
        """Return a technique record by ID (e.g. 'T1059') or None."""
        row = self._db.fetchone(
            "SELECT * FROM mitre_techniques WHERE technique_id=?",
            (technique_id.upper(),),
        )
        return dict(row) if row else None

    def search(self, query: str) -> list[dict]:
        """Full-text search across technique ID, name, tactic, description."""
        q = f"%{query}%"
        rows = self._db.fetchall(
            """SELECT * FROM mitre_techniques
               WHERE technique_id LIKE ?
                  OR name LIKE ?
                  OR tactic LIKE ?
                  OR description LIKE ?
               ORDER BY technique_id LIMIT 100""",
            (q, q, q, q),
        )
        return [dict(r) for r in rows]

    def all_techniques(self) -> list[dict]:
        rows = self._db.fetchall(
            "SELECT * FROM mitre_techniques ORDER BY technique_id"
        )
        return [dict(r) for r in rows]

    def by_tactic(self, tactic: str) -> list[dict]:
        rows = self._db.fetchall(
            "SELECT * FROM mitre_techniques WHERE tactic LIKE ? ORDER BY technique_id",
            (f"%{tactic}%",),
        )
        return [dict(r) for r in rows]

    def all_tactics(self) -> list[str]:
        return _TACTICS

    def auto_map(self, text: str) -> list[dict]:
        """
        Scan free text for technique IDs (e.g. T1059) and return matches.
        """
        ids = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text, re.I)
        results = []
        seen: set[str] = set()
        for tid in ids:
            tid_upper = tid.upper()
            if tid_upper in seen:
                continue
            seen.add(tid_upper)
            t = self.get(tid_upper)
            if t:
                results.append(t)
        return results

    # ── Seeding ────────────────────────────────────────────────────────────

    def _ensure_seeded(self) -> None:
        count = self._db.fetchone("SELECT COUNT(*) AS c FROM mitre_techniques")
        if count and count["c"] > 0:
            return
        log.info("Seeding MITRE ATT&CK technique table …")
        for tech in _BUILTIN_TECHNIQUES:
            self._db.insert(
                """INSERT OR IGNORE INTO mitre_techniques
                   (technique_id, name, tactic, description, url, platform)
                   VALUES (?,?,?,?,?,?)""",
                (
                    tech["id"], tech["name"], tech.get("tactic", ""),
                    tech.get("description", ""), tech.get("url", ""),
                    tech.get("platform", ""),
                ),
            )
