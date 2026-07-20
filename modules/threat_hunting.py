"""
modules/threat_hunting.py – Proactive threat hunting with saved hunt queries,
pattern detection, and statistical anomaly surfacing.
"""

from __future__ import annotations

import logging
from typing import Optional

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QSplitter,
    QLabel, QPushButton, QLineEdit, QTextEdit,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QWidget, QComboBox, QListWidget, QListWidgetItem,
    QMessageBox, QFrame, QTabWidget,
)

from modules.base_module import BaseModule

log = logging.getLogger(__name__)

_BUILTIN_HUNTS = [
    {
        "name": "Brute Force Login Attempts",
        "description": "Find repeated failed logon events from same source IP",
        "sql": """SELECT source_ip, COUNT(*) as attempts, MAX(timestamp) as last_seen
                  FROM log_events
                  WHERE (message LIKE '%failed%' OR message LIKE '%invalid%'
                         OR message LIKE '%authentication failure%'
                         OR event_id IN ('4625','529','530','531','532','533','534','535','539'))
                  {case_filter}
                  GROUP BY source_ip HAVING attempts >= 5
                  ORDER BY attempts DESC LIMIT 100""",
        "columns": ["Source IP", "Attempts", "Last Seen"],
    },
    {
        "name": "New Admin Account Creation",
        "description": "Detect new user account creations (Event 4720)",
        "sql": """SELECT timestamp, source_host, user, message
                  FROM log_events
                  WHERE event_id IN ('4720','4722','4728','4732','4756')
                  {case_filter}
                  ORDER BY timestamp DESC LIMIT 200""",
        "columns": ["Timestamp", "Host", "User", "Message"],
    },
    {
        "name": "Suspicious PowerShell",
        "description": "PowerShell with encoded commands or download cradles",
        "sql": """SELECT timestamp, source_host, user, process, message
                  FROM log_events
                  WHERE (message LIKE '%powershell%' OR process LIKE '%powershell%')
                    AND (message LIKE '%encodedcommand%'
                         OR message LIKE '%-enc %'
                         OR message LIKE '%DownloadString%'
                         OR message LIKE '%IEX%'
                         OR message LIKE '%Invoke-Expression%'
                         OR message LIKE '%bypass%')
                  {case_filter}
                  ORDER BY timestamp DESC LIMIT 200""",
        "columns": ["Timestamp", "Host", "User", "Process", "Message"],
    },
    {
        "name": "Lateral Movement via SMB / RDP",
        "description": "Network logons and RDP sessions indicating lateral movement",
        "sql": """SELECT timestamp, source_host, source_ip, user, message
                  FROM log_events
                  WHERE event_id IN ('4624','4648','4776')
                    AND (message LIKE '%logon type 3%'
                         OR message LIKE '%logon type 10%'
                         OR message LIKE '%network logon%'
                         OR message LIKE '%remote interactive%')
                  {case_filter}
                  ORDER BY timestamp DESC LIMIT 200""",
        "columns": ["Timestamp", "Host", "Source IP", "User", "Message"],
    },
    {
        "name": "Scheduled Task Creation",
        "description": "New scheduled tasks created (T1053)",
        "sql": """SELECT timestamp, source_host, user, message
                  FROM log_events
                  WHERE event_id IN ('4698','4702') OR
                        (message LIKE '%schtasks%' AND message LIKE '%create%') OR
                        (message LIKE '%at.exe%')
                  {case_filter}
                  ORDER BY timestamp DESC LIMIT 200""",
        "columns": ["Timestamp", "Host", "User", "Message"],
    },
    {
        "name": "Process Injection Indicators",
        "description": "Detect process injection via CreateRemoteThread / WriteProcessMemory",
        "sql": """SELECT timestamp, source_host, process, user, message
                  FROM log_events
                  WHERE message LIKE '%CreateRemoteThread%'
                     OR message LIKE '%WriteProcessMemory%'
                     OR message LIKE '%VirtualAllocEx%'
                     OR message LIKE '%NtCreateThread%'
                     OR event_id IN ('8','10')
                  {case_filter}
                  ORDER BY timestamp DESC LIMIT 200""",
        "columns": ["Timestamp", "Host", "Process", "User", "Message"],
    },
    {
        "name": "Data Exfiltration via DNS",
        "description": "Unusually long DNS queries suggesting DNS tunneling",
        "sql": """SELECT timestamp, source_ip, message
                  FROM log_events
                  WHERE source_type IN ('zeek','suricata','dns')
                    AND (LENGTH(message) > 200 OR message LIKE '%.txt.%' OR message LIKE '%.base64.%')
                  {case_filter}
                  ORDER BY timestamp DESC LIMIT 200""",
        "columns": ["Timestamp", "Source IP", "Message"],
    },
    {
        "name": "Honeypot Activity (Cowrie)",
        "description": "All Cowrie honeypot interactions",
        "sql": """SELECT timestamp, source_ip, user, message
                  FROM log_events
                  WHERE source_type='cowrie'
                  {case_filter}
                  ORDER BY timestamp DESC LIMIT 500""",
        "columns": ["Timestamp", "Source IP", "User", "Message"],
    },
    {
        "name": "Web Scanning / 404 Storms",
        "description": "HTTP 404 responses indicating directory brute-force",
        "sql": """SELECT source_ip, COUNT(*) as hits, MAX(timestamp) as last_seen
                  FROM log_events
                  WHERE source_type IN ('apache','nginx') AND event_id='404'
                  {case_filter}
                  GROUP BY source_ip HAVING hits >= 10
                  ORDER BY hits DESC LIMIT 100""",
        "columns": ["Source IP", "Hits", "Last Seen"],
    },
    {
        "name": "Credential Dumping (LSASS)",
        "description": "Access to LSASS process memory (T1003)",
        "sql": """SELECT timestamp, source_host, process, user, message
                  FROM log_events
                  WHERE (message LIKE '%lsass%' AND (message LIKE '%access%' OR message LIKE '%dump%'))
                     OR event_id IN ('10') AND message LIKE '%lsass%'
                  {case_filter}
                  ORDER BY timestamp DESC LIMIT 200""",
        "columns": ["Timestamp", "Host", "Process", "User", "Message"],
    },
]


class HuntThread(QThread):
    finished = Signal(list)
    error = Signal(str)

    def __init__(self, db, sql: str) -> None:
        super().__init__()
        self._db = db
        self._sql = sql

    def run(self) -> None:
        try:
            rows = self._db.fetchall(self._sql)
            self.finished.emit([dict(r) for r in rows])
        except Exception as exc:
            self.error.emit(str(exc))


class ThreatHuntingModule(BaseModule):
    """Proactive threat hunting with built-in and custom hunt queries."""

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(self._make_page_header(
            "Threat Hunting",
            "Proactive detection using built-in hunt queries and custom SQL"
        ))

        tabs = QTabWidget()
        layout.addWidget(tabs, 1)

        # ── Tab 1: Built-in hunts ─────────────────────────────────────────
        hunt_tab = QWidget()
        hunt_layout = QHBoxLayout(hunt_tab)
        hunt_layout.setContentsMargins(0, 0, 0, 0)

        # Hunt list (left)
        hunt_list_panel = QWidget()
        hunt_list_panel.setFixedWidth(280)
        hunt_list_panel.setStyleSheet("background-color: #161B22; border-right: 1px solid #30363D;")
        hlp_layout = QVBoxLayout(hunt_list_panel)
        hlp_layout.setContentsMargins(10, 10, 10, 10)
        hlp_layout.setSpacing(6)

        hunt_lbl = QLabel("Hunt Queries")
        hunt_lbl.setObjectName("SectionTitle")
        hlp_layout.addWidget(hunt_lbl)

        self._hunt_list = QListWidget()
        for hunt in _BUILTIN_HUNTS:
            item = QListWidgetItem(hunt["name"])
            item.setToolTip(hunt["description"])
            self._hunt_list.addItem(item)
        self._hunt_list.currentRowChanged.connect(self._on_hunt_selected)
        hlp_layout.addWidget(self._hunt_list)

        run_btn = self._primary_btn("▶ Run Hunt")
        run_btn.clicked.connect(self._run_selected_hunt)
        hlp_layout.addWidget(run_btn)
        hunt_layout.addWidget(hunt_list_panel)

        # Results (right)
        result_panel = QWidget()
        rp_layout = QVBoxLayout(result_panel)
        rp_layout.setContentsMargins(12, 12, 12, 12)
        rp_layout.setSpacing(8)

        self._hunt_title_lbl = QLabel("Select a hunt query from the list")
        self._hunt_title_lbl.setStyleSheet("font-size: 15px; font-weight: 700; color: #C9D1D9;")
        rp_layout.addWidget(self._hunt_title_lbl)

        self._hunt_desc_lbl = QLabel("")
        self._hunt_desc_lbl.setObjectName("Muted")
        self._hunt_desc_lbl.setWordWrap(True)
        rp_layout.addWidget(self._hunt_desc_lbl)

        self._hunt_status = QLabel("")
        self._hunt_status.setObjectName("AccentLabel")
        rp_layout.addWidget(self._hunt_status)

        self._hunt_table = QTableWidget(0, 5)
        self._hunt_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._hunt_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._hunt_table.setAlternatingRowColors(True)
        self._hunt_table.verticalHeader().setVisible(False)
        self._hunt_table.horizontalHeader().setStretchLastSection(True)
        rp_layout.addWidget(self._hunt_table)

        export_hunt_btn = QPushButton("⬇ Export Results")
        export_hunt_btn.clicked.connect(self._export_hunt)
        rp_layout.addWidget(export_hunt_btn)
        hunt_layout.addWidget(result_panel, 1)
        tabs.addTab(hunt_tab, "Built-in Hunts")

        # ── Tab 2: Custom SQL hunt ─────────────────────────────────────────
        custom_tab = QWidget()
        cl = QVBoxLayout(custom_tab)
        cl.setContentsMargins(16, 16, 16, 16)
        cl.setSpacing(10)

        cl.addWidget(QLabel("Custom Hunt Query (SQL):"))
        self._custom_sql = QTextEdit()
        self._custom_sql.setPlaceholderText(
            "SELECT timestamp, source_ip, user, message FROM log_events\n"
            "WHERE message LIKE '%mimikatz%'\nORDER BY timestamp DESC LIMIT 500"
        )
        self._custom_sql.setStyleSheet(
            "font-family: 'Cascadia Code','JetBrains Mono',monospace; font-size: 12px;"
        )
        self._custom_sql.setMaximumHeight(160)
        cl.addWidget(self._custom_sql)

        run_custom_btn = self._primary_btn("▶ Run Query")
        run_custom_btn.clicked.connect(self._run_custom_hunt)
        cl.addWidget(run_custom_btn)

        self._custom_status = QLabel("")
        self._custom_status.setObjectName("Muted")
        cl.addWidget(self._custom_status)

        self._custom_table = QTableWidget(0, 5)
        self._custom_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._custom_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._custom_table.setAlternatingRowColors(True)
        self._custom_table.verticalHeader().setVisible(False)
        self._custom_table.horizontalHeader().setStretchLastSection(True)
        cl.addWidget(self._custom_table, 1)
        tabs.addTab(custom_tab, "Custom SQL Hunt")

        self._current_hunt: Optional[dict] = None
        self._hunt_results: list[dict] = []
        self._hunt_thread: Optional[HuntThread] = None

    # ── Hunt execution ─────────────────────────────────────────────────────

    def _on_hunt_selected(self, row: int) -> None:
        if 0 <= row < len(_BUILTIN_HUNTS):
            hunt = _BUILTIN_HUNTS[row]
            self._current_hunt = hunt
            self._hunt_title_lbl.setText(hunt["name"])
            self._hunt_desc_lbl.setText(hunt["description"])

    def _run_selected_hunt(self) -> None:
        if not self._current_hunt:
            return
        hunt = self._current_hunt
        case_filter = f"AND case_id={self._active_case_id}" if self._active_case_id else ""
        sql = hunt["sql"].format(case_filter=case_filter)
        self._hunt_status.setText("Running…")
        self._hunt_thread = HuntThread(self._db, sql)
        self._hunt_thread.finished.connect(
            lambda rows: self._on_hunt_done(rows, hunt["columns"])
        )
        self._hunt_thread.error.connect(
            lambda e: self._hunt_status.setText(f"Error: {e}")
        )
        self._hunt_thread.start()

    def _on_hunt_done(self, rows: list[dict], columns: list[str]) -> None:
        self._hunt_results = rows
        self._hunt_status.setText(f"✓ {len(rows)} results")
        self._hunt_table.setColumnCount(len(columns))
        self._hunt_table.setHorizontalHeaderLabels(columns)
        self._hunt_table.setRowCount(0)
        for row in rows:
            r = self._hunt_table.rowCount()
            self._hunt_table.insertRow(r)
            for c, val in enumerate(row.values()):
                self._hunt_table.setItem(r, c, QTableWidgetItem(str(val)))
        self._audit.record("threat_hunt", f"Hunt: {self._current_hunt['name']} → {len(rows)} hits")

    def _run_custom_hunt(self) -> None:
        sql = self._custom_sql.toPlainText().strip()
        if not sql:
            return
        self._custom_status.setText("Running…")
        self._hunt_thread = HuntThread(self._db, sql)
        self._hunt_thread.finished.connect(self._on_custom_done)
        self._hunt_thread.error.connect(
            lambda e: self._custom_status.setText(f"Error: {e}")
        )
        self._hunt_thread.start()

    def _on_custom_done(self, rows: list[dict]) -> None:
        self._custom_status.setText(f"✓ {len(rows)} results")
        if not rows:
            self._custom_table.setRowCount(0)
            return
        cols = list(rows[0].keys())
        self._custom_table.setColumnCount(len(cols))
        self._custom_table.setHorizontalHeaderLabels(cols)
        self._custom_table.setRowCount(0)
        for row in rows:
            r = self._custom_table.rowCount()
            self._custom_table.insertRow(r)
            for c, val in enumerate(row.values()):
                self._custom_table.setItem(r, c, QTableWidgetItem(str(val)))

    def _export_hunt(self) -> None:
        if not self._hunt_results:
            return
        from PySide6.QtWidgets import QFileDialog
        import csv
        path, _ = QFileDialog.getSaveFileName(self, "Export", "hunt_results.csv", "CSV (*.csv)")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            if self._hunt_results:
                writer = csv.DictWriter(f, fieldnames=list(self._hunt_results[0].keys()))
                writer.writeheader()
                writer.writerows(self._hunt_results)
