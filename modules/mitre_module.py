"""
modules/mitre_module.py – MITRE ATT&CK technique browser, search, and case mapping.
"""

from __future__ import annotations

import logging
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QSplitter,
    QLabel, QPushButton, QLineEdit, QTextEdit,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QWidget, QComboBox, QListWidget, QListWidgetItem,
    QMessageBox,
)

from modules.base_module import BaseModule
from core.mitre import MITREAttack

log = logging.getLogger(__name__)

_TACTIC_COLORS = {
    "Reconnaissance":       "#8B949E",
    "Resource Development": "#8B949E",
    "Initial Access":       "#F85149",
    "Execution":            "#D29922",
    "Persistence":          "#A371F7",
    "Privilege Escalation": "#FF7B72",
    "Defense Evasion":      "#79C0FF",
    "Credential Access":    "#FFA657",
    "Discovery":            "#56D364",
    "Lateral Movement":     "#F78166",
    "Collection":           "#D2A8FF",
    "Command and Control":  "#58A6FF",
    "Exfiltration":         "#FF9500",
    "Impact":               "#F85149",
}


class MITREModule(BaseModule):
    """MITRE ATT&CK technique browser and case mapping tool."""

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(self._make_page_header(
            "MITRE ATT&CK",
            "Browse techniques, search by tactic, map to timeline entries"
        ))

        self._mitre = MITREAttack(self._db)

        # Toolbar
        self._search_edit = QLineEdit()
        self._search_edit.setPlaceholderText("Search techniques, IDs, tactics…")
        self._search_edit.setFixedWidth(320)
        self._search_edit.textChanged.connect(self._search)

        self._tactic_combo = QComboBox()
        self._tactic_combo.addItem("All Tactics")
        for t in self._mitre.all_tactics():
            self._tactic_combo.addItem(t)
        self._tactic_combo.currentTextChanged.connect(self._filter_by_tactic)

        map_btn = self._primary_btn("📌 Map to Timeline")
        map_btn.clicked.connect(self._map_to_timeline)

        layout.addWidget(self._make_toolbar(
            self._search_edit, self._tactic_combo, None, map_btn
        ))

        # Stats row
        stats_row = QWidget()
        stats_row.setStyleSheet("background-color: #0D1117;")
        sl = QHBoxLayout(stats_row)
        sl.setContentsMargins(14, 4, 14, 4)
        self._count_lbl = QLabel("")
        self._count_lbl.setObjectName("Muted")
        sl.addWidget(self._count_lbl)
        sl.addStretch()
        layout.addWidget(stats_row)

        # Main splitter
        splitter = QSplitter(Qt.Horizontal)

        # Technique table
        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["ID", "Name", "Tactic", "Platform"])
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.Stretch)
        self._table.selectionModel().selectionChanged.connect(self._on_selection)
        splitter.addWidget(self._table)

        # Detail panel
        detail = QWidget()
        detail.setFixedWidth(380)
        detail.setStyleSheet("background-color: #161B22; border-left: 1px solid #30363D;")
        dl = QVBoxLayout(detail)
        dl.setContentsMargins(14, 14, 14, 14)
        dl.setSpacing(10)

        self._detail_id = QLabel("")
        self._detail_id.setStyleSheet(
            "font-size: 22px; font-weight: 800; color: #58A6FF; background: transparent;"
        )
        dl.addWidget(self._detail_id)

        self._detail_name = QLabel("")
        self._detail_name.setWordWrap(True)
        self._detail_name.setStyleSheet(
            "font-size: 15px; font-weight: 700; color: #C9D1D9; background: transparent;"
        )
        dl.addWidget(self._detail_name)

        self._detail_tactic = QLabel("")
        self._detail_tactic.setObjectName("AccentLabel")
        self._detail_tactic.setStyleSheet("background: transparent; color: #79C0FF;")
        dl.addWidget(self._detail_tactic)

        self._detail_platform = QLabel("")
        self._detail_platform.setObjectName("Muted")
        self._detail_platform.setStyleSheet("background: transparent; color: #8B949E;")
        dl.addWidget(self._detail_platform)

        self._detail_desc = QTextEdit()
        self._detail_desc.setReadOnly(True)
        self._detail_desc.setStyleSheet("background-color: #0D1117; font-size: 12px;")
        dl.addWidget(self._detail_desc, 1)

        open_url_btn = QPushButton("🌐 Open on MITRE")
        open_url_btn.clicked.connect(self._open_url)
        dl.addWidget(open_url_btn)

        map_btn2 = self._primary_btn("📌 Map to Case Timeline")
        map_btn2.clicked.connect(self._map_to_timeline)
        dl.addWidget(map_btn2)

        # Timeline entries for this technique
        dl.addWidget(QLabel("Case Timeline Hits:"))
        self._timeline_list = QListWidget()
        self._timeline_list.setMaximumHeight(150)
        self._timeline_list.setStyleSheet("font-size: 11px;")
        dl.addWidget(self._timeline_list)

        splitter.addWidget(detail)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter, 1)

        self._current_technique: Optional[dict] = None
        self._all_techniques: list[dict] = []
        self._load_all()

    # ── Data ───────────────────────────────────────────────────────────────

    def _load_all(self) -> None:
        self._all_techniques = self._mitre.all_techniques()
        self._populate_table(self._all_techniques)

    def _populate_table(self, techniques: list[dict]) -> None:
        self._table.setRowCount(0)
        self._count_lbl.setText(f"{len(techniques)} techniques")
        for tech in techniques:
            r = self._table.rowCount()
            self._table.insertRow(r)
            tactic = tech.get("tactic", "").split(",")[0].strip()
            color = _TACTIC_COLORS.get(tactic, "#C9D1D9")
            for c, val in enumerate([
                tech.get("technique_id", ""),
                tech.get("name", ""),
                tactic,
                tech.get("platform", ""),
            ]):
                item = QTableWidgetItem(str(val))
                if c == 2:
                    item.setForeground(QColor(color))
                self._table.setItem(r, c, item)

    def _search(self, query: str) -> None:
        if not query.strip():
            self._populate_table(self._all_techniques)
            return
        results = self._mitre.search(query)
        self._populate_table(results)

    def _filter_by_tactic(self, tactic: str) -> None:
        if tactic == "All Tactics":
            self._populate_table(self._all_techniques)
            return
        results = self._mitre.by_tactic(tactic)
        self._populate_table(results)

    def _on_selection(self) -> None:
        row = self._table.currentRow()
        id_item = self._table.item(row, 0)
        if not id_item:
            return
        tech = self._mitre.get(id_item.text())
        if not tech:
            return
        self._current_technique = tech
        self._detail_id.setText(tech.get("technique_id", ""))
        self._detail_name.setText(tech.get("name", ""))
        self._detail_tactic.setText(tech.get("tactic", ""))
        self._detail_platform.setText(f"Platforms: {tech.get('platform', '')}")
        self._detail_desc.setPlainText(
            tech.get("description", "") or "No description available in local cache.\nClick 'Open on MITRE' for full details."
        )
        self._load_timeline_hits(tech.get("technique_id", ""))

    def _load_timeline_hits(self, tech_id: str) -> None:
        self._timeline_list.clear()
        if not self._active_case_id or not tech_id:
            return
        rows = self._db.fetchall(
            """SELECT timestamp, description FROM timeline_entries
               WHERE case_id=? AND mitre_tech LIKE ?
               ORDER BY timestamp""",
            (self._active_case_id, f"%{tech_id}%"),
        )
        for row in rows:
            self._timeline_list.addItem(
                f"{row['timestamp'][:16]}  {row['description'][:60]}"
            )

    # ── Actions ────────────────────────────────────────────────────────────

    def _open_url(self) -> None:
        if not self._current_technique:
            return
        url = self._current_technique.get("url", "")
        if url:
            import webbrowser
            webbrowser.open(url)

    def _map_to_timeline(self) -> None:
        if not self._current_technique:
            QMessageBox.information(self, "Map", "Select a technique first.")
            return
        if not self._active_case_id:
            QMessageBox.warning(self, "No Case", "Activate a case first.")
            return
        tech = self._current_technique
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        self._db.insert(
            """INSERT INTO timeline_entries
               (case_id, timestamp, event_type, description,
                mitre_tactic, mitre_tech, severity)
               VALUES (?,?,?,?,?,?,?)""",
            (
                self._active_case_id, now,
                tech.get("tactic", "").split(",")[0].strip(),
                f"ATT&CK technique mapped: {tech['name']}",
                tech.get("tactic", "").split(",")[0].strip(),
                tech.get("technique_id", ""),
                "medium",
            ),
        )
        self._audit.record(
            "mitre_map",
            f"Mapped {tech['technique_id']} to case #{self._active_case_id}",
        )
        QMessageBox.information(
            self, "Mapped",
            f"{tech['technique_id']} – {tech['name']} added to case timeline."
        )
        self._load_timeline_hits(tech.get("technique_id", ""))

    def _on_case_changed(self, case_id) -> None:
        if self._current_technique:
            self._load_timeline_hits(self._current_technique.get("technique_id", ""))
