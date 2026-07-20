"""
modules/timeline.py – Chronological event timeline builder and viewer.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QSplitter,
    QLabel, QPushButton, QLineEdit, QTextEdit,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QWidget, QComboBox, QDialog, QFormLayout,
    QDialogButtonBox, QMessageBox,
)

from modules.base_module import BaseModule

log = logging.getLogger(__name__)

_EVENT_TYPES = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command & Control", "Exfiltration", "Impact",
    "Reconnaissance", "Network", "Authentication", "File Activity",
    "Process Activity", "Registry", "Scheduled Task", "Other",
]

_SEVERITIES = ["critical", "high", "medium", "low", "info"]


class TimelineEntryDialog(QDialog):
    def __init__(self, parent=None, entry: Optional[dict] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Edit Entry" if entry else "Add Timeline Entry")
        self.setMinimumWidth(520)
        self._entry = entry
        self._build_ui()
        if entry:
            self._populate(entry)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        form = QFormLayout()
        form.setSpacing(10)

        self._ts_edit = QLineEdit()
        self._ts_edit.setPlaceholderText("YYYY-MM-DDTHH:MM:SS")
        form.addRow("Timestamp *", self._ts_edit)

        self._type_combo = QComboBox()
        self._type_combo.addItems(_EVENT_TYPES)
        form.addRow("Event Type", self._type_combo)

        self._desc_edit = QTextEdit()
        self._desc_edit.setFixedHeight(80)
        self._desc_edit.setPlaceholderText("What happened…")
        form.addRow("Description *", self._desc_edit)

        self._source_edit = QLineEdit()
        self._source_edit.setPlaceholderText("evtx / suricata / analyst")
        form.addRow("Source", self._source_edit)

        self._actor_edit = QLineEdit()
        self._actor_edit.setPlaceholderText("username / process / IP")
        form.addRow("Actor", self._actor_edit)

        self._target_edit = QLineEdit()
        self._target_edit.setPlaceholderText("hostname / file path / URL")
        form.addRow("Target", self._target_edit)

        self._mitre_tactic = QLineEdit()
        self._mitre_tactic.setPlaceholderText("Initial Access")
        form.addRow("MITRE Tactic", self._mitre_tactic)

        self._mitre_tech = QLineEdit()
        self._mitre_tech.setPlaceholderText("T1566.001")
        form.addRow("MITRE Technique", self._mitre_tech)

        self._sev_combo = QComboBox()
        self._sev_combo.addItems([s.capitalize() for s in _SEVERITIES])
        self._sev_combo.setCurrentText("Medium")
        form.addRow("Severity", self._sev_combo)

        layout.addLayout(form)
        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.button(QDialogButtonBox.Ok).setObjectName("PrimaryButton")
        btns.button(QDialogButtonBox.Ok).setText("Save Entry")
        btns.accepted.connect(self._validate)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

    def _populate(self, e: dict) -> None:
        self._ts_edit.setText(e.get("timestamp", ""))
        idx = self._type_combo.findText(e.get("event_type", ""))
        if idx >= 0:
            self._type_combo.setCurrentIndex(idx)
        self._desc_edit.setPlainText(e.get("description", ""))
        self._source_edit.setText(e.get("source", ""))
        self._actor_edit.setText(e.get("actor", ""))
        self._target_edit.setText(e.get("target", ""))
        self._mitre_tactic.setText(e.get("mitre_tactic", ""))
        self._mitre_tech.setText(e.get("mitre_tech", ""))
        si = self._sev_combo.findText(e.get("severity", "medium").capitalize())
        if si >= 0:
            self._sev_combo.setCurrentIndex(si)

    def _validate(self) -> None:
        if not self._ts_edit.text().strip():
            QMessageBox.warning(self, "Validation", "Timestamp is required.")
            return
        if not self._desc_edit.toPlainText().strip():
            QMessageBox.warning(self, "Validation", "Description is required.")
            return
        self.accept()

    def get_data(self) -> dict:
        return {
            "timestamp":    self._ts_edit.text().strip(),
            "event_type":   self._type_combo.currentText(),
            "description":  self._desc_edit.toPlainText().strip(),
            "source":       self._source_edit.text().strip(),
            "actor":        self._actor_edit.text().strip(),
            "target":       self._target_edit.text().strip(),
            "mitre_tactic": self._mitre_tactic.text().strip(),
            "mitre_tech":   self._mitre_tech.text().strip(),
            "severity":     self._sev_combo.currentText().lower(),
        }


class TimelineModule(BaseModule):
    """Chronological timeline of investigation events."""

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(self._make_page_header(
            "Timeline",
            "Build and visualise a chronological event sequence for the investigation"
        ))

        # Toolbar
        self._filter_edit = QLineEdit()
        self._filter_edit.setPlaceholderText("Filter timeline…")
        self._filter_edit.setFixedWidth(260)
        self._filter_edit.textChanged.connect(self._filter)

        self._sev_filter = QComboBox()
        self._sev_filter.addItems(["All Severities"] + [s.capitalize() for s in _SEVERITIES])
        self._sev_filter.currentTextChanged.connect(self._filter)

        add_btn = self._primary_btn("＋ Add Entry")
        add_btn.clicked.connect(self._add_entry)

        export_btn = QPushButton("⬇ Export")
        export_btn.clicked.connect(self._export)

        layout.addWidget(self._make_toolbar(
            self._filter_edit, self._sev_filter, None, export_btn, add_btn
        ))

        # Stats row
        stats = QWidget()
        stats.setStyleSheet("background-color: #0D1117;")
        sl = QHBoxLayout(stats)
        sl.setContentsMargins(14, 6, 14, 6)
        self._count_label = QLabel("0 entries")
        self._count_label.setObjectName("Muted")
        self._span_label = QLabel("")
        self._span_label.setObjectName("Muted")
        sl.addWidget(self._count_label)
        sl.addWidget(self._span_label)
        sl.addStretch()
        layout.addWidget(stats)

        # Main splitter
        splitter = QSplitter(Qt.Vertical)

        # Timeline table
        self._table = QTableWidget(0, 9)
        self._table.setHorizontalHeaderLabels([
            "Timestamp", "Event Type", "Description", "Actor",
            "Target", "MITRE Tactic", "MITRE Tech", "Severity", "Source",
        ])
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.Stretch)
        self._table.selectionModel().selectionChanged.connect(self._on_selection)
        splitter.addWidget(self._table)

        # Detail pane
        detail_pane = QWidget()
        dpl = QVBoxLayout(detail_pane)
        dpl.setContentsMargins(12, 8, 12, 8)
        dpl.setSpacing(6)

        hdr2 = QHBoxLayout()
        hdr2.addWidget(QLabel("Entry Detail"))
        hdr2.addStretch()
        edit_btn = QPushButton("✎ Edit")
        edit_btn.clicked.connect(self._edit_selected)
        del_btn = self._danger_btn("🗑 Delete")
        del_btn.clicked.connect(self._delete_selected)
        hdr2.addWidget(edit_btn)
        hdr2.addWidget(del_btn)
        dpl.addLayout(hdr2)

        self._detail_text = QTextEdit()
        self._detail_text.setReadOnly(True)
        self._detail_text.setStyleSheet("background-color: #0D1117; font-size: 12px;")
        dpl.addWidget(self._detail_text)
        splitter.addWidget(detail_pane)
        splitter.setSizes([600, 180])
        layout.addWidget(splitter, 1)

        self._entries: list[dict] = []
        self._selected: Optional[dict] = None
        self._load()

    # ── Data ───────────────────────────────────────────────────────────────

    def _load(self) -> None:
        if self._active_case_id:
            rows = self._db.fetchall(
                "SELECT * FROM timeline_entries WHERE case_id=? ORDER BY timestamp, id",
                (self._active_case_id,),
            )
        else:
            rows = []
        self._entries = [dict(r) for r in rows]
        self._populate_table(self._entries)

    def _populate_table(self, entries: list[dict]) -> None:
        sev_colors = {
            "critical": "#F85149", "high": "#D29922",
            "medium": "#58A6FF", "low": "#3FB950", "info": "#8B949E",
        }
        from PySide6.QtGui import QColor
        self._table.setRowCount(0)
        for e in entries:
            r = self._table.rowCount()
            self._table.insertRow(r)
            vals = [
                e.get("timestamp", "")[:19], e.get("event_type", ""),
                e.get("description", "")[:100], e.get("actor", ""),
                e.get("target", ""), e.get("mitre_tactic", ""),
                e.get("mitre_tech", ""), e.get("severity", "").upper(),
                e.get("source", ""),
            ]
            for c, val in enumerate(vals):
                item = QTableWidgetItem(str(val))
                if c == 7:
                    item.setForeground(QColor(sev_colors.get(e.get("severity", ""), "#C9D1D9")))
                self._table.setItem(r, c, item)

        # Update stats
        self._count_label.setText(f"{len(entries)} entries")
        if len(entries) >= 2:
            start = entries[0].get("timestamp", "")[:19]
            end = entries[-1].get("timestamp", "")[:19]
            self._span_label.setText(f"Span: {start}  →  {end}")

    def _filter(self) -> None:
        q = self._filter_edit.text().lower()
        sev = self._sev_filter.currentText()
        filtered = []
        for e in self._entries:
            if q and q not in str(e).lower():
                continue
            if sev != "All Severities" and e.get("severity", "") != sev.lower():
                continue
            filtered.append(e)
        self._populate_table(filtered)

    def _on_selection(self) -> None:
        row = self._table.currentRow()
        if row < 0 or row >= len(self._entries):
            return
        e = self._entries[row]
        self._selected = e
        self._detail_text.setPlainText(
            f"Timestamp:    {e.get('timestamp','')}\n"
            f"Event Type:   {e.get('event_type','')}\n"
            f"Severity:     {e.get('severity','').upper()}\n"
            f"Source:       {e.get('source','')}\n"
            f"Actor:        {e.get('actor','')}\n"
            f"Target:       {e.get('target','')}\n"
            f"MITRE Tactic: {e.get('mitre_tactic','')}\n"
            f"MITRE Tech:   {e.get('mitre_tech','')}\n"
            f"\nDescription:\n{e.get('description','')}"
        )

    # ── CRUD ───────────────────────────────────────────────────────────────

    def _add_entry(self) -> None:
        if not self._active_case_id:
            QMessageBox.warning(self, "No Case", "Activate a case first.")
            return
        dlg = TimelineEntryDialog(self)
        if dlg.exec() != QDialog.Accepted:
            return
        data = dlg.get_data()
        self._db.insert(
            """INSERT INTO timeline_entries
               (case_id, timestamp, event_type, description, source,
                actor, target, mitre_tactic, mitre_tech, severity)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (self._active_case_id, data["timestamp"], data["event_type"],
             data["description"], data["source"], data["actor"], data["target"],
             data["mitre_tactic"], data["mitre_tech"], data["severity"]),
        )
        self._audit.record("timeline_add", f"Timeline entry added: {data['description'][:60]}")
        self._load()

    def _edit_selected(self) -> None:
        if not self._selected:
            return
        dlg = TimelineEntryDialog(self, entry=self._selected)
        if dlg.exec() != QDialog.Accepted:
            return
        data = dlg.get_data()
        self._db.update(
            """UPDATE timeline_entries SET timestamp=?, event_type=?, description=?,
               source=?, actor=?, target=?, mitre_tactic=?, mitre_tech=?, severity=?
               WHERE id=?""",
            (data["timestamp"], data["event_type"], data["description"],
             data["source"], data["actor"], data["target"], data["mitre_tactic"],
             data["mitre_tech"], data["severity"], self._selected["id"]),
        )
        self._load()

    def _delete_selected(self) -> None:
        if not self._selected:
            return
        reply = QMessageBox.question(
            self, "Delete Entry", "Delete this timeline entry?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        self._db.update("DELETE FROM timeline_entries WHERE id=?", (self._selected["id"],))
        self._selected = None
        self._load()

    def _export(self) -> None:
        from PySide6.QtWidgets import QFileDialog
        import csv
        path, _ = QFileDialog.getSaveFileName(self, "Export Timeline", "timeline.csv", "CSV (*.csv)")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            if self._entries:
                writer = csv.DictWriter(f, fieldnames=list(self._entries[0].keys()))
                writer.writeheader()
                writer.writerows(self._entries)
        QMessageBox.information(self, "Export", f"Exported {len(self._entries)} entries.")

    def _on_case_changed(self, case_id) -> None:
        self._load()
