"""
modules/ioc_investigation.py – IOC management and threat intelligence enrichment.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QSplitter,
    QLabel, QPushButton, QLineEdit, QTextEdit,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QWidget, QComboBox, QMessageBox, QDialog, QTabWidget,
)

from modules.base_module import BaseModule
from core.threat_intel import ThreatIntelEngine
from ui.dialogs.ioc_dialog import IOCDialog

log = logging.getLogger(__name__)


class EnrichThread(QThread):
    finished = Signal(dict)
    error = Signal(str)

    def __init__(self, engine: ThreatIntelEngine, ioc_type: str, value: str) -> None:
        super().__init__()
        self._engine = engine
        self._ioc_type = ioc_type
        self._value = value

    def run(self) -> None:
        try:
            result = self._engine.enrich_ioc(self._ioc_type, self._value)
            self.finished.emit(result)
        except Exception as exc:
            self.error.emit(str(exc))


class IOCInvestigationModule(BaseModule):
    """IOC management: add, search, bulk import, enrich via threat intel."""

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(self._make_page_header(
            "IOC Investigation",
            "Manage, investigate and enrich indicators of compromise"
        ))

        # Toolbar
        self._search_edit = QLineEdit()
        self._search_edit.setPlaceholderText("Search IOCs…")
        self._search_edit.setFixedWidth(260)
        self._search_edit.textChanged.connect(self._filter)

        self._type_filter = QComboBox()
        self._type_filter.addItems(["All Types", "ip", "domain", "url", "hash",
                                     "email", "filename", "registry", "other"])
        self._type_filter.currentTextChanged.connect(self._filter)

        add_btn = self._primary_btn("＋ Add IOC")
        add_btn.clicked.connect(self._add_ioc)

        import_btn = QPushButton("⬆ Bulk Import")
        import_btn.clicked.connect(self._bulk_import)

        enrich_btn = QPushButton("🌐 Enrich Selected")
        enrich_btn.clicked.connect(self._enrich_selected)

        layout.addWidget(self._make_toolbar(
            self._search_edit, self._type_filter, None,
            import_btn, enrich_btn, add_btn,
        ))

        # Splitter
        splitter = QSplitter(Qt.Horizontal)

        # IOC table
        self._table = QTableWidget(0, 7)
        self._table.setHorizontalHeaderLabels([
            "Type", "Value", "Confidence", "Threat Type", "Source", "Enriched", "Added"
        ])
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self._table.selectionModel().selectionChanged.connect(self._on_selection)
        splitter.addWidget(self._table)

        # Detail panel
        detail = QWidget()
        detail.setFixedWidth(380)
        detail.setStyleSheet("background-color: #161B22; border-left: 1px solid #30363D;")
        dl = QVBoxLayout(detail)
        dl.setContentsMargins(14, 14, 14, 14)
        dl.setSpacing(8)

        dl.addWidget(QLabel("IOC Details & Intelligence"))
        self._detail_text = QTextEdit()
        self._detail_text.setReadOnly(True)
        self._detail_text.setStyleSheet(
            "font-family: monospace; font-size: 12px; background-color: #0D1117;"
        )
        dl.addWidget(self._detail_text, 1)

        self._enrich_status = QLabel("")
        self._enrich_status.setObjectName("AccentLabel")
        dl.addWidget(self._enrich_status)

        enrich_btn2 = self._primary_btn("🌐 Enrich This IOC")
        enrich_btn2.clicked.connect(self._enrich_selected)
        edit_btn = QPushButton("✎ Edit IOC")
        edit_btn.clicked.connect(self._edit_selected)
        del_btn = self._danger_btn("🗑 Delete")
        del_btn.clicked.connect(self._delete_selected)
        dl.addWidget(enrich_btn2)
        dl.addWidget(edit_btn)
        dl.addWidget(del_btn)

        splitter.addWidget(detail)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter, 1)

        self._iocs: list[dict] = []
        self._selected: Optional[dict] = None
        self._enrich_thread: Optional[EnrichThread] = None
        self._intel = ThreatIntelEngine(self._config, self._db)
        self._load()

    # ── Data ───────────────────────────────────────────────────────────────

    def _load(self) -> None:
        if self._active_case_id:
            rows = self._db.fetchall(
                "SELECT * FROM iocs WHERE case_id=? ORDER BY created_at DESC",
                (self._active_case_id,),
            )
        else:
            rows = self._db.fetchall("SELECT * FROM iocs ORDER BY created_at DESC LIMIT 500")
        self._iocs = [dict(r) for r in rows]
        self._populate_table(self._iocs)

    def _populate_table(self, items: list[dict]) -> None:
        conf_colors = {"high": "#F85149", "medium": "#D29922", "low": "#3FB950"}
        from PySide6.QtGui import QColor
        self._table.setRowCount(0)
        for ioc in items:
            r = self._table.rowCount()
            self._table.insertRow(r)
            for c, val in enumerate([
                ioc.get("ioc_type", ""), ioc.get("value", ""),
                ioc.get("confidence", ""), ioc.get("threat_type", ""),
                ioc.get("source", ""),
                "Yes" if ioc.get("enriched") else "No",
                ioc.get("created_at", "")[:16],
            ]):
                item = QTableWidgetItem(str(val))
                if c == 2:
                    item.setForeground(QColor(conf_colors.get(ioc.get("confidence", ""), "#C9D1D9")))
                self._table.setItem(r, c, item)

    def _filter(self) -> None:
        q = self._search_edit.text().lower()
        type_f = self._type_filter.currentText()
        filtered = []
        for ioc in self._iocs:
            if q and q not in ioc.get("value", "").lower():
                continue
            if type_f != "All Types" and ioc.get("ioc_type") != type_f:
                continue
            filtered.append(ioc)
        self._populate_table(filtered)

    def _on_selection(self) -> None:
        row = self._table.currentRow()
        if row < 0:
            return
        val_item = self._table.item(row, 1)
        if not val_item:
            return
        ioc = next((i for i in self._iocs if i.get("value") == val_item.text()), None)
        if not ioc:
            return
        self._selected = ioc
        enrichment = ioc.get("enrichment", "")
        cached = self._intel.get_cached(ioc["ioc_type"], ioc["value"])
        intel_text = ""
        if cached:
            import json
            try:
                raw = json.loads(cached.get("raw_data", "{}"))
                intel_text = json.dumps(raw, indent=2)
            except Exception:
                intel_text = cached.get("raw_data", "")

        self._detail_text.setPlainText(
            f"Type:        {ioc.get('ioc_type','')}\n"
            f"Value:       {ioc.get('value','')}\n"
            f"Confidence:  {ioc.get('confidence','')}\n"
            f"Threat Type: {ioc.get('threat_type','')}\n"
            f"Source:      {ioc.get('source','')}\n"
            f"First Seen:  {ioc.get('first_seen','')}\n"
            f"Last Seen:   {ioc.get('last_seen','')}\n"
            f"Notes:       {ioc.get('notes','')}\n"
            f"\n── Threat Intelligence ──────────────────────────\n"
            f"{intel_text or enrichment or 'Not enriched yet.'}"
        )

    # ── CRUD / Actions ─────────────────────────────────────────────────────

    def _add_ioc(self) -> None:
        dlg = IOCDialog(self)
        if dlg.exec() != QDialog.Accepted:
            return
        data = dlg.get_data()
        if not data["value"]:
            return
        now = datetime.now(timezone.utc).isoformat()
        self._db.insert(
            """INSERT OR IGNORE INTO iocs
               (case_id, ioc_type, value, confidence, threat_type, source, notes,
                first_seen, last_seen)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (self._active_case_id, data["ioc_type"], data["value"],
             data["confidence"], data["threat_type"], data["source"],
             data["notes"], now, now),
        )
        self._audit.record("ioc_add", f"IOC added: {data['ioc_type']}={data['value']}")
        self._load()

    def _edit_selected(self) -> None:
        if not self._selected:
            return
        dlg = IOCDialog(self, ioc=self._selected)
        if dlg.exec() != QDialog.Accepted:
            return
        data = dlg.get_data()
        now = datetime.now(timezone.utc).isoformat()
        self._db.update(
            """UPDATE iocs SET ioc_type=?, value=?, confidence=?, threat_type=?,
               source=?, notes=?, last_seen=? WHERE id=?""",
            (data["ioc_type"], data["value"], data["confidence"], data["threat_type"],
             data["source"], data["notes"], now, self._selected["id"]),
        )
        self._load()

    def _delete_selected(self) -> None:
        if not self._selected:
            return
        reply = QMessageBox.question(
            self, "Delete IOC",
            f"Delete IOC: {self._selected['value']}?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        self._db.update("DELETE FROM iocs WHERE id=?", (self._selected["id"],))
        self._selected = None
        self._load()

    def _enrich_selected(self) -> None:
        if not self._selected:
            QMessageBox.information(self, "Enrich", "Select an IOC first.")
            return
        if self._enrich_thread and self._enrich_thread.isRunning():
            return
        self._enrich_status.setText("Enriching…")
        self._enrich_thread = EnrichThread(
            self._intel, self._selected["ioc_type"], self._selected["value"]
        )
        self._enrich_thread.finished.connect(self._on_enriched)
        self._enrich_thread.error.connect(lambda e: self._enrich_status.setText(f"Error: {e}"))
        self._enrich_thread.start()

    def _on_enriched(self, result: dict) -> None:
        import json
        self._enrich_status.setText("✓ Enriched")
        self._db.update(
            "UPDATE iocs SET enriched=1, enrichment=? WHERE id=?",
            (json.dumps(result, default=str)[:4000], self._selected["id"]),
        )
        self._detail_text.setPlainText(json.dumps(result, indent=2))
        self._load()
        self._audit.record("ioc_enrich", f"Enriched: {self._selected['value']}")

    def _bulk_import(self) -> None:
        from PySide6.QtWidgets import QFileDialog
        path, _ = QFileDialog.getOpenFileName(
            self, "Bulk Import IOCs", "", "Text Files (*.txt *.csv)"
        )
        if not path:
            return
        from pathlib import Path
        import csv
        count = 0
        content = Path(path).read_text(encoding="utf-8", errors="replace")
        now = datetime.now(timezone.utc).isoformat()
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            value = parts[0].strip()
            ioc_type = parts[1].strip() if len(parts) > 1 else "ip"
            self._db.insert(
                """INSERT OR IGNORE INTO iocs
                   (case_id, ioc_type, value, confidence, source, first_seen, last_seen)
                   VALUES (?,?,?,?,?,?,?)""",
                (self._active_case_id, ioc_type, value, "medium", "bulk_import", now, now),
            )
            count += 1
        QMessageBox.information(self, "Import", f"Imported {count} IOCs.")
        self._audit.record("ioc_bulk_import", f"Imported {count} IOCs")
        self._load()

    def _on_case_changed(self, case_id) -> None:
        self._load()
