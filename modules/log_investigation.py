"""
modules/log_investigation.py – Log event viewer with powerful filtering,
flagging, Sigma scanning, and IOC extraction.
"""

from __future__ import annotations

import logging
from typing import Optional

from PySide6.QtCore import Qt, QSortFilterProxyModel, QThread, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QSplitter,
    QLabel, QPushButton, QLineEdit, QTextEdit,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QWidget, QComboBox, QCheckBox, QSpinBox,
    QMessageBox, QFrame, QProgressBar,
)

from modules.base_module import BaseModule
from core.sigma_engine import SigmaEngine

log = logging.getLogger(__name__)

_LEVEL_COLORS = {
    "critical": "#F85149", "error": "#F85149",
    "warning": "#D29922", "info": "#3FB950",
    "verbose": "#8B949E", "debug": "#8B949E",
}

_PAGE_SIZE = 500


class SigmaScanThread(QThread):
    finished = Signal(dict)  # {event_id: [rule_metas]}

    def __init__(self, engine: SigmaEngine, events: list[dict]) -> None:
        super().__init__()
        self._engine = engine
        self._events = events

    def run(self) -> None:
        results = self._engine.scan_events(self._events)
        self.finished.emit(results)


class LogInvestigationModule(BaseModule):
    """High-performance log event viewer and investigator."""

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(self._make_page_header(
            "Log Investigation",
            "Search, filter and investigate log events across all evidence sources"
        ))

        # ── Filter bar ────────────────────────────────────────────────────
        filter_bar = QWidget()
        filter_bar.setStyleSheet(
            "background-color: #161B22; border-bottom: 1px solid #21262D;"
        )
        fb_layout = QHBoxLayout(filter_bar)
        fb_layout.setContentsMargins(12, 8, 12, 8)
        fb_layout.setSpacing(8)

        self._search_edit = QLineEdit()
        self._search_edit.setPlaceholderText("Search message, host, IP, user, process…")
        self._search_edit.setMinimumWidth(300)
        self._search_edit.returnPressed.connect(self._run_query)

        self._source_combo = QComboBox()
        self._source_combo.setFixedWidth(140)
        self._source_combo.addItem("All Sources")

        self._level_combo = QComboBox()
        self._level_combo.setFixedWidth(130)
        self._level_combo.addItems([
            "All Levels", "Critical", "Error", "Warning", "Info", "Verbose"
        ])

        self._flagged_only = QCheckBox("Flagged only")

        self._date_from = QLineEdit()
        self._date_from.setPlaceholderText("From: YYYY-MM-DD")
        self._date_from.setFixedWidth(140)

        self._date_to = QLineEdit()
        self._date_to.setPlaceholderText("To: YYYY-MM-DD")
        self._date_to.setFixedWidth(140)

        search_btn = self._primary_btn("Search")
        search_btn.clicked.connect(self._run_query)

        sigma_btn = QPushButton("⚡ Sigma Scan")
        sigma_btn.clicked.connect(self._run_sigma_scan)

        export_btn = QPushButton("⬇ Export")
        export_btn.clicked.connect(self._export_results)

        fb_layout.addWidget(self._search_edit)
        fb_layout.addWidget(self._source_combo)
        fb_layout.addWidget(self._level_combo)
        fb_layout.addWidget(self._flagged_only)
        fb_layout.addWidget(QLabel("From:"))
        fb_layout.addWidget(self._date_from)
        fb_layout.addWidget(QLabel("To:"))
        fb_layout.addWidget(self._date_to)
        fb_layout.addStretch()
        fb_layout.addWidget(sigma_btn)
        fb_layout.addWidget(export_btn)
        fb_layout.addWidget(search_btn)
        layout.addWidget(filter_bar)

        # ── Status row ────────────────────────────────────────────────────
        status_row = QWidget()
        status_row.setStyleSheet("background-color: #0D1117;")
        sr_layout = QHBoxLayout(status_row)
        sr_layout.setContentsMargins(12, 4, 12, 4)
        self._result_label = QLabel("No results")
        self._result_label.setObjectName("Muted")
        self._page_label = QLabel("")
        self._page_label.setObjectName("Muted")
        prev_btn = QPushButton("◀ Prev")
        prev_btn.setFixedWidth(70)
        prev_btn.clicked.connect(self._prev_page)
        next_btn = QPushButton("Next ▶")
        next_btn.setFixedWidth(70)
        next_btn.clicked.connect(self._next_page)
        self._sigma_result_label = QLabel("")
        self._sigma_result_label.setStyleSheet("color: #D29922;")
        sr_layout.addWidget(self._result_label)
        sr_layout.addWidget(self._sigma_result_label)
        sr_layout.addStretch()
        sr_layout.addWidget(self._page_label)
        sr_layout.addWidget(prev_btn)
        sr_layout.addWidget(next_btn)
        layout.addWidget(status_row)

        # ── Main splitter: table | detail ─────────────────────────────────
        splitter = QSplitter(Qt.Vertical)

        # Event table
        self._table = QTableWidget(0, 9)
        self._table.setHorizontalHeaderLabels([
            "⚑", "Timestamp", "Source", "Level", "Event ID",
            "Host", "IP", "User", "Message",
        ])
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(8, QHeaderView.Stretch)
        self._table.setColumnWidth(0, 30)
        self._table.selectionModel().selectionChanged.connect(self._on_row_selected)
        self._table.cellDoubleClicked.connect(self._toggle_flag)
        splitter.addWidget(self._table)

        # Detail panel
        detail = QWidget()
        detail_layout = QVBoxLayout(detail)
        detail_layout.setContentsMargins(12, 8, 12, 8)
        detail_layout.setSpacing(6)

        detail_hdr = QHBoxLayout()
        det_lbl = QLabel("Event Detail")
        det_lbl.setObjectName("AccentLabel")
        detail_hdr.addWidget(det_lbl)
        detail_hdr.addStretch()
        flag_btn = QPushButton("⚑ Flag / Unflag")
        flag_btn.clicked.connect(self._toggle_selected_flag)
        add_ioc_btn = QPushButton("+ Add IOC")
        add_ioc_btn.clicked.connect(self._add_ioc_from_event)
        add_timeline_btn = QPushButton("+ Timeline")
        add_timeline_btn.clicked.connect(self._add_to_timeline)
        detail_hdr.addWidget(flag_btn)
        detail_hdr.addWidget(add_ioc_btn)
        detail_hdr.addWidget(add_timeline_btn)
        detail_layout.addLayout(detail_hdr)

        self._detail_text = QTextEdit()
        self._detail_text.setReadOnly(True)
        self._detail_text.setStyleSheet(
            "background-color: #0D1117; color: #C9D1D9; "
            "font-family: 'Cascadia Code', 'JetBrains Mono', monospace; font-size: 12px;"
        )
        detail_layout.addWidget(self._detail_text)
        splitter.addWidget(detail)
        splitter.setSizes([600, 200])
        layout.addWidget(splitter, 1)

        self._events: list[dict] = []
        self._current_page = 0
        self._total_rows = 0
        self._selected_event: Optional[dict] = None
        self._sigma_engine = SigmaEngine(self._db)
        self._sigma_hits: dict[int, list[dict]] = {}
        self._load_sources()

    # ── Data loading ───────────────────────────────────────────────────────

    def _load_sources(self) -> None:
        rows = self._db.fetchall(
            "SELECT DISTINCT source_type FROM log_events ORDER BY source_type"
        )
        self._source_combo.clear()
        self._source_combo.addItem("All Sources")
        for r in rows:
            self._source_combo.addItem(r["source_type"])

    def _run_query(self) -> None:
        self._current_page = 0
        self._execute_query()

    def _execute_query(self) -> None:
        conditions = ["1=1"]
        params: list = []

        if self._active_case_id:
            conditions.append("case_id=?")
            params.append(self._active_case_id)

        q = self._search_edit.text().strip()
        if q:
            conditions.append(
                "(message LIKE ? OR source_host LIKE ? OR source_ip LIKE ? "
                "OR user LIKE ? OR process LIKE ? OR raw LIKE ?)"
            )
            like = f"%{q}%"
            params.extend([like] * 6)

        src = self._source_combo.currentText()
        if src != "All Sources":
            conditions.append("source_type=?")
            params.append(src)

        lvl = self._level_combo.currentText().lower()
        if lvl not in ("all levels", ""):
            conditions.append("level=?")
            params.append(lvl)

        if self._flagged_only.isChecked():
            conditions.append("flagged=1")

        date_from = self._date_from.text().strip()
        if date_from:
            conditions.append("timestamp >= ?")
            params.append(date_from)

        date_to = self._date_to.text().strip()
        if date_to:
            conditions.append("timestamp <= ?")
            params.append(date_to + "T23:59:59")

        where = " AND ".join(conditions)

        count_row = self._db.fetchone(
            f"SELECT COUNT(*) AS c FROM log_events WHERE {where}", tuple(params)
        )
        self._total_rows = count_row["c"] if count_row else 0

        offset = self._current_page * _PAGE_SIZE
        rows = self._db.fetchall(
            f"""SELECT id, timestamp, source_type, level, event_id,
                       source_host, source_ip, user, message, flagged, raw, process
                FROM log_events WHERE {where}
                ORDER BY timestamp DESC, id DESC
                LIMIT ? OFFSET ?""",
            tuple(params) + (_PAGE_SIZE, offset),
        )
        self._events = [dict(r) for r in rows]
        self._populate_table()
        total_pages = max(1, (self._total_rows + _PAGE_SIZE - 1) // _PAGE_SIZE)
        self._result_label.setText(
            f"{self._total_rows:,} events   Showing {offset + 1}–{min(offset + _PAGE_SIZE, self._total_rows)}"
        )
        self._page_label.setText(f"Page {self._current_page + 1} / {total_pages}")
        self._sigma_hits.clear()
        self._sigma_result_label.setText("")

    def _populate_table(self) -> None:
        self._table.setRowCount(0)
        for ev in self._events:
            r = self._table.rowCount()
            self._table.insertRow(r)
            flag_item = QTableWidgetItem("⚑" if ev["flagged"] else "")
            flag_item.setTextAlignment(Qt.AlignCenter)
            if ev["flagged"]:
                flag_item.setForeground(QColor("#F85149"))
            self._table.setItem(r, 0, flag_item)

            vals = [
                ev.get("timestamp", "")[:19],
                ev.get("source_type", ""),
                ev.get("level", ""),
                ev.get("event_id", ""),
                ev.get("source_host", ""),
                ev.get("source_ip", ""),
                ev.get("user", ""),
                ev.get("message", "")[:120],
            ]
            for c, val in enumerate(vals, 1):
                item = QTableWidgetItem(str(val))
                if c == 3:  # level
                    item.setForeground(
                        QColor(_LEVEL_COLORS.get(ev.get("level", "").lower(), "#C9D1D9"))
                    )
                self._table.setItem(r, c, item)

            # Highlight sigma hits
            if ev["id"] in self._sigma_hits:
                for col in range(self._table.columnCount()):
                    it = self._table.item(r, col)
                    if it:
                        it.setBackground(QColor("#2D1A00"))

    # ── Pagination ─────────────────────────────────────────────────────────

    def _next_page(self) -> None:
        max_page = max(0, (self._total_rows - 1) // _PAGE_SIZE)
        if self._current_page < max_page:
            self._current_page += 1
            self._execute_query()

    def _prev_page(self) -> None:
        if self._current_page > 0:
            self._current_page -= 1
            self._execute_query()

    # ── Event detail ───────────────────────────────────────────────────────

    def _on_row_selected(self) -> None:
        row = self._table.currentRow()
        if row < 0 or row >= len(self._events):
            return
        ev = self._events[row]
        self._selected_event = ev
        sigma_hits = self._sigma_hits.get(ev["id"], [])
        sigma_text = ""
        if sigma_hits:
            sigma_text = "\n\n⚡ SIGMA MATCHES:\n" + "\n".join(
                f"  • {h['name']} [{h['severity'].upper()}]" for h in sigma_hits
            )
        self._detail_text.setPlainText(
            f"ID:        {ev.get('id','')}\n"
            f"Timestamp: {ev.get('timestamp','')}\n"
            f"Source:    {ev.get('source_type','')}\n"
            f"Level:     {ev.get('level','').upper()}\n"
            f"Event ID:  {ev.get('event_id','')}\n"
            f"Host:      {ev.get('source_host','')}\n"
            f"IP:        {ev.get('source_ip','')}\n"
            f"User:      {ev.get('user','')}\n"
            f"Process:   {ev.get('process','')}\n"
            f"\n── Message ─────────────────────────────────────────\n"
            f"{ev.get('message','')}\n"
            f"\n── Raw ─────────────────────────────────────────────\n"
            f"{ev.get('raw','')}"
            f"{sigma_text}"
        )

    # ── Actions ────────────────────────────────────────────────────────────

    def _toggle_flag(self, row: int, col: int) -> None:
        if row < 0 or row >= len(self._events):
            return
        ev = self._events[row]
        new_flag = 0 if ev["flagged"] else 1
        self._db.update("UPDATE log_events SET flagged=? WHERE id=?", (new_flag, ev["id"]))
        ev["flagged"] = new_flag
        flag_item = self._table.item(row, 0)
        if flag_item:
            flag_item.setText("⚑" if new_flag else "")
            flag_item.setForeground(QColor("#F85149" if new_flag else "#484F58"))

    def _toggle_selected_flag(self) -> None:
        row = self._table.currentRow()
        self._toggle_flag(row, 0)

    def _add_ioc_from_event(self) -> None:
        if not self._selected_event:
            return
        from ui.dialogs.ioc_dialog import IOCDialog
        ip = self._selected_event.get("source_ip", "")
        dlg = IOCDialog(self, prefill_value=ip, prefill_type="ip" if ip else "")
        if dlg.exec():
            data = dlg.get_data()
            self._db.insert(
                """INSERT OR IGNORE INTO iocs
                   (case_id, ioc_type, value, confidence, threat_type, source, notes)
                   VALUES (?,?,?,?,?,?,?)""",
                (self._active_case_id, data["ioc_type"], data["value"],
                 data["confidence"], data["threat_type"], "log_event",
                 data.get("notes", "")),
            )
            self._audit.record("ioc_add", f"IOC added from log event: {data['value']}")

    def _add_to_timeline(self) -> None:
        if not self._selected_event or not self._active_case_id:
            return
        ev = self._selected_event
        from datetime import datetime, timezone
        self._db.insert(
            """INSERT INTO timeline_entries
               (case_id, timestamp, event_type, description, source, log_event_id)
               VALUES (?,?,?,?,?,?)""",
            (self._active_case_id, ev.get("timestamp", ""),
             ev.get("source_type", ""), ev.get("message", "")[:200],
             ev.get("source_type", ""), ev["id"]),
        )
        self._audit.record("timeline_add", f"Added event #{ev['id']} to timeline")

    def _run_sigma_scan(self) -> None:
        if not self._events:
            QMessageBox.information(self, "Sigma Scan", "No events loaded.")
            return
        self._sigma_engine.reload()
        self._scan_thread = SigmaScanThread(self._sigma_engine, self._events)
        self._scan_thread.finished.connect(self._on_sigma_done)
        self._scan_thread.start()
        self._sigma_result_label.setText("⚡ Scanning…")

    def _on_sigma_done(self, results: dict) -> None:
        # Map index → event_id
        hits_by_id: dict[int, list[dict]] = {}
        for idx, rules in results.items():
            if idx < len(self._events):
                ev_id = self._events[idx]["id"]
                hits_by_id[ev_id] = rules
        self._sigma_hits = hits_by_id
        self._sigma_result_label.setText(f"⚡ Sigma: {len(hits_by_id)} hits")
        self._populate_table()

    def _export_results(self) -> None:
        from PySide6.QtWidgets import QFileDialog
        import csv
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Events", "events.csv", "CSV (*.csv)"
        )
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["ID", "Timestamp", "Source", "Level",
                             "Event ID", "Host", "IP", "User", "Message"])
            for ev in self._events:
                writer.writerow([
                    ev.get("id"), ev.get("timestamp"), ev.get("source_type"),
                    ev.get("level"), ev.get("event_id"), ev.get("source_host"),
                    ev.get("source_ip"), ev.get("user"), ev.get("message"),
                ])
        QMessageBox.information(self, "Export", f"Exported {len(self._events)} events to {path}")

    def _on_case_changed(self, case_id) -> None:
        self._load_sources()
        self._run_query()
