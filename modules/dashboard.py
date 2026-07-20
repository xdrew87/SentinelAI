"""
modules/dashboard.py – SentinelAI Dashboard module.

Shows: case stats, recent events, IOC summary, flagged events,
recent AI conversations, and quick-action buttons.
"""

from __future__ import annotations

import logging
from typing import Optional

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QWidget, QFrame,
    QTableWidget, QTableWidgetItem, QHeaderView, QScrollArea,
)

from modules.base_module import BaseModule

log = logging.getLogger(__name__)


class StatCard(QWidget):
    """Single KPI card: large number + label + optional subtitle."""

    def __init__(
        self,
        title: str,
        value: str = "0",
        color: str = "#58A6FF",
        subtitle: str = "",
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._color = color
        self.setStyleSheet(
            f"background-color: #161B22; border: 1px solid #30363D; border-radius: 8px;"
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(4)

        self._val_lbl = QLabel(value)
        self._val_lbl.setStyleSheet(
            f"font-size: 32px; font-weight: 800; color: {color}; background: transparent;"
        )
        layout.addWidget(self._val_lbl)

        title_lbl = QLabel(title)
        title_lbl.setStyleSheet(
            "font-size: 12px; color: #8B949E; text-transform: uppercase; "
            "letter-spacing: 0.5px; background: transparent;"
        )
        layout.addWidget(title_lbl)

        if subtitle:
            sub = QLabel(subtitle)
            sub.setStyleSheet("font-size: 11px; color: #484F58; background: transparent;")
            layout.addWidget(sub)

    def set_value(self, value: str) -> None:
        self._val_lbl.setText(value)


class DashboardModule(BaseModule):
    """Main dashboard providing operational overview."""

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(self._make_page_header(
            "Dashboard",
            "Operational overview — active cases, recent events, threat summary"
        ))

        # Scrollable content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        content = QWidget()
        self._content_layout = QVBoxLayout(content)
        self._content_layout.setContentsMargins(20, 20, 20, 20)
        self._content_layout.setSpacing(20)
        scroll.setWidget(content)
        layout.addWidget(scroll, 1)

        self._build_stat_row()
        self._build_quick_actions()
        self._build_recent_cases()
        self._build_recent_events()
        self._build_ioc_summary()

        # Auto-refresh every 30 seconds
        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self.refresh)
        self._refresh_timer.start(30_000)
        self.refresh()

    def _build_stat_row(self) -> None:
        grid = QGridLayout()
        grid.setSpacing(12)

        self._card_cases = StatCard("Open Cases", "0", "#58A6FF")
        self._card_events = StatCard("Log Events", "0", "#3FB950")
        self._card_flagged = StatCard("Flagged Events", "0", "#F85149")
        self._card_iocs = StatCard("IOCs", "0", "#D29922")
        self._card_evidence = StatCard("Evidence Files", "0", "#A371F7")
        self._card_timeline = StatCard("Timeline Entries", "0", "#39D353")

        grid.addWidget(self._card_cases,    0, 0)
        grid.addWidget(self._card_events,   0, 1)
        grid.addWidget(self._card_flagged,  0, 2)
        grid.addWidget(self._card_iocs,     0, 3)
        grid.addWidget(self._card_evidence, 0, 4)
        grid.addWidget(self._card_timeline, 0, 5)

        self._content_layout.addLayout(grid)

    def _build_quick_actions(self) -> None:
        lbl = QLabel("Quick Actions")
        lbl.setObjectName("SectionTitle")
        self._content_layout.addWidget(lbl)

        bar = QHBoxLayout()
        bar.setSpacing(10)

        actions = [
            ("＋ New Case",          "#1F6FEB", lambda: self._nav(1)),
            ("📋 Add Evidence",      "#21262D", lambda: self._nav(2)),
            ("🔍 Investigate Logs",  "#21262D", lambda: self._nav(3)),
            ("🔗 Lookup IOC",        "#21262D", lambda: self._nav(5)),
            ("🤖 AI Assistant",      "#21262D", lambda: self._nav(14)),
            ("📊 Generate Report",   "#21262D", lambda: self._nav(15)),
        ]
        for text, bg, slot in actions:
            btn = QPushButton(text)
            btn.setStyleSheet(
                f"background-color: {bg}; color: #C9D1D9; border: 1px solid #30363D; "
                f"border-radius: 6px; padding: 8px 16px; font-weight: 600;"
            )
            btn.clicked.connect(slot)
            bar.addWidget(btn)
        bar.addStretch()
        self._content_layout.addLayout(bar)

    def _build_recent_cases(self) -> None:
        lbl = QLabel("Recent Cases")
        lbl.setObjectName("SectionTitle")
        self._content_layout.addWidget(lbl)

        self._cases_table = self._make_table(
            ["ID", "Title", "Severity", "Status", "Analyst", "Created"]
        )
        self._cases_table.setMaximumHeight(200)
        self._cases_table.doubleClicked.connect(self._open_case_from_table)
        self._content_layout.addWidget(self._cases_table)

    def _build_recent_events(self) -> None:
        lbl = QLabel("Recent Flagged Events")
        lbl.setObjectName("SectionTitle")
        self._content_layout.addWidget(lbl)

        self._events_table = self._make_table(
            ["Timestamp", "Source", "Level", "Event ID", "Host", "Message"]
        )
        self._events_table.setMaximumHeight(200)
        self._content_layout.addWidget(self._events_table)

    def _build_ioc_summary(self) -> None:
        lbl = QLabel("Recent IOCs")
        lbl.setObjectName("SectionTitle")
        self._content_layout.addWidget(lbl)

        self._ioc_table = self._make_table(
            ["Type", "Value", "Confidence", "Threat Type", "Added"]
        )
        self._ioc_table.setMaximumHeight(180)
        self._content_layout.addWidget(self._ioc_table)

    # ── Data refresh ────────────────────────────────────────────────────────

    def refresh(self) -> None:
        self._refresh_stats()
        self._refresh_cases()
        self._refresh_events()
        self._refresh_iocs()

    def _refresh_stats(self) -> None:
        def q(sql, *p):
            row = self._db.fetchone(sql, p)
            return str(row[0]) if row else "0"

        self._card_cases.set_value(
            q("SELECT COUNT(*) FROM cases WHERE status='open'")
        )
        self._card_events.set_value(
            q("SELECT COUNT(*) FROM log_events")
        )
        self._card_flagged.set_value(
            q("SELECT COUNT(*) FROM log_events WHERE flagged=1")
        )
        self._card_iocs.set_value(
            q("SELECT COUNT(*) FROM iocs")
        )
        self._card_evidence.set_value(
            q("SELECT COUNT(*) FROM evidence")
        )
        self._card_timeline.set_value(
            q("SELECT COUNT(*) FROM timeline_entries")
        )

    def _refresh_cases(self) -> None:
        rows = self._db.fetchall(
            "SELECT id, title, severity, status, analyst, created_at "
            "FROM cases ORDER BY created_at DESC LIMIT 20"
        )
        self._cases_table.setRowCount(0)
        sev_colors = {
            "critical": "#F85149", "high": "#D29922",
            "medium": "#58A6FF", "low": "#3FB950",
        }
        for row in rows:
            r = self._cases_table.rowCount()
            self._cases_table.insertRow(r)
            values = [
                str(row["id"]), row["title"], row["severity"].upper(),
                row["status"].capitalize(), row["analyst"],
                row["created_at"][:16],
            ]
            for c, val in enumerate(values):
                item = QTableWidgetItem(val)
                if c == 2:
                    item.setForeground(
                        __import__("PySide6.QtGui", fromlist=["QColor"]).QColor(
                            sev_colors.get(row["severity"], "#C9D1D9")
                        )
                    )
                self._cases_table.setItem(r, c, item)

    def _refresh_events(self) -> None:
        rows = self._db.fetchall(
            """SELECT timestamp, source_type, level, event_id, source_host, message
               FROM log_events WHERE flagged=1
               ORDER BY id DESC LIMIT 30"""
        )
        self._events_table.setRowCount(0)
        level_colors = {
            "critical": "#F85149", "error": "#F85149",
            "warning": "#D29922", "info": "#3FB950",
        }
        for row in rows:
            r = self._events_table.rowCount()
            self._events_table.insertRow(r)
            values = [
                row["timestamp"][:19], row["source_type"], row["level"].upper(),
                row["event_id"], row["source_host"], row["message"][:80],
            ]
            for c, val in enumerate(values):
                item = QTableWidgetItem(val)
                if c == 2:
                    from PySide6.QtGui import QColor
                    item.setForeground(
                        QColor(level_colors.get(row["level"].lower(), "#C9D1D9"))
                    )
                self._events_table.setItem(r, c, item)

    def _refresh_iocs(self) -> None:
        rows = self._db.fetchall(
            "SELECT ioc_type, value, confidence, threat_type, created_at "
            "FROM iocs ORDER BY id DESC LIMIT 20"
        )
        self._ioc_table.setRowCount(0)
        for row in rows:
            r = self._ioc_table.rowCount()
            self._ioc_table.insertRow(r)
            for c, val in enumerate([
                row["ioc_type"], row["value"], row["confidence"],
                row["threat_type"], row["created_at"][:16],
            ]):
                self._ioc_table.setItem(r, c, QTableWidgetItem(str(val)))

    # ── Helpers ─────────────────────────────────────────────────────────────

    @staticmethod
    def _make_table(headers: list[str]) -> QTableWidget:
        t = QTableWidget(0, len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.setEditTriggers(QTableWidget.NoEditTriggers)
        t.setSelectionBehavior(QTableWidget.SelectRows)
        t.setAlternatingRowColors(True)
        t.verticalHeader().setVisible(False)
        t.horizontalHeader().setStretchLastSection(True)
        t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        return t

    def _nav(self, index: int) -> None:
        if self._main_window:
            self._main_window._nav_to(index)

    def _open_case_from_table(self, index) -> None:
        row = index.row()
        id_item = self._cases_table.item(row, 0)
        title_item = self._cases_table.item(row, 1)
        if id_item and self._main_window:
            self._main_window.open_case(int(id_item.text()), title_item.text())

    def _on_case_changed(self, case_id) -> None:
        self.refresh()
