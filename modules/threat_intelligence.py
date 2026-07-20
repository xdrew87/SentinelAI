"""
modules/threat_intelligence.py – Threat intelligence provider dashboard.
Manage API keys, bulk enrich IOCs, view enrichment results, browse cached intel.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QSplitter,
    QLabel, QPushButton, QLineEdit, QTextEdit,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QWidget, QTabWidget, QComboBox,
    QMessageBox, QProgressBar, QFormLayout,
    QGroupBox,
)

from modules.base_module import BaseModule
from core.threat_intel import ThreatIntelEngine

log = logging.getLogger(__name__)

_PROVIDERS = [
    ("VirusTotal",    "virustotal_api_key",  "https://www.virustotal.com"),
    ("AbuseIPDB",     "abuseipdb_api_key",   "https://www.abuseipdb.com"),
    ("AlienVault OTX","otx_api_key",         "https://otx.alienvault.com"),
    ("Shodan",        "shodan_api_key",       "https://www.shodan.io"),
]


class BulkEnrichThread(QThread):
    progress = Signal(int, int, str)
    finished = Signal(int)
    error = Signal(str)

    def __init__(self, engine: ThreatIntelEngine, iocs: list[dict]) -> None:
        super().__init__()
        self._engine = engine
        self._iocs = iocs

    def run(self) -> None:
        count = 0
        for i, ioc in enumerate(self._iocs):
            try:
                self.progress.emit(i + 1, len(self._iocs), ioc.get("value", ""))
                self._engine.enrich_ioc(ioc["ioc_type"], ioc["value"])
                count += 1
            except Exception as exc:
                log.warning("Enrich failed for %s: %s", ioc.get("value"), exc)
        self.finished.emit(count)


class ThreatIntelModule(BaseModule):
    """Threat intelligence management and bulk enrichment."""

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(self._make_page_header(
            "Threat Intelligence",
            "Enrich IOCs via VirusTotal, AbuseIPDB, OTX — browse cached intelligence"
        ))

        self._intel = ThreatIntelEngine(self._config, self._db)

        tabs = QTabWidget()
        layout.addWidget(tabs, 1)

        # ── Tab 1: Bulk Enrichment ─────────────────────────────────────────
        bulk_tab = QWidget()
        bl = QVBoxLayout(bulk_tab)
        bl.setContentsMargins(20, 20, 20, 20)
        bl.setSpacing(14)

        # Status cards row
        cards_row = QHBoxLayout()
        self._card_iocs = self._stat_card("Total IOCs", "0", "#58A6FF")
        self._card_enriched = self._stat_card("Enriched", "0", "#3FB950")
        self._card_pending = self._stat_card("Pending", "0", "#D29922")
        self._card_cached = self._stat_card("Intel Records", "0", "#A371F7")
        for card in (self._card_iocs, self._card_enriched, self._card_pending, self._card_cached):
            cards_row.addWidget(card)
        bl.addLayout(cards_row)

        # Bulk controls
        ctrl_group = QGroupBox("Bulk Enrichment")
        cgl = QHBoxLayout(ctrl_group)
        self._type_filter = QComboBox()
        self._type_filter.addItems(["All Types", "ip", "domain", "url", "hash"])
        enrich_case_btn = self._primary_btn("⚡ Enrich Case IOCs")
        enrich_case_btn.clicked.connect(self._enrich_case_iocs)
        enrich_all_btn = QPushButton("⚡ Enrich All IOCs")
        enrich_all_btn.clicked.connect(self._enrich_all_iocs)
        self._bulk_progress = QProgressBar()
        self._bulk_progress.setVisible(False)
        self._bulk_status = QLabel("")
        self._bulk_status.setObjectName("AccentLabel")
        cgl.addWidget(QLabel("Type:"))
        cgl.addWidget(self._type_filter)
        cgl.addWidget(enrich_case_btn)
        cgl.addWidget(enrich_all_btn)
        cgl.addStretch()
        cgl.addWidget(self._bulk_status)
        cgl.addWidget(self._bulk_progress)
        bl.addWidget(ctrl_group)

        # Quick lookup
        lookup_group = QGroupBox("Quick IOC Lookup")
        lgl = QVBoxLayout(lookup_group)
        lookup_row = QHBoxLayout()
        self._lookup_type = QComboBox()
        self._lookup_type.addItems(["ip", "domain", "url", "hash"])
        self._lookup_value = QLineEdit()
        self._lookup_value.setPlaceholderText("Enter IOC value…")
        self._lookup_value.setMinimumWidth(300)
        self._lookup_value.returnPressed.connect(self._quick_lookup)
        lookup_btn = self._primary_btn("🔍 Lookup")
        lookup_btn.clicked.connect(self._quick_lookup)
        lookup_row.addWidget(self._lookup_type)
        lookup_row.addWidget(self._lookup_value)
        lookup_row.addWidget(lookup_btn)
        lookup_row.addStretch()
        lgl.addLayout(lookup_row)
        self._lookup_result = QTextEdit()
        self._lookup_result.setReadOnly(True)
        self._lookup_result.setMaximumHeight(200)
        self._lookup_result.setStyleSheet(
            "background-color: #0D1117; font-family: monospace; font-size: 12px;"
        )
        lgl.addWidget(self._lookup_result)
        bl.addWidget(lookup_group)
        bl.addStretch()
        tabs.addTab(bulk_tab, "Enrichment")

        # ── Tab 2: Intel Cache Browser ────────────────────────────────────
        cache_tab = QWidget()
        cl = QVBoxLayout(cache_tab)
        cl.setContentsMargins(0, 0, 0, 0)

        cache_toolbar = QWidget()
        cache_toolbar.setStyleSheet("background-color: #161B22; border-bottom: 1px solid #21262D;")
        ctl = QHBoxLayout(cache_toolbar)
        ctl.setContentsMargins(12, 8, 12, 8)
        self._cache_search = QLineEdit()
        self._cache_search.setPlaceholderText("Search cached intelligence…")
        self._cache_search.setFixedWidth(280)
        self._cache_search.textChanged.connect(self._filter_cache)
        refresh_btn = QPushButton("↺ Refresh")
        refresh_btn.clicked.connect(self._load_cache)
        ctl.addWidget(self._cache_search)
        ctl.addStretch()
        ctl.addWidget(refresh_btn)
        cl.addWidget(cache_toolbar)

        cache_splitter = QSplitter(Qt.Horizontal)
        self._cache_table = QTableWidget(0, 5)
        self._cache_table.setHorizontalHeaderLabels(
            ["Type", "Value", "Provider", "Confidence", "Fetched"]
        )
        self._cache_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._cache_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._cache_table.setAlternatingRowColors(True)
        self._cache_table.verticalHeader().setVisible(False)
        self._cache_table.horizontalHeader().setStretchLastSection(True)
        self._cache_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self._cache_table.selectionModel().selectionChanged.connect(self._on_cache_selected)
        cache_splitter.addWidget(self._cache_table)

        detail_pane = QWidget()
        detail_pane.setFixedWidth(400)
        detail_pane.setStyleSheet("background-color: #161B22; border-left: 1px solid #30363D;")
        dpl = QVBoxLayout(detail_pane)
        dpl.setContentsMargins(14, 14, 14, 14)
        dpl.addWidget(QLabel("Intelligence Detail"))
        self._cache_detail = QTextEdit()
        self._cache_detail.setReadOnly(True)
        self._cache_detail.setStyleSheet(
            "background-color: #0D1117; font-family: monospace; font-size: 11px;"
        )
        dpl.addWidget(self._cache_detail, 1)
        cache_splitter.addWidget(detail_pane)
        cache_splitter.setStretchFactor(0, 2)
        cache_splitter.setStretchFactor(1, 1)
        cl.addWidget(cache_splitter, 1)
        tabs.addTab(cache_tab, "Intel Cache")

        # ── Tab 3: Provider Status ────────────────────────────────────────
        prov_tab = QWidget()
        pl = QVBoxLayout(prov_tab)
        pl.setContentsMargins(20, 20, 20, 20)
        pl.setSpacing(12)
        pl.addWidget(QLabel("Configured Threat Intelligence Providers:"))
        for name, key_name, url in _PROVIDERS:
            grp = QGroupBox(name)
            gl = QHBoxLayout(grp)
            key = self._config.get_secret(key_name)
            status_lbl = QLabel("✓ Key configured" if key else "✗ No API key")
            status_lbl.setStyleSheet(
                f"color: {'#3FB950' if key else '#F85149'}; font-weight: 600;"
            )
            url_lbl = QLabel(f'<a href="{url}" style="color:#58A6FF;">{url}</a>')
            url_lbl.setOpenExternalLinks(True)
            gl.addWidget(status_lbl)
            gl.addStretch()
            gl.addWidget(url_lbl)
            pl.addWidget(grp)
        pl.addWidget(QLabel("Configure API keys in Settings → AI & Integrations"))
        pl.addStretch()
        tabs.addTab(prov_tab, "Providers")

        self._cache_records: list[dict] = []
        self._bulk_thread: Optional[BulkEnrichThread] = None
        self._lookup_thread: Optional[QThread] = None
        self._refresh_stats()
        self._load_cache()

    # ── Stat cards ─────────────────────────────────────────────────────────

    @staticmethod
    def _stat_card(title: str, value: str, color: str) -> QWidget:
        card = QWidget()
        card.setStyleSheet(
            f"background-color: #161B22; border: 1px solid #30363D; border-radius: 8px;"
        )
        cl = QVBoxLayout(card)
        cl.setContentsMargins(16, 12, 16, 12)
        val_lbl = QLabel(value)
        val_lbl.setObjectName("_val")
        val_lbl.setStyleSheet(
            f"font-size: 28px; font-weight: 800; color: {color}; background: transparent;"
        )
        title_lbl = QLabel(title)
        title_lbl.setStyleSheet(
            "font-size: 11px; color: #8B949E; text-transform: uppercase; background: transparent;"
        )
        cl.addWidget(val_lbl)
        cl.addWidget(title_lbl)
        return card

    def _set_card_value(self, card: QWidget, value: str) -> None:
        lbl = card.findChild(QLabel, "_val")
        if lbl:
            lbl.setText(value)

    def _refresh_stats(self) -> None:
        _r1 = self._db.fetchone("SELECT COUNT(*) AS c FROM iocs")
        total = _r1["c"] if _r1 else 0
        _r2 = self._db.fetchone("SELECT COUNT(*) AS c FROM iocs WHERE enriched=1")
        enriched = _r2["c"] if _r2 else 0
        _r3 = self._db.fetchone("SELECT COUNT(*) AS c FROM threat_intel")
        cached = _r3["c"] if _r3 else 0
        self._set_card_value(self._card_iocs, str(total))
        self._set_card_value(self._card_enriched, str(enriched))
        self._set_card_value(self._card_pending, str(total - enriched))
        self._set_card_value(self._card_cached, str(cached))

    # ── Enrichment ─────────────────────────────────────────────────────────

    def _enrich_case_iocs(self) -> None:
        if not self._active_case_id:
            QMessageBox.warning(self, "No Case", "Activate a case first.")
            return
        rows = self._db.fetchall(
            "SELECT ioc_type, value FROM iocs WHERE case_id=? AND enriched=0",
            (self._active_case_id,),
        )
        self._start_bulk([dict(r) for r in rows])

    def _enrich_all_iocs(self) -> None:
        ioc_type = self._type_filter.currentText()
        if ioc_type == "All Types":
            rows = self._db.fetchall("SELECT ioc_type, value FROM iocs WHERE enriched=0")
        else:
            rows = self._db.fetchall(
                "SELECT ioc_type, value FROM iocs WHERE enriched=0 AND ioc_type=?",
                (ioc_type,),
            )
        self._start_bulk([dict(r) for r in rows])

    def _start_bulk(self, iocs: list[dict]) -> None:
        if not iocs:
            QMessageBox.information(self, "Enrich", "No unenriched IOCs found.")
            return
        if self._bulk_thread and self._bulk_thread.isRunning():
            return
        self._bulk_progress.setRange(0, len(iocs))
        self._bulk_progress.setValue(0)
        self._bulk_progress.setVisible(True)
        self._bulk_thread = BulkEnrichThread(self._intel, iocs)
        self._bulk_thread.progress.connect(
            lambda c, t, v: (
                self._bulk_progress.setValue(c),
                self._bulk_status.setText(f"Enriching {v}…"),
            )
        )
        self._bulk_thread.finished.connect(self._on_bulk_done)
        self._bulk_thread.error.connect(lambda e: self._bulk_status.setText(f"Error: {e}"))
        self._bulk_thread.start()

    def _on_bulk_done(self, count: int) -> None:
        self._bulk_progress.setVisible(False)
        self._bulk_status.setText(f"✓ Enriched {count} IOCs")
        self._refresh_stats()
        self._load_cache()
        self._audit.record("intel_bulk_enrich", f"Bulk enriched {count} IOCs")

    # ── Quick lookup ───────────────────────────────────────────────────────

    def _quick_lookup(self) -> None:
        ioc_type = self._lookup_type.currentText()
        value = self._lookup_value.text().strip()
        if not value:
            return
        self._lookup_result.setPlainText("Looking up…")

        class _LookupThread(QThread):
            done = Signal(dict)
            err = Signal(str)

            def __init__(self, engine, t, v):
                super().__init__()
                self._e, self._t, self._v = engine, t, v

            def run(self):
                try:
                    self.done.emit(self._e.enrich_ioc(self._t, self._v))
                except Exception as exc:
                    self.err.emit(str(exc))

        self._lookup_thread = _LookupThread(self._intel, ioc_type, value)
        self._lookup_thread.done.connect(
            lambda r: self._lookup_result.setPlainText(json.dumps(r, indent=2, default=str))
        )
        self._lookup_thread.err.connect(
            lambda e: self._lookup_result.setPlainText(f"Error: {e}")
        )
        self._lookup_thread.start()

    # ── Cache browser ──────────────────────────────────────────────────────

    def _load_cache(self) -> None:
        rows = self._db.fetchall(
            "SELECT * FROM threat_intel ORDER BY fetched_at DESC LIMIT 1000"
        )
        self._cache_records = [dict(r) for r in rows]
        self._filter_cache(self._cache_search.text())

    def _filter_cache(self, query: str) -> None:
        q = query.lower()
        records = [
            r for r in self._cache_records
            if not q or q in r.get("value", "").lower() or q in r.get("ioc_type", "").lower()
        ]
        self._cache_table.setRowCount(0)
        for rec in records:
            row = self._cache_table.rowCount()
            self._cache_table.insertRow(row)
            conf = rec.get("confidence", 0)
            conf_str = f"{conf:.0%}" if isinstance(conf, float) else str(conf)
            for c, val in enumerate([
                rec.get("ioc_type", ""), rec.get("value", ""),
                rec.get("provider", ""), conf_str,
                rec.get("fetched_at", "")[:16],
            ]):
                self._cache_table.setItem(row, c, QTableWidgetItem(str(val)))

    def _on_cache_selected(self) -> None:
        row = self._cache_table.currentRow()
        if row < 0 or row >= len(self._cache_records):
            return
        # Match by value
        val_item = self._cache_table.item(row, 1)
        if not val_item:
            return
        rec = next((r for r in self._cache_records if r.get("value") == val_item.text()), None)
        if not rec:
            return
        try:
            raw = json.loads(rec.get("raw_data", "{}"))
            text = json.dumps(raw, indent=2)
        except Exception:
            text = rec.get("raw_data", "")
        self._cache_detail.setPlainText(text)

    def _on_case_changed(self, case_id) -> None:
        self._refresh_stats()
