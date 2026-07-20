"""
modules/memory_analysis.py – Memory dump analysis.
Parses Windows memory dumps for processes, network connections,
strings, and suspicious artifacts. Integrates with Volatility3 if available.
"""

from __future__ import annotations

import logging
import re
import struct
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QSplitter,
    QLabel, QPushButton, QLineEdit, QTextEdit,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QWidget, QTabWidget, QFileDialog,
    QMessageBox, QProgressBar, QComboBox,
)

from modules.base_module import BaseModule

log = logging.getLogger(__name__)


def _extract_strings(data: bytes, min_len: int = 6) -> list[str]:
    ascii_re = re.compile(rb'[ -~]{%d,}' % min_len)
    return [m.group().decode("ascii", errors="replace") for m in ascii_re.finditer(data)]


def _scan_ips(data: bytes) -> list[str]:
    """Extract IPv4 addresses from raw bytes."""
    pattern = re.compile(
        rb'(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'
    )
    seen: set[str] = set()
    results = []
    for m in pattern.finditer(data):
        ip = m.group().decode()
        if ip not in seen and not ip.startswith(("0.", "127.", "169.254.", "255.")):
            seen.add(ip)
            results.append(ip)
    return results


def _scan_urls(strings: list[str]) -> list[str]:
    pattern = re.compile(r'https?://[^\s"\'<>\x00]{8,}', re.I)
    seen: set[str] = set()
    results = []
    for s in strings:
        for m in pattern.finditer(s):
            url = m.group()
            if url not in seen:
                seen.add(url)
                results.append(url)
    return results


def _try_volatility(path: Path, plugin: str) -> Optional[str]:
    """Attempt to run a Volatility3 plugin, returning text output."""
    try:
        import subprocess
        result = subprocess.run(
            ["vol", "-f", str(path), plugin],
            capture_output=True, text=True, timeout=120,
        )
        return result.stdout if result.returncode == 0 else None
    except Exception:
        return None


class MemoryParseThread(QThread):
    progress = Signal(str)
    finished = Signal(dict)
    error = Signal(str)

    def __init__(self, path: Path) -> None:
        super().__init__()
        self._path = path

    def run(self) -> None:
        try:
            result = self._analyse(self._path)
            self.finished.emit(result)
        except Exception as exc:
            self.error.emit(str(exc))

    def _analyse(self, path: Path) -> dict:
        self.progress.emit("Reading dump…")
        size = path.stat().st_size

        # Try Volatility3 first
        vol_pslist = _try_volatility(path, "windows.pslist.PsList")
        vol_netscan = _try_volatility(path, "windows.netscan.NetScan")
        vol_cmdline = _try_volatility(path, "windows.cmdline.CmdLine")
        vol_malfind = _try_volatility(path, "windows.malfind.Malfind")

        self.progress.emit("Extracting strings…")
        # Read up to 256 MB for string extraction
        chunk_size = min(size, 256 * 1024 * 1024)
        with path.open("rb") as f:
            data = f.read(chunk_size)

        self.progress.emit("Scanning for IOCs…")
        strings = _extract_strings(data)
        ips = _scan_ips(data)
        urls = _scan_urls(strings)

        # Suspicious string patterns
        suspicious_patterns = [
            r'cmd\.exe', r'powershell', r'mimikatz', r'meterpreter',
            r'cobalt.?strike', r'CreateRemoteThread', r'VirtualAlloc',
            r'WriteProcessMemory', r'ShellCode', r'base64', r'net\.exe',
            r'whoami', r'lsass', r'procdump', r'wce\.exe', r'fgdump',
        ]
        suspicious = [
            s for s in strings
            if any(re.search(p, s, re.I) for p in suspicious_patterns)
        ]

        return {
            "path": str(path),
            "name": path.name,
            "size": size,
            "strings_count": len(strings),
            "ips": ips[:200],
            "urls": urls[:100],
            "suspicious_strings": suspicious[:500],
            "volatility": {
                "pslist":  vol_pslist,
                "netscan": vol_netscan,
                "cmdline": vol_cmdline,
                "malfind": vol_malfind,
            },
            "has_volatility": bool(vol_pslist),
        }


class MemoryAnalysisModule(BaseModule):
    """Memory dump analysis module."""

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(self._make_page_header(
            "Memory Analysis",
            "Analyse memory dumps — processes, network, strings, IOCs, Volatility3 integration"
        ))

        # File bar
        file_bar = QWidget()
        file_bar.setStyleSheet("background-color: #161B22; border-bottom: 1px solid #30363D;")
        fb = QHBoxLayout(file_bar)
        fb.setContentsMargins(14, 10, 14, 10)

        open_btn = self._primary_btn("📂 Open Dump")
        open_btn.clicked.connect(self._open_dump)
        self._file_lbl = QLabel("No dump loaded")
        self._file_lbl.setObjectName("Muted")
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.setFixedWidth(180)
        self._progress.setVisible(False)
        self._status_lbl = QLabel("")
        self._status_lbl.setObjectName("AccentLabel")

        fb.addWidget(open_btn)
        fb.addWidget(self._file_lbl)
        fb.addStretch()
        fb.addWidget(self._status_lbl)
        fb.addWidget(self._progress)
        layout.addWidget(file_bar)

        # Tabs
        tabs = QTabWidget()
        layout.addWidget(tabs, 1)

        # ── Overview ──────────────────────────────────────────────────────
        overview = QWidget()
        ol = QVBoxLayout(overview)
        ol.setContentsMargins(14, 14, 14, 14)
        self._overview_text = QTextEdit()
        self._overview_text.setReadOnly(True)
        self._overview_text.setStyleSheet(
            "font-family: 'Cascadia Code','JetBrains Mono',monospace; font-size: 12px;"
        )
        ol.addWidget(self._overview_text)
        tabs.addTab(overview, "Overview")

        # ── Processes (Volatility) ─────────────────────────────────────────
        ps_tab = QWidget()
        psl = QVBoxLayout(ps_tab)
        psl.setContentsMargins(14, 14, 14, 14)
        self._pslist_text = QTextEdit()
        self._pslist_text.setReadOnly(True)
        self._pslist_text.setStyleSheet(
            "font-family: monospace; font-size: 12px; background-color: #0D1117;"
        )
        psl.addWidget(self._pslist_text)
        tabs.addTab(ps_tab, "Processes")

        # ── Network (Volatility) ───────────────────────────────────────────
        net_tab = QWidget()
        netl = QVBoxLayout(net_tab)
        netl.setContentsMargins(14, 14, 14, 14)
        self._netscan_text = QTextEdit()
        self._netscan_text.setReadOnly(True)
        self._netscan_text.setStyleSheet(
            "font-family: monospace; font-size: 12px; background-color: #0D1117;"
        )
        netl.addWidget(self._netscan_text)
        tabs.addTab(net_tab, "Network")

        # ── Extracted IPs ─────────────────────────────────────────────────
        ips_tab = QWidget()
        ipl = QVBoxLayout(ips_tab)
        ipl.setContentsMargins(0, 0, 0, 0)
        self._ips_table = self._make_table(["IP Address"])
        ipl.addWidget(self._ips_table)

        add_iocs_btn = self._primary_btn("+ Add All IPs as IOCs")
        add_iocs_btn.clicked.connect(self._add_ips_as_iocs)
        ipl.addWidget(add_iocs_btn)
        tabs.addTab(ips_tab, "Extracted IPs")

        # ── URLs ──────────────────────────────────────────────────────────
        url_tab = QWidget()
        urll = QVBoxLayout(url_tab)
        urll.setContentsMargins(0, 0, 0, 0)
        self._urls_table = self._make_table(["URL"])
        urll.addWidget(self._urls_table)
        tabs.addTab(url_tab, "Extracted URLs")

        # ── Suspicious Strings ────────────────────────────────────────────
        susp_tab = QWidget()
        suspl = QVBoxLayout(susp_tab)
        suspl.setContentsMargins(14, 14, 14, 14)
        str_filter = QLineEdit()
        str_filter.setPlaceholderText("Filter suspicious strings…")
        str_filter.textChanged.connect(self._filter_strings)
        suspl.addWidget(str_filter)
        self._susp_table = self._make_table(["Suspicious String"])
        suspl.addWidget(self._susp_table)
        tabs.addTab(susp_tab, "Suspicious Strings")

        # ── Malfind ───────────────────────────────────────────────────────
        mf_tab = QWidget()
        mfl = QVBoxLayout(mf_tab)
        mfl.setContentsMargins(14, 14, 14, 14)
        self._malfind_text = QTextEdit()
        self._malfind_text.setReadOnly(True)
        self._malfind_text.setStyleSheet(
            "font-family: monospace; font-size: 12px; background-color: #0D1117; color: #F85149;"
        )
        mfl.addWidget(self._malfind_text)
        tabs.addTab(mf_tab, "Malfind")

        self._result: Optional[dict] = None
        self._thread: Optional[MemoryParseThread] = None
        self._all_suspicious: list[str] = []

    @staticmethod
    def _make_table(headers: list[str]) -> QTableWidget:
        t = QTableWidget(0, len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.setEditTriggers(QTableWidget.NoEditTriggers)
        t.setSelectionBehavior(QTableWidget.SelectRows)
        t.setAlternatingRowColors(True)
        t.verticalHeader().setVisible(False)
        t.horizontalHeader().setStretchLastSection(True)
        return t

    def _open_dump(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Memory Dump", str(Path.home()),
            "Memory Dumps (*.dmp *.mem *.raw *.vmem *.bin);;All Files (*.*)",
        )
        if not path:
            return
        self._file_lbl.setText(f"Analysing: {Path(path).name}…")
        self._progress.setVisible(True)
        self._thread = MemoryParseThread(Path(path))
        self._thread.progress.connect(lambda m: self._status_lbl.setText(m))
        self._thread.finished.connect(self._on_done)
        self._thread.error.connect(self._on_error)
        self._thread.start()

    def _on_done(self, result: dict) -> None:
        self._result = result
        self._progress.setVisible(False)
        self._file_lbl.setText(result["name"])
        self._status_lbl.setText("✓ Analysis complete")
        self._populate(result)
        self._audit.record("memory_analysis", f"Memory dump analysed: {result['name']}")

    def _on_error(self, msg: str) -> None:
        self._progress.setVisible(False)
        self._status_lbl.setText("✗ Failed")
        QMessageBox.critical(self, "Memory Analysis Error", msg)

    def _populate(self, r: dict) -> None:
        vol = r.get("volatility", {})
        vol_note = "✓ Volatility3 available" if r.get("has_volatility") else \
                   "⚠ Volatility3 not found — install vol3 for process/network analysis"

        self._overview_text.setPlainText(
            f"File:           {r['name']}\n"
            f"Size:           {r['size']:,} bytes ({r['size'] / (1024**3):.2f} GB)\n"
            f"Strings found:  {r['strings_count']:,}\n"
            f"Extracted IPs:  {len(r['ips'])}\n"
            f"Extracted URLs: {len(r['urls'])}\n"
            f"Suspicious:     {len(r['suspicious_strings'])}\n\n"
            f"Volatility3:    {vol_note}\n"
        )

        # Processes
        self._pslist_text.setPlainText(
            vol.get("pslist") or
            "Volatility3 not available.\n\nInstall with: pip install volatility3\n"
            "Then ensure 'vol' is on PATH."
        )

        # Network
        self._netscan_text.setPlainText(
            vol.get("netscan") or "Volatility3 not available or no network connections found."
        )

        # Malfind
        self._malfind_text.setPlainText(
            vol.get("malfind") or "Volatility3 not available or no malfind results."
        )

        # IPs
        self._ips_table.setRowCount(0)
        for ip in r["ips"]:
            row = self._ips_table.rowCount()
            self._ips_table.insertRow(row)
            self._ips_table.setItem(row, 0, QTableWidgetItem(ip))

        # URLs
        self._urls_table.setRowCount(0)
        for url in r["urls"]:
            row = self._urls_table.rowCount()
            self._urls_table.insertRow(row)
            self._urls_table.setItem(row, 0, QTableWidgetItem(url))

        # Suspicious strings
        self._all_suspicious = r["suspicious_strings"]
        self._render_suspicious(self._all_suspicious)

    def _render_suspicious(self, items: list[str]) -> None:
        self._susp_table.setRowCount(0)
        for s in items:
            row = self._susp_table.rowCount()
            self._susp_table.insertRow(row)
            self._susp_table.setItem(row, 0, QTableWidgetItem(s))

    def _filter_strings(self, query: str) -> None:
        q = query.lower()
        filtered = [s for s in self._all_suspicious if q in s.lower()] if q else self._all_suspicious
        self._render_suspicious(filtered)

    def _add_ips_as_iocs(self) -> None:
        if not self._result or not self._active_case_id:
            QMessageBox.warning(self, "No Case", "Activate a case and load a dump first.")
            return
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        count = 0
        for ip in self._result["ips"]:
            self._db.insert(
                """INSERT OR IGNORE INTO iocs
                   (case_id, ioc_type, value, confidence, source, first_seen, last_seen)
                   VALUES (?,?,?,?,?,?,?)""",
                (self._active_case_id, "ip", ip, "medium", "memory_analysis", now, now),
            )
            count += 1
        self._audit.record("ioc_bulk_add", f"Added {count} IPs from memory dump as IOCs")
        QMessageBox.information(self, "IOCs Added", f"Added {count} IP addresses as IOCs.")

    def _on_case_changed(self, case_id) -> None:
        pass
