"""
modules/pcap_analysis.py – PCAP network capture analysis.
Uses scapy for packet parsing; falls back to raw hex if unavailable.
"""

from __future__ import annotations

import logging
import struct
from collections import defaultdict
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


class PCAPParseThread(QThread):
    progress = Signal(int, int)
    finished = Signal(dict)
    error = Signal(str)

    def __init__(self, path: Path) -> None:
        super().__init__()
        self._path = path

    def run(self) -> None:
        try:
            result = self._parse(self._path)
            self.finished.emit(result)
        except Exception as exc:
            self.error.emit(str(exc))

    def _parse(self, path: Path) -> dict:
        try:
            from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw, Ether
            packets = rdpcap(str(path))
        except ImportError:
            return self._parse_raw(path)

        conversations: dict[tuple, dict] = defaultdict(lambda: {
            "packets": 0, "bytes": 0, "start": None, "end": None,
            "flags": set(), "payload_samples": [],
        })
        dns_queries: list[dict] = []
        http_requests: list[dict] = []
        top_talkers: dict[str, int] = defaultdict(int)
        protocols: dict[str, int] = defaultdict(int)
        alerts: list[str] = []

        for i, pkt in enumerate(packets):
            self.progress.emit(i + 1, len(packets))
            ts = float(pkt.time)

            if pkt.haslayer("IP"):
                src_ip = pkt["IP"].src
                dst_ip = pkt["IP"].dst
                top_talkers[src_ip] += 1
                proto = "TCP" if pkt.haslayer("TCP") else \
                        "UDP" if pkt.haslayer("UDP") else \
                        "ICMP" if pkt.haslayer("ICMP") else "OTHER"
                protocols[proto] += 1

                src_port = dst_port = 0
                flags = ""
                if pkt.haslayer("TCP"):
                    src_port = pkt["TCP"].sport
                    dst_port = pkt["TCP"].dport
                    flag_int = pkt["TCP"].flags
                    flags = str(flag_int)
                elif pkt.haslayer("UDP"):
                    src_port = pkt["UDP"].sport
                    dst_port = pkt["UDP"].dport

                key = (src_ip, dst_ip, src_port, dst_port, proto)
                conv = conversations[key]
                conv["packets"] += 1
                conv["bytes"] += len(pkt)
                if conv["start"] is None:
                    conv["start"] = ts
                conv["end"] = ts
                if flags:
                    conv["flags"].add(flags)

                # DNS
                if pkt.haslayer("DNS") and pkt.haslayer("DNSQR"):
                    try:
                        qname = pkt["DNSQR"].qname.decode(errors="replace").rstrip(".")
                        dns_queries.append({
                            "src": src_ip, "dst": dst_ip,
                            "query": qname, "type": pkt["DNSQR"].qtype,
                        })
                        if len(qname) > 100:
                            alerts.append(f"Long DNS query (possible tunneling): {qname[:80]}")
                    except Exception:
                        pass

                # HTTP (port 80)
                if dst_port == 80 and pkt.haslayer("Raw"):
                    try:
                        raw = pkt["Raw"].load.decode("utf-8", errors="replace")
                        if raw.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ")):
                            lines = raw.split("\r\n")
                            http_requests.append({
                                "src": src_ip, "dst": dst_ip,
                                "request": lines[0][:200],
                                "host": next((l[6:] for l in lines if l.lower().startswith("host:")), ""),
                            })
                    except Exception:
                        pass

                # Port scan detection
                if proto == "TCP" and flags == "2":  # SYN only
                    pass  # tracked separately

        # Detect port scans: >20 unique dst_ports from same src
        src_dst_ports: dict[str, set] = defaultdict(set)
        for (src, dst, sp, dp, proto), _ in conversations.items():
            if proto == "TCP":
                src_dst_ports[src].add(dp)
        for src, ports in src_dst_ports.items():
            if len(ports) > 20:
                alerts.append(f"Port scan detected from {src}: {len(ports)} ports")

        sessions = []
        for (src_ip, dst_ip, src_port, dst_port, proto), conv in conversations.items():
            sessions.append({
                "src_ip": src_ip, "dst_ip": dst_ip,
                "src_port": src_port, "dst_port": dst_port,
                "protocol": proto,
                "packets": conv["packets"], "bytes": conv["bytes"],
                "start": conv["start"], "end": conv["end"],
                "flags": ",".join(conv["flags"]),
            })

        return {
            "total_packets": len(packets),
            "sessions": sorted(sessions, key=lambda x: x["bytes"], reverse=True)[:500],
            "dns_queries": dns_queries[:500],
            "http_requests": http_requests[:200],
            "top_talkers": sorted(top_talkers.items(), key=lambda x: x[1], reverse=True)[:20],
            "protocols": dict(protocols),
            "alerts": alerts,
        }

    def _parse_raw(self, path: Path) -> dict:
        """Minimal PCAP parser without scapy (reads global header + packet records)."""
        data = path.read_bytes()
        if len(data) < 24:
            return {"error": "File too small", "total_packets": 0}
        magic = struct.unpack_from("<I", data, 0)[0]
        if magic not in (0xA1B2C3D4, 0xD4C3B2A1):
            return {"error": "Not a valid PCAP file", "total_packets": 0}
        offset = 24
        count = 0
        while offset + 16 <= len(data):
            incl_len = struct.unpack_from("<I", data, offset + 8)[0]
            offset += 16 + incl_len
            count += 1
        return {
            "total_packets": count,
            "sessions": [],
            "dns_queries": [],
            "http_requests": [],
            "top_talkers": [],
            "protocols": {},
            "alerts": ["Install scapy for full PCAP analysis: pip install scapy"],
        }


class PCAPModule(BaseModule):
    """PCAP network capture analysis module."""

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(self._make_page_header(
            "PCAP Analysis",
            "Parse network captures — sessions, DNS, HTTP, protocol breakdown, anomalies"
        ))

        # File bar
        file_bar = QWidget()
        file_bar.setStyleSheet("background-color: #161B22; border-bottom: 1px solid #30363D;")
        fb = QHBoxLayout(file_bar)
        fb.setContentsMargins(14, 10, 14, 10)
        self._file_label = QLabel("No PCAP loaded")
        self._file_label.setObjectName("Muted")
        open_btn = self._primary_btn("📂 Open PCAP")
        open_btn.clicked.connect(self._open_pcap)
        self._progress = QProgressBar()
        self._progress.setFixedWidth(180)
        self._progress.setVisible(False)
        self._filter_edit = QLineEdit()
        self._filter_edit.setPlaceholderText("Filter by IP, port, protocol…")
        self._filter_edit.setFixedWidth(240)
        self._filter_edit.textChanged.connect(self._apply_filter)
        fb.addWidget(open_btn)
        fb.addWidget(self._file_label)
        fb.addStretch()
        fb.addWidget(self._filter_edit)
        fb.addWidget(self._progress)
        layout.addWidget(file_bar)

        # Tabs
        tabs = QTabWidget()
        layout.addWidget(tabs, 1)

        # ── Overview tab ─────────────────────────────────────────────────
        overview_tab = QWidget()
        ol = QVBoxLayout(overview_tab)
        ol.setContentsMargins(14, 14, 14, 14)
        self._overview_text = QTextEdit()
        self._overview_text.setReadOnly(True)
        self._overview_text.setStyleSheet("font-family: monospace; font-size: 12px;")
        ol.addWidget(self._overview_text)
        tabs.addTab(overview_tab, "Overview")

        # ── Sessions tab ──────────────────────────────────────────────────
        sessions_tab = QWidget()
        sl = QVBoxLayout(sessions_tab)
        sl.setContentsMargins(0, 0, 0, 0)
        self._sessions_table = self._make_table([
            "Src IP", "Dst IP", "Src Port", "Dst Port",
            "Protocol", "Packets", "Bytes", "Duration",
        ])
        sl.addWidget(self._sessions_table)
        tabs.addTab(sessions_tab, "Sessions")

        # ── DNS tab ───────────────────────────────────────────────────────
        dns_tab = QWidget()
        dl = QVBoxLayout(dns_tab)
        dl.setContentsMargins(0, 0, 0, 0)
        self._dns_table = self._make_table(["Source IP", "Dest IP", "Query", "Type"])
        dl.addWidget(self._dns_table)
        tabs.addTab(dns_tab, "DNS Queries")

        # ── HTTP tab ──────────────────────────────────────────────────────
        http_tab = QWidget()
        hl = QVBoxLayout(http_tab)
        hl.setContentsMargins(0, 0, 0, 0)
        self._http_table = self._make_table(["Source IP", "Dest IP", "Host", "Request"])
        hl.addWidget(self._http_table)
        tabs.addTab(http_tab, "HTTP")

        # ── Top Talkers tab ───────────────────────────────────────────────
        talkers_tab = QWidget()
        tl = QVBoxLayout(talkers_tab)
        tl.setContentsMargins(0, 0, 0, 0)
        self._talkers_table = self._make_table(["IP Address", "Packet Count"])
        tl.addWidget(self._talkers_table)
        tabs.addTab(talkers_tab, "Top Talkers")

        # ── Alerts tab ────────────────────────────────────────────────────
        alerts_tab = QWidget()
        al = QVBoxLayout(alerts_tab)
        al.setContentsMargins(14, 14, 14, 14)
        self._alerts_text = QTextEdit()
        self._alerts_text.setReadOnly(True)
        self._alerts_text.setStyleSheet(
            "background-color: #0D1117; color: #F85149; font-family: monospace; font-size: 12px;"
        )
        al.addWidget(self._alerts_text)
        tabs.addTab(alerts_tab, "Alerts ⚠")

        self._result: Optional[dict] = None
        self._parse_thread: Optional[PCAPParseThread] = None

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

    def _open_pcap(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open PCAP File", str(Path.home()),
            "PCAP Files (*.pcap *.pcapng *.cap);;All Files (*.*)",
        )
        if not path:
            return
        self._file_label.setText(f"Parsing: {Path(path).name}…")
        self._progress.setRange(0, 0)
        self._progress.setVisible(True)
        self._parse_thread = PCAPParseThread(Path(path))
        self._parse_thread.progress.connect(
            lambda c, t: (self._progress.setRange(0, t), self._progress.setValue(c))
        )
        self._parse_thread.finished.connect(self._on_parsed)
        self._parse_thread.error.connect(self._on_error)
        self._parse_thread.start()

    def _on_parsed(self, result: dict) -> None:
        self._result = result
        self._progress.setVisible(False)
        self._file_label.setText(f"Loaded — {result.get('total_packets', 0):,} packets")
        self._populate_all(result)
        self._audit.record("pcap_analysis", f"PCAP parsed: {result.get('total_packets',0)} packets")

    def _on_error(self, msg: str) -> None:
        self._progress.setVisible(False)
        self._file_label.setText("Parse failed")
        QMessageBox.critical(self, "PCAP Error", msg)

    def _populate_all(self, r: dict) -> None:
        # Overview
        protocols_str = "  ".join(f"{k}: {v}" for k, v in r.get("protocols", {}).items())
        self._overview_text.setPlainText(
            f"Total Packets:   {r.get('total_packets', 0):,}\n"
            f"Sessions:        {len(r.get('sessions', []))}\n"
            f"DNS Queries:     {len(r.get('dns_queries', []))}\n"
            f"HTTP Requests:   {len(r.get('http_requests', []))}\n"
            f"Alerts:          {len(r.get('alerts', []))}\n\n"
            f"Protocols:\n  {protocols_str}\n\n"
            f"Top Talkers:\n" +
            "\n".join(f"  {ip}: {cnt} packets" for ip, cnt in r.get("top_talkers", []))
        )

        # Sessions
        self._sessions_table.setRowCount(0)
        for s in r.get("sessions", []):
            row = self._sessions_table.rowCount()
            self._sessions_table.insertRow(row)
            duration = ""
            if s.get("start") and s.get("end"):
                duration = f"{s['end'] - s['start']:.2f}s"
            for c, val in enumerate([
                s["src_ip"], s["dst_ip"], str(s["src_port"]), str(s["dst_port"]),
                s["protocol"], str(s["packets"]), f"{s['bytes']:,}", duration,
            ]):
                self._sessions_table.setItem(row, c, QTableWidgetItem(val))

        # DNS
        self._dns_table.setRowCount(0)
        for d in r.get("dns_queries", []):
            row = self._dns_table.rowCount()
            self._dns_table.insertRow(row)
            for c, val in enumerate([d["src"], d["dst"], d["query"], str(d["type"])]):
                self._dns_table.setItem(row, c, QTableWidgetItem(val))

        # HTTP
        self._http_table.setRowCount(0)
        for h in r.get("http_requests", []):
            row = self._http_table.rowCount()
            self._http_table.insertRow(row)
            for c, val in enumerate([h["src"], h["dst"], h.get("host", ""), h["request"]]):
                self._http_table.setItem(row, c, QTableWidgetItem(val))

        # Top Talkers
        self._talkers_table.setRowCount(0)
        for ip, cnt in r.get("top_talkers", []):
            row = self._talkers_table.rowCount()
            self._talkers_table.insertRow(row)
            self._talkers_table.setItem(row, 0, QTableWidgetItem(ip))
            self._talkers_table.setItem(row, 1, QTableWidgetItem(str(cnt)))

        # Alerts
        alerts = r.get("alerts", [])
        self._alerts_text.setPlainText(
            "\n".join(f"⚠  {a}" for a in alerts) if alerts else "No alerts detected."
        )

    def _apply_filter(self, query: str) -> None:
        if not self._result or not query:
            if self._result:
                self._populate_all(self._result)
            return
        q = query.lower()
        filtered = {**self._result}
        filtered["sessions"] = [
            s for s in self._result.get("sessions", [])
            if q in s["src_ip"].lower() or q in s["dst_ip"].lower()
            or q in str(s["src_port"]) or q in str(s["dst_port"])
            or q in s["protocol"].lower()
        ]
        filtered["dns_queries"] = [
            d for d in self._result.get("dns_queries", [])
            if q in d["src"].lower() or q in d["query"].lower()
        ]
        self._populate_all(filtered)
