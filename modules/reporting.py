"""
modules/reporting.py – Report generation module.
Generate PDF, HTML, Markdown, JSON, CSV, DOCX reports with AI summaries.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QSplitter,
    QLabel, QPushButton, QLineEdit, QTextEdit,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QWidget, QComboBox, QCheckBox, QGroupBox,
    QFileDialog, QMessageBox, QFormLayout,
    QProgressBar,
)

from modules.base_module import BaseModule
from core.report_engine import ReportEngine
from core.ai_client import AIClient

log = logging.getLogger(__name__)

_FORMATS = ["PDF", "HTML", "Markdown", "JSON", "CSV", "DOCX"]


class ReportThread(QThread):
    finished = Signal(str)
    error = Signal(str)

    def __init__(self, engine: ReportEngine, case_id: int, fmt: str,
                 output_path: Optional[Path], title: str, ai_summary: str) -> None:
        super().__init__()
        self._engine = engine
        self._case_id = case_id
        self._fmt = fmt
        self._output_path = output_path
        self._title = title
        self._ai_summary = ai_summary

    def run(self) -> None:
        try:
            path = self._engine.generate(
                self._case_id, self._fmt.lower(),
                self._output_path, self._title or None, self._ai_summary
            )
            self.finished.emit(str(path))
        except Exception as exc:
            self.error.emit(str(exc))


class AIReportThread(QThread):
    finished = Signal(str)
    error = Signal(str)

    def __init__(self, client: AIClient, prompt: str) -> None:
        super().__init__()
        self._client = client
        self._prompt = prompt

    def run(self) -> None:
        try:
            resp = self._client.complete(self._prompt)
            self.finished.emit(resp)
        except Exception as exc:
            self.error.emit(str(exc))


class ReportingModule(BaseModule):
    """Report generation and management."""

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(self._make_page_header(
            "Reporting",
            "Generate investigation reports in PDF, HTML, Markdown, JSON, CSV, DOCX"
        ))

        splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(splitter, 1)

        # ── Left: config panel ─────────────────────────────────────────────
        left = QWidget()
        left.setFixedWidth(340)
        left.setStyleSheet("background-color: #161B22; border-right: 1px solid #30363D;")
        ll = QVBoxLayout(left)
        ll.setContentsMargins(16, 16, 16, 16)
        ll.setSpacing(14)

        ll.addWidget(QLabel("Report Configuration"))

        form = QFormLayout()
        form.setSpacing(10)

        # Case selector
        self._case_combo = QComboBox()
        self._case_combo.setMinimumWidth(240)
        self._load_cases_combo()
        form.addRow("Case:", self._case_combo)

        # Report title
        self._title_edit = QLineEdit()
        self._title_edit.setPlaceholderText("Auto-generated if blank")
        form.addRow("Title:", self._title_edit)

        # Format
        self._format_combo = QComboBox()
        self._format_combo.addItems(_FORMATS)
        form.addRow("Format:", self._format_combo)

        # Output directory
        self._outdir_edit = QLineEdit()
        self._outdir_edit.setText(
            self._config.get("report_output_dir", str(Path.home() / "SentinelAI_Reports"))
        )
        browse_btn = QPushButton("…")
        browse_btn.setFixedWidth(30)
        browse_btn.clicked.connect(self._browse_outdir)
        outdir_row = QHBoxLayout()
        outdir_row.addWidget(self._outdir_edit)
        outdir_row.addWidget(browse_btn)
        form.addRow("Output Dir:", outdir_row)

        ll.addLayout(form)

        # AI summary option
        ai_group = QGroupBox("AI Summary")
        agl = QVBoxLayout(ai_group)
        self._ai_summary_cb = QCheckBox("Generate AI executive summary")
        self._ai_summary_cb.setChecked(True)
        agl.addWidget(self._ai_summary_cb)
        self._ai_summary_text = QTextEdit()
        self._ai_summary_text.setPlaceholderText(
            "AI-generated summary will appear here.\nOr type your own summary…"
        )
        self._ai_summary_text.setMaximumHeight(140)
        agl.addWidget(self._ai_summary_text)
        gen_ai_btn = QPushButton("🤖 Generate AI Summary")
        gen_ai_btn.clicked.connect(self._generate_ai_summary)
        agl.addWidget(gen_ai_btn)
        ll.addWidget(ai_group)

        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.setVisible(False)
        ll.addWidget(self._progress)

        self._status_lbl = QLabel("")
        self._status_lbl.setObjectName("AccentLabel")
        self._status_lbl.setWordWrap(True)
        ll.addWidget(self._status_lbl)

        ll.addStretch()

        gen_btn = self._primary_btn("📊 Generate Report")
        gen_btn.setMinimumHeight(40)
        gen_btn.clicked.connect(self._generate_report)
        ll.addWidget(gen_btn)

        splitter.addWidget(left)

        # ── Right: report history ──────────────────────────────────────────
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(14, 14, 14, 14)
        rl.setSpacing(10)

        rl.addWidget(QLabel("Generated Reports"))

        self._reports_table = QTableWidget(0, 5)
        self._reports_table.setHorizontalHeaderLabels(
            ["ID", "Case", "Title", "Format", "Generated"]
        )
        self._reports_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._reports_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._reports_table.setAlternatingRowColors(True)
        self._reports_table.verticalHeader().setVisible(False)
        self._reports_table.horizontalHeader().setStretchLastSection(True)
        self._reports_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self._reports_table.doubleClicked.connect(self._open_report)
        rl.addWidget(self._reports_table, 1)

        btn_row = QHBoxLayout()
        open_btn = QPushButton("📂 Open Selected")
        open_btn.clicked.connect(self._open_report)
        open_folder_btn = QPushButton("📁 Open Output Folder")
        open_folder_btn.clicked.connect(self._open_output_folder)
        refresh_btn = QPushButton("↺ Refresh")
        refresh_btn.clicked.connect(self._load_reports)
        btn_row.addWidget(open_btn)
        btn_row.addWidget(open_folder_btn)
        btn_row.addStretch()
        btn_row.addWidget(refresh_btn)
        rl.addLayout(btn_row)

        splitter.addWidget(right)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)

        self._report_engine = ReportEngine(self._config, self._db)
        self._ai_client = AIClient(self._config)
        self._report_thread: Optional[ReportThread] = None
        self._ai_thread: Optional[AIReportThread] = None
        self._load_reports()

    # ── Data ───────────────────────────────────────────────────────────────

    def _load_cases_combo(self) -> None:
        self._case_combo.clear()
        self._case_combo.addItem("— Select Case —", 0)
        rows = self._db.fetchall("SELECT id, title FROM cases ORDER BY created_at DESC")
        for r in rows:
            self._case_combo.addItem(r["title"], r["id"])
        # Pre-select active case
        if self._active_case_id:
            for i in range(self._case_combo.count()):
                if self._case_combo.itemData(i) == self._active_case_id:
                    self._case_combo.setCurrentIndex(i)
                    break

    def _load_reports(self) -> None:
        rows = self._db.fetchall(
            """SELECT r.id, c.title AS case_title, r.title, r.format, r.generated_at, r.file_path
               FROM reports r LEFT JOIN cases c ON r.case_id=c.id
               ORDER BY r.generated_at DESC LIMIT 200"""
        )
        self._reports_table.setRowCount(0)
        self._reports: list[dict] = [dict(r) for r in rows]
        for rep in self._reports:
            row = self._reports_table.rowCount()
            self._reports_table.insertRow(row)
            for c, val in enumerate([
                str(rep["id"]), rep.get("case_title", ""),
                rep["title"], rep["format"].upper(),
                rep["generated_at"][:16],
            ]):
                self._reports_table.setItem(row, c, QTableWidgetItem(str(val)))

    def _browse_outdir(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if folder:
            self._outdir_edit.setText(folder)
            self._config.set("report_output_dir", folder)

    # ── Report generation ──────────────────────────────────────────────────

    def _generate_report(self) -> None:
        case_id = self._case_combo.currentData()
        if not case_id:
            QMessageBox.warning(self, "No Case", "Select a case to report on.")
            return
        fmt = self._format_combo.currentText()
        title = self._title_edit.text().strip()
        out_dir = self._outdir_edit.text().strip()
        ai_summary = self._ai_summary_text.toPlainText().strip() \
                     if self._ai_summary_cb.isChecked() else ""

        if out_dir:
            self._config.set("report_output_dir", out_dir)

        self._progress.setVisible(True)
        self._status_lbl.setText(f"Generating {fmt} report…")

        self._report_thread = ReportThread(
            self._report_engine, case_id, fmt, None, title, ai_summary
        )
        self._report_thread.finished.connect(self._on_report_done)
        self._report_thread.error.connect(self._on_report_error)
        self._report_thread.start()

    def _on_report_done(self, path: str) -> None:
        self._progress.setVisible(False)
        self._status_lbl.setText(f"✓ Report saved:\n{path}")
        self._audit.record("report_generated", f"Report: {path}")
        self._load_reports()

        reply = QMessageBox.question(
            self, "Report Generated",
            f"Report saved to:\n{path}\n\nOpen it now?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self._open_file(path)

    def _on_report_error(self, msg: str) -> None:
        self._progress.setVisible(False)
        self._status_lbl.setText("✗ Generation failed")
        QMessageBox.critical(self, "Report Error", msg)

    # ── AI summary ─────────────────────────────────────────────────────────

    def _generate_ai_summary(self) -> None:
        case_id = self._case_combo.currentData()
        if not case_id:
            QMessageBox.warning(self, "No Case", "Select a case first.")
            return
        _case_row = self._db.fetchone("SELECT * FROM cases WHERE id=?", (case_id,))
        if not _case_row:
            return
        case = dict(_case_row)
        _r1 = self._db.fetchone("SELECT COUNT(*) AS c FROM log_events WHERE case_id=?", (case_id,))
        ev_count = _r1["c"] if _r1 else 0
        _r2 = self._db.fetchone("SELECT COUNT(*) AS c FROM log_events WHERE case_id=? AND flagged=1", (case_id,))
        flagged = _r2["c"] if _r2 else 0
        iocs = self._db.fetchall(
            "SELECT ioc_type, value, threat_type FROM iocs WHERE case_id=? LIMIT 20", (case_id,)
        )
        ioc_text = "\n".join(f"  [{r['ioc_type']}] {r['value']} ({r['threat_type']})" for r in iocs)
        tl_entries = self._db.fetchall(
            "SELECT timestamp, event_type, description FROM timeline_entries WHERE case_id=? ORDER BY timestamp LIMIT 20",
            (case_id,)
        )
        tl_text = "\n".join(
            f"  {r['timestamp'][:16]}  {r['event_type']}: {r['description'][:80]}"
            for r in tl_entries
        )
        prompt = (
            f"Write a professional executive summary for the following DFIR investigation case.\n\n"
            f"Case: {case['title']}\n"
            f"Severity: {case['severity'].upper()}\n"
            f"Description: {case.get('description','')}\n"
            f"Log Events: {ev_count:,} (flagged: {flagged})\n\n"
            f"IOCs:\n{ioc_text}\n\n"
            f"Timeline:\n{tl_text}\n\n"
            f"Write a 3-4 paragraph executive summary covering: what happened, "
            f"attack timeline, impact, and recommended actions."
        )
        self._ai_summary_text.setPlainText("Generating AI summary…")
        self._ai_thread = AIReportThread(self._ai_client, prompt)
        self._ai_thread.finished.connect(self._ai_summary_text.setPlainText)
        self._ai_thread.error.connect(
            lambda e: self._ai_summary_text.setPlainText(f"AI error: {e}")
        )
        self._ai_thread.start()

    # ── File operations ────────────────────────────────────────────────────

    def _open_report(self) -> None:
        row = self._reports_table.currentRow()
        if row < 0 or row >= len(self._reports):
            return
        path = self._reports[row].get("file_path", "")
        if path:
            self._open_file(path)

    @staticmethod
    def _open_file(path: str) -> None:
        import subprocess, sys
        try:
            if sys.platform == "win32":
                import os
                os.startfile(path)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception as exc:
            log.error("Could not open file: %s", exc)

    def _open_output_folder(self) -> None:
        folder = self._outdir_edit.text().strip()
        if folder:
            self._open_file(folder)

    def _on_case_changed(self, case_id) -> None:
        self._load_cases_combo()
        self._load_reports()
