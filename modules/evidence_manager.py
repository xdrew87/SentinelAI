"""
modules/evidence_manager.py – Evidence ingestion, hashing, and management.
Supports drag-and-drop file ingestion with background parsing.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, QThread, Signal, QRunnable, QThreadPool, QObject
from PySide6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QSplitter,
    QLabel, QPushButton, QLineEdit, QTextEdit,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QWidget, QDialog, QDialogButtonBox, QFormLayout,
    QFileDialog, QMessageBox, QProgressBar, QFrame,
    QApplication,
)

from modules.base_module import BaseModule
from core.evidence_parser import EvidenceParser

log = logging.getLogger(__name__)


class IngestWorker(QObject):
    """Background worker for evidence ingestion."""

    progress = Signal(int, int)   # (current, total)
    finished = Signal(int, str)   # (evidence_id, file_name)
    error = Signal(str)

    def __init__(self, parser: EvidenceParser, case_id: int, file_path: Path) -> None:
        super().__init__()
        self._parser = parser
        self._case_id = case_id
        self._file_path = file_path

    def run(self) -> None:
        try:
            ev_id = self._parser.ingest(
                self._case_id,
                self._file_path,
                progress_cb=lambda cur, tot: self.progress.emit(cur, tot),
            )
            self.finished.emit(ev_id, self._file_path.name)
        except Exception as exc:
            self.error.emit(str(exc))


class IngestThread(QThread):
    """QThread wrapper for evidence ingestion."""

    progress = Signal(int, int)
    finished = Signal(int, str)
    error = Signal(str)

    def __init__(self, parser: EvidenceParser, case_id: int, file_path: Path) -> None:
        super().__init__()
        self._parser = parser
        self._case_id = case_id
        self._file_path = file_path

    def run(self) -> None:
        try:
            ev_id = self._parser.ingest(
                self._case_id,
                self._file_path,
                progress_cb=lambda cur, tot: self.progress.emit(cur, tot),
            )
            self.finished.emit(ev_id, self._file_path.name)
        except Exception as exc:
            self.error.emit(str(exc))


class EvidenceManagerModule(BaseModule):
    """Evidence file management with background ingestion."""

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(self._make_page_header(
            "Evidence Manager",
            "Ingest and manage evidence files — EVTX, PCAP, logs, memory dumps and more"
        ))

        # Toolbar
        self._search_edit = QLineEdit()
        self._search_edit.setPlaceholderText("Search evidence…")
        self._search_edit.setFixedWidth(260)
        self._search_edit.textChanged.connect(self._filter)

        add_btn = self._primary_btn("＋ Add Evidence")
        add_btn.clicked.connect(self._add_evidence)

        add_dir_btn = QPushButton("📂 Add Folder")
        add_dir_btn.clicked.connect(self._add_folder)

        self._progress_bar = QProgressBar()
        self._progress_bar.setFixedWidth(220)
        self._progress_bar.setVisible(False)

        self._progress_label = QLabel("")
        self._progress_label.setObjectName("Muted")

        layout.addWidget(self._make_toolbar(
            self._search_edit, None,
            self._progress_label, self._progress_bar,
            add_dir_btn, add_btn,
        ))

        # Main splitter
        splitter = QSplitter(Qt.Horizontal)

        # Evidence table
        self._table = QTableWidget(0, 7)
        self._table.setHorizontalHeaderLabels(
            ["ID", "File Name", "Type", "Size", "SHA-256", "MD5", "Added"]
        )
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
        detail.setMinimumWidth(320)
        detail.setMaximumWidth(420)
        detail.setStyleSheet("background-color: #161B22; border-left: 1px solid #30363D;")
        dl = QVBoxLayout(detail)
        dl.setContentsMargins(16, 16, 16, 16)
        dl.setSpacing(10)

        lbl = QLabel("Evidence Details")
        lbl.setObjectName("SectionTitle")
        dl.addWidget(lbl)

        self._detail_lbl = QLabel("Select an evidence file to view details.")
        self._detail_lbl.setWordWrap(True)
        self._detail_lbl.setStyleSheet("color: #8B949E; background: transparent;")
        dl.addWidget(self._detail_lbl)

        self._notes_edit = QTextEdit()
        self._notes_edit.setPlaceholderText("Notes about this evidence file…")
        self._notes_edit.setMaximumHeight(120)
        dl.addWidget(QLabel("Notes:"))
        dl.addWidget(self._notes_edit)

        save_notes_btn = QPushButton("Save Notes")
        save_notes_btn.clicked.connect(self._save_notes)
        dl.addWidget(save_notes_btn)

        dl.addStretch()

        parse_btn = self._primary_btn("⚙ Re-parse File")
        parse_btn.clicked.connect(self._reparse_selected)
        del_btn = self._danger_btn("🗑 Remove Evidence")
        del_btn.clicked.connect(self._delete_selected)
        dl.addWidget(parse_btn)
        dl.addWidget(del_btn)

        splitter.addWidget(detail)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter, 1)

        self._evidence: list[dict] = []
        self._selected_id: Optional[int] = None
        self._active_thread: Optional[IngestThread] = None
        self._load_evidence()

    # ── Data ───────────────────────────────────────────────────────────────

    def _load_evidence(self) -> None:
        if self._active_case_id:
            rows = self._db.fetchall(
                "SELECT * FROM evidence WHERE case_id=? ORDER BY created_at DESC",
                (self._active_case_id,),
            )
        else:
            rows = self._db.fetchall(
                "SELECT * FROM evidence ORDER BY created_at DESC LIMIT 200"
            )
        self._evidence = [dict(r) for r in rows]
        self._populate_table(self._evidence)

    def _populate_table(self, items: list[dict]) -> None:
        self._table.setRowCount(0)
        for ev in items:
            r = self._table.rowCount()
            self._table.insertRow(r)
            size_kb = f"{ev['file_size'] // 1024:,} KB" if ev["file_size"] else "—"
            sha = ev.get("sha256", "")
            sha_short = sha[:16] + "…" if sha else ""
            md5 = ev.get("md5", "")[:16]
            vals = [
                str(ev["id"]), ev["name"], ev.get("file_type", ""),
                size_kb, sha_short, md5, ev["created_at"][:16],
            ]
            for c, val in enumerate(vals):
                item = QTableWidgetItem(val)
                self._table.setItem(r, c, item)

    def _filter(self) -> None:
        q = self._search_edit.text().lower()
        filtered = [e for e in self._evidence
                    if q in e["name"].lower() or q in e.get("file_type", "").lower()]
        self._populate_table(filtered)

    def _on_selection(self) -> None:
        row = self._table.currentRow()
        id_item = self._table.item(row, 0)
        if not id_item:
            return
        ev_id = int(id_item.text())
        self._selected_id = ev_id
        ev = next((e for e in self._evidence if e["id"] == ev_id), None)
        if not ev:
            return
        self._detail_lbl.setText(
            f"<b>Name:</b> {ev['name']}<br>"
            f"<b>Path:</b> {ev.get('file_path','')}<br>"
            f"<b>Type:</b> {ev.get('file_type','')}<br>"
            f"<b>Size:</b> {ev.get('file_size',0):,} bytes<br>"
            f"<b>Parsed:</b> {'Yes' if ev.get('parsed') else 'No'}<br>"
            f"<b>SHA-256:</b><br><small>{ev.get('sha256','')}</small><br>"
            f"<b>MD5:</b> {ev.get('md5','')}"
        )
        self._notes_edit.setPlainText(ev.get("notes", ""))

    # ── Actions ────────────────────────────────────────────────────────────

    def _add_evidence(self) -> None:
        if not self._active_case_id:
            QMessageBox.warning(self, "No Case", "Activate a case first.")
            return
        paths, _ = QFileDialog.getOpenFileNames(
            self,
            "Select Evidence Files",
            str(Path.home()),
            "All Files (*.*);;"
            "EVTX (*.evtx);;PCAP (*.pcap *.pcapng);;JSON (*.json);;"
            "CSV (*.csv);;Log Files (*.log *.txt);;XML (*.xml)",
        )
        for p in paths:
            self._ingest_file(Path(p))

    def _add_folder(self) -> None:
        if not self._active_case_id:
            QMessageBox.warning(self, "No Case", "Activate a case first.")
            return
        folder = QFileDialog.getExistingDirectory(self, "Select Evidence Folder")
        if not folder:
            return
        supported = {".evtx", ".pcap", ".pcapng", ".json", ".csv",
                     ".log", ".txt", ".xml", ".eml"}
        for p in Path(folder).rglob("*"):
            if p.is_file() and p.suffix.lower() in supported:
                self._ingest_file(p)

    def _ingest_file(self, path: Path) -> None:
        if self._active_thread and self._active_thread.isRunning():
            QMessageBox.information(self, "Busy", "Wait for current ingestion to finish.")
            return
        parser = EvidenceParser(self._db)
        self._active_thread = IngestThread(parser, self._active_case_id, path)
        self._active_thread.progress.connect(self._on_progress)
        self._active_thread.finished.connect(self._on_ingest_done)
        self._active_thread.error.connect(self._on_ingest_error)
        self._progress_bar.setVisible(True)
        self._progress_bar.setValue(0)
        self._progress_label.setText(f"Ingesting {path.name}…")
        self._active_thread.start()

    def _on_progress(self, current: int, total: int) -> None:
        if total > 0:
            self._progress_bar.setMaximum(total)
            self._progress_bar.setValue(current)

    def _on_ingest_done(self, ev_id: int, name: str) -> None:
        self._progress_bar.setVisible(False)
        self._progress_label.setText(f"✓ Ingested: {name}")
        self._audit.record("evidence_add", f"Evidence #{ev_id}: {name}")
        self._load_evidence()

    def _on_ingest_error(self, msg: str) -> None:
        self._progress_bar.setVisible(False)
        self._progress_label.setText("✗ Ingestion failed")
        QMessageBox.critical(self, "Ingestion Error", msg)

    def _reparse_selected(self) -> None:
        if not self._selected_id:
            return
        ev = next((e for e in self._evidence if e["id"] == self._selected_id), None)
        if not ev:
            return
        path = Path(ev["file_path"])
        if not path.exists():
            QMessageBox.warning(self, "File Not Found", f"{path} does not exist.")
            return
        # Delete existing log events for this evidence
        self._db.update("DELETE FROM log_events WHERE evidence_id=?", (ev["id"],))
        self._db.update("UPDATE evidence SET parsed=0 WHERE id=?", (ev["id"],))
        self._ingest_file(path)

    def _save_notes(self) -> None:
        if not self._selected_id:
            return
        notes = self._notes_edit.toPlainText()
        self._db.update("UPDATE evidence SET notes=? WHERE id=?",
                        (notes, self._selected_id))

    def _delete_selected(self) -> None:
        if not self._selected_id:
            return
        ev = next((e for e in self._evidence if e["id"] == self._selected_id), None)
        if not ev:
            return
        reply = QMessageBox.question(
            self, "Remove Evidence",
            f"Remove '{ev['name']}' and all associated log events?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        self._db.update("DELETE FROM evidence WHERE id=?", (ev["id"],))
        self._audit.record("evidence_delete", f"Removed evidence #{ev['id']}: {ev['name']}")
        self._selected_id = None
        self._load_evidence()

    def _on_case_changed(self, case_id) -> None:
        self._load_evidence()
