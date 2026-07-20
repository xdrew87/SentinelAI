"""
modules/yara_module.py – YARA rule management: editor, compiler, file scanner.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor, QFont, QSyntaxHighlighter, QTextCharFormat
from PySide6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QSplitter,
    QLabel, QPushButton, QLineEdit, QTextEdit,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QWidget, QDialog, QDialogButtonBox, QFormLayout,
    QFileDialog, QMessageBox, QListWidget, QListWidgetItem,
    QCheckBox,
)

from modules.base_module import BaseModule
from core.yara_engine import YARAEngine

log = logging.getLogger(__name__)

_YARA_TEMPLATE = """\
rule SuspiciousRule
{
    meta:
        description = "Detects suspicious behaviour"
        author      = "SentinelAI"
        date        = "2024-01-01"
        severity    = "high"

    strings:
        $s1 = "cmd.exe" nocase
        $s2 = "powershell" nocase
        $hex = { 4D 5A 90 00 }

    condition:
        any of them
}
"""


class YARASyntaxHighlighter(QSyntaxHighlighter):
    """Basic YARA syntax highlighter."""

    def __init__(self, document) -> None:
        super().__init__(document)
        import re
        self._rules: list[tuple] = []

        def fmt(color: str, bold: bool = False) -> QTextCharFormat:
            f = QTextCharFormat()
            f.setForeground(QColor(color))
            if bold:
                f.setFontWeight(QFont.Bold)
            return f

        keywords = r"\b(rule|meta|strings|condition|and|or|not|any|all|of|them|nocase|wide|ascii|fullword|private|global|import|include|true|false|uint8|uint16|uint32|filesize|entrypoint|at|in|for|them)\b"
        self._rules = [
            (re.compile(keywords), fmt("#569CD6", bold=True)),
            (re.compile(r"//.*"), fmt("#6A9955")),
            (re.compile(r'"[^"]*"'), fmt("#CE9178")),
            (re.compile(r"\{[0-9A-Fa-f\s\?\-\[\]\(\)\|]+\}"), fmt("#B5CEA8")),
            (re.compile(r"\$\w+"), fmt("#9CDCFE")),
            (re.compile(r"\b\d+\b"), fmt("#B5CEA8")),
        ]

    def highlightBlock(self, text: str) -> None:
        for pattern, fmt in self._rules:
            for m in pattern.finditer(text):
                self.setFormat(m.start(), m.end() - m.start(), fmt)


class ScanThread(QThread):
    progress = Signal(str)
    finished = Signal(list)
    error = Signal(str)

    def __init__(self, engine: YARAEngine, paths: list) -> None:
        super().__init__()
        self._engine = engine
        self._paths = paths

    def run(self) -> None:
        results = []
        for p in self._paths:
            from pathlib import Path
            path = Path(p)
            self.progress.emit(f"Scanning {path.name}…")
            hits = self._engine.scan_file(path)
            for h in hits:
                results.append({"file": str(path), **h})
        self.finished.emit(results)


class YARAModule(BaseModule):
    """YARA rule editor, compiler, and file scanner."""

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(self._make_page_header(
            "YARA Rules",
            "Create, edit and compile YARA rules — scan files and memory"
        ))

        self._yara_engine = YARAEngine(self._db)

        splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(splitter, 1)

        # ── Left: rule list ───────────────────────────────────────────────
        left = QWidget()
        left.setFixedWidth(280)
        left.setStyleSheet("background-color: #161B22; border-right: 1px solid #30363D;")
        ll = QVBoxLayout(left)
        ll.setContentsMargins(10, 10, 10, 10)
        ll.setSpacing(6)

        ll.addWidget(QLabel("YARA Rules"))

        self._rule_search = QLineEdit()
        self._rule_search.setPlaceholderText("Filter rules…")
        self._rule_search.textChanged.connect(self._filter_rules)
        ll.addWidget(self._rule_search)

        self._rule_list = QListWidget()
        self._rule_list.currentRowChanged.connect(self._on_rule_selected)
        ll.addWidget(self._rule_list, 1)

        btn_row = QHBoxLayout()
        new_btn = self._primary_btn("＋ New")
        new_btn.clicked.connect(self._new_rule)
        del_btn = self._danger_btn("🗑")
        del_btn.setFixedWidth(36)
        del_btn.clicked.connect(self._delete_rule)
        btn_row.addWidget(new_btn)
        btn_row.addWidget(del_btn)
        ll.addLayout(btn_row)

        import_btn = QPushButton("⬆ Import .yar")
        import_btn.clicked.connect(self._import_rules)
        ll.addWidget(import_btn)

        splitter.addWidget(left)

        # ── Right: editor + scanner ───────────────────────────────────────
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(14, 14, 14, 14)
        rl.setSpacing(8)

        # Meta row
        meta_row = QHBoxLayout()
        self._name_edit = QLineEdit()
        self._name_edit.setPlaceholderText("Rule name")
        self._desc_edit = QLineEdit()
        self._desc_edit.setPlaceholderText("Description")
        self._enabled_cb = QCheckBox("Enabled")
        self._enabled_cb.setChecked(True)
        meta_row.addWidget(QLabel("Name:"))
        meta_row.addWidget(self._name_edit)
        meta_row.addWidget(QLabel("Desc:"))
        meta_row.addWidget(self._desc_edit, 1)
        meta_row.addWidget(self._enabled_cb)
        rl.addLayout(meta_row)

        # Editor
        self._editor = QTextEdit()
        self._editor.setStyleSheet(
            "font-family: 'Cascadia Code','JetBrains Mono','Courier New',monospace;"
            "font-size: 13px; background-color: #0D1117; color: #C9D1D9;"
        )
        self._editor.setPlainText(_YARA_TEMPLATE)
        self._highlighter = YARASyntaxHighlighter(self._editor.document())
        rl.addWidget(self._editor, 2)

        # Action buttons
        action_row = QHBoxLayout()
        compile_btn = self._primary_btn("⚙ Compile & Save")
        compile_btn.clicked.connect(self._compile_and_save)
        scan_btn = QPushButton("🔍 Scan Files")
        scan_btn.clicked.connect(self._scan_files)
        scan_evidence_btn = QPushButton("🔍 Scan Evidence")
        scan_evidence_btn.clicked.connect(self._scan_evidence)
        self._compile_status = QLabel("")
        action_row.addWidget(compile_btn)
        action_row.addWidget(scan_btn)
        action_row.addWidget(scan_evidence_btn)
        action_row.addStretch()
        action_row.addWidget(self._compile_status)
        rl.addLayout(action_row)

        # Scan results
        rl.addWidget(QLabel("Scan Results:"))
        self._results_table = QTableWidget(0, 4)
        self._results_table.setHorizontalHeaderLabels(["File", "Rule", "Tags", "Strings"])
        self._results_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._results_table.setAlternatingRowColors(True)
        self._results_table.verticalHeader().setVisible(False)
        self._results_table.horizontalHeader().setStretchLastSection(True)
        rl.addWidget(self._results_table, 1)

        splitter.addWidget(right)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)

        self._rules: list[dict] = []
        self._current_rule_id: Optional[int] = None
        self._scan_thread: Optional[ScanThread] = None
        self._load_rules()

    # ── Rule management ────────────────────────────────────────────────────

    def _load_rules(self) -> None:
        rows = self._db.fetchall("SELECT * FROM yara_rules ORDER BY name")
        self._rules = [dict(r) for r in rows]
        self._filter_rules(self._rule_search.text())

    def _filter_rules(self, query: str) -> None:
        q = query.lower()
        self._rule_list.clear()
        for rule in self._rules:
            if q and q not in rule["name"].lower():
                continue
            item = QListWidgetItem(
                ("✓ " if rule["enabled"] else "✗ ") + rule["name"]
            )
            item.setForeground(QColor("#3FB950" if rule["enabled"] else "#8B949E"))
            item.setData(Qt.UserRole, rule["id"])
            self._rule_list.addItem(item)

    def _on_rule_selected(self, row: int) -> None:
        item = self._rule_list.item(row)
        if not item:
            return
        rule_id = item.data(Qt.UserRole)
        rule = next((r for r in self._rules if r["id"] == rule_id), None)
        if not rule:
            return
        self._current_rule_id = rule_id
        self._name_edit.setText(rule["name"])
        self._desc_edit.setText(rule.get("description", ""))
        self._enabled_cb.setChecked(bool(rule["enabled"]))
        self._editor.setPlainText(rule["rule_text"])

    def _new_rule(self) -> None:
        self._current_rule_id = None
        self._name_edit.setText("NewRule")
        self._desc_edit.setText("")
        self._enabled_cb.setChecked(True)
        self._editor.setPlainText(_YARA_TEMPLATE)
        self._compile_status.setText("")

    def _compile_and_save(self) -> None:
        name = self._name_edit.text().strip()
        rule_text = self._editor.toPlainText()
        if not name:
            QMessageBox.warning(self, "Validation", "Rule name is required.")
            return
        ok, err = self._yara_engine.compile_rule(rule_text)
        if not ok:
            self._compile_status.setText(f"✗ Compile error")
            QMessageBox.critical(self, "YARA Compile Error", err)
            return
        self._compile_status.setText("✓ Compiled OK")
        now = datetime.now(timezone.utc).isoformat()
        enabled = 1 if self._enabled_cb.isChecked() else 0
        desc = self._desc_edit.text().strip()
        if self._current_rule_id:
            self._db.update(
                """UPDATE yara_rules SET name=?, rule_text=?, description=?,
                   enabled=?, updated_at=? WHERE id=?""",
                (name, rule_text, desc, enabled, now, self._current_rule_id),
            )
        else:
            self._current_rule_id = self._db.insert(
                """INSERT INTO yara_rules (name, rule_text, description, enabled, created_at, updated_at)
                   VALUES (?,?,?,?,?,?)""",
                (name, rule_text, desc, enabled, now, now),
            )
        self._yara_engine.reload()
        self._audit.record("yara_save", f"Saved YARA rule: {name}")
        self._load_rules()

    def _delete_rule(self) -> None:
        if not self._current_rule_id:
            return
        reply = QMessageBox.question(self, "Delete", "Delete this YARA rule?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        self._db.update("DELETE FROM yara_rules WHERE id=?", (self._current_rule_id,))
        self._current_rule_id = None
        self._yara_engine.reload()
        self._load_rules()

    def _import_rules(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Import YARA Rules", "", "YARA Rules (*.yar *.yara);;All Files (*.*)"
        )
        count = 0
        for p in paths:
            from pathlib import Path
            text = Path(p).read_text(encoding="utf-8", errors="replace")
            name = Path(p).stem
            now = datetime.now(timezone.utc).isoformat()
            ok, _ = self._yara_engine.compile_rule(text)
            self._db.insert(
                """INSERT OR IGNORE INTO yara_rules
                   (name, rule_text, description, enabled, created_at, updated_at)
                   VALUES (?,?,?,?,?,?)""",
                (name, text, f"Imported from {Path(p).name}", 1 if ok else 0, now, now),
            )
            count += 1
        self._yara_engine.reload()
        self._load_rules()
        QMessageBox.information(self, "Import", f"Imported {count} rule file(s).")

    # ── Scanning ───────────────────────────────────────────────────────────

    def _scan_files(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Select Files to Scan", str(__import__("pathlib").Path.home()), "All Files (*.*)"
        )
        if not paths:
            return
        self._start_scan(paths)

    def _scan_evidence(self) -> None:
        rows = self._db.fetchall("SELECT file_path FROM evidence")
        paths = [r["file_path"] for r in rows if __import__("pathlib").Path(r["file_path"]).exists()]
        if not paths:
            QMessageBox.information(self, "Scan Evidence", "No evidence files found on disk.")
            return
        self._start_scan(paths)

    def _start_scan(self, paths: list[str]) -> None:
        self._results_table.setRowCount(0)
        self._compile_status.setText(f"Scanning {len(paths)} file(s)…")
        self._scan_thread = ScanThread(self._yara_engine, paths)
        self._scan_thread.progress.connect(lambda m: self._compile_status.setText(m))
        self._scan_thread.finished.connect(self._on_scan_done)
        self._scan_thread.start()

    def _on_scan_done(self, results: list[dict]) -> None:
        self._compile_status.setText(f"✓ {len(results)} hit(s)")
        self._results_table.setRowCount(0)
        for hit in results:
            r = self._results_table.rowCount()
            self._results_table.insertRow(r)
            strings_summary = ", ".join(s["identifier"] for s in hit.get("strings", [])[:5])
            for c, val in enumerate([
                hit.get("file", ""), hit.get("rule", ""),
                ", ".join(hit.get("tags", [])), strings_summary,
            ]):
                self._results_table.setItem(r, c, QTableWidgetItem(str(val)))
        self._audit.record("yara_scan", f"YARA scan: {len(results)} hits")
