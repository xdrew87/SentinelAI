"""
modules/sigma_module.py – Sigma rule management, YAML editor, log scanner.
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
    QWidget, QListWidget, QListWidgetItem,
    QFileDialog, QMessageBox, QCheckBox, QComboBox,
)

from modules.base_module import BaseModule
from core.sigma_engine import SigmaEngine

log = logging.getLogger(__name__)

_SIGMA_TEMPLATE = """\
title: Suspicious PowerShell Encoded Command
id: a0b1c2d3-e4f5-6789-abcd-ef0123456789
status: experimental
description: Detects use of PowerShell with encoded command parameter
author: SentinelAI
date: 2024/01/01
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        process|contains: 'powershell'
        message|contains|all:
            - '-EncodedCommand'
            - '-Enc'
    condition: selection
falsepositives:
    - Legitimate administration scripts
level: high
"""


class YAMLHighlighter(QSyntaxHighlighter):
    def __init__(self, document) -> None:
        super().__init__(document)
        import re

        def fmt(color: str, bold: bool = False) -> QTextCharFormat:
            f = QTextCharFormat()
            f.setForeground(QColor(color))
            if bold:
                f.setFontWeight(QFont.Bold)
            return f

        self._rules = [
            (re.compile(r"^(\s*)([\w\-]+)(:)"), fmt("#9CDCFE")),
            (re.compile(r"#.*"), fmt("#6A9955")),
            (re.compile(r"'[^']*'"), fmt("#CE9178")),
            (re.compile(r'"[^"]*"'), fmt("#CE9178")),
            (re.compile(r"\b(true|false|null|yes|no)\b"), fmt("#569CD6", bold=True)),
            (re.compile(r"^\s*-\s"), fmt("#D4D4D4")),
            (re.compile(r"\b\d+\b"), fmt("#B5CEA8")),
        ]

    def highlightBlock(self, text: str) -> None:
        for pattern, fmt in self._rules:
            for m in pattern.finditer(text):
                self.setFormat(m.start(), m.end() - m.start(), fmt)


class SigmaScanThread(QThread):
    finished = Signal(list)
    error = Signal(str)

    def __init__(self, engine: SigmaEngine, db, case_id: Optional[int]) -> None:
        super().__init__()
        self._engine = engine
        self._db = db
        self._case_id = case_id

    def run(self) -> None:
        try:
            if self._case_id:
                rows = self._db.fetchall(
                    "SELECT * FROM log_events WHERE case_id=? LIMIT 50000",
                    (self._case_id,)
                )
            else:
                rows = self._db.fetchall("SELECT * FROM log_events LIMIT 50000")
            events = [dict(r) for r in rows]
            hits_by_idx = self._engine.scan_events(events)
            results = []
            for idx, rules in hits_by_idx.items():
                ev = events[idx]
                for rule in rules:
                    results.append({
                        "event_id": ev.get("id", ""),
                        "timestamp": ev.get("timestamp", ""),
                        "source": ev.get("source_type", ""),
                        "rule_name": rule.get("name", ""),
                        "severity": rule.get("severity", ""),
                        "message": ev.get("message", "")[:120],
                    })
            self.finished.emit(results)
        except Exception as exc:
            self.error.emit(str(exc))


class SigmaModule(BaseModule):
    """Sigma rule editor, validator, and log scanner."""

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(self._make_page_header(
            "Sigma Rules",
            "Create and manage Sigma detection rules — scan all log events"
        ))

        self._sigma_engine = SigmaEngine(self._db)

        splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(splitter, 1)

        # ── Left: rule list ───────────────────────────────────────────────
        left = QWidget()
        left.setFixedWidth(280)
        left.setStyleSheet("background-color: #161B22; border-right: 1px solid #30363D;")
        ll = QVBoxLayout(left)
        ll.setContentsMargins(10, 10, 10, 10)
        ll.setSpacing(6)

        ll.addWidget(QLabel("Sigma Rules"))

        self._search_edit = QLineEdit()
        self._search_edit.setPlaceholderText("Filter rules…")
        self._search_edit.textChanged.connect(self._filter_rules)
        ll.addWidget(self._search_edit)

        self._sev_filter = QComboBox()
        self._sev_filter.addItems(["All", "critical", "high", "medium", "low"])
        self._sev_filter.currentTextChanged.connect(self._filter_rules)
        ll.addWidget(self._sev_filter)

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

        import_btn = QPushButton("⬆ Import .yml")
        import_btn.clicked.connect(self._import_rules)
        ll.addWidget(import_btn)

        splitter.addWidget(left)

        # ── Right: editor + results ───────────────────────────────────────
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(14, 14, 14, 14)
        rl.setSpacing(8)

        meta_row = QHBoxLayout()
        self._name_edit = QLineEdit()
        self._name_edit.setPlaceholderText("Rule name")
        self._sev_edit = QComboBox()
        self._sev_edit.addItems(["critical", "high", "medium", "low", "informational"])
        self._enabled_cb = QCheckBox("Enabled")
        self._enabled_cb.setChecked(True)
        meta_row.addWidget(QLabel("Name:"))
        meta_row.addWidget(self._name_edit)
        meta_row.addWidget(QLabel("Sev:"))
        meta_row.addWidget(self._sev_edit)
        meta_row.addWidget(self._enabled_cb)
        rl.addLayout(meta_row)

        self._editor = QTextEdit()
        self._editor.setStyleSheet(
            "font-family: 'Cascadia Code','JetBrains Mono',monospace;"
            "font-size: 13px; background-color: #0D1117; color: #C9D1D9;"
        )
        self._editor.setPlainText(_SIGMA_TEMPLATE)
        self._highlighter = YAMLHighlighter(self._editor.document())
        rl.addWidget(self._editor, 2)

        action_row = QHBoxLayout()
        validate_btn = QPushButton("✔ Validate YAML")
        validate_btn.clicked.connect(self._validate_rule)
        save_btn = self._primary_btn("💾 Save Rule")
        save_btn.clicked.connect(self._save_rule)
        scan_btn = QPushButton("⚡ Scan Logs")
        scan_btn.clicked.connect(self._scan_logs)
        self._status_lbl = QLabel("")
        action_row.addWidget(validate_btn)
        action_row.addWidget(save_btn)
        action_row.addWidget(scan_btn)
        action_row.addStretch()
        action_row.addWidget(self._status_lbl)
        rl.addLayout(action_row)

        rl.addWidget(QLabel("Scan Hits:"))
        self._results_table = QTableWidget(0, 6)
        self._results_table.setHorizontalHeaderLabels([
            "Event ID", "Timestamp", "Source", "Rule", "Severity", "Message"
        ])
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
        self._scan_thread: Optional[SigmaScanThread] = None
        self._load_rules()

    def _load_rules(self) -> None:
        rows = self._db.fetchall("SELECT * FROM sigma_rules ORDER BY name")
        self._rules = [dict(r) for r in rows]
        self._filter_rules(self._search_edit.text())

    def _filter_rules(self, *_) -> None:
        q = self._search_edit.text().lower()
        sev = self._sev_filter.currentText()
        self._rule_list.clear()
        for rule in self._rules:
            if q and q not in rule["name"].lower():
                continue
            if sev != "All" and rule.get("severity", "") != sev:
                continue
            item = QListWidgetItem(("✓ " if rule["enabled"] else "✗ ") + rule["name"])
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
        si = self._sev_edit.findText(rule.get("severity", "medium"))
        if si >= 0:
            self._sev_edit.setCurrentIndex(si)
        self._enabled_cb.setChecked(bool(rule["enabled"]))
        self._editor.setPlainText(rule["rule_yaml"])

    def _new_rule(self) -> None:
        self._current_rule_id = None
        self._name_edit.setText("NewSigmaRule")
        self._editor.setPlainText(_SIGMA_TEMPLATE)
        self._status_lbl.setText("")

    def _validate_rule(self) -> None:
        ok, err = self._sigma_engine.validate_yaml(self._editor.toPlainText())
        if ok:
            self._status_lbl.setText("✓ Valid YAML")
            self._status_lbl.setStyleSheet("color: #3FB950;")
        else:
            self._status_lbl.setText(f"✗ {err}")
            self._status_lbl.setStyleSheet("color: #F85149;")

    def _save_rule(self) -> None:
        name = self._name_edit.text().strip()
        rule_yaml = self._editor.toPlainText()
        if not name:
            QMessageBox.warning(self, "Validation", "Rule name is required.")
            return
        ok, err = self._sigma_engine.validate_yaml(rule_yaml)
        if not ok:
            QMessageBox.critical(self, "Invalid YAML", err)
            return
        now = datetime.now(timezone.utc).isoformat()
        enabled = 1 if self._enabled_cb.isChecked() else 0
        sev = self._sev_edit.currentText()
        if self._current_rule_id:
            self._db.update(
                """UPDATE sigma_rules SET name=?, rule_yaml=?, severity=?,
                   enabled=?, updated_at=? WHERE id=?""",
                (name, rule_yaml, sev, enabled, now, self._current_rule_id),
            )
        else:
            self._current_rule_id = self._db.insert(
                """INSERT INTO sigma_rules (name, rule_yaml, severity, enabled, created_at, updated_at)
                   VALUES (?,?,?,?,?,?)""",
                (name, rule_yaml, sev, enabled, now, now),
            )
        self._sigma_engine.reload()
        self._status_lbl.setText("✓ Saved")
        self._status_lbl.setStyleSheet("color: #3FB950;")
        self._audit.record("sigma_save", f"Saved Sigma rule: {name}")
        self._load_rules()

    def _delete_rule(self) -> None:
        if not self._current_rule_id:
            return
        reply = QMessageBox.question(self, "Delete", "Delete this Sigma rule?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        self._db.update("DELETE FROM sigma_rules WHERE id=?", (self._current_rule_id,))
        self._current_rule_id = None
        self._sigma_engine.reload()
        self._load_rules()

    def _import_rules(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Import Sigma Rules", "", "YAML (*.yml *.yaml);;All Files (*.*)"
        )
        count = 0
        for p in paths:
            from pathlib import Path
            text = Path(p).read_text(encoding="utf-8", errors="replace")
            name = Path(p).stem
            ok, _ = self._sigma_engine.validate_yaml(text)
            now = datetime.now(timezone.utc).isoformat()
            self._db.insert(
                """INSERT OR IGNORE INTO sigma_rules
                   (name, rule_yaml, severity, enabled, created_at, updated_at)
                   VALUES (?,?,?,?,?,?)""",
                (name, text, "medium", 1 if ok else 0, now, now),
            )
            count += 1
        self._sigma_engine.reload()
        self._load_rules()
        QMessageBox.information(self, "Import", f"Imported {count} Sigma rule(s).")

    def _scan_logs(self) -> None:
        self._results_table.setRowCount(0)
        self._status_lbl.setText("Scanning…")
        self._sigma_engine.reload()
        self._scan_thread = SigmaScanThread(self._sigma_engine, self._db, self._active_case_id)
        self._scan_thread.finished.connect(self._on_scan_done)
        self._scan_thread.error.connect(lambda e: self._status_lbl.setText(f"Error: {e}"))
        self._scan_thread.start()

    def _on_scan_done(self, results: list[dict]) -> None:
        self._status_lbl.setText(f"⚡ {len(results)} hits")
        sev_colors = {"critical": "#F85149", "high": "#D29922", "medium": "#58A6FF", "low": "#3FB950"}
        from PySide6.QtGui import QColor
        self._results_table.setRowCount(0)
        for hit in results:
            r = self._results_table.rowCount()
            self._results_table.insertRow(r)
            for c, val in enumerate([
                str(hit["event_id"]), hit["timestamp"][:19], hit["source"],
                hit["rule_name"], hit["severity"].upper(), hit["message"],
            ]):
                item = QTableWidgetItem(val)
                if c == 4:
                    item.setForeground(QColor(sev_colors.get(hit["severity"], "#C9D1D9")))
                self._results_table.setItem(r, c, item)
        self._audit.record("sigma_scan", f"Sigma scan: {len(results)} hits")
