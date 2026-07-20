"""
modules/case_management.py – Full case lifecycle management.
Create, read, update, delete cases. Activate cases for investigation.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QSplitter,
    QLabel, QPushButton, QLineEdit, QTextEdit,
    QComboBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QWidget, QDialog, QDialogButtonBox,
    QFormLayout, QMessageBox, QFrame,
)

from modules.base_module import BaseModule

log = logging.getLogger(__name__)

_SEVERITIES = ["critical", "high", "medium", "low", "info"]
_STATUSES = ["open", "in-progress", "closed", "archived"]


class CaseDialog(QDialog):
    """Create / Edit case dialog."""

    def __init__(self, parent=None, case: Optional[dict] = None) -> None:
        super().__init__(parent)
        self._case = case
        self.setWindowTitle("Edit Case" if case else "New Case")
        self.setMinimumWidth(520)
        self._build_ui()
        if case:
            self._populate(case)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        form = QFormLayout()
        form.setSpacing(10)

        self._title_edit = QLineEdit()
        self._title_edit.setPlaceholderText("Short descriptive title…")
        form.addRow("Title *", self._title_edit)

        self._desc_edit = QTextEdit()
        self._desc_edit.setPlaceholderText("Incident description, initial context…")
        self._desc_edit.setFixedHeight(100)
        form.addRow("Description", self._desc_edit)

        self._severity_combo = QComboBox()
        self._severity_combo.addItems([s.capitalize() for s in _SEVERITIES])
        self._severity_combo.setCurrentText("Medium")
        form.addRow("Severity", self._severity_combo)

        self._status_combo = QComboBox()
        self._status_combo.addItems([s.capitalize() for s in _STATUSES])
        form.addRow("Status", self._status_combo)

        self._analyst_edit = QLineEdit()
        self._analyst_edit.setPlaceholderText("Assigned analyst name")
        form.addRow("Analyst", self._analyst_edit)

        self._tags_edit = QLineEdit()
        self._tags_edit.setPlaceholderText("ransomware, phishing, lateral-movement…")
        form.addRow("Tags", self._tags_edit)

        layout.addLayout(form)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._validate_and_accept)
        buttons.rejected.connect(self.reject)
        ok_btn = buttons.button(QDialogButtonBox.Ok)
        ok_btn.setObjectName("PrimaryButton")
        ok_btn.setText("Save Case")
        layout.addWidget(buttons)

    def _populate(self, case: dict) -> None:
        self._title_edit.setText(case.get("title", ""))
        self._desc_edit.setPlainText(case.get("description", ""))
        sev = case.get("severity", "medium").capitalize()
        idx = self._severity_combo.findText(sev)
        if idx >= 0:
            self._severity_combo.setCurrentIndex(idx)
        stat = case.get("status", "open").capitalize()
        idx2 = self._status_combo.findText(stat)
        if idx2 >= 0:
            self._status_combo.setCurrentIndex(idx2)
        self._analyst_edit.setText(case.get("analyst", ""))
        self._tags_edit.setText(case.get("tags", ""))

    def _validate_and_accept(self) -> None:
        if not self._title_edit.text().strip():
            QMessageBox.warning(self, "Validation", "Title is required.")
            return
        self.accept()

    def get_data(self) -> dict:
        return {
            "title":       self._title_edit.text().strip(),
            "description": self._desc_edit.toPlainText().strip(),
            "severity":    self._severity_combo.currentText().lower(),
            "status":      self._status_combo.currentText().lower(),
            "analyst":     self._analyst_edit.text().strip(),
            "tags":        self._tags_edit.text().strip(),
        }


class CaseManagementModule(BaseModule):
    """Full case management: list, create, edit, delete, activate."""

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(self._make_page_header(
            "Case Management",
            "Create and manage investigation cases"
        ))

        # Toolbar
        self._search_edit = QLineEdit()
        self._search_edit.setPlaceholderText("Search cases…")
        self._search_edit.setFixedWidth(280)
        self._search_edit.textChanged.connect(self._filter_cases)

        self._status_filter = QComboBox()
        self._status_filter.addItems(["All Statuses"] + [s.capitalize() for s in _STATUSES])
        self._status_filter.currentTextChanged.connect(self._filter_cases)

        self._sev_filter = QComboBox()
        self._sev_filter.addItems(["All Severities"] + [s.capitalize() for s in _SEVERITIES])
        self._sev_filter.currentTextChanged.connect(self._filter_cases)

        new_btn = self._primary_btn("＋ New Case")
        new_btn.clicked.connect(self._create_case)

        layout.addWidget(self._make_toolbar(
            self._search_edit, self._status_filter, self._sev_filter,
            None, new_btn
        ))

        # Main splitter: table | detail panel
        splitter = QSplitter(Qt.Horizontal)

        # Case table
        self._table = QTableWidget(0, 7)
        self._table.setHorizontalHeaderLabels(
            ["ID", "Title", "Severity", "Status", "Analyst", "Tags", "Created"]
        )
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self._table.selectionModel().selectionChanged.connect(self._on_selection)
        self._table.doubleClicked.connect(self._activate_selected)
        splitter.addWidget(self._table)

        # Detail panel
        detail = QWidget()
        detail.setMinimumWidth(300)
        detail.setMaximumWidth(400)
        detail.setStyleSheet("background-color: #161B22; border-left: 1px solid #30363D;")
        detail_layout = QVBoxLayout(detail)
        detail_layout.setContentsMargins(16, 16, 16, 16)
        detail_layout.setSpacing(10)

        self._detail_title = QLabel("Select a case")
        self._detail_title.setStyleSheet(
            "font-size: 15px; font-weight: 700; color: #C9D1D9; background: transparent;"
        )
        self._detail_title.setWordWrap(True)
        detail_layout.addWidget(self._detail_title)

        self._detail_body = QLabel()
        self._detail_body.setWordWrap(True)
        self._detail_body.setStyleSheet("color: #8B949E; font-size: 12px; background: transparent;")
        detail_layout.addWidget(self._detail_body)

        self._detail_desc = QLabel()
        self._detail_desc.setWordWrap(True)
        self._detail_desc.setStyleSheet("color: #C9D1D9; background: transparent;")
        detail_layout.addWidget(self._detail_desc)

        detail_layout.addStretch()

        # Action buttons
        activate_btn = self._primary_btn("▶ Activate Case")
        activate_btn.clicked.connect(self._activate_selected)
        edit_btn = QPushButton("✎ Edit")
        edit_btn.clicked.connect(self._edit_selected)
        del_btn = self._danger_btn("🗑 Delete")
        del_btn.clicked.connect(self._delete_selected)

        detail_layout.addWidget(activate_btn)
        detail_layout.addWidget(edit_btn)
        detail_layout.addWidget(del_btn)

        splitter.addWidget(detail)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter, 1)

        self._cases: list[dict] = []
        self._load_cases()

    # ── Data operations ────────────────────────────────────────────────────

    def _load_cases(self) -> None:
        rows = self._db.fetchall(
            "SELECT * FROM cases ORDER BY created_at DESC"
        )
        self._cases = [dict(r) for r in rows]
        self._populate_table(self._cases)
        # Update header bar
        if self._main_window and hasattr(self._main_window, "_header"):
            self._main_window._header.set_cases(self._cases)

    def _populate_table(self, cases: list[dict]) -> None:
        sev_colors = {
            "critical": "#F85149", "high": "#D29922",
            "medium": "#58A6FF", "low": "#3FB950", "info": "#8B949E",
        }
        from PySide6.QtGui import QColor
        self._table.setRowCount(0)
        for case in cases:
            r = self._table.rowCount()
            self._table.insertRow(r)
            vals = [
                str(case["id"]), case["title"],
                case["severity"].upper(), case["status"].capitalize(),
                case.get("analyst", ""), case.get("tags", ""),
                case["created_at"][:16],
            ]
            for c, val in enumerate(vals):
                item = QTableWidgetItem(val)
                if c == 2:
                    item.setForeground(QColor(sev_colors.get(case["severity"], "#C9D1D9")))
                self._table.setItem(r, c, item)

    def _filter_cases(self) -> None:
        query = self._search_edit.text().lower()
        status_filter = self._status_filter.currentText()
        sev_filter = self._sev_filter.currentText()
        filtered = []
        for c in self._cases:
            if query and query not in c["title"].lower() and query not in c.get("tags", "").lower():
                continue
            if status_filter != "All Statuses" and c["status"] != status_filter.lower():
                continue
            if sev_filter != "All Severities" and c["severity"] != sev_filter.lower():
                continue
            filtered.append(c)
        self._populate_table(filtered)

    def _get_selected_case(self) -> Optional[dict]:
        rows = self._table.selectedItems()
        if not rows:
            return None
        row = self._table.currentRow()
        id_item = self._table.item(row, 0)
        if not id_item:
            return None
        case_id = int(id_item.text())
        return next((c for c in self._cases if c["id"] == case_id), None)

    def _on_selection(self) -> None:
        case = self._get_selected_case()
        if not case:
            return
        sev_colors = {
            "critical": "#F85149", "high": "#D29922",
            "medium": "#58A6FF", "low": "#3FB950",
        }
        color = sev_colors.get(case.get("severity", ""), "#C9D1D9")
        self._detail_title.setText(case["title"])
        self._detail_body.setText(
            f'<span style="color:{color}">⬤ {case["severity"].upper()}</span> &nbsp; '
            f'{case["status"].capitalize()} &nbsp; | &nbsp; {case.get("analyst","")}'
        )
        self._detail_desc.setText(case.get("description", ""))

    # ── CRUD actions ───────────────────────────────────────────────────────

    def _create_case(self) -> None:
        dlg = CaseDialog(self)
        if dlg.exec() != QDialog.Accepted:
            return
        data = dlg.get_data()
        now = datetime.now(timezone.utc).isoformat()
        case_id = self._db.insert(
            """INSERT INTO cases
               (title, description, severity, status, analyst, tags, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (data["title"], data["description"], data["severity"],
             data["status"], data["analyst"], data["tags"], now, now),
        )
        self._audit.record("case_create", f"Created case #{case_id}: {data['title']}")
        self._load_cases()
        if self._main_window:
            self._main_window.open_case(case_id, data["title"])

    def _edit_selected(self) -> None:
        case = self._get_selected_case()
        if not case:
            QMessageBox.information(self, "Edit Case", "Select a case first.")
            return
        dlg = CaseDialog(self, case=case)
        if dlg.exec() != QDialog.Accepted:
            return
        data = dlg.get_data()
        now = datetime.now(timezone.utc).isoformat()
        self._db.update(
            """UPDATE cases SET title=?, description=?, severity=?, status=?,
               analyst=?, tags=?, updated_at=? WHERE id=?""",
            (data["title"], data["description"], data["severity"],
             data["status"], data["analyst"], data["tags"], now, case["id"]),
        )
        self._audit.record("case_edit", f"Edited case #{case['id']}: {data['title']}")
        self._load_cases()

    def _delete_selected(self) -> None:
        case = self._get_selected_case()
        if not case:
            return
        reply = QMessageBox.question(
            self, "Delete Case",
            f"Delete case '{case['title']}'?\nAll evidence and events will be removed.",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        self._db.update("DELETE FROM cases WHERE id=?", (case["id"],))
        self._audit.record("case_delete", f"Deleted case #{case['id']}: {case['title']}")
        self._load_cases()

    def _activate_selected(self) -> None:
        case = self._get_selected_case()
        if not case:
            return
        if self._main_window:
            self._main_window.open_case(case["id"], case["title"])

    def _on_case_changed(self, case_id) -> None:
        self._load_cases()
