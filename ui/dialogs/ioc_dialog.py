"""
ui/dialogs/ioc_dialog.py – Add/Edit IOC dialog.
"""

from __future__ import annotations

from typing import Optional
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QFormLayout, QLineEdit,
    QComboBox, QTextEdit, QDialogButtonBox, QLabel,
)


class IOCDialog(QDialog):
    """Dialog for creating or editing an IOC."""

    IOC_TYPES = ["ip", "domain", "url", "hash", "email", "filename", "registry", "other"]
    CONFIDENCES = ["high", "medium", "low"]

    def __init__(
        self,
        parent=None,
        prefill_value: str = "",
        prefill_type: str = "",
        ioc: Optional[dict] = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Edit IOC" if ioc else "Add IOC")
        self.setMinimumWidth(460)
        self._ioc = ioc
        self._build_ui()
        if ioc:
            self._populate(ioc)
        elif prefill_value:
            self._value_edit.setText(prefill_value)
        if prefill_type:
            idx = self._type_combo.findText(prefill_type)
            if idx >= 0:
                self._type_combo.setCurrentIndex(idx)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        form = QFormLayout()
        form.setSpacing(10)

        self._type_combo = QComboBox()
        self._type_combo.addItems(self.IOC_TYPES)
        form.addRow("Type *", self._type_combo)

        self._value_edit = QLineEdit()
        self._value_edit.setPlaceholderText("192.168.1.1 / evil.com / d41d8cd9…")
        form.addRow("Value *", self._value_edit)

        self._confidence_combo = QComboBox()
        self._confidence_combo.addItems(self.CONFIDENCES)
        self._confidence_combo.setCurrentText("medium")
        form.addRow("Confidence", self._confidence_combo)

        self._threat_edit = QLineEdit()
        self._threat_edit.setPlaceholderText("ransomware / c2 / phishing…")
        form.addRow("Threat Type", self._threat_edit)

        self._source_edit = QLineEdit()
        self._source_edit.setPlaceholderText("analyst / threat-feed / log-event")
        form.addRow("Source", self._source_edit)

        self._notes_edit = QTextEdit()
        self._notes_edit.setFixedHeight(80)
        form.addRow("Notes", self._notes_edit)

        layout.addLayout(form)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("Save IOC")
        buttons.button(QDialogButtonBox.Ok).setObjectName("PrimaryButton")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _populate(self, ioc: dict) -> None:
        idx = self._type_combo.findText(ioc.get("ioc_type", ""))
        if idx >= 0:
            self._type_combo.setCurrentIndex(idx)
        self._value_edit.setText(ioc.get("value", ""))
        ci = self._confidence_combo.findText(ioc.get("confidence", "medium"))
        if ci >= 0:
            self._confidence_combo.setCurrentIndex(ci)
        self._threat_edit.setText(ioc.get("threat_type", ""))
        self._source_edit.setText(ioc.get("source", ""))
        self._notes_edit.setPlainText(ioc.get("notes", ""))

    def get_data(self) -> dict:
        return {
            "ioc_type":   self._type_combo.currentText(),
            "value":      self._value_edit.text().strip(),
            "confidence": self._confidence_combo.currentText(),
            "threat_type": self._threat_edit.text().strip(),
            "source":     self._source_edit.text().strip(),
            "notes":      self._notes_edit.toPlainText().strip(),
        }
