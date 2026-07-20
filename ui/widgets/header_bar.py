"""
ui/widgets/header_bar.py – Top application header bar.

Shows: logo/title, active case selector, quick search, provider indicator.
"""

from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QWidget, QHBoxLayout, QLabel, QComboBox,
    QLineEdit, QPushButton, QFrame,
)

if TYPE_CHECKING:
    from core.config import Config


class HeaderBar(QWidget):
    """Persistent top bar providing case context and global search."""

    case_changed = Signal(int, str)  # (case_id, case_title)

    def __init__(self, config: "Config", parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._config = config
        self.setFixedHeight(52)
        self.setObjectName("HeaderBar")
        self.setStyleSheet(
            "#HeaderBar { background-color: #161B22; border-bottom: 1px solid #30363D; }"
        )
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 0, 16, 0)
        layout.setSpacing(16)

        # Logo / Brand
        logo = QLabel("⬡ SentinelAI")
        logo.setStyleSheet(
            "color: #58A6FF; font-size: 17px; font-weight: 700; letter-spacing: 0.5px;"
        )
        layout.addWidget(logo)

        # Separator
        sep = QFrame()
        sep.setFrameShape(QFrame.VLine)
        sep.setStyleSheet("color: #30363D;")
        sep.setFixedHeight(30)
        layout.addWidget(sep)

        # Case selector label
        lbl = QLabel("Active Case:")
        lbl.setStyleSheet("color: #8B949E; font-size: 12px;")
        layout.addWidget(lbl)

        # Case combo
        self._case_combo = QComboBox()
        self._case_combo.setMinimumWidth(260)
        self._case_combo.setPlaceholderText("Select a case…")
        self._case_combo.currentIndexChanged.connect(self._on_case_changed)
        layout.addWidget(self._case_combo)

        # Refresh cases button
        refresh_btn = QPushButton("↺")
        refresh_btn.setToolTip("Refresh case list")
        refresh_btn.setFixedSize(30, 30)
        refresh_btn.clicked.connect(self.refresh_cases)
        layout.addWidget(refresh_btn)

        layout.addStretch()

        # AI provider indicator
        self._provider_label = QLabel()
        self._provider_label.setObjectName("Muted")
        layout.addWidget(self._provider_label)
        self._update_provider_label()

    def _update_provider_label(self) -> None:
        provider = self._config.get("ai_provider", "openai").upper()
        model = self._config.get("ai_model", "")
        self._provider_label.setText(f"AI: {provider} / {model}")

    def refresh_cases(self) -> None:
        """Populate case combo from DB (called externally when cases change)."""
        # Avoid circular import; access DB via parent's attribute if needed
        pass  # Modules call this via set_cases()

    def set_cases(self, cases: list[dict]) -> None:
        """Populate the case dropdown. cases: list of {id, title} dicts."""
        current_id = self.get_active_case_id()
        self._case_combo.blockSignals(True)
        self._case_combo.clear()
        self._case_combo.addItem("— No active case —", userData=0)
        for c in cases:
            self._case_combo.addItem(c["title"], userData=c["id"])
        # Restore selection
        if current_id:
            for i in range(self._case_combo.count()):
                if self._case_combo.itemData(i) == current_id:
                    self._case_combo.setCurrentIndex(i)
                    break
        self._case_combo.blockSignals(False)

    def get_active_case_id(self) -> int:
        return self._case_combo.currentData() or 0

    def _on_case_changed(self, index: int) -> None:
        case_id = self._case_combo.itemData(index) or 0
        title = self._case_combo.currentText() if case_id else ""
        self.case_changed.emit(case_id, title)
