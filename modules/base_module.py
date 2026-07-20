"""
modules/base_module.py – Abstract base for all SentinelAI module pages.
"""

from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QHBoxLayout, QFrame
from PySide6.QtCore import Qt

if TYPE_CHECKING:
    from core.config import Config
    from core.database import Database
    from core.audit_log import AuditLog


class BaseModule(QWidget):
    """
    Base class for every module page.

    Subclasses receive config, db, audit, main_window references and
    must implement _build_ui().
    """

    def __init__(
        self,
        config: "Config",
        db: "Database",
        audit: "AuditLog",
        main_window=None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._config = config
        self._db = db
        self._audit = audit
        self._main_window = main_window
        self._active_case_id: Optional[int] = None
        self._build_ui()

    def _build_ui(self) -> None:
        """Override in subclasses to construct the module's UI."""
        raise NotImplementedError

    def set_active_case(self, case_id: Optional[int]) -> None:
        """Called by MainWindow when the active case changes."""
        self._active_case_id = case_id
        self._on_case_changed(case_id)

    def _on_case_changed(self, case_id: Optional[int]) -> None:
        """Override to react to case selection changes."""
        pass

    def _make_page_header(self, title: str, subtitle: str = "") -> QWidget:
        """Return a styled page header widget."""
        container = QWidget()
        container.setStyleSheet(
            "background-color: #161B22; border-bottom: 1px solid #30363D;"
        )
        layout = QVBoxLayout(container)
        layout.setContentsMargins(20, 14, 20, 14)
        layout.setSpacing(2)

        title_lbl = QLabel(title)
        title_lbl.setStyleSheet(
            "font-size: 18px; font-weight: 700; color: #C9D1D9; background: transparent;"
        )
        layout.addWidget(title_lbl)

        if subtitle:
            sub_lbl = QLabel(subtitle)
            sub_lbl.setObjectName("Muted")
            sub_lbl.setStyleSheet("background: transparent; color: #8B949E; font-size: 12px;")
            layout.addWidget(sub_lbl)

        return container

    def _make_toolbar(self, *widgets) -> QWidget:
        """Return a horizontal toolbar containing provided widgets."""
        bar = QWidget()
        bar.setStyleSheet("background-color: #161B22; border-bottom: 1px solid #21262D;")
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(12, 6, 12, 6)
        layout.setSpacing(8)
        for w in widgets:
            if w is None:
                layout.addStretch()
            else:
                layout.addWidget(w)
        return bar

    def _make_separator(self) -> QFrame:
        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet("color: #30363D; background-color: #30363D;")
        sep.setFixedHeight(1)
        return sep

    def _primary_btn(self, text: str) -> "QPushButton":
        from PySide6.QtWidgets import QPushButton
        btn = QPushButton(text)
        btn.setObjectName("PrimaryButton")
        return btn

    def _danger_btn(self, text: str) -> "QPushButton":
        from PySide6.QtWidgets import QPushButton
        btn = QPushButton(text)
        btn.setObjectName("DangerButton")
        return btn
