"""
ui/main_window.py – SentinelAI main window with sidebar navigation.

Architecture:
  Left sidebar  → QListWidget (icon + label per module)
  Center        → QStackedWidget (one page per module)
  Status bar    → persistent status + current case indicator
"""

from __future__ import annotations

import logging
from typing import Optional, TYPE_CHECKING

from PySide6.QtCore import Qt, QTimer, QThread, Signal
from PySide6.QtGui import QIcon, QAction, QKeySequence
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QListWidget, QListWidgetItem, QStackedWidget,
    QLabel, QSplitter, QStatusBar, QMenuBar, QSizePolicy,
    QFrame,
)

from ui.theme import apply_theme
from ui.widgets.header_bar import HeaderBar

# Module pages
from modules.dashboard import DashboardModule
from modules.case_management import CaseManagementModule
from modules.evidence_manager import EvidenceManagerModule
from modules.log_investigation import LogInvestigationModule
from modules.threat_hunting import ThreatHuntingModule
from modules.ioc_investigation import IOCInvestigationModule
from modules.timeline import TimelineModule
from modules.malware_analysis import MalwareAnalysisModule
from modules.yara_module import YARAModule
from modules.sigma_module import SigmaModule
from modules.mitre_module import MITREModule
from modules.pcap_analysis import PCAPModule
from modules.memory_analysis import MemoryAnalysisModule
from modules.threat_intelligence import ThreatIntelModule
from modules.ai_assistant import AIAssistantModule
from modules.reporting import ReportingModule
from modules.settings_module import SettingsModule
from modules.license_module import LicenseModule
from modules.plugin_manager import PluginManagerModule

if TYPE_CHECKING:
    from core.config import Config
    from core.database import Database
    from core.audit_log import AuditLog

log = logging.getLogger(__name__)


_NAV_ITEMS = [
    # (label, icon_char)
    ("Dashboard",          "⊞"),
    ("Cases",              "📁"),
    ("Evidence",           "📋"),
    ("Log Investigation",  "🔍"),
    ("Threat Hunting",     "🎯"),
    ("IOC Investigation",  "🔗"),
    ("Timeline",           "⏱"),
    ("Malware Analysis",   "🦠"),
    ("YARA",               "📜"),
    ("Sigma",              "Σ"),
    ("MITRE ATT&CK",       "🛡"),
    ("PCAP Analysis",      "📡"),
    ("Memory Analysis",    "💾"),
    ("Threat Intelligence","🌐"),
    ("AI Assistant",       "🤖"),
    ("Reporting",          "📊"),
    ("Settings",           "⚙"),
    ("License",            "🔑"),
    ("Plugins",            "🔌"),
]


class MainWindow(QMainWindow):
    """
    Root application window.

    Holds the sidebar navigation, module stack, header bar, and status bar.
    """

    def __init__(
        self,
        config: "Config",
        db: "Database",
        audit: "AuditLog",
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._config = config
        self._db = db
        self._audit = audit
        self._current_case_id: Optional[int] = None

        apply_theme(self.parent() or self)
        self._build_ui()
        self._build_menu()
        self._restore_window_state()

    # ── UI construction ────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self.setWindowTitle("SentinelAI")
        self.setMinimumSize(1280, 800)

        # ── Root layout ───────────────────────────────────────────────────
        root = QWidget()
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        self.setCentralWidget(root)

        # ── Header bar ────────────────────────────────────────────────────
        self._header = HeaderBar(config=self._config)
        self._header.case_changed.connect(self._on_case_changed)
        root_layout.addWidget(self._header)

        # ── Horizontal splitter: sidebar | content ────────────────────────
        body_splitter = QSplitter(Qt.Horizontal)
        body_splitter.setHandleWidth(1)
        root_layout.addWidget(body_splitter, stretch=1)

        # Sidebar
        self._nav = QListWidget()
        self._nav.setObjectName("NavList")
        self._nav.setFixedWidth(200)
        self._nav.setSpacing(0)
        self._nav.setIconSize(self._nav.iconSize())
        for label, icon in _NAV_ITEMS:
            item = QListWidgetItem(f"  {icon}  {label}")
            self._nav.addItem(item)
        self._nav.currentRowChanged.connect(self._on_nav_changed)
        body_splitter.addWidget(self._nav)

        # Module stack
        self._stack = QStackedWidget()
        body_splitter.addWidget(self._stack)
        body_splitter.setStretchFactor(0, 0)
        body_splitter.setStretchFactor(1, 1)

        # Build modules
        self._modules = self._build_modules()
        for module in self._modules:
            self._stack.addWidget(module)

        # ── Status bar ────────────────────────────────────────────────────
        status = QStatusBar()
        self.setStatusBar(status)
        self._status_label = QLabel("Ready")
        self._case_label = QLabel("No active case")
        self._case_label.setObjectName("AccentLabel")
        status.addWidget(self._status_label, 1)
        status.addPermanentWidget(self._case_label)

        # Default to dashboard
        self._nav.setCurrentRow(0)

    def _build_modules(self) -> list[QWidget]:
        ctx = {
            "config": self._config,
            "db": self._db,
            "audit": self._audit,
            "main_window": self,
        }
        return [
            DashboardModule(**ctx),
            CaseManagementModule(**ctx),
            EvidenceManagerModule(**ctx),
            LogInvestigationModule(**ctx),
            ThreatHuntingModule(**ctx),
            IOCInvestigationModule(**ctx),
            TimelineModule(**ctx),
            MalwareAnalysisModule(**ctx),
            YARAModule(**ctx),
            SigmaModule(**ctx),
            MITREModule(**ctx),
            PCAPModule(**ctx),
            MemoryAnalysisModule(**ctx),
            ThreatIntelModule(**ctx),
            AIAssistantModule(**ctx),
            ReportingModule(**ctx),
            SettingsModule(**ctx),
            LicenseModule(**ctx),
            PluginManagerModule(**ctx),
        ]

    def _build_menu(self) -> None:
        mb = self.menuBar()

        file_menu = mb.addMenu("&File")
        file_menu.addAction(self._make_action("New Case", "Ctrl+N",
                                               lambda: self._nav_to(1)))
        file_menu.addAction(self._make_action("Open Evidence", "Ctrl+O",
                                               lambda: self._nav_to(2)))
        file_menu.addSeparator()
        file_menu.addAction(self._make_action("Quit", "Ctrl+Q", self.close))

        view_menu = mb.addMenu("&View")
        view_menu.addAction(self._make_action("Dashboard", "Ctrl+Home",
                                               lambda: self._nav_to(0)))
        view_menu.addAction(self._make_action("AI Assistant", "Ctrl+I",
                                               lambda: self._nav_to(14)))
        view_menu.addAction(self._make_action("Settings", "Ctrl+,",
                                               lambda: self._nav_to(16)))

        help_menu = mb.addMenu("&Help")
        help_menu.addAction(self._make_action("About SentinelAI", shortcut="",
                                               slot=self._show_about))

    @staticmethod
    def _make_action(text: str, shortcut: str = "", slot=None) -> QAction:
        action = QAction(text)
        if shortcut:
            action.setShortcut(QKeySequence(shortcut))
        if slot:
            action.triggered.connect(slot)
        return action

    # ── Navigation ─────────────────────────────────────────────────────────

    def _nav_to(self, index: int) -> None:
        self._nav.setCurrentRow(index)

    def _on_nav_changed(self, row: int) -> None:
        if 0 <= row < self._stack.count():
            self._stack.setCurrentIndex(row)
            label = _NAV_ITEMS[row][0] if row < len(_NAV_ITEMS) else ""
            self.set_status(label)
            log.debug("Navigation → %s", label)

    # ── Case management ─────────────────────────────────────────────────────

    def _on_case_changed(self, case_id: int, case_title: str) -> None:
        self._current_case_id = case_id
        self._case_label.setText(f"Case: {case_title}" if case_id else "No active case")
        # Propagate to all modules
        for module in self._modules:
            if hasattr(module, "set_active_case"):
                module.set_active_case(case_id)

    def get_active_case_id(self) -> Optional[int]:
        return self._current_case_id

    def open_case(self, case_id: int, title: str = "") -> None:
        """Called by CaseManagement to activate a case."""
        if not title:
            row = self._db.fetchone("SELECT title FROM cases WHERE id=?", (case_id,))
            title = row["title"] if row else str(case_id)
        self._on_case_changed(case_id, title)
        self._audit.record("case_open", f"Case #{case_id}: {title}")

    # ── Status bar helpers ─────────────────────────────────────────────────

    def set_status(self, message: str, timeout_ms: int = 0) -> None:
        self._status_label.setText(message)
        if timeout_ms:
            QTimer.singleShot(timeout_ms, lambda: self._status_label.setText("Ready"))

    # ── Window state ───────────────────────────────────────────────────────

    def _restore_window_state(self) -> None:
        self.resize(1400, 900)
        self.showMaximized()

    # ── About dialog ───────────────────────────────────────────────────────

    def _show_about(self) -> None:
        from PySide6.QtWidgets import QMessageBox
        QMessageBox.about(
            self,
            "About SentinelAI",
            "<h2>SentinelAI v1.0.0</h2>"
            "<p>Commercial-grade DFIR &amp; Threat Intelligence platform.</p>"
            "<p>Built with Python 3, PySide6, SQLite.</p>"
            "<p>&copy; 2024 SentinelAI Security. All rights reserved.</p>",
        )

    # ── Cleanup ────────────────────────────────────────────────────────────

    def closeEvent(self, event) -> None:
        self._audit.record("app_stop", "SentinelAI application closed")
        self._db.close()
        event.accept()
