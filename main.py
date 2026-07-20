#!/usr/bin/env python3
"""
SentinelAI - Commercial-Grade DFIR & Threat Intelligence Desktop Application
Entry point: bootstraps the application, initialises core services, launches UI.
"""

from __future__ import annotations

import sys
import os
import logging
import traceback
from pathlib import Path

# ---------------------------------------------------------------------------
# Ensure the repo root is on sys.path regardless of launch location
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from PySide6.QtWidgets import QApplication, QMessageBox, QSplashScreen
from PySide6.QtGui import QPixmap, QIcon, QColor
from PySide6.QtCore import Qt, QTimer

from core.config import Config
from core.database import Database
from core.audit_log import AuditLog
from core.crash_log import install_crash_handler
from ui.main_window import MainWindow


def _setup_logging(config: Config) -> None:
    """Configure root logger with rotating file handler + console handler."""
    log_path = config.app_data_dir / "logs" / "sentinelai.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    from logging.handlers import RotatingFileHandler

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    fh = RotatingFileHandler(log_path, maxBytes=10 * 1024 * 1024, backupCount=5)
    fh.setFormatter(fmt)
    fh.setLevel(logging.DEBUG)
    root.addHandler(fh)

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    ch.setLevel(logging.INFO)
    root.addHandler(ch)


def main() -> None:
    """Application entry point."""
    # High-DPI scaling
    os.environ.setdefault("QT_AUTO_SCREEN_SCALE_FACTOR", "1")

    app = QApplication(sys.argv)
    app.setApplicationName("SentinelAI")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("SentinelAI Security")

    # ── Splash ────────────────────────────────────────────────────────────
    splash_pix = QPixmap(600, 340)
    splash_pix.fill(QColor("#0D1117"))
    splash = QSplashScreen(splash_pix, Qt.WindowStaysOnTopHint)
    splash.showMessage(
        "  Initialising SentinelAI…",
        Qt.AlignBottom | Qt.AlignLeft,
        QColor("#58A6FF"),
    )
    splash.show()
    app.processEvents()

    # ── Core services ─────────────────────────────────────────────────────
    config = Config()
    _setup_logging(config)
    install_crash_handler(config)

    log = logging.getLogger(__name__)
    log.info("SentinelAI starting up (v%s)", app.applicationVersion())

    db = Database(config)
    db.initialise()

    audit = AuditLog(db)
    audit.record("app_start", "SentinelAI application started")

    # ── Main window ───────────────────────────────────────────────────────
    window = MainWindow(config=config, db=db, audit=audit)
    window.show()

    QTimer.singleShot(1500, splash.close)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
