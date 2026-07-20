"""
core/crash_log.py – Unhandled exception crash reporter.
Writes a timestamped crash report to disk and shows a user-facing dialog.
"""

from __future__ import annotations

import logging
import sys
import traceback
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.config import Config

log = logging.getLogger(__name__)


def install_crash_handler(config: "Config") -> None:
    """Replace sys.excepthook with one that logs crashes to disk."""
    crash_dir = config.app_data_dir / "crashes"
    crash_dir.mkdir(parents=True, exist_ok=True)

    def _handler(exc_type, exc_value, exc_tb):
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        path = crash_dir / f"crash_{ts}.txt"
        tb_str = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        log.critical("Unhandled exception:\n%s", tb_str)
        try:
            path.write_text(tb_str, encoding="utf-8")
        except Exception:
            pass
        # Try to show a Qt dialog if QApplication is running
        try:
            from PySide6.QtWidgets import QMessageBox, QApplication
            if QApplication.instance():
                msg = QMessageBox()
                msg.setWindowTitle("SentinelAI – Unexpected Error")
                msg.setIcon(QMessageBox.Critical)
                msg.setText(
                    f"An unexpected error occurred.\n\n"
                    f"Crash report saved to:\n{path}\n\n"
                    f"{exc_type.__name__}: {exc_value}"
                )
                msg.exec()
        except Exception:
            pass
        sys.__excepthook__(exc_type, exc_value, exc_tb)

    sys.excepthook = _handler
