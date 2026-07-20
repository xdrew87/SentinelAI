"""
modules/plugin_manager.py – Plugin discovery, installation, enable/disable.
Plugins are Python packages placed in the configured plugin directory.
Each plugin must expose a sentinelai_plugin() function returning a PluginManifest.
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QSplitter,
    QLabel, QPushButton, QLineEdit, QTextEdit,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QWidget, QFileDialog, QMessageBox, QGroupBox,
)

from modules.base_module import BaseModule

log = logging.getLogger(__name__)


class PluginManagerModule(BaseModule):
    """Discover, install, enable and disable SentinelAI plugins."""

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(self._make_page_header(
            "Plugin Manager",
            "Extend SentinelAI with third-party plugins — discovery, install, enable/disable"
        ))

        # Toolbar
        self._plugin_dir_edit = QLineEdit()
        self._plugin_dir_edit.setPlaceholderText("Plugin directory path…")
        self._plugin_dir_edit.setText(self._config.get("plugin_dir", ""))
        self._plugin_dir_edit.setMinimumWidth(300)

        browse_btn = QPushButton("📂 Browse")
        browse_btn.clicked.connect(self._browse_dir)

        scan_btn = self._primary_btn("🔍 Scan & Discover")
        scan_btn.clicked.connect(self._scan_plugins)

        install_btn = QPushButton("⬆ Install Plugin")
        install_btn.clicked.connect(self._install_plugin)

        layout.addWidget(self._make_toolbar(
            self._plugin_dir_edit, browse_btn, None, install_btn, scan_btn
        ))

        # Main splitter
        splitter = QSplitter(Qt.Horizontal)

        # Plugin table
        self._table = QTableWidget(0, 6)
        self._table.setHorizontalHeaderLabels(
            ["Name", "Version", "Author", "Description", "Status", "Installed"]
        )
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.Stretch)
        self._table.selectionModel().selectionChanged.connect(self._on_selection)
        splitter.addWidget(self._table)

        # Detail panel
        detail = QWidget()
        detail.setFixedWidth(340)
        detail.setStyleSheet("background-color: #161B22; border-left: 1px solid #30363D;")
        dl = QVBoxLayout(detail)
        dl.setContentsMargins(14, 14, 14, 14)
        dl.setSpacing(10)

        dl.addWidget(QLabel("Plugin Details"))

        self._detail_text = QTextEdit()
        self._detail_text.setReadOnly(True)
        self._detail_text.setStyleSheet("background-color: #0D1117; font-size: 12px;")
        dl.addWidget(self._detail_text, 1)

        self._status_lbl = QLabel("")
        self._status_lbl.setObjectName("AccentLabel")
        dl.addWidget(self._status_lbl)

        enable_btn = self._primary_btn("✓ Enable Plugin")
        enable_btn.clicked.connect(self._enable_selected)
        disable_btn = QPushButton("✗ Disable Plugin")
        disable_btn.clicked.connect(self._disable_selected)
        uninstall_btn = self._danger_btn("🗑 Uninstall")
        uninstall_btn.clicked.connect(self._uninstall_selected)
        load_btn = QPushButton("▶ Load Now")
        load_btn.clicked.connect(self._load_selected)

        dl.addWidget(enable_btn)
        dl.addWidget(disable_btn)
        dl.addWidget(load_btn)
        dl.addWidget(uninstall_btn)

        splitter.addWidget(detail)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter, 1)

        # How-to info
        info_group = QGroupBox()
        info_group.setVisible(False)  # hidden, shown only when no plugins
        il = QVBoxLayout(info_group)
        il.addWidget(QLabel(
            "Plugin SDK:\n\n"
            "Create a Python file with:\n\n"
            "  from sentinelai_sdk import PluginManifest\n\n"
            "  def sentinelai_plugin():\n"
            "      return PluginManifest(\n"
            "          name='My Plugin',\n"
            "          version='1.0.0',\n"
            "          author='You',\n"
            "          description='What it does',\n"
            "          entry_point='MyPlugin',\n"
            "      )\n\n"
            "  class MyPlugin:\n"
            "      def activate(self, context): ...\n"
            "      def deactivate(self): ..."
        ))
        layout.addWidget(info_group)

        self._plugins: list[dict] = []
        self._selected: Optional[dict] = None
        self._load_plugins()

    # ── Data ───────────────────────────────────────────────────────────────

    def _load_plugins(self) -> None:
        rows = self._db.fetchall("SELECT * FROM plugins ORDER BY name")
        self._plugins = [dict(r) for r in rows]
        self._populate_table()

    def _populate_table(self) -> None:
        self._table.setRowCount(0)
        for p in self._plugins:
            r = self._table.rowCount()
            self._table.insertRow(r)
            status = "Enabled" if p.get("enabled") else "Disabled"
            for c, val in enumerate([
                p.get("name", ""), p.get("version", ""),
                p.get("author", ""), p.get("description", ""),
                status, p.get("installed_at", "")[:16],
            ]):
                item = QTableWidgetItem(str(val))
                if c == 4:
                    item.setForeground(
                        QColor("#3FB950" if p.get("enabled") else "#8B949E")
                    )
                self._table.setItem(r, c, item)

    def _on_selection(self) -> None:
        row = self._table.currentRow()
        name_item = self._table.item(row, 0)
        if not name_item:
            return
        p = next((x for x in self._plugins if x["name"] == name_item.text()), None)
        if not p:
            return
        self._selected = p
        self._detail_text.setPlainText(
            f"Name:         {p.get('name','')}\n"
            f"Version:      {p.get('version','')}\n"
            f"Author:       {p.get('author','')}\n"
            f"Entry Point:  {p.get('entry_point','')}\n"
            f"Status:       {'Enabled' if p.get('enabled') else 'Disabled'}\n"
            f"Installed:    {p.get('installed_at','')[:16]}\n\n"
            f"Description:\n{p.get('description','')}"
        )

    # ── Plugin discovery ───────────────────────────────────────────────────

    def _browse_dir(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Select Plugin Directory")
        if folder:
            self._plugin_dir_edit.setText(folder)
            self._config.set("plugin_dir", folder)

    def _scan_plugins(self) -> None:
        plugin_dir = self._plugin_dir_edit.text().strip()
        if not plugin_dir:
            QMessageBox.information(self, "Scan", "Set a plugin directory first.")
            return
        path = Path(plugin_dir)
        if not path.exists():
            QMessageBox.warning(self, "Not Found", f"Directory not found: {path}")
            return
        discovered = 0
        for py_file in path.glob("*.py"):
            try:
                manifest = self._load_manifest(py_file)
                if manifest:
                    self._register_plugin(manifest, str(py_file))
                    discovered += 1
            except Exception as exc:
                log.warning("Plugin scan error %s: %s", py_file, exc)
        self._load_plugins()
        self._status_lbl.setText(f"✓ Discovered {discovered} plugin(s)")
        self._audit.record("plugin_scan", f"Scanned {plugin_dir}: {discovered} found")

    def _load_manifest(self, py_file: Path) -> Optional[dict]:
        spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
        if not spec or not spec.loader:
            return None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        if not hasattr(mod, "sentinelai_plugin"):
            return None
        manifest = mod.sentinelai_plugin()
        if hasattr(manifest, "__dict__"):
            return vars(manifest)
        return dict(manifest) if isinstance(manifest, dict) else None

    def _register_plugin(self, manifest: dict, file_path: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        existing = self._db.fetchone(
            "SELECT id FROM plugins WHERE name=?", (manifest.get("name", ""),)
        )
        if existing:
            self._db.update(
                "UPDATE plugins SET version=?, description=?, author=?, entry_point=? WHERE id=?",
                (manifest.get("version", ""), manifest.get("description", ""),
                 manifest.get("author", ""), manifest.get("entry_point", ""),
                 existing["id"]),
            )
        else:
            self._db.insert(
                """INSERT INTO plugins (name, version, description, author, entry_point, enabled, installed_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (manifest.get("name", ""), manifest.get("version", ""),
                 manifest.get("description", ""), manifest.get("author", ""),
                 manifest.get("entry_point", ""), 1, now),
            )

    def _install_plugin(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Install Plugin", "", "Python Files (*.py);;All Files (*.*)"
        )
        if not path:
            return
        try:
            manifest = self._load_manifest(Path(path))
            if not manifest:
                QMessageBox.warning(self, "Invalid Plugin",
                                    "File does not expose sentinelai_plugin() function.")
                return
            self._register_plugin(manifest, path)
            self._load_plugins()
            self._status_lbl.setText(f"✓ Installed: {manifest.get('name','')}")
            self._audit.record("plugin_install", f"Installed plugin: {manifest.get('name','')}")
        except Exception as exc:
            QMessageBox.critical(self, "Install Error", str(exc))

    # ── Enable / disable / uninstall ───────────────────────────────────────

    def _enable_selected(self) -> None:
        if not self._selected:
            return
        self._db.update("UPDATE plugins SET enabled=1 WHERE id=?", (self._selected["id"],))
        self._load_plugins()
        self._audit.record("plugin_enable", f"Enabled: {self._selected['name']}")

    def _disable_selected(self) -> None:
        if not self._selected:
            return
        self._db.update("UPDATE plugins SET enabled=0 WHERE id=?", (self._selected["id"],))
        self._load_plugins()
        self._audit.record("plugin_disable", f"Disabled: {self._selected['name']}")

    def _uninstall_selected(self) -> None:
        if not self._selected:
            return
        reply = QMessageBox.question(
            self, "Uninstall",
            f"Uninstall plugin '{self._selected['name']}'?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        self._db.update("DELETE FROM plugins WHERE id=?", (self._selected["id"],))
        self._selected = None
        self._load_plugins()

    def _load_selected(self) -> None:
        if not self._selected:
            return
        QMessageBox.information(
            self, "Load Plugin",
            f"Plugin '{self._selected['name']}' would be loaded at runtime.\n"
            f"Full hot-loading requires application restart in this build."
        )
