"""
modules/settings_module.py – Application settings: general, AI providers,
API keys, appearance, database maintenance.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit,
    QWidget, QTabWidget, QComboBox,
    QGroupBox, QFormLayout, QSpinBox,
    QMessageBox, QFileDialog, QCheckBox,
    QScrollArea, QFrame,
)

from modules.base_module import BaseModule
from core.ai_client import AIClient

log = logging.getLogger(__name__)


class TestConnectionThread(QThread):
    finished = Signal(bool, str)

    def __init__(self, client: AIClient, provider: str) -> None:
        super().__init__()
        self._client = client
        self._provider = provider

    def run(self) -> None:
        ok, msg = self._client.test_connection(self._provider)
        self.finished.emit(ok, msg)


class SettingsModule(BaseModule):
    """Application settings and configuration."""

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(self._make_page_header(
            "Settings",
            "Configure application preferences, AI providers, API keys, and database"
        ))

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        content = QWidget()
        cl = QVBoxLayout(content)
        cl.setContentsMargins(24, 24, 24, 24)
        cl.setSpacing(20)
        scroll.setWidget(content)
        layout.addWidget(scroll, 1)

        tabs = QTabWidget()
        cl.addWidget(tabs)

        # ── Tab: General ─────────────────────────────────────────────────
        general_tab = QWidget()
        gl = QVBoxLayout(general_tab)
        gl.setContentsMargins(20, 20, 20, 20)
        gl.setSpacing(16)

        app_group = QGroupBox("Application")
        agl = QFormLayout(app_group)
        agl.setSpacing(10)

        self._font_size = QSpinBox()
        self._font_size.setRange(10, 20)
        self._font_size.setValue(self._config.get("font_size", 13))
        agl.addRow("Font Size:", self._font_size)

        self._max_log_rows = QSpinBox()
        self._max_log_rows.setRange(1000, 1_000_000)
        self._max_log_rows.setSingleStep(10000)
        self._max_log_rows.setValue(self._config.get("max_log_rows", 100000))
        agl.addRow("Max Log Rows:", self._max_log_rows)

        self._report_dir_edit = QLineEdit()
        self._report_dir_edit.setText(
            self._config.get("report_output_dir", str(Path.home() / "SentinelAI_Reports"))
        )
        report_browse = QPushButton("…")
        report_browse.setFixedWidth(30)
        report_browse.clicked.connect(self._browse_report_dir)
        report_row = QHBoxLayout()
        report_row.addWidget(self._report_dir_edit)
        report_row.addWidget(report_browse)
        agl.addRow("Report Output Dir:", report_row)

        self._analyst_edit = QLineEdit()
        self._analyst_edit.setPlaceholderText("Your name / analyst handle")
        self._analyst_edit.setText(self._config.get("analyst_name", ""))
        agl.addRow("Default Analyst:", self._analyst_edit)

        gl.addWidget(app_group)

        save_general_btn = self._primary_btn("💾 Save General Settings")
        save_general_btn.clicked.connect(self._save_general)
        gl.addWidget(save_general_btn)
        gl.addStretch()
        tabs.addTab(general_tab, "General")

        # ── Tab: AI & Integrations ────────────────────────────────────────
        ai_tab = QWidget()
        al = QVBoxLayout(ai_tab)
        al.setContentsMargins(20, 20, 20, 20)
        al.setSpacing(16)

        # Provider selection
        prov_group = QGroupBox("Default AI Provider")
        pgl = QFormLayout(prov_group)
        pgl.setSpacing(10)

        self._ai_provider_combo = QComboBox()
        self._ai_provider_combo.addItems(["openai", "anthropic", "gemini", "ollama"])
        self._ai_provider_combo.setCurrentText(self._config.get("ai_provider", "openai"))
        self._ai_provider_combo.currentTextChanged.connect(self._on_provider_changed)
        pgl.addRow("Provider:", self._ai_provider_combo)

        self._ai_model_edit = QLineEdit()
        self._ai_model_edit.setText(self._config.get("ai_model", "gpt-4o"))
        self._ai_model_edit.setPlaceholderText("e.g. gpt-4o / claude-sonnet-4-6 / gemini-1.5-pro")
        pgl.addRow("Model:", self._ai_model_edit)

        self._ollama_url_edit = QLineEdit()
        self._ollama_url_edit.setText(self._config.get("ollama_base_url", "http://localhost:11434"))
        pgl.addRow("Ollama URL:", self._ollama_url_edit)

        al.addWidget(prov_group)

        # API Keys
        keys_group = QGroupBox("API Keys (Encrypted Storage)")
        kgl = QFormLayout(keys_group)
        kgl.setSpacing(10)

        self._api_key_fields: dict[str, QLineEdit] = {}
        key_configs = [
            ("OpenAI",        "openai_api_key",      "sk-…"),
            ("Anthropic",     "anthropic_api_key",   "sk-ant-…"),
            ("Google Gemini", "gemini_api_key",      "AIza…"),
            ("VirusTotal",    "virustotal_api_key",  "64-char hex key"),
            ("AbuseIPDB",     "abuseipdb_api_key",   "API key"),
            ("AlienVault OTX","otx_api_key",         "OTX API key"),
            ("Shodan",        "shodan_api_key",       "Shodan API key"),
        ]
        for label, key_name, placeholder in key_configs:
            row_widget = QWidget()
            row_layout = QHBoxLayout(row_widget)
            row_layout.setContentsMargins(0, 0, 0, 0)
            row_layout.setSpacing(6)

            field = QLineEdit()
            field.setEchoMode(QLineEdit.Password)
            field.setPlaceholderText(placeholder)
            existing = self._config.get_secret(key_name)
            if existing:
                field.setText(existing)
            self._api_key_fields[key_name] = field

            toggle_btn = QPushButton("👁")
            toggle_btn.setFixedWidth(32)
            toggle_btn.setCheckable(True)
            toggle_btn.toggled.connect(
                lambda checked, f=field: f.setEchoMode(
                    QLineEdit.Normal if checked else QLineEdit.Password
                )
            )
            clear_btn = QPushButton("✕")
            clear_btn.setFixedWidth(28)
            clear_btn.clicked.connect(
                lambda _, k=key_name, f=field: self._clear_key(k, f)
            )
            row_layout.addWidget(field, 1)
            row_layout.addWidget(toggle_btn)
            row_layout.addWidget(clear_btn)
            kgl.addRow(f"{label}:", row_widget)

        al.addWidget(keys_group)

        # Test + Save
        test_row = QHBoxLayout()
        test_btn = QPushButton("🔌 Test Connection")
        test_btn.clicked.connect(self._test_ai_connection)
        self._test_result = QLabel("")
        test_row.addWidget(test_btn)
        test_row.addWidget(self._test_result)
        test_row.addStretch()
        al.addLayout(test_row)

        save_ai_btn = self._primary_btn("💾 Save AI Settings")
        save_ai_btn.clicked.connect(self._save_ai_settings)
        al.addWidget(save_ai_btn)
        al.addStretch()
        tabs.addTab(ai_tab, "AI & Integrations")

        # ── Tab: Database ─────────────────────────────────────────────────
        db_tab = QWidget()
        dbl = QVBoxLayout(db_tab)
        dbl.setContentsMargins(20, 20, 20, 20)
        dbl.setSpacing(12)

        db_info_group = QGroupBox("Database Information")
        dil = QFormLayout(db_info_group)
        db_path = self._config.app_data_dir / "sentinelai.db"
        db_size = f"{db_path.stat().st_size / (1024*1024):.2f} MB" if db_path.exists() else "N/A"
        self._db_path_lbl = QLabel(str(db_path))
        self._db_path_lbl.setStyleSheet("color: #8B949E; font-family: monospace;")
        self._db_size_lbl = QLabel(db_size)
        dil.addRow("Path:", self._db_path_lbl)
        dil.addRow("Size:", self._db_size_lbl)
        dbl.addWidget(db_info_group)

        maint_group = QGroupBox("Maintenance")
        mgl = QVBoxLayout(maint_group)

        vacuum_btn = QPushButton("🗜 VACUUM Database (optimise)")
        vacuum_btn.clicked.connect(self._vacuum_db)
        mgl.addWidget(vacuum_btn)

        clear_intel_btn = QPushButton("🗑 Clear Threat Intel Cache")
        clear_intel_btn.clicked.connect(self._clear_intel_cache)
        mgl.addWidget(clear_intel_btn)

        clear_ai_btn = QPushButton("🗑 Clear AI Conversation History")
        clear_ai_btn.clicked.connect(self._clear_ai_history)
        mgl.addWidget(clear_ai_btn)

        export_db_btn = QPushButton("⬇ Export Database Backup")
        export_db_btn.clicked.connect(self._export_db)
        mgl.addWidget(export_db_btn)

        self._maint_status = QLabel("")
        self._maint_status.setObjectName("AccentLabel")
        mgl.addWidget(self._maint_status)
        dbl.addWidget(maint_group)
        dbl.addStretch()
        tabs.addTab(db_tab, "Database")

        # ── Tab: Audit Log ────────────────────────────────────────────────
        audit_tab = QWidget()
        audl = QVBoxLayout(audit_tab)
        audl.setContentsMargins(14, 14, 14, 14)

        from PySide6.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView
        self._audit_table = QTableWidget(0, 4)
        self._audit_table.setHorizontalHeaderLabels(["Action", "Detail", "User", "Time"])
        self._audit_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._audit_table.setAlternatingRowColors(True)
        self._audit_table.verticalHeader().setVisible(False)
        self._audit_table.horizontalHeader().setStretchLastSection(True)
        self._audit_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        audl.addWidget(self._audit_table)

        refresh_audit_btn = QPushButton("↺ Refresh")
        refresh_audit_btn.clicked.connect(self._load_audit)
        audl.addWidget(refresh_audit_btn)
        tabs.addTab(audit_tab, "Audit Log")

        self._test_thread: Optional[TestConnectionThread] = None
        self._load_audit()

    # ── Actions ────────────────────────────────────────────────────────────

    def _save_general(self) -> None:
        self._config.set("font_size", self._font_size.value())
        self._config.set("max_log_rows", self._max_log_rows.value())
        self._config.set("report_output_dir", self._report_dir_edit.text().strip())
        self._config.set("analyst_name", self._analyst_edit.text().strip())
        QMessageBox.information(self, "Saved", "General settings saved.")
        self._audit.record("settings_save", "General settings updated")

    def _save_ai_settings(self) -> None:
        self._config.set("ai_provider", self._ai_provider_combo.currentText())
        self._config.set("ai_model", self._ai_model_edit.text().strip())
        self._config.set("ollama_base_url", self._ollama_url_edit.text().strip())
        for key_name, field in self._api_key_fields.items():
            val = field.text().strip()
            if val:
                self._config.set_secret(key_name, val)
        QMessageBox.information(self, "Saved", "AI settings and API keys saved (encrypted).")
        self._audit.record("settings_save", "AI settings and API keys updated")

    def _clear_key(self, key_name: str, field: QLineEdit) -> None:
        self._config.delete_secret(key_name)
        field.clear()

    def _on_provider_changed(self, provider: str) -> None:
        model_defaults = {
            "openai":    "gpt-4o",
            "anthropic": "claude-sonnet-4-6",
            "gemini":    "gemini-1.5-pro",
            "ollama":    "llama3",
        }
        self._ai_model_edit.setText(model_defaults.get(provider, ""))

    def _test_ai_connection(self) -> None:
        self._test_result.setText("Testing…")
        provider = self._ai_provider_combo.currentText()
        client = AIClient(self._config)
        self._test_thread = TestConnectionThread(client, provider)
        self._test_thread.finished.connect(self._on_test_done)
        self._test_thread.start()

    def _on_test_done(self, ok: bool, msg: str) -> None:
        if ok:
            self._test_result.setText(f"✓ Connected — {msg[:40]}")
            self._test_result.setStyleSheet("color: #3FB950;")
        else:
            self._test_result.setText(f"✗ Failed — {msg[:80]}")
            self._test_result.setStyleSheet("color: #F85149;")

    def _browse_report_dir(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Select Report Output Directory")
        if folder:
            self._report_dir_edit.setText(folder)

    # ── Database maintenance ───────────────────────────────────────────────

    def _vacuum_db(self) -> None:
        self._db.execute("VACUUM")
        self._db.commit()
        self._maint_status.setText("✓ VACUUM complete")
        self._audit.record("db_vacuum", "Database vacuumed")

    def _clear_intel_cache(self) -> None:
        reply = QMessageBox.question(
            self, "Clear Cache",
            "Clear all cached threat intelligence data?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self._db.update("DELETE FROM threat_intel")
            self._maint_status.setText("✓ Intel cache cleared")
            self._audit.record("clear_intel_cache", "Threat intel cache cleared")

    def _clear_ai_history(self) -> None:
        reply = QMessageBox.question(
            self, "Clear History",
            "Clear all AI conversation history?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self._db.update("DELETE FROM ai_conversations")
            self._maint_status.setText("✓ AI history cleared")

    def _export_db(self) -> None:
        import shutil
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Database", "sentinelai_backup.db", "SQLite (*.db)"
        )
        if path:
            src = self._config.app_data_dir / "sentinelai.db"
            shutil.copy2(str(src), path)
            self._maint_status.setText(f"✓ Backup saved: {Path(path).name}")
            self._audit.record("db_backup", f"Database exported to {path}")

    # ── Audit log ──────────────────────────────────────────────────────────

    def _load_audit(self) -> None:
        from PySide6.QtWidgets import QTableWidgetItem
        rows = self._audit.recent(500)
        self._audit_table.setRowCount(0)
        for row in rows:
            r = self._audit_table.rowCount()
            self._audit_table.insertRow(r)
            for c, val in enumerate([
                row["action"], row["detail"][:80],
                row["user"], row["created_at"][:19],
            ]):
                self._audit_table.setItem(r, c, QTableWidgetItem(str(val)))
