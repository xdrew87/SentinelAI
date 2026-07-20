"""
modules/license_module.py – License key validation and management.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from datetime import datetime

from PySide6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QWidget, QGroupBox, QFormLayout,
    QMessageBox,
)
from PySide6.QtCore import Qt

from modules.base_module import BaseModule

log = logging.getLogger(__name__)

# HMAC secret for offline license validation (in production, use asymmetric keys)
_LICENSE_SECRET = b"SentinelAI-License-Secret-2024-CHANGE-IN-PROD"


def _validate_license_key(key: str) -> tuple[bool, dict]:
    """
    Validate a license key.  Format: SAIXX-XXXXX-XXXXX-XXXXX-HMAC8
    Returns (valid, info_dict).
    In production: replace with RSA signature verification against a public key.
    """
    key = key.strip().upper()
    parts = key.split("-")
    if len(parts) != 5:
        return False, {"error": "Invalid format (expected 5 groups separated by -)"}

    payload = "-".join(parts[:4])
    provided_hmac = parts[4]
    expected = hmac.new(_LICENSE_SECRET, payload.encode(), hashlib.sha256).hexdigest()[:8].upper()

    if not hmac.compare_digest(provided_hmac, expected):
        return False, {"error": "Invalid license key — HMAC mismatch"}

    # Decode tier from prefix
    prefix = parts[0]
    tiers = {"SAIPRO": "Professional", "SAIENT": "Enterprise", "SAIDEV": "Developer"}
    tier = tiers.get(prefix[:6], "Community")

    return True, {
        "tier": tier,
        "key": key,
        "validated_at": datetime.utcnow().isoformat(),
        "features": _tier_features(tier),
    }


def _tier_features(tier: str) -> list[str]:
    base = [
        "Case Management", "Evidence Manager", "Log Investigation",
        "IOC Investigation", "Timeline", "YARA Rules", "Sigma Rules",
        "MITRE ATT&CK", "Reporting (PDF/HTML/Markdown)",
    ]
    pro = base + [
        "Threat Hunting", "Malware Analysis", "PCAP Analysis",
        "AI Assistant (all providers)", "Reporting (all formats)",
        "Plugin Manager",
    ]
    enterprise = pro + [
        "Memory Analysis", "Threat Intelligence (all providers)",
        "Priority support", "API access",
    ]
    return {"Community": base, "Professional": pro, "Enterprise": enterprise,
            "Developer": enterprise}.get(tier, base)


def _generate_demo_key() -> str:
    """Generate a demo professional license key for testing."""
    payload = "SAIPRO-DEMO1-00000-ABCDE"
    hmac_val = hmac.new(_LICENSE_SECRET, payload.encode(), hashlib.sha256).hexdigest()[:8].upper()
    return f"{payload}-{hmac_val}"


class LicenseModule(BaseModule):
    """License key activation and feature management."""

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(self._make_page_header(
            "License Management",
            "Activate your SentinelAI license key"
        ))

        content = QWidget()
        cl = QVBoxLayout(content)
        cl.setContentsMargins(40, 40, 40, 40)
        cl.setSpacing(24)
        layout.addWidget(content, 1)

        # Current status
        status_group = QGroupBox("Current License Status")
        sgl = QVBoxLayout(status_group)
        sgl.setSpacing(10)

        self._tier_lbl = QLabel()
        self._tier_lbl.setStyleSheet("font-size: 20px; font-weight: 800;")
        sgl.addWidget(self._tier_lbl)

        self._status_lbl = QLabel()
        self._status_lbl.setObjectName("Muted")
        sgl.addWidget(self._status_lbl)

        self._key_lbl = QLabel()
        self._key_lbl.setStyleSheet("font-family: monospace; color: #8B949E;")
        sgl.addWidget(self._key_lbl)

        self._validated_lbl = QLabel()
        self._validated_lbl.setObjectName("Muted")
        sgl.addWidget(self._validated_lbl)

        cl.addWidget(status_group)

        # Activation
        activate_group = QGroupBox("Activate License")
        agl = QVBoxLayout(activate_group)

        key_row = QHBoxLayout()
        self._key_edit = QLineEdit()
        self._key_edit.setPlaceholderText("SAIPRO-XXXXX-XXXXX-XXXXX-XXXXXXXX")
        self._key_edit.setMinimumWidth(400)
        self._key_edit.setStyleSheet("font-family: monospace; font-size: 14px;")
        activate_btn = self._primary_btn("✓ Activate")
        activate_btn.setFixedWidth(110)
        activate_btn.clicked.connect(self._activate)
        key_row.addWidget(self._key_edit)
        key_row.addWidget(activate_btn)
        key_row.addStretch()
        agl.addLayout(key_row)

        self._activate_result = QLabel("")
        self._activate_result.setWordWrap(True)
        agl.addWidget(self._activate_result)

        demo_row = QHBoxLayout()
        demo_note = QLabel("For evaluation:")
        demo_note.setObjectName("Muted")
        demo_key_btn = QPushButton("Generate Demo Key")
        demo_key_btn.clicked.connect(self._insert_demo_key)
        deactivate_btn = QPushButton("Deactivate")
        deactivate_btn.clicked.connect(self._deactivate)
        demo_row.addWidget(demo_note)
        demo_row.addWidget(demo_key_btn)
        demo_row.addStretch()
        demo_row.addWidget(deactivate_btn)
        agl.addLayout(demo_row)

        cl.addWidget(activate_group)

        # Features grid
        features_group = QGroupBox("Licensed Features")
        fgl = QVBoxLayout(features_group)
        self._features_lbl = QLabel()
        self._features_lbl.setWordWrap(True)
        self._features_lbl.setStyleSheet("color: #C9D1D9; line-height: 1.8;")
        fgl.addWidget(self._features_lbl)
        cl.addWidget(features_group)

        cl.addStretch()
        self._refresh_status()

    def _refresh_status(self) -> None:
        valid = self._config.get("license_valid", False)
        key = self._config.get("license_key", "")
        tier = self._config.get("license_tier", "Community")
        validated_at = self._config.get("license_validated_at", "")

        if valid and key:
            self._tier_lbl.setText(f"✓ {tier} License")
            self._tier_lbl.setStyleSheet("font-size: 20px; font-weight: 800; color: #3FB950;")
            self._status_lbl.setText("License active and verified")
            self._key_lbl.setText(f"Key: {key}")
            self._validated_lbl.setText(f"Validated: {validated_at[:19]}")
            features = _tier_features(tier)
        else:
            self._tier_lbl.setText("Community (Unlicensed)")
            self._tier_lbl.setStyleSheet("font-size: 20px; font-weight: 800; color: #D29922;")
            self._status_lbl.setText("No valid license key — running in community mode")
            self._key_lbl.setText("")
            self._validated_lbl.setText("")
            features = _tier_features("Community")

        self._features_lbl.setText(
            "  ✓  " + "\n  ✓  ".join(features)
        )

    def _activate(self) -> None:
        key = self._key_edit.text().strip()
        if not key:
            return
        ok, info = _validate_license_key(key)
        if ok:
            self._config.set("license_valid", True)
            self._config.set("license_key", key)
            self._config.set("license_tier", info["tier"])
            self._config.set("license_validated_at", info["validated_at"])
            self._activate_result.setText(f"✓ License activated — {info['tier']}")
            self._activate_result.setStyleSheet("color: #3FB950; font-weight: 600;")
            self._audit.record("license_activate", f"License activated: {info['tier']}")
        else:
            self._activate_result.setText(f"✗ {info.get('error', 'Invalid key')}")
            self._activate_result.setStyleSheet("color: #F85149; font-weight: 600;")
        self._refresh_status()

    def _deactivate(self) -> None:
        reply = QMessageBox.question(
            self, "Deactivate",
            "Deactivate the current license?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        self._config.set("license_valid", False)
        self._config.set("license_key", "")
        self._config.set("license_tier", "Community")
        self._audit.record("license_deactivate", "License deactivated")
        self._refresh_status()

    def _insert_demo_key(self) -> None:
        key = _generate_demo_key()
        self._key_edit.setText(key)
        self._activate_result.setText(f"Demo key generated: {key}")
        self._activate_result.setStyleSheet("color: #58A6FF;")
