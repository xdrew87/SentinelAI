"""
core/config.py – Application configuration with encrypted secret storage.

All sensitive values (API keys, passwords) are encrypted at rest using
Fernet symmetric encryption derived from a machine-unique key.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import struct
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

log = logging.getLogger(__name__)

_APP_NAME = "SentinelAI"
_CONFIG_FILE = "config.json"
_SECRETS_FILE = "secrets.enc"
_SALT_FILE = "salt.bin"


def _machine_id() -> str:
    """Return a stable, per-machine identifier used as the KDF password."""
    system = platform.system()
    try:
        if system == "Linux":
            mid = Path("/etc/machine-id").read_text().strip()
        elif system == "Darwin":
            import subprocess
            out = subprocess.check_output(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"], text=True
            )
            for line in out.splitlines():
                if "IOPlatformUUID" in line:
                    mid = line.split('"')[-2]
                    break
            else:
                mid = platform.node()
        elif system == "Windows":
            import subprocess
            out = subprocess.check_output(
                ["wmic", "csproduct", "get", "UUID"], text=True
            )
            mid = out.strip().splitlines()[-1].strip()
        else:
            mid = platform.node()
    except Exception:
        mid = platform.node()
    return mid or "sentinelai-default-machine-id"


class Config:
    """
    Manages persistent application settings and encrypted secrets.

    Plain settings are stored as JSON.  Secrets (API keys, etc.) are stored
    encrypted in a separate Fernet-encrypted file.
    """

    def __init__(self) -> None:
        self.app_data_dir: Path = self._resolve_app_data_dir()
        self.app_data_dir.mkdir(parents=True, exist_ok=True)

        self._config_path = self.app_data_dir / _CONFIG_FILE
        self._secrets_path = self.app_data_dir / _SECRETS_FILE
        self._salt_path = self.app_data_dir / _SALT_FILE

        self._fernet: Fernet = self._build_fernet()
        self._settings: dict[str, Any] = self._load_settings()
        self._secrets: dict[str, str] = self._load_secrets()

    # ── Public settings API ───────────────────────────────────────────────

    def get(self, key: str, default: Any = None) -> Any:
        """Return a plain setting value."""
        return self._settings.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Persist a plain setting value."""
        self._settings[key] = value
        self._save_settings()

    # ── Secrets API ───────────────────────────────────────────────────────

    def get_secret(self, key: str) -> str | None:
        """Return a decrypted secret value or None."""
        return self._secrets.get(key)

    def set_secret(self, key: str, value: str) -> None:
        """Encrypt and persist a secret value."""
        self._secrets[key] = value
        self._save_secrets()

    def delete_secret(self, key: str) -> None:
        """Remove a stored secret."""
        self._secrets.pop(key, None)
        self._save_secrets()

    def list_secret_keys(self) -> list[str]:
        """Return all stored secret key names (values remain encrypted)."""
        return list(self._secrets.keys())

    # ── Internal ──────────────────────────────────────────────────────────

    @staticmethod
    def _resolve_app_data_dir() -> Path:
        system = platform.system()
        if system == "Windows":
            base = Path(os.environ.get("APPDATA", Path.home()))
        elif system == "Darwin":
            base = Path.home() / "Library" / "Application Support"
        else:
            base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        return base / _APP_NAME

    def _get_or_create_salt(self) -> bytes:
        if self._salt_path.exists():
            return self._salt_path.read_bytes()
        salt = os.urandom(32)
        self._salt_path.write_bytes(salt)
        return salt

    def _build_fernet(self) -> Fernet:
        salt = self._get_or_create_salt()
        password = _machine_id().encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480_000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return Fernet(key)

    def _load_settings(self) -> dict[str, Any]:
        if not self._config_path.exists():
            return self._default_settings()
        try:
            data = json.loads(self._config_path.read_text(encoding="utf-8"))
            # Merge any missing defaults
            defaults = self._default_settings()
            for k, v in defaults.items():
                data.setdefault(k, v)
            return data
        except Exception as exc:
            log.warning("Could not load config (%s); using defaults.", exc)
            return self._default_settings()

    def _save_settings(self) -> None:
        try:
            self._config_path.write_text(
                json.dumps(self._settings, indent=2), encoding="utf-8"
            )
        except Exception as exc:
            log.error("Failed to save settings: %s", exc)

    def _load_secrets(self) -> dict[str, str]:
        if not self._secrets_path.exists():
            return {}
        try:
            raw = self._secrets_path.read_bytes()
            plaintext = self._fernet.decrypt(raw)
            return json.loads(plaintext.decode("utf-8"))
        except Exception as exc:
            log.warning("Could not decrypt secrets (%s); returning empty.", exc)
            return {}

    def _save_secrets(self) -> None:
        try:
            plaintext = json.dumps(self._secrets).encode("utf-8")
            ciphertext = self._fernet.encrypt(plaintext)
            self._secrets_path.write_bytes(ciphertext)
        except Exception as exc:
            log.error("Failed to save secrets: %s", exc)

    @staticmethod
    def _default_settings() -> dict[str, Any]:
        return {
            "theme": "dark",
            "ai_provider": "openai",
            "ai_model": "gpt-4o",
            "font_size": 13,
            "timeline_zoom": 1.0,
            "max_log_rows": 100_000,
            "report_output_dir": str(Path.home() / "SentinelAI_Reports"),
            "plugin_dir": "",
            "license_key": "",
            "license_valid": False,
            "first_run": True,
        }
