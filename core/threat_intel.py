"""
core/threat_intel.py – IOC enrichment via multiple threat intelligence providers.

Supports: VirusTotal, AbuseIPDB, AlienVault OTX, Shodan, URLhaus.
API keys are retrieved from encrypted config storage.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional, TYPE_CHECKING

import requests

if TYPE_CHECKING:
    from core.config import Config
    from core.database import Database

log = logging.getLogger(__name__)
_TIMEOUT = 30


class ThreatIntelEngine:
    """Enrich IOCs using configured threat intelligence providers."""

    def __init__(self, config: "Config", db: "Database") -> None:
        self._config = config
        self._db = db

    # ── Public API ─────────────────────────────────────────────────────────

    def enrich_ioc(self, ioc_type: str, value: str) -> dict:
        """
        Enrich a single IOC.  Returns aggregated intelligence as a dict.
        Results are cached in threat_intel table.
        """
        results: dict = {"ioc_type": ioc_type, "value": value, "sources": []}

        if ioc_type == "ip":
            self._enrich_vt(ioc_type, value, results)
            self._enrich_abuseipdb(value, results)
            self._enrich_otx(ioc_type, value, results)
        elif ioc_type == "domain":
            self._enrich_vt(ioc_type, value, results)
            self._enrich_otx(ioc_type, value, results)
        elif ioc_type == "url":
            self._enrich_vt(ioc_type, value, results)
            self._enrich_urlhaus(value, results)
        elif ioc_type == "hash":
            self._enrich_vt(ioc_type, value, results)
        else:
            log.warning("No enrichment handler for ioc_type=%r", ioc_type)

        self._cache(ioc_type, value, results)
        return results

    def get_cached(self, ioc_type: str, value: str) -> Optional[dict]:
        row = self._db.fetchone(
            "SELECT * FROM threat_intel WHERE ioc_type=? AND value=? ORDER BY fetched_at DESC LIMIT 1",
            (ioc_type, value),
        )
        if not row:
            return None
        return dict(row)

    # ── VirusTotal ─────────────────────────────────────────────────────────

    def _enrich_vt(self, ioc_type: str, value: str, results: dict) -> None:
        api_key = self._config.get_secret("virustotal_api_key")
        if not api_key:
            return
        try:
            type_map = {"ip": "ip_addresses", "domain": "domains",
                        "url": "urls", "hash": "files"}
            endpoint = type_map.get(ioc_type, "files")
            if ioc_type == "url":
                import base64
                url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
                url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            else:
                url = f"https://www.virustotal.com/api/v3/{endpoint}/{value}"
            resp = requests.get(url, headers={"x-apikey": api_key}, timeout=_TIMEOUT)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values()) if stats else 0
                results["sources"].append({
                    "provider": "VirusTotal",
                    "malicious": malicious,
                    "total_engines": total,
                    "reputation": data.get("reputation", 0),
                    "tags": data.get("tags", []),
                    "country": data.get("country", ""),
                    "as_owner": data.get("as_owner", ""),
                })
        except Exception as exc:
            log.debug("VirusTotal enrichment failed for %s: %s", value, exc)

    # ── AbuseIPDB ──────────────────────────────────────────────────────────

    def _enrich_abuseipdb(self, ip: str, results: dict) -> None:
        api_key = self._config.get_secret("abuseipdb_api_key")
        if not api_key:
            return
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                headers={"Key": api_key, "Accept": "application/json"},
                timeout=_TIMEOUT,
            )
            if resp.status_code == 200:
                d = resp.json().get("data", {})
                results["sources"].append({
                    "provider": "AbuseIPDB",
                    "abuse_confidence": d.get("abuseConfidenceScore", 0),
                    "country": d.get("countryCode", ""),
                    "isp": d.get("isp", ""),
                    "total_reports": d.get("totalReports", 0),
                    "last_reported": d.get("lastReportedAt", ""),
                })
        except Exception as exc:
            log.debug("AbuseIPDB enrichment failed for %s: %s", ip, exc)

    # ── AlienVault OTX ─────────────────────────────────────────────────────

    def _enrich_otx(self, ioc_type: str, value: str, results: dict) -> None:
        api_key = self._config.get_secret("otx_api_key")
        if not api_key:
            return
        try:
            type_map = {"ip": "IPv4", "domain": "domain", "hash": "file"}
            section = "general"
            otx_type = type_map.get(ioc_type, ioc_type)
            url = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{value}/{section}"
            resp = requests.get(
                url, headers={"X-OTX-API-KEY": api_key}, timeout=_TIMEOUT
            )
            if resp.status_code == 200:
                d = resp.json()
                pulses = d.get("pulse_info", {}).get("count", 0)
                results["sources"].append({
                    "provider": "AlienVault OTX",
                    "pulse_count": pulses,
                    "reputation": d.get("reputation", 0),
                    "sections": d.get("sections", []),
                })
        except Exception as exc:
            log.debug("OTX enrichment failed for %s: %s", value, exc)

    # ── URLhaus ────────────────────────────────────────────────────────────

    def _enrich_urlhaus(self, url_val: str, results: dict) -> None:
        try:
            resp = requests.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": url_val},
                timeout=_TIMEOUT,
            )
            if resp.status_code == 200:
                d = resp.json()
                if d.get("query_status") == "is_listed":
                    results["sources"].append({
                        "provider": "URLhaus",
                        "threat": d.get("threat", ""),
                        "url_status": d.get("url_status", ""),
                        "tags": d.get("tags", []),
                        "date_added": d.get("date_added", ""),
                    })
        except Exception as exc:
            log.debug("URLhaus enrichment failed for %s: %s", url_val, exc)

    # ── Cache ──────────────────────────────────────────────────────────────

    def _cache(self, ioc_type: str, value: str, results: dict) -> None:
        raw = json.dumps(results, default=str)
        confidence = 0.0
        country = ""
        malware_family = ""
        tags_list: list[str] = []
        threat_type = ""
        for src in results.get("sources", []):
            if src.get("abuse_confidence"):
                confidence = max(confidence, src["abuse_confidence"] / 100.0)
            if src.get("malicious", 0) > 0:
                confidence = max(confidence, 0.8)
                threat_type = "malicious"
            if src.get("country"):
                country = src["country"]
            if isinstance(src.get("tags"), list):
                tags_list.extend(src["tags"])
        try:
            self._db.update(
                """INSERT OR REPLACE INTO threat_intel
                   (ioc_type, value, provider, threat_type, confidence,
                    country, tags, raw_data, fetched_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    ioc_type, value, "aggregated", threat_type, confidence,
                    country, ",".join(tags_list), raw[:8000] if (raw := raw) else "",
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
        except Exception as exc:
            log.debug("Cache write failed: %s", exc)
