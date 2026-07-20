"""
core/evidence_parser.py – Parses all supported evidence types into log_events rows.

Supported formats:
  EVTX, Sysmon (EVTX), Suricata JSON, Cowrie JSON, Zeek TSV/JSON,
  Apache/Nginx access logs, Linux auth.log, Windows Defender CSV,
  CSV, JSON, TXT, XML, Email headers.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from core.database import Database

log = logging.getLogger(__name__)

# ── Apache/Nginx combined-log pattern ─────────────────────────────────────
_APACHE_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+)?\s*(?P<path>[^"]*?)\s*(?P<proto>HTTP/[^"]+)?" '
    r'(?P<status>\d+) (?P<size>\S+)'
)
# ── Linux auth.log pattern ────────────────────────────────────────────────
_AUTHLOG_RE = re.compile(
    r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)'
    r'\s+(?P<host>\S+)\s+(?P<proc>[^:]+):\s*(?P<msg>.*)'
)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _md5(path: Path) -> str:
    h = hashlib.md5()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class EvidenceParser:
    """Parses evidence files and inserts log_events into the database."""

    def __init__(self, db: "Database") -> None:
        self._db = db

    # ── Public ─────────────────────────────────────────────────────────────

    def ingest(
        self,
        case_id: int,
        file_path: Path,
        evidence_name: str = "",
        notes: str = "",
        progress_cb=None,
    ) -> int:
        """
        Ingest a file into the database.

        Returns the evidence.id of the created record.
        """
        name = evidence_name or file_path.name
        size = file_path.stat().st_size
        sha256 = _sha256(file_path)
        md5 = _md5(file_path)
        file_type = self._detect_type(file_path)

        ev_id = self._db.insert(
            """INSERT INTO evidence
               (case_id, name, file_path, file_type, file_size, sha256, md5, notes)
               VALUES (?,?,?,?,?,?,?,?)""",
            (case_id, name, str(file_path), file_type, size, sha256, md5, notes),
        )

        try:
            count = self._parse(case_id, ev_id, file_path, file_type, progress_cb)
            self._db.update(
                "UPDATE evidence SET parsed=1 WHERE id=?", (ev_id,)
            )
            log.info("Ingested %d events from %s (evidence_id=%d)", count, file_path.name, ev_id)
        except Exception as exc:
            log.error("Parse failed for %s: %s", file_path, exc)

        return ev_id

    # ── Type detection ─────────────────────────────────────────────────────

    def _detect_type(self, path: Path) -> str:
        ext = path.suffix.lower()
        name = path.name.lower()
        if ext == ".evtx":
            return "evtx"
        if ext == ".pcap" or ext == ".pcapng":
            return "pcap"
        if "suricata" in name and ext == ".json":
            return "suricata"
        if "cowrie" in name and ext == ".json":
            return "cowrie"
        if "zeek" in name or "bro" in name:
            return "zeek"
        if "auth" in name and ext in (".log", ".txt", ""):
            return "authlog"
        if "defender" in name and ext == ".csv":
            return "defender"
        if "apache" in name or "access" in name:
            return "apache"
        if "nginx" in name:
            return "nginx"
        if ext == ".csv":
            return "csv"
        if ext == ".json":
            return "json"
        if ext == ".xml":
            return "xml"
        if ext in (".txt", ".log"):
            return "txt"
        if "email" in name or ext in (".eml", ".msg"):
            return "email"
        return "unknown"

    # ── Dispatcher ─────────────────────────────────────────────────────────

    def _parse(
        self,
        case_id: int,
        ev_id: int,
        path: Path,
        file_type: str,
        progress_cb=None,
    ) -> int:
        parsers = {
            "evtx": self._parse_evtx,
            "suricata": self._parse_suricata,
            "cowrie": self._parse_cowrie,
            "zeek": self._parse_zeek,
            "authlog": self._parse_authlog,
            "apache": self._parse_apache,
            "nginx": self._parse_apache,
            "defender": self._parse_defender,
            "csv": self._parse_csv,
            "json": self._parse_json,
            "xml": self._parse_xml,
            "txt": self._parse_txt,
            "email": self._parse_email,
        }
        parser = parsers.get(file_type, self._parse_txt)
        rows = list(parser(path, case_id, ev_id))
        if rows:
            self._batch_insert(rows, progress_cb)
        return len(rows)

    def _batch_insert(self, rows: list[dict], progress_cb=None) -> None:
        sql = """INSERT INTO log_events
                 (case_id, evidence_id, source_type, timestamp, level,
                  event_id, source_host, source_ip, dest_ip, user,
                  process, message, raw, tags)
                 VALUES
                 (:case_id, :evidence_id, :source_type, :timestamp, :level,
                  :event_id, :source_host, :source_ip, :dest_ip, :user,
                  :process, :message, :raw, :tags)"""
        batch: list[tuple] = []
        for i, row in enumerate(rows):
            batch.append((
                row.get("case_id", 0),
                row.get("evidence_id", 0),
                row.get("source_type", ""),
                row.get("timestamp", ""),
                row.get("level", ""),
                row.get("event_id", ""),
                row.get("source_host", ""),
                row.get("source_ip", ""),
                row.get("dest_ip", ""),
                row.get("user", ""),
                row.get("process", ""),
                row.get("message", "")[:4000],
                row.get("raw", "")[:8000],
                row.get("tags", ""),
            ))
            if len(batch) >= 1000:
                self._db.executemany(
                    """INSERT INTO log_events
                       (case_id,evidence_id,source_type,timestamp,level,
                        event_id,source_host,source_ip,dest_ip,user,
                        process,message,raw,tags)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    batch,
                )
                self._db.commit()
                if progress_cb:
                    progress_cb(i + 1, len(rows))
                batch.clear()
        if batch:
            self._db.executemany(
                """INSERT INTO log_events
                   (case_id,evidence_id,source_type,timestamp,level,
                    event_id,source_host,source_ip,dest_ip,user,
                    process,message,raw,tags)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                batch,
            )
            self._db.commit()

    # ── EVTX ───────────────────────────────────────────────────────────────

    def _parse_evtx(
        self, path: Path, case_id: int, ev_id: int
    ) -> Generator[dict, None, None]:
        try:
            from evtx import PyEvtxParser  # python-evtx
        except ImportError:
            log.error("python-evtx not installed; cannot parse EVTX files.")
            return
        parser = PyEvtxParser(str(path))
        for record in parser.records_json():
            try:
                data = json.loads(record["data"])
                sys_data = data.get("Event", {}).get("System", {})
                event_data = data.get("Event", {}).get("EventData", {}) or {}
                user_data = data.get("Event", {}).get("UserData", {}) or {}
                ts = sys_data.get("TimeCreated", {})
                if isinstance(ts, dict):
                    ts = ts.get("#attributes", {}).get("SystemTime", "")
                level_map = {"0": "info", "1": "critical", "2": "error",
                             "3": "warning", "4": "info", "5": "verbose"}
                level_raw = str(sys_data.get("Level", "4"))
                message_parts = []
                if isinstance(event_data, dict):
                    for k, v in event_data.items():
                        if k.startswith("#"):
                            continue
                        message_parts.append(f"{k}={v}")
                yield {
                    "case_id": case_id,
                    "evidence_id": ev_id,
                    "source_type": "evtx",
                    "timestamp": str(ts),
                    "level": level_map.get(level_raw, "info"),
                    "event_id": str(sys_data.get("EventID", "")),
                    "source_host": str(sys_data.get("Computer", "")),
                    "source_ip": "",
                    "dest_ip": "",
                    "user": str(
                        (data.get("Event", {})
                         .get("System", {})
                         .get("Security", {}) or {})
                        .get("#attributes", {})
                        .get("UserID", "")
                    ),
                    "process": str(sys_data.get("Provider", {})
                                   .get("#attributes", {})
                                   .get("Name", "") if isinstance(sys_data.get("Provider"), dict)
                                   else sys_data.get("Provider", "")),
                    "message": " | ".join(message_parts)[:4000],
                    "raw": record["data"][:8000],
                    "tags": "",
                }
            except Exception as exc:
                log.debug("EVTX record parse error: %s", exc)

    # ── Suricata ───────────────────────────────────────────────────────────

    def _parse_suricata(
        self, path: Path, case_id: int, ev_id: int
    ) -> Generator[dict, None, None]:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    severity_map = {1: "critical", 2: "high", 3: "medium"}
                    sig = obj.get("alert", {})
                    yield {
                        "case_id": case_id,
                        "evidence_id": ev_id,
                        "source_type": "suricata",
                        "timestamp": obj.get("timestamp", ""),
                        "level": severity_map.get(sig.get("severity", 3), "medium"),
                        "event_id": str(sig.get("signature_id", "")),
                        "source_host": "",
                        "source_ip": obj.get("src_ip", ""),
                        "dest_ip": obj.get("dest_ip", ""),
                        "user": "",
                        "process": obj.get("proto", ""),
                        "message": sig.get("signature", obj.get("event_type", "")),
                        "raw": line[:8000],
                        "tags": obj.get("event_type", ""),
                    }
                except Exception:
                    continue

    # ── Cowrie ─────────────────────────────────────────────────────────────

    def _parse_cowrie(
        self, path: Path, case_id: int, ev_id: int
    ) -> Generator[dict, None, None]:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    yield {
                        "case_id": case_id,
                        "evidence_id": ev_id,
                        "source_type": "cowrie",
                        "timestamp": obj.get("timestamp", ""),
                        "level": "warning",
                        "event_id": obj.get("eventid", ""),
                        "source_host": obj.get("sensor", ""),
                        "source_ip": obj.get("src_ip", ""),
                        "dest_ip": "",
                        "user": obj.get("username", ""),
                        "process": "cowrie",
                        "message": obj.get("message", obj.get("input", "")),
                        "raw": line[:8000],
                        "tags": "honeypot",
                    }
                except Exception:
                    continue

    # ── Zeek ───────────────────────────────────────────────────────────────

    def _parse_zeek(
        self, path: Path, case_id: int, ev_id: int
    ) -> Generator[dict, None, None]:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            fields: list[str] = []
            for line in f:
                if line.startswith("#fields"):
                    fields = line.strip().split("\t")[1:]
                    continue
                if line.startswith("#"):
                    continue
                parts = line.strip().split("\t")
                if not parts or not fields:
                    continue
                row = dict(zip(fields, parts))
                ts_raw = row.get("ts", "")
                try:
                    ts = datetime.fromtimestamp(float(ts_raw), tz=timezone.utc).isoformat()
                except Exception:
                    ts = ts_raw
                yield {
                    "case_id": case_id,
                    "evidence_id": ev_id,
                    "source_type": "zeek",
                    "timestamp": ts,
                    "level": "info",
                    "event_id": "",
                    "source_host": "",
                    "source_ip": row.get("id.orig_h", row.get("orig_h", "")),
                    "dest_ip": row.get("id.resp_h", row.get("resp_h", "")),
                    "user": row.get("user", row.get("username", "")),
                    "process": row.get("proto", path.stem),
                    "message": " ".join(f"{k}={v}" for k, v in row.items()
                                        if k not in ("ts",))[:4000],
                    "raw": line[:8000],
                    "tags": "zeek",
                }

    # ── Auth.log ───────────────────────────────────────────────────────────

    def _parse_authlog(
        self, path: Path, case_id: int, ev_id: int
    ) -> Generator[dict, None, None]:
        year = datetime.now().year
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                m = _AUTHLOG_RE.match(line)
                if not m:
                    yield {
                        "case_id": case_id, "evidence_id": ev_id,
                        "source_type": "authlog", "timestamp": "", "level": "info",
                        "event_id": "", "source_host": "", "source_ip": "",
                        "dest_ip": "", "user": "", "process": "",
                        "message": line.strip()[:4000], "raw": line[:8000], "tags": "",
                    }
                    continue
                msg = m.group("msg")
                ts_str = f"{year} {m.group('month')} {m.group('day')} {m.group('time')}"
                try:
                    ts = datetime.strptime(ts_str, "%Y %b %d %H:%M:%S").isoformat()
                except Exception:
                    ts = ts_str
                # Extract user/IP hints
                user_m = re.search(r"user (\S+)", msg, re.I)
                ip_m = re.search(r"from (\d+\.\d+\.\d+\.\d+)", msg)
                level = "warning" if any(k in msg.lower() for k in
                                         ("fail", "invalid", "error", "denied")) else "info"
                yield {
                    "case_id": case_id, "evidence_id": ev_id,
                    "source_type": "authlog", "timestamp": ts, "level": level,
                    "event_id": "", "source_host": m.group("host"),
                    "source_ip": ip_m.group(1) if ip_m else "",
                    "dest_ip": "", "user": user_m.group(1) if user_m else "",
                    "process": m.group("proc").strip(), "message": msg[:4000],
                    "raw": line[:8000], "tags": "",
                }

    # ── Apache / Nginx ─────────────────────────────────────────────────────

    def _parse_apache(
        self, path: Path, case_id: int, ev_id: int
    ) -> Generator[dict, None, None]:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                m = _APACHE_RE.match(line)
                if not m:
                    continue
                status = m.group("status")
                level = "error" if status.startswith("5") else \
                        "warning" if status.startswith("4") else "info"
                yield {
                    "case_id": case_id, "evidence_id": ev_id,
                    "source_type": "apache",
                    "timestamp": m.group("time"),
                    "level": level,
                    "event_id": status,
                    "source_host": "", "source_ip": m.group("ip"),
                    "dest_ip": "",
                    "user": "",
                    "process": "httpd",
                    "message": f"{m.group('method')} {m.group('path')} → {status}",
                    "raw": line[:8000], "tags": "",
                }

    # ── Windows Defender CSV ───────────────────────────────────────────────

    def _parse_defender(
        self, path: Path, case_id: int, ev_id: int
    ) -> Generator[dict, None, None]:
        with path.open("r", encoding="utf-8-sig", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                yield {
                    "case_id": case_id, "evidence_id": ev_id,
                    "source_type": "defender",
                    "timestamp": row.get("Date", row.get("Timestamp", "")),
                    "level": "warning",
                    "event_id": row.get("ThreatID", row.get("ID", "")),
                    "source_host": row.get("Computer Name", ""),
                    "source_ip": "",
                    "dest_ip": "",
                    "user": row.get("User", ""),
                    "process": row.get("Process Name", ""),
                    "message": row.get("Threat Name",
                                       row.get("Description", str(dict(row))))[:4000],
                    "raw": str(dict(row))[:8000],
                    "tags": "defender,av",
                }

    # ── Generic CSV ────────────────────────────────────────────────────────

    def _parse_csv(
        self, path: Path, case_id: int, ev_id: int
    ) -> Generator[dict, None, None]:
        with path.open("r", encoding="utf-8-sig", errors="replace") as f:
            reader = csv.DictReader(f)
            ts_keys = ["timestamp", "time", "date", "datetime", "@timestamp"]
            msg_keys = ["message", "msg", "description", "event", "log"]
            for row in reader:
                keys_lower = {k.lower(): v for k, v in row.items()}
                ts = next((keys_lower[k] for k in ts_keys if k in keys_lower), "")
                msg = next((keys_lower[k] for k in msg_keys if k in keys_lower),
                           str(dict(row)))
                yield {
                    "case_id": case_id, "evidence_id": ev_id,
                    "source_type": "csv", "timestamp": ts, "level": "info",
                    "event_id": "", "source_host": "", "source_ip": "",
                    "dest_ip": "", "user": "", "process": "",
                    "message": msg[:4000], "raw": str(dict(row))[:8000], "tags": "",
                }

    # ── Generic JSON ───────────────────────────────────────────────────────

    def _parse_json(
        self, path: Path, case_id: int, ev_id: int
    ) -> Generator[dict, None, None]:
        raw = path.read_text(encoding="utf-8", errors="replace")
        try:
            data = json.loads(raw)
        except Exception:
            # Try line-by-line NDJSON
            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    yield self._json_obj_to_event(obj, line, case_id, ev_id)
                except Exception:
                    continue
            return
        if isinstance(data, list):
            for obj in data:
                yield self._json_obj_to_event(obj, json.dumps(obj), case_id, ev_id)
        elif isinstance(data, dict):
            yield self._json_obj_to_event(data, raw[:8000], case_id, ev_id)

    def _json_obj_to_event(self, obj: dict, raw: str, case_id: int, ev_id: int) -> dict:
        ts_keys = ["timestamp", "@timestamp", "time", "datetime", "ts"]
        ts = next((str(obj[k]) for k in ts_keys if k in obj), "")
        return {
            "case_id": case_id, "evidence_id": ev_id,
            "source_type": "json", "timestamp": ts, "level": "info",
            "event_id": str(obj.get("event_id", obj.get("id", ""))),
            "source_host": str(obj.get("host", obj.get("hostname", ""))),
            "source_ip": str(obj.get("src_ip", obj.get("source_ip", ""))),
            "dest_ip": str(obj.get("dest_ip", obj.get("destination_ip", ""))),
            "user": str(obj.get("user", obj.get("username", ""))),
            "process": str(obj.get("process", obj.get("proc", ""))),
            "message": str(obj.get("message", obj.get("msg", str(obj))))[:4000],
            "raw": raw[:8000], "tags": "",
        }

    # ── XML ────────────────────────────────────────────────────────────────

    def _parse_xml(
        self, path: Path, case_id: int, ev_id: int
    ) -> Generator[dict, None, None]:
        try:
            tree = ET.parse(str(path))
            root = tree.getroot()
        except Exception as exc:
            log.error("XML parse failed: %s", exc)
            return
        for elem in root.iter():
            text = (elem.text or "").strip()
            if not text:
                continue
            yield {
                "case_id": case_id, "evidence_id": ev_id,
                "source_type": "xml", "timestamp": "", "level": "info",
                "event_id": "", "source_host": "", "source_ip": "",
                "dest_ip": "", "user": "", "process": "",
                "message": f"{elem.tag}: {text}"[:4000],
                "raw": ET.tostring(elem, encoding="unicode")[:8000], "tags": "",
            }

    # ── Plain text ─────────────────────────────────────────────────────────

    def _parse_txt(
        self, path: Path, case_id: int, ev_id: int
    ) -> Generator[dict, None, None]:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line.strip():
                    continue
                yield {
                    "case_id": case_id, "evidence_id": ev_id,
                    "source_type": "txt", "timestamp": "", "level": "info",
                    "event_id": "", "source_host": "", "source_ip": "",
                    "dest_ip": "", "user": "", "process": "",
                    "message": line[:4000], "raw": line[:8000], "tags": "",
                }

    # ── Email headers ──────────────────────────────────────────────────────

    def _parse_email(
        self, path: Path, case_id: int, ev_id: int
    ) -> Generator[dict, None, None]:
        import email
        raw = path.read_bytes()
        msg = email.message_from_bytes(raw)
        headers = dict(msg.items())
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                if ct == "text/plain":
                    try:
                        body = part.get_payload(decode=True).decode("utf-8", errors="replace")
                    except Exception:
                        pass
                    break
        else:
            try:
                body = msg.get_payload(decode=True).decode("utf-8", errors="replace")
            except Exception:
                pass
        yield {
            "case_id": case_id, "evidence_id": ev_id,
            "source_type": "email",
            "timestamp": headers.get("Date", ""),
            "level": "info",
            "event_id": headers.get("Message-ID", ""),
            "source_host": headers.get("Received", "").split(" ")[-1]
                          if headers.get("Received") else "",
            "source_ip": "",
            "dest_ip": "",
            "user": headers.get("From", ""),
            "process": "email",
            "message": f"Subject: {headers.get('Subject','')} | From: {headers.get('From','')} | To: {headers.get('To','')}",
            "raw": str(headers)[:8000],
            "tags": "email",
        }
