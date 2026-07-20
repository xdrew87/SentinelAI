"""
core/sigma_engine.py – Sigma rule evaluation against log events.

Parses Sigma YAML and evaluates detection conditions against event dicts.
Implements the core Sigma condition grammar without external dependencies.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Optional, TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from core.database import Database

log = logging.getLogger(__name__)


class SigmaCondition:
    """Evaluate a single Sigma detection condition against an event."""

    def __init__(self, rule: dict) -> None:
        self.title = rule.get("title", "")
        self.detection = rule.get("detection", {})
        self.condition_str: str = str(self.detection.get("condition", "all of them"))

    def matches(self, event: dict) -> bool:
        """Return True if the event matches the detection condition."""
        try:
            return self._eval_condition(self.condition_str, event)
        except Exception as exc:
            log.debug("Sigma eval error in '%s': %s", self.title, exc)
            return False

    def _eval_condition(self, cond: str, event: dict) -> bool:
        cond = cond.strip()

        # "all of them" / "1 of them"
        if cond == "all of them":
            identifiers = [k for k in self.detection if k != "condition"]
            return all(self._eval_identifier(k, event) for k in identifiers)
        if re.match(r"1 of them", cond):
            identifiers = [k for k in self.detection if k != "condition"]
            return any(self._eval_identifier(k, event) for k in identifiers)

        # "all of filter*" / "1 of filter*"
        all_match = re.match(r"all of (\w+)\*", cond)
        if all_match:
            prefix = all_match.group(1)
            keys = [k for k in self.detection if k.startswith(prefix) and k != "condition"]
            return all(self._eval_identifier(k, event) for k in keys)
        one_match = re.match(r"1 of (\w+)\*", cond)
        if one_match:
            prefix = one_match.group(1)
            keys = [k for k in self.detection if k.startswith(prefix) and k != "condition"]
            return any(self._eval_identifier(k, event) for k in keys)

        # Boolean: and / or / not
        if " and " in cond.lower():
            parts = re.split(r"\band\b", cond, flags=re.I)
            return all(self._eval_condition(p, event) for p in parts)
        if " or " in cond.lower():
            parts = re.split(r"\bor\b", cond, flags=re.I)
            return any(self._eval_condition(p, event) for p in parts)
        if cond.lower().startswith("not "):
            return not self._eval_condition(cond[4:], event)

        # Parentheses
        if cond.startswith("(") and cond.endswith(")"):
            return self._eval_condition(cond[1:-1], event)

        # Single identifier
        return self._eval_identifier(cond.strip(), event)

    def _eval_identifier(self, key: str, event: dict) -> bool:
        selection = self.detection.get(key)
        if selection is None:
            return False
        if isinstance(selection, list):
            # List of keyword strings – OR logic
            return any(self._match_value(v, event) for v in selection)
        if isinstance(selection, dict):
            # Field: value mapping
            return self._match_field_dict(selection, event)
        # Plain string keyword
        return self._match_value(selection, event)

    def _match_field_dict(self, field_map: dict, event: dict) -> bool:
        """All field conditions must match (AND within a selection block)."""
        for field, values in field_map.items():
            field_clean = field.rstrip("|contains|startswith|endswith|re|all").rstrip("|")
            modifier = ""
            if "|" in field:
                parts = field.split("|")
                field_clean = parts[0]
                modifier = "|".join(parts[1:]).lower()

            event_val = self._get_field(event, field_clean)
            if event_val is None:
                return False

            value_list = values if isinstance(values, list) else [values]

            if "all" in modifier:
                if not all(self._compare(str(event_val), str(v), modifier) for v in value_list):
                    return False
            else:
                if not any(self._compare(str(event_val), str(v), modifier) for v in value_list):
                    return False
        return True

    @staticmethod
    def _get_field(event: dict, field: str) -> Optional[Any]:
        """Case-insensitive field lookup."""
        field_lower = field.lower()
        for k, v in event.items():
            if k.lower() == field_lower:
                return v
        return None

    @staticmethod
    def _compare(event_val: str, rule_val: str, modifier: str) -> bool:
        ev = event_val.lower()
        rv = rule_val.lower().replace("*", ".*").replace("?", ".")
        if "startswith" in modifier:
            return ev.startswith(rule_val.lower())
        if "endswith" in modifier:
            return ev.endswith(rule_val.lower())
        if "contains" in modifier:
            return rule_val.lower() in ev
        if "re" in modifier:
            return bool(re.search(rule_val, event_val, re.I))
        # Default: wildcard glob
        pattern = "^" + re.escape(rule_val.lower()).replace(r"\*", ".*").replace(r"\?", ".") + "$"
        return bool(re.match(pattern, ev))

    def _match_value(self, value: str, event: dict) -> bool:
        """Check if any event field contains the keyword."""
        v = str(value).lower()
        return any(v in str(ev_val).lower() for ev_val in event.values() if ev_val)


class SigmaEngine:
    """Load, store, and apply Sigma rules against events."""

    def __init__(self, db: "Database") -> None:
        self._db = db
        self._rules_cache: Optional[list[tuple[dict, SigmaCondition]]] = None

    def reload(self) -> None:
        self._rules_cache = None

    def scan_event(self, event: dict) -> list[dict]:
        """Return list of matching Sigma rule records for a single event."""
        rules = self._get_rules()
        matches = []
        for rule_meta, condition in rules:
            if condition.matches(event):
                matches.append(rule_meta)
        return matches

    def scan_events(self, events: list[dict]) -> dict[int, list[dict]]:
        """
        Scan a list of events.
        Returns {event_index: [matching_rule_meta, ...]}
        """
        rules = self._get_rules()
        results: dict[int, list[dict]] = {}
        for idx, event in enumerate(events):
            hits = []
            for rule_meta, condition in rules:
                if condition.matches(event):
                    hits.append(rule_meta)
            if hits:
                results[idx] = hits
        return results

    def validate_yaml(self, rule_yaml: str) -> tuple[bool, str]:
        try:
            rule = yaml.safe_load(rule_yaml)
            if "detection" not in rule:
                return False, "Missing 'detection' key"
            if "condition" not in rule.get("detection", {}):
                return False, "Missing 'condition' in detection"
            return True, ""
        except Exception as exc:
            return False, str(exc)

    def _get_rules(self) -> list[tuple[dict, SigmaCondition]]:
        if self._rules_cache is not None:
            return self._rules_cache
        rows = self._db.fetchall(
            "SELECT * FROM sigma_rules WHERE enabled=1"
        )
        compiled: list[tuple[dict, SigmaCondition]] = []
        for row in rows:
            try:
                rule_dict = yaml.safe_load(row["rule_yaml"])
                cond = SigmaCondition(rule_dict)
                meta = {
                    "id": row["id"],
                    "name": row["name"],
                    "severity": row["severity"],
                    "description": row["description"],
                    "tags": row["tags"],
                    "mitre_tags": row["mitre_tags"],
                }
                compiled.append((meta, cond))
            except Exception as exc:
                log.warning("Failed to compile Sigma rule '%s': %s", row["name"], exc)
        self._rules_cache = compiled
        return compiled
