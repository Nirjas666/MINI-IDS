"""MITRE ATT&CK mapping helper module.

This module provides a lightweight, dependency-free mapping engine that
maps human-readable IDS alert strings to MITRE ATT&CK tactics and techniques.

Usage:
    from src.mitre_mapper import annotate_alert
    mapping = annotate_alert("Port scan detected from 1.2.3.4: probed 25 distinct ports")

The annotate_alert function returns a dict with the original alert, a boolean
indicating whether a mapping was found, the matched technique/tactic, and a
`summary` string suitable for appending to human-readable logs.

It also exposes write_mapping_json to append machine-readable mapping records
to a JSON-lines file for downstream analysis.

This module intentionally performs simple, conservative substring matching on
alert text to avoid false positives. It is easy to extend the MITRE_MAPPING
dictionary for additional alerts.
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Dict, Optional

# Output file (newline-delimited JSON entries)
DEFAULT_MITRE_JSON_LOG = os.path.join("logs", "ids_alerts_mitre.jsonl")

# Simple mapping table: alert keyword -> MITRE technique/tactic
# Extend this dictionary with additional alert names as needed.
MITRE_MAPPING: Dict[str, Dict[str, str]] = {
    "Port Scan": {
        "technique_id": "T1046",
        "technique": "Network Service Discovery",
        "tactic": "Discovery",
    },
    "Brute Force Login": {
        "technique_id": "T1110",
        "technique": "Brute Force",
        "tactic": "Credential Access",
    },
    "Suspicious PowerShell": {
        "technique_id": "T1059.001",
        "technique": "PowerShell",
        "tactic": "Execution",
    },
    "Command Injection": {
        "technique_id": "T1059",
        "technique": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    "DNS Tunneling": {
        "technique_id": "T1071.004",
        "technique": "Application Layer Protocol: DNS",
        "tactic": "Command and Control",
    },
    "SYN flood": {
        "technique_id": "T1499.001",
        "technique": "SYN Flood",
        "tactic": "Impact",
    },
    "ICMP flood": {
        "technique_id": "T1499.003",
        "technique": "ICMP Flood",
        "tactic": "Impact",
    },
    "UDP flood": {
        "technique_id": "T1499.002",
        "technique": "UDP Flood",
        "tactic": "Impact",
    },
    "Suspicious activity": {
        "technique_id": "T1204",
        "technique": "User Execution",
        "tactic": "Execution",
    },
    "High global packet rate": {
        "technique_id": "T1499",
        "technique": "Endpoint Denial of Service",
        "tactic": "Impact",
    },
}


def _match_mapping(alert_text: str) -> Optional[Dict[str, str]]:
    """Return the MITRE mapping for the first matching key found in alert_text.

    Matching is case-insensitive and uses simple substring checks against the
    keys in MITRE_MAPPING. The search order follows the insertion order of the
    dictionary, which makes it predictable and easy to tune.
    """
    if not alert_text:
        return None
    lowered = alert_text.lower()
    for key, value in MITRE_MAPPING.items():
        if key.lower() in lowered:
            # Return a shallow copy so callers can safely attach additional fields
            return dict(value)
    return None


def annotate_alert(alert_text: str, timestamp_utc: Optional[str] = None) -> Dict:
    """Annotate an IDS alert string with MITRE ATT&CK mapping information.

    Returns a dict with keys:
      - original_alert: str
      - timestamp_utc: ISO timestamp string (if not provided, populated automatically)
      - mapped: bool
      - technique_id, technique, tactic: present when mapped is True
      - summary: short human-readable summary suitable for appending to text logs
    """
    ts = timestamp_utc or datetime.utcnow().isoformat() + "Z"
    mapping = _match_mapping(alert_text)
    result = {
        "original_alert": alert_text,
        "timestamp_utc": ts,
        "mapped": bool(mapping),
        "summary": "",
    }
    if mapping:
        result.update(mapping)
        result["summary"] = f"MITRE: {mapping['technique_id']} - {mapping['technique']} ({mapping['tactic']})"
    else:
        result["summary"] = "MITRE: no mapping found"
    return result


def write_mapping_json(mapping_record: Dict, path: Optional[str] = None) -> None:
    """Append a mapping record as JSON (one object per line) to the given path.

    Creates the parent directory if needed. This function is tolerant to
    concurrent appends (simple file append) and avoids raising on common
    filesystem errors to prevent breaking the IDS workflow.
    """
    out_path = path or DEFAULT_MITRE_JSON_LOG
    try:
        parent = os.path.dirname(out_path)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)
        with open(out_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(mapping_record, ensure_ascii=False) + "\n")
    except Exception:
        # Silently ignore filesystem errors to avoid interfering with IDS operation
        return
