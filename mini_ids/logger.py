"""Mini IDS logging utilities with MITRE ATT&CK enrichment.

This module keeps the original logging behaviour (text alert file + packet CSV)
but enriches human-readable alerts with MITRE mappings when available and also
writes a machine-readable JSON-lines mapping file for downstream processing.

We keep the public function `log_alert(text: str)` and its behaviour so the
existing detection workflow does not need to change.
"""
import os
import csv
from datetime import datetime
from typing import Dict
from .config import LOG_DIR, TEXT_LOG, CSV_LOG

# Try to import the MITRE mapper. It lives under `src.mitre_mapper` per project
# structure. If the import fails, we simply disable MITRE enrichment to avoid
# breaking the IDS.
try:
    from src import mitre_mapper  # type: ignore
    _MITRE_AVAILABLE = True
except Exception:
    mitre_mapper = None  # type: ignore
    _MITRE_AVAILABLE = False


def ensure_log_dir():
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)


def log_alert(text: str):
    """Append a human-readable alert to the text log with timestamp.

    When a MITRE mapping is available, append a short MITRE summary to the
    logged line and write a JSON-lines record for machine processing.
    """
    ensure_log_dir()
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f UTC")

    mitre_summary = ""
    if _MITRE_AVAILABLE and mitre_mapper:
        try:
            mapping = mitre_mapper.annotate_alert(text)
            mitre_summary = " | " + mapping.get("summary", "")
            # write machine-readable record alongside the text log
            mitre_mapper.write_mapping_json(mapping)
        except Exception:
            # Don't let mapping failures prevent alert logging
            mitre_summary = ""

    line = f"[{ts}] ALERT: {text}{mitre_summary}\n"
    print(line.strip())
    with open(TEXT_LOG, "a", encoding="utf-8") as f:
        f.write(line)


def init_csv():
    """Create CSV with header if it does not exist."""
    ensure_log_dir()
    if not os.path.exists(CSV_LOG):
        with open(CSV_LOG, "w", newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp_utc", "src_ip", "dst_ip", "proto", "sport", "dport", "len", "info"]) 


def log_packet_csv(record: Dict):
    """Append a packet record (dict) to CSV. Expected keys: timestamp_utc, src_ip, dst_ip, proto, sport, dport, len, info."""
    init_csv()
    with open(CSV_LOG, "a", newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            record.get("timestamp_utc", ""),
            record.get("src_ip", ""),
            record.get("dst_ip", ""),
            record.get("proto", ""),
            record.get("sport", ""),
            record.get("dport", ""),
            record.get("len", ""),
            record.get("info", ""),
        ])
