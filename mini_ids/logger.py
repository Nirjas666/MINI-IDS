"""Simple logging utilities for the Mini IDS.

Writes human-readable alerts to a .txt file and packet records to a CSV for visualization.
"""
import os
import csv
from datetime import datetime
from typing import Dict
from .config import LOG_DIR, TEXT_LOG, CSV_LOG


def ensure_log_dir():
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)


def log_alert(text: str):
    """Append a human-readable alert to the text log with timestamp."""
    ensure_log_dir()
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f UTC")
    line = f"[{ts}] ALERT: {text}\n"
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
