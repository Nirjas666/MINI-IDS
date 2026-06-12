"""Parser for syslog-style logs (RFC3164-ish and basic RFC5424 support).

This parser extracts an optional PRI (<34>), the timestamp (month day time), host,
process name, optional pid, and the message. If a PRI is present, it also exposes
facility and severity derived from the PRI value.
"""
import re
from datetime import datetime
from ..utils import parse_timestamp

# Match optional PRI, timestamp (RFC3164-like), host, process[pid]: message
SYSLOG_RE = re.compile(
    r'^(?:<(?P<pri>\d{1,3})>)?'
    r'(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<process>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$'
)

# Fallback generic syslog line split


def _pri_to_fac_sev(pri: int):
    try:
        pri = int(pri)
    except Exception:
        return None, None
    facility = pri >> 3
    severity = pri & 0x7
    return facility, severity


def parse_syslog_line(line: str) -> dict:
    """Parse a syslog line into structured fields.

    Returned fields (when available):
      - timestamp: ISO 8601 string (best-effort)
      - host
      - process
      - pid (optional)
      - message
      - pri (optional)
      - facility (optional)
      - severity (optional)
      - raw
    """
    s = line.strip()
    m = SYSLOG_RE.match(s)
    if not m:
        # Best-effort fallback: split first 4 tokens into timestamp+host and rest
        parts = s.split()
        if len(parts) >= 5:
            ts_str = " ".join(parts[0:3])
            host = parts[3]
            message = " ".join(parts[4:])
            try:
                dt = parse_timestamp(ts_str)
                timestamp = dt.isoformat() if isinstance(dt, datetime) else str(dt)
            except Exception:
                timestamp = ts_str
            return {
                "timestamp": timestamp,
                "host": host,
                "message": message,
                "raw": line,
            }
        return {"raw": line}

    gd = m.groupdict()
    pri = gd.get("pri")
    facility = severity = None
    if pri is not None:
        facility, severity = _pri_to_fac_sev(pri)

    ts_str = f"{gd['month']} {gd['day']} {gd['time']}"
    try:
        dt = parse_timestamp(ts_str)
        timestamp = dt.isoformat() if isinstance(dt, datetime) else str(dt)
    except Exception:
        timestamp = ts_str

    return {
        "timestamp": timestamp,
        "host": gd.get("host") or "",
        "process": (gd.get("process") or "").strip(),
        "pid": gd.get("pid"),
        "message": gd.get("message") or "",
        "pri": int(pri) if pri is not None else None,
        "facility": facility,
        "severity": severity,
        "raw": line,
    }
