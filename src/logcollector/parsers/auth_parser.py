"""Improved parser for Linux auth.log entries using regex and timestamp parsing."""
import re
from datetime import datetime
from ..utils import parse_timestamp

# Regex to capture typical auth.log entries
AUTH_RE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<process>[^\[]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$'
)


def parse_auth_line(line: str) -> dict:
    """Parse a single auth.log line into structured fields.

    Returned fields:
      - timestamp: ISO 8601 string (no year, uses current year if not present)
      - host
      - process
      - pid (optional)
      - message
      - raw
    """
    m = AUTH_RE.match(line.strip())
    if not m:
        return {"raw": line}

    gd = m.groupdict()
    # Build a timestamp string like "Jun 10 12:34:56" and try to parse it
    ts_str = f"{gd['month']} {gd['day']} {gd['time']}"
    try:
        dt = parse_timestamp(ts_str)
        if isinstance(dt, datetime):
            timestamp = dt.isoformat()
        else:
            timestamp = str(dt)
    except Exception:
        timestamp = ts_str

    return {
        "timestamp": timestamp,
        "host": gd.get("host") or "",
        "process": (gd.get("process") or "").strip(),
        "pid": gd.get("pid"),
        "message": gd.get("message") or "",
        "raw": line,
    }
