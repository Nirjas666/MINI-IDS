"""Threat intelligence enrichment module for Mini IDS.

Provides optional, extensible IP enrichment that checks whether an IP is
known malicious (via local feeds or optional external APIs), determines
geolocation (country) when available, and associates IPs with known
malware campaigns from feeds.

Design goals:
- Non-blocking: failures do not raise — they return conservative defaults.
- Configurable: external lookups are only performed when explicitly enabled
  via environment variables to avoid accidental external network calls.
- Easy to extend: add local feeds under `feeds/` or enable external APIs.

Public API:
- annotate_ip(ip: str, alert_text: Optional[str] = None) -> Dict
- write_threatintel_json(record: Dict, path: Optional[str] = None) -> None

Behavior summary:
- If IP is private (RFC1918), it is marked as internal and no external
  lookups are performed by default.
- If feeds/blocked_ips.csv exists and contains the IP, it is marked malicious
  and associated metadata is returned.
- If ENABLE_EXTERNAL_LOOKUP=1 in env and requests is installed, the module
  will attempt optional AbuseIPDB and ip-api lookups when corresponding
  environment variables are set.
"""
from __future__ import annotations

import csv
import ipaddress
import json
import os
import time
from datetime import datetime
from typing import Dict, List, Optional

try:
    import requests
except Exception:
    requests = None  # type: ignore

# Local feeds (optional)
LOCAL_BLOCKED_IPS = os.path.join("feeds", "blocked_ips.csv")
LOCAL_IP_CAMPAIGNS = os.path.join("feeds", "ip_campaigns.csv")

# Output log for threat intel enrichment
DEFAULT_THREATINTEL_JSON_LOG = os.path.join("logs", "ids_threatintel.jsonl")

# Environment flags
ENABLE_EXTERNAL = os.getenv("ENABLE_EXTERNAL_LOOKUP", "0") == "1"
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VT_API_KEY")


def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


def _load_local_blocked() -> Dict[str, Dict]:
    """Load blocked IPs from LOCAL_BLOCKED_IPS file if present.

    CSV format: ip,source,reason,campaign
    """
    data: Dict[str, Dict] = {}
    if not os.path.exists(LOCAL_BLOCKED_IPS):
        return data
    try:
        with open(LOCAL_BLOCKED_IPS, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                ip = row.get("ip")
                if not ip:
                    continue
                data[ip.strip()] = {
                    "source": row.get("source", "local_feed"),
                    "reason": row.get("reason", ""),
                    "campaign": row.get("campaign", ""),
                }
    except Exception:
        return {}
    return data


def _lookup_abuseipdb(ip: str) -> Optional[Dict]:
    """Optional: query AbuseIPDB for reported maliciousness.

    Requires ABUSEIPDB_API_KEY env var and requests package.
    """
    if not ENABLE_EXTERNAL or not ABUSEIPDB_API_KEY or requests is None:
        return None
    try:
        url = f"https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip}
        r = requests.get(url, headers=headers, params=params, timeout=5)
        if r.status_code == 200:
            j = r.json().get("data")
            return {"abuseConfidenceScore": j.get("abuseConfidenceScore", 0), "reports": j.get("totalReports", 0)}
    except Exception:
        return None
    return None


def _geoip_ip_api(ip: str) -> Optional[Dict]:
    """Optional: lightweight geoip via ip-api.com (no key required)

    Only used if ENABLE_EXTERNAL=1 and requests package available.
    """
    if not ENABLE_EXTERNAL or requests is None:
        return None
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode"
        r = requests.get(url, timeout=4)
        if r.status_code == 200:
            j = r.json()
            if j.get("status") == "success":
                return {"country": j.get("country"), "countryCode": j.get("countryCode")}
    except Exception:
        return None
    return None


def _load_campaigns() -> Dict[str, List[str]]:
    """Load ip->campaign mappings from LOCAL_IP_CAMPAIGNS CSV if available.

    CSV fields: ip,campaign
    """
    mapping: Dict[str, List[str]] = {}
    if not os.path.exists(LOCAL_IP_CAMPAIGNS):
        return mapping
    try:
        with open(LOCAL_IP_CAMPAIGNS, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                ip = row.get("ip")
                campaign = row.get("campaign")
                if not ip or not campaign:
                    continue
                mapping.setdefault(ip.strip(), []).append(campaign.strip())
    except Exception:
        return {}
    return mapping


def annotate_ip(ip: str, alert_text: Optional[str] = None) -> Dict:
    """Annotate an IP address with threat intelligence metadata.

    Returns a dictionary containing:
      - ip
      - timestamp_utc
      - is_private
      - is_malicious
      - sources (list of sources contributing to the decision)
      - reason (string, if available)
      - country (if known)
      - campaigns (list)
    """
    ts = datetime.utcnow().isoformat() + "Z"
    record: Dict = {
        "ip": ip,
        "timestamp_utc": ts,
        "is_private": False,
        "is_malicious": False,
        "sources": [],
        "reason": "",
        "country": "",
        "campaigns": [],
        "alert_text": alert_text or "",
    }

    # Validate IP
    try:
        _ = ipaddress.ip_address(ip)
    except Exception:
        record["reason"] = "invalid_ip"
        return record

    # Private IP check
    if _is_private_ip(ip):
        record["is_private"] = True
        record["country"] = "Private Network"
        # Optionally check local feeds for internal bad IPs
    # Local feeds
    local_blocked = _load_local_blocked()
    if ip in local_blocked:
        rec = local_blocked[ip]
        record["is_malicious"] = True
        record["sources"].append(rec.get("source", "local_feed"))
        record["reason"] = rec.get("reason", "listed_in_local_feed")
        campaign = rec.get("campaign")
        if campaign:
            record["campaigns"].append(campaign)

    # Local campaign mappings
    campaigns = _load_campaigns()
    if ip in campaigns:
        record["campaigns"].extend(campaigns[ip])
        if campaigns[ip]:
            record["sources"].append("local_campaigns")

    # Optional external enrichment
    if ENABLE_EXTERNAL:
        # AbuseIPDB check
        abuse = _lookup_abuseipdb(ip)
        if abuse:
            score = abuse.get("abuseConfidenceScore", 0)
            reports = abuse.get("reports", 0)
            if score >= 50 or reports > 0:
                record["is_malicious"] = True
                record["sources"].append("abuseipdb")
                record["reason"] = f"abuse_score={score},reports={reports}"
        # GeoIP
        geo = _geoip_ip_api(ip)
        if geo:
            record["country"] = geo.get("country") or record["country"]
            if geo.get("countryCode"):
                record.setdefault("countryCode", geo.get("countryCode"))

    # Finalize
    if not record["sources"] and not record["is_private"]:
        record["sources"].append("none")

    # Write record to jsonl for later analysis
    write_threatintel_json(record)
    return record


def write_threatintel_json(record: Dict, path: Optional[str] = None) -> None:
    out_path = path or DEFAULT_THREATINTEL_JSON_LOG
    try:
        parent = os.path.dirname(out_path)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)
        with open(out_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        # Never raise — keep IDS running
        return
