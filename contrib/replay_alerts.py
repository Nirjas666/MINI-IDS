"""Simple helper to replay sample alerts through the logger for testing.

Run this script from the repository root with PYTHONPATH=. to ensure `src`
is importable and the MITRE enrichment is applied.

Example:
    PYTHONPATH=. python3 contrib/replay_alerts.py
"""
import time

from mini_ids import logger

SAMPLES = [
    "Port scan detected from 192.168.1.100: probed 25 distinct ports",
    "SYN flood suspected from 10.0.0.5: 60 SYNs in monitoring window",
    "ICMP flood suspected from 127.0.0.1: 120 ICMP packets in monitoring window",
    "Suspicious PowerShell: powershell.exe launched mshta",
    "Unknown alert: something weird happened",
]


def main():
    for s in SAMPLES:
        logger.log_alert(s)
        time.sleep(0.2)


if __name__ == '__main__':
    main()
