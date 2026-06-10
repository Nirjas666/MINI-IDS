"""Port scan signature detector (scaffold)

This detector implements a simple signature-based approach: it records
seen destination ports per source IP within a sliding time window and
raises an alert when the number of distinct destination ports from a
single source exceeds a configured threshold.

Expected packet shape for the scaffold (detectors should parse real
packets into this dict before calling handle):
{
    "src_ip": "1.2.3.4",
    "dst_ip": "5.6.7.8",
    "dst_port": 80,
    "timestamp": 1620000000.0
}

This is a lightweight, testable implementation suitable for unit tests.
"""

import time
from collections import defaultdict, deque
from typing import Dict, Deque, Set, List, Any, Optional


class PortScanDetector:
    """Detects scanning behavior by counting distinct destination ports
    per source IP in a sliding time window.
    """

    def __init__(self, threshold: int = 50, window_seconds: int = 60):
        self.threshold = int(threshold)
        self.window_seconds = int(window_seconds)
        # For each src_ip, keep a deque of (timestamp, dst_port)
        self._events: Dict[str, Deque[tuple]] = defaultdict(deque)

    def _purge_old(self, src_ip: str, now: float) -> None:
        q = self._events[src_ip]
        cutoff = now - self.window_seconds
        while q and q[0][0] < cutoff:
            q.popleft()
        if not q:
            # free memory if no events remain
            del self._events[src_ip]

    def handle(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a parsed packet (dict) and return an alert dict if
        detection threshold is exceeded, otherwise None.

        The alert dict contains: rule_id (optional), detector, src_ip,
        count, window_seconds, timestamp.
        """
        try:
            src = packet.get("src_ip")
            dst_port = int(packet.get("dst_port"))
            ts = float(packet.get("timestamp", time.time()))
        except Exception:
            # Malformed packet for this scaffold — ignore
            return None

        # Add event
        q = self._events[src]
        q.append((ts, dst_port))

        # Purge old events for this src
        self._purge_old(src, ts)

        # Count distinct destination ports in the current window
        ports: Set[int] = {p for _, p in q}
        count = len(ports)

        if count >= self.threshold:
            # Compose a simple alert
            alert = {
                "detector": "port_scan",
                "src_ip": src,
                "distinct_dst_ports": count,
                "window_seconds": self.window_seconds,
                "timestamp": ts,
                "threshold": self.threshold,
            }
            # Optionally reset state for this src to avoid duplicate alerts
            try:
                del self._events[src]
            except KeyError:
                pass
            return alert

        return None


# Convenience helper for tests
def detect_from_packets(packets: List[Dict[str, Any]], threshold: int = 50, window_seconds: int = 60) -> List[Dict[str, Any]]:
    det = PortScanDetector(threshold=threshold, window_seconds=window_seconds)
    alerts: List[Dict[str, Any]] = []
    for p in packets:
        a = det.handle(p)
        if a is not None:
            alerts.append(a)
    return alerts
