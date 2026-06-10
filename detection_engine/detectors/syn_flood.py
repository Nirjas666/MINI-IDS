"""SYN flood signature detector (scaffold)

Detects a high rate of TCP SYN packets to the same destination (IP/port)
within a short time window. This scaffold expects pre-parsed packet dicts
with the following shape:
{
    "src_ip": "1.2.3.4",
    "dst_ip": "5.6.7.8",
    "dst_port": 80,
    "flags": ["S"],  # list of TCP flags present
    "timestamp": 1620000000.0
}

This is a testable, lightweight implementation appropriate for unit tests
and further extension.
"""

import time
from collections import defaultdict, deque
from typing import Dict, Deque, Tuple, List, Any, Optional


class SynFloodDetector:
    """Detects SYN flood behavior by counting SYN packets per (dst_ip,dst_port)
    within a sliding time window.
    """

    def __init__(self, syn_rate_threshold: int = 100, window_seconds: int = 10):
        self.syn_rate_threshold = int(syn_rate_threshold)
        self.window_seconds = int(window_seconds)
        # For each (dst_ip, dst_port), keep a deque of timestamps
        self._events: Dict[Tuple[str, int], Deque[float]] = defaultdict(deque)

    def _purge_old(self, key: Tuple[str, int], now: float) -> None:
        q = self._events.get(key)
        if not q:
            return
        cutoff = now - self.window_seconds
        while q and q[0] < cutoff:
            q.popleft()
        if not q:
            try:
                del self._events[key]
            except KeyError:
                pass

    def handle(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a parsed packet and return an alert dict if the SYN-rate
        threshold is exceeded for the destination, otherwise None.
        """
        try:
            dst_ip = packet.get("dst_ip")
            dst_port = int(packet.get("dst_port"))
            flags = packet.get("flags", []) or []
            ts = float(packet.get("timestamp", time.time()))
        except Exception:
            return None

        # Only consider SYN packets (simple heuristic)
        if "S" not in flags:
            return None

        key = (dst_ip, dst_port)
        q = self._events[key]
        q.append(ts)

        # Purge old timestamps
        self._purge_old(key, ts)

        count = len(q)
        if count >= self.syn_rate_threshold:
            alert = {
                "detector": "syn_flood",
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "syn_count": count,
                "window_seconds": self.window_seconds,
                "timestamp": ts,
                "threshold": self.syn_rate_threshold,
            }
            # reset state for this destination to avoid repeated alerts
            try:
                del self._events[key]
            except KeyError:
                pass
            return alert

        return None


# Convenience helper for tests
def detect_from_packets(packets: List[Dict[str, Any]], syn_rate_threshold: int = 100, window_seconds: int = 10) -> List[Dict[str, Any]]:
    det = SynFloodDetector(syn_rate_threshold=syn_rate_threshold, window_seconds=window_seconds)
    alerts: List[Dict[str, Any]] = []
    for p in packets:
        a = det.handle(p)
        if a is not None:
            alerts.append(a)
    return alerts
