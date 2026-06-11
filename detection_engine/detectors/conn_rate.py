"""Connection-rate behavioral detector (scaffold)

Uses the SlidingWindowCounter from detection_engine.behavioral to track the
number of connection attempts per source IP and per destination IP within a
sliding window. Raises an alert when counts exceed configured thresholds.

Packet shape expected by this scaffold (detectors should parse raw packets):
{
    "src_ip": "1.2.3.4",
    "dst_ip": "5.6.7.8",
    "timestamp": 1620000000.0
}

This is a simple, testable implementation suitable for unit tests and as a
building block for more sophisticated behavior-based detectors.
"""

from typing import Dict, Any, Optional, List
import time

from detection_engine.behavioral import SlidingWindowCounter


class ConnRateDetector:
    """Detects unusually high connection rates per source or destination.

    Configuration:
    - src_threshold: number of connections from a single source within window to alert
    - dst_threshold: number of connections to a single destination within window to alert
    - window_seconds: size of the sliding window
    """

    def __init__(self, src_threshold: int = 100, dst_threshold: int = 500, window_seconds: int = 60):
        self.src_threshold = int(src_threshold)
        self.dst_threshold = int(dst_threshold)
        self.window_seconds = int(window_seconds)

        self._src_counter = SlidingWindowCounter(window_seconds=self.window_seconds)
        self._dst_counter = SlidingWindowCounter(window_seconds=self.window_seconds)

    def handle(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            src = packet.get("src_ip")
            dst = packet.get("dst_ip")
            ts = float(packet.get("timestamp", time.time()))
        except Exception:
            return None

        # Record the connection attempt
        if src:
            self._src_counter.add(src, timestamp=ts)
        if dst:
            self._dst_counter.add(dst, timestamp=ts)

        # Evaluate thresholds
        if src and self._src_counter.count(src, now=ts) >= self.src_threshold:
            alert = {
                "detector": "conn_rate",
                "type": "src",
                "key": src,
                "count": self._src_counter.count(src, now=ts),
                "threshold": self.src_threshold,
                "window_seconds": self.window_seconds,
                "timestamp": ts,
            }
            # reset for the src to avoid repeated alerts
            self._src_counter.clear(src)
            return alert

        if dst and self._dst_counter.count(dst, now=ts) >= self.dst_threshold:
            alert = {
                "detector": "conn_rate",
                "type": "dst",
                "key": dst,
                "count": self._dst_counter.count(dst, now=ts),
                "threshold": self.dst_threshold,
                "window_seconds": self.window_seconds,
                "timestamp": ts,
            }
            self._dst_counter.clear(dst)
            return alert

        return None


# Convenience helper for tests
def detect_from_packets(packets: List[Dict[str, Any]], src_threshold: int = 100, dst_threshold: int = 500, window_seconds: int = 60) -> List[Dict[str, Any]]:
    det = ConnRateDetector(src_threshold=src_threshold, dst_threshold=dst_threshold, window_seconds=window_seconds)
    alerts: List[Dict[str, Any]] = []
    for p in packets:
        a = det.handle(p)
        if a is not None:
            alerts.append(a)
    return alerts
