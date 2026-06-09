"""DetectionEngine core (scaffold)

Provides a minimal DetectionEngine class with a register API and a
run_once stub that iterates packets and forwards them to registered
detectors. This file is intentionally minimal for the first commit.
"""

from typing import Iterable, List, Any, Dict


class DetectionEngine:
    """Simple detection engine scaffold.

    - register_detector(detector): detector must implement handle(packet) -> Optional[dict]
    - run_once(packet_iterable): iterates packets and collects detector results
    """

    def __init__(self, config: Dict = None):
        self.detectors = []
        self.config = config or {}

    def register_detector(self, detector) -> None:
        """Register a detector object. Detector must have a `handle(packet)` method."""
        if not hasattr(detector, "handle"):
            raise TypeError("Detector must implement a handle(packet) method")
        self.detectors.append(detector)

    def run_once(self, packet_iterable: Iterable[Any]) -> List[dict]:
        """Run a single pass over packet_iterable and return a list of alerts.

        This is a stub implementation used for tests and early integration.
        """
        alerts = []
        for packet in packet_iterable:
            for detector in self.detectors:
                try:
                    result = detector.handle(packet)
                except Exception:
                    # Detector implementation will be responsible for its own logging.
                    result = None
                if result:
                    alerts.append(result)
        return alerts

    @classmethod
    def load_config(cls, path: str) -> Dict:
        """Load engine configuration from a simple key=value file (placeholder).

        Real implementation will support JSON/YAML and validation.
        """
        cfg = {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        k, v = line.split("=", 1)
                        cfg[k.strip()] = v.strip()
        except FileNotFoundError:
            pass
        return cfg
