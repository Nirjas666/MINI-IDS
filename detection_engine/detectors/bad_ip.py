"""bad_ip detector and blocklist loader

Loads a simple blocklist from detection_engine/rules/blocklist.txt (one IP per line)
or a JSON file (blocklist.json) containing ["1.2.3.4", ...]. The detector
raises an alert when a packet's src_ip or dst_ip matches a blocked IP.
"""

import os
import json
from typing import Set, Iterable, Dict, Any, Optional


class BlocklistLoader:
    def __init__(self, path: str = None):
        self.path = path or os.path.join(os.path.dirname(__file__), "rules", "blocklist.txt")

    def load(self) -> Set[str]:
        if not os.path.exists(self.path):
            return set()
        _, ext = os.path.splitext(self.path.lower())
        if ext == ".json":
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return set(map(str, data))
            except Exception:
                return set()
        else:
            # treat as simple newline-delimited text
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    lines = [l.strip() for l in f if l.strip()]
                return set(lines)
            except Exception:
                return set()


class BadIPDetector:
    def __init__(self, blocklist: Iterable[str] = None, loader: BlocklistLoader = None):
        if blocklist is not None:
            self.blocked = set(blocklist)
        elif loader is not None:
            self.blocked = set(loader.load())
        else:
            self.blocked = set()

    def handle(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            src = packet.get("src_ip")
            dst = packet.get("dst_ip")
        except Exception:
            return None

        for ip in (src, dst):
            if ip in self.blocked:
                return {
                    "detector": "bad_ip",
                    "matched_ip": ip,
                    "src_ip": src,
                    "dst_ip": dst,
                    "timestamp": packet.get("timestamp"),
                }
        return None
