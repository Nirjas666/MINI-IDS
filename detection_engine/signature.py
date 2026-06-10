"""Signature rule core (scaffold)

Provides a minimal Rule model and RuleLoader that reads rule files from
`detection_engine/rules/`. The actual matching logic is a placeholder —
real detectors will implement packet parsing and use rule fields.
"""

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List
import json
import glob
import os

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - yaml optional
    yaml = None


@dataclass
class Rule:
    id: str
    type: str
    description: str
    raw: Dict[str, Any]

    def match(self, packet: Any) -> bool:
        """Placeholder match: real implementation must inspect the packet.

        For now this returns False. Detectors using Rule should implement
        packet parsing and apply rule fields (thresholds, windows, etc.).
        """
        # TODO: implement matching semantics based on rule type and fields
        return False


class RuleLoader:
    """Load rules from detection_engine/rules/ supporting YAML and JSON.

    Usage:
        loader = RuleLoader()
        rules = loader.load_all()
    """

    def __init__(self, rules_dir: str = None):
        self.rules_dir = rules_dir or os.path.join(os.path.dirname(__file__), "rules")

    def _load_file(self, path: str) -> Iterable[Dict[str, Any]]:
        _, ext = os.path.splitext(path.lower())
        with open(path, "r", encoding="utf-8") as f:
            if ext in (".yaml", ".yml"):
                if yaml is None:
                    raise RuntimeError("PyYAML is required to load YAML rule files")
                return yaml.safe_load(f) or []
            elif ext == ".json":
                return json.load(f) or []
            else:
                return []

    def load_all(self) -> List[Rule]:
        """Find and load all rule definitions from the rules directory."""
        rules: List[Rule] = []
        patterns = ("*.yaml", "*.yml", "*.json")
        for pat in patterns:
            for path in glob.glob(os.path.join(self.rules_dir, pat)):
                try:
                    entries = self._load_file(path)
                except Exception:
                    # ignore malformed or unreadable rule files for now
                    entries = []
                if isinstance(entries, dict):
                    entries = [entries]
                for entry in entries:
                    try:
                        r = Rule(
                            id=str(entry.get("id", "")),
                            type=str(entry.get("type", "")),
                            description=str(entry.get("description", "")),
                            raw=entry,
                        )
                        rules.append(r)
                    except Exception:
                        continue
        return rules
