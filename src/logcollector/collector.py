"""Core collector that discovers sources and runs parsers."""
import yaml
import logging
from .sources import LogSource
from .forwarder import Forwarder
from .parsers.auth_parser import parse_auth_line
from .parsers.syslog_parser import parse_syslog_line
from .parsers.web_parser import parse_web_line
from .parsers.firewall_parser import parse_firewall_line
from .parsers.app_parser import parse_app_line
from .parsers.network_parser import parse_network_line

logger = logging.getLogger(__name__)

# Map parser names to parser functions
PARSER_MAP = {
    "auth": parse_auth_line,
    "syslog": parse_syslog_line,
    "web": parse_web_line,
    "firewall": parse_firewall_line,
    "app": parse_app_line,
    "network": parse_network_line,
}


class Collector:
    def __init__(self, config_path="config/logcollector.yaml"):
        with open(config_path) as f:
            self.config = yaml.safe_load(f)
        self.sources = [LogSource.from_config(s) for s in self.config.get("sources", [])]
        self.forwarder = Forwarder(self.config.get("forward", {}))

    def run_once(self):
        for src in self.sources:
            logger.info("Collecting from %s", src.name)
            for record in src.collect():
                # Apply parser if specified
                if src.parser and src.parser in PARSER_MAP:
                    parser_fn = PARSER_MAP[src.parser]
                    try:
                        parsed = parser_fn(record.get("raw", ""))
                        # Merge parsed fields into the record
                        record.update(parsed)
                    except Exception as e:
                        logger.exception("Failed to parse record from %s: %s", src.name, e)
                self.forwarder.forward(record)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    Collector().run_once()
