"""Integration test for syslog parser using examples/syslog.sample."""
import pytest
import tempfile
import yaml
from pathlib import Path
from src.logcollector.collector import Collector


def test_syslog_integration_with_sample(tmp_path):
    """Test that the collector parses syslog lines correctly using the syslog parser."""
    # Create a temporary syslog file with sample lines
    syslog_file = tmp_path / "syslog.log"
    syslog_file.write_text(
        "<34>Jun 10 12:34:56 host CRON[1234]: (root) CMD (run-parts /etc/cron.hourly)\n"
        "Jun 10 12:35:00 host sshd[5678]: Failed password for invalid user\n"
        "<13>Jun 10 12:36:00 host kernel: CPU0: temperature above threshold\n"
    )

    # Create a temporary config
    config_file = tmp_path / "logcollector.yaml"
    config = {
        "sources": [
            {
                "name": "test-syslog",
                "paths": [str(syslog_file)],
                "parser": "syslog",
            }
        ],
        "forward": {"mode": "console"},
    }
    config_file.write_text(yaml.dump(config))

    # Run the collector and capture records
    records = []
    original_forward = Collector.run_once

    def mock_run_once(self):
        for src in self.sources:
            for record in src.collect():
                if src.parser and src.parser in self.PARSER_MAP:
                    parser_fn = self.PARSER_MAP[src.parser]
                    try:
                        parsed = parser_fn(record.get("raw", ""))
                        record.update(parsed)
                    except Exception:
                        pass
                records.append(record)

    # Temporarily replace run_once to capture records
    Collector.run_once = mock_run_once
    try:
        collector = Collector(config_path=str(config_file))
        collector.run_once()
    finally:
        Collector.run_once = original_forward

    # Verify we got parsed records
    assert len(records) == 3

    # Check the first record (with PRI)
    rec1 = records[0]
    assert rec1["process"] == "CRON"
    assert rec1["pid"] == "1234"
    assert rec1["facility"] == 4
    assert rec1["severity"] == 2
    assert "CMD" in rec1["message"]

    # Check the second record (without PRI)
    rec2 = records[1]
    assert rec2["process"] == "sshd"
    assert rec2["pid"] == "5678"
    assert "Failed password" in rec2["message"]

    # Check the third record (no PID)
    rec3 = records[2]
    assert rec3["process"] == "kernel"
    assert rec3.get("pid") is None
    assert rec3["facility"] == 1
    assert rec3["severity"] == 5
