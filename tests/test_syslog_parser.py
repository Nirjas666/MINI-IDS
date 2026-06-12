import pytest
from src.logcollector.parsers.syslog_parser import parse_syslog_line


def test_syslog_with_pri():
    line = "<34>Jun 10 12:34:56 host CRON[1234]: (root) CMD (run-parts /etc/cron.hourly)"
    out = parse_syslog_line(line)
    assert out["raw"] == line
    assert out["pri"] == 34
    assert out["facility"] == 4
    assert out["severity"] == 2
    assert out["host"] == "host"
    assert out["process"] == "CRON"
    assert out["pid"] == "1234"
    assert "CMD" in out["message"]


def test_syslog_without_pri():
    line = "Jun 10 12:34:56 host sshd[987]: Failed password for invalid user"
    out = parse_syslog_line(line)
    assert out["raw"] == line
    assert out.get("pri") is None
    assert out["host"] == "host"
    assert out["process"] == "sshd"
    assert out["pid"] == "987"
    assert "Failed password" in out["message"]


def test_syslog_missing_pid():
    line = "<13>Jun 10 12:34:56 host kernel: CPU0: temperature above threshold"
    out = parse_syslog_line(line)
    assert out["raw"] == line
    assert out["pri"] == 13
    assert out["facility"] == 1
    assert out["severity"] == 5
    assert out["process"] == "kernel"
    assert out.get("pid") is None
    assert "temperature" in out["message"]


def test_syslog_malformed_short_line():
    # Completely malformed line should return raw only
    line = "not a syslog"
    out = parse_syslog_line(line)
    assert out == {"raw": line}


def test_syslog_malformed_but_parseable():
    # A long-ish line without the usual colon form should still be parsed by fallback
    line = "Jun 10 12:34:56 host somecomponent this is a message without colon"
    out = parse_syslog_line(line)
    assert "timestamp" in out
    assert out["host"] == "host"
    assert "this is a message" in out["message"]
