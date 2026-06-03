"""Unit tests for MITRE mapper.

Simple tests to validate annotate_alert returns expected mappings and
that unmapped alerts are handled gracefully.
"""
import pytest

from src.mitre_mapper import annotate_alert


def test_port_scan_mapping():
    rec = annotate_alert("Port scan detected from 1.2.3.4: probed 12 distinct ports")
    assert rec["mapped"] is True
    assert rec["technique_id"] == "T1046"
    assert "Network Service Discovery" in rec["technique"]


def test_no_mapping():
    rec = annotate_alert("Unknown alert: foo bar baz")
    assert rec["mapped"] is False
    assert rec["summary"].startswith("MITRE: no mapping")
