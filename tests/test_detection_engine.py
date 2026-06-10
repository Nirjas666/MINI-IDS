"""Basic unit tests for the detection engine scaffold."""

from detection_engine import DetectionEngine


class DummyDetector:
    def __init__(self):
        self.handled = []

    def handle(self, packet):
        # simple stub: record the packet and return None
        self.handled.append(packet)
        return None


def test_engine_register_and_run_once():
    engine = DetectionEngine()
    d = DummyDetector()
    engine.register_detector(d)

    packets = [b"packet1", b"packet2"]
    alerts = engine.run_once(packets)

    assert len(engine.detectors) == 1
    assert alerts == []
    assert d.handled == packets
