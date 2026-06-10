"""Detection Engine documentation (brief)

Architecture:
- detection_engine.engine.DetectionEngine: orchestrates detectors
- detection_engine.detectors/: implementations for signature, behavioral, statistical detectors
- detection_engine.rules/: signature rule files
- detectors should be small, single-responsibility classes providing a `handle(packet)` method

Plugin model:
- Detectors implement a common interface (`handle(packet)`)
- The engine registers detectors via `engine.register_detector(detector_instance)`
- Signature rules are loaded from YAML/JSON files in detection_engine/rules/ and consumed by signature detectors

Testing and CI:
- Add unit tests under tests/ using pytest
- CI should run pytest across supported Python versions

Contributing:
- To add a detector: create a file under detection_engine/detectors, implement `handle(packet)`, add tests under tests/ and update docs.
- Follow the project code style and add docstrings for public APIs.

Future work:
- Provide JSONSchema/YAML schema for rules
- Add a runtime configuration and plugin discovery mechanism
- Implement signature, behavioral, and statistical detectors as separate modules
"""
