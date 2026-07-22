"""MINI-IDS Detection Engine package (scaffold)

This package will host detectors (signature, behavioral, statistical)
and provide a simple engine interface used by the rest of the project.
"""

from .engine import DetectionEngine

__all__ = ["DetectionEngine"]
