"""Plugin discovery and loader for detectors.

Scans the `detection_engine.detectors` package for modules and finds
callable detector classes. A detector class is considered valid if it is a
class defined in the module and provides a `handle(packet)` method. This
module provides utilities to discover available detectors and to instantiate
them by name.

Usage:
    from detection_engine.plugins import discover_detectors, load_detector

    available = discover_detectors()
    # available -> dict mapping short name -> (class, module_name)

    inst = load_detector("port_scan", threshold=50)

This is intentionally liberal: names are derived from module names (module
`port_scan` -> loader name `port_scan`).
"""

from typing import Dict, Tuple, Type, Any, Optional
import importlib
import pkgutil
import inspect

_DETECTORS_PKG = "detection_engine.detectors"


def discover_detectors() -> Dict[str, Tuple[Type[Any], str]]:
    """Discover detector classes in the detection_engine.detectors package.

    Returns a mapping: short_name -> (class, module_name)
    where short_name is the module name (without package prefix).
    """
    detectors: Dict[str, Tuple[Type[Any], str]] = {}
    try:
        pkg = importlib.import_module(_DETECTORS_PKG)
    except Exception:
        return detectors

    prefix = pkg.__name__ + "."
    for finder, name, ispkg in pkgutil.iter_modules(pkg.__path__, prefix):
        # name is like 'detection_engine.detectors.port_scan'
        short = name.split(".")[-1]
        try:
            mod = importlib.import_module(name)
        except Exception:
            # ignore modules that fail to import
            continue
        # find classes in the module that implement handle()
        for _, obj in inspect.getmembers(mod, inspect.isclass):
            # only consider classes defined in the module itself
            if obj.__module__ != name:
                continue
            if hasattr(obj, "handle") and inspect.isfunction(getattr(obj, "handle")):
                detectors[short] = (obj, name)
                break
    return detectors


def load_detector(name: str, **kwargs) -> Optional[Any]:
    """Instantiate a detector by its short module name (e.g. 'port_scan').

    Additional kwargs are forwarded to the detector class constructor.
    Returns an instance or None if the detector cannot be found/instantiated.
    """
    detected = discover_detectors()
    info = detected.get(name)
    if info is None:
        return None
    cls, module_name = info
    try:
        return cls(**kwargs)
    except Exception:
        # If instantiation fails, attempt to call with no args
        try:
            return cls()
        except Exception:
            return None
