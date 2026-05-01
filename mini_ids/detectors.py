"""Detection functions for different attack types.

Each function receives the IP src, a snapshot of recent event timestamps/ports and the overall counters.
They return an alert string when detection conditions are met, else None.
"""
from collections import defaultdict
from .config import PORT_SCAN_PORT_COUNT, SYN_FLOOD_COUNT, ICMP_FLOOD_COUNT, SUSPICIOUS_REQ_COUNT


def detect_port_scan(src, ports_seen_set):
    """Detect port scan by number of distinct destination ports probed by src within the window."""
    if len(ports_seen_set) >= PORT_SCAN_PORT_COUNT:
        return f"Port scan detected from {src}: probed {len(ports_seen_set)} distinct ports"
    return None


def detect_syn_flood(src, syn_count):
    """Detect SYN flood by count of SYN (no-ACK) packets from src within window."""
    if syn_count >= SYN_FLOOD_COUNT:
        return f"SYN flood suspected from {src}: {syn_count} SYNs in monitoring window"
    return None


def detect_icmp_flood(src, icmp_count):
    """Detect ICMP flood by ICMP packet count from src within window."""
    if icmp_count >= ICMP_FLOOD_COUNT:
        return f"ICMP flood suspected from {src}: {icmp_count} ICMP packets in monitoring window"
    return None


def detect_suspicious_activity(src, total_count):
    """Detect general suspicious activity if total packets from src exceeds threshold."""
    if total_count >= SUSPICIOUS_REQ_COUNT:
        return f"Suspicious activity from {src}: {total_count} packets in monitoring window"
    return None
