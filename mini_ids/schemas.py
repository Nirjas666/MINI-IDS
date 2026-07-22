"""Shared packet and alert schemas for MINI-IDS.

This module provides the first normalization layer for the project so the
sniffer, detectors, logger, backend, and future database/API layers can speak
the same event format.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

try:
    from scapy.all import ICMP, IP, TCP, UDP  # type: ignore
except Exception:  # pragma: no cover - scapy may not be present in all test envs
    IP = TCP = UDP = ICMP = None  # type: ignore


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _coerce_int(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except Exception:
        return None


def _normalize_flags(flags: Any) -> str:
    if flags is None:
        return ""
    if isinstance(flags, str):
        return flags
    if isinstance(flags, (list, tuple, set)):
        return "".join(str(flag) for flag in flags)
    return str(flags)


def _build_connection_info(
    src_ip: str,
    dst_ip: str,
    protocol: str,
    src_port: Optional[int],
    dst_port: Optional[int],
    flags: str,
    info: str,
) -> str:
    if info:
        return info
    if protocol == "TCP" and src_port is not None and dst_port is not None:
        flag_suffix = f" Flags={flags}" if flags else ""
        return f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}{flag_suffix}"
    if protocol == "UDP" and src_port is not None and dst_port is not None:
        return f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
    if protocol == "ICMP":
        return f"{src_ip} -> {dst_ip} ICMP"
    if src_ip or dst_ip:
        return f"{src_ip} -> {dst_ip}".strip()
    return ""


@dataclass(frozen=True)
class PacketEvent:
    timestamp_utc: str
    src_ip: str = ""
    dst_ip: str = ""
    protocol: str = ""
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    packet_size: int = 0
    flags: str = ""
    connection_info: str = ""
    info: str = ""

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["timestamp"] = self.timestamp_utc
        data["timestamp_utc"] = self.timestamp_utc
        data["proto"] = self.protocol
        data["sport"] = self.src_port
        data["dport"] = self.dst_port
        data["len"] = self.packet_size
        data["raw_summary"] = self.info
        return data


@dataclass(frozen=True)
class AlertRecord:
    id: str
    timestamp: str
    source_ip: str = ""
    destination_ip: str = ""
    attack_type: str = ""
    severity: str = "LOW"
    description: str = ""
    mitre_technique: str = ""
    status: str = "NEW"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def normalize_packet(packet: Any) -> Dict[str, Any]:
    """Convert a raw packet into a structured event dictionary.

    The returned dictionary keeps canonical field names for future services and
    legacy aliases used by the current logger.
    """

    timestamp_utc = utc_now_iso()
    src_ip = ""
    dst_ip = ""
    protocol = ""
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    packet_size = 0
    flags = ""
    info = ""

    if isinstance(packet, dict):
        timestamp_utc = str(packet.get("timestamp_utc") or packet.get("timestamp") or timestamp_utc)
        src_ip = str(packet.get("src_ip") or "")
        dst_ip = str(packet.get("dst_ip") or "")
        protocol = str(packet.get("protocol") or packet.get("proto") or "").upper()
        src_port = _coerce_int(packet.get("src_port") or packet.get("sport"))
        dst_port = _coerce_int(packet.get("dst_port") or packet.get("dport"))
        packet_size = _coerce_int(packet.get("packet_size") or packet.get("len")) or 0
        flags = _normalize_flags(packet.get("flags"))
        info = str(packet.get("info") or packet.get("raw_summary") or "")
    else:
        try:
            packet_size = int(len(packet))
        except Exception:
            packet_size = 0

        try:
            if IP is not None and IP in packet:
                src_ip = str(packet[IP].src)
                dst_ip = str(packet[IP].dst)
        except Exception:
            pass

        try:
            if TCP is not None and TCP in packet:
                protocol = "TCP"
                src_port = _coerce_int(packet[TCP].sport)
                dst_port = _coerce_int(packet[TCP].dport)
                flags = _normalize_flags(packet[TCP].flags)
            elif UDP is not None and UDP in packet:
                protocol = "UDP"
                src_port = _coerce_int(packet[UDP].sport)
                dst_port = _coerce_int(packet[UDP].dport)
            elif ICMP is not None and ICMP in packet:
                protocol = "ICMP"
            elif IP is not None and IP in packet:
                protocol = str(getattr(packet[IP], "proto", ""))
        except Exception:
            protocol = protocol or "UNKNOWN"

        try:
            info = str(packet.summary())
        except Exception:
            info = ""

    connection_info = _build_connection_info(src_ip, dst_ip, protocol, src_port, dst_port, flags, info)
    event = PacketEvent(
        timestamp_utc=timestamp_utc,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        packet_size=packet_size,
        flags=flags,
        connection_info=connection_info,
        info=info or connection_info,
    )
    return event.to_dict()


def build_alert_record(
    *,
    source_ip: str = "",
    destination_ip: str = "",
    attack_type: str = "",
    severity: str = "LOW",
    description: str = "",
    mitre_technique: str = "",
    status: str = "NEW",
    metadata: Optional[Dict[str, Any]] = None,
    alert_id: str = "",
    timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    record = AlertRecord(
        id=alert_id,
        timestamp=timestamp or utc_now_iso(),
        source_ip=source_ip,
        destination_ip=destination_ip,
        attack_type=attack_type,
        severity=severity,
        description=description,
        mitre_technique=mitre_technique,
        status=status,
        metadata=metadata or {},
    )
    return record.to_dict()