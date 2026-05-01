"""mini IDS - live packet capture and threshold-based detectors using Scapy.

Features:
- Capture live traffic using Scapy's sniff()
- Analyze TCP/UDP/ICMP
- Detect: Port scans, SYN floods, ICMP floods, suspicious IP activity
- Maintain a human-readable alert log (.txt) and a packet CSV for visualization
- Modular detectors in detectors.py

Run this on Kali as root (sudo python3 ids.py). On Windows you'd need to run with Administrator and have Npcap.
"""
import time
import threading
from collections import defaultdict, deque
from datetime import datetime
import signal

from scapy.all import sniff, IP, TCP, UDP, ICMP

from . import detectors
from .logger import log_alert, log_packet_csv
from .config import (
    TIME_WINDOW,
    DEFAULT_INTERFACE,
)

# Data structures for sliding-window counters
# For each src IP we keep deques of timestamps (seconds) for different event types
src_ports = defaultdict(set)          # src_ip -> set of dst ports seen in WINDOW
src_syn_times = defaultdict(lambda: deque())   # src_ip -> deque of syn packet timestamps
src_icmp_times = defaultdict(lambda: deque())  # src_ip -> deque of icmp packet timestamps
src_total_times = defaultdict(lambda: deque()) # src_ip -> deque of all packet timestamps

# Global packet timestamps for packet-rate monitoring
global_pkt_times = deque()

# Graceful shutdown
stop_sniff = threading.Event()

# Debug counters
pkt_count = 0
ip_pkt_count = 0
tcp_pkt_count = 0
udp_pkt_count = 0
icmp_pkt_count = 0
last_debug_print = time.time()


def now_ts():
    return time.time()


def prune_deque(dq: deque, window_seconds: int):
    """Remove timestamps older than window_seconds from left of deque."""
    cutoff = now_ts() - window_seconds
    while dq and dq[0] < cutoff:
        dq.popleft()


def packet_record(pkt):
    """Create a dict record for CSV logging from a Scapy packet."""
    rec = {
        "timestamp_utc": datetime.utcnow().isoformat(),
        "src_ip": "",
        "dst_ip": "",
        "proto": "",
        "sport": "",
        "dport": "",
        "len": len(pkt),
        "info": "",
    }
    if IP in pkt:
        rec["src_ip"] = pkt[IP].src
        rec["dst_ip"] = pkt[IP].dst
        if TCP in pkt:
            rec["proto"] = "TCP"
            rec["sport"] = pkt[TCP].sport
            rec["dport"] = pkt[TCP].dport
            rec["info"] = pkt.sprintf("%IP.src%:%TCP.sport% -> %IP.dst%:%TCP.dport% Flags=%TCP.flags%")
        elif UDP in pkt:
            rec["proto"] = "UDP"
            rec["sport"] = pkt[UDP].sport
            rec["dport"] = pkt[UDP].dport
            rec["info"] = pkt.sprintf("%IP.src%:%UDP.sport% -> %IP.dst%:%UDP.dport%")
        elif ICMP in pkt:
            rec["proto"] = "ICMP"
            rec["info"] = pkt.sprintf("%IP.src% -> %IP.dst% ICMP type=%ICMP.type% code=%ICMP.code%")
        else:
            rec["proto"] = str(pkt[IP].proto)
    else:
        rec["info"] = pkt.summary()
    return rec


def handle_packet(pkt):
    """Main packet callback for Scapy sniff: update counters, run detectors and log."""
    global pkt_count, ip_pkt_count, tcp_pkt_count, udp_pkt_count, icmp_pkt_count, last_debug_print
    
    pkt_count += 1
    ts = now_ts()
    
    # Print debug stats every 5 seconds
    if ts - last_debug_print >= 5:
        print(f"\n[DEBUG] Packets captured: Total={pkt_count}, IP={ip_pkt_count}, TCP={tcp_pkt_count}, UDP={udp_pkt_count}, ICMP={icmp_pkt_count}, Sources={len(src_total_times)}")
        last_debug_print = ts
    
    # Log packet to CSV (non-blocking could be added later)
    try:
        rec = packet_record(pkt)
        log_packet_csv(rec)
    except Exception as e:
        # Logging should not crash the sniffer
        print("CSV log error:", e)

    if IP not in pkt:
        return

    ip_pkt_count += 1
    src = pkt[IP].src
    dst = pkt[IP].dst

    # Update global packet timestamps
    global_pkt_times.append(ts)
    prune_deque(global_pkt_times, TIME_WINDOW)

    # Update per-src totals
    src_total_times[src].append(ts)
    prune_deque(src_total_times[src], TIME_WINDOW)

    # TCP handling
    if TCP in pkt:
        tcp_pkt_count += 1
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        flags = pkt[TCP].flags
        # record ports probed
        src_ports[src].add(dport)

        # SYN detection (S flag set and not ACK)
        if flags & 0x02 and not (flags & 0x10):  # SYN and not ACK
            src_syn_times[src].append(ts)
            prune_deque(src_syn_times[src], TIME_WINDOW)

    # UDP handling
    if UDP in pkt:
        udp_pkt_count += 1
        # record destination port to detect UDP-based scanning
        dport = pkt[UDP].dport
        src_ports[src].add(dport)

    # ICMP handling
    if ICMP in pkt:
        icmp_pkt_count += 1
        src_icmp_times[src].append(ts)
        prune_deque(src_icmp_times[src], TIME_WINDOW)

    # After updating data structures, run detectors (lightweight)
    # Port scan detector
    try:
        ps_alert = detectors.detect_port_scan(src, src_ports[src])
        if ps_alert:
            log_alert(ps_alert)
            # Reset ports set to avoid repeated alerts for same burst
            src_ports[src].clear()

        syn_alert = detectors.detect_syn_flood(src, len(src_syn_times[src]))
        if syn_alert:
            log_alert(syn_alert)
            src_syn_times[src].clear()

        icmp_alert = detectors.detect_icmp_flood(src, len(src_icmp_times[src]))
        if icmp_alert:
            log_alert(icmp_alert)
            src_icmp_times[src].clear()

        suspicious_alert = detectors.detect_suspicious_activity(src, len(src_total_times[src]))
        if suspicious_alert:
            log_alert(suspicious_alert)
            src_total_times[src].clear()
    except Exception as e:
        print("Detector error:", e)


def monitor_global_rate():
    """Background thread: monitor global packet rate to detect anomalies and prune old state."""
    from .config import GLOBAL_PKT_RATE_PER_SEC

    while not stop_sniff.is_set():
        try:
            prune_deque(global_pkt_times, TIME_WINDOW)
            rate = len(global_pkt_times) / max(1, TIME_WINDOW)
            if rate >= GLOBAL_PKT_RATE_PER_SEC:
                log_alert(f"High global packet rate detected: {rate:.1f} pkt/s")

            # Periodic housekeeping: prune deques per IP to conserve memory
            cutoff = now_ts() - TIME_WINDOW
            # Iterate and prune; remove empty entries to keep dicts small
            for src in list(src_total_times.keys()):
                prune_deque(src_total_times[src], TIME_WINDOW)
                if not src_total_times[src]:
                    src_total_times.pop(src, None)
            for src in list(src_syn_times.keys()):
                prune_deque(src_syn_times[src], TIME_WINDOW)
                if not src_syn_times[src]:
                    src_syn_times.pop(src, None)
            for src in list(src_icmp_times.keys()):
                prune_deque(src_icmp_times[src], TIME_WINDOW)
                if not src_icmp_times[src]:
                    src_icmp_times.pop(src, None)
            # Sleep a short while before next check
            time.sleep(1)
        except Exception as e:
            print("Monitor thread error:", e)
            time.sleep(1)


def start_sniffer(interface=DEFAULT_INTERFACE):
    """Start sniffing in the foreground. Requires root/admin privileges to capture live traffic."""
    print("Starting Mini IDS sniffer. Interface:", interface or "default")
    monitor_thread = threading.Thread(target=monitor_global_rate, daemon=True)
    monitor_thread.start()

    # Use Scapy sniff; store=0 to avoid memory growth
    try:
        sniff(iface=interface, prn=handle_packet, store=False, stop_filter=lambda x: stop_sniff.is_set())
    except PermissionError:
        print("PermissionError: run this script with root/Administrator privileges to capture packets.")


def stop_gracefully(signum, frame):
    print("Stopping sniffer...")
    stop_sniff.set()


if __name__ == "__main__":
    # Install signal handler so Ctrl+C stops threads cleanly
    signal.signal(signal.SIGINT, stop_gracefully)
    signal.signal(signal.SIGTERM, stop_gracefully)
    start_sniffer()
