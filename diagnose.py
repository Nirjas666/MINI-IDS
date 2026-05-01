#!/usr/bin/env python3
"""Diagnostic script to check IDS setup and interface configuration.

Usage:
  sudo python3 diagnose.py [interface_name]

Examples:
  sudo python3 diagnose.py              # Check all interfaces
  sudo python3 diagnose.py eth0         # Check specific interface and capture 10 packets
"""

import sys
from scapy.all import get_if_list, sniff, IP, TCP, UDP, ICMP


def show_interfaces():
    """Display all available network interfaces."""
    print("[INFO] Available network interfaces:")
    interfaces = get_if_list()
    if not interfaces:
        print("  [ERROR] No interfaces found! Check if Scapy has proper permissions.")
        return interfaces
    for i, iface in enumerate(interfaces, 1):
        print(f"  {i}. {iface}")
    return interfaces


def capture_sample_packets(interface=None, count=10):
    """Capture and display sample packets to verify data flow."""
    print(f"\n[INFO] Attempting to capture {count} packets on interface: {interface or 'default'}")
    print("[INFO] Please generate some traffic (ping, port scan, etc.) or wait for background traffic...\n")
    
    captured = []
    
    def pkt_callback(pkt):
        captured.append(pkt)
        if len(captured) == 1:
            print("[✓] First packet captured! Traffic is flowing.\n")
        
        # Display minimal info
        info = ""
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = "?"
            details = ""
            if TCP in pkt:
                proto = "TCP"
                details = f"{pkt[TCP].sport} → {pkt[TCP].dport}"
            elif UDP in pkt:
                proto = "UDP"
                details = f"{pkt[UDP].sport} → {pkt[UDP].dport}"
            elif ICMP in pkt:
                proto = "ICMP"
                details = f"type={pkt[ICMP].type} code={pkt[ICMP].code}"
            print(f"  [{len(captured)}] {src} → {dst} ({proto}) {details}")
    
    try:
        sniff(iface=interface, prn=pkt_callback, store=False, count=count, timeout=10)
        print(f"\n[✓] Capture complete. Captured {len(captured)} packets.")
        return len(captured) > 0
    except PermissionError:
        print("[ERROR] PermissionError: Need root/admin privileges to capture packets.")
        print("  Run with: sudo python3 diagnose.py")
        return False
    except Exception as e:
        print(f"[ERROR] {type(e).__name__}: {e}")
        return False


def check_config():
    """Display IDS configuration thresholds."""
    print("\n[INFO] Current IDS detection thresholds (from config.py):")
    try:
        from mini_ids.config import (
            TIME_WINDOW, PORT_SCAN_PORT_COUNT, SYN_FLOOD_COUNT, 
            ICMP_FLOOD_COUNT, SUSPICIOUS_REQ_COUNT, GLOBAL_PKT_RATE_PER_SEC
        )
        print(f"  TIME_WINDOW: {TIME_WINDOW} seconds")
        print(f"  PORT_SCAN threshold: {PORT_SCAN_PORT_COUNT} distinct ports")
        print(f"  SYN_FLOOD threshold: {SYN_FLOOD_COUNT} SYN packets")
        print(f"  ICMP_FLOOD threshold: {ICMP_FLOOD_COUNT} ICMP packets")
        print(f"  SUSPICIOUS_ACTIVITY threshold: {SUSPICIOUS_REQ_COUNT} total packets")
        print(f"  GLOBAL_PKT_RATE threshold: {GLOBAL_PKT_RATE_PER_SEC} pkt/sec")
    except Exception as e:
        print(f"  [ERROR] Could not load config: {e}")


def main():
    print("=" * 60)
    print("Mini IDS - Diagnostic Tool")
    print("=" * 60)
    
    interfaces = show_interfaces()
    
    if not interfaces:
        print("\n[ERROR] No interfaces available. Check your system and permissions.")
        sys.exit(1)
    
    interface = None
    if len(sys.argv) > 1:
        interface = sys.argv[1]
        if interface not in interfaces:
            print(f"\n[ERROR] Interface '{interface}' not found. Available: {', '.join(interfaces)}")
            sys.exit(1)
    
    check_config()
    
    success = capture_sample_packets(interface, count=10)
    
    if success:
        print("\n[✓] DIAGNOSTIC PASSED: Traffic is being captured successfully.")
        print("[INFO] The IDS should be able to log packets and detect attacks.")
        print("[NEXT] Run: sudo python3 run_ids.py", f"{interface if interface else ''}")
    else:
        print("\n[✗] DIAGNOSTIC FAILED: No packets captured.")
        print("[TROUBLESHOOTING]")
        print("  1. Ensure you're running as root/admin: sudo python3 diagnose.py")
        print("  2. Check your interface: ip a (Linux) or ipconfig (Windows)")
        print("  3. Verify network is active and generating traffic")
        print("  4. Try a different interface: sudo python3 diagnose.py eth0")


if __name__ == "__main__":
    main()
