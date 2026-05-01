#!/usr/bin/env python3
"""Entry point script to run the Mini IDS.

Usage (Linux/Kali):
  sudo python3 run_ids.py [interface_name]

Examples:
  sudo python3 run_ids.py              # Use default interface
  sudo python3 run_ids.py eth0         # Use eth0
  sudo python3 run_ids.py ens33        # Use ens33
"""

import sys
import signal
from mini_ids.ids import start_sniffer, stop_sniff


def main():
    interface = None
    if len(sys.argv) > 1:
        interface = sys.argv[1]
    
    def stop_gracefully(signum, frame):
        print("\n[INFO] Stopping sniffer...")
        stop_sniff.set()
    
    signal.signal(signal.SIGINT, stop_gracefully)
    signal.signal(signal.SIGTERM, stop_gracefully)
    
    print(f"[INFO] Starting Mini IDS sniffer on interface: {interface or 'default'}")
    try:
        start_sniffer(interface=interface)
    except PermissionError:
        print("[ERROR] PermissionError: This script requires root/administrator privileges.")
        print("[INFO] Run with: sudo python3 run_ids.py")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] {type(e).__name__}: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
