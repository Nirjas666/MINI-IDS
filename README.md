# Mini IDS — Lightweight Network Intrusion Detection System

[![Python 3.6+](https://img.shields.io/badge/python-3.6%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Scapy](https://img.shields.io/badge/Scapy-2.4%2B-green)](https://scapy.readthedocs.io/)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux%2FKali-red)](https://www.kali.org/)
[![Status: Stable](https://img.shields.io/badge/status-stable-brightgreen)](https://github.com)

A **lightweight, modular Intrusion Detection System (IDS)** built with Python and Scapy for educational purposes. Captures live network traffic and detects common cyberattacks using threshold-based detection logic.

## 🎯 Features

- ✅ **Live packet capture** using Scapy (TCP/UDP/ICMP)
- ✅ **Port scan detection** (many distinct destination ports)
- ✅ **SYN flood detection** (many SYN packets without ACKs)
- ✅ **ICMP flood detection** (ping floods)
- ✅ **Suspicious IP activity** detection (anomalous packet rates)
- ✅ **Global packet rate anomaly** detection
- ✅ **Real-time alerts** to terminal + persistent logs
- ✅ **CSV export** for visualization and analysis
- ✅ **Modular design** with pluggable detectors
- ✅ **Threshold-based** logic (easy to customize)

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Usage](#-usage)
- [Project Structure](#-project-structure)
- [Detection Methods](#-detection-methods)
- [Configuration](#-configuration)
- [Troubleshooting](#-troubleshooting)
- [Testing](#-testing)
- [License](#-license)

## ⚡ Quick Start

```bash
# Clone and install
git clone https://github.com/yourusername/Mini-IDS.git
cd Mini-IDS
sudo pip3 install -r requirements.txt

# Run the IDS
sudo python3 run_ids.py eth0

# In another terminal, generate traffic
sudo ping -f -c 100 127.0.0.1

# See alerts in the first terminal!
```

## 📦 Installation

### Prerequisites

**Windows Host (for development):**

- VMware Workstation (or Player) installed and working; alternatively any hypervisor that supports network bridging.
- Npcap installed if you plan to capture on Windows host.
- Wireshark installed on host for verifying captures (optional).

**Kali VM (recommended - where you run the IDS):**

- Start Kali VM in VMware Workstation (or your chosen hypervisor).
- Install Python 3 and pip (usually present):
  ```bash
  sudo apt update && sudo apt install -y python3 python3-pip
  ```
- Install Scapy:
  ```bash
  sudo pip3 install scapy
  ```
- Run the IDS as root:
  ```bash
  sudo python3 run_ids.py
  ```

## 🖥️ System Architecture

```
Network Traffic (Ethernet)
        ↓
    Scapy Sniffer
        ↓
    ┌───────────────────────────────┐
    │   Packet Handler              │
    │   - Parse TCP/UDP/ICMP        │
    │   - Update counters           │
    └───────────────────────────────┘
        ↓
    ┌───────────────────────────────┐
    │   Detection Engines           │
    │   - Port scan                 │
    │   - SYN flood                 │
    │   - ICMP flood                │
    │   - Suspicious IPs            │
    │   - Global rate anomaly       │
    └───────────────────────────────┘
        ↓
    ┌───────────────────────────────┐
    │   Logging & Alerting          │
    │   - logs/ids_alerts.txt       │
    │   - logs/ids_packets.csv      │
    │   - Terminal output           │
    └───────────────────────────────┘
```

## 📁 Project Structure

```
Mini IDS/
├── run_ids.py                    # Entry point (run this!)
├── diagnose.py                   # Diagnostic tool
├── requirements.txt              # Dependencies
├── setup.py                      # Installation script
├── LICENSE                       # MIT License
├── .gitignore                    # Git ignore file
├── README.md                     # This file
└── mini_ids/                     # Main package
    ├── __init__.py               # Package marker
    ├── config.py                 # Thresholds & settings
    ├── ids.py                    # Main sniffer engine
    ├── detectors.py              # Detection functions
    ├── logger.py                 # Logging utilities
    └── ids_visualization.ipynb   # Jupyter notebook for analysis
```

## 🔍 Detection Methods

### Port Scan Detection
Detects when a single source IP probes too many distinct destination ports within a time window.
### SYN Flood Detection
Detects when a single source sends many SYN packets (connection initiation) without ACKs, indicating a flood attack.

### ICMP Flood Detection
Detects when a single source sends many ICMP echo requests (ping) within a time window.

### Suspicious IP Activity Detection
Detects when a single source sends many total packets across all protocols within a time window.

### Global Packet Rate Anomaly
Detects when the overall network packet rate exceeds the configured threshold.

---

## ⚙️ Configuration

Edit `mini_ids/config.py` to adjust detection thresholds:

```python
TIME_WINDOW = 10                    # Sliding window (seconds)
PORT_SCAN_PORT_COUNT = 10           # Distinct ports → port scan alert
SYN_FLOOD_COUNT = 50                # SYN packets → SYN flood alert
ICMP_FLOOD_COUNT = 50               # ICMP packets → ICMP flood alert
SUSPICIOUS_REQ_COUNT = 100          # Total packets → suspicious alert
GLOBAL_PKT_RATE_PER_SEC = 500       # Packets/sec → rate anomaly
```

### Network configuration

1. Start the IDS in the Kali VM.
2. On the Kali VM (or host if bridged and capturing host traffic), open Wireshark and select the same interface used by Scapy.
3. Start a capture in Wireshark. Trigger a sample attack (see below). You should see packets (SYN, ICMP, etc.).
4. Use Wireshark filters to verify specific traffic: `tcp.flags.syn==1 && tcp.flags.ack==0` (SYNs), `icmp` (ICMP packets), or `ip.src == x.x.x.x` to focus on a source IP.

Sample attack simulation commands (run from Kali VM against a target IP)
-----------------------------------------------------------------------

### Port Scan
```bash
nmap -sS -p1-2000 TARGET_IP
```

### SYN Flood
```bash
sudo hping3 -S --flood -V -p 80 TARGET_IP
```

### ICMP Flood (Ping Flood)
```bash
sudo ping -f -c 10000 TARGET_IP
```

### UDP Flood
```bash
python3 -c "import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
for i in range(10000): s.sendto(b'A'*1024,('TARGET_IP', 53))"
```

---

## 📊 Output Files

### `logs/ids_alerts.txt` (Human-Readable)
```
[2026-03-10 10:23:15.123456 UTC] ALERT: ICMP flood suspected from 127.0.0.1: 120 ICMP packets in monitoring window
[2026-03-10 10:23:20.456789 UTC] ALERT: Port scan detected from 192.168.1.100: probed 25 distinct ports
```

### `logs/ids_packets.csv` (For Analysis)
```
timestamp_utc,src_ip,dst_ip,proto,sport,dport,len,info
2026-03-10T10:23:15.123456,127.0.0.1,127.0.0.1,ICMP,,,84,127.0.0.1 -> 127.0.0.1 ICMP type=8 code=0
2026-03-10T10:23:15.124567,192.168.1.100,10.0.0.1,TCP,54321,80,60,192.168.1.100:54321 -> 10.0.0.1:80 Flags=S
```

---

## 🐛 Troubleshooting

**No alerts appearing?**

1. Run `sudo python3 diagnose.py` to check if traffic is flowing.
2. Verify you're using the correct interface: `ip a`
3. Check thresholds in `mini_ids/config.py` (may be too high).
4. Tail the alert log: `tail -f logs/ids_alerts.txt`

**"PermissionError: script requires root privileges"**

Run with `sudo`:
```bash
sudo python3 run_ids.py eth0
```

**"No interface named 'eth0' found"**

Find the correct interface:
```bash
ip a
# Look for an interface with an IP address (eth0, ens33, wlan0, etc.)
```

For more help, see this README section above.

---

## 💡 Use Cases

- **Educational**: Learn how IDS works
- **Lab environment**: Test attack detection
- **Network monitoring**: Monitor your personal lab network
- **Security research**: Baseline for custom detection rules

---

## 📚 Testing methodology

1. Start IDS in Kali as root.
2. Launch a Wireshark capture for verification.
3. From a second terminal (or another machine), run the sample attack commands targeted at the host/VM.
4. Observe alerts printed in the IDS terminal and check `logs/ids_alerts.txt` and `logs/ids_packets.csv` for recorded evidence.

---



