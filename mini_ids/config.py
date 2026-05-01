# Configuration and thresholds for the Mini IDS
from datetime import timedelta

# Time window (seconds) used for sliding-window detections
TIME_WINDOW = 10  # seconds

# Detection thresholds
PORT_SCAN_PORT_COUNT = 10       # distinct destination ports within TIME_WINDOW -> port scan (lowered for testing)
SYN_FLOOD_COUNT = 50            # SYN packets within TIME_WINDOW -> possible SYN flood (lowered for testing)
ICMP_FLOOD_COUNT = 50           # ICMP packets within TIME_WINDOW -> possible ICMP flood (lowered for testing)
SUSPICIOUS_REQ_COUNT = 100      # total packets from single IP within TIME_WINDOW -> suspicious (lowered for testing)

# Packet rate anomaly (global)
GLOBAL_PKT_RATE_PER_SEC = 500  # packets per second -> anomaly (lowered for testing)

# Logging
LOG_DIR = "logs"
TEXT_LOG = "logs/ids_alerts.txt"
CSV_LOG = "logs/ids_packets.csv"

# Sniffing
DEFAULT_INTERFACE = None  # set to None to use Scapy default, or specify e.g. 'eth0'
