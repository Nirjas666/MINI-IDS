# Rules folder for signature-based detection

Place signature rule files (YAML/JSON) that describe signature-based detections here.

Example YAML rule format (prototype):

- id: "SIG-001"
  type: "port_scan"
  description: "Detects many distinct destination ports from a single source IP in a time window"
  threshold: 50
  window_seconds: 60

- id: "SIG-010"
  type: "syn_flood"
  description: "Detects a high rate of TCP SYN packets to the same destination IP/port"
  syn_rate_threshold: 100
  window_seconds: 10

Rules will be loaded by the signature-based detector implemented in later commits.

Notes
- This README is a placeholder and the rule schema will be finalized when the signature core is implemented.
- Use semantic, stable IDs for rules (e.g., SIG-<number>) so alerts can reference rule IDs.
