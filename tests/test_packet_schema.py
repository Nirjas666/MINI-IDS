from mini_ids.schemas import normalize_packet, build_alert_record


def test_normalize_packet_from_dict_uses_canonical_fields():
    packet = {
        "timestamp": "2026-07-22T12:00:00Z",
        "src_ip": "10.0.0.10",
        "dst_ip": "10.0.0.20",
        "protocol": "tcp",
        "src_port": 51515,
        "dst_port": 22,
        "packet_size": 74,
        "flags": "S",
    }

    event = normalize_packet(packet)

    assert event["timestamp_utc"] == "2026-07-22T12:00:00Z"
    assert event["protocol"] == "TCP"
    assert event["src_port"] == 51515
    assert event["dst_port"] == 22
    assert event["packet_size"] == 74
    assert event["flags"] == "S"
    assert event["proto"] == "TCP"
    assert event["sport"] == 51515
    assert event["dport"] == 22


def test_build_alert_record_defaults_to_new_status():
    alert = build_alert_record(
        source_ip="10.0.0.10",
        destination_ip="10.0.0.20",
        attack_type="Port Scan",
        severity="HIGH",
        description="Port scan detected",
        mitre_technique="T1046",
        alert_id="alert-1",
    )

    assert alert["id"] == "alert-1"
    assert alert["status"] == "NEW"
    assert alert["attack_type"] == "Port Scan"
    assert alert["mitre_technique"] == "T1046"