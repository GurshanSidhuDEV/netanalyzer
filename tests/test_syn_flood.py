import pandas as pd

from netanalyzer.detections import detect_syn_floods

RULE = {
    "id": "NA-002",
    "title": "Possible SYN flood",
    "level": "high",
    "attack": {"technique": "T1498"},
    "detection": {"type": "syn_flood", "half_open_syns": 100, "window_seconds": 5},
}


def pkt(time, src, sport, flags, dst="10.0.0.9", dport=80):
    return {"time": time, "size": 60, "protocol": "TCP", "src": src, "dst": dst,
            "sport": sport, "dport": dport, "flags": flags}


def test_flags_flood_from_many_spoofed_sources():
    rows = [pkt(i * 0.01, f"10.1.{i // 250}.{i % 250 + 1}", 40000, "S") for i in range(300)]
    alerts = detect_syn_floods(pd.DataFrame(rows), RULE)
    assert len(alerts) == 1
    assert alerts[0]["dst"] == "10.0.0.9:80"


def test_ignores_busy_server_when_handshakes_complete():
    rows = []
    for i in range(300):
        src = f"10.1.{i // 250}.{i % 250 + 1}"
        rows.append(pkt(i * 0.01, src, 40000, "S"))
        rows.append(pkt(i * 0.01 + 0.001, src, 40000, "A"))
    assert detect_syn_floods(pd.DataFrame(rows), RULE) == []


def test_retransmitted_syns_count_once():
    rows = [pkt(i * 0.01, "10.0.0.5", 40000, "S") for i in range(300)]
    assert detect_syn_floods(pd.DataFrame(rows), RULE) == []
    
def test_capture_without_syns_does_not_crash():
    rows = [pkt(i * 0.01, "10.0.0.5", 40000, "A", dport=80) for i in range(50)]
    assert detect_syn_floods(pd.DataFrame(rows), RULE) == []
