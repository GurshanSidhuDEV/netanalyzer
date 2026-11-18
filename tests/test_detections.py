import pandas as pd

from netanalyzer.detections import detect_port_scans

RULE = {
    "id": "NA-001",
    "title": "Possible TCP port scan",
    "level": "medium",
    "attack": {"technique": "T1046"},
    "detection": {"type": "port_scan", "protocol": "TCP", "flags": "S",
                  "distinct_ports": 15, "window_seconds": 10},
}

def make_syns(src, dst, ports, gap=0.1):
    rows = [{"time": i * gap, "size": 60, "protocol": "TCP", "src": src,
             "dst": dst, "sport": 40000, "dport": p, "flags": "S"}
            for i, p in enumerate(ports)]
    return pd.DataFrame(rows)

def test_flags_scan_of_many_ports():
    alerts = detect_port_scans(make_syns("10.0.0.5", "10.0.0.9", range(1, 51)), RULE)
    assert len(alerts) == 1
    assert alerts[0]["src"] == "10.0.0.5"

def test_ignores_many_connections_to_one_port():
    assert detect_port_scans(make_syns("10.0.0.5", "10.0.0.9", [443] * 50), RULE) == []

def test_misses_slow_scan():

    assert detect_port_scans(make_syns("10.0.0.5", "10.0.0.9", range(1, 51), gap=5.0), RULE) == []
