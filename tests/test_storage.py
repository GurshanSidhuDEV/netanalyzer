import pandas as pd
from netanalyzer.storage import (alerts_for, connect, list_captures, protocol_breakdown, save_analysis, top_talkers, traffic_over_time)

ALERT = {"rule_id": "NA-001", "title": "Possible TCP port scan", "level": "medium", "technique": "T1046", "src": "10.0.0.1", "dst": "10.0.0.2", "first_seen": 0.0, "evidence": "15 distinct ports in 10s"}

def sample_df():
    rows = [
        {"time": 0.0, "size": 100, "protocol": "TCP", "src": "10.0.0.1", "dst": "10.0.0.2", "sport": 40000, "dport": 80, "flags": "S", "dns_query": None},
        {"time": 30.0, "size": 200, "protocol": "TCP", "src": "10.0.0.1", "dst": "10.0.0.2", "sport": 40000, "dport": 80, "flags": "A", "dns_query": None},
        {"time": 70.0, "size": 50, "protocol": "DNS", "src": "10.0.0.3", "dst": "10.0.0.53", "sport": 50000, "dport": 53, "flags": None, "dns_query": "example.com"},
    ]
    return pd.DataFrame(rows)

def make_file(tmp_path, name, content):
    path = tmp_path / name
    path.write_bytes(content)
    return path

def test_saves_and_queries(tmp_path):
    conn = connect(tmp_path / "t.db")
    path = make_file(tmp_path, "a.pcap", b"capture a")
    cid = save_analysis(conn, path, sample_df(), [ALERT])

    proto = protocol_breakdown(conn, cid)
    assert dict(zip(proto["protocol"], proto["packets"])) == {"TCP": 2, "DNS": 1}
    assert top_talkers(conn, cid).iloc[0]["src"] == "10.0.0.1"  # 300 bytes beats 50
    traffic = traffic_over_time(conn, cid, 60)
    assert list(traffic["bucket"]) == [0, 60]
    assert list(traffic["packets"]) == [2, 1]
    alerts = alerts_for(conn, cid)
    assert len(alerts) == 1 and alerts.iloc[0]["rule_id"] == "NA-001"

def test_reanalyzing_same_file_replaces_results(tmp_path):
    conn = connect(tmp_path / "t.db")
    path = make_file(tmp_path, "a.pcap", b"capture a")
    save_analysis(conn, path, sample_df(), [ALERT])
    save_analysis(conn, path, sample_df(), [ALERT])
    assert len(list_captures(conn)) == 1
    assert conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0] == 3
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1

def test_different_files_are_kept_separately(tmp_path):
    conn = connect(tmp_path / "t.db")
    save_analysis(conn, make_file(tmp_path, "a.pcap", b"capture a"), sample_df(), [])
    save_analysis(conn, make_file(tmp_path, "b.pcap", b"capture b"), sample_df(), [])
    assert len(list_captures(conn)) == 2
