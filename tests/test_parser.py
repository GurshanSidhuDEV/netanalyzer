from netanalyzer.parser import load_capture

def test_loads_every_packet():
    df = load_capture("data/sample_small.pcap")
    assert len(df) == 2263

def test_finds_dns_and_tcp():
    df = load_capture("data/sample_small.pcap")
    assert {"DNS", "TCP"} <= set(df["protocol"])
    
def test_extracts_dns_query_names():
    df = load_capture("data/sample_small.pcap")
    assert "sterling.freenode.net" in set(df["dns_query"].dropna())
