from scapy.all import rdpcap


def test_libraries_import():
    import pandas
    import yaml


def test_sample_capture_loads():
    packets = rdpcap("data/sample_small.pcap")
    assert len(packets) == 2263
