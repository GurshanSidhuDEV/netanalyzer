"""Read a packet capture and turn it into a pandas table."""
import pandas as pd
from scapy.all import DNS, ICMP, IP, TCP, UDP, ARP, rdpcap

def classify(pkt):
    if pkt.haslayer(DNS):
        return "DNS"
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(ARP):
        return "ARP"
    return "OTHER"

def load_capture(path):
    """Load a packet capture and return a pandas DataFrame with one row per packet."""
    rows = []
    for pkt in rdpcap(path):
        row = {
            "time": float(pkt.time),
            "size": len(pkt),
            "protocol": classify(pkt),
            "src": None,
            "dst": None,
            "sport": None,
            "dport": None,
            "flags": None,
        }
        if pkt.haslayer(IP):
            row["src"] = pkt[IP].src
            row["dst"] = pkt[IP].dst
        if pkt.haslayer(TCP):
            row["sport"] = pkt[TCP].sport
            row["dport"] = pkt[TCP].dport
            row["flags"] = str(pkt[TCP].flags)
        elif pkt.haslayer(UDP):
            row["sport"] = pkt[UDP].sport
            row["dport"] = pkt[UDP].dport
        rows.append(row)
    return pd.DataFrame(rows)
