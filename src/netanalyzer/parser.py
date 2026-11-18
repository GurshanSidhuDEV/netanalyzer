"""Read a packet capture and turn it into a pandas table."""
import pandas as pd
from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, rdpcap

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

def dns_query_name(pkt):
    if not pkt.haslayer(DNS):
        return None
    try:
        dns = pkt[DNS]
        if dns.qr != 0:  # 0 means query, 1 means answer
            return None
        qd = dns.qd
        if isinstance(qd, list):
            qd = qd[0] if qd else None
        if qd is None:
            return None
        name = qd.qname
        if isinstance(name, bytes):
            name = name.decode("utf-8", errors="replace")
        return name.rstrip(".").lower()
    except (AttributeError, IndexError, TypeError):
        return None

def load_capture(path):

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
            "dns_query": dns_query_name(pkt),
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
