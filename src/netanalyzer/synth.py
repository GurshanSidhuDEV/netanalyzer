"""
Usage: python3 -m netanalyzer.synth [output_folder]"""
import random
import sys
from pathlib import Path

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, wrpcap

START = 1_700_000_000.0  # a fixed start time, so every run is the same

def stamped(packets, gap):
    for i, pkt in enumerate(packets):
        pkt.time = START + i * gap
    return packets

def eth():
    return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") #fake mac addresses

def tcp(src, dst, sport, dport, flags):
    return eth() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)

def dns_query(src, name, sport=50000):
    return (eth() / IP(src=src, dst="10.0.0.53") / UDP(sport=sport, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=name)))

def client_ip(i):
    return f"10.1.{i // 250}.{i % 250 + 1}"

def syn_flood():
    return stamped([tcp(client_ip(i), "10.0.0.9", 40000, 80, "S") for i in range(300)], 0.01)

def benign_busy_server():
    packets = []
    for i in range(300):
        c = client_ip(i)
        packets += [tcp(c, "10.0.0.9", 40000, 80, "S"), tcp("10.0.0.9", c, 80, 40000, "SA"), tcp(c, "10.0.0.9", 40000, 80, "A")]
    return stamped(packets, 0.01)

def dns_tunnel():
    rng = random.Random(7)
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    names = ["".join(rng.choice(alphabet) for _ in range(40)) + ".tunnel.example"
             for _ in range(40)]
    return stamped([dns_query("10.0.0.5", n, 50000 + i) for i, n in enumerate(names)], 0.5)

def benign_dns():
    names = ["www.google.com", "mail.example.org", "sterling.freenode.net"] * 5
    names += [f"c-68-47-20-{i}.hsd1.ga.comcast.net" for i in range(30)]
    names += [f"{i}.1.168.192.in-addr.arpa" for i in range(30)]
    return stamped([dns_query("10.0.0.5", n, 50000 + i) for i, n in enumerate(names)], 0.5)

FILES = {
    "syn_flood": syn_flood,
    "benign_busy_server": benign_busy_server,
    "dns_tunnel": dns_tunnel,
    "benign_dns": benign_dns,
}

def generate(out_dir):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths = {}
    for name, build in FILES.items():
        path = out / f"{name}.pcap"
        wrpcap(str(path), build())
        paths[name] = path
    return paths

if __name__ == "__main__":
    folder = sys.argv[1] if len(sys.argv) > 1 else "data/synthetic"
    for name, path in generate(folder).items():
        print(f"wrote {path}")
