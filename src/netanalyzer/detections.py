import math
from collections import Counter
from pathlib import Path

import yaml

def load_rules(folder="rules"):
    """Read every .yml rule file in a folder."""
    rules = []
    for path in sorted(Path(folder).glob("*.yml")):
        with open(path) as f:
            rules.append(yaml.safe_load(f))
    return rules

def detect_port_scans(df, rule):
    cfg = rule["detection"]
    window = cfg["window_seconds"]
    threshold = cfg["distinct_ports"]

    # Keep only the first step of a TCP handshake (SYN, no ACK).
    probes = df[(df["protocol"] == cfg["protocol"]) & (df["flags"] == cfg["flags"])]

    alerts = []
    for (src, dst), group in probes.groupby(["src", "dst"]):
        group = group.sort_values("time")
        times = group["time"].tolist()
        ports = group["dport"].astype(int).tolist()

        start = 0
        for end in range(len(times)):
            while times[end] - times[start] > window:
                start += 1
            distinct = set(ports[start:end + 1])
            if len(distinct) >= threshold:
                alerts.append({
                    "rule_id": rule["id"],
                    "title": rule["title"],
                    "level": rule["level"],
                    "technique": rule["attack"]["technique"],
                    "src": src,
                    "dst": dst,
                    "first_seen": times[start],
                    "evidence": f"{len(distinct)} distinct ports in {window}s",
                })
                break  #one alert per pair is enough
    return alerts

def detect_syn_floods(df, rule):
    """Flag targets that receive many connection attempts that never complete."""
    cfg = rule["detection"]
    window = cfg["window_seconds"]
    threshold = cfg["half_open_syns"]

    tcp = df[df["protocol"] == "TCP"].dropna(subset=["src", "dst", "sport", "dport"]).copy()
    tcp[["sport", "dport"]] = tcp[["sport", "dport"]].astype(int)

    key = ["src", "sport", "dst", "dport"]

    syns = tcp[tcp["flags"] == "S"].drop_duplicates(subset=key)

    progressed = tcp[~tcp["flags"].isin(["S", "SA"])]
    completed = set(map(tuple, progressed[key].values))

    half_open = syns[[tuple(row) not in completed for row in syns[key].values]]

    alerts = []
    for (dst, dport), group in half_open.groupby(["dst", "dport"]):
        group = group.sort_values("time")
        times = group["time"].tolist()
        start = 0
        for end in range(len(times)):
            while times[end] - times[start] > window:
                start += 1
            count = end - start + 1
            if count >= threshold:
                sources = group["src"].iloc[start:end + 1].nunique()
                alerts.append({
                    "rule_id": rule["id"],
                    "title": rule["title"],
                    "level": rule["level"],
                    "technique": rule["attack"]["technique"],
                    "src": f"{sources} source(s)",
                    "dst": f"{dst}:{dport}",
                    "first_seen": times[start],
                    "evidence": f"{count} half-open connections in {window}s",
                })
                break
    return alerts

def shannon_entropy(text):
    """Bits of randomness per character: 0 for 'aaaa', higher for random strings."""
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())

def detect_dns_tunneling(df, rule):
    """Flag hosts sending many long, random-looking subdomains to one parent domain."""
    cfg = rule["detection"]
    queries = df.dropna(subset=["src", "dns_query"])

    seen = {}
    for src, name in zip(queries["src"], queries["dns_query"]):
        if name.endswith(tuple(cfg["ignore_suffixes"])):
            continue  # reverse lookups look random but are normal
        labels = name.split(".")
        if len(labels) < 3:
            continue  # no subdomain to inspect
        parent = ".".join(labels[-2:])
        subdomain = ".".join(labels[:-2])
        if len(subdomain) < cfg["min_subdomain_length"]:
            continue
        if max(len(label) for label in subdomain.split(".")) < cfg["min_label_length"]:
            continue
        entropy = shannon_entropy(subdomain)
        if entropy >= cfg["min_entropy"]:
            seen.setdefault((src, parent), {})[subdomain] = entropy

    alerts = []
    for (src, parent), subs in seen.items():
        if len(subs) >= cfg["min_unique_subdomains"]:
            avg = sum(subs.values()) / len(subs)
            alerts.append({
                "rule_id": rule["id"],
                "title": rule["title"],
                "level": rule["level"],
                "technique": rule["attack"]["technique"],
                "src": src,
                "dst": parent,
                "evidence": f"{len(subs)} unique random-looking subdomains "
                            f"(avg entropy {avg:.1f} bits/char)",
            })
    return alerts

DETECTORS = {
    "port_scan": detect_port_scans,
    "syn_flood": detect_syn_floods,
    "dns_tunnel": detect_dns_tunneling,
}

def run_rules(df, rules):
    alerts = []
    for rule in rules:
        alerts.extend(DETECTORS[rule["detection"]["type"]](df, rule))
    return alerts
