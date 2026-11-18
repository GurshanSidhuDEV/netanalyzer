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

DETECTORS = {"port_scan": detect_port_scans}

def run_rules(df, rules):
    alerts = []
    for rule in rules:
        alerts.extend(DETECTORS[rule["detection"]["type"]](df, rule))
    return alerts
