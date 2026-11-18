import random

import pandas as pd

from netanalyzer.detections import detect_dns_tunneling, shannon_entropy

RULE = {
    "id": "NA-003",
    "title": "Possible DNS tunneling",
    "level": "medium",
    "attack": {"technique": "T1071.004"},
    "detection": {"type": "dns_tunnel", "min_subdomain_length": 20,
                  "min_entropy": 4.0, "min_label_length": 25,
                  "min_unique_subdomains": 10,
                  "ignore_suffixes": ["in-addr.arpa", "ip6.arpa"]},
}

def random_label(rng, length=40):
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(length))

def queries(names, src="10.0.0.5"):
    return pd.DataFrame([{"time": i, "src": src, "dns_query": n} for i, n in enumerate(names)])

def test_entropy_of_simple_strings():
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abcd") == 2

def test_flags_tunnel_like_queries():
    rng = random.Random(1)
    names = [f"{random_label(rng)}.tunnel.example" for _ in range(30)]
    alerts = detect_dns_tunneling(queries(names), RULE)
    assert len(alerts) == 1
    assert alerts[0]["dst"] == "tunnel.example"

def test_ignores_normal_short_names():
    names = ["www.google.com", "mail.example.org", "sterling.freenode.net"] * 10
    assert detect_dns_tunneling(queries(names), RULE) == []

def test_ignores_too_few_queries():
    rng = random.Random(2)
    names = [f"{random_label(rng)}.tunnel.example" for _ in range(5)]
    assert detect_dns_tunneling(queries(names), RULE) == []

def test_ignores_long_but_repetitive_names():
    names = [f"{'a' * 30}{i}.cdn.example" for i in range(30)]
    assert detect_dns_tunneling(queries(names), RULE) == []

def test_ignores_reverse_lookups():
    rng = random.Random(3)
    names = [f"{random_label(rng)}.in-addr.arpa" for _ in range(30)]
    assert detect_dns_tunneling(queries(names), RULE) == []

def test_ignores_isp_style_hostnames():
    names = [f"c-68-47-20-{i}.hsd1.ga.comcast.net" for i in range(30)]
    names += [f"cpe-24-242-44-{i}.hot.res.rr.com" for i in range(30)]
    assert detect_dns_tunneling(queries(names), RULE) == []

