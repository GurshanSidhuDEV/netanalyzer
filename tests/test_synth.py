from netanalyzer.detections import load_rules, run_rules
from netanalyzer.parser import load_capture
from netanalyzer.synth import generate

def fired(path):
    df = load_capture(str(path))
    return {a["rule_id"] for a in run_rules(df, load_rules("rules"))}
def test_synthetic_attacks_detected_and_benign_traffic_clean(tmp_path):
    files = generate(tmp_path)
    assert fired(files["syn_flood"]) == {"NA-002"}
    assert fired(files["dns_tunnel"]) == {"NA-003"}
    assert fired(files["benign_busy_server"]) == set()
    assert fired(files["benign_dns"]) == set()
