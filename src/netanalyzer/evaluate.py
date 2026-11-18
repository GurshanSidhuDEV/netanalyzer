"""Usage: python3 -m netanalyzer.evaluate [labels.yml]"""

import sys
from pathlib import Path
import yaml
from netanalyzer.detections import load_rules, run_rules
from netanalyzer.parser import load_capture

def ratio(numerator, denominator):
    """Format a fraction as a percentage, or n/a when there is nothing to divide by."""
    if denominator == 0:
        return "n/a"
    return f"{numerator / denominator:.0%} ({numerator}/{denominator})"

def main():
    labels_path = sys.argv[1] if len(sys.argv) > 1 else "data/labels.yml"
    with open(labels_path) as f:
        captures = yaml.safe_load(f)["captures"]

    rules = load_rules("rules")
    rule_ids = [r["id"] for r in rules]
    counts = {rid: {"tp": 0, "fp": 0, "fn": 0, "tn": 0} for rid in rule_ids}
    attacks = 0
    attacks_flagged = 0

    for item in captures:
        path = item["file"]
        if not Path(path).exists():
            print(f"skipping {path} (file not found)")
            continue
        df = load_capture(path)
        fired = {a["rule_id"] for a in run_rules(df, rules)}
        expected = set(item["expected"])

        for rid in rule_ids:
            if rid in expected:
                counts[rid]["tp" if rid in fired else "fn"] += 1
            else:
                counts[rid]["fp" if rid in fired else "tn"] += 1

        if item["attack"]:
            attacks += 1
            attacks_flagged += bool(fired)

        print(f"{Path(path).name:28} attack={str(item['attack']):5} "
              f"expected={sorted(expected) or '-'} fired={sorted(fired) or '-'}")

    print("\nPer rule:")
    for rule in rules:
        c = counts[rule["id"]]
        print(f"  {rule['id']} {rule['title']}: "
              f"precision {ratio(c['tp'], c['tp'] + c['fp'])}, "
              f"recall {ratio(c['tp'], c['tp'] + c['fn'])}, "
              f"false positives {c['fp']}")

    print(f"\nOverall coverage: {ratio(attacks_flagged, attacks)} "
          "of attack captures flagged by at least one rule")

if __name__ == "__main__":
    main()
