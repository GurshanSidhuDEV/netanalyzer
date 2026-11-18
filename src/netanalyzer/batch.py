"""Usage: python3 -m netanalyzer.batch <capture> [<capture> ...]"""
import sys

from netanalyzer.detections import load_rules, run_rules
from netanalyzer.parser import load_capture

def main():
    rules = load_rules("rules")
    for path in sys.argv[1:]:
        try:
            df = load_capture(path)
        except Exception as exc:
            print(f"\n{path}: could not read ({exc})")
            continue
        syns = int(((df["protocol"] == "TCP") & (df["flags"] == "S")).sum())
        alerts = run_rules(df, rules)
        print(f"\n{path}: {len(df)} packets, {syns} SYN packets")
        if not alerts:
            print("  Alerts: none")
        for a in alerts:
            print(f"  [{a['level']}] {a['title']} ({a['technique']}): "
                  f"{a['src']} -> {a['dst']} - {a['evidence']}")

if __name__ == "__main__":
    main()
