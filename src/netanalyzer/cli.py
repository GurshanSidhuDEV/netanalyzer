"""Usage: python3 -m netanalyzer.cli <capture.pcap>"""
import sys

import pandas as pd

from netanalyzer.detections import load_rules, run_rules
from netanalyzer.parser import load_capture

def main():
    df = load_capture(sys.argv[1])
    print(f"Total packets: {len(df)}")
    print("\nProtocol breakdown:")
    print(df["protocol"].value_counts())
    print("\nTop sources by packets:")
    print(df["src"].value_counts().head(5))
    print("\nTop sources by bytes:")
    print(df.groupby("src")["size"].sum().sort_values(ascending=False).head(5))
    print("\nPackets per minute:")
    times = pd.to_datetime(df["time"], unit="s")
    print(df.set_index(times).resample("1min").size())

    print("\nAlerts:")
    alerts = run_rules(df, load_rules("rules"))
    if not alerts:
        print("  none")
    for a in alerts:
        print(f"  [{a['level']}] {a['title']} ({a['technique']}): "
              f"{a['src']} -> {a['dst']} - {a['evidence']}")

if __name__ == "__main__":
    main()
