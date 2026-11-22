"""Usage: python3 -m netanalyzer.save_captures <capture> [<capture> ...] [--db netanalyzer.db]"""
import argparse
from netanalyzer.detections import load_rules, run_rules
from netanalyzer.parser import load_capture
from netanalyzer.storage import connect, save_analysis

def main():
    parser = argparse.ArgumentParser(description="Analyze captures and store the results in SQLite.")
    parser.add_argument("captures", nargs="+", help="one or more capture files")
    parser.add_argument("--db", default="netanalyzer.db", help="database file to write")
    args = parser.parse_args()
    rules = load_rules("rules")
    conn = connect(args.db)
    for path in args.captures:
        try:
            df = load_capture(path)
        except Exception as exc:
            print(f"{path}: could not read ({exc})")
            continue
        alerts = run_rules(df, rules)
        capture_id = save_analysis(conn, path, df, alerts)
        print(f"{path}: stored as capture {capture_id} ({len(df)} packets, {len(alerts)} alerts)")
    conn.close()

if __name__ == "__main__":
    main()
