"""Store results in using SQLite so that they can be shown in a dashboard"""
import hashlib
import sqlite3
from datetime import datetime, timezone
import pandas as pd

SCHEMA = """ 
CREATE TABLE IF NOT EXISTS captures (
    id INTEGER PRIMARY KEY,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL UNIQUE,
    analyzed_at TEXT NOT NULL,
    packets INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS packets (
    capture_id INTEGER NOT NULL REFERENCES captures(id),
    time REAL,
    size INTEGER,
    protocol TEXT,
    src TEXT,
    dst TEXT,
    sport INTEGER,
    dport INTEGER,
    flags TEXT,
    dns_query TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    capture_id INTEGER NOT NULL REFERENCES captures(id),
    rule_id TEXT,
    title TEXT,
    level TEXT,
    technique TEXT,
    src TEXT,
    dst TEXT,
    first_seen REAL,
    evidence TEXT
);
CREATE INDEX IF NOT EXISTS idx_packets_capture ON packets(capture_id);
CREATE INDEX IF NOT EXISTS idx_alerts_capture ON alerts(capture_id); """

PACKET_COLUMNS = ["time", "size", "protocol", "src", "dst", "sport", "dport", "flags", "dns_query"]

def connect(db_path="netanalyzer.db"):
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    return conn

def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def save_analysis(conn, path, df, alerts):
    sha = file_sha256(path)
    with conn:
        old = conn.execute("SELECT id FROM captures WHERE sha256 = ?", (sha,)).fetchone()
        if old:
            for table in ("alerts", "packets"):
                conn.execute(f"DELETE FROM {table} WHERE capture_id = ?", (old[0],))
            conn.execute("DELETE FROM captures WHERE id = ?", (old[0],))
        cursor = conn.execute(
            "INSERT INTO captures (path, sha256, analyzed_at, packets) VALUES (?, ?, ?, ?)",
            (str(path), sha, datetime.now(timezone.utc).isoformat(timespec="seconds"), len(df)),
        )
        capture_id = cursor.lastrowid
        if len(df):
            rows = df[PACKET_COLUMNS].copy()
            rows.insert(0, "capture_id", capture_id)
            rows.to_sql("packets", conn, if_exists="append", index=False, chunksize=5000)
        conn.executemany(
            "INSERT INTO alerts (capture_id, rule_id, title, level, technique, src, dst, "
            "first_seen, evidence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(capture_id, a["rule_id"], a["title"], a["level"], a["technique"],
              a["src"], a["dst"], a.get("first_seen"), a["evidence"]) for a in alerts],
        )
    return capture_id

def list_captures(conn):
    return pd.read_sql_query(
        "SELECT c.id, c.path, c.analyzed_at, c.packets, "
        "(SELECT COUNT(*) FROM alerts a WHERE a.capture_id = c.id) AS alerts "
        "FROM captures c ORDER BY c.id",
        conn,
    )

def protocol_breakdown(conn, capture_id):
    return pd.read_sql_query(
        "SELECT protocol, COUNT(*) AS packets, SUM(size) AS bytes FROM packets "
        "WHERE capture_id = ? GROUP BY protocol ORDER BY packets DESC",
        conn, params=(capture_id,),
    )

def top_talkers(conn, capture_id, limit=10):
    return pd.read_sql_query(
        "SELECT src, COUNT(*) AS packets, SUM(size) AS bytes FROM packets "
        "WHERE capture_id = ? AND src IS NOT NULL "
        "GROUP BY src ORDER BY bytes DESC LIMIT ?",
        conn, params=(capture_id, limit),
    )

def traffic_over_time(conn, capture_id, bucket_seconds=60):
    return pd.read_sql_query(
        "SELECT CAST(time / ? AS INTEGER) * ? AS bucket, COUNT(*) AS packets FROM packets "
        "WHERE capture_id = ? GROUP BY bucket ORDER BY bucket",
        conn, params=(bucket_seconds, bucket_seconds, capture_id),
    )

def alerts_for(conn, capture_id):
    return pd.read_sql_query(
        "SELECT rule_id, title, level, technique, src, dst, first_seen, evidence "
        "FROM alerts WHERE capture_id = ? ORDER BY id",
        conn, params=(capture_id,),
    )
