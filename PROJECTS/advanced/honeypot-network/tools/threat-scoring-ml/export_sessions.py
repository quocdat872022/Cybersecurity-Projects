#!/usr/bin/env python3
"""
©AngelaMos | 2026
export_sessions.py

Exports completed honeypot sessions with engineered features to CSV,
for manual labeling and downstream model training. Pulls both the
session summary row and its constituent events (for features the
sessions table doesn't carry: unique command count, inter-command
timing, tool-transfer/persistence flags).
"""

import csv
import json
import os
import statistics
import sys

import psycopg2
import psycopg2.extras

DSN = os.environ.get(
    "HIVE_DATABASE_URL",
    "postgres://hive:hive@localhost:53743/hive?sslmode=disable",
)

TOOL_TRANSFER_PATTERNS = ("wget", "curl", "tftp", "scp", "sftp", "ftp ")
PERSISTENCE_PATTERNS = ("crontab", "/etc/cron", "systemctl", "/etc/systemd")


def extract_command(service_data):
    if not service_data:
        return None
    try:
        data = json.loads(service_data) if isinstance(service_data, str) else service_data
    except (TypeError, ValueError):
        return None
    return data.get("command") or data.get("query")


def fetch_sessions(conn, limit):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT id, sensor_id, started_at, ended_at, service_type,
                   source_ip, login_success, username, command_count,
                   mitre_techniques, threat_score
            FROM sessions
            WHERE ended_at IS NOT NULL
            ORDER BY started_at DESC
            LIMIT %s
            """,
            (limit,),
        )
        return cur.fetchall()


def fetch_events_for_session(conn, session_id):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT event_type, timestamp, service_data
            FROM events
            WHERE session_id = %s
            ORDER BY timestamp ASC
            """,
            (session_id,),
        )
        return cur.fetchall()


def build_features(session, events):
    duration_seconds = 0.0
    if session["ended_at"] and session["started_at"]:
        duration_seconds = (
            session["ended_at"] - session["started_at"]
        ).total_seconds()

    commands = [
        extract_command(ev["service_data"])
        for ev in events
        if ev["event_type"] == "command.input"
    ]
    commands = [c for c in commands if c]
    unique_commands = len(set(commands))

    auth_attempts = sum(
        1 for ev in events
        if ev["event_type"] in ("login.success", "login.failed")
    )

    cmd_timestamps = [
        ev["timestamp"] for ev in events
        if ev["event_type"] == "command.input"
    ]
    gaps = [
        (cmd_timestamps[i + 1] - cmd_timestamps[i]).total_seconds()
        for i in range(len(cmd_timestamps) - 1)
    ]
    mean_gap = statistics.mean(gaps) if gaps else 0.0
    std_gap = statistics.pstdev(gaps) if len(gaps) > 1 else 0.0

    lower_cmds = " ".join(commands).lower()
    has_tool_transfer = any(p in lower_cmds for p in TOOL_TRANSFER_PATTERNS)
    has_persistence = any(p in lower_cmds for p in PERSISTENCE_PATTERNS)

    mitre_count = len(session["mitre_techniques"] or [])

    return {
        "session_id": session["id"],
        "service_type": session["service_type"],
        "source_ip": session["source_ip"],
        "started_at": session["started_at"].isoformat(),
        "command_count": session["command_count"],
        "unique_commands": unique_commands,
        "duration_seconds": round(duration_seconds, 2),
        "auth_attempts": auth_attempts,
        "mitre_technique_count": mitre_count,
        "mean_command_gap": round(mean_gap, 2),
        "std_command_gap": round(std_gap, 2),
        "has_tool_transfer": int(has_tool_transfer),
        "has_persistence": int(has_persistence),
        "login_success": int(session["login_success"]),
        "heuristic_threat_score": session["threat_score"],
        # left blank for manual labeling
        "label": "",
    }


def main():
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 200

    conn = psycopg2.connect(DSN)
    try:
        sessions = fetch_sessions(conn, limit)
        rows = []
        for sess in sessions:
            events = fetch_events_for_session(conn, sess["id"])
            rows.append(build_features(sess, events))
    finally:
        conn.close()

    if not rows:
        print("No completed sessions found.", file=sys.stderr)
        return

    fieldnames = list(rows[0].keys())
    writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)


if __name__ == "__main__":
    main()