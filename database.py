
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


DB_PATH = Path(__file__).resolve().parent / "sentinelnode.db"


def get_connection():
    """Open a SQLite connection with dictionary-style row access."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 10000")
    return conn


def initialize_database():
    """Create missing tables and indexes without deleting existing data."""
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                time TEXT NOT NULL,
                severity TEXT NOT NULL,
                event TEXT NOT NULL,
                source TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open',
                details TEXT NOT NULL DEFAULT ''
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                src_ip TEXT,
                src_port INTEGER,
                dest_ip TEXT,
                dest_port INTEGER,
                protocol TEXT,
                summary TEXT NOT NULL DEFAULT '',
                raw_json TEXT NOT NULL,
                ingested_at TEXT NOT NULL
                    DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            )
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_incidents_time
            ON incidents(time)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_security_events_timestamp
            ON security_events(timestamp)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_security_events_type
            ON security_events(event_type)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_security_events_src_ip
            ON security_events(src_ip)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_security_events_dest_ip
            ON security_events(dest_ip)
        """)


def _first_value(*values):
    for value in values:
        if value is not None and value != "":
            return value
    return None


def _safe_int(value):
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _normalize_event(event):
    """Normalize a Suricata EVE record for persistent storage."""
    if not isinstance(event, dict):
        raise ValueError("Security event must be a dictionary")

    raw_json = json.dumps(
        event,
        sort_keys=True,
        ensure_ascii=False,
        default=str,
    )
    event_id = hashlib.sha256(raw_json.encode("utf-8")).hexdigest()

    alert = event.get("alert") or {}
    dns = event.get("dns") or {}
    http = event.get("http") or {}
    tls = event.get("tls") or {}

    event_type = str(event.get("event_type") or "unknown").lower()

    summary = _first_value(
        alert.get("signature"),
        dns.get("rrname"),
        dns.get("query"),
        http.get("hostname"),
        http.get("url"),
        tls.get("sni"),
        (event.get("flow") or {}).get("state"),
        event_type,
        "Suricata event",
    )

    return {
        "id": event_id,
        "timestamp": str(_first_value(
            event.get("timestamp"),
            datetime.now(timezone.utc).isoformat(),
        )),
        "event_type": event_type,
        "src_ip": event.get("src_ip"),
        "src_port": _safe_int(event.get("src_port")),
        "dest_ip": event.get("dest_ip"),
        "dest_port": _safe_int(event.get("dest_port")),
        "protocol": _first_value(event.get("proto"), event.get("protocol")),
        "summary": str(summary),
        "raw_json": raw_json,
    }


def save_security_event(event):
    """Insert an event once; never overwrite an existing telemetry record."""
    item = _normalize_event(event)

    with get_connection() as conn:
        cursor = conn.execute("""
            INSERT OR IGNORE INTO security_events (
                id, timestamp, event_type, src_ip, src_port,
                dest_ip, dest_port, protocol, summary, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            item["id"], item["timestamp"], item["event_type"],
            item["src_ip"], item["src_port"], item["dest_ip"],
            item["dest_port"], item["protocol"], item["summary"],
            item["raw_json"],
        ))
        return cursor.rowcount == 1


def save_security_events(events):
    """Save a batch of telemetry events and return the insertion count."""
    return sum(1 for event in events if save_security_event(event))


def load_security_events(
    limit=500,
    event_type=None,
    src_ip=None,
    dest_ip=None,
):
    """Load telemetry with optional type, source IP and destination IP filters."""
    limit = max(1, min(int(limit), 10000))
    conditions = []
    params = []

    if event_type:
        conditions.append("event_type = ?")
        params.append(str(event_type).lower())

    if src_ip:
        conditions.append("src_ip = ?")
        params.append(src_ip)

    if dest_ip:
        conditions.append("dest_ip = ?")
        params.append(dest_ip)

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    with get_connection() as conn:
        rows = conn.execute(
            f"""
            SELECT *
            FROM security_events
            {where}
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (*params, limit),
        ).fetchall()

    results = []
    for row in rows:
        item = dict(row)
        try:
            item["raw"] = json.loads(item.get("raw_json") or "{}")
        except (TypeError, json.JSONDecodeError):
            item["raw"] = {}
        results.append(item)

    return results


def count_security_events(event_type=None):
    with get_connection() as conn:
        if event_type:
            row = conn.execute("""
                SELECT COUNT(*) AS total
                FROM security_events
                WHERE event_type = ?
            """, (event_type.lower(),)).fetchone()
        else:
            row = conn.execute("""
                SELECT COUNT(*) AS total
                FROM security_events
            """).fetchone()

    return row["total"]


def save_incident(incident):
    """Insert an incident without replacing its existing status or data."""
    if not isinstance(incident, dict):
        raise ValueError("Incident must be a dictionary")

    incident_id = incident.get("id")
    if not incident_id:
        raise ValueError("Incident must contain an id")

    incident_time = _first_value(
        incident.get("timestamp"),
        incident.get("time"),
        datetime.now(timezone.utc).isoformat(),
    )
    event = _first_value(
        incident.get("title"),
        incident.get("event"),
        "Security incident",
    )
    details = _first_value(
        incident.get("description"),
        incident.get("details"),
        "",
    )

    with get_connection() as conn:
        cursor = conn.execute("""
            INSERT OR IGNORE INTO incidents (
                id, time, severity, event, source, status, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            str(incident_id),
            str(incident_time),
            str(_first_value(incident.get("severity"), "Medium")),
            str(event),
            str(_first_value(incident.get("source"), "SentinelNode")),
            str(_first_value(incident.get("status"), "Open")),
            str(details),
        ))
        return cursor.rowcount == 1


def load_incidents(limit=1000):
    """Return incidents with legacy fields and API-compatible aliases."""
    limit = max(1, min(int(limit), 10000))

    with get_connection() as conn:
        rows = conn.execute("""
            SELECT id, time, severity, event, source, status, details
            FROM incidents
            ORDER BY time DESC
            LIMIT ?
        """, (limit,)).fetchall()

    results = []
    for row in rows:
        item = dict(row)
        item["timestamp"] = item.get("time")
        item["title"] = item.get("event")
        item["description"] = item.get("details")
        results.append(item)

    return results


def update_incident_status(incident_id, status):
    """Change only the requested incident's status."""
    with get_connection() as conn:
        cursor = conn.execute("""
            UPDATE incidents
            SET status = ?
            WHERE id = ?
        """, (status, incident_id))
        return cursor.rowcount > 0


initialize_database()
