import asyncio
import hashlib
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from threading import Lock

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import database
from server import (
    get_server_status,
    get_suricata_alerts,
    get_suricata_events,
)
from main import (
    convert_alert,
    SERVER_USERNAME,
    SERVER_HOST,
    ALERT_LIMIT,
)
from discord_alerts import send_alert


# --------------------------------------------------
# Configuration
# --------------------------------------------------

COLLECTION_INTERVAL = 30
EVENT_COLLECTION_LIMIT = 500
DISCORD_COOLDOWN_MINUTES = 15

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SentinelNode] %(levelname)s: %(message)s",
)
logger = logging.getLogger("sentinelnode")

# Prevent simultaneous manual/background collection.
poll_lock = Lock()


def make_notification_fingerprint(event):
    """
    Create a stable notification key for repeated alerts.

    Source port is excluded because a client often uses a different ephemeral
    source port for each connection. This affects notification grouping only;
    it does not delete or merge stored telemetry or incident records.
    """
    alert = event.get("alert") or {}
    identity = "|".join(str(value if value is not None else "Unknown") for value in (
        alert.get("signature_id", "unknown"),
        event.get("src_ip"),
        event.get("dest_ip"),
        event.get("dest_port"),
        event.get("proto") or event.get("protocol"),
    ))
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


# --------------------------------------------------
# Background collection
# --------------------------------------------------

def collect_incidents():
    """Collect Suricata alerts, save new incidents, and notify Discord."""
    if not poll_lock.acquire(blocking=False):
        logger.warning("Collection skipped: another collection is running.")
        return {
            "collected": 0,
            "new_incidents": 0,
            "discord_notifications_sent": 0,
            "discord_notifications_failed": 0,
            "discord_notifications_suppressed": 0,
            "skipped": True,
        }

    try:
        success, events = get_suricata_alerts(
            SERVER_USERNAME,
            SERVER_HOST,
            limit=ALERT_LIMIT,
        )

        if not success:
            raise RuntimeError(f"Suricata alert collection failed: {events}")

        existing = {
            str(item["id"])
            for item in database.load_incidents(limit=10000)
            if item.get("id") is not None
        }

        added = 0
        discord_sent = 0
        discord_failed = 0
        discord_suppressed = 0

        for event in events:
            try:
                # Preserve the original Suricata alert as telemetry as well.
                # This is idempotent: database.save_security_event uses INSERT OR IGNORE.
                try:
                    database.save_security_event(event)
                except Exception:
                    logger.exception("Could not save original alert telemetry.")

                incident = convert_alert(event)
                incident_id = str(incident.get("id", "")).strip()

                if not incident_id or incident_id in existing:
                    continue

                saved = database.save_incident(incident)
                if not saved:
                    continue

                existing.add(incident_id)
                added += 1

                try:
                    fingerprint = make_notification_fingerprint(event)
                    severity = str(incident.get("severity", "Low"))

                    if not database.discord_notification_allowed(
                        fingerprint,
                        severity,
                        cooldown_minutes=DISCORD_COOLDOWN_MINUTES,
                    ):
                        discord_suppressed += 1
                        logger.info(
                            "Suppressed repeated Discord notification for %s",
                            incident_id,
                        )
                        continue

                    if send_alert(incident):
                        database.record_discord_notification(
                            fingerprint,
                            severity,
                        )
                        discord_sent += 1
                    else:
                        discord_failed += 1
                        logger.error(
                            "Discord notification failed for incident %s",
                            incident_id,
                        )
                except Exception:
                    discord_failed += 1
                    logger.exception(
                        "Discord notification processing failed for %s",
                        incident_id,
                    )

            except Exception:
                logger.exception("Failed to process one Suricata alert.")

        result = {
            "collected": len(events),
            "new_incidents": added,
            "discord_notifications_sent": discord_sent,
            "discord_notifications_failed": discord_failed,
            "discord_notifications_suppressed": discord_suppressed,
            "skipped": False,
        }
        logger.info("Incident collection result: %s", result)
        return result

    finally:
        poll_lock.release()


def collect_events(limit=EVENT_COLLECTION_LIMIT):
    """Collect general telemetry separately from incident alerts."""
    success, events = get_suricata_events(
        SERVER_USERNAME,
        SERVER_HOST,
        limit=limit,
    )

    if not success:
        raise RuntimeError(f"Suricata telemetry collection failed: {events}")

    inserted = 0
    for event in events:
        try:
            if database.save_security_event(event):
                inserted += 1
        except Exception:
            logger.exception("Failed to save one telemetry event.")

    return {
        "received": len(events),
        "new_events": inserted,
        "duplicates": len(events) - inserted,
        "stored_total": database.count_security_events(),
    }


async def automatic_collection_loop():
    """Poll the sensor periodically without blocking the API event loop."""
    while True:
        try:
            await asyncio.to_thread(collect_incidents)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Automatic incident collection failed.")

        try:
            await asyncio.to_thread(collect_events, EVENT_COLLECTION_LIMIT)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Automatic telemetry collection failed.")

        try:
            await asyncio.sleep(COLLECTION_INTERVAL)
        except asyncio.CancelledError:
            raise


@asynccontextmanager
async def lifespan(app: FastAPI):
    database.initialize_database()
    task = asyncio.create_task(automatic_collection_loop())
    logger.info(
        "Automatic collection enabled; interval=%s seconds.",
        COLLECTION_INTERVAL,
    )

    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


# --------------------------------------------------
# FastAPI application
# --------------------------------------------------

app = FastAPI(
    title="SentinelNode SIEM API",
    description="Security monitoring, telemetry and incident management",
    version="1.5.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["*"],
)


class StatusUpdate(BaseModel):
    status: str


# --------------------------------------------------
# Health and information
# --------------------------------------------------

@app.get("/")
def root():
    return {
        "name": app.title,
        "version": app.version,
        "status": "online",
        "docs": "/docs",
        "health": "/api/health",
    }


@app.get("/api/health")
def health():
    return {
        "api": "online",
        "time": datetime.now(timezone.utc).isoformat(),
        "automatic_collection": True,
        "collection_interval_seconds": COLLECTION_INTERVAL,
    }


@app.get("/api/routes")
def list_routes():
    return {
        "application": app.title,
        "version": app.version,
        "routes": sorted({
            f"{method} {route.path}"
            for route in app.routes
            if hasattr(route, "methods")
            for method in route.methods
            if method not in {"HEAD", "OPTIONS"}
        }),
    }


# --------------------------------------------------
# Dashboard summary
# --------------------------------------------------

@app.get("/api/summary")
def summary():
    incidents = database.load_incidents(limit=10000)
    total = len(incidents)
    high_critical = sum(
        str(item.get("severity", "")).casefold() in {"high", "critical"}
        for item in incidents
    )
    open_count = sum(
        str(item.get("status", "Open")).casefold() in {"open", "in progress"}
        for item in incidents
    )
    resolved_count = sum(
        str(item.get("status", "")).casefold() in {"resolved", "closed"}
        for item in incidents
    )
    return {
        # Keep both key styles for compatibility with the existing frontend.
        "total": total,
        "total_incidents": total,
        "high_critical": high_critical,
        "open": open_count,
        "open_incidents": open_count,
        "resolved": resolved_count,
        "security_events": database.count_security_events(),
    }


# --------------------------------------------------
# Incident endpoints
# --------------------------------------------------

@app.get("/api/incidents")
def list_incidents(
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
):
    incidents = database.load_incidents(limit=10000)

    if severity:
        incidents = [
            item for item in incidents
            if str(item.get("severity", "")).casefold()
            == severity.strip().casefold()
        ]

    if status:
        incidents = [
            item for item in incidents
            if str(item.get("status", "Open")).casefold()
            == status.strip().casefold()
        ]

    return incidents[:limit]


def _parse_utc_timestamp(value):
    """Parse ISO timestamps, including Suricata's ±HHMM offset format."""
    if not value:
        return None
    try:
        value = str(value)
        # Python's fromisoformat expects a colon in timezone offsets on some versions.
        if len(value) >= 5 and value[-5] in {"+", "-"} and value[-3] != ":":
            value = value[:-2] + ":" + value[-2:]
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


@app.get("/api/incidents/{incident_id}/telemetry")
def incident_telemetry(
    incident_id: str,
    window_minutes: int = Query(default=5, ge=1, le=60),
):
    """Return the matching Suricata alert and nearby events for an incident."""
    incidents = database.load_incidents(limit=10000)
    incident = next(
        (item for item in incidents if str(item.get("id")) == incident_id),
        None,
    )
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found.")

    stored_events = database.load_security_events(limit=10000)
    exact_match = None

    # Prefer exact matching with the same converter that originally created the incident.
    for item in stored_events:
        raw = item.get("raw") or {}
        if str(raw.get("event_type", "")).lower() != "alert":
            continue
        try:
            if str(convert_alert(raw).get("id", "")) == incident_id:
                exact_match = item
                break
        except Exception:
            logger.debug("Could not convert stored alert %s", item.get("id"), exc_info=True)

    # Fallback for older incidents: match signature, endpoints and nearest timestamp.
    if exact_match is None:
        details = str(incident.get("description") or "")
        incident_time = _parse_utc_timestamp(incident.get("timestamp"))
        candidates = []
        for item in stored_events:
            raw = item.get("raw") or {}
            alert = raw.get("alert") or {}
            if str(raw.get("event_type", "")).lower() != "alert":
                continue
            signature_id = str(alert.get("signature_id", ""))
            src_ip = str(raw.get("src_ip") or "")
            dest_ip = str(raw.get("dest_ip") or "")
            if signature_id and signature_id not in details:
                # Incident descriptions include "Rule ID: <sid>" for current custom alerts.
                if f"Rule ID: {signature_id}" not in details:
                    continue
            if src_ip and src_ip not in details:
                continue
            if dest_ip and dest_ip not in details:
                continue
            event_time = _parse_utc_timestamp(item.get("timestamp"))
            delta = abs((event_time - incident_time).total_seconds()) if event_time and incident_time else 10**12
            if delta <= window_minutes * 60:
                candidates.append((delta, item))
        if candidates:
            exact_match = min(candidates, key=lambda pair: pair[0])[1]

    if exact_match is None:
        return {
            "incident_id": incident_id,
            "exact_match": None,
            "related_events": [],
            "count": 0,
            "window_minutes": window_minutes,
            "message": "Original alert not found in stored telemetry. Run Collect events and retry.",
        }

    raw_alert = exact_match.get("raw") or {}
    source_ip = raw_alert.get("src_ip")
    destination_ip = raw_alert.get("dest_ip")
    alert_time = _parse_utc_timestamp(exact_match.get("timestamp"))
    incident_ips = {ip for ip in (source_ip, destination_ip) if ip}
    related = []

    for item in stored_events:
        if item.get("id") == exact_match.get("id"):
            continue
        event_ips = {ip for ip in (item.get("src_ip"), item.get("dest_ip")) if ip}
        if not event_ips.intersection(incident_ips):
            continue
        event_time = _parse_utc_timestamp(item.get("timestamp"))
        if alert_time and event_time:
            delta = abs((event_time - alert_time).total_seconds())
            if delta > window_minutes * 60:
                continue
        related.append(item)

    related.sort(key=lambda item: item.get("timestamp") or "", reverse=True)
    return {
        "incident_id": incident_id,
        "exact_match": exact_match,
        "related_events": related[:200],
        "count": 1 + len(related),
        "window_minutes": window_minutes,
        "message": None,
    }


@app.patch("/api/incidents/{incident_id}")
def update_incident(incident_id: str, update: StatusUpdate):
    status = update.status.strip().title()
    if status not in {"Open", "In Progress", "Resolved", "Closed"}:
        raise HTTPException(
            status_code=400,
            detail="Status must be Open, In Progress, Resolved, or Closed.",
        )

    updated = database.update_incident_status(incident_id, status)
    if not updated:
        raise HTTPException(status_code=404, detail="Incident not found.")

    incident = next(
        (
            item for item in database.load_incidents(limit=10000)
            if str(item.get("id")) == incident_id
        ),
        None,
    )
    if incident is None:
        raise HTTPException(
            status_code=500,
            detail="Incident updated but could not be reloaded.",
        )
    return incident


# --------------------------------------------------
# Sensor status
# --------------------------------------------------

@app.get("/api/server")
def server_status():
    try:
        success, output = get_server_status(SERVER_USERNAME, SERVER_HOST)
        return {
            "connected": bool(success),
            "server": f"{SERVER_USERNAME}@{SERVER_HOST}",
            "message": str(output),
        }
    except Exception:
        logger.exception("Sensor status check failed.")
        return {
            "connected": False,
            "server": f"{SERVER_USERNAME}@{SERVER_HOST}",
            "message": "Could not check the sensor. Check the API terminal.",
        }


# --------------------------------------------------
# Manual collection endpoints
# --------------------------------------------------

@app.post("/api/collect")
def collect_alerts():
    try:
        return collect_incidents()
    except Exception as exc:
        logger.exception("Manual alert collection failed.")
        raise HTTPException(
            status_code=502,
            detail=f"Alert collection failed: {exc}",
        ) from exc


@app.post("/api/collect-events")
def collect_events_endpoint(
    limit: int = Query(default=500, ge=1, le=5000),
):
    try:
        return collect_events(limit=limit)
    except Exception as exc:
        logger.exception("Manual telemetry collection failed.")
        raise HTTPException(
            status_code=502,
            detail=f"Telemetry collection failed: {exc}",
        ) from exc


# --------------------------------------------------
# Telemetry endpoints
# --------------------------------------------------

@app.get("/api/events")
def list_events(
    event_type: str | None = Query(default=None),
    src_ip: str | None = Query(default=None),
    dest_ip: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=5000),
):
    allowed_types = {"alert", "dns", "http", "tls", "flow"}

    if event_type:
        event_type = event_type.strip().lower()
        if event_type not in allowed_types:
            raise HTTPException(
                status_code=400,
                detail="event_type must be one of: "
                + ", ".join(sorted(allowed_types)),
            )

    try:
        return database.load_security_events(
            limit=limit,
            event_type=event_type,
            src_ip=src_ip,
            dest_ip=dest_ip,
        )
    except Exception as exc:
        logger.exception("Telemetry query failed.")
        raise HTTPException(
            status_code=500,
            detail=f"Could not load telemetry: {exc}",
        ) from exc
