
from datetime import datetime, timezone

import database
from main import convert_alert
from discord_alerts import send_discord_alert


def main():
    database.initialize_database()

    # Create a synthetic Suricata-style alert with a unique ID.
    now = datetime.now(timezone.utc).isoformat()
    test_event = {
        "timestamp": now,
        "event_type": "alert",
        "src_ip": "192.0.2.10",
        "src_port": int(datetime.now().timestamp()) % 60000 + 1024,
        "dest_ip": "192.0.2.20",
        "dest_port": 443,
        "proto": "TCP",
        "alert": {
            "signature_id": 9900001,
            "signature": "SentinelNode Synthetic Notification Test",
            "severity": 2,
            "category": "Test Event",
            "action": "allowed",
        },
    }

    incident = convert_alert(test_event)

    # Check the existing database before doing anything.
    existing_ids = {
        item["id"] for item in database.load_incidents()
    }

    if incident["id"] in existing_ids:
        print("Test incident already exists; stopping to avoid duplicates.")
        return

    # Follow the dashboard's new-incident path.
    database.save_incident(incident)
    print("PASS: New synthetic incident saved to SQLite.")

    saved_ids = {
        item["id"] for item in database.load_incidents()
    }

    if incident["id"] not in saved_ids:
        print("FAIL: Incident was not found in SQLite.")
        return

    print("Sending Discord notification...")
    success, message = send_discord_alert(incident)
    print(message)

    if success:
        print("PASS: Notification delivered to Discord.")
        print("Incident ID:", incident["id"])
        print("Open the dashboard to see the test incident.")
    else:
        print("FAIL: Discord notification failed.")


if __name__ == "__main__":
    main()
