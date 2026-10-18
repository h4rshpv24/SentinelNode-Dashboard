
import os
from pathlib import Path

import requests
from dotenv import load_dotenv

# Always load .env from the SentinelNode project directory.
ENV_PATH = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=ENV_PATH, override=True)

DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "").strip()


def send_alert(incident: dict) -> bool:
    webhook = DISCORD_WEBHOOK_URL

    if not webhook.startswith("https://discord.com/api/webhooks/"):
        print("Discord Error: Missing or invalid webhook in .env")
        return False

    severity = str(incident.get("severity", "Medium")).capitalize()
    colors = {
        "Critical": 15158332,
        "High": 15158332,
        "Medium": 16776960,
        "Low": 3447003,
    }

    source = incident.get("src_ip") or incident.get("source") or "N/A"
    destination = incident.get("dest_ip") or incident.get("destination") or "N/A"
    timestamp = incident.get("timestamp") or incident.get("time") or "N/A"
    title = str(
        incident.get("title") or incident.get("event") or "Security Alert"
    )

    payload = {
        "content": "🚨 **SentinelNode | New Security Alert**",
        "allowed_mentions": {"parse": []},
        "embeds": [{
            "title": title[:256],
            "color": colors.get(severity, 3447003),
            "fields": [
                {"name": "Severity", "value": severity, "inline": True},
                {
                    "name": "Status",
                    "value": str(incident.get("status", "Open"))[:1024],
                    "inline": True,
                },
                {"name": "Source IP", "value": str(source)[:1024], "inline": True},
                {
                    "name": "Destination IP",
                    "value": str(destination)[:1024],
                    "inline": True,
                },
                {
                    "name": "Timestamp",
                    "value": str(timestamp)[:1024],
                    "inline": False,
                },
            ],
            "footer": {
                "text": f"Incident ID: {incident.get('id', 'N/A')}"
            },
        }],
    }

    try:
        response = requests.post(webhook, json=payload, timeout=10)

        if response.status_code in (200, 204):
            print("Discord: Alert dispatched successfully.")
            return True

        print(f"Discord Error: HTTP {response.status_code}: {response.text[:300]}")
        return False

    except requests.RequestException as exc:
        print(f"Discord Error: Request failed: {exc}")
        return False


def send_discord_alert(incident: dict) -> bool:
    return send_alert(incident)
