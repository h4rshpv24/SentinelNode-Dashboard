
from discord_alerts import send_discord_alert
from datetime import datetime

test_incident = {
    "id": f"SN-TEST-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "severity": "Medium",
    "event": "SentinelNode Pipeline Test",
    "source": "127.0.0.1",
    "status": "Open",
    "details": (
        "Synthetic test incident. "
        "No attack occurred. "
        "Testing Discord delivery only."
    ),
}

success, message = send_discord_alert(test_incident)

print("Test incident:", test_incident["id"])
print("Result:", message)

if success:
    print("PASS: Discord received the test request.")
else:
    print("FAIL: Check your webhook configuration.")
