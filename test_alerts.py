
from server import get_suricata_alerts

success, result = get_suricata_alerts(
    "harsh", "192.168.0.195", limit=10
)

if success:
    print("SURICATA CONNECTION: SUCCESS")
    print("Alerts retrieved:", len(result))

    for alert in result[:3]:
        details = alert.get("alert", {})
        print(
            alert.get("timestamp"),
            "|",
            details.get("signature", "Unknown alert"),
            "| severity:",
            details.get("severity", "?"),
        )
else:
    print("SURICATA CONNECTION: FAILED")
    print(result)
