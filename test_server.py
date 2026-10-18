
from server import get_server_status

USERNAME = "harsh"
HOST = "192.168.0.195"

success, output = get_server_status(USERNAME, HOST)

if success:
    print("SENTINELNODE SERVER: CONNECTED")
    print(output)
else:
    print("SENTINELNODE SERVER: CONNECTION FAILED")
    print(output)
