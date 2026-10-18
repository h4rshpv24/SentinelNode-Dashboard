
import json
import shlex
import subprocess


EVE_LOG_PATH = "/var/log/suricata/eve.json"

SUPPORTED_EVENT_TYPES = {
    "alert",
    "dns",
    "http",
    "tls",
    "flow",
}


def run_ssh_command(username, host, command, timeout=20):
    """Run a command on the Linux sensor through SSH."""
    target = f"{username}@{host}"

    try:
        result = subprocess.run(
            [
                "ssh",
                "-o", "BatchMode=yes",
                "-o", "IPQoS=throughput",
                "-o", "ConnectTimeout=10",
                "-o", "ConnectionAttempts=1",
                "-o", "ServerAliveInterval=5",
                "-o", "ServerAliveCountMax=2",
                target,
                command,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

        if result.returncode == 0:
            return True, result.stdout.strip()

        error = result.stderr.strip()
        if "Permission denied" in error:
            return False, "SSH authentication failed. Check the sensor username and SSH key."
        if "Could not resolve hostname" in error:
            return False, f"Could not resolve sensor hostname: {host}"
        if "Connection refused" in error:
            return False, f"SSH connection refused by {host}. Check that SSH is running."

        return False, error or f"SSH exited with code {result.returncode}."

    except subprocess.TimeoutExpired:
        return False, f"SSH command timed out after {timeout} seconds."
    except FileNotFoundError:
        return False, "Windows could not find ssh.exe. Install or enable the OpenSSH Client."
    except OSError as exc:
        return False, f"Could not run SSH: {exc}"


def get_server_status(username, host):
    """Check connectivity and retrieve the sensor's hostname and uptime."""
    return run_ssh_command(
        username,
        host,
        "hostname && uptime",
        timeout=20,
    )


def get_suricata_events(
    username,
    host,
    limit=500,
    event_types=None,
):
    """
    Fetch recent Suricata EVE records.

    Returns:
        (True, list[dict]) on success
        (False, error_message) on failure
    """
    try:
        limit = max(1, min(int(limit), 5000))
    except (TypeError, ValueError):
        return False, "The event limit must be a valid integer."

    if event_types is None:
        event_types = set(SUPPORTED_EVENT_TYPES)
    else:
        event_types = set(event_types)

    if not event_types or not event_types.issubset(SUPPORTED_EVENT_TYPES):
        return False, "Unsupported or empty Suricata event type list."

    # Quote all remote shell arguments. Event types are also allowlisted above.
    path = shlex.quote(EVE_LOG_PATH)
    types_pattern = "|".join(sorted(event_types))
    pattern = (
        '"event_type"[[:space:]]*:[[:space:]]*'
        f'"({types_pattern})"'
    )
    quoted_pattern = shlex.quote(pattern)

    # tail runs first in the pipeline so we examine only recent lines.
    # grep then filters the recent lines by supported event type.
    command = (
        f"tail -n {limit * 10} {path} "
        f"| grep -E {quoted_pattern} "
        f"| tail -n {limit}"
    )

    success, output = run_ssh_command(
        username,
        host,
        command,
        timeout=45,
    )

    if not success:
        return False, output

    events = []

    for line in output.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        if (
            isinstance(event, dict)
            and event.get("event_type") in event_types
        ):
            events.append(event)

    return True, events


def get_suricata_alerts(username, host, limit=100):
    """Backward-compatible alert-only collector."""
    return get_suricata_events(
        username,
        host,
        limit=limit,
        event_types={"alert"},
    )
