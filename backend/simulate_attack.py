
import json
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

API_URL = "http://127.0.0.1:8000/events"

# A controlled, simulated attack sequence.
# All events use documentation-only IP addresses.
ATTACK_SCENARIO = [
    {
        "event_type": "login_failed",
        "username": "simulation_user",
        "source_ip": "192.0.2.50",
        "details": "Simulated failed login attempt 1",
    },
    {
        "event_type": "login_failed",
        "username": "simulation_user",
        "source_ip": "192.0.2.50",
        "details": "Simulated failed login attempt 2",
    },
    {
        "event_type": "login_failed",
        "username": "simulation_user",
        "source_ip": "192.0.2.50",
        "details": "Simulated failed login attempt 3",
    },
    {
        "event_type": "login_success",
        "username": "simulation_user",
        "source_ip": "192.0.2.50",
        "details": "Simulated successful login after failures",
    },
    {
        "event_type": "privilege_change",
        "username": "simulation_user",
        "source_ip": "192.0.2.50",
        "details": "Simulated privilege escalation",
    },
    {
        "event_type": "internal_discovery",
        "username": "simulation_user",
        "source_ip": "192.0.2.50",
        "details": "Simulated internal network discovery",
    },
    {
        "event_type": "outbound_transfer",
        "username": "simulation_user",
        "source_ip": "192.0.2.50",
        "details": "Simulated suspicious outbound data transfer",
    },
]


def send_event(event):
    payload = json.dumps(event).encode("utf-8")

    request = Request(
        API_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urlopen(request, timeout=5) as response:
        result = json.loads(response.read().decode("utf-8"))
        print(
            f"[{response.status}] "
            f"{event['event_type']} for {event['username']} "
            f"(ID: {result['event_id']})"
        )


def main():
    print("Starting Sentinel-X attack simulation...")
    print(f"Sending {len(ATTACK_SCENARIO)} events to {API_URL}\n")

    try:
        for event in ATTACK_SCENARIO:
            send_event(event)
            time.sleep(0.3)

    except HTTPError as error:
        print(f"API rejected an event: HTTP {error.code}")
        print(error.read().decode("utf-8"))

    except URLError as error:
        print(f"Could not connect to Sentinel-X API: {error.reason}")
        print("Make sure the backend server is running.")

    except TimeoutError:
        print("The API request timed out.")

    else:
        print("\nSimulation complete. All events were accepted.")


if __name__ == "__main__":
    main()
