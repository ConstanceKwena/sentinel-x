"""Trigger the backend's local-only synthetic attack demonstration."""

import argparse
import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


API_URL = "http://127.0.0.1:8000/simulation/run"
SCENARIOS = (
    "brute_force",
    "account_compromise",
    "privilege_escalation",
    "data_transfer",
    "full_attack_chain",
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenario",
        choices=SCENARIOS,
        default="full_attack_chain",
        help="Synthetic event sequence to send (default: full_attack_chain).",
    )
    arguments = parser.parse_args()
    request = Request(
        API_URL,
        data=json.dumps({"scenario": arguments.scenario}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=10) as response:
            result = json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")
        print(f"Simulation request rejected: HTTP {error.code}: {body}")
        return
    except URLError as error:
        print(f"Could not connect to Sentinel-X API: {error.reason}")
        print("Start the backend with: python -m uvicorn backend.main:app --reload")
        return
    except TimeoutError:
        print("The API request timed out.")
        return

    print(f"{result['message']} Scenario: {result['scenario']}")
    print(f"Synthetic events recorded: {result['event_count']}")
    print(f"Incidents created: {result['incidents_created']}")
    print(f"Correlated attack chains: {len(result['attack_chains'])}")
    for event_id in result["event_ids"]:
        print(f"  Event: {event_id}")
    for chain in result["attack_chains"]:
        print(f"  Chain: {chain['description']}")
        print(f"  Account: {chain['username']} from {chain['source_ip']}")


if __name__ == "__main__":
    main()
