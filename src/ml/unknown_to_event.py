import json
import os
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

PATTERN_STORE_FILE = PROJECT_ROOT / "output" / "pattern_store.json"
EVENT_FILE = PROJECT_ROOT / "output" / "events.json"


def load_patterns():

    if not os.path.exists(PATTERN_STORE_FILE):
        print("pattern_store.json not found.")
        return []

    with open(
        PATTERN_STORE_FILE,
        "r",
        encoding="utf-8"
    ) as f:

        return json.load(f)


def append_event(event):

    with open(
        EVENT_FILE,
        "a",
        encoding="utf-8"
    ) as f:

        f.write(
            json.dumps(event) + "\n"
        )


def main():

    print("=" * 65)
    print(" UNKNOWN PATTERN → EVENT INTEGRATION")
    print("=" * 65)

    patterns = load_patterns()

    if not patterns:
        print("No patterns available.")
        return

    events_created = 0

    for pattern in patterns:

        # Only integrate newly discovered patterns
        if pattern.get("status") != "NEW":
            continue

        pattern_id = pattern.get(
            "pattern_id",
            "UNKNOWN"
        )

        signature = pattern.get(
            "behavioral_signature",
            {}
        )

        observation_count = pattern.get(
            "observations",
            pattern.get("cluster_size", 0)
        )

        event_id = (
            "EVT-UNKNOWN-" +
            pattern_id.replace("P-", "")
        )

        event = {

            "event_id": event_id,

            "timestamp":
                datetime.now(
                    timezone.utc
                ).isoformat(),

            "src": "UNKNOWN",

            "dst": "UNKNOWN",

            "src_port": 0,

            "dst_port": 0,

            "protocol": "UNKNOWN",

            "type":
                "UNKNOWN_BEHAVIOR",

            "confidence": None,

            "severity": "MEDIUM",

            "pattern_id":
                pattern_id,

            "evidence": {

                "classification":
                    "UNKNOWN_BEHAVIOR",

                "pattern_status":
                    pattern.get(
                        "status",
                        "NEW"
                    ),

                "observation_count":
                    observation_count,

                "detection_method":
                    "IsolationForest + DBSCAN",

                "behavioral_signature":
                    signature
            }
        }

        append_event(event)

        events_created += 1

        print()
        print(
            f"Created event: {event_id}"
        )

        print(
            f"Pattern: {pattern_id}"
        )

        print(
            f"Observations: "
            f"{observation_count}"
        )

        print(
            "Classification: "
            "UNKNOWN_BEHAVIOR"
        )

        print(
            "Status: NEW"
        )


    print()
    print("=" * 65)
    print(
        f"UNKNOWN EVENTS CREATED: "
        f"{events_created}"
    )
    print("=" * 65)


if __name__ == "__main__":
    main()