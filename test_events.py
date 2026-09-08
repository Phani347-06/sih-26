import json
from datetime import datetime, timedelta


events = []

base_time = datetime.now()


# Simulate reconnaissance
for i, port in enumerate([
    21,
    22,
    23,
    25,
    80,
    443,
    8080
]):

    event = {

        "event_id": f"EVT-{i+1}",

        "timestamp": (
            base_time +
            timedelta(seconds=i)
        ).isoformat(),

        "src": "192.168.1.50",

        "dst": "192.168.1.100",

        "src_port": 50000 + i,

        "dst_port": port,

        "protocol": "TCP",

        "type": "PORT_SCAN",

        "confidence": 0.95,

        "severity": "HIGH",

        "evidence": {

            "packet_count": 2,

            "total_bytes": 120,

            "packet_rate": 2,

            "syn_count": 1,

            "ack_count": 0
        }
    }

    events.append(event)


with open(
        "src/output/events.json",
    "w",
    encoding="utf-8"
) as f:

    for event in events:

        json.dump(event, f)

        f.write("\n")


print(
    "Created",
    len(events),
    "test security events."
)