import json
import os


EVENT_FILE = "../output/events.json"
INCIDENT_FILE = "../output/incidents.json"
GRAPH_FILE = "../output/attack_graph.json"
OUTPUT_FILE = "../output/dashboard_data.json"


# ============================================================
# LOAD JSONL EVENTS
# ============================================================

def load_events():

    if not os.path.exists(EVENT_FILE):
        return []

    events = []

    with open(
        EVENT_FILE,
        "r",
        encoding="utf-8"
    ) as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            try:
                events.append(
                    json.loads(line)
                )
            except:
                pass

    return events


# ============================================================
# LOAD JSON
# ============================================================

def load_json(filename):

    if not os.path.exists(filename):
        return {}

    with open(
        filename,
        "r",
        encoding="utf-8"
    ) as f:

        return json.load(f)


# ============================================================
# BUILD DASHBOARD DATA
# ============================================================

def build_dashboard():

    events = load_events()

    incidents = load_json(
        INCIDENT_FILE
    )

    graph = load_json(
        GRAPH_FILE
    )


    # --------------------------------------------------------
    # Threat statistics
    # --------------------------------------------------------

    threat_counts = {}

    for event in events:

        event_type = event.get(
            "type",
            "UNKNOWN"
        )

        if event_type == "BENIGN":
            continue

        threat_counts[event_type] = (
            threat_counts.get(
                event_type,
                0
            ) + 1
        )


    # --------------------------------------------------------
    # Severity statistics
    # --------------------------------------------------------

    severity_counts = {}

    for event in events:

        severity = event.get(
            "severity",
            "UNKNOWN"
        )

        severity_counts[severity] = (
            severity_counts.get(
                severity,
                0
            ) + 1
        )


    # --------------------------------------------------------
    # Timeline
    # --------------------------------------------------------

    timeline = []

    for event in events:

        if event.get("type") == "BENIGN":
            continue

        evidence = event.get(
            "evidence",
            {}
        )


        timeline.append({

            "timestamp":
                event.get(
                    "timestamp",
                    ""
                ),

            "event_id":
                event.get(
                    "event_id",
                    ""
                ),

            "source":
                event.get(
                    "src",
                    ""
                ),

            "destination":
                event.get(
                    "dst",
                    ""
                ),

            "port":
                evidence.get(
                    "dst_port"
                ),

            "type":
                event.get(
                    "type",
                    "UNKNOWN"
                ),

            "confidence":
                event.get(
                    "confidence",
                    0
                ),

            "severity":
                event.get(
                    "severity",
                    "UNKNOWN"
                )
        })


    # --------------------------------------------------------
    # Sort timeline
    # --------------------------------------------------------

    timeline.sort(
        key=lambda x: x["timestamp"]
    )


    # --------------------------------------------------------
    # Dashboard object
    # --------------------------------------------------------

    dashboard = {

        "summary": {

            "total_events":
                len(events),

            "suspicious_events":
                len(timeline),

            "incidents":
                len(incidents),

            "threat_types":
                threat_counts,

            "severity":
                severity_counts
        },


        "incidents":
            incidents,


        "timeline":
            timeline,


        "attack_graph":
            graph

    }


    return dashboard


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 65)
    print(" DASHBOARD DATA BUILDER")
    print("=" * 65)


    dashboard = build_dashboard()


    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            dashboard,
            f,
            indent=2
        )


    print()
    print(
        "Total events:",
        dashboard["summary"]["total_events"]
    )

    print(
        "Suspicious events:",
        dashboard["summary"]["suspicious_events"]
    )

    print(
        "Incidents:",
        dashboard["summary"]["incidents"]
    )


    print()
    print(
        "Threat types:",
        dashboard["summary"]["threat_types"]
    )


    print()
    print("Saved:")
    print(
        f"  {OUTPUT_FILE}"
    )


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    main()