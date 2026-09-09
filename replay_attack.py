import json
import os
from collections import defaultdict, Counter
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

EVENT_FILE = PROJECT_ROOT / "output" / "events.json"

# Events must occur within this time window
CORRELATION_WINDOW = 60


# ============================================================
# LOAD EVENTS
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

            except json.JSONDecodeError:
                continue

    return events


# ============================================================
# TIMESTAMP PARSER
# ============================================================

def parse_timestamp(timestamp):

    try:

        if timestamp.endswith("Z"):
            timestamp = (
                timestamp[:-1]
                + "+00:00"
            )

        return datetime.fromisoformat(
            timestamp
        )

    except Exception:

        return datetime.min.replace(
            tzinfo=timezone.utc
        )


# ============================================================
# PORT-SCAN / RECON DETECTION
# ============================================================

def detect_recon(events):

    by_source = defaultdict(list)


    # --------------------------------------------------------
    # Group suspicious events by source
    # --------------------------------------------------------

    for event in events:

        event_type = event.get("type")

        # Ignore only benign traffic.
        # PORT_SCAN must be included.
        if event_type == "BENIGN":
            continue

        src = event.get("src")

        if src:
            by_source[src].append(event)


    incidents = []


    # ========================================================
    # Analyze each source
    # ========================================================

    for src, source_events in by_source.items():

        if len(source_events) < 3:
            continue


        # Chronological order
        source_events.sort(
            key=lambda x: parse_timestamp(
                x.get("timestamp", "")
            )
        )


        # ----------------------------------------------------
        # Sliding correlation window
        # ----------------------------------------------------

        for i in range(
            len(source_events)
        ):

            window_events = []

            start_time = parse_timestamp(
                source_events[i].get(
                    "timestamp",
                    ""
                )
            )


            for event in source_events[i:]:

                event_time = parse_timestamp(
                    event.get(
                        "timestamp",
                        ""
                    )
                )

                difference = (
                    event_time - start_time
                ).total_seconds()


                if difference <= CORRELATION_WINDOW:

                    window_events.append(
                        event
                    )

                else:

                    break


            if len(window_events) < 3:
                continue


            # ------------------------------------------------
            # Extract destinations and ports
            # ------------------------------------------------

            destinations = set()
            ports = set()


            for event in window_events:

                dst = event.get("dst")

                if dst:
                    destinations.add(dst)


                evidence = event.get(
                    "evidence",
                    {}
                )

                dst_port = evidence.get(
                    "dst_port"
                )


                # Fallback if dst_port exists
                # directly in the event
                if dst_port is None:

                    dst_port = event.get(
                        "dst_port"
                    )


                if dst_port is not None:

                    ports.add(
                        str(dst_port)
                    )


            # ------------------------------------------------
            # Reconnaissance rule
            # ------------------------------------------------

            if (
                len(ports) >= 5
                or len(destinations) >= 3
            ):

                incidents.append({

                    "incident_id":
                        f"INC-{src.replace('.', '-')}",

                    "type":
                        "RECONNAISSANCE",

                    "source":
                        src,

                    "first_seen":
                        window_events[0][
                            "timestamp"
                        ],

                    "last_seen":
                        window_events[-1][
                            "timestamp"
                        ],

                    "events":
                        [
                            e["event_id"]
                            for e in window_events
                        ],

                    "evidence": {

                        "event_count":
                            len(window_events),

                        "unique_destinations":
                            len(destinations),

                        "unique_ports":
                            len(ports),

                        "detection_reason":
                            "Multiple suspicious connections to multiple ports or destinations within correlation window"
                    },

                    "severity":
                        "HIGH"
                })

                # Only one recon incident per source
                break


    return incidents


# ============================================================
# GENERAL EVENT CORRELATION
# ============================================================

def correlate(events):

    incidents = []

    by_source = defaultdict(list)

    # --------------------------------------------------------
    # Group suspicious events by source
    # --------------------------------------------------------

    for event in events:

        event_type = event.get("type")

        if event_type == "BENIGN":
            continue

        src = event.get("src")

        if src:
            by_source[src].append(event)


    # ========================================================
    # Analyze each source
    # ========================================================

    for src, source_events in by_source.items():

        if len(source_events) < 2:
            continue


        # ----------------------------------------------------
        # Sort chronologically
        # ----------------------------------------------------

        source_events.sort(
            key=lambda x: parse_timestamp(
                x.get("timestamp", "")
            )
        )


        # ----------------------------------------------------
        # Examine correlation windows
        # ----------------------------------------------------

        for i in range(len(source_events)):

            start_time = parse_timestamp(
                source_events[i].get(
                    "timestamp",
                    ""
                )
            )

            window_events = []


            for event in source_events[i:]:

                event_time = parse_timestamp(
                    event.get(
                        "timestamp",
                        ""
                    )
                )

                elapsed = (
                    event_time - start_time
                ).total_seconds()


                if elapsed <= CORRELATION_WINDOW:

                    window_events.append(event)

                else:

                    break


            if len(window_events) < 2:
                continue


            # =================================================
            # COUNT EACH BEHAVIOR
            # =================================================

            type_counts = Counter()

            for event in window_events:

                event_type = event.get(
                    "type"
                )

                if (
                    event_type
                    and event_type != "BENIGN"
                ):

                    type_counts[event_type] += 1


            # =================================================
            # ONLY ACCEPT REPEATED BEHAVIORS
            # =================================================

            repeated_types = []

            for event_type, count in type_counts.items():

                # A stage must have at least 2
                # independent observations.

                if count >= 2:

                    repeated_types.append(
                        event_type
                    )


            # =================================================
            # MULTI-STAGE ATTACK
            # =================================================

            if len(repeated_types) >= 2:

                incidents.append({

                    "incident_id":
                        f"INC-{src.replace('.', '-')}-CHAIN",

                    "type":
                        "MULTI_STAGE_ACTIVITY",

                    "source":
                        src,

                    "attack_chain":
                        repeated_types,

                    "events":
                        [
                            e["event_id"]
                            for e in window_events
                            if e.get("type")
                            in repeated_types
                        ],

                    "first_seen":
                        window_events[0][
                            "timestamp"
                        ],

                    "last_seen":
                        window_events[-1][
                            "timestamp"
                        ],

                    "behavior_counts":
                        {
                            k: v
                            for k, v
                            in type_counts.items()
                        },

                    "severity":
                        "CRITICAL"
                })

                break


    return incidents

# ============================================================
# ATTACK GRAPH
# ============================================================

def build_attack_graph(events):

    nodes = []
    edges = []

    seen_nodes = set()


    for event in events:

        src = event.get("src")
        dst = event.get("dst")


        if not src or not dst:
            continue


        # ----------------------------------------------------
        # Source node
        # ----------------------------------------------------

        if src not in seen_nodes:

            nodes.append({

                "id":
                    src,

                "type":
                    "HOST"

            })

            seen_nodes.add(src)


        # ----------------------------------------------------
        # Destination node
        # ----------------------------------------------------

        if dst not in seen_nodes:

            nodes.append({

                "id":
                    dst,

                "type":
                    "DESTINATION"

            })

            seen_nodes.add(dst)


        # ----------------------------------------------------
        # Edge
        # ----------------------------------------------------

        edges.append({

            "source":
                src,

            "target":
                dst,

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

            "timestamp":
                event.get(
                    "timestamp",
                    ""
                )
        })


    return {

        "nodes":
            nodes,

        "edges":
            edges

    }


# ============================================================
# SAVE INCIDENTS
# ============================================================

def save_incidents(incidents):
    with open(
            PROJECT_ROOT / "output" / "incidents.json",
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            incidents,
            f,
            indent=2
        )


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 65)
    print(" INCIDENT CORRELATION ENGINE")
    print("=" * 65)


    # --------------------------------------------------------
    # Load events
    # --------------------------------------------------------

    events = load_events()

    print()
    print(
        "Events loaded:",
        len(events)
    )


    if not events:

        print()
        print("No events found.")
        print("Run the detector first.")

        return


    # --------------------------------------------------------
    # Reconnaissance
    # --------------------------------------------------------

    recon = detect_recon(
        events
    )


    # --------------------------------------------------------
    # Multi-stage correlation
    # --------------------------------------------------------

    chains = correlate(
        events
    )


    # --------------------------------------------------------
    # Combine
    # --------------------------------------------------------

    incidents = (
        recon
        + chains
    )


    # --------------------------------------------------------
    # Attack graph
    # --------------------------------------------------------

    graph = build_attack_graph(
        events
    )


    # --------------------------------------------------------
    # Save incidents
    # --------------------------------------------------------

    save_incidents(
        incidents
    )


    # --------------------------------------------------------
    # Save graph
    # --------------------------------------------------------

    with open(
            PROJECT_ROOT / "output" / "attack_graph.json",
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            graph,
            f,
            indent=2
        )


    # ========================================================
    # DISPLAY
    # ========================================================

    print()
    print("=" * 65)

    print(
        "INCIDENTS:",
        len(incidents)
    )

    print("=" * 65)


    for incident in incidents:

        print()

        print(
            "Incident:",
            incident["incident_id"]
        )

        print(
            "Type:",
            incident["type"]
        )

        print(
            "Source:",
            incident["source"]
        )

        print(
            "Severity:",
            incident["severity"]
        )


        if "attack_chain" in incident:

            print(
                "Attack chain:",
                " → ".join(
                    incident["attack_chain"]
                )
            )


        if "behavior_counts" in incident:

            print(
                "Behavior counts:",
                incident[
                    "behavior_counts"
                ]
            )


        if "evidence" in incident:

            print(
                "Evidence:",
                incident["evidence"]
            )


        print(
            "Events:",
            len(
                incident["events"]
            )
        )


    print()
    print("Saved:")
    print("  incidents.json")
    print("  attack_graph.json")


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    main()