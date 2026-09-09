import json
from datetime import datetime
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

EVENT_FILE = PROJECT_ROOT / "output" / "events.json"
INCIDENT_FILE = PROJECT_ROOT / "output" / "incidents.json"
GRAPH_FILE = PROJECT_ROOT / "output" / "attack_graph.json"


# ============================================================
# LOAD EVENTS
# ============================================================

def load_events():
    events = []

    try:
        with open(EVENT_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    print("Warning: Skipping invalid JSON line.")

    except FileNotFoundError:
        return []

    return events


# ============================================================
# TIMESTAMP PARSER
# ============================================================

def parse_timestamp(value):
    if not value:
        return None

    try:
        value = value.replace("Z", "+00:00")
        return datetime.fromisoformat(value)
    except Exception:
        return None


# ============================================================
# RECONNAISSANCE DETECTION
# ============================================================

def detect_recon(events):
    incidents = []

    suspicious = [
        event
        for event in events
        if event.get("type") not in ("BENIGN", "UNKNOWN_BEHAVIOR")
    ]

    by_source = defaultdict(list)

    for event in suspicious:
        source = event.get("src", "UNKNOWN")
        if source != "UNKNOWN":
            by_source[source].append(event)

    for source, source_events in by_source.items():
        source_events.sort(
            key=lambda event: parse_timestamp(event.get("timestamp")) or datetime.min
        )

        # ----------------------------------------------------
        # Sliding temporal window (60s)
        # ----------------------------------------------------
        for i in range(len(source_events)):
            start_time = parse_timestamp(source_events[i].get("timestamp"))
            if start_time is None:
                continue

            window = []
            for j in range(i, len(source_events)):
                current_time = parse_timestamp(source_events[j].get("timestamp"))
                if current_time is None:
                    continue

                elapsed = (current_time - start_time).total_seconds()
                if elapsed <= 60:
                    window.append(source_events[j])
                else:
                    break

            if len(window) < 3:
                continue

            unique_ports = set()
            unique_destinations = set()

            for event in window:
                dst_port = event.get("dst_port")
                if dst_port is not None:
                    try:
                        unique_ports.add(int(dst_port))
                    except Exception:
                        pass

                destination = event.get("dst")
                if destination and destination != "UNKNOWN":
                    unique_destinations.add(destination)

            # ------------------------------------------------
            # Reconnaissance condition
            # ------------------------------------------------
            if len(unique_ports) >= 5 or len(unique_destinations) >= 3:
                incident = {
                    "incident_id": f"INC-RECON-{source.replace('.', '-')}",
                    "type": "RECONNAISSANCE",
                    "source": source,
                    "severity": "HIGH",
                    "events": window,
                    "event_count": len(window),
                    "unique_ports": len(unique_ports),
                    "unique_destinations": len(unique_destinations),
                    "evidence": {
                        "event_count": len(window),
                        "unique_ports": sorted(list(unique_ports)),
                        "unique_destinations": sorted(list(unique_destinations)),
                        "detection_method": "Temporal and behavioral correlation of suspicious network events"
                    }
                }
                incidents.append(incident)
                break

    return incidents


# ============================================================
# UNKNOWN BEHAVIOR
# ============================================================

def detect_unknown_patterns(events):
    incidents = []

    for event in events:
        if event.get("type") != "UNKNOWN_BEHAVIOR":
            continue

        evidence = event.get("evidence", {})
        pattern_id = event.get("pattern_id", "UNKNOWN")

        incident = {
            "incident_id": f"INC-UNKNOWN-{pattern_id}",
            "type": "UNKNOWN_BEHAVIOR",
            "source": event.get("src", "UNKNOWN"),
            "severity": event.get("severity", "MEDIUM"),
            "events": [event],
            "event_count": 1,
            "pattern_id": pattern_id,
            "observations": evidence.get("observation_count", 0),
            "status": evidence.get("pattern_status", "NEW"),
            "evidence": evidence
        }
        incidents.append(incident)

    return incidents


# ============================================================
# MULTI-STAGE DETECTION
# ============================================================

def detect_multistage(events):
    incidents = []
    by_source = defaultdict(list)

    for event in events:
        event_type = event.get("type")
        if event_type in ("BENIGN", "UNKNOWN_BEHAVIOR"):
            continue

        source = event.get("src", "UNKNOWN")
        if source != "UNKNOWN":
            by_source[source].append(event)

    for source, source_events in by_source.items():
        behaviors = defaultdict(list)

        for event in source_events:
            event_type = event.get("type", "UNKNOWN")
            behaviors[event_type].append(event)

        # Require at least 2 observations of EACH behavior
        repeated_behaviors = {
            behavior: event_list
            for behavior, event_list in behaviors.items()
            if len(event_list) >= 2
        }

        if len(repeated_behaviors) < 2:
            continue

        all_events = []
        for event_list in repeated_behaviors.values():
            all_events.extend(event_list)

        all_events.sort(
            key=lambda event: parse_timestamp(event.get("timestamp")) or datetime.min
        )

        incident = {
            "incident_id": f"INC-MULTI-{source.replace('.', '-')}",
            "type": "MULTI_STAGE_ACTIVITY",
            "source": source,
            "severity": "HIGH",
            "events": all_events,
            "event_count": len(all_events),
            "behaviors": sorted(list(repeated_behaviors.keys())),
            "evidence": {
                "distinct_behaviors": sorted(list(repeated_behaviors.keys())),
                "event_count": len(all_events),
                "detection_method": "Cross-behavior temporal correlation with repeated evidence"
            }
        }
        incidents.append(incident)

    return incidents


# ============================================================
# DEDUPLICATION
# ============================================================

def deduplicate_incidents(incidents):
    unique = {}

    for incident in incidents:
        key = (
            incident.get("type"),
            incident.get("source"),
            incident.get("pattern_id")
        )
        unique[key] = incident

    return list(unique.values())


# ============================================================
# ATTACK GRAPH
# ============================================================

def build_attack_graph(events):
    nodes = {}
    edges = []

    for event in events:
        source = event.get("src", "UNKNOWN")
        destination = event.get("dst", "UNKNOWN")
        behavior = event.get("type", "UNKNOWN")

        if source not in nodes:
            nodes[source] = {
                "id": source,
                "type": "SOURCE"
            }

        if destination not in nodes:
            nodes[destination] = {
                "id": destination,
                "type": "DESTINATION"
            }

        confidence = event.get("confidence")

        edges.append({
            "source": source,
            "target": destination,
            "type": behavior,
            "behavior": behavior,
            "confidence": confidence,
            "timestamp": event.get("timestamp")
        })

    return {
        "nodes": list(nodes.values()),
        "edges": edges
    }


# ============================================================
# PRINT INCIDENT
# ============================================================

def print_incident(incident):
    print(f"Incident: {incident.get('incident_id')}")
    print(f"Type: {incident.get('type')}")
    print(f"Source: {incident.get('source')}")
    print(f"Severity: {incident.get('severity')}")
    print(f"Events: {incident.get('event_count')}")

    if incident.get("type") == "RECONNAISSANCE":
        print(f"Unique ports: {incident.get('unique_ports')}")
        print(f"Unique destinations: {incident.get('unique_destinations')}")

    elif incident.get("type") == "UNKNOWN_BEHAVIOR":
        print(f"Pattern: {incident.get('pattern_id')}")
        print(f"Observations: {incident.get('observations')}")
        print(f"Status: {incident.get('status')}")

    elif incident.get("type") == "MULTI_STAGE_ACTIVITY":
        behaviors = incident.get("behaviors", [])
        print(f"Behaviors: {', '.join(behaviors)}")

    print()


# ============================================================
# STREAMING UPDATE CYCLE
# ============================================================

def run_correlation_cycle():
    """Triggered by flow_engine.py on every 5-second tumbling window."""
    events = load_events()
    if not events:
        return []

    incidents = []
    incidents.extend(detect_recon(events))
    incidents.extend(detect_unknown_patterns(events))
    incidents.extend(detect_multistage(events))
    incidents = deduplicate_incidents(incidents)

    with open(INCIDENT_FILE, "w", encoding="utf-8") as f:
        json.dump(incidents, f, indent=2)

    graph = build_attack_graph(events)
    with open(GRAPH_FILE, "w", encoding="utf-8") as f:
        json.dump(graph, f, indent=2)

    return incidents


# ============================================================
# ENTRY POINT
# ============================================================

def main():
    print("=" * 65)
    print(" CYBER INCIDENT CORRELATION ENGINE")
    print("=" * 65)
    print()

    events = load_events()
    print(f"Events loaded: {len(events)}\n")

    if not events:
        print("No events found in output/events.json.")
        return

    distribution = defaultdict(int)
    for event in events:
        distribution[event.get("type", "UNKNOWN")] += 1

    print("Event distribution:")
    for event_type in sorted(distribution.keys()):
        print(f"  {event_type}: {distribution[event_type]}")
    print()

    incidents = run_correlation_cycle()

    print(f"Incidents detected: {len(incidents)}\n")
    for incident in incidents:
        print_incident(incident)

    print(f"Saved: {INCIDENT_FILE}")
    print(f"Saved: {GRAPH_FILE}")
    print("=" * 65)


if __name__ == "__main__":
    main()