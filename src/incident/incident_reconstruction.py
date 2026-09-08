import json
import os
from datetime import datetime, timezone


EVENT_FILE = "../output/events.json"
INCIDENT_FILE = "../output/incidents.json"
REPORT_FILE = "../output/incident_report.json"


# ============================================================
# LOAD JSON LINES EVENTS
# ============================================================

def load_events():

    if not os.path.exists(EVENT_FILE):
        print("events.json not found.")
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
# LOAD INCIDENTS
# ============================================================

def load_incidents():

    if not os.path.exists(INCIDENT_FILE):
        print("incidents.json not found.")
        return []

    try:

        with open(
            INCIDENT_FILE,
            "r",
            encoding="utf-8"
        ) as f:

            data = json.load(f)

        if isinstance(data, list):
            return data

        return []

    except Exception as e:

        print(
            f"Could not load incidents.json: {e}"
        )

        return []


# ============================================================
# TIMESTAMP
# ============================================================

def timestamp_value(event):

    timestamp = event.get(
        "timestamp",
        ""
    )

    if not timestamp:
        return ""

    return timestamp


# ============================================================
# BUILD TIMELINE
# ============================================================

def build_timeline(incident):

    incident_events = incident.get(
        "events",
        []
    )

    timeline = []


    for event in incident_events:

        # ----------------------------------------------------
        # Full event dictionary
        # ----------------------------------------------------

        if isinstance(event, dict):

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

                "type":
                    event.get(
                        "type",
                        "UNKNOWN"
                    ),

                "source":
                    event.get(
                        "src",
                        event.get(
                            "source",
                            "UNKNOWN"
                        )
                    ),

                "destination":
                    event.get(
                        "dst",
                        event.get(
                            "destination",
                            "UNKNOWN"
                        )
                    ),

                "src_port":
                    event.get(
                        "src_port",
                        0
                    ),

                "dst_port":
                    event.get(
                        "dst_port",
                        0
                    ),

                "protocol":
                    event.get(
                        "protocol",
                        "UNKNOWN"
                    ),

                "confidence":
                    event.get(
                        "confidence"
                    ),

                "severity":
                    event.get(
                        "severity",
                        "MEDIUM"
                    ),

                "pattern_id":
                    event.get(
                        "pattern_id"
                    )
            })


    timeline.sort(
        key=lambda x: x.get(
            "timestamp",
            ""
        )
    )

    return timeline


# ============================================================
# BEHAVIOR SUMMARY
# ============================================================

def build_behavior_summary(timeline):

    summary = {}

    for event in timeline:

        event_type = event.get(
            "type",
            "UNKNOWN"
        )

        summary[event_type] = (
            summary.get(
                event_type,
                0
            ) + 1
        )

    return summary


# ============================================================
# RECONNAISSANCE RECONSTRUCTION
# ============================================================

def reconstruct_reconnaissance(
    incident,
    timeline
):

    source = incident.get(
        "source",
        "UNKNOWN"
    )

    event_count = incident.get(
        "event_count",
        len(timeline)
    )

    unique_ports = incident.get(
        "unique_ports",
        0
    )

    unique_destinations = incident.get(
        "unique_destinations",
        0
    )


    observations = [

        f"{event_count} suspicious "
        f"network observations were correlated.",

        f"{unique_ports} unique destination "
        f"ports were observed.",

        f"{unique_destinations} unique "
        f"destination(s) were observed."
    ]


    inference = (
        "The observed connection pattern "
        "is consistent with reconnaissance "
        "or port-scanning activity."
    )


    limitation = (
        "Behavioral network evidence indicates "
        "suspicious activity but does not by "
        "itself prove attacker intent."
    )


    summary = (
        f"Source host {source} generated "
        f"{event_count} suspicious network "
        f"observations involving "
        f"{unique_ports} unique ports and "
        f"{unique_destinations} unique "
        f"destination(s) within the "
        f"correlation window."
    )


    return {

        "classification":
            "RECONNAISSANCE",

        "summary":
            summary,

        "observations":
            observations,

        "inference":
            inference,

        "limitation":
            limitation
    }


# ============================================================
# UNKNOWN BEHAVIOR RECONSTRUCTION
# ============================================================

def reconstruct_unknown(
    incident,
    timeline
):

    pattern_id = incident.get(
        "pattern_id",
        "UNKNOWN"
    )

    observations_count = incident.get(
        "observations",
        0
    )

    status = incident.get(
        "pattern_status",
        "NEW"
    )

    detection_method = incident.get(
        "detection_method",
        "IsolationForest + DBSCAN"
    )


    observations = [

        f"{observations_count} anomalous "
        f"observations contributed to the "
        f"discovered behavioral pattern.",

        f"Pattern {pattern_id} was created "
        f"using {detection_method}.",

        f"Pattern status is {status}."
    ]


    inference = (
        "A previously unseen behavioral "
        "pattern was detected among anomalous "
        "network observations. The pattern "
        "may represent previously unrecognized "
        "activity and requires analyst validation."
    )


    limitation = (
        "The unknown pattern is not automatically "
        "classified as malicious. Additional "
        "evidence or analyst validation is required."
    )


    summary = (
        f"Pattern {pattern_id} contains "
        f"{observations_count} anomalous "
        f"observations grouped into a recurring "
        f"behavioral pattern."
    )


    return {

        "classification":
            "UNKNOWN_BEHAVIOR",

        "pattern_id":
            pattern_id,

        "status":
            status,

        "summary":
            summary,

        "observations":
            observations,

        "inference":
            inference,

        "limitation":
            limitation
    }


# ============================================================
# MULTI-STAGE RECONSTRUCTION
# ============================================================

def reconstruct_multistage(
    incident,
    timeline
):

    source = incident.get(
        "source",
        "UNKNOWN"
    )

    behaviors = incident.get(
        "behaviors",
        {}
    )

    observations = [

        f"{len(timeline)} suspicious "
        f"network observations were correlated.",

        f"Observed behaviors: {behaviors}"
    ]


    inference = (
        "Multiple suspicious behaviors were "
        "observed from the same source. Their "
        "temporal relationship may indicate "
        "related stages of a cyber incident."
    )


    limitation = (
        "Correlation between behaviors does not "
        "prove that they belong to the same attack. "
        "Additional evidence is required."
    )


    summary = (
        f"Source host {source} generated "
        f"multiple suspicious behavioral stages "
        f"that were correlated as a possible "
        f"multi-stage incident."
    )


    return {

        "classification":
            "MULTI_STAGE_ACTIVITY",

        "summary":
            summary,

        "observations":
            observations,

        "inference":
            inference,

        "limitation":
            limitation
    }


# ============================================================
# GENERIC RECONSTRUCTION
# ============================================================

def reconstruct_generic(
    incident,
    timeline
):

    incident_type = incident.get(
        "type",
        "UNKNOWN"
    )

    return {

        "classification":
            incident_type,

        "summary":
            f"Incident classified as "
            f"{incident_type} based on "
            f"correlated network evidence.",

        "observations":
            [
                f"{len(timeline)} event(s) "
                f"associated with the incident."
            ],

        "inference":
            "The observed network behavior "
            "is considered suspicious based "
            "on the detection and correlation "
            "pipeline.",

        "limitation":
            "Network metadata alone may not "
            "establish attacker intent."
    }


# ============================================================
# BUILD REPORT
# ============================================================

def build_report(
    incidents,
    events
):

    reports = []


    for incident in incidents:

        timeline = build_timeline(
            incident
        )

        behavior_summary = (
            build_behavior_summary(
                timeline
            )
        )


        incident_type = incident.get(
            "type",
            "UNKNOWN"
        )


        # ----------------------------------------------------
        # Select reconstruction method
        # ----------------------------------------------------

        if incident_type == "RECONNAISSANCE":

            reconstruction = (
                reconstruct_reconnaissance(
                    incident,
                    timeline
                )
            )

        elif incident_type == "UNKNOWN_BEHAVIOR":

            reconstruction = (
                reconstruct_unknown(
                    incident,
                    timeline
                )
            )

        elif incident_type == "MULTI_STAGE_ACTIVITY":

            reconstruction = (
                reconstruct_multistage(
                    incident,
                    timeline
                )
            )

        else:

            reconstruction = (
                reconstruct_generic(
                    incident,
                    timeline
                )
            )


        # ----------------------------------------------------
        # Report
        # ----------------------------------------------------

        report = {

            "incident_id":
                incident.get(
                    "incident_id",
                    "UNKNOWN"
                ),

            "type":
                incident_type,

            "source":
                incident.get(
                    "source",
                    "UNKNOWN"
                ),

            "destination":
                incident.get(
                    "destination",
                    "UNKNOWN"
                ),

            "severity":
                incident.get(
                    "severity",
                    "MEDIUM"
                ),

            "event_count":
                incident.get(
                    "event_count",
                    len(timeline)
                ),

            "behavior_summary":
                behavior_summary,

            "timeline":
                timeline,

            "reconstruction":
                reconstruction,

            "evidence":
                incident.get(
                    "evidence",
                    {}
                )
        }


        reports.append(
            report
        )


    return reports


# ============================================================
# SAVE REPORT
# ============================================================

def save_report(reports):

    with open(
        REPORT_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            reports,
            f,
            indent=2
        )


# ============================================================
# DISPLAY
# ============================================================

def display_reports(reports):

    print()
    print("=" * 65)
    print(" RECONSTRUCTED INCIDENTS")
    print("=" * 65)


    for report in reports:

        reconstruction = report.get(
            "reconstruction",
            {}
        )


        print()
        print(
            f"Incident: "
            f"{report.get('incident_id')}"
        )

        print(
            f"Type: "
            f"{report.get('type')}"
        )

        print(
            f"Source: "
            f"{report.get('source')}"
        )

        print(
            f"Severity: "
            f"{report.get('severity')}"
        )

        print(
            f"Events: "
            f"{report.get('event_count')}"
        )


        if report.get("type") == "UNKNOWN_BEHAVIOR":

            print(
                f"Pattern: "
                f"{reconstruction.get('pattern_id')}"
            )

            print(
                f"Status: "
                f"{reconstruction.get('status')}"
            )


        print()
        print("Reconstruction:")

        print(
            reconstruction.get(
                "summary",
                ""
            )
        )


        print()
        print("Observed Evidence:")

        for observation in reconstruction.get(
            "observations",
            []
        ):

            print(
                f"  • {observation}"
            )


        print()
        print("Inference:")

        print(
            reconstruction.get(
                "inference",
                ""
            )
        )


        print()
        print("Limitation:")

        print(
            reconstruction.get(
                "limitation",
                ""
            )
        )


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 65)
    print(" INCIDENT RECONSTRUCTION ENGINE")
    print("=" * 65)


    events = load_events()

    incidents = load_incidents()


    print()
    print(
        f"Events loaded: {len(events)}"
    )

    print(
        f"Incidents loaded: {len(incidents)}"
    )


    if not incidents:

        print()
        print(
            "No incidents available "
            "for reconstruction."
        )

        save_report([])

        return


    reports = build_report(
        incidents,
        events
    )


    save_report(
        reports
    )


    display_reports(
        reports
    )


    print()
    print("=" * 65)
    print(
        f"Reports generated: "
        f"{len(reports)}"
    )

    print(
        f"Saved: {REPORT_FILE}"
    )

    print("=" * 65)


if __name__ == "__main__":

    main()