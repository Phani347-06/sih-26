import streamlit as st
import json
import os
import pandas as pd


# ============================================================
# CONFIG
# ============================================================

DATA_FILE = "../output/dashboard_data.json"


# ============================================================
# PAGE
# ============================================================

st.set_page_config(
    page_title="Cyber Incident Reconstruction",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# LOAD DATA
# ============================================================

@st.cache_data
def load_data():

    if not os.path.exists(DATA_FILE):
        return None

    with open(
        DATA_FILE,
        "r",
        encoding="utf-8"
    ) as f:

        return json.load(f)


data = load_data()


if data is None:

    st.error(
        "dashboard_data.json not found."
    )

    st.stop()


summary = data["summary"]
incidents = data["incidents"]
timeline = data["timeline"]
graph = data["attack_graph"]


# ============================================================
# TITLE
# ============================================================

st.title(
    "🛡️ Cyber Incident Reconstruction"
)

st.caption(
    "AI-powered passive network threat detection and "
    "evidence-based incident reconstruction"
)


# ============================================================
# SUMMARY CARDS
# ============================================================

col1, col2, col3, col4 = st.columns(4)


with col1:

    st.metric(
        "Total Events",
        summary["total_events"]
    )


with col2:

    st.metric(
        "Suspicious Events",
        summary["suspicious_events"]
    )


with col3:

    st.metric(
        "Incidents",
        summary["incidents"]
    )


with col4:

    severity = "NORMAL"

    if summary["severity"].get("HIGH", 0) > 0:
        severity = "HIGH"

    if summary["severity"].get("CRITICAL", 0) > 0:
        severity = "CRITICAL"

    st.metric(
        "Highest Severity",
        severity
    )


st.divider()


# ============================================================
# INCIDENT SUMMARY
# ============================================================

st.header(
    "🚨 Reconstructed Incidents"
)


if not incidents:

    st.info(
        "No incidents reconstructed."
    )

else:

    for incident in incidents:

        with st.container():

            st.subheader(
                f"{incident['type']} — "
                f"{incident['incident_id']}"
            )


            c1, c2, c3 = st.columns(3)


            with c1:

                st.write(
                    "**Source:**",
                    incident["source"]
                )


            with c2:

                st.write(
                    "**Severity:**",
                    incident["severity"]
                )


            with c3:

                st.write(
                    "**Events:**",
                    len(
                        incident["events"]
                    )
                )


            if "evidence" in incident:

                evidence = incident[
                    "evidence"
                ]

                st.write(
                    "**Evidence:**"
                )

                st.json(
                    evidence
                )


            if "attack_chain" in incident:

                st.write(
                    "**Attack Chain:**"
                )

                st.write(
                    " → ".join(
                        incident[
                            "attack_chain"
                        ]
                    )
                )


st.divider()


# ============================================================
# THREAT DISTRIBUTION
# ============================================================

st.header(
    "📊 Threat Distribution"
)


threat_data = summary[
    "threat_types"
]


if threat_data:

    threat_df = pd.DataFrame(
        {
            "Threat": list(
                threat_data.keys()
            ),

            "Count": list(
                threat_data.values()
            )
        }
    )

    st.bar_chart(
        threat_df.set_index(
            "Threat"
        )
    )


# ============================================================
# INCIDENT TIMELINE
# ============================================================

st.header(
    "⏱️ Incident Timeline"
)


if timeline:

    timeline_df = pd.DataFrame(
        timeline
    )


    # Display useful columns
    display_columns = [

        "timestamp",

        "type",

        "source",

        "destination",

        "port",

        "confidence",

        "severity"

    ]


    display_columns = [

        column

        for column in display_columns

        if column in timeline_df.columns

    ]


    st.dataframe(

        timeline_df[
            display_columns
        ],

        use_container_width=True,

        hide_index=True

    )


# ============================================================
# ATTACK GRAPH
# ============================================================

st.header(
    "🕸️ Attack Graph"
)


nodes = graph.get(
    "nodes",
    []
)

edges = graph.get(
    "edges",
    []
)


st.write(
    f"Nodes: {len(nodes)}"
)

st.write(
    f"Relationships: {len(edges)}"
)


# ------------------------------------------------------------
# Simple graph representation
# ------------------------------------------------------------

if edges:

    graph_rows = []


    for edge in edges:

        graph_rows.append({

            "Source":
                edge["source"],

            "Relationship":
                edge["type"],

            "Target":
                edge["target"],

            "Confidence":
                edge["confidence"],

            "Timestamp":
                edge.get(
                    "timestamp",
                    ""
                )

        })


    graph_df = pd.DataFrame(
        graph_rows
    )


    st.dataframe(

        graph_df,

        use_container_width=True,

        hide_index=True

    )


# ============================================================
# FORENSIC RECONSTRUCTION
# ============================================================

st.divider()

st.header(
    "🔎 Evidence-Based Reconstruction"
)


if incidents:

    incident = incidents[0]


    reconstruction = incident.get(
        "reconstruction",
        {}
    )


    # incident_reconstruction.py stores
    # reconstruction separately, so use
    # the report if available.


    report_file = "../output/incident_report.json"


    if os.path.exists(
        report_file
    ):

        with open(
            report_file,
            "r",
            encoding="utf-8"
        ) as f:

            reports = json.load(f)


        if reports:

            reconstruction = reports[0][
                "reconstruction"
            ]


    st.write(
        "**Classification:**",
        reconstruction.get(
            "classification",
            incident["type"]
        )
    )


    st.write(
        "**Summary:**"
    )

    st.info(
        reconstruction.get(
            "summary",
            "No reconstruction summary available."
        )
    )


    st.write(
        "**Observed Evidence:**"
    )

    for observation in reconstruction.get(
        "observations",
        []
    ):

        st.write(
            f"• {observation}"
        )


    st.write(
        "**Inference:**"
    )

    st.warning(
        reconstruction.get(
            "inference",
            "No inference available."
        )
    )


    st.write(
        "**Limitation:**"
    )

    st.caption(
        reconstruction.get(
            "limitation",
            "No limitation specified."
        )
    )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "Passive monitoring • No active probing • "
    "Evidence-first reconstruction"
)