# AI-Powered Cyber Incident Reconstruction

AI-powered passive network monitoring and cyber incident reconstruction system for detecting suspicious network behavior from one-directional IP traffic.

## Overview

The system follows an evidence-first approach:

Traffic ? Flow Extraction ? ML Detection ? Event Generation ? Evidence Correlation ? Incident Reconstruction ? Attack Graph ? Dashboard

The system is designed for environments where traffic can only be observed passively and no active interaction with the source or destination is allowed.

## Key Components

- TShark-based passive packet metadata capture
- Bidirectional flow aggregation
- Random Forest known-threat classification
- Isolation Forest anomaly detection
- DBSCAN unknown-pattern discovery
- Evidence-based event generation
- Time/host/behavior correlation
- Incident reconstruction
- Attack graph generation
- Streamlit dashboard

## Project Structure

SIH-26/
+-- data/
+-- models/
+-- src/
¦   +-- capture/
¦   +-- ml/
¦   +-- incident/
¦   +-- dashboard/
¦   +-- demo/
+-- output/
+-- tests/

## ML Features

The current model uses 22 flow-level network features covering:

- Flow duration
- Packet and byte counts
- Packet and byte rates
- Packet-size statistics
- Inter-arrival timing
- TCP flags
- Header lengths
- Directional traffic ratio

## Running

Install dependencies:

    pip install -r requirements.txt

Verify TShark:

    & "C:\Program Files\Wireshark\tshark.exe" --version

Preprocess:

    python src\ml\preprocess.py

Train Random Forest:

    python src\ml\train_rf.py

Train anomaly detector:

    python src\ml\train_anomaly.py

Run unknown-pattern demonstration:

    python src\demo\unknown_demo.py

Convert unknown patterns to events:

    python src\ml\unknown_to_event.py

Run incident correlation:

    python src\incident\corelation_engine.py

Generate incident reconstruction:

    python src\incident\incident_reconstruction.py

Build dashboard data:

    python src\dashboard\dashboard_data.py

Start dashboard:

    streamlit run src\dashboard\dashboard.py

## Passive Monitoring

The system does not perform active probing, packet injection, handshake completion, remote queries, exploitation, or mitigation.

It operates using passively observed network metadata.

## Limitations

Unknown behavioral patterns are not automatically classified as malicious and require further validation.

CICIDS is a benchmark dataset and does not represent every real-world network environment.

Production deployment would require stronger time-based validation and continuous pipeline orchestration.

## Technology

Python, TShark, Pandas, NumPy, Scikit-learn, Joblib, and Streamlit.
