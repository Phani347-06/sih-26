# IIoT security conversion plan

## Purpose and source

Convert the existing passive network incident reconstruction prototype into the two-architecture IIoT system described in `IIoT-security-from-sensor-integrity-to-incident-response.pptx` (8 slides, inspected on 2026-10-27).

The target demonstration monitors water-quality sensors, verifies telemetry and commands, detects suspicious sensor and network behavior, and reconstructs incidents from shared evidence.

This is an implementation specification. Proposed modules, interfaces, and acceptance criteria below are additions, not claims about existing capabilities. Do not replace the entire project or retrain its network classifier on sensor columns.

## 1. Requirements from the abstract

| Slide | Requirement |
| --- | --- |
| 1–2 | Two complementary architectures connected by shared timestamps, device identity, evidence, and incidents |
| 3–4 | ESP32 #1 reads pH, turbidity, and electrical conductivity; authenticates readings with HMAC-SHA-256; server verifies freshness and classifies readings; ESP32 #2 verifies commands and enforces local safety limits |
| 5–6 | Passive TShark capture, flow aggregation, Random Forest known-threat detection, Isolation Forest anomaly detection, and preserved network evidence |
| 7 | Correlate sensor findings, network events, and control responses by identity and time |
| 8 | Streamlit investigation dashboard and SQLite-backed storage |

Use HTTPS for the first implementation. MQTT over TLS is an alternative transport from the slides, not a requirement to implement both transports immediately. TLS protects transport; application sequence numbers and freshness checks provide message replay protection.

## 2. Existing code and conversion scope

| Existing component | Reuse and required work |
| --- | --- |
| `src/capture/flow_engine.py` | Reuse bidirectional flow extraction; separate capture, feature extraction, inference, and event persistence; make capture configuration portable |
| `src/capture/tshark_stream.py` | Reference for packet metadata ingestion; avoid running a second capture unnecessarily |
| `src/ml/preprocess.py`, `train_rf.py` | Preserve existing network training; publish a versioned feature contract and model metadata |
| `src/ml/train_anomaly.py` | Reuse network anomaly training and connect inference to live flows |
| `src/ml/unknown_pattern.py` | Extract reusable batch clustering; replace cluster-size-only pattern matching |
| `src/demo/unknown_demo.py` | Keep as a clearly labeled synthetic demo, separate from evaluation |
| `src/ml/unknown_to_event.py` | Migrate pattern events into the common event schema and persistent store |
| `src/incident/corelation_engine.py` | Reuse useful rules; add device identity, cross-source correlation, bounded time windows, and idempotent writes |
| `src/incident/incident_reconstruction.py` | Extend evidence-based reports to sensor verification and command outcomes |
| `src/dashboard/dashboard_data.py` | Generate compatibility exports from SQLite instead of treating JSON files as primary storage |
| `src/dashboard/dashboard.py` | Extend into the unified Streamlit dashboard required by the abstract |
| `frontend/` | Preserve the React interface as an optional client; its Vite file middleware is not the production API |

Current gaps confirmed in source:

- Live flow processing prints Random Forest predictions but does not call `create_event()` or save events.
- Isolation Forest and DBSCAN are separate offline/demo paths.
- Live duration and inter-arrival calculations use seconds; CICIDS timing features use microseconds. Other feature semantics also need verification before model reuse.
- The capture executable path and interface are hardcoded for one Windows machine.
- There is no sensor ingestion, authenticated command service, ESP32 firmware, or SQLite event store.
- React loads JSON once; scripts are manually orchestrated.
- Multi-stage correlation does not currently enforce a temporal window.

## 3. Target deployment and architecture

Run the Python services on a laptop or Linux edge gateway. ESP32 devices handle acquisition and constrained actuation. They do not run the existing scikit-learn forests.

```text
Water-quality sensors
        |
ESP32 #1: acquire, timestamp, sequence, HMAC
        |
        | HTTPS + authenticated message
        v
Edge server
  Telemetry verification -> sensor features -> sensor RF + rules
        |                                      |
        |                              control policy
        |                                      |
        |                              signed command
        |                                      v
        |                           ESP32 #2 controller
        |                           verify + local limits
        |                                      |
        |                         LED / buzzer / simulated pump
        |                                      |
        +---------------------------- command acknowledgments

Observable network packets -> TShark -> flows -> network RF / IF
                                                    |
                                          bounded anomaly batches
                                                    |
                                                  DBSCAN

Sensor findings + network findings + command outcomes
        |
Common event service -> SQLite -> correlation -> incident reports
        |
Streamlit dashboard / optional React API client
```

The capture host must actually observe traffic: use the gateway interface, a switch mirror, or a network TAP. Sharing a Wi-Fi network alone does not guarantee visibility. Encrypted payloads remain encrypted; network models use observable metadata. Sensor values reach the authorized ingestion service through authenticated application messages.

## 4. Sensor and command trust model

### Device registration

- Register each acquisition device and controller with a stable ID, role, credential reference, allowed sensors or actuators, and enabled status.
- Use distinct credentials per device and distinct telemetry and command keys. Define which acquisition device may influence which controller.
- Provision credentials outside source control. Store server secrets outside SQLite evidence records and logs.
- Track IP-to-device associations with validity intervals. An observed IP or a submitted device ID alone is not authenticated identity.

### Telemetry message contract

Define a versioned envelope containing:

```json
{
  "schema_version": 1,
  "message_type": "telemetry",
  "device_id": "sensor-01",
  "key_id": "telemetry-key-01",
  "session_id": "server-issued-session",
  "sequence": 1234,
  "timestamp": "2026-10-27T10:00:00.000Z",
  "readings": {
    "ph": 7.1,
    "turbidity_ntu": 2.4,
    "conductivity_us_cm": 450.0
  }
}
```

These values illustrate the wire format; they are not operating limits or an experimental dataset.

Use an outer transport envelope with `payload_b64` and `hmac_hex`. Compute HMAC-SHA-256 over the exact UTF-8 payload bytes decoded from `payload_b64`; never regenerate JSON before verification. Authenticate every payload field, including message type and key ID. Specify encoding and size limits, and supply a shared ESP32/Python test vector. Reject duplicate JSON keys, nonfinite values, malformed fields, and unknown schema versions.

Verification order:

1. Bound message size and parse the outer envelope safely.
2. Decode the payload, select an allowed device credential, and compare HMAC in constant time.
3. Check the device role, enabled status, message type, schema, and session binding.
4. Check UTC freshness against a configured clock-skew allowance.
5. Atomically enforce a strictly increasing sequence for the authenticated device/session.
6. Persist verification outcome and accepted telemetry transactionally.
7. Run sensor feature extraction only on accepted readings.

Use a persisted sequence or a server-issued session established over an authenticated exchange after reboot. A device cannot reset replay state by inventing a new session ID. Define reconnect, clock-loss, and server-restart behavior. Retried accepted messages return the original result and must not repeat a control action.

HMAC demonstrates possession of the device key and integrity in transit. It cannot prove physical accuracy or detect a compromised device that signs fabricated values.

### Command contract and local enforcement

Commands contain a schema version, message type, unique command ID, target controller ID, authenticated session, monotonic sequence, issue time, expiry, action, bounded parameters, policy version, and triggering evidence IDs. Authenticate the entire payload with the controller's dedicated command key.

ESP32 #2 must independently:

- Verify authenticity, target, session, sequence, expiry, and allowed action.
- Enforce configured output limits and maximum actuation duration.
- Reject duplicate execution; return a signed acknowledgment with command ID and outcome.
- Maintain a local watchdog and documented fallback behavior when communications fail.
- Preserve manual override and applicable physical interlocks.

Verification failure or insufficient evidence must not initiate a new ML-driven actuation. The fallback state is defined for the physical process; do not assume that turning a pump off is always safe. Use LEDs, buzzers, and a simulated pump or valve for the initial demonstration.

## 5. Separate sensor and network models

### Sensor model: new implementation

Create `sensor_random_forest.pkl`; retain `random_forest_model.pkl` as a network model. Their feature spaces and labels are different.

Candidate sensor features:

- Current calibrated pH, turbidity, and conductivity, with explicit units.
- Rate of change per second using actual measurement intervals.
- Rolling mean, standard deviation, deviation from a baseline, and repeated-value duration.
- Sample age and missing-sample indicators.
- Cross-sensor consistency only where supported by process knowledge.

Specify causal windows and minimum history. Never fill features with future samples. During startup or missing history, return `INSUFFICIENT_HISTORY` and apply documented rules instead of presenting a confident ML result.

Start with normal/suspicious labels where reliable labels exist. Keep verification failures separate from physical sensor anomalies. Add specific fault or attack categories only when supported by collected data.

Collect normal operation, legitimate process changes, calibration periods, disconnections, stuck readings, drift, spikes, and controlled falsification scenarios. Retain scenario provenance. Physical faults and attacks can produce similar readings, so classification alone does not establish malicious intent.

Use splits by recording session, device, and time before creating overlapping windows. Keep an untouched test set. Evaluate precision, recall, F1, confusion matrices, false alerts per operating hour, and detection delay. Do not report training accuracy as deployment performance.

### Network models: adapt and validate

- Preserve the 22-feature order through one shared schema used by training and inference.
- Specify timing units, packet-length definition, header fields, forward direction, flag semantics, standard-deviation convention, and rate calculations.
- Correct timing units without changing byte/packet rates from per-second units.
- Verify actual TShark flag encodings rather than assuming strings such as `true`.
- Compare extracted features against a reference on the same PCAP before trusting old model predictions.
- Five-second fragments differ from full-session CICIDS flows. Train and evaluate with the intended windowing strategy or document the mismatch and retrain.
- Run network RF and IF in the live service; preserve each output independently.
- Treat the current 70% known-threat threshold as an initial inherited setting to validate, not a proven operating point.
- Batch anomalies with fixed time and record-count bounds before DBSCAN. A missing cluster must not erase an individual anomaly event.
- Replace matching by cluster size with a versioned signature distance and explicit matching threshold, or retain separate pattern IDs until matching is validated.

Evaluate on representative IIoT traffic from the demonstration network. Public datasets may supplement evaluation only after checking licenses, feature compatibility, and relevance. An anomaly score is not a calibrated probability of malicious activity.

Store model version, feature schema, units, training provenance, label mapping, dependency versions, validation metrics, and thresholds beside each artifact. Loading an incompatible artifact must fail clearly.

## 6. SQLite evidence architecture

Use SQLite as the source of truth for the single-edge-host prototype. Enable foreign keys, use transactions and migrations, and bound retention. WAL mode and a serialized writer queue can support concurrent capture and API ingestion; measure contention before expanding deployment.

| Table | Minimum responsibility |
| --- | --- |
| `devices` | Device identity, role, status, credential reference, configuration |
| `device_addresses` | Device/IP associations with start/end times and provenance |
| `replay_state` | Accepted sequence and authenticated session per device/key |
| `telemetry_messages` | Receipt time, source time, payload reference/hash, verification result and reason |
| `sensor_readings` | Accepted calibrated values, units, and telemetry reference |
| `sensor_predictions` | Feature-window references, model version, result, score, rule findings |
| `flows` | Endpoints, protocol, event interval, feature schema and extracted features |
| `network_predictions` | RF label/probabilities and IF score/result per flow |
| `events` | Unified findings, origin, affected device, severity, evidence references |
| `patterns` | Behavioral signatures, clustering configuration, observations and versions |
| `commands` | Signed command reference, policy decision, expiry, delivery and acknowledgment state |
| `incidents` | Type, status, interval, severity, reconstruction and limitations |
| `incident_events` | Many-to-many incident/evidence linkage |
| `capture_files` | PCAP location, capture interval, digest, retention and access metadata |
| `audit_log` | Operator actions, device registration changes, policy and model changes |

Use UTC source timestamps plus server receipt timestamps; retain device clock quality and uncertainty. Reject or quarantine unusable timestamps instead of mixing timezone-aware and naive datetimes.

Apply stable IDs and unique constraints for telemetry, commands, flow processing, and rule outputs. Retrying a batch or restarting a worker must not duplicate incidents or commands. JSON files remain optional compatibility exports written atomically.

Optional PCAP ring buffers preserve bounded packet evidence with file digests and event references. Metadata-only capture cannot reconstruct payload evidence later. Digests detect later changes only when their reference values are trusted; a local database is not automatically tamper-proof.

## 7. Unified events and incident correlation

The shared event schema includes:

```text
event_id, schema_version, origin, event_type
occurred_at, received_at, interval_start, interval_end
device_id (nullable), identity_provenance
source_ip, destination_ip, ports, protocol (where applicable)
severity, detector_name, model_or_rule_version
score_kind, score_value (nullable)
evidence_refs, verification_reason, limitations
```

Suggested event types: `TELEMETRY_INTEGRITY_FAILED`, `TELEMETRY_REPLAY_REJECTED`, `SENSOR_ANOMALY`, `NETWORK_KNOWN_THREAT`, `NETWORK_ANOMALY`, `COMMAND_REJECTED`, `COMMAND_EXPIRED`, and `CONTROL_ACK_TIMEOUT`.

Correlation requirements:

- Resolve identity through authenticated telemetry and time-valid inventory associations; retain unresolved flows as network evidence.
- Use configurable bounded event-time windows and a policy for late arrivals.
- Combine sensor, network, and command evidence without treating temporal proximity as proof of causation.
- Preserve contributing events and the exact rule/version behind each incident.
- Avoid counting one observation repeatedly as independent supporting evidence.
- Keep rejected readings available as evidence but out of accepted-reading baselines and control decisions.

Example: a replayed message from an acquisition device is rejected; near the same time, that endpoint exhibits scanning traffic. Create a possible correlated incident containing both findings and the identity/time evidence. State that the association does not prove one caused the other.

## 8. Services, API, and dashboard

Use a small Python service layer, proposed with FastAPI, for ingestion, queries, and controller communication. FastAPI and its server would be new dependencies. Keep inference, policy, and storage logic callable without HTTP for tests and replay.

Proposed interfaces:

| Interface | Purpose |
| --- | --- |
| `POST /v1/telemetry` | Receive and verify ESP32 #1 telemetry |
| `POST /v1/controllers/commands/poll` | Authenticated controller polling with freshness and replay checks |
| `POST /v1/commands/ack` | Verify controller acknowledgments |
| `GET /v1/devices` | Device status and last accepted reading time |
| `GET /v1/readings` | Paginated readings and quality status |
| `GET /v1/events` | Filtered, paginated security findings |
| `GET /v1/incidents/{id}` | Evidence, timeline, commands, reconstruction |
| `GET /v1/health` | Service, capture, model, queue and storage health |

Authenticate devices and operators using separate mechanisms; scope credentials by role. Protect dashboard data and operator actions. Validate HTTPS certificates on devices. Do not expose a general actuator-control endpoint in the first milestone.

Extend Streamlit to show live readings, verification failures, device freshness, sensor and network alerts, suspicious connections, command outcomes, and a shared incident timeline. Refresh with a documented interval and display capture or model failures explicitly. Label synthetic and replayed data. Optional React integration must query the same services rather than depend on Vite middleware.

## 9. Proposed file layout

```text
config/
  edge.example.yaml
  device_inventory.example.yaml
src/
  common/       # configuration, schemas, UTC time, stable IDs
  storage/      # SQLite migrations and repositories
  api/          # ingestion, query routes, authentication
  sensor/       # verification, calibration, causal features, inference
  control/      # policy, command authentication, acknowledgments
  capture/      # portable TShark adapter and bounded flow engine
  ml/           # reusable network inference and anomaly batching
  incident/     # unified correlation and reconstruction
  dashboard/    # Streamlit views and compatibility exports
  runtime/      # startup, bounded queues, worker lifecycle, health
firmware/
  acquisition_esp32/
  controller_esp32/
scripts/
  train_sensor.py
  replay_scenario.py
tests/
  fixtures/     # HMAC vectors, telemetry, flow/PCAP and scenario fixtures
  test_verification.py
  test_feature_contract.py
  test_correlation.py
  test_command_lifecycle.py
  test_restart_recovery.py
```

Names are proposed. Introduce modules gradually and preserve existing scripts as wrappers where useful. Do not run capture, load large models, or modify evidence files merely by importing a module.

## 10. Implementation sequence and acceptance gates

### Phase 1 — Repair and connect existing network detection

- Extract reusable capture, feature, inference, and event functions.
- Configure executable/interface, flow limits, timeouts, model paths, and thresholds.
- Fix feature compatibility and add SQLite storage with schema migrations.
- Run RF and IF on live flows, and store results with capture timestamps.
- Add bounded flow expiration driven by a timer, including idle capture periods; flush or explicitly account for pending flows at shutdown.

**Gate:** a fixed PCAP produces reproducible features and persisted findings. Replaying it with the same run identity does not duplicate records. Capture loss, full queues, and model failures are visible.

### Phase 2 — Add authenticated telemetry

- Implement the device registry, HTTPS ingestion, HMAC verification, sessions, freshness, and atomic replay state.
- Start with a simulator using the exact firmware wire contract, then connect ESP32 #1.
- Persist accepted and rejected messages with reason codes.

**Gate:** valid messages are accepted; altered, stale, replayed, malformed, wrong-role and disabled-device messages are rejected. Reboots and concurrent retries cannot reset replay protection.

### Phase 3 — Add sensor integrity detection

- Add calibration metadata, process limits, causal feature windows, and explicit missing-history states.
- Collect labeled recordings, train a separate sensor RF, and version its feature pipeline.
- Keep deterministic validation and process rules alongside model inference.

**Gate:** held-out recordings produce documented metrics; a legitimate process transition is included in evaluation. Bad authentication never reaches the sensor baseline or control policy.

### Phase 4 — Add constrained control

- Implement policy decisions, signed expiring commands, controller verification, local limits, watchdog behavior, and signed acknowledgments.
- Demonstrate with simulated actuation before physical process control.

**Gate:** tampered, expired, duplicate, wrong-target, out-of-range, and reordered commands do not execute. A valid command executes once, and missing acknowledgments become evidence.

### Phase 5 — Join incident evidence and dashboard

- Add device/time correlation across telemetry, network findings, and command outcomes.
- Extend report templates and Streamlit investigation views.
- Preserve evidence references, model versions, and rule versions for each finding.

**Gate:** a controlled replay-plus-network-anomaly scenario appears as one reviewable incident with both source findings, timestamps, identity provenance, command outcomes, and limitations.

### Phase 6 — Measure edge behavior

- Run on the intended edge hardware and measure CPU, memory, storage growth, dropped packets, inference latency, and end-to-end alert delay.
- Test service restart, device disconnect, clock drift, full storage, queue overflow, and credential rotation.
- Document installation and startup for the actual operating system.

**Gate:** publish measured operating limits and recovery behavior. Set hardware-specific performance targets before measurement; do not invent throughput or latency claims.

## 11. Required verification scenarios

| Scenario | Expected result |
| --- | --- |
| Normal calibrated readings and ordinary network traffic | Readings accepted; policy acts within configured bounds; evidence retained |
| Payload altered after HMAC generation | Integrity rejection; no sensor inference or actuation from that message |
| Old valid message resent | Replay/freshness rejection with durable evidence |
| Repeated message during concurrent ingestion | At most one accepted observation and one associated action |
| Device signs a sensor spike with a valid key | Authentication passes; sensor detection evaluates the abnormal value separately |
| Stuck sensor or gradual drift | Quality/rule/model finding supported by the observation window |
| Legitimate rapid process change | Included in false-positive evaluation; no assumption that all changes are attacks |
| Anomalous traffic to monitored endpoints | Independent network finding, with device association only where supported |
| Lost network or invalid controller command | Local fallback behavior; rejected or missing acknowledgment recorded |
| Restart after issuing a command | No duplicate actuation; command state and replay state recovered |
| Idle capture and flow timeout | Flows expire predictably without waiting for another packet |
| Sensor finding without network anomaly | Sensor finding remains valid; absence of network evidence is stated |

## 12. Completion checklist

- [ ] Two architectures operate together with a shared device/time/evidence contract.
- [ ] Sensor and network models have separate artifacts and versioned feature pipelines.
- [ ] Live detection persists findings without manual script chaining.
- [ ] Telemetry and commands have verified integrity, freshness, and replay protection.
- [ ] ESP32 #2 enforces local constraints independently of server predictions.
- [ ] SQLite retains accepted readings, verification failures, model outputs, commands, and incidents.
- [ ] Streamlit supports the investigation view described in the abstract.
- [ ] Scenario tests cover rejection paths, restart recovery, and exactly-once command effects through idempotency.
- [ ] Sensor and network detection quality is evaluated on held-out representative traffic/readings.
- [ ] Edge resource usage and evidence retention are measured and documented.
- [ ] Documentation distinguishes authenticated data, anomalous behavior, suspected compromise, and confirmed evidence.

## 13. Instructions for an implementation agent

Implement this plan incrementally in the existing repository. Read repository instructions first. Begin with Phase 1, preserve unrelated changes, and make each phase demonstrable before proceeding. Treat proposed interfaces and filenames as implementation guidance, and record material deviations. Use configuration for installation-specific values and keep secrets out of commits. Do not silently replace missing hardware with synthetic results: label simulators and replay fixtures explicitly. Do not claim production readiness, detection accuracy, or physical-process safety without measured evidence and the relevant validation.
