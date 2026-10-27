# IIoT security: complete data engineering analysis

## 1. Scope, evidence, and assumptions

This document analyzes the existing SIH-26 data pipeline and specifies the data engineering needed for the IIoT sensor-integrity and network-security system in `IIOT_CONVERSION_PLAN.md`.

Repository observations are based on source inspection and the available directory/file structure on 2026-10-27. The inspection did not profile every dataset, rerun training, load the saved model artifacts, benchmark hardware, or validate live devices. Dataset sizes, class distributions, accuracy, latency, and throughput must be measured before being reported.

The proposed deployment is one laptop or edge computer receiving authenticated water-quality telemetry from ESP32 #1, monitoring observable network traffic, and recording constrained commands and acknowledgments from ESP32 #2. SQLite is the proposed operational store; versioned files provide raw evidence and offline analytical datasets.

The principal data products are:

1. Verified sensor readings with calibration and quality context.
2. Network flows with reproducible feature definitions.
3. Sensor and network predictions tied to specific model versions.
4. Security events with traceable evidence.
5. Incident histories connecting readings, traffic, and control outcomes.
6. Reproducible training/evaluation datasets and model manifests.

## 2. Current-state assessment

| Area | Current implementation | Consequence |
| --- | --- | --- |
| Raw network data | Eight CICIDS CSV files are present under `data/raw/` | Benchmark data is available; relevance to local IIoT traffic needs evaluation |
| Preprocessing | Six selected files; column/label cleanup, per-file deduplication, 22 features, invalid-row removal | Cleaning exists, but there is no persisted per-rule rejection report or dataset manifest |
| Processed storage | One combined `processed_dataset.csv` | Weak lineage back to source file, original row, device, and recording session |
| Known-threat training | Stratified random 80/20 split and Random Forest | Split preserves label ratios but does not establish generalization across sessions, devices, or time |
| Anomaly training | Isolation Forest fitted on up to 100,000 benign records | A normal reference exists; its applicability to the target devices is unverified |
| Live capture | TShark metadata; in-memory bidirectional flows; five-second processing windows | No durable live event handoff; flow state is lost on restart |
| Feature consistency | Feature names are duplicated across scripts; live timing is in seconds versus CICIDS microseconds | Schema names alone do not ensure equivalent model inputs |
| Events | `output/events.json` is consumed as line-delimited JSON | Its extension hides its actual format; parse failures can be skipped without durable quarantine |
| Unknown patterns | Standardized anomaly batches, DBSCAN, JSON pattern store | Pattern identity and reproducibility need stronger definitions |
| Correlation | Python rules produce incidents and a graph | No shared persistent identity/time contract across sensor, network, and control evidence |
| Reports/dashboard | Derived JSON and Streamlit; React loads JSON once through Vite middleware | Views can be stale and exports can represent different pipeline runs |
| Sensor/control data | Not implemented | New ingestion, verification, calibration, and command lifecycle contracts are required |

### Important distinctions

- `events.json` is a JSON Lines stream; other output files are ordinary JSON documents. Rename or explicitly version each format during migration.
- Deduplication currently occurs before feature selection within each source file. Records can still become feature-identical after projection, or overlap across files; quantify this rather than assuming independence.
- IPs and ports support capture and correlation but are not inputs in the current 22-feature classifier.
- Synthetic demo output is demonstration evidence, not held-out evaluation evidence. The checked-in pattern store alone cannot establish detection quality.
- Model confidence, anomaly score, and incident severity are different quantities and need separate fields.

## 3. Source inventory and ownership

| Source | Grain | Time fields | Trust/quality considerations | Proposed owner |
| --- | --- | --- | --- | --- |
| ESP32 sensor telemetry | One authenticated message containing named readings | Device measurement time, server receipt time | Device clock, sequence, HMAC, calibration, missing samples | Sensor ingestion service |
| Device inventory | One versioned device record | Effective interval | Device identity, role, credentials, allowed mappings | Provisioning/operator workflow |
| Address associations | Device-address relationship during an interval | Valid from/to | DHCP, NAT, address reuse, uncertain attribution | Inventory/correlation service |
| TShark metadata | One observed packet | Capture timestamp | Packet loss, interface visibility, parsing, truncated capture | Capture worker |
| PCAP evidence | One bounded capture file | Capture start/end | Sensitive payloads, disk usage, missing packets | Evidence service |
| Network flow | One aggregation fragment | First/last packet, window interval | Feature definitions, direction, timeout and completeness | Flow worker |
| Controller command | One requested action | Issued, expires, sent | Authorization, policy version, idempotency | Control service |
| Controller acknowledgment | One authenticated outcome report | Device execution time, receipt time | Lost/late/duplicate ACK, uncertain physical outcome | Command verification service |
| Benchmark CSV | One supplied labeled flow row | Dataset-specific fields, if retained | Label provenance, feature compatibility, dataset license | Offline dataset pipeline |
| Operator annotation | One review decision | Review time | Human uncertainty, revisions, reviewer identity | Incident review workflow |

Never replace unknown identity or missing measurements with fabricated IDs or zero values. Store unresolved identity as nullable with a reason.

## 4. Target data flow and layers

```text
Sources
  Sensor messages | packets/PCAP | commands/ACK | benchmark files
        |
        v
Bounded ingestion + durable receipt
        |
        +--> Rejected/quarantined evidence with reason codes
        |
        v
Validated records + explicit identity/time/unit contracts
        |
        +--> SQLite operational tables
        +--> Versioned raw/curated file partitions
        |
        v
Causal feature computation + versioned models/rules
        |
        v
Predictions -> common events -> correlation -> incidents
        |
        +--> Live operational queries and Streamlit
        +--> Reproducible analytical/training snapshots
```

### Raw layer

Preserve original benchmark files with digests and import manifests. For telemetry, retain the authenticated byte representation or a controlled-access evidence reference. Preserve capture metadata and optional PCAP references. Record ingestion run, producer, receipt time, source identity claim, and source digest.

Treat raw evidence as append-only through application permissions and retention policy. Local files and SQLite are not inherently immutable or tamper-proof.

### Curated layer

Store accepted telemetry, normalized calibrated readings, network flows, verification outcomes, and command lifecycle facts. Apply explicit schemas and quality rules. Preserve raw references and transformation versions.

### Serving and analytical layer

Provide predictions, events, incidents, dashboard aggregates, and immutable dataset snapshots. Operational views read SQLite; large offline experiments can read partitioned Parquet. Parquet is a proposed addition, not a current dependency or requirement for the first milestone.

## 5. Canonical contracts

All persisted contracts need a `schema_version`. Use stable IDs, UTC timestamps, explicit units, nullable fields with defined meaning, and separate producer/source provenance.

### Telemetry and sensor readings

One telemetry message contains `device_id`, `key_id`, authenticated session, sequence, measurement time, and named readings. Store:

```text
message_id, device_id, session_id, sequence, key_id
measured_at, received_at, clock_quality, clock_offset_estimate_ms
payload_ref, payload_sha256, verification_status, rejection_reason
schema_version, ingestion_run_id
```

Each accepted scalar measurement becomes one reading:

```text
reading_id, message_id, sensor_id, metric
raw_value, calibrated_value, unit
calibration_version, quality_status
```

Allowed metrics initially include pH, turbidity in NTU, and conductivity in µS/cm. pH is dimensionless. Retain conductivity temperature-compensation status and temperature reference where applicable; add a temperature measurement if the calibration method requires it. Never silently mix compensated and uncompensated values.

Uniqueness: `(device_id, authenticated_session, sequence)` identifies one accepted message. Sequence state updates and message insertion must occur in one transaction. A retry returns the prior result rather than producing another downstream action.

Verification must use the exact authenticated bytes specified in the conversion plan. Canonical analytical records are generated after verification and cannot substitute for the original bytes during HMAC checks.

### Network flows

```text
flow_id, capture_run_id, aggregation_version
endpoint_a_ip, endpoint_a_port, endpoint_b_ip, endpoint_b_port, protocol
first_source_ip, first_source_port
first_packet_at, last_packet_at, window_start, window_end
packet_count, capture_quality, feature_schema_version
raw_capture_refs
```

Use a normalized endpoint tuple to group reverse traffic, but retain the first observed sender separately to define forward features. A normalized tuple alone is not globally unique: connections reuse ports, so include capture/session/window identity. Record whether the flow ended by idle timeout, active timeout, shutdown, or a connection signal.

### Predictions and events

```text
prediction_id, input_record_or_window_id
model_id, model_version, feature_schema_version
predicted_label, score_kind, score_value, class_probabilities
decision_threshold_version, inferred_at, inference_status
```

`score_kind` distinguishes RF class probability from IF decision score, rule result, or clustering distance. Unsupported inference and insufficient history are explicit states.

Events reference predictions and original evidence. Incidents reference events through a join table rather than duplicating their full payloads. Keep rule-generated severity separate from classifier probability.

### Commands and acknowledgments

Separate command intent, delivery attempts, and acknowledgment observations. Required identifiers include `command_id`, controller identity/session/sequence, issue/expiry times, policy version, bounded action parameters, triggering evidence IDs, and authentication result.

A timeout means the execution outcome is unknown unless additional evidence resolves it. An ACK records the controller's report; it does not independently prove the physical actuator moved. Duplicate delivery must not cause duplicate actuation.

## 6. Time, ordering, and identity

Use source event time for physical timelines where trustworthy and server receipt time for ingestion and audit. Store both. Network timestamps describe capture time; model inference time describes processing, not occurrence.

Normalize to timezone-aware UTC and preserve useful source precision. Never mix naive and aware Python datetimes. Reject malformed times with a reason; do not replace them with current time and present them as observed occurrence.

For each source define:

- Allowed clock skew and freshness interval.
- Authenticated boot/session establishment and sequence reset policy.
- Maximum accepted lateness and out-of-order behavior.
- Clock-quality state and policy when time synchronization fails.

For causal sensor inference, either reject older sequence/time observations or buffer within an explicitly bounded ordering interval. Persist late observations even when excluded from an already-computed feature window. Corrections create a new derived version rather than silently changing prior evidence.

For incident correlation, use configurable event-time windows, a lateness allowance, and a finalization policy. A late event may update an incident with an audit trail. Device identity joins must use address validity intervals; do not join all historical traffic to the current owner of an IP.

## 7. Data quality and quarantine

| Check | Example | Action |
| --- | --- | --- |
| Structural validity | Missing schema field, duplicate JSON key, invalid type | Reject/quarantine with parser version |
| Authentication | Incorrect HMAC, unknown/disabled key | Reject, record minimal evidence, exclude from accepted readings |
| Freshness/replay | Expired timestamp or reused sequence | Reject and record reason |
| Numerical validity | NaN, infinity, negative packet count | Reject or mark invalid; never silently treat as normal |
| Physical/calibration validity | Reading outside sensor specification or missing calibration | Preserve authenticated observation; attach quality finding |
| Process plausibility | Rapid change or process-limit breach | Generate a rule finding; retain the reading for investigation |
| Completeness | Expected samples absent | Emit gap/availability evidence |
| Cross-field consistency | Bytes incompatible with counts, end time before start | Quarantine or mark incomplete with explicit policy |
| Reference integrity | Missing device/model/evidence reference | Reject derived write or retain unresolved linkage explicitly |
| Capture quality | Dropped packets, worker restart, interface unavailable | Mark affected intervals and expose degraded coverage |

Keep instrument specification bounds distinct from configured process limits and security thresholds. A valid measurement outside a process limit may be the most important evidence and should not be erased by cleaning.

Create a quarantine record containing source reference, safe payload reference/hash, rule ID/version, reason, receipt time, and resolution status. Bound rejected-input retention and rate-limit abusive sources. Authentication secrets and full sensitive payloads must not leak into exception logs.

Every import reports total input, accepted, rejected, duplicate, and unresolved records. Counts must reconcile under documented mutually exclusive dispositions. Versioned reports make preprocessing losses visible.

## 8. Feature engineering and compatibility

### Network feature dictionary

| Feature group | Contract |
| --- | --- |
| Flow Duration | Microseconds if retaining the CICIDS-compatible model; define zero-duration behavior |
| Fwd/Bwd packet counts | Counts relative to first observed sender |
| Fwd/Bwd total lengths and means | Bytes with an explicit packet/layer-length definition |
| Flow Bytes/s and Packets/s | Per second, even when duration is represented in microseconds |
| Flow IAT mean/std; Fwd/Bwd IAT mean | Microseconds; define ordering, short-flow cases, and standard-deviation convention |
| Fwd/Bwd PSH | Explicit flag-count semantics and verified TShark encoding |
| Fwd/Bwd header lengths | Bytes, with exact included protocol layers and missing-value behavior |
| Packet length mean/std | Same length definition as training; fixed variance convention |
| SYN and ACK counts | Explicit TCP flag interpretation; non-TCP behavior defined |
| Down/Up ratio | Backward packet count divided by forward packet count; define empty-forward handling |

The current live extractor uses `frame.len`; training feature names do not prove an identical length definition. Validate against the reference extractor on a fixed PCAP. Also examine retransmissions, fragmented packets, UDP headers, multi-valued TShark fields, IPv6 support, and capture truncation. Scope unsupported traffic explicitly.

Place feature order, types, units, and missing-value policy in one shared versioned contract. A model manifest must declare its expected contract. Fail incompatible inference rather than silently reshuffling columns.

Five-second fragments and full connection flows produce different distributions. Use matching extraction/window rules for training and deployment, or retrain and validate the changed representation.

### Sensor features

Use calibrated current values, actual elapsed-time slopes, rolling statistics, baseline deviation, repeated-value duration, sample gaps, and calibration/quality state. Define each window by time and minimum observations. Exclude rejected telemetry and future samples.

Do not interpolate across long gaps or silently treat missing samples as zero. If a model requires imputation, fit its parameters on training data only, version them, and include missingness indicators where justified.

Keep deterministic authenticity, freshness, and safety checks outside probabilistic models. Sensor-model output indicates observed behavior, not proof of tampering.

### Clustering

Store DBSCAN batch boundaries, member record IDs, scaler parameters, feature version, `eps`, and `min_samples`. Scaling each batch independently changes distances and complicates cross-batch pattern comparison. Choose either a versioned reference scaler or an explicitly documented batch-relative interpretation.

Cluster IDs are local to one run. Use separate stable pattern IDs and validated signature matching; equal member counts are insufficient evidence of pattern identity. Retain unclustered anomalies as individual findings.

## 9. Dataset engineering and label management

Each dataset release needs:

```text
dataset_id and version
source URIs/paths, digests, capture/import intervals, license/provenance
schema and extraction versions
cleaning rules and quality summary
label taxonomy, source of labels, uncertainty and review status
split strategy, membership manifest, seed where applicable
feature pipeline and calibration versions
row counts by source/class/split/device/session
known exclusions and limits of applicability
```

Preserve raw label strings alongside normalized labels. Version mappings such as DoS variants to `DOS`, and explicitly report dropped `OTHER` classes. Do not silently compare metrics from experiments using different taxonomies; the unseen-evaluation script also differs from main training in its treatment of Heartbleed.

### Split procedure

1. Identify recording sessions, devices, attack scenarios, and repeated/related records.
2. Assign disjoint train, validation, and test groups before creating overlapping sensor windows or fitting transformations.
3. Check exact duplicates and near-duplicate feature records across splits; report potential leakage.
4. Fit imputers, scalers, baselines, feature selection, and model parameters on training data only.
5. Select operating thresholds on validation data.
6. Evaluate once on the held-out test set and retain prediction-level results.

If benchmark files lack sufficient session/device metadata, document the resulting limitation rather than claiming a device-independent split. A chronological split alone may still leak repeated campaigns or overlapping flows.

Human-reviewed outcomes are new label records with reviewer, time, rationale, and confidence. Never promote model predictions into ground-truth labels automatically. Distinguish process faults, legitimate changes, and deliberately injected attacks.

## 10. Persistence, partitioning, and serving

### Operational SQLite

Use the entity tables in the conversion plan with foreign keys and schema migrations. Recommended indexes follow actual query patterns:

- Unique accepted telemetry identity: device/session/sequence.
- Readings: sensor or device plus measurement time.
- Flows: capture run plus interval; endpoint plus time where justified.
- Events: device plus event time; origin/type plus time.
- Incidents: status plus updated time; indexed event join references.
- Commands: unique command ID, controller plus sequence, expiry/status.

Avoid creating an index for every JSON field. Promote commonly filtered fields into typed columns and inspect query plans. SQLite does not enforce timezone or units by itself; validate these in shared code and use database constraints where possible.

Use short transactions, bounded batches, configured busy timeouts, and a serialized writer where needed. WAL is for a local-host database; do not place the live database on a shared network filesystem and assume equivalent reliability. Long readers can delay WAL checkpoints, so monitor WAL growth.

### File layout for evidence and offline datasets

```text
data/
  raw/benchmark/<source>/<release>/
  raw/telemetry/date=YYYY-MM-DD/hour=HH/
  raw/capture/date=YYYY-MM-DD/hour=HH/
  curated/readings/schema_v=<n>/date=YYYY-MM-DD/
  curated/flows/schema_v=<n>/date=YYYY-MM-DD/
  datasets/<dataset_id>/<version>/
    manifest.json
    split_membership.parquet
    train.parquet
    validation.parquet
    test.parquet
models/<model_id>/<version>/
  model.pkl
  manifest.json
  evaluation.json
```

This is a proposed layout. Avoid partitioning by high-cardinality IDs by default; it creates many tiny files. Compact offline files with recorded lineage and retention-aware cleanup. Do not rewrite original benchmark files.

### Dashboard serving

Query operational tables through service/repository functions with pagination, filters, and bounded date ranges. Return `as_of`, coverage interval, and pipeline health so stale data is visible. Count events and incidents separately; one incident can contain many events.

If JSON compatibility exports remain, build all outputs from one consistent database snapshot, publish a shared generation ID, and replace a complete export generation atomically. A partial update must not mix old reports with a new graph.

## 11. Streaming reliability and orchestration

Use supervised workers for capture, ingestion, inference, correlation, and housekeeping. Define startup dependencies and health checks. Optional training and large imports stay outside the latency-sensitive runtime.

Each handoff needs explicit durability and failure behavior:

| Handoff | Durability/retry rule |
| --- | --- |
| Device to ingestion | Device retries within bounded expiry; server deduplicates authenticated identity |
| Packet to flow worker | Bounded memory; expose drops; packet loss cannot be repaired without captured evidence |
| Completed flow to inference | Persist work item or flow before retryable inference |
| Prediction to event | Transactional write or durable outbox to avoid losing the finding |
| Event to correlation | Persistent checkpoint with idempotent incident updates |
| Policy to controller | Durable command intent; retry same ID; controller deduplicates effects |

Describe the system as at-least-once processing with idempotent effects where implemented. End-to-end exactly-once physical actuation cannot be inferred from a database transaction alone.

Bound active flows, queue lengths, batch sizes, anomaly windows, raw evidence storage, and retry counts. On overload, record which intervals or records lost coverage. Prefer dropping optional work such as visualization refresh before exhausting ingestion capacity, under an explicit policy.

Use event-time and wall-clock timers to close idle flows without waiting for a new packet. On restart, recover durable jobs, mark interrupted captures, and avoid issuing expired commands. Store worker checkpoints after successful transactional effects.

## 12. Lineage, reproducibility, and governance

Required lineage chains:

```text
Incident -> correlation rule -> event -> prediction
         -> feature window/flow -> accepted input -> raw evidence

Command -> policy decision -> triggering evidence -> signed payload
        -> delivery attempt -> verified acknowledgment

Model -> training run -> dataset manifest -> split membership
      -> preprocessing version -> source files and labels
```

Keep machine-readable manifests and referential IDs instead of embedding all upstream records into each report. Retain code revision or release ID and configuration digest for runs. Random seeds improve repeatability but do not replace dependency and environment records.

Limit access by role: devices submit their own messages; controllers retrieve their own commands; analysts review evidence; authorized operators change inventory and policy. Audit changes to labels, calibration, keys, models, thresholds, and incident status.

PCAPs can contain sensitive traffic. Restrict raw evidence access, encrypt supported storage/backups, and define deletion/export rules. Use pseudonymized datasets for research where feasible; keep stable mappings in a separate controlled location. If addresses are transformed, preserve only the relationships needed for the analysis and record the method.

Model pickle/joblib files must come from trusted build artifacts because loading them can execute code. Record digests and restrict write access to deployed model directories.

## 13. Retention, capacity, backup, and recovery

Set separate retention periods for raw PCAP, raw telemetry, curated readings, flows, predictions, incidents, audit records, and trained artifacts. Keep replay state long enough to preserve session validity and prevent old-message acceptance. Legal or incident holds override ordinary deletion through a documented process.

Capacity planning uses measured rates:

```text
telemetry records/day = devices × samples/second × 86,400
flow records/day      = measured completed flows/second × 86,400
logical storage/day  = Σ(records/day × measured average stored bytes)
retained storage     = Σ(storage/day per class × retention days)
                       + indexes + WAL + backups + headroom
```

Illustration only: 20 devices sampling once per second produce 1,728,000 telemetry messages/day. At an assumed 500 bytes/message that is about 864 MB/day before indexes, raw copies, and backups. Normalizing each message into three sensor readings creates 5,184,000 reading rows/day. This is not a measurement of this repository.

Estimate PCAP separately from packet rate and captured bytes; it can dominate disk usage. Benchmark compression and actual SQLite sizes instead of using wire payload size as a storage estimate.

Use SQLite's supported online backup mechanism or a coordinated consistent snapshot; copying only an active `.db` file can omit WAL contents. Back up external evidence, manifests, and model artifacts consistently, with separately controlled secret recovery. Test restore and check evidence references and database integrity.

Define recovery point and recovery time objectives before deployment. Measure them in a restore exercise. Full disks, corrupted files, missing PCAPs, and unavailable keys must produce visible degraded states rather than false healthy status.

## 14. Observability and analytical validation

Track operational metrics:

- Input, accepted, rejected, duplicate, and quarantined records by source/reason.
- Last accepted device sample, sequence gaps, clock skew, and missing intervals.
- Capture drops, active flows, queue depth, overflow count, and processing lag.
- Feature validation failures, insufficient-history rates, model load/inference errors.
- Event and incident counts by detector/version, distinct affected devices, late arrivals.
- Command age, delivery retries, rejection reasons, ACK delay, unresolved outcomes.
- SQLite write latency, lock contention, WAL size, disk usage, retention and backup status.

Track detection quality separately: per-class precision/recall/F1, false alerts per device-hour, sensor/network detection delay, and outcomes of reviewed incidents. Monitor changes in feature distributions and alert rates by device class and operating mode. Distribution drift is evidence to investigate; it does not automatically authorize retraining or prove attack activity.

Dashboard totals should reconcile to underlying queries for the same interval and filters. Display unknown identity, missing evidence, and capture gaps instead of presenting complete coverage.

## 15. Verification plan

| Verification | Acceptance evidence |
| --- | --- |
| Import reproducibility | Same inputs/config produce the same dataset membership and transformation results |
| Preprocessing accounting | All inputs reconcile to accepted/rejected/duplicate dispositions |
| Network feature parity | Fixed PCAP compared with a documented reference; justified tolerances per feature |
| Sensor causal windows | Future observations cannot affect earlier predictions; gaps and warmup are explicit |
| Authentication/replay | Modified, stale, duplicated, concurrent and reordered submissions handled correctly |
| Schema evolution | Old supported messages migrate; incompatible versions fail explicitly |
| Cross-split leakage | Session/device/group overlap and duplicates reported and resolved or disclosed |
| Persistence retries | Repeated jobs do not duplicate predictions, events, incidents or command effects |
| Identity correlation | Address reassignment does not attach old traffic to a new device |
| Late evidence | Updates follow finalization policy and retain revision history |
| Evidence traceability | Sample incident can be followed back to raw inputs and exact model/rule versions |
| Snapshot consistency | Graph, timeline, counts and reports share one export generation |
| Failure recovery | Restart, queue overflow, disk-full and restore exercises preserve documented behavior |
| Edge load | Measured sustainable input rate, resource use, loss and alert latency on target hardware |

Use small deterministic fixtures for contracts and controlled recordings for end-to-end scenarios. Keep synthetic examples, benchmark evaluation, and physical-device trials as distinct evidence categories.

## 16. Prioritized implementation roadmap

### P0 — Establish trustworthy inputs and persistence

1. Publish shared schema, timestamp, feature-unit, and identity contracts.
2. Profile existing CSVs and produce source manifests, class counts, missingness, duplicates, and cleaning reports.
3. Validate/fix live network feature semantics against fixed capture evidence.
4. Introduce SQLite migrations, raw/evidence references, stable IDs, and idempotent writes.
5. Connect live flows and RF/IF predictions to durable storage; expose capture loss.

**Deliverable:** reproducible network ingestion with traceable persisted findings.

### P1 — Add verified sensor data and command lifecycle

1. Implement registration, authenticated sessions, message verification, and durable replay state.
2. Normalize calibrated readings while retaining raw values and quality outcomes.
3. Implement causal sensor features and collect versioned labeled recording sessions.
4. Store policy decisions, signed command intent, delivery attempts, and verified acknowledgments.

**Deliverable:** one sensor-to-controller scenario with complete evidence and explicit rejection paths.

### P2 — Join analytical evidence

1. Add time-valid device/address mapping and cross-source correlation.
2. Build sensor datasets with group/time splits and a separately versioned model.
3. Add bounded anomaly clustering with reproducible batches and pattern identities.
4. Extend Streamlit and optional API/React views using consistent query definitions.

**Deliverable:** an incident linking sensor, network and control evidence with model/rule provenance.

### P3 — Validate operation and retention

1. Measure workload and storage on target hardware; set explicit retention and operating limits.
2. Test backup/restore, restarts, late data, clock failure, overload, and disk-full handling.
3. Produce held-out detection metrics and operator review procedures.
4. Document installation, data contracts, schema migrations, evidence exports, and known coverage gaps.

**Deliverable:** measured operational envelope and reproducible evaluation package.

## 17. Definition of done

- [ ] Every retained observation has source, timestamps, schema version, quality outcome, and lineage.
- [ ] Sensor, network, command, and incident data share resolvable identity/time contracts.
- [ ] Invalid and missing data remain distinguishable from normal values.
- [ ] Training and inference use equivalent versioned features and calibration.
- [ ] Dataset snapshots and split membership can be reproduced without leakage from future observations.
- [ ] Prediction scores retain their meaning and are separate from severity and verification status.
- [ ] Retried ingestion and restart recovery preserve idempotent analytical and command effects.
- [ ] Dashboards expose freshness and coverage, and aggregates reconcile with stored facts.
- [ ] Incidents trace to original evidence and exact model/rule/policy versions.
- [ ] Storage, retention, backups, resource limits and recovery behavior have measured evidence.

This document specifies the data engineering work. It does not imply that the current code already provides authenticated telemetry, reliable IoT detection, continuous orchestration, or validated physical control.
