# Architecture 1: afternoon prototype plan

## Scope and precedence

Revised to the user's confirmed scope: implement Architecture 1 only. This replaces the earlier two-architecture plan and task list. Network capture, network RF/Isolation Forest, DBSCAN, incident network correlation, and dashboard redevelopment are outside this prototype. Earlier broad conversion/data engineering documents are background, not the active implementation scope.

Deliver a command-line server that receives sensor readings, verifies message integrity and freshness, records the decision, and authorizes a bounded motor action through the second ESP32. Motor hardware work proceeds separately; a clearly labeled controller simulator permits server development meanwhile.

## Confirmed inputs

- Two ESP32 boards: the sensor board reads DS18B20 temperature and turbidity; the other board controls the motor. These functional names avoid ambiguity around monitoring/acquisition terminology.
- Sensor firmware is `data/data.ino`: GPIO 4 for DS18B20, GPIO 34 for turbidity, 12-bit raw ADC, JSON POST to `/api/sensor`, HMAC header `X-HMAC-SHA256`.
- `receiver.py` has now been supplied and inspected: Flask, exact-body HMAC, 30-second age/10-second future tolerance, initially RAM-only replay state and an external unverified ML path. The server has been revised to persist replay/decisions in SQLite, validate the registered device/schema, and explicitly disable unsupported ML. See `RECEIVER_DEMO.md` for current behavior and remaining limitations.
- Turbidity module specifications supplied by the user: 5 VDC, maximum 30 mA, operating temperature -30 to 80 degrees C, advertised measurement range 0-1000 NTU. Its analog output voltage and calibration curve are not specified. Sensor operating temperature is not a water process threshold.
- Both readings are currently working. Motor integration is in progress.
- No labeled sensor dataset exists. Process thresholds are not yet settled.
- Interpret the stated connectivity as a phone hotspot shared by ESP32 boards and laptop(s); confirm this during connectivity testing.
- CLI output is sufficient. The prototype is due this afternoon; no multi-day model training or dashboard work is on the critical path.

## Intended flow

```text
Sensor ESP32 -> laptop /api/sensor
  -> verify exact-body HMAC
  -> check schema + registered identity + freshness + replay
  -> record accepted/rejected decision
  -> optional explicit process-policy checks
  -> signed, expiring motor authorization
Motor ESP32 polls laptop -> independently verifies authorization
  -> bounded motor ON -> local timeout -> OFF
  -> authenticated acknowledgment -> laptop CLI/evidence
```

Controller polling is now selected by the user. `motor_service.py` implements signed polling/ACKs and `motor_simulator.py` is the runnable client reference. Motor authorization is opt-in and physical firmware remains pending. The proposed motor output is GPIO 18; active polarity is unconfirmed. See `RECEIVER_DEMO.md` for startup and protocol details.

## What establishes message tampering

HMAC-SHA-256 verifies that the received bytes match what a holder of the device key signed. A changed body with the original signature must be rejected. Compare signatures in constant time over the original request bytes, not reconstructed JSON.

Freshness and sequence/session checks separately reject stale and replayed authentic messages. A valid signature does not prove the sensor is physically accurate or that a compromised device has not signed fabricated values.

The existing Random Forest is a network-flow classifier and cannot process temperature/turbidity readings. With no labeled sensor data, sensor ML training is deferred. Do not invent an accuracy number or claim that ML detects cryptographic message modification. Optional anomaly experiments must not decide integrity or bypass verification.

For today's controlled demonstration, motor eligibility is explicitly based on authenticated, fresh, nonreplayed telemetry and configured local constraints. This does not certify that water is safe. If physical-quality approval is required, define the process thresholds first; otherwise use a bounded motor demonstration with that limitation stated.

## Server processing order

1. Bound request size; read original body and signature header.
2. Parse enough to identify a registered device; all submitted identity is untrusted until HMAC succeeds. Reject malformed JSON, duplicate keys, nonfinite values and invalid types.
3. Verify HMAC with the registered device key using constant-time comparison.
4. Check timestamp freshness and device sequence/session. Persist replay state; never silently clear it to fix a reboot.
5. Validate expected temperature and raw turbidity fields and quality states. Keep transport verification separate from physical-quality checks.
6. Atomically persist acceptance and sequence advancement, or persist a rejection reason. Do not advance replay state on unauthenticated input.
7. Create at most one authorization per accepted sample under a documented policy. Do not let five-second samples indefinitely extend a motor's maximum local run time.
8. Deliver a signed expiring command and record ACK or unknown outcome. Failed verification creates no new ON command. Previously issued ON commands must still terminate through controller expiry/watchdog behavior.

Use SQLite for durable replay/decision/command state with minimal dependencies. CLI should show receipt time, device, sequence, temperature C, raw ADC, verification result/reason and command/ACK state. Do not print keys.

## Firmware and motor contract

Keep current JSON/header compatibility initially. Add versioned session handling in coordinated firmware/server changes. Choose either persistent monotonic sequence management or an authenticated session handshake; current RAM sequence restarts at zero. Reboot behavior is an acceptance test, not an undocumented exception.

Commands must authenticate command ID, target device, sequence/session, action, issue time, expiry and maximum ON duration using a separate controller credential. The controller rejects altered, duplicate, expired and wrong-target commands, independently enforces its maximum duration, and starts with outputs OFF for the proposed demo. Confirm the actual relay active level and motor wiring before enabling hardware.

Prefer certificate-validated HTTPS. The existing HTTP path supplies no confidentiality or server authentication. If TLS cannot be completed for the isolated afternoon demonstration, explicitly disclose this limit and keep HMAC and replay verification; do not describe HTTP as TLS-secured. Do not disable certificate verification and call that HTTPS protection.

Do not drive a motor directly from an ESP32 GPIO. Confirm a suitable driver/relay, supply, protection and default state with the hardware build. The module's 5 V supply specification does not establish a safe ADC output voltage: measure/verify the output range against the actual ESP32 input limits. Keep turbidity in ADC counts until calibrated; advertised 0-1000 NTU alone does not supply the conversion.

## Delivery order

1. Inspect supplied receiver and preserve its working wire contract.
2. Run sensor-to-laptop reception and exact-body HMAC checks with durable evidence.
3. Add freshness, replay rejection and explicit reboot/session behavior.
4. Produce signed commands against a controller simulator and record ACK outcomes.
5. Integrate the motor ESP32 after the command contract and wiring are confirmed.
6. Rehearse accepted, tampered, replayed and expired-command cases; retain CLI logs.

Stop optional features when they threaten the demonstration. Do not omit integrity/replay checks to make the motor operate. A simulator must always be labeled as a simulator.

## Required demonstration cases

| Input | Expected result |
| --- | --- |
| Fresh authentic sample | Accept; bounded authorization if configured demo policy permits |
| One sensor value modified without a new HMAC | Reject integrity; no new authorization |
| Previously accepted authentic sample resent | Reject replay or return prior decision without a new motor effect |
| Authentic sample with stale timestamp | Reject freshness |
| Device/server reboot | Replay protection remains enforced; session recovery follows the selected protocol |
| Altered or expired motor command | Controller rejects; no actuation |
| Laptop/hotspot disconnect during ON | Controller's local maximum duration/watchdog terminates the output |
| No motor hardware available | Labeled simulator verifies command decisions; no claim of physical actuation |

## Remaining implementation inputs

- `receiver.py`, plus motor ESP32 firmware if available.
- Confirm phone hotspot/client isolation and laptop inbound port reachability.
- Decide whether today's eligibility is an integrity-only demonstration or includes physical-quality limits. Actual limits must be supplied/justified, not guessed.
- Confirm motor command interface, driver/relay behavior, maximum ON duration and manual stop.
- Select the coordinated reboot/session solution; confirm whether firmware can be reflashed before presentation.

Existing exposed/shared firmware credentials should be replaced through local provisioning; keep actual values out of the plan. Hardware sensor ML, calibrated NTU and Streamlit are follow-up work after this prototype.
