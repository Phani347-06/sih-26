# Architecture 1 afternoon checklist

This replaces the earlier broad task list following the user's scope correction. All implementation items remain unchecked. Dependencies and design: `tasks/plan.md`.

## 1. Inspect receiver and prove connectivity

Dependencies: receiver supplied by user. Likely files: supplied `receiver.py`, endpoint configuration. Scope: small.

- [x] Inspect current receiver and preserve `/api/sensor` and the exact-body HMAC header contract.
- [ ] Confirm hotspot address, endpoint and incoming ESP32 request.
- [ ] Save a test-only exact-body/HMAC vector with no operational secrets.

Verification: request received from actual sensor board; existing payload/header remain compatible.

## 2. Make acceptance trustworthy and durable

Dependencies: 1. Likely files: receiver verification and SQLite helpers, focused tests. Scope: medium.

- [ ] Validate schema and exact-byte HMAC; reject altered data with a specific reason.
- [ ] Add transactional freshness/replay state and coordinated reboot/session behavior.
- [ ] Persist accept/reject outcomes and show concise CLI decisions.

Verification: valid, altered, duplicate, stale, concurrent/retry and reboot cases; rejected input cannot authorize ON.

### Checkpoint: Sensor-to-server

- [ ] Actual temperature/raw turbidity visible; no claim of calibrated NTU or trained sensor classification.
- [ ] Integrity and replay rejection demonstrated before connecting control.

## 3. Implement controller simulation

Dependencies: 2. Likely files: command helper and labeled controller simulator, command tests. Scope: medium.

- [ ] Agree polling/push contract; sign target-bound expiring commands using a separate controller key.
- [ ] Deduplicate sample decisions and command execution; bound ON duration.
- [ ] Verify ACKs and record timeout as unknown outcome.

Verification: valid, altered, wrong-target, duplicate and expired command cases; repeated samples do not extend ON forever.

## 4. Connect motor ESP32 when available

Dependencies: 3 plus controller firmware/wiring. Likely files: controller firmware and configuration. Scope: medium.

- [ ] Confirm suitable driver, output polarity, supply and manual stop.
- [ ] Independently enforce command verification, replay/expiry and maximum run duration on ESP32.
- [ ] Return authenticated acknowledgment; retain OFF/default and watchdog behavior for this demo.

Verification: bench test bounded ON, duplicate command, expiry and hotspot/server loss. Label simulation if physical integration remains incomplete.

## 5. Rehearse presentation

Dependencies: 2, 3; include 4 if ready. Likely files: demo instructions and redacted logs. Scope: small.

- [ ] Demonstrate valid input, altered HMAC body and replay, with visible command decisions.
- [ ] State transport status, absent labeled dataset and integrity-versus-water-quality distinction accurately.
- [ ] Show physical actuation only if verified; otherwise show the labeled simulator.

Verification: repeatable CLI script and actual device run; no network architecture or dashboard work required.
