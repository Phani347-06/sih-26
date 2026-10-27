# Sensor receiver: CLI prototype

The receiver preserves `/api/sensor` and `X-HMAC-SHA256`. It checks exact request bytes, registered identity, schema/instrument bounds, freshness and increasing sequence. SQLite retains decisions and replay state across server restarts. CLI shows readings and rejection reasons.

This is integrity-only processing. No compatible sensor model has been supplied, and the existing network model cannot classify two sensor values. `prediction` and `confidence` are explicitly null. `motor_eligible=true` means these message checks passed, not that water is safe or a motor command was sent. Signed polling is implemented; physical motor firmware remains pending.

## Setup in PowerShell

Flask has been installed in the project virtual environment. Activate it before the commands below (or use `.venv/Scripts/python.exe` in place of `python`). For a new environment, install Flask:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install flask
```

Set the key to exactly the value provisioned in the sensor firmware, without entering it into command history:

```powershell
$sensorKeyInput = Read-Host 'Sensor HMAC key' -AsSecureString
$env:IIOT_SENSOR_KEY = [System.Net.NetworkCredential]::new('', $sensorKeyInput).Password
$env:IIOT_DEVICE_ID = 'ESP32_SENSOR_01'
python receiver.py
```

Use the laptop's hotspot IPv4 and port 5000 in firmware. Check hotspot client isolation and applicable inbound firewall rules if the board cannot connect. Starting this receiver does not change firewall rules. The key remains plaintext in process memory; replace the existing shared/exposed firmware key through coordinated provisioning before deployment.

Optional environment settings: `IIOT_PORT` (5000), `IIOT_DATABASE` (`output/receiver.sqlite3`). `GET /health` reports receiver/storage readiness and missing ML/controller integration. Freshness allows at most 30 seconds old or 10 seconds ahead of laptop time; synchronize clocks.

## Capture ESP32 packets on Laptop 2

Run the receiver and capture on the laptop receiving the ESP32 HTTP requests. Install Wireshark with TShark and Npcap on that laptop. No packet-forwarding code is needed on Laptop 1: the ESP32 sends over Wi-Fi directly to Laptop 2.

In the server terminal, first list interfaces (no HMAC key required for listing):

```powershell
.\.venv\Scripts\python.exe receiver.py --list-interfaces
```

Choose the Wi-Fi adapter connected to the phone hotspot. Interface 5 is Wi-Fi on the inspected machine; check the actual listing on Laptop 2 rather than assuming the same number.

With the sensor key configured as above, leave motor authorization disabled and start:

```powershell
$env:IIOT_ENABLE_MOTOR_DEMO = '0'
Remove-Item Env:\IIOT_MOTOR_KEY -ErrorAction SilentlyContinue
.\.venv\Scripts\python.exe receiver.py --capture-interface 5
```

Replace 5 as needed. `--tshark 'C:\Program Files\Wireshark\tshark.exe'` selects a different executable location; `--capture-dir PATH` selects the PCAP directory. `IIOT_CAPTURE_INTERFACE` can supply the interface instead of the CLI flag. Plain `receiver.py` still runs without capture unless that environment variable is set.

The terminal displays `PACKET source:port -> destination:port bytes=...` alongside ACCEPTED/REJECTED message decisions. Capture filters TCP traffic on the receiver port (5000 by default), including requests, responses, handshakes and retransmissions from any peer on that interface. These are packet observations, not additional independent sensor readings.

Full packets are saved under `output/captures/` as `.pcapng`; TShark assigns ring filenames based on the displayed run name. Open them in Wireshark and use Follow TCP Stream to reconstruct HTTP. A ring retains up to five files of about 10 MB per run. New starts create new runs, so old run files remain and need deliberate retention management. `*.tshark.log` records capture startup/errors and capture statistics when available.

`GET /health` includes `packet_capture.running`, `packets_observed`, last packet capture timestamp, filter and paths. A running process with zero packets does not establish correct interface visibility. If capture exits, health shows it stopped and CLI reports an error; sensor verification continues. Startup capture failure stops startup and points to its log. Check Npcap installation/permissions if access is denied; some installations require an elevated terminal. Ctrl+C stops the receiver and capture child; a forced shutdown may leave the last capture incomplete.

The capture is independent evidence collection. It does not classify network attacks or determine HMAC validity. The receiver still verifies the reconstructed request bytes. Network ML has not been enabled.

For tampering over Wi-Fi, run `simulate_tampering.py --url http://SERVER_LAPTOP_IP:5000/api/sensor` from Laptop 1. A test to `127.0.0.1` on Laptop 2 uses the loopback adapter instead, so select that interface to capture it.

Optional capture integration check with a loopback interface from the listing:

```powershell
.\.venv\Scripts\python.exe verify_receiver_capture.py --interface 9
```

This generates only local test traffic with a test key, verifies HTTP 200/401 behavior, and reads back saved packets. It uses temporary evidence files and does not change the physical sensor's database. Select the correct loopback number on your machine.

## Sequence reset limitation

The server now retains replay state. The current ESP32 firmware resets its sequence on reboot, so low sequences after reboot are rejected until they exceed the stored value. This requires coordinated persistent sequence handling or an authenticated session protocol in firmware/server; that protocol is not implemented yet.

Do not delete evidence or clear replay state to make live traffic pass. A separate fresh database is only a new labeled test run, not proof of reboot resilience. Server restart replay protection and sensor reboot recovery are different requirements.

## Verification and demonstration

```powershell
python -m unittest discover -s tests -p 'test_*.py' -v
```

Tests use temporary databases and test-only keys. Demonstrate a fresh authentic sample (200), body modification without a new signature (401), repeated accepted message (409), and a correctly signed stale timestamp (409). Restarting the server must not make the accepted sequence reusable.

### Live tampering demonstration

First confirm real sensor samples show ACCEPTED, so the shared key is known to match. Keep the receiver running. In a second terminal on the server laptop:

```powershell
cd C:\Users\manoj\Desktop\n8n\SIH-26
.\.venv\Scripts\python.exe simulate_tampering.py
```

If prompted, enter the same sensor HMAC key. The script signs a fabricated 26.5 C message, changes it to 40.0 C without updating the signature, and sends only the modified message. Expected: HTTP 401 INVALID_HMAC, a REJECTED log and a rejection decision in SQLite. It never submits the original valid message, so it does not advance the physical sensor's replay sequence.

From another laptop with this script and Python, specify the server laptop address:

```powershell
python simulate_tampering.py --url http://SERVER_LAPTOP_IP:5000/api/sensor
```

This deliberately constructed message demonstrates an integrity check, not interception of the real ESP32 connection. A wrong key produces the same rejection; confirming accepted real readings first is essential to interpreting the demo.

The current endpoint uses HTTP: it is not encrypted and does not authenticate the server. HMAC is not TLS. Certificate-validated HTTPS remains pending. ADC counts are not calibrated NTU, and accepted instrument ranges are not water-quality policy thresholds. Flask's development server is for this prototype.

## Motor polling demonstration

Choose a separate motor secret and set it in both server and simulator terminals through the same secure prompt pattern used for the sensor key:

```powershell
$motorKeyInput = Read-Host 'Separate motor HMAC key' -AsSecureString
$env:IIOT_MOTOR_KEY = [System.Net.NetworkCredential]::new('', $motorKeyInput).Password
$env:IIOT_MOTOR_DEVICE_ID = 'ESP32_MOTOR_01'
```

In the server terminal, explicitly enable integrity-only motor authorizations before starting/restarting the receiver:

```powershell
$env:IIOT_ENABLE_MOTOR_DEMO = '1'
python receiver.py
```

In the simulator terminal, activate the same environment, set the same motor key/ID, then run:

```powershell
$env:IIOT_SERVER_URL = 'http://127.0.0.1:5000'
python motor_simulator.py
```

Fresh accepted sensor samples can queue an authorization. The default ON duration is three seconds, command delivery expiry is ten seconds, and minimum authorization interval is fifteen seconds. A pending/delivered unexpired command suppresses another authorization. Bad messages create no new command but do not revoke a previously issued one. Disabling authorization requires restarting the server with `IIOT_ENABLE_MOTOR_DEMO` unset or `0`; previously queued unexpired commands can still be delivered.

The simulator polls every two seconds, verifies signatures/target/expiry/local duration, persists request sequences and seen commands, prints SIMULATOR ON/OFF, and sends authenticated completion. It never accesses GPIO or a physical motor. Failed ACK transmission leaves an uncertain server outcome and does not repeat the simulated ON. A server record of completion is an authenticated client report, not independent proof of movement.

Responses to sensor POSTs keep `motor_command_sent=false`: authorization has only been queued, not delivered/executed. A nonnull `motor_command_id` and `motor_status=queued_for_poll` indicate a queued command. Inspect command status/outcome in `output/receiver.sqlite3`.

GPIO 18 is the user-confirmed proposed motor output. Its active polarity and driver wiring remain unconfirmed. Port the tested polling contract below to ESP32 firmware and enforce a local watchdog/manual stop before physical integration.

## Polling protocol for ESP32 implementation

`POST /api/motor/poll` has an exact-byte HMAC header using the motor key, with a JSON body:

```json
{"message_type":"motor_poll","device_id":"ESP32_MOTOR_01","sequence":1,"timestamp":1793095200}
```

The timestamp is illustrative; use current Unix time. Polls and ACKs share one increasing request sequence, persisted across reboot. The server rejects timestamps over 30 seconds old or 10 seconds ahead, and rejects repeated/reset sequences.

The response envelope is `{"payload":"<exact JSON string>","hmac_sha256":"<signature>"}`. Verify HMAC over the UTF-8 bytes of the payload string before interpreting it. The signed payload includes `message_type=motor_poll_response`, device ID, echoed request sequence, issue time, and `command` (null or another signed envelope). Verify response freshness and request-sequence matching.

The nested command authenticates `message_type=motor_command`, schema version, target device, command ID, monotonic command sequence, issue/expiry time, `action=ON`, duration, source sensor-decision ID and policy version. Verify all local constraints and durably mark the command seen before starting an output. Redelivery returns the same command; it must not cause another ON.

After OFF, `POST /api/motor/ack` uses the same motor HMAC protocol with `message_type=motor_ack`, target device, increasing request sequence, current timestamp, command ID and outcome (`COMPLETED_OFF`, `REJECTED`, or `FAILED_OFF`). The response is also signed and echoes the request sequence. ACKs before delivery and conflicting completion reports are rejected. Missing acknowledgments leave execution uncertain.

The protocol remains HTTP in this prototype. Signed responses provide application integrity checks but not encryption. Sensor and motor keys must differ. The simulator is the runnable reference for this protocol; no motor firmware compilation or hardware run has been performed.
