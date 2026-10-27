"""Local integration check: capture generated test HTTP traffic, no hardware required."""

import argparse
import hashlib
import hmac
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from werkzeug.serving import make_server

from receiver import create_app
from receiver_capture import ReceiverCapture, find_tshark


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", required=True, help="Loopback interface from receiver.py --list-interfaces")
    args = parser.parse_args()
    executable = find_tshark()
    output = Path(__file__).parent / "output"
    output.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="capture_check_", dir=output) as folder:
        key = b"capture-test-only-not-a-device-key"
        app = create_app({"DATABASE": str(Path(folder) / "test.sqlite3"), "SENSOR_KEY": key,
                          "MOTOR_KEY": "", "ENABLE_MOTOR_DEMO": False, "DEVICE_ID": "capture-test"})
        server = make_server("127.0.0.1", 0, app)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        capture = ReceiverCapture(executable, args.interface, server.server_port, folder)
        thread.start()
        try:
            capture.start()
            # Allow the Npcap interface to finish initializing before emitting the fixture.
            time.sleep(2)
            raw = json.dumps({"device_id": "capture-test", "timestamp": int(time.time()),
                "sequence": 1, "sensors": {"temperature_c": 26.5, "turbidity_raw": 1800}}, separators=(",", ":")).encode()
            signature = hmac.new(key, raw, hashlib.sha256).hexdigest()
            statuses = []
            for body in (raw, raw.replace(b"26.5", b"40.0")):
                req = Request(f"http://127.0.0.1:{server.server_port}/api/sensor", data=body,
                              headers={"Content-Type": "application/json", "X-HMAC-SHA256": signature})
                try:
                    with urlopen(req, timeout=5) as response:
                        statuses.append(response.status)
                        response.read()
                except HTTPError as error:
                    statuses.append(error.code)
                    error.read()
            deadline = time.monotonic() + 5
            while capture.packet_count == 0 and capture.process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.1)
            if statuses != [200, 401]:
                raise RuntimeError(f"Unexpected receiver results: {statuses}")
            # Let dumpcap/TShark flush the short burst before stopping the process.
            time.sleep(2)
        finally:
            capture.stop()
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
        files = list(Path(folder).glob("*.pcapng"))
        if not files or capture.packet_count == 0:
            detail = capture.error_path.read_text(encoding="utf-8", errors="replace")
            raise RuntimeError("No captured packets. Check loopback interface/Npcap. " + detail)
        packets = []
        http_results = []
        for path in files:
            decoded = subprocess.run([executable, "-n", "-r", str(path), "-T", "fields",
                "-e", "frame.number", "-e", "tcp.dstport"], capture_output=True, text=True, timeout=15)
            if decoded.returncode:
                raise RuntimeError(decoded.stderr)
            packets.extend(line for line in decoded.stdout.splitlines() if line.strip())
            http = subprocess.run([executable, "-n", "-r", str(path),
                "-d", f"tcp.port=={server.server_port},http", "-T", "fields",
                "-e", "http.request.method", "-e", "http.response.code"],
                capture_output=True, text=True, timeout=15)
            if http.returncode:
                raise RuntimeError(http.stderr)
            http_results.extend(line for line in http.stdout.splitlines() if line.strip())
        if not packets:
            raise RuntimeError("Saved PCAP was empty.")
        if sum("POST" in line for line in http_results) != 2 or not any("401" in line for line in http_results):
            raise RuntimeError(f"Capture did not retain both HTTP requests and rejection response: {http_results}")
        print(json.dumps({"receiver_statuses": statuses, "live_packet_summaries": capture.packet_count,
                          "readable_saved_packets": len(packets), "result": "PASS"}))


if __name__ == "__main__":
    main()
