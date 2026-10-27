"""Send an intentionally modified message to demonstrate HMAC rejection."""

import argparse
import getpass
import hashlib
import hmac
import json
import os
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:5000/api/sensor",
                        help="Receiver endpoint; use the server laptop IP from another laptop")
    args = parser.parse_args()
    key = os.environ.get("IIOT_SENSOR_KEY") or getpass.getpass("Sensor HMAC key (hidden): ")
    if not key:
        raise SystemExit("A key is required. Use the same key as the receiver/firmware.")

    original = json.dumps({
        "device_id": os.environ.get("IIOT_DEVICE_ID", "ESP32_SENSOR_01"),
        "timestamp": int(time.time()), "sequence": 1,
        "sensors": {"turbidity_raw": 1800, "temperature_c": 26.5},
    }, separators=(",", ":")).encode()
    signature = hmac.new(key.encode(), original, hashlib.sha256).hexdigest()

    # Simulate changing the transmitted body without possession/use of the signing key.
    modified = original.replace(b'"temperature_c":26.5', b'"temperature_c":40.0')
    assert modified != original
    print("SIMULATION: sign temperature 26.5 C, then change it to 40.0 C.")
    print("Send the changed body with the ORIGINAL signature.")
    print("The original valid message is NOT sent; live sequence state is not advanced.")
    req = Request(args.url, data=modified, method="POST", headers={
        "Content-Type": "application/json", "X-HMAC-SHA256": signature,
    })
    try:
        with urlopen(req, timeout=5) as response:
            status, body = response.status, response.read()
    except HTTPError as error:
        status, body = error.code, error.read()
    except URLError as error:
        raise SystemExit(f"Cannot reach receiver: {error.reason}. Check IP, port, hotspot and server.")
    print(f"HTTP {status}")
    print(body.decode("utf-8", errors="replace"))
    try:
        result = json.loads(body)
    except ValueError:
        raise SystemExit("Unexpected response: this may not be the intended receiver.")
    if status != 401 or result.get("reason") != "INVALID_HMAC":
        raise SystemExit("Unexpected result: expected HTTP 401 INVALID_HMAC.")
    print("PASS: altered message rejected. No valid sample or motor authorization created.")
    print("A wrong supplied key also causes INVALID_HMAC; confirm live ESP32 samples are accepted first.")


if __name__ == "__main__":
    main()
