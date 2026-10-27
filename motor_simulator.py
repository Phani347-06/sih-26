"""Polling client protocol demonstration. Never operates a GPIO or physical motor."""

import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import time
from urllib.request import Request, urlopen


def verify(envelope, key):
    payload = envelope["payload"]
    expected = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, envelope["hmac_sha256"]):
        raise ValueError("Invalid server signature")
    return json.loads(payload)


def main():
    key = os.environ.get("IIOT_MOTOR_KEY", "").encode()
    if not key:
        raise SystemExit("Set IIOT_MOTOR_KEY to the receiver's separate motor key.")
    device = os.environ.get("IIOT_MOTOR_DEVICE_ID", "ESP32_MOTOR_01")
    base = os.environ.get("IIOT_SERVER_URL", "http://127.0.0.1:5000").rstrip("/")
    path = Path(os.environ.get("IIOT_SIM_DATABASE", "output/motor_simulator.sqlite3"))
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS sequence (id INTEGER PRIMARY KEY CHECK(id=1), value INTEGER NOT NULL);
        INSERT OR IGNORE INTO sequence VALUES (1,0);
        CREATE TABLE IF NOT EXISTS seen (command_id TEXT PRIMARY KEY, command_sequence INTEGER NOT NULL UNIQUE);
    """)

    def exchange(route, kind, **extra):
        db.execute("UPDATE sequence SET value=value+1 WHERE id=1")
        sequence = db.execute("SELECT value FROM sequence WHERE id=1").fetchone()[0]
        db.commit()
        body = json.dumps({"device_id": device, "message_type": kind,
            "sequence": sequence, "timestamp": time.time(), **extra}, separators=(",", ":")).encode()
        signature = hmac.new(key, body, hashlib.sha256).hexdigest()
        req = Request(base + route, data=body, headers={"Content-Type": "application/json", "X-HMAC-SHA256": signature})
        with urlopen(req, timeout=5) as response:
            result = verify(json.load(response), key)
        if (result["device_id"] != device or result["request_sequence"] != sequence
                or result["message_type"] != kind + "_response"
                or not -10 <= time.time() - result["issued_at"] <= 30):
            raise ValueError("Wrong/stale response")
        return result

    print("SIMULATOR ONLY: physical motor and GPIO 18 are not operated.", flush=True)
    try:
        while True:
            try:
                response = exchange("/api/motor/poll", "motor_poll")
                if response["command"]:
                    command = verify(response["command"], key)
                    now = time.time()
                    if (command["device_id"] != device or command["message_type"] != "motor_command"
                            or command["schema_version"] != 1 or command["action"] != "ON"
                            or not command["issued_at"] <= now <= command["expires_at"]
                            or type(command["duration_seconds"]) not in (int, float)
                            or not 0 < command["duration_seconds"] <= 5):
                        raise ValueError("Command violates local constraints")
                    latest = db.execute("SELECT MAX(command_sequence) FROM seen").fetchone()[0] or 0
                    if command["sequence"] <= latest:
                        print("SIMULATOR: repeated/old command ignored", flush=True)
                    else:
                        # Persist before the simulated effect. A crash must not repeat ON.
                        db.execute("INSERT INTO seen VALUES (?,?)", (command["command_id"], command["sequence"]))
                        db.commit()
                        print("SIMULATOR ON", command["command_id"], flush=True)
                        time.sleep(command["duration_seconds"])
                        print("SIMULATOR OFF", flush=True)
                        exchange("/api/motor/ack", "motor_ack", command_id=command["command_id"], outcome="COMPLETED_OFF")
                time.sleep(2)
            except Exception as error:
                print("SIMULATOR: no new actuation;", type(error).__name__, str(error), flush=True)
                time.sleep(2)
    except KeyboardInterrupt:
        print("SIMULATOR stopped; no physical output was used.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
