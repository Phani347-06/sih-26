"""Integrity-only sensor receiver; see RECEIVER_DEMO.md."""
import hashlib
import argparse
import hmac
import json
import logging
import math
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import time
from contextlib import contextmanager
from flask import Flask, jsonify, request
from werkzeug.exceptions import RequestEntityTooLarge
from motor_service import register_motor

LOG = logging.getLogger("iiot.receiver")

def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate key")
        result[key] = value
    return result

def invalid_constant(value):
    raise ValueError("Nonfinite number")

@contextmanager
def connect(path):
    db = sqlite3.connect(path, timeout=5, isolation_level=None)
    try:
        yield db
    finally:
        db.close()

def create_app(config=None):
    app = Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=4096,
        DATABASE=os.environ.get("IIOT_DATABASE", str(Path(__file__).parent / "output" / "receiver.sqlite3")),
        SENSOR_KEY=os.environ.get("IIOT_SENSOR_KEY", ""),
        DEVICE_ID=os.environ.get("IIOT_DEVICE_ID", "ESP32_SENSOR_01"),
        MOTOR_KEY=os.environ.get("IIOT_MOTOR_KEY", ""),
        MOTOR_DEVICE_ID=os.environ.get("IIOT_MOTOR_DEVICE_ID", "ESP32_MOTOR_01"),
        ENABLE_MOTOR_DEMO=os.environ.get("IIOT_ENABLE_MOTOR_DEMO") == "1",
        MOTOR_DURATION_SECONDS=3)
    if config:
        app.config.update(config)
    secret = app.config["SENSOR_KEY"]
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    if not isinstance(secret, bytes) or not secret:
        raise ValueError("Set IIOT_SENSOR_KEY to the sensor firmware HMAC key before starting.")
    database = str(app.config["DATABASE"])
    Path(database).parent.mkdir(parents=True, exist_ok=True)
    with connect(database) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS replay_state (
            device_id TEXT PRIMARY KEY, last_sequence INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS telemetry_decisions (
            id INTEGER PRIMARY KEY, received_at REAL NOT NULL,
            payload_sha256 TEXT NOT NULL, device_id TEXT,
            sequence INTEGER, measured_at INTEGER, temperature_c REAL,
            turbidity_raw INTEGER, decision TEXT NOT NULL, reason TEXT NOT NULL);
        CREATE UNIQUE INDEX IF NOT EXISTS accepted_message
            ON telemetry_decisions(device_id, sequence) WHERE decision='ACCEPTED';
        """)

    authorize_motor = register_motor(app, connect, database, strict_object, invalid_constant)

    def record(db, raw, now, reason, data=None, accepted=False):
        data = data or {}
        sensors = data.get("sensors", {})
        return db.execute("""INSERT INTO telemetry_decisions
            (received_at,payload_sha256,device_id,sequence,measured_at,
             temperature_c,turbidity_raw,decision,reason) VALUES (?,?,?,?,?,?,?,?,?)""",
            (now, hashlib.sha256(raw).hexdigest(), data.get("device_id"),
             data.get("sequence"), data.get("timestamp"), sensors.get("temperature_c"),
             sensors.get("turbidity_raw"), "ACCEPTED" if accepted else "REJECTED", reason)).lastrowid

    def reject(raw, now, reason, status, data=None):
        with connect(database) as db:
            decision_id = record(db, raw, now, reason, data)
        LOG.warning("REJECTED reason=%s decision=%s", reason, decision_id)
        return jsonify(status="rejected", error=reason, reason=reason,
            decision_id=decision_id, motor_eligible=False, motor_command_sent=False), status

    @app.errorhandler(RequestEntityTooLarge)
    def oversized(error):
        LOG.warning("REJECTED reason=PAYLOAD_TOO_LARGE")
        return jsonify(status="rejected", reason="PAYLOAD_TOO_LARGE",
            motor_eligible=False, motor_command_sent=False), 413

    @app.errorhandler(sqlite3.Error)
    def storage_error(error):
        LOG.error("STORAGE_UNAVAILABLE: %s", type(error).__name__)
        return jsonify(status="unavailable", reason="STORAGE_UNAVAILABLE",
            motor_eligible=False, motor_command_sent=False), 503

    @app.get("/health")
    def health():
        with connect(database) as db:
            db.execute("SELECT COUNT(*) FROM replay_state").fetchone()
        capture = app.extensions.get("packet_capture")
        return jsonify(status="ok", mode="integrity_only", sensor_ml="not_configured",
            packet_capture=capture.status() if capture else {"enabled": False, "running": False},
            motor_delivery="signed_polling" if app.config["MOTOR_KEY"] else "not_configured",
            motor_authorization_enabled=app.config["ENABLE_MOTOR_DEMO"])

    @app.post("/api/sensor")
    def receive_sensor():
        raw = request.get_data()
        now = time.time()
        signature = request.headers.get("X-HMAC-SHA256", "")
        expected = hmac.new(secret, raw, hashlib.sha256).hexdigest()
        if not re.fullmatch(r"[0-9a-fA-F]{64}", signature) or not hmac.compare_digest(expected, signature.lower()):
            return reject(raw, now, "INVALID_HMAC", 401)
        try:
            data = json.loads(raw, object_pairs_hook=strict_object, parse_constant=invalid_constant)
            if not isinstance(data, dict):
                raise ValueError("Expected object")
            device, timestamp, sequence = data["device_id"], data["timestamp"], data["sequence"]
            sensors = data["sensors"]
            if not isinstance(device, str) or len(device) > 128:
                raise ValueError("Invalid device")
            if type(timestamp) is not int or not 0 <= timestamp < 2**63:
                raise ValueError("Invalid timestamp")
            if type(sequence) is not int or not 1 <= sequence <= 0xFFFFFFFF:
                raise ValueError("Invalid sequence")
            if not isinstance(sensors, dict):
                raise ValueError("Invalid sensors")
            turbidity, temperature = sensors["turbidity_raw"], sensors["temperature_c"]
            if type(turbidity) is not int or type(temperature) not in (int, float):
                raise ValueError("Invalid sensor types")
            if not math.isfinite(temperature):
                raise ValueError("Invalid temperature")
        except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
            return reject(raw, now, "INVALID_JSON_OR_SCHEMA", 400)
        if device != app.config["DEVICE_ID"]:
            return reject(raw, now, "UNREGISTERED_DEVICE", 403)
        if not (0 <= turbidity <= 4095 and -55 <= temperature <= 125):
            return reject(raw, now, "SENSOR_VALUES_OUT_OF_RANGE", 400)
        if not -10 <= now - timestamp <= 30:
            return reject(raw, now, "INVALID_TIMESTAMP", 409, data)
        # Serialize comparison + state update + decision across concurrent requests.
        with connect(database) as db:
            try:
                db.execute("BEGIN IMMEDIATE")
                prior = db.execute("SELECT last_sequence FROM replay_state WHERE device_id=?", (device,)).fetchone()
                if prior and sequence <= prior[0]:
                    reason = "REPLAY_OR_SEQUENCE_RESET"
                    decision_id = record(db, raw, now, reason, data)
                    db.commit()
                    LOG.warning("REJECTED device=%s sequence=%s reason=%s", device, sequence, reason)
                    return jsonify(status="rejected", error=reason, reason=reason,
                        decision_id=decision_id, motor_eligible=False, motor_command_sent=False), 409
                db.execute("""INSERT INTO replay_state VALUES (?,?)
                    ON CONFLICT(device_id) DO UPDATE SET last_sequence=excluded.last_sequence""", (device, sequence))
                decision_id = record(db, raw, now, "VERIFIED_INTEGRITY_ONLY", data, True)
                command_id = authorize_motor(db, decision_id, now)
                db.commit()
            except Exception:
                db.rollback()
                raise
        LOG.info("ACCEPTED device=%s sequence=%s temperature_c=%s turbidity_raw=%s decision=%s motor_command=%s",
                 device, sequence, temperature, turbidity, decision_id, command_id or "NONE")
        return jsonify(status="success", device_id=device, decision_id=decision_id,
            integrity="verified", freshness="verified", replay="not_seen",
            temperature_c=temperature, turbidity_raw=turbidity,
            mode="integrity_only", water_quality="not_assessed",
            prediction=None, confidence=None, sensor_ml="not_configured",
            motor_eligible=True, motor_command_sent=False, motor_command_id=command_id,
            motor_status="queued_for_poll" if command_id else "not_queued"), 200
    return app

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Sensor receiver with optional packet capture on this laptop")
    parser.add_argument("--list-interfaces", action="store_true", help="List TShark interfaces without starting the receiver")
    parser.add_argument("--capture-interface", default=os.environ.get("IIOT_CAPTURE_INTERFACE"),
                        help="TShark interface number/name on the SERVER laptop")
    parser.add_argument("--tshark", default=os.environ.get("IIOT_TSHARK"), help="Path to tshark executable")
    parser.add_argument("--capture-dir", default=str(Path(__file__).parent / "output" / "captures"))
    args = parser.parse_args()
    capture = None
    try:
        from receiver_capture import ReceiverCapture, find_tshark, list_interfaces
        if args.list_interfaces:
            print(list_interfaces(find_tshark(args.tshark)))
            raise SystemExit(0)
        application = create_app()
        port = int(os.environ.get("IIOT_PORT", "5000"))
        if args.capture_interface:
            capture = ReceiverCapture(find_tshark(args.tshark), args.capture_interface, port, args.capture_dir)
            capture.start()
            application.extensions["packet_capture"] = capture
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        raise SystemExit(str(error))
    LOG.warning("Integrity-only HTTP prototype; motor authorization enabled=%s.", application.config["ENABLE_MOTOR_DEMO"])
    LOG.warning("Sensor reboot sequence resets are rejected; see RECEIVER_DEMO.md.")
    try:
        application.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
    finally:
        if capture:
            capture.stop()
