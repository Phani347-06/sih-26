"""Signed motor polling protocol for the integrity-only demonstration."""

import hashlib
import hmac
import json
import math
import re
import time
import uuid

from flask import jsonify, request


def register_motor(app, connect, database, strict_object, invalid_constant):
    key = app.config["MOTOR_KEY"]
    if isinstance(key, str):
        key = key.encode()
    enabled = app.config["ENABLE_MOTOR_DEMO"]
    if enabled and not key:
        raise ValueError("IIOT_MOTOR_KEY is required to enable motor authorization.")
    if app.config["MOTOR_DEVICE_ID"] == app.config["DEVICE_ID"]:
        raise ValueError("Sensor and motor device IDs must differ.")
    sensor_key = app.config["SENSOR_KEY"]
    if isinstance(sensor_key, str):
        sensor_key = sensor_key.encode()
    if key and key == sensor_key:
        raise ValueError("Motor and sensor must use separate keys.")
    duration = app.config["MOTOR_DURATION_SECONDS"]
    if not 0 < duration <= 5:
        raise ValueError("Demo motor duration must be greater than zero and at most five seconds.")
    with connect(database) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS motor_commands (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            command_id TEXT NOT NULL UNIQUE,
            sensor_decision_id INTEGER NOT NULL UNIQUE,
            issued_at REAL NOT NULL, expires_at REAL NOT NULL,
            payload TEXT NOT NULL, signature TEXT NOT NULL,
            status TEXT NOT NULL, outcome TEXT
        );
        CREATE TABLE IF NOT EXISTS motor_requests (
            device_id TEXT PRIMARY KEY, last_sequence INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS motor_audit (
            id INTEGER PRIMARY KEY, received_at REAL NOT NULL,
            request_sha256 TEXT NOT NULL, reason TEXT NOT NULL
        );
        """)

    def signed(payload):
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        return {"payload": body, "hmac_sha256": hmac.new(key, body.encode(), hashlib.sha256).hexdigest()}

    def authorize(db, decision_id, now):
        if not enabled:
            return None
        # A delivered command may have run. Never treat its expired ACK as proof of no actuation.
        db.execute("UPDATE motor_commands SET status='EXPIRED', outcome='UNKNOWN' "
                   "WHERE status IN ('PENDING','DELIVERED') AND expires_at < ?", (now,))
        latest = db.execute("SELECT issued_at,status FROM motor_commands ORDER BY sequence DESC LIMIT 1").fetchone()
        if latest and (latest[1] in ("PENDING", "DELIVERED") or now - latest[0] < 15):
            return None
        command_id = uuid.uuid4().hex
        expires = now + 10
        cursor = db.execute("""INSERT INTO motor_commands
            (command_id,sensor_decision_id,issued_at,expires_at,payload,signature,status)
            VALUES (?,?,?,?,?,?,'PENDING')""", (command_id, decision_id, now, expires, "", ""))
        envelope = signed({"schema_version": 1, "message_type": "motor_command",
            "device_id": app.config["MOTOR_DEVICE_ID"], "command_id": command_id,
            "sequence": cursor.lastrowid, "issued_at": now, "expires_at": expires,
            "action": "ON", "duration_seconds": duration,
            "sensor_decision_id": decision_id, "policy": "integrity_only_demo_v1"})
        db.execute("UPDATE motor_commands SET payload=?,signature=? WHERE command_id=?",
                   (envelope["payload"], envelope["hmac_sha256"], command_id))
        return command_id

    def dispatch(kind):
        now = time.time()
        raw = request.get_data()
        digest = hashlib.sha256(raw).hexdigest()

        def failure(reason, status):
            with connect(database) as db:
                db.execute("INSERT INTO motor_audit(received_at,request_sha256,reason) VALUES (?,?,?)",
                           (now, digest, reason))
            return jsonify(status="rejected", reason=reason), status

        if not key:
            return failure("MOTOR_NOT_CONFIGURED", 503)
        signature = request.headers.get("X-HMAC-SHA256", "")
        expected = hmac.new(key, raw, hashlib.sha256).hexdigest()
        if not re.fullmatch(r"[0-9a-fA-F]{64}", signature) or not hmac.compare_digest(signature.lower(), expected):
            return failure("INVALID_HMAC", 401)
        try:
            data = json.loads(raw, object_pairs_hook=strict_object, parse_constant=invalid_constant)
            if not isinstance(data, dict) or data["message_type"] != kind:
                raise ValueError("Invalid message type")
            if data["device_id"] != app.config["MOTOR_DEVICE_ID"]:
                return failure("WRONG_DEVICE", 403)
            seq, stamp = data["sequence"], data["timestamp"]
            if type(seq) is not int or not 1 <= seq < 2**63:
                raise ValueError("Invalid sequence")
            if type(stamp) not in (int, float) or not math.isfinite(stamp):
                raise ValueError("Invalid timestamp")
            if kind == "motor_ack" and (not isinstance(data["command_id"], str)
                    or len(data["command_id"]) != 32
                    or data["outcome"] not in ("COMPLETED_OFF", "REJECTED", "FAILED_OFF")):
                raise ValueError("Invalid ACK")
        except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
            return failure("INVALID_SCHEMA", 400)
        if not -10 <= now - stamp <= 30:
            return failure("INVALID_TIMESTAMP", 409)
        with connect(database) as db:
            try:
                db.execute("BEGIN IMMEDIATE")
                prior = db.execute("SELECT last_sequence FROM motor_requests WHERE device_id=?",
                                   (data["device_id"],)).fetchone()
                if prior and seq <= prior[0]:
                    db.rollback()
                    return failure("REPLAY_OR_SEQUENCE_RESET", 409)
                command = None
                if kind == "motor_ack":
                    row = db.execute("SELECT status,outcome FROM motor_commands WHERE command_id=?",
                                     (data["command_id"],)).fetchone()
                    if not row or row[0] == "PENDING":
                        db.rollback()
                        return failure("COMMAND_NOT_DELIVERED", 409)
                    if row[0] == "ACKNOWLEDGED" and row[1] != data["outcome"]:
                        db.rollback()
                        return failure("CONFLICTING_ACK", 409)
                    db.execute("UPDATE motor_commands SET status='ACKNOWLEDGED',outcome=? WHERE command_id=?",
                               (data["outcome"], data["command_id"]))
                else:
                    db.execute("UPDATE motor_commands SET status='EXPIRED',outcome='UNKNOWN' "
                               "WHERE status IN ('PENDING','DELIVERED') AND expires_at < ?", (now,))
                    row = db.execute("SELECT command_id,payload,signature FROM motor_commands "
                                     "WHERE status IN ('PENDING','DELIVERED') ORDER BY sequence LIMIT 1").fetchone()
                    if row:
                        command = {"payload": row[1], "hmac_sha256": row[2]}
                        db.execute("UPDATE motor_commands SET status='DELIVERED' WHERE command_id=?", (row[0],))
                db.execute("INSERT INTO motor_requests VALUES (?,?) ON CONFLICT(device_id) "
                           "DO UPDATE SET last_sequence=excluded.last_sequence", (data["device_id"], seq))
                db.execute("INSERT INTO motor_audit(received_at,request_sha256,reason) VALUES (?,?,?)",
                           (now, digest, kind.upper() + '_ACCEPTED'))
                db.commit()
            except Exception:
                db.rollback()
                raise
        return jsonify(signed({"schema_version": 1, "message_type": kind + "_response",
            "device_id": data["device_id"], "request_sequence": seq,
            "issued_at": now, "command": command, "status": "ok"}))

    app.add_url_rule("/api/motor/poll", "motor_poll", lambda: dispatch("motor_poll"), methods=["POST"])
    app.add_url_rule("/api/motor/ack", "motor_ack", lambda: dispatch("motor_ack"), methods=["POST"])
    return authorize
