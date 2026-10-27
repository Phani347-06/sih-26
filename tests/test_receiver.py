import hashlib
import hmac
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing

from receiver import create_app


class ReceiverTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = str(Path(folder.name) / "test.sqlite3")
        self.config = {"TESTING": True, "DATABASE": self.path,
                       "SENSOR_KEY": b"test-only-key", "DEVICE_ID": "sensor-test",
                       "MOTOR_KEY": "", "ENABLE_MOTOR_DEMO": False}
        self.app = create_app(self.config)

    def body(self, **overrides):
        body = {"device_id": "sensor-test", "timestamp": int(time.time()),
                "sequence": 1, "sensors": {"temperature_c": 26.5, "turbidity_raw": 1800}}
        body.update(overrides)
        return json.dumps(body, separators=(",", ":")).encode()

    def send(self, raw, signature=None, app=None):
        if signature is None:
            signature = hmac.new(b"test-only-key", raw, hashlib.sha256).hexdigest()
        with (app or self.app).test_client() as client:
            return client.post("/api/sensor", data=raw, content_type="application/json",
                               headers={"X-HMAC-SHA256": signature})

    def test_valid_records_integrity_without_claiming_motor_or_ml(self):
        response = self.send(self.body())
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["motor_eligible"])
        self.assertFalse(response.json["motor_command_sent"])
        self.assertIsNone(response.json["prediction"])
        with closing(sqlite3.connect(self.path)) as db:
            count = db.execute("SELECT COUNT(*) FROM telemetry_decisions "
                               "WHERE decision='ACCEPTED'").fetchone()[0]
        self.assertEqual(count, 1)

    def test_tampering_and_missing_signature(self):
        raw = self.body()
        signature = hmac.new(b"test-only-key", raw, hashlib.sha256).hexdigest()
        self.assertEqual(self.send(raw.replace(b"1800", b"1801"), signature).status_code, 401)
        self.assertEqual(self.send(raw, "").status_code, 401)
        self.assertEqual(self.send(raw).status_code, 200)

    def test_replay_survives_server_restart(self):
        raw = self.body()
        self.assertEqual(self.send(raw).status_code, 200)
        restarted = create_app(self.config)
        self.assertEqual(self.send(raw, app=restarted).status_code, 409)
        self.assertEqual(self.send(self.body(sequence=2), app=restarted).status_code, 200)

    def test_stale_and_future_do_not_advance_sequence(self):
        for offset in (-60, 60):
            self.assertEqual(self.send(self.body(timestamp=int(time.time()) + offset)).status_code, 409)
        self.assertEqual(self.send(self.body()).status_code, 200)

    def test_unknown_identity(self):
        self.assertEqual(self.send(self.body(device_id="unregistered")).status_code, 403)

    def test_types_bounds_and_duplicate_json_keys(self):
        bodies = [self.body(sequence=True), self.body(sequence="1"),
                  self.body(sensors={"temperature_c": float("nan"), "turbidity_raw": 100}),
                  self.body(sensors={"temperature_c": 26, "turbidity_raw": 4096}),
                  self.body(sensors={"temperature_c": -127, "turbidity_raw": 100}),
                  b'[]', b'{"sequence":1,"sequence":2}', b'null']
        for body in bodies:
            with self.subTest(raw=body):
                self.assertEqual(self.send(body).status_code, 400)

    def test_concurrent_duplicate_accepts_once(self):
        raw = self.body()
        with ThreadPoolExecutor(max_workers=4) as pool:
            statuses = list(pool.map(lambda _: self.send(raw).status_code, range(4)))
        self.assertEqual(sorted(statuses), [200, 409, 409, 409])

    def test_sensor_reboot_sequence_reset_rejected(self):
        self.assertEqual(self.send(self.body(sequence=10)).status_code, 200)
        self.assertEqual(self.send(self.body(sequence=1)).status_code, 409)

    def test_payload_limit(self):
        response = self.send(b"x" * 5000)
        self.assertEqual(response.status_code, 413)
        self.assertFalse(response.json["motor_eligible"])

    def test_storage_failure_never_authorizes(self):
        Path(self.path).unlink()
        response = self.send(self.body())
        self.assertEqual(response.status_code, 503)
        self.assertFalse(response.json["motor_eligible"])

    def test_missing_key_fails_startup(self):
        with self.assertRaises(ValueError):
            create_app({**self.config, "SENSOR_KEY": ""})


if __name__ == "__main__":
    unittest.main()
