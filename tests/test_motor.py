import hashlib
import hmac
import json
from pathlib import Path
import tempfile
import time
import unittest

from receiver import create_app, connect


class MotorTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = str(Path(folder.name) / "test.sqlite3")
        self.key = b"motor-test-only"
        self.app = create_app({"TESTING": True, "DATABASE": self.path,
            "SENSOR_KEY": b"sensor-test-only", "MOTOR_KEY": self.key,
            "DEVICE_ID": "sensor", "MOTOR_DEVICE_ID": "motor", "ENABLE_MOTOR_DEMO": True})

    def post(self, path, body, key=None):
        raw = json.dumps(body, separators=(",", ":")).encode()
        signature = hmac.new(key or self.key, raw, hashlib.sha256).hexdigest()
        with self.app.test_client() as client:
            return client.post(path, data=raw, headers={"X-HMAC-SHA256": signature})

    def sample(self, sequence=1):
        return self.post("/api/sensor", {"device_id": "sensor", "timestamp": int(time.time()),
            "sequence": sequence, "sensors": {"temperature_c": 25, "turbidity_raw": 1000}}, b"sensor-test-only")

    def poll(self, sequence=1):
        return self.post("/api/motor/poll", {"message_type": "motor_poll",
            "device_id": "motor", "timestamp": time.time(), "sequence": sequence})

    def unpack(self, envelope):
        expected = hmac.new(self.key, envelope["payload"].encode(), hashlib.sha256).hexdigest()
        self.assertTrue(hmac.compare_digest(expected, envelope["hmac_sha256"]))
        return json.loads(envelope["payload"])

    def test_signed_command_redelivery_ack_and_no_repeat_effect(self):
        sample = self.sample()
        self.assertEqual(sample.status_code, 200)
        self.assertIsNotNone(sample.json["motor_command_id"])
        self.assertFalse(sample.json["motor_command_sent"])
        outer = self.unpack(self.poll().json)
        self.assertEqual(outer["request_sequence"], 1)
        command = self.unpack(outer["command"])
        self.assertEqual(command["action"], "ON")
        self.assertLessEqual(command["duration_seconds"], 5)
        self.assertGreater(command["expires_at"], time.time())
        again = self.unpack(self.poll(2).json)
        self.assertEqual(again["command"], outer["command"])
        ack = self.post("/api/motor/ack", {"message_type": "motor_ack", "device_id": "motor",
            "timestamp": time.time(), "sequence": 3, "command_id": command["command_id"],
            "outcome": "COMPLETED_OFF"})
        self.assertEqual(ack.status_code, 200)
        self.assertIsNone(self.unpack(self.poll(4).json)["command"])
        self.assertIsNone(self.sample(2).json["motor_command_id"])

    def test_motor_request_authentication_and_replay(self):
        self.assertEqual(self.poll().status_code, 200)
        self.assertEqual(self.poll().status_code, 409)
        result = self.post("/api/motor/poll", {"message_type": "motor_poll",
            "device_id": "motor", "timestamp": time.time(), "sequence": 2}, b"wrong")
        self.assertEqual(result.status_code, 401)

    def test_expired_command_is_not_delivered(self):
        self.sample()
        with connect(self.path) as db:
            db.execute("UPDATE motor_commands SET expires_at=?", (time.time() - 1,))
        self.assertIsNone(self.unpack(self.poll().json)["command"])

    def test_ack_for_undelivered_command_rejected(self):
        command_id = self.sample().json["motor_command_id"]
        result = self.post("/api/motor/ack", {"message_type": "motor_ack", "device_id": "motor",
            "timestamp": time.time(), "sequence": 1, "command_id": command_id,
            "outcome": "COMPLETED_OFF"})
        self.assertEqual(result.status_code, 409)

    def test_rejected_sensor_cannot_create_command(self):
        self.post("/api/sensor", {"sequence": 1}, b"wrong")
        self.assertIsNone(self.unpack(self.poll().json)["command"])


if __name__ == "__main__":
    unittest.main()
