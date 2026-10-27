from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from receiver_capture import ReceiverCapture, find_tshark, list_interfaces


class CaptureTests(unittest.TestCase):
    def test_command_limits_capture_to_receiver_and_bounded_files(self):
        capture = ReceiverCapture("tshark", "Wi-Fi", 5000, "output/captures")
        capture.capture_path = Path("output/captures/test.pcapng")
        command = capture.command()
        self.assertEqual(command[command.index("-i") + 1], "Wi-Fi")
        self.assertEqual(command[command.index("-f") + 1], "tcp port 5000")
        self.assertIn("filesize:10240", command)
        self.assertIn("files:5", command)
        self.assertIn("-P", command)
        self.assertIn("-w", command)

    def test_missing_executable_has_actionable_error(self):
        with self.assertRaisesRegex(ValueError, "TShark not found"):
            find_tshark("definitely_missing_tshark.exe")

    def test_interface_failure_reports_permissions(self):
        with patch("receiver_capture.subprocess.run", return_value=subprocess.CompletedProcess(
                ["tshark", "-D"], 1, stdout="", stderr="Npcap access denied")):
            with self.assertRaisesRegex(ValueError, "Npcap access denied"):
                list_interfaces("tshark")

    def test_unstarted_capture_is_not_reported_running(self):
        capture = ReceiverCapture("tshark", "5", 5000, "output/captures")
        self.assertFalse(capture.status()["running"])
        self.assertEqual(capture.status()["packets_observed"], 0)
        capture.stop()

    def test_start_failure_closes_log(self):
        with tempfile.TemporaryDirectory() as folder:
            capture = ReceiverCapture("missing.exe", "5", 5000, folder)
            with patch("receiver_capture.subprocess.Popen", side_effect=FileNotFoundError):
                with self.assertRaises(FileNotFoundError):
                    capture.start()
            self.assertTrue(capture.log_file.closed)


if __name__ == "__main__":
    unittest.main()
