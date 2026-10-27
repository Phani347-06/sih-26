"""Optional TShark capture on the receiving laptop, independent of HMAC checks."""

import logging
from pathlib import Path
import shutil
import subprocess
import threading
import time
import uuid

LOG = logging.getLogger("iiot.capture")
FIELDS = ["frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
          "tcp.srcport", "tcp.dstport", "frame.len"]


def find_tshark(explicit=None):
    candidate = explicit or shutil.which("tshark") or r"C:\Program Files\Wireshark\tshark.exe"
    if not Path(candidate).is_file():
        raise ValueError("TShark not found. Install Wireshark/TShark with Npcap or use --tshark PATH.")
    return str(Path(candidate).resolve())


def list_interfaces(executable):
    result = subprocess.run([executable, "-D"], capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise ValueError(result.stderr.strip() or "Cannot list capture interfaces; check Npcap permissions.")
    return result.stdout


class ReceiverCapture:
    def __init__(self, executable, interface, port, output_dir):
        if not interface or not 1 <= port <= 65535:
            raise ValueError("Capture requires an interface and valid server port.")
        self.executable = executable
        self.interface = str(interface)
        self.port = port
        self.output_dir = Path(output_dir).resolve()
        self.process = None
        self.log_file = None
        self.reader = None
        self.packet_count = 0
        self.last_packet_at = None
        self.stopped = False
        self.capture_path = None
        self.error_path = None

    def command(self):
        command = [self.executable, "-n", "-l", "-p", "-i", self.interface,
                   "-f", f"tcp port {self.port}",
                   "-b", "filesize:10240", "-b", "files:5",
                   "-w", str(self.capture_path), "-P", "-T", "fields",
                   "-E", "separator=/t", "-E", "occurrence=f"]
        for field in FIELDS:
            command.extend(["-e", field])
        return command

    def start(self):
        self.output_dir.mkdir(parents=True, exist_ok=True)
        run_id = time.strftime("%Y%m%d_%H%M%S", time.gmtime()) + "_" + uuid.uuid4().hex[:8]
        self.capture_path = self.output_dir / f"sensor_{run_id}.pcapng"
        self.error_path = self.output_dir / f"sensor_{run_id}.tshark.log"
        self.log_file = self.error_path.open("w", encoding="utf-8")
        try:
            self.process = subprocess.Popen(self.command(), stdout=subprocess.PIPE,
                stderr=self.log_file, text=True, encoding="utf-8", errors="replace", bufsize=1)
            self.reader = threading.Thread(target=self._read, name="receiver-packets", daemon=True)
            self.reader.start()
            time.sleep(0.5)
            if self.process.poll() is not None:
                raise ValueError(f"TShark exited ({self.process.returncode}); inspect {self.error_path}")
        except Exception:
            self.stop()
            raise
        LOG.info("Capture started: interface=%s filter='tcp port %s' directory=%s",
                 self.interface, self.port, self.output_dir)
        LOG.info("PCAP ring: five files of about 10 MB per run; no packets observed until counter increases.")

    def _read(self):
        try:
            for line in self.process.stdout:
                values = line.rstrip("\r\n").split("\t")
                if len(values) != len(FIELDS):
                    continue
                stamp, src4, src6, dst4, dst6, src_port, dst_port, size = values
                self.packet_count += 1
                self.last_packet_at = stamp
                LOG.info("PACKET %s:%s -> %s:%s bytes=%s capture_time=%s",
                         src4 or src6 or "?", src_port, dst4 or dst6 or "?", dst_port, size, stamp)
        finally:
            if self.process:
                self.process.stdout.close()
                code = self.process.wait()
                if not self.stopped:
                    LOG.error("Packet capture stopped (exit=%s); receiver can still process readings. See %s",
                              code, self.error_path)

    def status(self):
        return {"enabled": True, "running": self.process is not None and self.process.poll() is None,
                "interface": self.interface, "filter": f"tcp port {self.port}",
                "packets_observed": self.packet_count, "last_packet_at": self.last_packet_at,
                "directory": str(self.output_dir), "tshark_log": str(self.error_path)}

    def stop(self):
        self.stopped = True
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self.reader:
            self.reader.join(timeout=2)
        if self.log_file:
            self.log_file.close()
