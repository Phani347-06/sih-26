import subprocess
import json
import time
import sys

# ============================================================
# CONFIGURATION
# ============================================================

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
INTERFACE = "5"  # Run 'tshark -D' in CMD/PowerShell to confirm index

FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "ip.proto",
    "frame.len",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.push",
    "ip.hdr_len",
    "tcp.hdr_len"
]

# ============================================================
# BUILD COMMAND (STREAMING MODE, NO PACKET LIMIT)
# ============================================================

cmd = [
    TSHARK,
    "-i", INTERFACE,
    "-l",               # Flush stdout per packet (line-buffered)
    "-T", "fields",
    "-E", "separator=|",
    "-E", "quote=n",
    "-E", "header=n"
]

for field in FIELDS:
    cmd.extend(["-e", field])

print("=" * 65)
print(" CONTINUOUS TSHARK PACKET STREAMER")
print("=" * 65)
print(f"[*] Interface: {INTERFACE}")
print("[*] Line buffering: Enabled (-l)")
print("[*] Mode: Continuous Capture (No packet cap)")
print("=" * 65)

# ============================================================
# SUBPROCESS EXECUTION
# ============================================================

process = subprocess.Popen(
    cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True,
    bufsize=1
)

packet_count = 0
start_time = time.time()

try:
    for line in iter(process.stdout.readline, ""):
        clean_line = line.strip()
        if not clean_line:
            continue

        values = clean_line.split("|")
        if len(values) < len(FIELDS):
            values.extend([""] * (len(FIELDS) - len(values)))

        packet = dict(zip(FIELDS, values))
        packet_count += 1

        # Emit raw JSON packet to stdout for piping or logging
        print(json.dumps(packet), flush=True)

        # Telemetry benchmark logged every 50 packets to stderr (avoids polluting stdout)
        if packet_count % 50 == 0:
            elapsed = time.time() - start_time
            rate = packet_count / elapsed if elapsed > 0 else 0.0
            sys.stderr.write(f"\r[STREAM TELEMETRY] Ingested: {packet_count} packets | Live Rate: {rate:.2f} pkt/s")
            sys.stderr.flush()

except KeyboardInterrupt:
    print("\n\n[*] Stopping continuous capture streamer...", file=sys.stderr)
    process.terminate()
    process.wait()