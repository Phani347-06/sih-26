import subprocess
import json
import time

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"

# Your Wi-Fi interface was interface 5
INTERFACE = "5"

FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "ip.proto",
    "frame.len"
]

cmd = [
    TSHARK,
    "-i", INTERFACE,
    "-l",
    "-T", "fields",
    "-E", "separator=|",
    "-E", "quote=n",
    "-E", "header=n"
]

for field in FIELDS:
    cmd.extend(["-e", field])

print("Starting TShark...")
print("Listening on interface:", INTERFACE)

process = subprocess.Popen(
    cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True,
    bufsize=1
)

packet_count = 0
start = time.time()

try:

    for line in process.stdout:

        line = line.strip()

        if not line:
            continue

        values = line.split("|")

        packet = dict(
            zip(FIELDS, values)
        )

        packet_count += 1

        print(
            json.dumps(packet),
            flush=True
        )

        # Print rate every 10 packets
        if packet_count % 10 == 0:

            elapsed = time.time() - start

            rate = packet_count / elapsed

            print(
                f"\n[INFO] Packets: {packet_count} | "
                f"Rate: {rate:.2f} packets/sec\n",
                flush=True
            )

except KeyboardInterrupt:

    print("\nStopping TShark...")

    process.terminate()