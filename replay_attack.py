import socket
import time
import sys

# ============================================================
# RESOLVE LOCAL WI-FI IP
# ============================================================
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

TARGET_IP = get_local_ip()

# Target ports commonly checked during recon / port scans
PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 993, 995, 1433, 3306, 3389, 5900, 8080, 8443
]

print("=" * 65)
print(" LIVE ATTACK TRAFFIC GENERATOR (PORT SCAN REPLAY)")
print("=" * 65)
print(f"[*] Target Destination: {TARGET_IP}")
print(f"[*] Probing {len(PORTS)} target ports across 3 rapid waves...")
print("=" * 65)

start_time = time.time()
sent_count = 0

try:
    for wave in range(1, 4):
        print(f"\n[>] Dispatching Wave {wave}/3...")
        for port in PORTS:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.04)
            try:
                # connect_ex sends a TCP SYN packet on interface 5
                s.connect_ex((TARGET_IP, port))
                sent_count += 1
            except Exception:
                pass
            finally:
                s.close()
            time.sleep(0.02)  # High packet rate typical of port scans

    duration = round(time.time() - start_time, 2)
    print("\n" + "=" * 65)
    print(f"[*] Attack simulation complete in {duration}s")
    print(f"[*] Total probe packets transmitted: {sent_count}")
    print("=" * 65)

except KeyboardInterrupt:
    print("\n[!] Simulation stopped by user.")