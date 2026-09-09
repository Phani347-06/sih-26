import subprocess
import time
import threading
import queue
from collections import defaultdict
import numpy as np
import pandas as pd
import joblib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# ============================================================
# CONFIGURATION & PATHS
# ============================================================

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
INTERFACE = "5"  # Wi-Fi interface index

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = PROJECT_ROOT / "models" / "random_forest_model.pkl"
OUTPUT_DIR = PROJECT_ROOT / "output"
EVENT_FILE = OUTPUT_DIR / "events.json"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

WINDOW = 5.0  # Continuous 5-second tumbling aggregation window

# Connect correlation engine directly
sys.path.append(str(PROJECT_ROOT / "src"))
try:
    from incident.corelation_engine import run_correlation_cycle
except ImportError:
    run_correlation_cycle = None

# ============================================================
# 22 FEATURES (EXACT TRAINING ORDER)
# ============================================================

FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Packet Length Mean",
    "Packet Length Std",
    "SYN Flag Count",
    "ACK Flag Count",
    "Down/Up Ratio"
]

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

print("=" * 65)
print("[*] Loading Random Forest model into memory...")
model = joblib.load(MODEL_PATH)
print(f"[*] Model loaded successfully. Classes: {model.classes_}")
print("=" * 65)

# ============================================================
# TSHARK PROCESS & LINE BUFFERING
# ============================================================

def start_tshark():
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

    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1
    )

def enqueue_output(out, q):
    for line in iter(out.readline, ''):
        if line:
            q.put(line)
    out.close()

# ============================================================
# PACKET PARSER
# ============================================================

def parse_packet(line):
    values = line.strip().split("|")
    if len(values) < len(FIELDS):
        values.extend([""] * (len(FIELDS) - len(values)))

    data = dict(zip(FIELDS, values))

    try:
        timestamp = float(data["frame.time_epoch"])
        packet_size = int(data["frame.len"])
    except (ValueError, TypeError):
        return None

    src = data["ip.src"]
    dst = data["ip.dst"]
    if not src or not dst:
        return None

    proto_num = data["ip.proto"]
    if proto_num == "6":
        protocol = "TCP"
        src_port = data["tcp.srcport"] or "0"
        dst_port = data["tcp.dstport"] or "0"
    elif proto_num == "17":
        protocol = "UDP"
        src_port = data["udp.srcport"] or "0"
        dst_port = data["udp.dstport"] or "0"
    else:
        return None

    syn = 1 if data["tcp.flags.syn"].lower() in ("true", "1") else 0
    ack = 1 if data["tcp.flags.ack"].lower() in ("true", "1") else 0
    push = 1 if data["tcp.flags.push"].lower() in ("true", "1") else 0

    try:
        ip_header = int(data["ip.hdr_len"]) if data["ip.hdr_len"] else 20
    except ValueError:
        ip_header = 20

    try:
        tcp_header = int(data["tcp.hdr_len"]) if data["tcp.hdr_len"] else 0
    except ValueError:
        tcp_header = 0

    return {
        "timestamp": timestamp,
        "src": src,
        "dst": dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "size": packet_size,
        "syn": syn,
        "ack": ack,
        "push": push,
        "header_length": ip_header + tcp_header
    }

# ============================================================
# FLOW AGGREGATION
# ============================================================

def make_flow_key(packet):
    endpoint1 = (packet["src"], packet["src_port"])
    endpoint2 = (packet["dst"], packet["dst_port"])
    if endpoint1 <= endpoint2:
        return (packet["src"], packet["src_port"], packet["dst"], packet["dst_port"], packet["protocol"])
    return (packet["dst"], packet["dst_port"], packet["src"], packet["src_port"], packet["protocol"])

def create_flow(packet):
    return {
        "first_src": packet["src"],
        "first_dst": packet["dst"],
        "src_port": packet["src_port"],
        "dst_port": packet["dst_port"],
        "protocol": packet["protocol"],
        "first_packet_epoch": packet["timestamp"],
        "timestamps": [],
        "sizes": [],
        "directions": [],
        "syn": [],
        "ack": [],
        "push": [],
        "header_lengths": []
    }

def add_packet(flow, packet):
    flow["timestamps"].append(packet["timestamp"])
    flow["sizes"].append(packet["size"])
    flow["syn"].append(packet["syn"])
    flow["ack"].append(packet["ack"])
    flow["push"].append(packet["push"])
    flow["header_lengths"].append(packet["header_length"])

    if packet["src"] == flow["first_src"] and packet["dst"] == flow["first_dst"]:
        flow["directions"].append("FWD")
    else:
        flow["directions"].append("BWD")

# ============================================================
# FEATURE CALCULATION (22 FEATURES)
# ============================================================

def calculate_features(flow):
    timestamps = np.array(flow["timestamps"])
    sizes = np.array(flow["sizes"])
    directions = np.array(flow["directions"])
    syn = np.array(flow["syn"])
    ack = np.array(flow["ack"])
    push = np.array(flow["push"])
    headers = np.array(flow["header_lengths"])

    fwd_mask = directions == "FWD"
    bwd_mask = directions == "BWD"

    fwd_sizes = sizes[fwd_mask]
    bwd_sizes = sizes[bwd_mask]
    fwd_times = timestamps[fwd_mask]
    bwd_times = timestamps[bwd_mask]

    duration = timestamps[-1] - timestamps[0]
    if duration <= 0:
        duration = 0.001

    total_fwd = len(fwd_sizes)
    total_bwd = len(bwd_sizes)

    fwd_length_total = float(np.sum(fwd_sizes)) if total_fwd > 0 else 0.0
    bwd_length_total = float(np.sum(bwd_sizes)) if total_bwd > 0 else 0.0

    fwd_mean = float(np.mean(fwd_sizes)) if total_fwd > 0 else 0.0
    bwd_mean = float(np.mean(bwd_sizes)) if total_bwd > 0 else 0.0

    total_bytes = float(np.sum(sizes))
    total_packets = len(sizes)

    flow_bytes_sec = total_bytes / duration
    flow_packets_sec = total_packets / duration

    if len(timestamps) > 1:
        flow_iat = np.diff(timestamps)
        flow_iat_mean = float(np.mean(flow_iat))
        flow_iat_std = float(np.std(flow_iat))
    else:
        flow_iat_mean, flow_iat_std = 0.0, 0.0

    fwd_iat_mean = float(np.mean(np.diff(fwd_times))) if len(fwd_times) > 1 else 0.0
    bwd_iat_mean = float(np.mean(np.diff(bwd_times))) if len(bwd_times) > 1 else 0.0

    fwd_push = int(np.sum(push[fwd_mask]))
    bwd_push = int(np.sum(push[bwd_mask]))

    fwd_header = int(np.sum(headers[fwd_mask]))
    bwd_header = int(np.sum(headers[bwd_mask]))

    packet_mean = float(np.mean(sizes))
    packet_std = float(np.std(sizes))

    syn_count = int(np.sum(syn))
    ack_count = int(np.sum(ack))
    down_up_ratio = (total_bwd / total_fwd) if total_fwd > 0 else 0.0

    return [
        duration, total_fwd, total_bwd, fwd_length_total, bwd_length_total,
        fwd_mean, bwd_mean, flow_bytes_sec, flow_packets_sec,
        flow_iat_mean, flow_iat_std, fwd_iat_mean, bwd_iat_mean,
        fwd_push, bwd_push, fwd_header, bwd_header,
        packet_mean, packet_std, syn_count, ack_count, down_up_ratio
    ]

# ============================================================
# INFERENCE & TELEMETRY
# ============================================================

def predict_flow(flow):
    t_feat_start = time.time()
    values = calculate_features(flow)
    t_feat_end = time.time()

    X = pd.DataFrame([values], columns=FEATURES)
    X = X.replace([np.inf, -np.inf], 0).fillna(0)

    t_infer_start = time.time()
    prediction = model.predict(X)[0]
    probabilities = model.predict_proba(X)[0]
    confidence = float(np.max(probabilities))
    t_infer_end = time.time()

    timing_telemetry = {
        "first_packet_time": flow["first_packet_epoch"],
        "feat_extract_ms": round((t_feat_end - t_feat_start) * 1000, 2),
        "inference_ms": round((t_infer_end - t_infer_start) * 1000, 2),
        "event_time_epoch": time.time()
    }

    return prediction, confidence, values, timing_telemetry

def create_event(flow, prediction, confidence, values, telemetry):
    alert_time = telemetry["event_time_epoch"]
    latency_sec = round(alert_time - telemetry["first_packet_time"], 3)

    return {
        "event_id": f"EVT-{int(alert_time * 1000)}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src": flow["first_src"],
        "dst": flow["first_dst"],
        "src_port": flow["src_port"],
        "dst_port": flow["dst_port"],
        "protocol": flow["protocol"],
        "type": str(prediction),
        "confidence": round(float(confidence), 4),
        "severity": "HIGH" if confidence >= 0.85 else "MEDIUM",
        "detection_latency_sec": latency_sec,
        "telemetry": telemetry,
        "evidence": {
            "packet_count": len(flow["sizes"]),
            "total_bytes": int(sum(flow["sizes"])),
            "flow_duration": round(values[0], 4),
            "packet_rate": round(values[8], 4),
            "byte_rate": round(values[7], 4),
            "packet_size_mean": round(values[17], 4),
            "packet_size_std": round(values[18], 4),
            "syn_count": int(values[19]),
            "ack_count": int(values[20])
        }
    }

# ============================================================
# MAIN STREAMING LOOP
# ============================================================

def main():
    print(f"[*] Starting continuous capture on interface [{INTERFACE}]...")

    tshark = start_tshark()
    q = queue.Queue()
    t = threading.Thread(target=enqueue_output, args=(tshark.stdout, q), daemon=True)
    t.start()

    flows = {}
    window_start = time.time()

    try:
        while True:
            # Drain non-blocking incoming packet queue
            while not q.empty():
                line = q.get_nowait()
                packet = parse_packet(line)
                if packet is None:
                    continue

                key = make_flow_key(packet)
                if key not in flows:
                    flows[key] = create_flow(packet)

                add_packet(flows[key], packet)

            # Check bounded 5-second window
            current_time = time.time()
            if current_time - window_start >= WINDOW:
                window_flows = flows
                flows = {}  # Clear for subsequent window immediately
                window_start = current_time
                print(f"[*] Window tick: {len(window_flows)} raw flows collected.")

                if len(window_flows) > 0:
                    new_threats_found = 0
                    evaluated_count = 0
                    
                    with open(EVENT_FILE, "a", encoding="utf-8") as f_out:
                        for flow in window_flows.values():
                            if len(flow["timestamps"]) < 2:
                                continue

                            evaluated_count += 1
                            try:
                                pred, conf, vals, telem = predict_flow(flow)
                                # DEBUG: print what the model is predicting
                                if str(pred).upper() != "BENIGN":
                                    event = create_event(flow, pred, conf, vals, telem)
                                    f_out.write(json.dumps(event) + "\n")
                                    f_out.flush()
                                    new_threats_found += 1
                                    
                                    print(f"[!] THREAT: {flow['first_src']} -> {flow['first_dst']} | "
                                          f"Type: {pred} | Latency: {event['detection_latency_sec']}s")
                            except Exception as e:
                                print(f"[-] Inference error: {e}")

                    print(f"[*] Evaluated {evaluated_count} multi-packet flows | Threats logged: {new_threats_found}")

                    # Incremental correlation trigger
                    if new_threats_found > 0 and run_correlation_cycle:
                        run_correlation_cycle()

                if len(window_flows) > 0:
                    new_threats_found = 0
                    with open(EVENT_FILE, "a", encoding="utf-8") as f_out:
                        for flow in window_flows.values():
                            if len(flow["timestamps"]) < 2:
                                continue

                            try:
                                pred, conf, vals, telem = predict_flow(flow)
                                if str(pred).upper() != "BENIGN":
                                    event = create_event(flow, pred, conf, vals, telem)
                                    f_out.write(json.dumps(event) + "\n")
                                    f_out.flush()
                                    new_threats_found += 1
                                    
                                    print(f"[!] THREAT: {flow['first_src']} -> {flow['first_dst']} | "
                                          f"Type: {pred} | Latency: {event['detection_latency_sec']}s")
                            except Exception as e:
                                print(f"[-] Inference error: {e}")

                    # Incremental correlation trigger
                    if new_threats_found > 0 and run_correlation_cycle:
                        run_correlation_cycle()

            time.sleep(0.02)

    except KeyboardInterrupt:
        print("\nStopping streaming pipeline...")
        tshark.terminate()

if __name__ == "__main__":
    main()