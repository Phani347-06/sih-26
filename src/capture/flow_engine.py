import subprocess
import time
from collections import defaultdict

import numpy as np
import pandas as pd
import joblib

import json
from datetime import datetime, timezone


# ============================================================
# CONFIG
# ============================================================

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
INTERFACE = "5"

MODEL_PATH = "../../models/random_forest_model.pkl"

WINDOW = 5


# ============================================================
# FEATURES USED BY THE RANDOM FOREST
# EXACT SAME ORDER AS TRAINING
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


# ============================================================
# TSHARK FIELDS
# ============================================================

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
# LOAD MODEL
# ============================================================

print("Loading Random Forest model...")

model = joblib.load(MODEL_PATH)

print("Model loaded successfully.")
print("Classes:", model.classes_)
print()


# ============================================================
# START TSHARK
# ============================================================

def start_tshark():

    command = [
        TSHARK,
        "-i", INTERFACE,
        "-l",
        "-T", "fields",

        "-E", "separator=|",
        "-E", "quote=n",
        "-E", "header=n"
    ]

    for field in FIELDS:
        command.extend(["-e", field])

    return subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1
    )


# ============================================================
# PARSE PACKET
# ============================================================

def parse_packet(line):

    values = line.strip().split("|")

    if len(values) != len(FIELDS):
        return None

    data = dict(zip(FIELDS, values))

    try:

        timestamp = float(data["frame.time_epoch"])

        packet_size = int(data["frame.len"])

    except:

        return None

    src = data["ip.src"]
    dst = data["ip.dst"]

    # Ignore non-IP packets
    if not src or not dst:
        return None

    protocol_number = data["ip.proto"]

    if protocol_number == "6":

        protocol = "TCP"

        src_port = data["tcp.srcport"]
        dst_port = data["tcp.dstport"]

    elif protocol_number == "17":

        protocol = "UDP"

        src_port = data["udp.srcport"]
        dst_port = data["udp.dstport"]

    else:

        return None


    # TCP flags

    syn = 1 if data["tcp.flags.syn"].lower() == "true" else 0
    ack = 1 if data["tcp.flags.ack"].lower() == "true" else 0
    push = 1 if data["tcp.flags.push"].lower() == "true" else 0

    # Header lengths

    try:
        ip_header = int(data["ip.hdr_len"] or 20)
    except:
        ip_header = 20

    try:
        tcp_header = int(data["tcp.hdr_len"] or 0)
    except:
        tcp_header = 0


    header_length = ip_header + tcp_header


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

        "header_length": header_length
    }


# ============================================================
# BIDIRECTIONAL FLOW KEY
# ============================================================

def make_flow_key(packet):

    endpoint1 = (
        packet["src"],
        packet["src_port"]
    )

    endpoint2 = (
        packet["dst"],
        packet["dst_port"]
    )

    if endpoint1 <= endpoint2:

        return (
            packet["src"],
            packet["src_port"],
            packet["dst"],
            packet["dst_port"],
            packet["protocol"]
        )

    else:

        return (
            packet["dst"],
            packet["dst_port"],
            packet["src"],
            packet["src_port"],
            packet["protocol"]
        )


# ============================================================
# CREATE FLOW
# ============================================================

def create_flow(packet):

    return {

        "first_src": packet["src"],
        "first_dst": packet["dst"],

        "src_port": packet["src_port"],
        "dst_port": packet["dst_port"],

        "protocol": packet["protocol"],

        "timestamps": [],

        "sizes": [],

        "directions": [],

        "syn": [],
        "ack": [],
        "push": [],

        "header_lengths": []
    }


# ============================================================
# ADD PACKET TO FLOW
# ============================================================

def add_packet(flow, packet):

    flow["timestamps"].append(packet["timestamp"])

    flow["sizes"].append(packet["size"])

    flow["syn"].append(packet["syn"])

    flow["ack"].append(packet["ack"])

    flow["push"].append(packet["push"])

    flow["header_lengths"].append(
        packet["header_length"]
    )


    # Direction

    if (
        packet["src"] == flow["first_src"]
        and
        packet["dst"] == flow["first_dst"]
    ):

        flow["directions"].append("FWD")

    else:

        flow["directions"].append("BWD")


# ============================================================
# CALCULATE 22 FEATURES
# ============================================================

def calculate_features(flow):

    timestamps = np.array(flow["timestamps"])

    sizes = np.array(flow["sizes"])

    directions = np.array(flow["directions"])

    syn = np.array(flow["syn"])

    ack = np.array(flow["ack"])

    push = np.array(flow["push"])

    headers = np.array(flow["header_lengths"])


    # --------------------------------------------------------
    # Forward / backward
    # --------------------------------------------------------

    fwd_mask = directions == "FWD"

    bwd_mask = directions == "BWD"


    fwd_sizes = sizes[fwd_mask]

    bwd_sizes = sizes[bwd_mask]


    fwd_times = timestamps[fwd_mask]

    bwd_times = timestamps[bwd_mask]


    # --------------------------------------------------------
    # Duration
    # --------------------------------------------------------

    duration = timestamps[-1] - timestamps[0]

    # Avoid division by zero
    if duration <= 0:

        duration = 0.001


    # --------------------------------------------------------
    # Packet counts
    # --------------------------------------------------------

    total_fwd = len(fwd_sizes)

    total_bwd = len(bwd_sizes)


    # --------------------------------------------------------
    # Packet lengths
    # --------------------------------------------------------

    fwd_length_total = (
        np.sum(fwd_sizes)
        if len(fwd_sizes) > 0
        else 0
    )

    bwd_length_total = (
        np.sum(bwd_sizes)
        if len(bwd_sizes) > 0
        else 0
    )


    fwd_mean = (
        np.mean(fwd_sizes)
        if len(fwd_sizes) > 0
        else 0
    )

    bwd_mean = (
        np.mean(bwd_sizes)
        if len(bwd_sizes) > 0
        else 0
    )


    # --------------------------------------------------------
    # Flow rate
    # --------------------------------------------------------

    total_bytes = np.sum(sizes)

    total_packets = len(sizes)

    flow_bytes_sec = total_bytes / duration

    flow_packets_sec = total_packets / duration


    # --------------------------------------------------------
    # IAT
    # --------------------------------------------------------

    if len(timestamps) > 1:

        flow_iat = np.diff(timestamps)

        flow_iat_mean = np.mean(flow_iat)

        flow_iat_std = np.std(flow_iat)

    else:

        flow_iat_mean = 0

        flow_iat_std = 0


    # --------------------------------------------------------
    # Forward IAT
    # --------------------------------------------------------

    if len(fwd_times) > 1:

        fwd_iat = np.diff(fwd_times)

        fwd_iat_mean = np.mean(fwd_iat)

    else:

        fwd_iat_mean = 0


    # --------------------------------------------------------
    # Backward IAT
    # --------------------------------------------------------

    if len(bwd_times) > 1:

        bwd_iat = np.diff(bwd_times)

        bwd_iat_mean = np.mean(bwd_iat)

    else:

        bwd_iat_mean = 0


    # --------------------------------------------------------
    # PSH
    # --------------------------------------------------------

    fwd_push = np.sum(
        push[fwd_mask]
    )

    bwd_push = np.sum(
        push[bwd_mask]
    )


    # --------------------------------------------------------
    # Header lengths
    # --------------------------------------------------------

    fwd_header = np.sum(
        headers[fwd_mask]
    )

    bwd_header = np.sum(
        headers[bwd_mask]
    )


    # --------------------------------------------------------
    # Packet statistics
    # --------------------------------------------------------

    packet_mean = np.mean(sizes)

    packet_std = np.std(sizes)


    # --------------------------------------------------------
    # SYN / ACK
    # --------------------------------------------------------

    syn_count = np.sum(syn)

    ack_count = np.sum(ack)


    # --------------------------------------------------------
    # Down / Up ratio
    # --------------------------------------------------------

    if total_fwd > 0:

        down_up_ratio = total_bwd / total_fwd

    else:

        down_up_ratio = 0


    # --------------------------------------------------------
    # FINAL VECTOR
    # --------------------------------------------------------

    feature_values = [

        duration,

        total_fwd,

        total_bwd,

        fwd_length_total,

        bwd_length_total,

        fwd_mean,

        bwd_mean,

        flow_bytes_sec,

        flow_packets_sec,

        flow_iat_mean,

        flow_iat_std,

        fwd_iat_mean,

        bwd_iat_mean,

        fwd_push,

        bwd_push,

        fwd_header,

        bwd_header,

        packet_mean,

        packet_std,

        syn_count,

        ack_count,

        down_up_ratio
    ]


    return feature_values


# ============================================================
# PREDICT
# ============================================================

def predict_flow(flow):

    values = calculate_features(flow)

    X = pd.DataFrame(
        [values],
        columns=FEATURES
    )


    # Remove invalid values

    X = X.replace(
        [np.inf, -np.inf],
        0
    )

    X = X.fillna(0)


    prediction = model.predict(X)[0]


    probabilities = model.predict_proba(X)[0]

    confidence = np.max(probabilities)


    return prediction, confidence, values

def create_event(flow, prediction, confidence, values):

    event = {
        "event_id": f"EVT-{int(time.time() * 1000)}",

        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),

        "src": flow["first_src"],
        "dst": flow["first_dst"],

        "src_port": flow["src_port"],
        "dst_port": flow["dst_port"],

        "protocol": flow["protocol"],

        "type": prediction,

        "confidence": round(
            float(confidence),
            4
        ),

        "severity": (
            "HIGH"
            if confidence >= 0.90
            else "MEDIUM"
        ),

        "evidence": {
            "packet_count": len(flow["sizes"]),
            "total_bytes": int(sum(flow["sizes"])),

            "flow_duration": round(
                values[0],
                4
            ),

            "packet_rate": round(
                values[8],
                4
            ),

            "byte_rate": round(
                values[7],
                4
            ),

            "packet_size_mean": round(
                values[17],
                4
            ),

            "packet_size_std": round(
                values[18],
                4
            ),

            "syn_count": int(
                values[19]
            ),

            "ack_count": int(
                values[20]
            )
        }
    }

    return event

# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 65)
    print(" AI CYBER THREAT DETECTOR")
    print("=" * 65)

    print()

    print("Starting live capture...")

    tshark = start_tshark()

    flows = {}

    window_start = time.time()

    try:

        while True:

            line = tshark.stdout.readline()

            if not line:
                continue


            packet = parse_packet(line)

            if packet is None:
                continue


            key = make_flow_key(packet)


            if key not in flows:

                flows[key] = create_flow(packet)


            add_packet(
                flows[key],
                packet
            )


            # ------------------------------------------------
            # PROCESS WINDOW
            # ------------------------------------------------

            if time.time() - window_start >= WINDOW:

                print()
                print("=" * 65)

                print(
                    f"PROCESSING WINDOW | "
                    f"Flows: {len(flows)}"
                )

                print("=" * 65)


                processed = 0


                for flow in flows.values():

                    # Very small flows are not useful
                    if len(flow["timestamps"]) < 2:
                        continue


                    try:

                        prediction, confidence, values = predict_flow(
                            flow
                        )


                        print()

                        print(
                            f"{flow['first_src']} → "
                            f"{flow['first_dst']}"
                        )

                        print(
                            f"Protocol: {flow['protocol']} | "
                            f"Packets: {len(flow['sizes'])}"
                        )

                        print(
                            f"Prediction: {prediction}"
                        )

                        print(
                            f"Confidence: "
                            f"{confidence * 100:.2f}%"
                        )


                        if prediction != "BENIGN":

                            print(
                                "⚠️  THREAT DETECTED"
                            )


                        processed += 1


                    except Exception as e:

                        print(
                            "Prediction error:",
                            e
                        )


                print()

                print(
                    f"Processed flows: {processed}"
                )


                # Reset window

                flows.clear()

                window_start = time.time()


    except KeyboardInterrupt:

        print()
        print("Stopping detector...")

        tshark.terminate()


if __name__ == "__main__":

    main()