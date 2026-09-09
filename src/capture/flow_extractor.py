import pandas as pd
import numpy as np

# Read packet data
df = pd.read_csv("packets_clean.csv", sep="\t")

# Clean column names
df.columns = df.columns.str.strip()

# Convert numeric columns
numeric_columns = [
    "frame.time_epoch",
    "ip.proto",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "frame.len",
]

for column in numeric_columns:
    df[column] = pd.to_numeric(df[column], errors="coerce")

# Get source and destination ports
df["src_port"] = df["tcp.srcport"].fillna(df["udp.srcport"]).fillna(0)
df["dst_port"] = df["tcp.dstport"].fillna(df["udp.dstport"]).fillna(0)

# Create bidirectional flow key
def make_flow_key(row):

    endpoint1 = (
        str(row["ip.src"]),
        int(row["src_port"])
    )

    endpoint2 = (
        str(row["ip.dst"]),
        int(row["dst_port"])
    )

    protocol = (
        int(row["ip.proto"])
        if pd.notna(row["ip.proto"])
        else 0
    )

    endpoints = sorted([endpoint1, endpoint2])

    return (
        endpoints[0][0],
        endpoints[0][1],
        endpoints[1][0],
        endpoints[1][1],
        protocol
    )


df["flow_key"] = df.apply(make_flow_key, axis=1)

# Store extracted flows
flow_records = []

# Process every bidirectional flow
for flow_key, group in df.groupby("flow_key"):

    group = group.sort_values("frame.time_epoch").copy()

    ip1, port1, ip2, port2, protocol = flow_key

    # Determine forward and backward packets
    forward_mask = (
        (group["ip.src"].astype(str) == ip1)
        & (group["src_port"] == port1)
        & (group["ip.dst"].astype(str) == ip2)
        & (group["dst_port"] == port2)
    )

    forward = group[forward_mask]
    backward = group[~forward_mask]

    # Flow timing
    flow_start = group["frame.time_epoch"].min()
    flow_end = group["frame.time_epoch"].max()

    flow_duration = flow_end - flow_start

    # Packet counts
    total_fwd_packets = len(forward)
    total_bwd_packets = len(backward)

    # Byte counts
    total_fwd_bytes = forward["frame.len"].sum()
    total_bwd_bytes = backward["frame.len"].sum()

    # Packet length means
    fwd_packet_mean = (
        forward["frame.len"].mean()
        if len(forward) > 0
        else 0
    )

    bwd_packet_mean = (
        backward["frame.len"].mean()
        if len(backward) > 0
        else 0
    )

    # Overall packet statistics
    packet_lengths = group["frame.len"]

    packet_length_mean = packet_lengths.mean()
    packet_length_std = packet_lengths.std()

    if pd.isna(packet_length_std):
        packet_length_std = 0

    # Flow IAT
    timestamps = group["frame.time_epoch"].values

    if len(timestamps) > 1:

        iat = np.diff(timestamps)

        flow_iat_mean = np.mean(iat)
        flow_iat_std = np.std(iat)

    else:

        flow_iat_mean = 0
        flow_iat_std = 0

    # Forward IAT
    fwd_times = forward["frame.time_epoch"].values

    if len(fwd_times) > 1:
        fwd_iat_mean = np.mean(np.diff(fwd_times))
    else:
        fwd_iat_mean = 0

    # Backward IAT
    bwd_times = backward["frame.time_epoch"].values

    if len(bwd_times) > 1:
        bwd_iat_mean = np.mean(np.diff(bwd_times))
    else:
        bwd_iat_mean = 0

    # Flow rates
    safe_duration = (
        flow_duration
        if flow_duration > 0
        else 1
    )

    flow_bytes_per_second = (
        (total_fwd_bytes + total_bwd_bytes)
        / safe_duration
    )

    flow_packets_per_second = (
        (total_fwd_packets + total_bwd_packets)
        / safe_duration
    )

    # Down / Up ratio
    if total_fwd_packets > 0:
        down_up_ratio = (
            total_bwd_packets /
            total_fwd_packets
        )
    else:
        down_up_ratio = 0

    # -------------------------------------------------
    # TCP FLAGS AND HEADER FEATURES
    # -------------------------------------------------

    fwd_psh_flags = 0
    bwd_psh_flags = 0

    syn_flag_count = 0
    ack_flag_count = 0

    fwd_header_length = 0
    bwd_header_length = 0

    # Examine every packet in this flow
    for _, packet in group.iterrows():

        # Only TCP packets have TCP flags/header length
        if packet["ip.proto"] != 6:
            continue

        # Determine packet direction
        is_forward = (
            str(packet["ip.src"]) == ip1
            and packet["src_port"] == port1
            and str(packet["ip.dst"]) == ip2
            and packet["dst_port"] == port2
        )

        # TCP flags
        syn = (
            str(packet["tcp.flags.syn"]).lower()
            == "true"
        )

        ack = (
            str(packet["tcp.flags.ack"]).lower()
            == "true"
        )

        push = (
            str(packet["tcp.flags.push"]).lower()
            == "true"
        )

        # SYN count
        if syn:
            syn_flag_count += 1

        # ACK count
        if ack:
            ack_flag_count += 1

        # PSH count
        if is_forward and push:
            fwd_psh_flags += 1

        elif not is_forward and push:
            bwd_psh_flags += 1

        # TCP header length
        header_length = pd.to_numeric(
            packet["tcp.hdr_len"],
            errors="coerce"
        )

        if pd.notna(header_length):

            if is_forward:
                fwd_header_length += header_length
            else:
                bwd_header_length += header_length

    # -------------------------------------------------
    # CREATE FLOW RECORD
    # -------------------------------------------------

    record = {

        "Flow Duration": flow_duration,

        "Total Fwd Packets":
            total_fwd_packets,

        "Total Backward Packets":
            total_bwd_packets,

        "Total Length of Fwd Packets":
            total_fwd_bytes,

        "Total Length of Bwd Packets":
            total_bwd_bytes,

        "Fwd Packet Length Mean":
            fwd_packet_mean,

        "Bwd Packet Length Mean":
            bwd_packet_mean,

        "Flow Bytes/s":
            flow_bytes_per_second,

        "Flow Packets/s":
            flow_packets_per_second,

        "Flow IAT Mean":
            flow_iat_mean,

        "Flow IAT Std":
            flow_iat_std,

        "Fwd IAT Mean":
            fwd_iat_mean,

        "Bwd IAT Mean":
            bwd_iat_mean,

        "Fwd PSH Flags":
            fwd_psh_flags,

        "Bwd PSH Flags":
            bwd_psh_flags,

        "Fwd Header Length":
            fwd_header_length,

        "Bwd Header Length":
            bwd_header_length,

        "Packet Length Mean":
            packet_length_mean,

        "Packet Length Std":
            packet_length_std,

        "SYN Flag Count":
            syn_flag_count,

        "ACK Flag Count":
            ack_flag_count,

        "Down/Up Ratio":
            down_up_ratio,

        # Metadata
        "Source IP":
            ip1,

        "Destination IP":
            ip2,

        "Source Port":
            port1,

        "Destination Port":
            port2,

        "Protocol":
            protocol,

        "Flow Start":
            flow_start,
    }

    flow_records.append(record)


# Convert to DataFrame
flows = pd.DataFrame(flow_records)

# Save extracted flows
flows.to_csv(
    "flows_bidirectional.csv",
    index=False
)

# Display results
print("Bidirectional flow extraction completed!")
print("Packets:", len(df))
print("Bidirectional flows:", len(flows))

print("\nFlow columns:")
print(flows.columns.tolist())

print("\nFirst 5 flows:")
print(flows.head())