import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PATTERN_STORE_FILE = PROJECT_ROOT / "output" / "pattern_store.json"
EVENT_FILE = PROJECT_ROOT / "output" / "events.json"

# Import streaming correlation runner
try:
    import sys
    sys.path.append(str(PROJECT_ROOT / "src"))
    from incident.corelation_engine import run_correlation_cycle
except ImportError:
    run_correlation_cycle = None

# ============================================================
# LOAD PATTERNS
# ============================================================

def load_patterns():
    if not os.path.exists(PATTERN_STORE_FILE):
        print(f"[-] Pattern store not found: {PATTERN_STORE_FILE}")
        return []

    try:
        with open(PATTERN_STORE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[-] Error loading pattern store: {e}")
        return []

# ============================================================
# APPEND TO STREAMING EVENT LOG
# ============================================================

def append_event(event):
    EVENT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(EVENT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")
        f.flush()

# ============================================================
# PROCESS PATTERNS TO STREAMING EVENTS
# ============================================================

def main():
    print("=" * 65)
    print(" UNKNOWN PATTERN → REAL-TIME EVENT STREAM BRIDGE")
    print("=" * 65)

    patterns = load_patterns()
    if not patterns:
        print("[*] No patterns currently available to convert.")
        return

    events_created = 0
    t_now = time.time()

    for pattern in patterns:
        # Only integrate newly discovered clusters
        if pattern.get("status") != "NEW":
            continue

        pattern_id = pattern.get("pattern_id", "UNKNOWN")
        signature = pattern.get("behavioral_signature", {})
        observation_count = pattern.get("observations", pattern.get("cluster_size", 0))

        # First observed arrival time (falls back to current time minus window if absent)
        first_observed_epoch = pattern.get("first_seen_epoch", t_now - 5.0)
        latency_sec = round(t_now - first_observed_epoch, 3)

        event_id = f"EVT-UNKNOWN-{pattern_id.replace('P-', '')}-{int(t_now * 1000)}"

        event = {
            "event_id": event_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src": pattern.get("src", "UNKNOWN"),
            "dst": pattern.get("dst", "UNKNOWN"),
            "src_port": pattern.get("src_port", 0),
            "dst_port": pattern.get("dst_port", 0),
            "protocol": pattern.get("protocol", "UNKNOWN"),
            "type": "UNKNOWN_BEHAVIOR",
            "confidence": pattern.get("confidence", 0.75),
            "severity": "HIGH" if observation_count >= 10 else "MEDIUM",
            "pattern_id": pattern_id,
            "detection_latency_sec": latency_sec,
            "telemetry": {
                "first_packet_time": first_observed_epoch,
                "event_time_epoch": t_now,
                "pipeline_stage": "unsupervised_anomaly_clustering"
            },
            "evidence": {
                "classification": "UNKNOWN_BEHAVIOR",
                "pattern_status": pattern.get("status", "NEW"),
                "observation_count": observation_count,
                "detection_method": "IsolationForest + DBSCAN",
                "behavioral_signature": signature
            }
        }

        append_event(event)
        events_created += 1

        # Mark the pattern status as INTEGRATED in the pattern store
        pattern["status"] = "INTEGRATED"

        print(f"[!] Created event: {event_id} | Pattern: {pattern_id} | Latency: {latency_sec}s")

    # Update pattern store status
    if events_created > 0:
        try:
            with open(PATTERN_STORE_FILE, "w", encoding="utf-8") as f:
                json.dump(patterns, f, indent=2)
        except Exception as e:
            print(f"[-] Could not update pattern_store.json: {e}")

        # Trigger incremental correlation
        if run_correlation_cycle:
            print("[*] Triggering correlation engine for newly ingested unknown events...")
            run_correlation_cycle()

    print("=" * 65)
    print(f"[*] Integration complete. Unknown events added: {events_created}")
    print("=" * 65)

if __name__ == "__main__":
    main()