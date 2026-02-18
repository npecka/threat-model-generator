# port_scanner.py
from collections import defaultdict
from datetime import datetime
from config import PORT_SCAN_THRESHOLD, TIME_WINDOW_SECONDS

def detect_port_scanning(flows):
    scan_events = []
    source_flows = defaultdict(list)

    for flow_wrap in flows:
        # Skip non-dict entries (errors, parse failures, strings)
        if not isinstance(flow_wrap, dict):
            continue

        # Handle error responses
        if "error" in flow_wrap or "parse_error" in flow_wrap:
            continue

        flow = flow_wrap.get("flow", {})
        if flow.get("verdict") != "FORWARDED":
            continue
        if flow.get("event_type", {}).get("type") != "L3_L4":
            continue
        source = flow.get("source", {}).get("pod_name")
        if not source or not flow.get("time"):
            continue
        source_flows[source].append(flow)

    for src_pod, pod_flows in source_flows.items():
        time_buckets = defaultdict(set)

        for flow in pod_flows:
            try:
                ts = datetime.strptime(flow["time"], "%Y-%m-%dT%H:%M:%S.%fZ")
            except Exception:
                continue
            bucket = ts.replace(second=(ts.second // TIME_WINDOW_SECONDS) * TIME_WINDOW_SECONDS, microsecond=0)
            dst_key = (flow.get("destination", {}).get("ip"), flow.get("destination", {}).get("port"))
            time_buckets[bucket].add(dst_key)

        for bucket, ports in time_buckets.items():
            if len(ports) >= PORT_SCAN_THRESHOLD:
                scan_events.append({
                    "source_pod": src_pod,
                    "ports_hit": list(ports),
                    "timestamp": bucket.isoformat(),
                    "reason": f"Port scan detected: {len(ports)} ports hit in {TIME_WINDOW_SECONDS}s"
                })

    return scan_events
