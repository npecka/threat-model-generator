# hubble_fetcher.py

import subprocess
import json
import os

def fetch_hubble_flows_from_file(file_path="output/hubble_flows.jsonl", max_flows=50000):
    """
    Read Hubble flows from a collected JSONL file.
    This is used when flows were pre-collected by hubble_collector.sh

    Args:
        file_path: Path to the JSONL file containing collected flows
        max_flows: Maximum number of flows to load (default: 50000, set to None for all)
                  Loads the LAST N flows (most recent) using tail approach

    Returns:
        List of flow objects or error dict
    """
    try:
        if not os.path.exists(file_path):
            return {"error": f"Hubble flows file not found: {file_path}"}

        # Get file size for progress indication
        file_size = os.path.getsize(file_path)
        print(f"[Hubble] Reading flows from {file_path} ({file_size / (1024**3):.2f} GB)")

        flows = []

        # If max_flows is set, use tail to get last N lines (most recent flows)
        if max_flows is not None:
            print(f"[Hubble] Loading last {max_flows:,} flows (most recent during collection window)...")

            # Use tail command to get last N lines efficiently
            try:
                result = subprocess.run(
                    ["tail", f"-n{max_flows}", file_path],
                    capture_output=True,
                    text=True,
                    timeout=60
                )

                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                else:
                    # Fall back to Python if tail fails
                    print("[Hubble] tail command failed, using Python fallback...")
                    with open(file_path, 'r') as f:
                        lines = list(f)[-max_flows:]

            except (subprocess.TimeoutExpired, FileNotFoundError):
                # tail not available or timeout, use Python
                print("[Hubble] Using Python to read last flows...")
                with open(file_path, 'r') as f:
                    lines = list(f)[-max_flows:]

            # Parse the lines
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    flow = json.loads(line)
                    flows.append(flow)
                except json.JSONDecodeError as je:
                    flows.append({
                        "parse_error": str(je),
                        "line_number": line_num,
                        "raw": line[:200]
                    })
        else:
            # Load all flows (warning: can be very slow for large files)
            print("[Hubble] Loading ALL flows (this may take a while)...")
            with open(file_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        flow = json.loads(line)
                        flows.append(flow)
                    except json.JSONDecodeError as je:
                        flows.append({
                            "parse_error": str(je),
                            "line_number": line_num,
                            "raw": line[:200]
                        })

                    # Progress indicator for large files
                    if line_num % 1000000 == 0:
                        print(f"[Hubble] Processed {line_num:,} lines...")

        print(f"[Hubble] Loaded {len(flows):,} flows from {file_path}")
        return flows

    except Exception as e:
        return {"error": f"Failed to read Hubble flows file: {str(e)}"}

def fetch_hubble_flows_via_grpc():
    """
    Fetch Hubble flows directly via gRPC (live/real-time query).
    This provides a snapshot of flows currently in Hubble's memory buffer.

    Returns:
        List of flow objects or error dict
    """
    try:
        result = subprocess.run(
            ["grpcurl", "-insecure", "-format", "json", "-d", "{}", "hubble-api.lab.internal:443", "observer.Observer.GetFlows"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0:
            return {"error": result.stderr.strip()}

        raw_output = result.stdout.strip()
        flows = []

        buffer = ''
        open_braces = 0

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            open_braces += line.count('{')
            open_braces -= line.count('}')
            buffer += line

            if open_braces == 0 and buffer:
                try:
                    flows.append(json.loads(buffer))
                except json.JSONDecodeError as je:
                    flows.append({"parse_error": str(je), "raw": buffer})
                buffer = ''

        return flows

    except Exception as e:
        return {"error": f"Failed to execute grpcurl: {str(e)}"}

def fetch_hubble_flows(prefer_file=True, file_path="output/hubble_flows.jsonl"):
    """
    Fetch Hubble flows with automatic fallback.

    Strategy:
    1. If prefer_file=True and file exists, use collected flows (more complete)
    2. Otherwise, fall back to live gRPC query (current snapshot)

    Args:
        prefer_file: Whether to prefer reading from file if available
        file_path: Path to collected flows file

    Returns:
        List of flow objects or error dict
    """
    if prefer_file and os.path.exists(file_path):
        print(f"[Hubble] Using pre-collected flows from {file_path}")
        return fetch_hubble_flows_from_file(file_path)
    else:
        print("[Hubble] Querying live flows via gRPC")
        return fetch_hubble_flows_via_grpc()
