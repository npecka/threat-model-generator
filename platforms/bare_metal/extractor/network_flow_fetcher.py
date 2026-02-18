"""
Collect network flows using tcpdump on VMs
"""
import subprocess
import time
import json
from datetime import datetime
from config import VMS, TCPDUMP_DURATION

def start_tcpdump_on_vm(vm_ip, user, output_file):
    """Start tcpdump on a VM in background"""
    try:
        # Start tcpdump via SSH, running in background
        cmd = f"sudo tcpdump -i any -n -l -tttt 'tcp or udp' 2>/dev/null"
        process = subprocess.Popen(
            ["ssh", "-o", "StrictHostKeyChecking=no", f"{user}@{vm_ip}", cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return process
    except Exception as e:
        print(f"Error starting tcpdump on {vm_ip}: {e}")
        return None

def parse_tcpdump_line(line, source_vm):
    """Parse a tcpdump line into flow format"""
    try:
        # Format with -i any: 2026-01-06 01:32:30.919386 eth0  In  IP 192.168.100.20.57896 > 192.168.100.10.22: Flags [S]
        # Skip tcpdump header lines
        if 'tcpdump:' in line or 'listening on' in line or 'packets captured' in line:
            return None

        parts = line.split()
        if len(parts) < 9:
            return None

        # Parse format: date time interface direction protocol src > dst
        timestamp = f"{parts[0]} {parts[1]}"
        # parts[2] = interface (eth0)
        # parts[3] = direction (In/Out/B)
        protocol_type = parts[4]  # IP, IP6

        if protocol_type not in ['IP', 'IP6']:
            return None

        src = parts[5]
        dst = parts[7].rstrip(':')

        # Parse IP:port (format is IP.port)
        if '.' in src and '.' in dst:
            src_parts = src.rsplit('.', 1)
            dst_parts = dst.rsplit('.', 1)

            if len(src_parts) == 2 and len(dst_parts) == 2:
                # Validate IP addresses (should have at least 3 dots for IPv4)
                if src_parts[0].count('.') >= 3 and dst_parts[0].count('.') >= 3:
                    return {
                        "timestamp": timestamp,
                        "source_vm": source_vm,
                        "source_ip": src_parts[0],
                        "source_port": src_parts[1],
                        "dest_ip": dst_parts[0],
                        "dest_port": dst_parts[1],
                        "protocol": "TCP" if "tcp" in line.lower() or "Flags" in line else "UDP",
                        "direction": parts[3],  # In/Out/B (broadcast)
                        "raw": line
                    }
    except Exception as e:
        pass
    return None

def collect_flows_from_vm(vm_ip, user, vm_name, duration=60):
    """Collect network flows from a VM for specified duration"""
    print(f"  Starting packet capture on {vm_name} for {duration} seconds...")

    output_file = f"/tmp/tcpdump_{vm_name}.txt"
    process = start_tcpdump_on_vm(vm_ip, user, output_file)

    if not process:
        return []

    flows = []
    start_time = time.time()

    try:
        # Collect flows for specified duration
        while time.time() - start_time < duration:
            line = process.stdout.readline()
            if line:
                flow = parse_tcpdump_line(line.strip(), vm_name)
                if flow:
                    flows.append(flow)
    finally:
        # Kill tcpdump
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()

    print(f"  Collected {len(flows)} flows from {vm_name}")
    return flows

def aggregate_flows(flows):
    """Aggregate flows by source-destination pair"""
    flow_map = {}

    for flow in flows:
        key = f"{flow['source_ip']}:{flow['source_port']}→{flow['dest_ip']}:{flow['dest_port']}"

        if key not in flow_map:
            flow_map[key] = {
                "source_ip": flow["source_ip"],
                "source_port": flow["source_port"],
                "dest_ip": flow["dest_ip"],
                "dest_port": flow["dest_port"],
                "protocol": flow["protocol"],
                "source_vm": flow["source_vm"],
                "count": 0,
                "first_seen": flow["timestamp"],
                "last_seen": flow["timestamp"]
            }

        flow_map[key]["count"] += 1
        flow_map[key]["last_seen"] = flow["timestamp"]

    return list(flow_map.values())

def get_network_flows():
    """Collect network flows from all VMs"""
    print(f"Collecting network flows (duration: {TCPDUMP_DURATION}s)...")

    all_flows = []

    for vm in VMS:
        flows = collect_flows_from_vm(
            vm["ip"],
            vm["ssh_user"],
            vm["name"],
            TCPDUMP_DURATION
        )
        all_flows.extend(flows)

    # Aggregate flows
    aggregated = aggregate_flows(all_flows)

    print(f"Total flows collected: {len(all_flows)}")
    print(f"Unique flow pairs: {len(aggregated)}")

    return aggregated
