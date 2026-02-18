#!/usr/bin/env python3
"""
Bare-Metal Data Extractor
Collects runtime data from VMs for threat modeling
"""
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Add parent directories to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from common.metrics_collector import MetricsCollector

from config import OUTPUT_DIR, VMS
from vm_metadata_fetcher import get_all_vm_metadata
from network_flow_fetcher import get_network_flows
from config_file_fetcher import get_all_config_files, get_docker_configs

def write_output(data, filename="bare_metal_metadata.json"):
    """Write collected data to JSON file"""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, filename)

    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)

    print(f"\nOutput written to: {output_path}")
    print(f"File size: {os.path.getsize(output_path) / 1024:.2f} KB")

def main():
    print("=" * 60)
    print("Bare-Metal Data Collection")
    print("=" * 60)
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"VMs to scan: {len(VMS)}")
    print()

    # Initialize metrics collector
    metrics = MetricsCollector()

    # Check SSH connectivity
    print("Checking VM connectivity...")
    metrics.start_phase("connectivity_check")
    import subprocess
    for vm in VMS:
        result = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=no",
             f"{vm['ssh_user']}@{vm['ip']}", "echo OK"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            print(f"  ✓ {vm['name']} ({vm['ip']})")
        else:
            print(f"  ✗ {vm['name']} ({vm['ip']}) - NOT REACHABLE")
            sys.exit(1)
    metrics.end_phase("connectivity_check")
    print()

    # Collect data
    try:
        # 1. VM Metadata (pods equivalent)
        metrics.start_phase("vm_metadata_collection")
        vm_metadata = get_all_vm_metadata()
        metrics.end_phase("vm_metadata_collection")
        print()

        # 2. Network Flows (hubble equivalent)
        metrics.start_phase("network_flow_collection")
        network_flows = get_network_flows()
        metrics.end_phase("network_flow_collection")
        print()

        # 3. Configuration Files (configmaps equivalent)
        metrics.start_phase("config_files_collection")
        config_files = get_all_config_files()
        metrics.end_phase("config_files_collection")
        print()

        # 4. Docker Configurations
        metrics.start_phase("docker_configs_collection")
        docker_configs = get_docker_configs()
        metrics.end_phase("docker_configs_collection")
        print()

        # Build output structure
        metrics.start_phase("output_serialization")
        output = {
            "platform": "bare-metal",
            "collection_time": datetime.now().isoformat(),
            "vms": vm_metadata,
            "network_flows": network_flows,
            "config_files": config_files,
            "docker_configs": docker_configs,
            "zones": [
                {
                    "name": "dev-zone",
                    "vms": [vm for vm in VMS if vm["zone"] == "dev-zone"]
                },
                {
                    "name": "cicd-zone",
                    "vms": [vm for vm in VMS if vm["zone"] == "cicd-zone"]
                },
                {
                    "name": "prod-zone",
                    "vms": [vm for vm in VMS if vm["zone"] == "prod-zone"]
                }
            ],
            "statistics": {
                "total_vms": len(vm_metadata),
                "total_flows": len(network_flows),
                "total_config_files": len(config_files),
                "total_secrets_found": sum(len(c.get("secrets", [])) for c in config_files)
            }
        }

        # Write output
        write_output(output)
        metrics.end_phase("output_serialization")

        # Save metrics report
        performance_summary = metrics.generate_report()
        metrics_output_path = os.path.join(OUTPUT_DIR, "extractor_metrics.json")
        with open(metrics_output_path, 'w') as f:
            json.dump(performance_summary, f, indent=2)

        print()
        print("=" * 60)
        print("Collection Summary")
        print("=" * 60)
        print(f"VMs scanned:           {output['statistics']['total_vms']}")
        print(f"Network flows:         {output['statistics']['total_flows']}")
        print(f"Config files:          {output['statistics']['total_config_files']}")
        print(f"Secrets found (T8):    {output['statistics']['total_secrets_found']}")
        print()

        # Print performance metrics
        print("=" * 60)
        print("Performance Metrics")
        print("=" * 60)
        perf = performance_summary.get('performance', {})
        print(f"Total time:            {perf.get('total_time_seconds', 0):.2f}s")
        print(f"Peak memory:           {perf.get('max_memory_mb', 0):.1f} MB")
        print(f"Avg CPU:               {perf.get('avg_cpu_percent', 0):.1f}%")
        print()
        print("Phase breakdown:")
        for phase, time_s in perf.get('phase_breakdown', {}).items():
            pct = (time_s / perf.get('total_time_seconds', 1)) * 100
            print(f"  {phase:30s} {time_s:6.2f}s ({pct:5.1f}%)")
        print()
        print(f"Metrics saved to: {metrics_output_path}")
        print()
        print("✓ Data collection complete!")
        print()

    except KeyboardInterrupt:
        print("\n\nCollection interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
