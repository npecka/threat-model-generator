#!/usr/bin/env python3
"""
AWS Cloud Supply Chain Data Extractor
Collects metadata from AWS for threat detection
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Add parent directories to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from common.metrics_collector import MetricsCollector

from config import AWS_REGION, OUTPUT_FILE
from ec2_fetcher import (
    get_ec2_instances,
    get_security_groups,
    get_iam_roles,
    get_iam_users,
    get_vpc_details
)
from config_fetcher import collect_instance_configs, get_docker_info


def main():
    print("=" * 60)
    print("AWS Cloud Data Collection")
    print("=" * 60)
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Region: {AWS_REGION}")
    print()

    # Initialize metrics collector
    metrics = MetricsCollector()

    # Collect EC2 instances
    print("Collecting EC2 instances...")
    metrics.start_phase("ec2_instances_collection")
    instances = get_ec2_instances(AWS_REGION)
    metrics.end_phase("ec2_instances_collection")

    if not instances:
        print("\n⚠️  No instances found!")
        print("Make sure infrastructure is deployed:")
        print("  cd ../../case_studies/cloud_aws/supply_chain")
        print("  bash deploy.sh")
        return

    print(f"\n✓ Found {len(instances)} instances")
    for inst in instances:
        print(f"  - {inst['name']} ({inst['zone']}): {inst['public_ip']}")

    # Collect Security Groups
    print("\nCollecting security groups...")
    metrics.start_phase("security_groups_collection")
    sg_ids = list(set(sg for inst in instances for sg in inst['security_groups']))
    security_groups = get_security_groups(AWS_REGION, sg_ids)
    metrics.end_phase("security_groups_collection")

    # Collect IAM Roles
    print("\nCollecting IAM roles...")
    metrics.start_phase("iam_roles_collection")
    profile_arns = list(set(inst['iam_instance_profile'] for inst in instances if inst['iam_instance_profile']))
    iam_roles = get_iam_roles(AWS_REGION, profile_arns)
    metrics.end_phase("iam_roles_collection")

    # Collect IAM Users
    print("\nCollecting IAM users...")
    metrics.start_phase("iam_users_collection")
    iam_users = get_iam_users(AWS_REGION)
    metrics.end_phase("iam_users_collection")

    # Collect VPC details
    print("\nCollecting VPC configuration...")
    metrics.start_phase("vpc_collection")
    vpc_ids = list(set(inst['vpc_id'] for inst in instances if inst['vpc_id']))
    vpc = get_vpc_details(AWS_REGION, vpc_ids[0] if vpc_ids else None)
    metrics.end_phase("vpc_collection")

    # Collect configuration files from instances
    print("\nCollecting configuration files...")
    metrics.start_phase("config_files_collection")
    all_configs = []
    for instance in instances:
        configs = collect_instance_configs(instance)
        all_configs.extend(configs)
    metrics.end_phase("config_files_collection")

    print(f"\n✓ Collected {len(all_configs)} config files")

    # Collect S3 buckets
    print("\nCollecting S3 buckets...")
    metrics.start_phase("s3_buckets_collection")
    from ec2_fetcher import get_s3_buckets
    s3_buckets = get_s3_buckets(AWS_REGION)
    metrics.end_phase("s3_buckets_collection")

    # Collect Docker info from each instance
    print("\nCollecting Docker information...")
    metrics.start_phase("docker_info_collection")
    for instance in instances:
        if instance['public_ip']:
            docker_info = get_docker_info(instance['public_ip'])
            instance['docker'] = docker_info
            print(f"  {instance['name']}: {len(docker_info['containers'])} containers")
    metrics.end_phase("docker_info_collection")

    # Assemble output
    metrics.start_phase("output_serialization")
    output_data = {
        'timestamp': datetime.now().isoformat(),
        'region': AWS_REGION,
        'platform': 'cloud-aws',
        'instances': instances,
        'security_groups': security_groups,
        'iam_roles': iam_roles,
        'iam_users': iam_users,
        'vpc': vpc,
        's3_buckets': s3_buckets,
        'configs': all_configs,
        'summary': {
            'instances_count': len(instances),
            'security_groups_count': len(security_groups),
            'iam_roles_count': len(iam_roles),
            'iam_users_count': len(iam_users),
            's3_buckets_count': len(s3_buckets),
            'config_files_count': len(all_configs),
        }
    }

    # Ensure output directory exists
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    # Write output
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(output_data, f, indent=2, default=str)
    metrics.end_phase("output_serialization")

    # Get file size
    file_size = os.path.getsize(OUTPUT_FILE) / 1024  # KB

    # Save metrics report
    performance_summary = metrics.generate_report()
    metrics_output_path = os.path.join(os.path.dirname(OUTPUT_FILE), "extractor_metrics.json")
    with open(metrics_output_path, 'w') as f:
        json.dump(performance_summary, f, indent=2)

    print()
    print(f"Output written to: {OUTPUT_FILE}")
    print(f"File size: {file_size:.2f} KB")
    print()

    # Summary
    print("=" * 60)
    print("Collection Summary")
    print("=" * 60)
    print(f"EC2 Instances:     {len(instances)}")
    print(f"Security Groups:   {len(security_groups)}")
    print(f"IAM Roles:         {len(iam_roles)}")
    print(f"VPC/Subnets:       {len(vpc.get('subnets', []))}")
    print(f"Config Files:      {len(all_configs)}")
    print()

    # Print performance metrics
    print("=" * 60)
    print("Performance Metrics")
    print("=" * 60)
    perf = performance_summary.get('performance', {})
    print(f"Total time:        {perf.get('total_time_seconds', 0):.2f}s")
    print(f"Peak memory:       {perf.get('max_memory_mb', 0):.1f} MB")
    print(f"Avg CPU:           {perf.get('avg_cpu_percent', 0):.1f}%")
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
    print("Next step: Run threat analyzer")
    print("  cd ../analyzer")
    print("  python3 main.py")
    print()


if __name__ == '__main__':
    main()
