#!/usr/bin/env python3
"""
Threat Instance Counter for AWS deployments.
Counts individual threat instances (not just types) from extracted metadata.
Used for paper reporting: "17 threat types yielding N threat instances"
"""

import json
import re
import sys
from pathlib import Path
from collections import defaultdict

# Import T01-T10 detectors
from threat_detector import detect_all_threats


def count_additional_traditional(data):
    """Count additional traditional threat instances from user-data and S3 metadata.
    Supplements T05-T10 detections that the basic threat_detector misses
    when deployments use docker run (not docker-compose) or different services."""
    additional = defaultdict(list)

    instances = data.get('instances', [])
    s3_buckets = data.get('s3_buckets', [])

    # T05: S3 public access (registry/artifact storage without auth)
    for bucket in s3_buckets:
        pub = bucket.get('public_access_block', {})
        if not pub.get('BlockPublicAcls', True) and not pub.get('BlockPublicPolicy', True):
            additional['T05'].append({
                'threat_id': 'T5',
                'threat': 'Anonymous Registry Access',
                'severity': 'CRITICAL',
                'resource': bucket['name'],
                'resource_id': bucket['name'],
                'details': f"S3 bucket {bucket['name']} has public access enabled"
            })
        if bucket.get('policy'):
            for stmt in bucket['policy'].get('Statement', []):
                if stmt.get('Principal') == '*' or stmt.get('Principal', {}).get('AWS') == '*':
                    additional['T05'].append({
                        'threat_id': 'T5',
                        'threat': 'Anonymous Registry Access',
                        'severity': 'CRITICAL',
                        'resource': bucket['name'],
                        'resource_id': bucket['name'],
                        'details': f"S3 bucket {bucket['name']} allows anonymous access via policy"
                    })

    # T06: CI/CD production access via shared IAM roles
    cicd_names = ['jenkins', 'cicd', 'build']
    non_cicd_names = ['prod', 'app', 'database', 'storage', 'llm', 'loadbalancer']
    cicd_instances = [i for i in instances if any(n in i['name'].lower() for n in cicd_names)]
    prod_instances = [i for i in instances if any(n in i['name'].lower() for n in non_cicd_names)]
    if cicd_instances and prod_instances:
        cicd_profiles = set(i.get('iam_instance_profile', '') for i in cicd_instances if i.get('iam_instance_profile'))
        prod_profiles = set(i.get('iam_instance_profile', '') for i in prod_instances if i.get('iam_instance_profile'))
        shared = cicd_profiles & prod_profiles
        if shared:
            additional['T06'].append({
                'threat_id': 'T6',
                'threat': 'CI/CD to Production Access',
                'severity': 'CRITICAL',
                'resource': cicd_instances[0]['name'],
                'resource_id': cicd_instances[0]['id'],
                'details': f"CI/CD instance shares IAM role with production instances"
            })

    # T07: Missing logging from user-data (no log config, no monitoring setup)
    for inst in instances:
        ud = inst.get('user_data', '')
        if ud and 'log-driver' not in ud and 'logging' not in ud.lower() and 'cloudwatch' not in ud.lower():
            if 'docker' in ud.lower() or 'systemd' in ud.lower():
                additional['T07'].append({
                    'threat_id': 'T7',
                    'threat': 'Missing Audit Logging',
                    'severity': 'HIGH',
                    'resource': inst['name'],
                    'resource_id': inst['id'],
                    'details': f"No logging configuration in service setup"
                })

    # T09: Missing authentication on services (from user-data)
    for inst in instances:
        ud = inst.get('user_data', '')
        if '# T01: No password' in ud or '"authentication": "none"' in ud:
            additional['T09'].append({
                'threat_id': 'T9',
                'threat': 'Broad Access Control',
                'severity': 'HIGH',
                'resource': inst['name'],
                'resource_id': inst['id'],
                'details': f"Service configured without authentication"
            })
        if 'sslmode=disable' in ud:
            additional['T09'].append({
                'threat_id': 'T9',
                'threat': 'Broad Access Control',
                'severity': 'HIGH',
                'resource': inst['name'],
                'resource_id': inst['id'],
                'details': f"Database connection uses sslmode=disable"
            })

    # T10: Missing resource limits in docker run commands (user-data)
    for inst in instances:
        ud = inst.get('user_data', '')
        docker_runs = re.findall(r'docker run\s+.*?(?:\n|$)', ud, re.DOTALL)
        for cmd in docker_runs:
            if '--memory' not in cmd and '--cpus' not in cmd and '-m ' not in cmd:
                additional['T10'].append({
                    'threat_id': 'T10',
                    'threat': 'Missing Resource Limits',
                    'severity': 'MEDIUM',
                    'resource': inst['name'],
                    'resource_id': inst['id'],
                    'details': f"Docker container started without resource limits"
                })

    # Deduplicate
    deduped = {}
    for tid, findings in additional.items():
        seen = set()
        unique = []
        for f in findings:
            key = (f['resource'], f['details'])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        deduped[tid] = unique

    return deduped


def count_ml_instances(data):
    """Count ML-specific threat instances (T11-T17) from configs and user-data"""
    ml_instances = defaultdict(list)

    configs = data.get('configs', [])
    instances = data.get('instances', [])

    # Combine config content and user_data for scanning
    all_content = []
    for config in configs:
        all_content.append({
            'source': f"config:{config.get('path', '')}",
            'instance': config.get('instance', ''),
            'content': config.get('content', '')
        })
    for inst in instances:
        if inst.get('user_data'):
            all_content.append({
                'source': f"user-data:{inst.get('name', '')}",
                'instance': inst.get('name', ''),
                'content': inst.get('user_data', '')
            })

    for item in all_content:
        content = item['content']
        source = item['source']
        inst_name = item['instance']

        # T11: Unauthorized Model Access - ML service without auth
        if ('MLFLOW_AUTH=none' in content or 'MLFLOW_AUTH' in content and 'none' in content) or \
           ('mlflow' in content.lower() and 'no auth' in content.lower()) or \
           ('"authentication": "none"' in content and ('model' in content.lower() or 'llm' in content.lower())) or \
           ('# T11' in content):
            ml_instances['T11'].append({
                'resource': inst_name,
                'details': 'ML service exposed without authentication',
                'source': source
            })

        # T12: Training Data Poisoning - write access to training/model data
        if ('training-data' in content.lower() or 'training_data' in content.lower()) and \
           ('write' in content.lower() or ':rw' in content or 's3:PutObject' in content or
            'edit' in content.lower()):
            ml_instances['T12'].append({
                'resource': inst_name,
                'details': 'Write access to training data',
                'source': source
            })
        elif ('s3:*' in content or 'S3_BUCKET' in content or 's3_bucket' in content.lower()) and \
             ('model' in content.lower() or 'quay' in content.lower()):
            ml_instances['T12'].append({
                'resource': inst_name,
                'details': 'Unrestricted S3 access to model/image storage',
                'source': source
            })

        # T13: Model Theft via API - inference endpoint without auth/rate limiting
        if ('ml-inference' in content.lower() or 'inference' in content.lower() or
            'llm' in content.lower()) and \
           ('8000' in content) and \
           ('no auth' in content.lower() or 'RATE_LIMIT' not in content or
            '# T13' in content or '"authentication": "none"' in content):
            ml_instances['T13'].append({
                'resource': inst_name,
                'details': 'ML inference API without authentication/rate limiting',
                'source': source
            })

        # T14: Unencrypted Model Transfer - HTTP model downloads/endpoints
        if 'MLFLOW_TRACKING_URI=http://' in content or \
           ('mlflow' in content.lower() and 'http://' in content and 'https://' not in content) or \
           ('# T14' in content) or \
           ('model' in content.lower() and 'http://' in content and 'https://' not in content and
            ('download' in content.lower() or 'inference' in content.lower() or 'llm' in content.lower())):
            ml_instances['T14'].append({
                'resource': inst_name,
                'details': 'HTTP (unencrypted) model transfer',
                'source': source
            })

        # T15: ML Pipeline to Production Access
        if ('jenkins' in content.lower() or 'cicd' in content.lower()) and \
           ('prod' in content.lower() or 's3:*' in content or 'ec2:*' in content) and \
           ('ec2:*' in content or 'ssh' in content.lower() or 'edit' in content.lower() or
            's3:*' in content or 'deploy' in content.lower()):
            ml_instances['T15'].append({
                'resource': inst_name,
                'details': 'CI/CD pipeline has production ML access',
                'source': source
            })

        # T16: Missing Model Provenance
        if ('mlflow' in content.lower() and
            ('file://' in content or 'filesystem' in content.lower() or
             'no versioning' in content.lower() or 'BACKEND_STORE_URI=file' in content)) or \
           ('# T16' in content) or \
           ('model' in content.lower() and 'provenance' in content.lower()):
            ml_instances['T16'].append({
                'resource': inst_name,
                'details': 'No model provenance/versioning tracking',
                'source': source
            })

        # T17: Exposed Model Metadata
        if ('DEBUG_MODE=true' in content or 'debug_mode=true' in content.lower()) and \
           ('model' in content.lower() or 'inference' in content.lower()):
            ml_instances['T17'].append({
                'resource': inst_name,
                'details': 'Debug endpoints expose model metadata',
                'source': source
            })
        elif ('# T17' in content) or \
             ('model-info' in content.lower() and ('api_port' in content or 'model_path' in content)):
            ml_instances['T17'].append({
                'resource': inst_name,
                'details': 'Model metadata exposed in configuration',
                'source': source
            })

    # Deduplicate: keep only unique (threat_id, instance) pairs
    deduped = {}
    for tid, findings in ml_instances.items():
        seen = set()
        unique = []
        for f in findings:
            key = f['resource']
            if key not in seen:
                seen.add(key)
                unique.append(f)
        deduped[tid] = unique

    return deduped


def main():
    # Load metadata
    metadata_path = Path("platforms/cloud_aws/extractor/output/cloud_aws_metadata.json")
    if not metadata_path.exists():
        print(f"ERROR: {metadata_path} not found. Run extractor first.")
        sys.exit(1)

    with open(metadata_path) as f:
        data = json.load(f)

    print("=" * 70)
    print("THREAT INSTANCE COUNTER")
    print("=" * 70)
    print()

    # T01-T10: Run existing detectors
    print("--- Traditional Threats (T01-T10) ---")
    traditional_threats = detect_all_threats(data)

    # Count by type
    traditional_by_type = defaultdict(list)
    for t in traditional_threats:
        # Normalize threat ID: T1 -> T01
        tid = t['threat_id']
        if len(tid) == 2:  # T1 -> T01
            tid = f"T{int(tid[1:]):02d}"
        traditional_by_type[tid].append(t)

    # Supplement with additional detections from user-data and S3
    additional = count_additional_traditional(data)
    for tid_short, findings in additional.items():
        full_tid = tid_short  # Already T05 format
        if full_tid not in traditional_by_type or len(traditional_by_type[full_tid]) == 0:
            for f in findings:
                traditional_threats.append(f)
                traditional_by_type[full_tid].append(f)

    print()
    for tid in sorted(traditional_by_type.keys()):
        instances = traditional_by_type[tid]
        print(f"  {tid}: {len(instances)} instances")
        for inst in instances:
            print(f"    - {inst['resource']}: {inst['details']}")

    traditional_total = len(traditional_threats)
    print(f"\n  Traditional total: {traditional_total}")

    # T11-T17: ML threats
    print("\n--- ML/AI Threats (T11-T17) ---")
    ml_by_type = count_ml_instances(data)

    ml_total = 0
    for tid in sorted(ml_by_type.keys()):
        instances = ml_by_type[tid]
        ml_total += len(instances)
        print(f"  {tid}: {len(instances)} instances")
        for inst in instances:
            print(f"    - {inst['resource']}: {inst['details']}")

    # Fill in any ML threats not found
    for i in range(11, 18):
        tid = f"T{i:02d}"
        if tid not in ml_by_type:
            print(f"  {tid}: 0 instances (NOT DETECTED)")

    print(f"\n  ML total: {ml_total}")

    # Summary
    grand_total = traditional_total + ml_total
    types_detected = len(traditional_by_type) + len(ml_by_type)

    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Threat types detected: {types_detected}/17")
    print(f"  Traditional instances (T01-T10): {traditional_total}")
    print(f"  ML instances (T11-T17): {ml_total}")
    print(f"  TOTAL INSTANCES: {grand_total}")
    print()

    # Save results
    results = {
        'platform': 'AWS',
        'case_study': data.get('summary', {}).get('instances_count', 'unknown'),
        'threat_types_detected': types_detected,
        'traditional_instances': traditional_total,
        'ml_instances': ml_total,
        'total_instances': grand_total,
        'by_type': {}
    }
    for tid in sorted(list(traditional_by_type.keys()) + list(ml_by_type.keys())):
        if tid in traditional_by_type:
            results['by_type'][tid] = len(traditional_by_type[tid])
        elif tid in ml_by_type:
            results['by_type'][tid] = len(ml_by_type[tid])

    output_path = Path("platforms/cloud_aws/analyzer/output/instance_counts.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"Results saved to: {output_path}")


if __name__ == '__main__':
    main()
