#!/usr/bin/env python3
"""
AWS Threat Report Generator
Generates markdown reports from detected threats
"""

from datetime import datetime
from collections import defaultdict


def generate_summary(threats, metadata):
    """Generate threat summary statistics"""
    threat_counts = defaultdict(int)
    severity_counts = defaultdict(int)

    for threat in threats:
        threat_counts[threat['threat_id']] += 1
        severity_counts[threat['severity']] += 1

    unique_threats = len(threat_counts)
    total_threats = len(threats)

    return {
        'total_threats': total_threats,
        'unique_threats': unique_threats,
        'threat_counts': dict(threat_counts),
        'severity_counts': dict(severity_counts),
        'metadata': metadata
    }


def generate_markdown_report(threats, summary):
    """Generate markdown threat report"""

    metadata = summary['metadata']

    report = f"""# AWS Cloud Threat Detection Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Platform:** {metadata.get('platform', 'cloud-aws')}
**Region:** {metadata.get('region', 'N/A')}
**Data Timestamp:** {metadata.get('timestamp', 'N/A')}

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Threats Detected | {summary['total_threats']} |
| Unique Threat Types | {summary['unique_threats']}/10 |
| EC2 Instances Analyzed | {metadata.get('summary', {}).get('instances_count', 0)} |
| Security Groups Analyzed | {metadata.get('summary', {}).get('security_groups_count', 0)} |
| IAM Roles Analyzed | {metadata.get('summary', {}).get('iam_roles_count', 0)} |
| Config Files Analyzed | {metadata.get('summary', {}).get('config_files_count', 0)} |

### Severity Distribution

"""

    severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    for severity in severity_order:
        count = summary['severity_counts'].get(severity, 0)
        if count > 0:
            report += f"- **{severity}:** {count}\n"

    report += "\n### Threat Type Distribution\n\n"

    threat_names = {
        'T1': 'Unauthenticated External Access',
        'T2': 'Excessive Permissions',
        'T3': 'Unencrypted Communication',
        'T4': 'Missing Network Segmentation',
        'T5': 'Anonymous Registry Access',
        'T6': 'CI/CD to Production Access',
        'T7': 'Missing Audit Logging',
        'T8': 'Exposed Secrets',
        'T9': 'Broad Source Control Access',
        'T10': 'Missing Resource Limits'
    }

    for threat_id in sorted(summary['threat_counts'].keys()):
        count = summary['threat_counts'][threat_id]
        name = threat_names.get(threat_id, 'Unknown')
        report += f"- **{threat_id}** ({name}): {count}\n"

    report += "\n---\n\n## Detailed Findings\n\n"

    # Group threats by type
    threats_by_type = defaultdict(list)
    for threat in threats:
        threats_by_type[threat['threat_id']].append(threat)

    for threat_id in sorted(threats_by_type.keys()):
        threat_list = threats_by_type[threat_id]
        threat_name = threat_names.get(threat_id, 'Unknown Threat')

        report += f"### {threat_id}: {threat_name}\n\n"
        report += f"**Count:** {len(threat_list)} findings\n\n"

        for idx, threat in enumerate(threat_list, 1):
            report += f"#### Finding {threat_id}.{idx}\n\n"
            report += f"- **Severity:** {threat['severity']}\n"
            report += f"- **Resource:** {threat['resource']}\n"
            report += f"- **Resource ID:** `{threat['resource_id']}`\n"
            report += f"- **Details:** {threat['details']}\n"

            if threat.get('evidence'):
                report += f"- **Evidence:**\n"
                for key, value in threat['evidence'].items():
                    report += f"  - `{key}`: {value}\n"

            report += "\n"

        report += "---\n\n"

    # Detection rate
    detection_rate = (summary['unique_threats'] / 10) * 100

    report += f"""## Detection Rate

**{summary['unique_threats']}/10 threat types detected ({detection_rate:.0f}%)**

"""

    if detection_rate == 100:
        report += "✅ **ALL T1-T10 threats detected!**\n\n"
    else:
        report += "⚠️ **Some threat types not detected.**\n\n"
        missing = set(f'T{i}' for i in range(1, 11)) - set(summary['threat_counts'].keys())
        if missing:
            report += f"Missing: {', '.join(sorted(missing))}\n\n"

    # Infrastructure details
    report += """---

## Infrastructure Details

### EC2 Instances

"""

    for instance in metadata.get('instances', []):
        report += f"""
**{instance['name']}** (`{instance['id']}`)
- Zone: {instance['zone']}
- Instance Type: {instance['instance_type']}
- Public IP: {instance['public_ip']}
- Private IP: {instance['private_ip']}
- Security Groups: {len(instance['security_groups'])}
- IAM Instance Profile: {instance.get('iam_instance_profile', 'None')[:50]}...
"""

    report += "\n### Security Groups\n\n"

    for sg in metadata.get('security_groups', []):
        report += f"""
**{sg['name']}** (`{sg['id']}`)
- VPC: {sg['vpc_id']}
- Ingress Rules: {len(sg['ingress_rules'])}
- Egress Rules: {len(sg['egress_rules'])}
"""

    report += "\n### IAM Roles\n\n"

    for role in metadata.get('iam_roles', []):
        report += f"""
**{role['name']}**
- ARN: `{role['arn']}`
- Instance Profile: {role['instance_profile']}
- Inline Policies: {len(role['inline_policies'])}
- Attached Policies: {len(role['attached_policies'])}
"""

    report += f"""
---

## Recommendations

Based on the findings, the following remediations are recommended:

### Critical Issues
"""

    critical_threats = [t for t in threats if t['severity'] == 'CRITICAL']
    if critical_threats:
        report += """
1. **Remove 0.0.0.0/0 access** from Security Groups (T1)
2. **Restrict IAM permissions** to least privilege (T2)
3. **Enable registry authentication** (T5)
4. **Remove production access** from CI/CD roles (T6)
5. **Rotate exposed secrets** immediately (T8)

"""
    else:
        report += "\nNo critical issues detected.\n\n"

    report += """### High Priority

1. **Enable TLS/HTTPS** for all services (T3)
2. **Implement network segmentation** with restrictive Security Groups (T4)
3. **Enable Docker logging** and CloudTrail (T7)
4. **Restrict source control access** (T9)

### Medium Priority

1. **Add resource limits** to Docker containers (T10)

---

## Next Steps

1. Review all critical findings and develop remediation plan
2. Implement security hardening for IAM roles and Security Groups
3. Enable comprehensive logging and monitoring
4. Establish network segmentation between zones
5. Rotate all exposed secrets
6. Re-run threat detection to validate fixes

---

*This is an automated threat detection report for educational purposes.*
*Infrastructure is intentionally vulnerable for demonstration.*
"""

    return report


def print_summary(summary):
    """Print summary to console"""
    print("\n" + "=" * 60)
    print("THREAT DETECTION SUMMARY")
    print("=" * 60)
    print(f"Platform: {summary['metadata'].get('platform', 'cloud-aws')}")
    print(f"Region: {summary['metadata'].get('region', 'N/A')}")
    print(f"Total Threats Detected: {summary['total_threats']}")
    print(f"Unique Threat Types: {summary['unique_threats']}/10")
    print()

    detection_rate = (summary['unique_threats'] / 10) * 100
    print(f"Detection Rate: {summary['unique_threats']}/10 ({detection_rate:.0f}%)")

    if detection_rate == 100:
        print("\n✅ ALL T1-T10 threats detected!")
    else:
        print("\n⚠️ Some threats not detected")

    print("\nSeverity Breakdown:")
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = summary['severity_counts'].get(severity, 0)
        if count > 0:
            print(f"  {severity}: {count}")

    print("\nThreat Breakdown:")
    for threat_id in sorted(summary['threat_counts'].keys()):
        count = summary['threat_counts'][threat_id]
        print(f"  {threat_id}: {count}")

    print("=" * 60)
