#!/usr/bin/env python3
"""
AWS Threat Detector
Detects T1-T10 supply chain threats in AWS infrastructure
"""

import re
from config import (
    EXTERNAL_ACCESS_CIDRS,
    EXCESSIVE_IAM_ACTIONS,
    INSECURE_PORTS,
    VPC_WIDE_CIDRS,
    REGISTRY_PORTS,
    CICD_ROLE_PATTERNS,
    PRODUCTION_ACTIONS,
    DISABLED_LOG_DRIVERS,
    SECRET_PATTERNS,
    GITEA_INSECURE_SETTINGS,
    RESOURCE_LIMIT_KEYS
)


def detect_t1_external_access(data):
    """T1: Unauthenticated External Access via Security Groups"""
    threats = []

    for sg in data.get('security_groups', []):
        for rule in sg.get('ingress_rules', []):
            for cidr in rule.get('cidr_blocks', []):
                if cidr in EXTERNAL_ACCESS_CIDRS:
                    threats.append({
                        'threat_id': 'T1',
                        'threat': 'Unauthenticated External Access',
                        'severity': 'CRITICAL',
                        'resource': sg['name'],
                        'resource_id': sg['id'],
                        'details': f"Security group allows {cidr} ingress on port {rule.get('from_port', 'all')}",
                        'evidence': {
                            'protocol': rule.get('protocol', ''),
                            'from_port': rule.get('from_port', ''),
                            'to_port': rule.get('to_port', ''),
                            'cidr': cidr
                        }
                    })

    return threats


def detect_t2_excessive_permissions(data):
    """T2: Excessive Permissions in IAM Roles"""
    threats = []

    for role in data.get('iam_roles', []):
        # Check inline policies
        for policy in role.get('inline_policies', []):
            for statement in policy.get('document', {}).get('Statement', []):
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]

                for action in actions:
                    if action in EXCESSIVE_IAM_ACTIONS:
                        threats.append({
                            'threat_id': 'T2',
                            'threat': 'Excessive Permissions',
                            'severity': 'CRITICAL',
                            'resource': role['name'],
                            'resource_id': role['arn'],
                            'details': f"IAM role has excessive permission: {action}",
                            'evidence': {
                                'policy_name': policy['name'],
                                'action': action,
                                'effect': statement.get('Effect', ''),
                                'resource': statement.get('Resource', '')
                            }
                        })

        # Check attached managed policies
        for policy in role.get('attached_policies', []):
            # AdministratorAccess or PowerUserAccess are excessive
            if 'Administrator' in policy['name'] or 'PowerUser' in policy['name']:
                threats.append({
                    'threat_id': 'T2',
                    'threat': 'Excessive Permissions',
                    'severity': 'CRITICAL',
                    'resource': role['name'],
                    'resource_id': role['arn'],
                    'details': f"IAM role has excessive managed policy: {policy['name']}",
                    'evidence': {
                        'policy_name': policy['name'],
                        'policy_arn': policy['arn']
                    }
                })

    return threats


def detect_t3_unencrypted_communication(data):
    """T3: Unencrypted Communication (HTTP instead of HTTPS)"""
    threats = []

    # Check security groups for HTTP ports
    for sg in data.get('security_groups', []):
        for rule in sg.get('ingress_rules', []):
            from_port = rule.get('from_port', 0)
            to_port = rule.get('to_port', 0)

            for insecure_port in INSECURE_PORTS:
                if from_port <= insecure_port <= to_port:
                    threats.append({
                        'threat_id': 'T3',
                        'threat': 'Unencrypted Communication',
                        'severity': 'HIGH',
                        'resource': sg['name'],
                        'resource_id': sg['id'],
                        'details': f"Security group allows insecure port {insecure_port} (HTTP/plaintext)",
                        'evidence': {
                            'port': insecure_port,
                            'protocol': rule.get('protocol', ''),
                            'cidr_blocks': rule.get('cidr_blocks', [])
                        }
                    })

    # Check config files for HTTP URLs
    for config in data.get('configs', []):
        content = config.get('content', '')
        if 'http://' in content.lower() and 'https://' not in content.lower():
            threats.append({
                'threat_id': 'T3',
                'threat': 'Unencrypted Communication',
                'severity': 'HIGH',
                'resource': config['instance'],
                'resource_id': config['instance_id'],
                'details': f"Config file uses HTTP URLs: {config['path']}",
                'evidence': {
                    'file': config['path'],
                    'zone': config['zone']
                }
            })

    return threats


def detect_t4_missing_segmentation(data):
    """T4: Missing Network Segmentation"""
    threats = []

    # Check security groups for VPC-wide access
    for sg in data.get('security_groups', []):
        for rule in sg.get('ingress_rules', []):
            for cidr in rule.get('cidr_blocks', []):
                # Check if CIDR covers entire VPC
                for vpc_cidr in VPC_WIDE_CIDRS:
                    if cidr.startswith(vpc_cidr.split('/')[0]):
                        threats.append({
                            'threat_id': 'T4',
                            'threat': 'Missing Network Segmentation',
                            'severity': 'HIGH',
                            'resource': sg['name'],
                            'resource_id': sg['id'],
                            'details': f"Security group allows VPC-wide access ({cidr})",
                            'evidence': {
                                'cidr': cidr,
                                'from_port': rule.get('from_port', ''),
                                'to_port': rule.get('to_port', ''),
                                'vpc_id': sg['vpc_id']
                            }
                        })

    return threats


def detect_t5_anonymous_registry(data):
    """T5: Anonymous Registry Access"""
    threats = []

    # Check security groups for exposed registry ports
    for sg in data.get('security_groups', []):
        for rule in sg.get('ingress_rules', []):
            from_port = rule.get('from_port', 0)
            to_port = rule.get('to_port', 0)

            for registry_port in REGISTRY_PORTS:
                if from_port <= registry_port <= to_port:
                    for cidr in rule.get('cidr_blocks', []):
                        if cidr in EXTERNAL_ACCESS_CIDRS:
                            threats.append({
                                'threat_id': 'T5',
                                'threat': 'Anonymous Registry Access',
                                'severity': 'CRITICAL',
                                'resource': sg['name'],
                                'resource_id': sg['id'],
                                'details': f"Docker Registry exposed on port {registry_port} to {cidr}",
                                'evidence': {
                                    'port': registry_port,
                                    'cidr': cidr
                                }
                            })

    # Check config files for registry without auth
    for config in data.get('configs', []):
        content = config.get('content', '')
        if 'registry' in config.get('path', '').lower():
            if 'REGISTRY_AUTH' not in content and 'htpasswd' not in content:
                threats.append({
                    'threat_id': 'T5',
                    'threat': 'Anonymous Registry Access',
                    'severity': 'CRITICAL',
                    'resource': config['instance'],
                    'resource_id': config['instance_id'],
                    'details': f"Docker Registry has no authentication configured",
                    'evidence': {
                        'file': config['path'],
                        'zone': config['zone']
                    }
                })

    return threats


def detect_t6_cicd_prod_access(data):
    """T6: CI/CD to Production Access"""
    threats = []

    for role in data.get('iam_roles', []):
        role_name = role['name'].lower()

        # Check if this is a CI/CD role
        is_cicd_role = any(pattern in role_name for pattern in CICD_ROLE_PATTERNS)

        if is_cicd_role:
            # Check if it has production access
            for policy in role.get('inline_policies', []):
                for statement in policy.get('document', {}).get('Statement', []):
                    actions = statement.get('Action', [])
                    if isinstance(actions, str):
                        actions = [actions]

                    for action in actions:
                        if action in PRODUCTION_ACTIONS or action == '*':
                            threats.append({
                                'threat_id': 'T6',
                                'threat': 'CI/CD to Production Access',
                                'severity': 'CRITICAL',
                                'resource': role['name'],
                                'resource_id': role['arn'],
                                'details': f"CI/CD role has production permissions: {action}",
                                'evidence': {
                                    'policy_name': policy['name'],
                                    'action': action,
                                    'resource': statement.get('Resource', '')
                                }
                            })

    return threats


def detect_t7_missing_logging(data):
    """T7: Missing Audit Logging"""
    threats = []

    for config in data.get('configs', []):
        if 'daemon.json' in config.get('path', ''):
            content = config.get('content', '')

            # Check for disabled logging
            for disabled_driver in DISABLED_LOG_DRIVERS:
                if f'"log-driver": "{disabled_driver}"' in content:
                    threats.append({
                        'threat_id': 'T7',
                        'threat': 'Missing Audit Logging',
                        'severity': 'HIGH',
                        'resource': config['instance'],
                        'resource_id': config['instance_id'],
                        'details': f"Docker logging disabled (log-driver: {disabled_driver})",
                        'evidence': {
                            'file': config['path'],
                            'log_driver': disabled_driver,
                            'zone': config['zone']
                        }
                    })

    # Check if CloudTrail is disabled (would be in VPC data if enabled)
    # For now, assume missing CloudTrail if not explicitly configured

    return threats


def detect_t8_exposed_secrets(data):
    """T8: Exposed Secrets in Configuration Files"""
    threats = []

    for config in data.get('configs', []):
        content = config.get('content', '')

        # Scan for hardcoded secrets
        secrets_found = []
        for pattern in SECRET_PATTERNS:
            # Look for pattern = "value" or pattern: value
            regex = rf'{pattern}["\s:=]+["\']?([^"\'\s]+)'
            matches = re.findall(regex, content, re.IGNORECASE)

            for match in matches:
                # Ignore placeholder values
                if match not in ['${', '***', 'CHANGE_ME', 'your-', 'example']:
                    secrets_found.append((pattern, match))

        if secrets_found:
            threats.append({
                'threat_id': 'T8',
                'threat': 'Exposed Secrets',
                'severity': 'CRITICAL',
                'resource': config['instance'],
                'resource_id': config['instance_id'],
                'details': f"Found {len(secrets_found)} hardcoded secrets in {config['path']}",
                'evidence': {
                    'file': config['path'],
                    'zone': config['zone'],
                    'secrets_count': len(secrets_found),
                    'secret_types': [s[0] for s in secrets_found]
                }
            })

    return threats


def detect_t9_broad_scm_access(data):
    """T9: Broad Source Control Access"""
    threats = []

    for config in data.get('configs', []):
        if 'gitea' in config.get('path', '').lower():
            content = config.get('content', '')

            # Check for insecure Gitea settings
            for insecure_setting in GITEA_INSECURE_SETTINGS:
                if insecure_setting in content:
                    threats.append({
                        'threat_id': 'T9',
                        'threat': 'Broad Source Control Access',
                        'severity': 'HIGH',
                        'resource': config['instance'],
                        'resource_id': config['instance_id'],
                        'details': f"Gitea allows anonymous access: {insecure_setting}",
                        'evidence': {
                            'file': config['path'],
                            'zone': config['zone'],
                            'setting': insecure_setting
                        }
                    })

    return threats


def detect_t10_missing_limits(data):
    """T10: Missing Resource Limits"""
    threats = []

    for config in data.get('configs', []):
        if 'docker-compose' in config.get('path', ''):
            content = config.get('content', '')

            # Check if resource limits are missing
            has_limits = any(key in content for key in RESOURCE_LIMIT_KEYS)

            if not has_limits:
                # Count services without limits
                service_count = content.count('image:')

                if service_count > 0:
                    threats.append({
                        'threat_id': 'T10',
                        'threat': 'Missing Resource Limits',
                        'severity': 'MEDIUM',
                        'resource': config['instance'],
                        'resource_id': config['instance_id'],
                        'details': f"Docker Compose has {service_count} services without resource limits",
                        'evidence': {
                            'file': config['path'],
                            'zone': config['zone'],
                            'services_count': service_count
                        }
                    })

    return threats


def detect_all_threats(data):
    """Run all threat detectors"""
    all_threats = []

    detectors = [
        ('T1', detect_t1_external_access),
        ('T2', detect_t2_excessive_permissions),
        ('T3', detect_t3_unencrypted_communication),
        ('T4', detect_t4_missing_segmentation),
        ('T5', detect_t5_anonymous_registry),
        ('T6', detect_t6_cicd_prod_access),
        ('T7', detect_t7_missing_logging),
        ('T8', detect_t8_exposed_secrets),
        ('T9', detect_t9_broad_scm_access),
        ('T10', detect_t10_missing_limits),
    ]

    print("\nRunning threat detection...")
    print("=" * 60)

    for threat_id, detector in detectors:
        threats = detector(data)
        all_threats.extend(threats)
        print(f"{threat_id}: {len(threats)} threats detected")

    return all_threats
