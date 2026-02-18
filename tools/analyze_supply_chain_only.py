#!/usr/bin/env python3
"""
Focused analysis: Only detect T1-T10 threats in supply chain namespaces.
Filters out all other namespaces and threat types.
"""

import json
import sys

# Supply chain namespaces ONLY
SUPPLY_CHAIN_NS = {'dev-zone', 'cicd-zone', 'prod-zone'}

def filter_supply_chain_data(metadata):
    """Filter metadata to only include supply chain namespaces"""

    filtered = {
        'pods': [p for p in metadata['pods'] if p['namespace'] in SUPPLY_CHAIN_NS],
        'services': {name: data for name, data in metadata['services'].items()
                     if data['namespace'] in SUPPLY_CHAIN_NS},
        'rbac': [r for r in metadata['rbac'] if r.get('namespace') in SUPPLY_CHAIN_NS
                 or any(s.get('namespace') in SUPPLY_CHAIN_NS for s in r.get('subjects', []))],
        'configmaps': [c for c in metadata['configmaps'] if c['namespace'] in SUPPLY_CHAIN_NS],
        'network_policies': metadata.get('network_policies', []),  # Keep all for checking missing ones
        'namespaces': [n for n in metadata['namespaces'] if n['name'] in SUPPLY_CHAIN_NS],
        'falco_events': [e for e in metadata.get('falco_events', [])
                         if e.get('namespace') in SUPPLY_CHAIN_NS],
        'hubble_flows': metadata.get('hubble_flows', [])  # Flows will be filtered by pod IPs
    }

    return filtered

def detect_t1_external_exposure(services):
    """T1: Unauthenticated External Access (LoadBalancer/NodePort)"""
    threats = []
    for name, svc in services.items():
        svc_type = svc.get('type', 'ClusterIP')
        if svc_type in ['LoadBalancer', 'NodePort']:
            threats.append({
                'id': 'T01',
                'component': name,
                'namespace': svc['namespace'],
                'severity': 'High',
                'description': f"Service {name} exposed via {svc_type} without authentication",
                'evidence': f"Service type: {svc_type} (externally accessible)"
            })
    return threats

def detect_t2_excessive_permissions(rbac):
    """T2: Excessive Permissions"""
    threats = []
    dangerous_roles = ['cluster-admin', 'admin']

    for binding in rbac:
        role = binding.get('role', '')
        if role in dangerous_roles:
            for subject in binding.get('subjects', []):
                if subject.get('namespace') in SUPPLY_CHAIN_NS:
                    threats.append({
                        'id': 'T02',
                        'component': subject.get('name', 'unknown'),
                        'namespace': subject.get('namespace'),
                        'severity': 'High',
                        'description': f"ServiceAccount {subject.get('name')} has excessive permissions ({role})",
                        'evidence': f"ClusterRole: {role}"
                    })
    return threats

def detect_t3_unencrypted_http(services):
    """T3: Unencrypted HTTP Communication"""
    threats = []
    for name, svc in services.items():
        for port_info in svc.get('ports', []):
            port = port_info.get('port')
            if port in [80, 8080, 3000]:  # Common HTTP ports
                threats.append({
                    'id': 'T03',
                    'component': name,
                    'namespace': svc['namespace'],
                    'severity': 'Medium',
                    'description': f"Service {name} uses unencrypted HTTP on port {port}",
                    'evidence': f"Port {port} (HTTP) without TLS encryption"
                })
    return threats

def detect_t4_missing_network_policies(namespaces, network_policies):
    """T4: Missing Network Policies"""
    threats = []

    # Get namespaces that have network policies
    ns_with_policies = set(np.get('namespace') for np in network_policies)

    for ns in namespaces:
        ns_name = ns['name']
        if ns_name not in ns_with_policies:
            threats.append({
                'id': 'T04',
                'component': ns_name,
                'namespace': ns_name,
                'severity': 'High',
                'description': f"Namespace {ns_name} has no NetworkPolicies (unrestricted network access)",
                'evidence': "No NetworkPolicy resources found in namespace"
            })
    return threats

def detect_t5_registry_misconfig(pods, configmaps):
    """T5: Anonymous Registry Access"""
    threats = []

    # Look for registry pods
    for pod in pods:
        if 'registry' in pod['name'].lower():
            # Check for auth in configmaps
            registry_configs = [c for c in configmaps if 'registry' in c['name'].lower()]
            has_auth = False
            for config in registry_configs:
                data = config.get('data', {})
                config_content = str(data)
                # Check if auth section is enabled (not commented out)
                if 'auth:' in config_content and not '# auth:' in config_content:
                    has_auth = True

            if not has_auth:
                threats.append({
                    'id': 'T05',
                    'component': pod['name'].rsplit('-', 2)[0],  # Get base name
                    'namespace': pod['namespace'],
                    'severity': 'Critical',
                    'description': f"Registry {pod['name']} has no authentication configured",
                    'evidence': "No authentication configuration found (auth section commented out)"
                })
    return threats

def detect_t6_cicd_to_prod(rbac):
    """T6: CI/CD Pipeline to Production Access"""
    threats = []

    for binding in rbac:
        # Check if binding grants cicd-zone service accounts access to prod-zone
        binding_ns = binding.get('namespace')
        role = binding.get('role', '')

        # Case 1: RoleBinding in prod-zone for cicd-zone subjects
        if binding_ns == 'prod-zone':
            for subject in binding.get('subjects', []):
                if subject.get('namespace') == 'cicd-zone':
                    threats.append({
                        'id': 'T06',
                        'component': subject.get('name'),
                        'namespace': 'cicd-zone',
                        'severity': 'High',
                        'description': f"CI/CD ServiceAccount {subject.get('name')} can access production namespace",
                        'evidence': f"RoleBinding {binding.get('binding')} grants {role} in prod-zone"
                    })

        # Case 2: ClusterRole binding for cicd-zone subjects (can access all namespaces)
        if binding_ns in [None, 'cluster'] and role in ['cluster-admin', 'admin', 'edit']:
            for subject in binding.get('subjects', []):
                if subject.get('namespace') == 'cicd-zone':
                    threats.append({
                        'id': 'T06',
                        'component': subject.get('name'),
                        'namespace': 'cicd-zone',
                        'severity': 'High',
                        'description': f"CI/CD ServiceAccount {subject.get('name')} has cluster-wide access",
                        'evidence': f"ClusterRoleBinding {binding.get('binding')} grants {role}"
                    })
    return threats

def detect_t7_missing_audit_logging(namespaces):
    """T7: Missing Audit Logging"""
    threats = []

    for ns in namespaces:
        ns_name = ns['name']
        annotations = ns.get('annotations', {})

        # Check if audit logging is explicitly disabled
        if annotations.get('audit.k8s.io/enabled') == 'false':
            threats.append({
                'id': 'T07',
                'component': ns_name,
                'namespace': ns_name,
                'severity': 'Medium',
                'description': f"Namespace {ns_name} has audit logging disabled",
                'evidence': "audit.k8s.io/enabled: false in namespace annotations"
            })
    return threats

def detect_t8_secrets_in_configmaps(configmaps):
    """T8: Hardcoded Secrets in ConfigMaps"""
    threats = []

    secret_keywords = ['password', 'secret', 'token', 'key', 'api-key', 'credential']

    for cm in configmaps:
        data = cm.get('data', {})
        for key, value in data.items():
            if any(keyword in key.lower() for keyword in secret_keywords):
                threats.append({
                    'id': 'T08',
                    'component': cm['name'],
                    'namespace': cm['namespace'],
                    'severity': 'Critical',
                    'description': f"ConfigMap {cm['name']} contains secret '{key}' in plaintext",
                    'evidence': f"Key '{key}' in ConfigMap (should use Secret resource)"
                })
    return threats

def detect_t9_anonymous_source_control(configmaps):
    """T9: Anonymous Source Control Access"""
    threats = []

    for cm in configmaps:
        if 'gitea' in cm['name'].lower() and cm['name'] != 'gitea-secrets':
            data = cm.get('data', {})
            config_str = str(data)

            # Check for anonymous access settings
            if 'REQUIRE_SIGNIN_VIEW = false' in config_str or 'REQUIRE_SIGNIN_VIEW=false' in config_str:
                threats.append({
                    'id': 'T09',
                    'component': 'gitea',
                    'namespace': cm['namespace'],
                    'severity': 'Medium',
                    'description': "Gitea allows anonymous repository access (REQUIRE_SIGNIN_VIEW=false)",
                    'evidence': "Anonymous repository viewing enabled in Gitea configuration"
                })
                break  # Only report once
    return threats

def detect_t10_missing_resource_limits(pods):
    """T10: Missing Resource Limits"""
    threats = []

    for pod in pods:
        for container in pod.get('containerSecurity', []):
            resources = container.get('resources', {})
            limits = resources.get('limits', {})

            if not limits:
                threats.append({
                    'id': 'T10',
                    'component': pod['name'].rsplit('-', 2)[0],  # Get base name
                    'namespace': pod['namespace'],
                    'severity': 'Medium',
                    'description': f"Container {container.get('name')} in {pod['name']} has no resource limits",
                    'evidence': "No CPU/memory limits defined (risk of resource exhaustion)"
                })
                break  # One threat per pod
    return threats

def analyze_supply_chain():
    """Main analysis function"""

    print("=" * 80)
    print("FOCUSED SUPPLY CHAIN THREAT ANALYSIS (T1-T10 ONLY)")
    print("=" * 80)

    # Load full metadata
    with open('output/k8s_enhanced_metadata.json', 'r') as f:
        full_metadata = json.load(f)

    # Filter to supply chain only
    metadata = filter_supply_chain_data(full_metadata)

    print(f"\n📊 Supply Chain Components:")
    print(f"  Namespaces: {len(metadata['namespaces'])} ({', '.join(SUPPLY_CHAIN_NS)})")
    print(f"  Pods: {len(metadata['pods'])}")
    print(f"  Services: {len(metadata['services'])}")
    print(f"  RBAC Bindings: {len(metadata['rbac'])}")
    print(f"  ConfigMaps: {len(metadata['configmaps'])}")

    # Run all T1-T10 detectors
    all_threats = []

    print(f"\n🔍 Running T1-T10 Threat Detectors...")

    threats_t1 = detect_t1_external_exposure(metadata['services'])
    all_threats.extend(threats_t1)
    print(f"  T01 (External Exposure): {len(threats_t1)} threats")

    threats_t2 = detect_t2_excessive_permissions(metadata['rbac'])
    all_threats.extend(threats_t2)
    print(f"  T02 (Excessive Permissions): {len(threats_t2)} threats")

    threats_t3 = detect_t3_unencrypted_http(metadata['services'])
    all_threats.extend(threats_t3)
    print(f"  T03 (Unencrypted HTTP): {len(threats_t3)} threats")

    threats_t4 = detect_t4_missing_network_policies(metadata['namespaces'], metadata['network_policies'])
    all_threats.extend(threats_t4)
    print(f"  T04 (Missing NetworkPolicies): {len(threats_t4)} threats")

    threats_t5 = detect_t5_registry_misconfig(metadata['pods'], metadata['configmaps'])
    all_threats.extend(threats_t5)
    print(f"  T05 (Anonymous Registry): {len(threats_t5)} threats")

    threats_t6 = detect_t6_cicd_to_prod(metadata['rbac'])
    all_threats.extend(threats_t6)
    print(f"  T06 (CI/CD to Prod Access): {len(threats_t6)} threats")

    threats_t7 = detect_t7_missing_audit_logging(metadata['namespaces'])
    all_threats.extend(threats_t7)
    print(f"  T07 (Missing Audit Logging): {len(threats_t7)} threats")

    threats_t8 = detect_t8_secrets_in_configmaps(metadata['configmaps'])
    all_threats.extend(threats_t8)
    print(f"  T08 (Secrets in ConfigMaps): {len(threats_t8)} threats")

    threats_t9 = detect_t9_anonymous_source_control(metadata['configmaps'])
    all_threats.extend(threats_t9)
    print(f"  T09 (Anonymous Source Control): {len(threats_t9)} threats")

    threats_t10 = detect_t10_missing_resource_limits(metadata['pods'])
    all_threats.extend(threats_t10)
    print(f"  T10 (Missing Resource Limits): {len(threats_t10)} threats")

    # Summary
    print(f"\n" + "=" * 80)
    print(f"📋 DETECTION SUMMARY")
    print(f"=" * 80)
    print(f"Total Threats Detected: {len(all_threats)}")

    # Group by threat ID
    from collections import defaultdict
    by_id = defaultdict(list)
    for t in all_threats:
        by_id[t['id']].append(t)

    print(f"\nBreakdown by Threat Type:")
    for tid in sorted(by_id.keys()):
        count = len(by_id[tid])
        example = by_id[tid][0]
        print(f"  {tid}: {count} instance(s) - {example['description'][:60]}...")

    # Check coverage
    expected_threats = [f'T{i:02d}' for i in range(1, 11)]
    detected_ids = set(by_id.keys())
    missing = set(expected_threats) - detected_ids

    if missing:
        print(f"\n⚠️  Missing Threats: {', '.join(sorted(missing))}")
    else:
        print(f"\n✅ ALL T1-T10 THREATS DETECTED!")

    # Save results
    output = {
        'supply_chain_threats': all_threats,
        'summary': {
            'total': len(all_threats),
            'by_type': {tid: len(threats) for tid, threats in by_id.items()},
            'coverage': f"{len(detected_ids)}/10"
        }
    }

    with open('output/supply_chain_t1_t10_threats.json', 'w') as f:
        json.dump(output, f, indent=2)

    print(f"\n✅ Results saved to: output/supply_chain_t1_t10_threats.json")

    return all_threats

if __name__ == '__main__':
    analyze_supply_chain()
