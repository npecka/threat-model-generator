#!/usr/bin/env python3
"""
Flow Correlation Module

Enhances runtime flow collection by:
1. Correlating IPs to pods/services
2. Detecting cross-zone flows
3. Identifying policy violations (allowed vs observed)
4. Building runtime-confirmed edge lists for threat detection
"""

import json
from collections import defaultdict
from typing import Dict, List, Set, Tuple
from datetime import datetime


class FlowCorrelator:
    """
    Correlates network flows with K8s architecture to identify
    runtime-confirmed connections for threat detection.
    """

    def __init__(self, pods_data: List[Dict], services_data: List[Dict],
                 network_policies: List[Dict] = None):
        """
        Args:
            pods_data: List of pod metadata with IPs
            services_data: List of service metadata
            network_policies: List of NetworkPolicy resources (optional)
        """
        self.pods = pods_data
        self.services = services_data
        self.network_policies = network_policies or []

        # Build lookup structures
        self.ip_to_pod = {}
        self.ip_to_service = {}
        self.pod_to_namespace = {}
        self.namespace_zones = {}

        self._build_ip_mappings()
        self._classify_trust_zones()

    def _build_ip_mappings(self):
        """Build IP → Pod and IP → Service mappings"""
        print("[FlowCorr] Building IP mappings...")

        # Map pod IPs
        for pod in self.pods:
            pod_name = pod.get('name')
            pod_ip = pod.get('ip')
            namespace = pod.get('namespace', 'unknown')

            if pod_ip:
                self.ip_to_pod[pod_ip] = pod_name
                self.pod_to_namespace[pod_name] = namespace

        # Map service IPs (ClusterIPs)
        for svc in self.services:
            svc_name = svc.get('name')
            svc_ip = svc.get('cluster_ip')
            namespace = svc.get('namespace', 'unknown')

            if svc_ip and svc_ip != 'None':
                self.ip_to_service[svc_ip] = f"{namespace}/{svc_name}"

        print(f"[FlowCorr] Mapped {len(self.ip_to_pod)} pod IPs")
        print(f"[FlowCorr] Mapped {len(self.ip_to_service)} service IPs")

    def _classify_trust_zones(self):
        """Classify namespaces into trust zones"""
        for namespace in set(self.pod_to_namespace.values()):
            if 'prod' in namespace.lower():
                self.namespace_zones[namespace] = 'prod-zone'
            elif 'cicd' in namespace.lower():
                self.namespace_zones[namespace] = 'cicd-zone'
            elif 'dev' in namespace.lower():
                self.namespace_zones[namespace] = 'dev-zone'
            elif 'kube-system' in namespace or 'kube-public' in namespace:
                self.namespace_zones[namespace] = 'system-zone'
            else:
                self.namespace_zones[namespace] = 'application-zone'

        print(f"[FlowCorr] Trust zones: {self.namespace_zones}")

    def correlate_hubble_flows(self, hubble_flows: List[Dict]) -> Dict:
        """
        Correlate Hubble flows with pod/service metadata

        Returns:
            {
                'flows': List of correlated flows,
                'statistics': Flow statistics,
                'cross_zone_flows': Flows crossing trust boundaries
            }
        """
        print(f"\n[FlowCorr] Correlating {len(hubble_flows)} Hubble flows...")

        correlated_flows = []
        cross_zone_flows = []
        flow_counts = defaultdict(int)  # (src_pod, dst_pod) -> count

        for flow in hubble_flows:
            if not isinstance(flow, dict):
                continue

            # Extract IPs from Hubble flow
            src_ip = self._extract_hubble_ip(flow, 'source')
            dst_ip = self._extract_hubble_ip(flow, 'destination')

            if not src_ip or not dst_ip:
                continue

            # Map to pods
            src_pod = self.ip_to_pod.get(src_ip, f"external:{src_ip}")
            dst_pod = self.ip_to_pod.get(dst_ip, f"external:{dst_ip}")

            # Get namespaces
            src_namespace = self.pod_to_namespace.get(src_pod, 'external')
            dst_namespace = self.pod_to_namespace.get(dst_pod, 'external')

            # Get zones
            src_zone = self.namespace_zones.get(src_namespace, 'external')
            dst_zone = self.namespace_zones.get(dst_namespace, 'external')

            # Extract protocol and port
            protocol = self._extract_protocol(flow)
            dst_port = self._extract_port(flow, 'destination')

            # Build correlated flow
            correlated = {
                'source_ip': src_ip,
                'source_pod': src_pod,
                'source_namespace': src_namespace,
                'source_zone': src_zone,
                'destination_ip': dst_ip,
                'destination_pod': dst_pod,
                'destination_namespace': dst_namespace,
                'destination_zone': dst_zone,
                'protocol': protocol,
                'destination_port': dst_port,
                'timestamp': flow.get('time', 'unknown'),
                'verdict': flow.get('verdict', 'unknown'),
                'crosses_zone': src_zone != dst_zone and src_zone != 'external'
            }

            correlated_flows.append(correlated)

            # Track counts
            flow_counts[(src_pod, dst_pod)] += 1

            # Track cross-zone flows
            if correlated['crosses_zone']:
                cross_zone_flows.append(correlated)

        # Build statistics
        # Convert flow_counts tuple keys to strings for JSON serialization
        flow_counts_serializable = {f"{src} → {dst}": count
                                     for (src, dst), count in flow_counts.items()}

        statistics = {
            'total_flows': len(correlated_flows),
            'cross_zone_flows': len(cross_zone_flows),
            'unique_connections': len(flow_counts),
            'pods_communicating': len(set(
                [f[0] for f in flow_counts.keys()] + [f[1] for f in flow_counts.keys()]
            )),
            'flow_distribution': flow_counts_serializable
        }

        print(f"[FlowCorr] Total flows: {statistics['total_flows']:,}")
        print(f"[FlowCorr] Cross-zone flows: {statistics['cross_zone_flows']:,}")
        print(f"[FlowCorr] Unique connections: {statistics['unique_connections']:,}")

        return {
            'flows': correlated_flows,
            'statistics': statistics,
            'cross_zone_flows': cross_zone_flows,
            'flow_counts': flow_counts_serializable
        }

    def _extract_hubble_ip(self, flow: Dict, direction: str) -> str:
        """Extract IP from Hubble flow (handles different formats)"""
        # Try direct access
        if direction in flow:
            if isinstance(flow[direction], dict):
                if 'IP' in flow[direction]:
                    return flow[direction]['IP']
                elif 'ip' in flow[direction]:
                    return flow[direction]['ip']

        # Try nested structure
        if f'{direction}_ip' in flow:
            return flow[f'{direction}_ip']

        # Try IP field
        if 'IP' in flow:
            if direction == 'source':
                return flow['IP'].get('source', '')
            else:
                return flow['IP'].get('destination', '')

        return None

    def _extract_protocol(self, flow: Dict) -> str:
        """Extract protocol from Hubble flow"""
        if 'l4' in flow:
            if 'TCP' in flow['l4']:
                return 'TCP'
            elif 'UDP' in flow['l4']:
                return 'UDP'
            elif 'ICMP' in flow['l4']:
                return 'ICMP'

        if 'protocol' in flow:
            return flow['protocol']

        return 'unknown'

    def _extract_port(self, flow: Dict, direction: str) -> int:
        """Extract port from Hubble flow"""
        if 'l4' in flow:
            l4 = flow['l4']
            if 'TCP' in l4:
                if direction == 'destination':
                    return l4['TCP'].get('destination_port', 0)
                else:
                    return l4['TCP'].get('source_port', 0)
            elif 'UDP' in l4:
                if direction == 'destination':
                    return l4['UDP'].get('destination_port', 0)
                else:
                    return l4['UDP'].get('source_port', 0)

        if f'{direction}_port' in flow:
            return flow[f'{direction}_port']

        return 0

    def build_runtime_edges(self, correlated_flows: List[Dict]) -> List[Dict]:
        """
        Build edge list for threat detection from runtime flows

        Returns:
            List of edges with runtime_observed=True
        """
        print("\n[FlowCorr] Building runtime-confirmed edges...")

        edges = []
        seen_edges = set()

        for flow in correlated_flows:
            src = flow['source_pod']
            dst = flow['destination_pod']

            # Skip external flows for now (focus on internal architecture)
            if src.startswith('external:') or dst.startswith('external:'):
                continue

            edge_key = (src, dst)
            if edge_key in seen_edges:
                continue

            seen_edges.add(edge_key)

            edge = {
                'source': src,
                'destination': dst,
                'source_namespace': flow['source_namespace'],
                'destination_namespace': flow['destination_namespace'],
                'runtime_observed': True,
                'protocol': flow['protocol'],
                'port': flow['destination_port'],
                'flow_count': sum(1 for f in correlated_flows
                                 if f['source_pod'] == src and f['destination_pod'] == dst),
                'crosses_zone': flow['crosses_zone'],
                'threats': self._identify_edge_threats(flow)
            }

            edges.append(edge)

        print(f"[FlowCorr] Built {len(edges)} runtime-confirmed edges")
        return edges

    def _identify_edge_threats(self, flow: Dict) -> List[str]:
        """Identify threats associated with this flow"""
        threats = []

        # T03: Unencrypted communication (HTTP ports)
        http_ports = [80, 8080, 3000, 5000, 8081, 8888, 9090]
        if flow['destination_port'] in http_ports:
            threats.append('T03')

        # T06: Cross-zone access
        if flow['crosses_zone']:
            src_zone = flow['source_zone']
            dst_zone = flow['destination_zone']

            # CI/CD → Production is T06
            if 'cicd' in src_zone and 'prod' in dst_zone:
                threats.append('T06')

            # CI/CD → Training data is T12
            if 'cicd' in src_zone and 'dev' in dst_zone:
                if 'training' in flow['destination_pod'].lower():
                    threats.append('T12')

        # T14: ML model download (MLflow → inference)
        if 'mlflow' in flow['source_pod'].lower() and 'inference' in flow['destination_pod'].lower():
            threats.append('T14')

        return threats

    def detect_policy_violations(self, correlated_flows: List[Dict]) -> List[Dict]:
        """
        Compare observed flows against NetworkPolicies to find violations

        A violation occurs when:
        - Flow is observed BUT NetworkPolicy should block it
        """
        print("\n[FlowCorr] Detecting policy violations...")

        if not self.network_policies:
            print("[FlowCorr] No NetworkPolicies provided, skipping violation detection")
            return []

        violations = []

        # Build policy rules
        # This is simplified - full NetworkPolicy parsing is complex
        policy_rules = self._parse_network_policies()

        for flow in correlated_flows:
            src_pod = flow['source_pod']
            dst_pod = flow['destination_pod']
            dst_port = flow['destination_port']

            # Check if flow should be blocked
            if self._should_be_blocked(flow, policy_rules):
                violations.append({
                    'source': src_pod,
                    'destination': dst_pod,
                    'port': dst_port,
                    'reason': 'Flow observed despite NetworkPolicy deny rule',
                    'threat': 'Policy bypass or enforcement disabled',
                    'evidence': f"Flow {src_pod} → {dst_pod}:{dst_port} observed {flow.get('flow_count', 1)} times"
                })

        if violations:
            print(f"[FlowCorr] ⚠️  Found {len(violations)} policy violations!")
        else:
            print(f"[FlowCorr] No policy violations detected")

        return violations

    def _parse_network_policies(self) -> Dict:
        """Parse NetworkPolicies into rule structures"""
        # Simplified - real implementation would need full NetworkPolicy parsing
        rules = {
            'deny_all_namespaces': [],
            'allow_rules': []
        }

        for policy in self.network_policies:
            namespace = policy.get('namespace')
            spec = policy.get('spec', {})

            # Check for deny-all pattern
            if not spec.get('ingress') and spec.get('policyTypes', []) == ['Ingress']:
                rules['deny_all_namespaces'].append(namespace)

        return rules

    def _should_be_blocked(self, flow: Dict, policy_rules: Dict) -> bool:
        """Check if flow should be blocked by NetworkPolicy"""
        # Simplified logic
        dst_namespace = flow['destination_namespace']

        # If destination namespace has deny-all policy
        if dst_namespace in policy_rules['deny_all_namespaces']:
            # And source is from different namespace
            if flow['source_namespace'] != dst_namespace:
                return True  # Should be blocked but wasn't

        return False

    def export_correlated_flows(self, output_file: str, correlated_data: Dict):
        """Export correlated flows to JSON"""
        with open(output_file, 'w') as f:
            json.dump(correlated_data, f, indent=2)

        print(f"\n[Export] Wrote correlated flows to {output_file}")


def main():
    """Example usage"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python flow_correlator.py <k8s_metadata.json> [output.json]")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "correlated_flows.json"

    # Load data
    with open(input_file) as f:
        data = json.load(f)

    pods = data.get('pods', [])
    services = data.get('services', [])
    hubble_flows = data.get('hubble_flows', [])
    network_policies = data.get('network_policies', [])

    # Correlate flows
    correlator = FlowCorrelator(pods, services, network_policies)
    correlated = correlator.correlate_hubble_flows(hubble_flows)

    # Build edges
    edges = correlator.build_runtime_edges(correlated['flows'])
    correlated['runtime_edges'] = edges

    # Detect violations
    violations = correlator.detect_policy_violations(correlated['flows'])
    correlated['policy_violations'] = violations

    # Export
    correlator.export_correlated_flows(output_file, correlated)

    print(f"\nDone!")
    print(f"  Flows correlated: {correlated['statistics']['total_flows']:,}")
    print(f"  Cross-zone flows: {correlated['statistics']['cross_zone_flows']:,}")
    print(f"  Runtime edges: {len(edges)}")
    print(f"  Policy violations: {len(violations)}")


if __name__ == '__main__':
    main()
