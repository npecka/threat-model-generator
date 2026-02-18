#!/usr/bin/env python3
"""
Threat Correlator - Multi-Modal Threat Validation

Research Contribution: Correlates static security findings (Trivy/Kubescape)
with runtime telemetry (Hubble flows, Falco events) to produce validated,
confidence-scored threats.

This solves the gap between:
- Static Analysis: "This COULD be exploited"
- Runtime Analysis: "This IS being exploited"

Output: Enhanced threats with validation status and confidence scores
"""

from typing import Dict, List, Set, Tuple
from collections import defaultdict
import json


class ThreatCorrelator:
    """Correlates static and runtime threat evidence."""

    def __init__(self):
        self.validation_strategies = {
            'T01': self._validate_external_access,
            'T02': self._validate_excessive_permissions,
            'T03': self._validate_unencrypted_communication,
            'T04': self._validate_network_segmentation,
            'T05': self._validate_registry_access,
            'T06': self._validate_cross_zone_access,
            'T07': self._validate_audit_logging,
            'T08': self._validate_secrets_exposure,
            'T09': self._validate_source_control,
            'T10': self._validate_resource_limits,
            'T11': self._validate_model_access,
            'T12': self._validate_data_poisoning,
            'T13': self._validate_model_theft,
            'T14': self._validate_model_transfer,
            'T15': self._validate_ml_deployment,
            'T16': self._validate_model_provenance,
            'T17': self._validate_model_metadata,
        }

    def correlate_threats(
        self,
        tool_results: Dict,
        hubble_flows: List[Dict],
        falco_events: List[Dict],
        pods: List[Dict],
        lateral_threats: List[Dict],
        egress_threats: List[Dict],
        services: Dict
    ) -> List[Dict]:
        """
        Main correlation function: Validate static findings with runtime evidence.

        Args:
            tool_results: Output from tool_integrator (Trivy/Kubescape findings)
            hubble_flows: Network flow data
            falco_events: Runtime behavior events
            pods: Pod metadata
            lateral_threats: Detected lateral movement
            egress_threats: External connection threats
            services: Service configurations

        Returns:
            List of correlated threat dictionaries with validation and confidence
        """
        correlated_threats = []

        # Convert services list to dict if needed (for compatibility)
        if isinstance(services, list):
            services = {svc.get('name', f'service-{i}'): svc for i, svc in enumerate(services)}

        # Get detected threat IDs from tools
        detected_threats = tool_results.get('combined_detection', [])
        tools_data = tool_results.get('tools', {})

        # Build runtime context for validation
        runtime_context = self._build_runtime_context(
            hubble_flows, falco_events, pods, lateral_threats, egress_threats, services
        )

        # Correlate each detected threat
        for threat_id in detected_threats:
            # Get static detection details from tools
            static_evidence = self._extract_static_evidence(threat_id, tools_data)

            # Validate with runtime data
            if threat_id in self.validation_strategies:
                runtime_evidence = self.validation_strategies[threat_id](
                    static_evidence, runtime_context
                )
            else:
                runtime_evidence = {'status': 'NO_VALIDATION', 'evidence': {}}

            # Build correlated threat
            correlated_threat = self._build_correlated_threat(
                threat_id, static_evidence, runtime_evidence
            )

            correlated_threats.append(correlated_threat)

        # Add runtime-only threats (no static detection)
        runtime_only = self._extract_runtime_only_threats(
            lateral_threats, egress_threats, detected_threats
        )
        correlated_threats.extend(runtime_only)

        return correlated_threats

    # =========================================================================
    # Runtime Context Building
    # =========================================================================

    def _build_runtime_context(
        self, flows, events, pods, lateral_threats, egress_threats, services
    ) -> Dict:
        """Build aggregated runtime context for validation."""
        context = {
            'external_connections': self._analyze_external_connections(flows),
            'cross_namespace_flows': self._analyze_cross_namespace_flows(flows, pods),
            'unencrypted_flows': self._analyze_unencrypted_flows(flows),
            'suspicious_syscalls': self._analyze_suspicious_syscalls(events),
            'lateral_movement': lateral_threats,
            'egress_connections': egress_threats,
            'service_exposure': self._analyze_service_exposure(services, flows),
            'pod_behaviors': self._analyze_pod_behaviors(events, pods),
        }
        return context

    def _analyze_external_connections(self, flows: List[Dict]) -> Dict:
        """Analyze flows to external IPs."""
        external_conns = defaultdict(list)

        for flow_wrap in flows:
            if not isinstance(flow_wrap, dict) or 'flow' not in flow_wrap:
                continue

            flow = flow_wrap['flow']
            src_pod = flow.get('source', {}).get('pod_name')
            dst_labels = flow.get('destination', {}).get('labels', [])
            dst_ip = flow.get('destination', {}).get('ip')

            if 'reserved:world' in dst_labels and src_pod:
                external_conns[src_pod].append({
                    'dest_ip': dst_ip,
                    'port': flow.get('l4', {}).get('TCP', {}).get('destinationPort'),
                    'verdict': flow.get('verdict')
                })

        return dict(external_conns)

    def _analyze_cross_namespace_flows(self, flows: List[Dict], pods: List[Dict]) -> List[Dict]:
        """Analyze flows crossing namespace boundaries."""
        # Build pod -> namespace map
        pod_ns_map = {p['name']: p['namespace'] for p in pods}

        cross_ns_flows = []
        for flow_wrap in flows:
            if not isinstance(flow_wrap, dict) or 'flow' not in flow_wrap:
                continue

            flow = flow_wrap['flow']
            src_pod = flow.get('source', {}).get('pod_name')
            dst_pod = flow.get('destination', {}).get('pod_name')

            if src_pod and dst_pod:
                src_ns = pod_ns_map.get(src_pod)
                dst_ns = pod_ns_map.get(dst_pod)

                if src_ns and dst_ns and src_ns != dst_ns:
                    cross_ns_flows.append({
                        'source': src_pod,
                        'source_namespace': src_ns,
                        'dest': dst_pod,
                        'dest_namespace': dst_ns,
                        'port': flow.get('l4', {}).get('TCP', {}).get('destinationPort')
                    })

        return cross_ns_flows

    def _analyze_unencrypted_flows(self, flows: List[Dict]) -> List[Dict]:
        """Identify flows on commonly unencrypted ports."""
        unencrypted_ports = [80, 8080, 3000, 5000, 8000]
        unencrypted = []

        for flow_wrap in flows:
            if not isinstance(flow_wrap, dict) or 'flow' not in flow_wrap:
                continue

            flow = flow_wrap['flow']
            port = flow.get('l4', {}).get('TCP', {}).get('destinationPort')

            if port in unencrypted_ports:
                unencrypted.append({
                    'source': flow.get('source', {}).get('pod_name'),
                    'dest': flow.get('destination', {}).get('pod_name') or flow.get('destination', {}).get('ip'),
                    'port': port
                })

        return unencrypted

    def _analyze_suspicious_syscalls(self, events: List[Dict]) -> Dict:
        """Analyze Falco events for suspicious system calls."""
        suspicious = defaultdict(list)

        for event in events:
            pod = event.get('output_fields', {}).get('k8s.pod.name')
            if pod:
                suspicious[pod].append({
                    'rule': event.get('rule'),
                    'priority': event.get('priority'),
                    'output': event.get('output')
                })

        return dict(suspicious)

    def _analyze_service_exposure(self, services: Dict, flows: List[Dict]) -> Dict:
        """Analyze which services have external exposure."""
        exposed = {}

        for svc_key, svc_data in services.items():
            svc_type = svc_data.get('type', 'ClusterIP')
            if svc_type in ['LoadBalancer', 'NodePort']:
                exposed[svc_key] = {
                    'type': svc_type,
                    'ports': svc_data.get('ports', []),
                    'external_ip': svc_data.get('external_ip')
                }

        return exposed

    def _analyze_pod_behaviors(self, events: List[Dict], pods: List[Dict]) -> Dict:
        """Aggregate suspicious behaviors per pod."""
        behaviors = defaultdict(lambda: {'events': [], 'severity': 'Low'})

        for event in events:
            pod = event.get('output_fields', {}).get('k8s.pod.name')
            if pod:
                behaviors[pod]['events'].append(event.get('rule'))
                priority = event.get('priority', 'Notice')
                if priority in ['Critical', 'Error']:
                    behaviors[pod]['severity'] = 'High'
                elif priority == 'Warning' and behaviors[pod]['severity'] == 'Low':
                    behaviors[pod]['severity'] = 'Medium'

        return dict(behaviors)

    # =========================================================================
    # Static Evidence Extraction
    # =========================================================================

    def _extract_static_evidence(self, threat_id: str, tools_data: Dict) -> Dict:
        """Extract static detection evidence from tool results."""
        evidence = {
            'threat_id': threat_id,
            'detected_by': [],
            'findings': []
        }

        # Check Trivy findings
        trivy = tools_data.get('trivy', {})
        if threat_id in trivy.get('detected_ground_truth', []):
            evidence['detected_by'].append('trivy')
            # Could add detailed findings here if needed

        # Check Kubescape findings
        kubescape = tools_data.get('kubescape', {})
        if threat_id in kubescape.get('detected_ground_truth', []):
            evidence['detected_by'].append('kubescape')

        return evidence

    # =========================================================================
    # Validation Strategies (Per Threat)
    # =========================================================================

    def _validate_external_access(self, static: Dict, runtime: Dict) -> Dict:
        """T01: Validate unauthenticated external access with runtime flows."""
        external_conns = runtime.get('external_connections', {})

        if external_conns:
            return {
                'status': 'CONFIRMED',
                'confidence': 'HIGH',
                'evidence': {
                    'pods_with_external_access': list(external_conns.keys()),
                    'connection_count': sum(len(conns) for conns in external_conns.values()),
                    'details': 'Service exposed AND actively receiving external connections'
                }
            }
        else:
            return {
                'status': 'POTENTIAL',
                'confidence': 'MEDIUM',
                'evidence': {
                    'details': 'Service exposed but no external connections observed in runtime data'
                }
            }

    def _validate_excessive_permissions(self, static: Dict, runtime: Dict) -> Dict:
        """T02: Validate excessive RBAC permissions with runtime usage."""
        suspicious_calls = runtime.get('suspicious_syscalls', {})

        if suspicious_calls:
            return {
                'status': 'CONFIRMED',
                'confidence': 'HIGH',
                'evidence': {
                    'suspicious_behavior_detected': True,
                    'affected_pods': list(suspicious_calls.keys()),
                    'details': 'Excessive permissions AND suspicious runtime behavior detected'
                }
            }
        else:
            return {
                'status': 'POTENTIAL',
                'confidence': 'MEDIUM',
                'evidence': {
                    'details': 'Excessive permissions exist but no suspicious usage observed'
                }
            }

    def _validate_unencrypted_communication(self, static: Dict, runtime: Dict) -> Dict:
        """T03: Validate unencrypted services with flow analysis."""
        unencrypted_flows = runtime.get('unencrypted_flows', [])

        if unencrypted_flows:
            return {
                'status': 'CONFIRMED',
                'confidence': 'CRITICAL',
                'evidence': {
                    'unencrypted_flow_count': len(unencrypted_flows),
                    'ports': list(set(f['port'] for f in unencrypted_flows)),
                    'details': 'Unencrypted services AND active HTTP traffic observed'
                }
            }
        else:
            return {
                'status': 'POTENTIAL',
                'confidence': 'LOW',
                'evidence': {
                    'details': 'Unencrypted service exists but no traffic observed'
                }
            }

    def _validate_network_segmentation(self, static: Dict, runtime: Dict) -> Dict:
        """T04: Validate missing network policies with cross-namespace flows."""
        cross_ns_flows = runtime.get('cross_namespace_flows', [])

        if cross_ns_flows:
            return {
                'status': 'CONFIRMED',
                'confidence': 'HIGH',
                'evidence': {
                    'cross_namespace_flows': len(cross_ns_flows),
                    'zone_violations': list(set(
                        f"{f['source_namespace']} → {f['dest_namespace']}"
                        for f in cross_ns_flows
                    )),
                    'details': 'Missing network policies AND cross-zone traffic observed'
                }
            }
        else:
            return {
                'status': 'POTENTIAL',
                'confidence': 'MEDIUM',
                'evidence': {
                    'details': 'Missing network policies but no cross-zone traffic observed'
                }
            }

    def _validate_registry_access(self, static: Dict, runtime: Dict) -> Dict:
        """T05: Validate registry access issues."""
        # Registry-specific validation would go here
        return {
            'status': 'UNVALIDATED',
            'confidence': 'MEDIUM',
            'evidence': {'details': 'Application-level threat, requires deeper inspection'}
        }

    def _validate_cross_zone_access(self, static: Dict, runtime: Dict) -> Dict:
        """T06: Validate CI/CD to production access."""
        lateral = runtime.get('lateral_movement', [])

        cicd_to_prod = [
            t for t in lateral
            if 'cicd' in t.get('source_namespace', '').lower()
            and 'prod' in t.get('dest_namespace', '').lower()
        ]

        if cicd_to_prod:
            return {
                'status': 'CONFIRMED',
                'confidence': 'CRITICAL',
                'evidence': {
                    'violation_count': len(cicd_to_prod),
                    'details': 'CI/CD has production access AND actively using it'
                }
            }
        else:
            return {
                'status': 'POTENTIAL',
                'confidence': 'MEDIUM',
                'evidence': {'details': 'Permissions exist but no runtime usage observed'}
            }

    def _validate_audit_logging(self, static: Dict, runtime: Dict) -> Dict:
        """T07: Validate missing audit logging."""
        return {
            'status': 'UNVALIDATED',
            'confidence': 'MEDIUM',
            'evidence': {'details': 'Audit logging gap detected by static analysis'}
        }

    def _validate_secrets_exposure(self, static: Dict, runtime: Dict) -> Dict:
        """T08: Validate secrets in ConfigMaps."""
        suspicious = runtime.get('suspicious_syscalls', {})

        if suspicious:
            return {
                'status': 'CONFIRMED',
                'confidence': 'HIGH',
                'evidence': {
                    'details': 'Exposed secrets AND suspicious runtime behavior detected',
                    'affected_pods': list(suspicious.keys())
                }
            }
        else:
            return {
                'status': 'POTENTIAL',
                'confidence': 'HIGH',
                'evidence': {'details': 'Secrets exposed in ConfigMap (static finding)'}
            }

    def _validate_source_control(self, static: Dict, runtime: Dict) -> Dict:
        """T09: Validate source control access issues."""
        return {
            'status': 'UNVALIDATED',
            'confidence': 'MEDIUM',
            'evidence': {'details': 'Application-level threat, requires deeper inspection'}
        }

    def _validate_resource_limits(self, static: Dict, runtime: Dict) -> Dict:
        """T10: Validate missing resource limits."""
        # Could correlate with actual resource usage if available
        return {
            'status': 'UNVALIDATED',
            'confidence': 'MEDIUM',
            'evidence': {'details': 'Missing resource limits (static finding)'}
        }

    # ML-specific validations (T11-T17)
    def _validate_model_access(self, static: Dict, runtime: Dict) -> Dict:
        """T11: Validate unauthorized model access."""
        return {'status': 'UNVALIDATED', 'confidence': 'MEDIUM', 'evidence': {}}

    def _validate_data_poisoning(self, static: Dict, runtime: Dict) -> Dict:
        """T12: Validate training data poisoning risks."""
        return {'status': 'UNVALIDATED', 'confidence': 'MEDIUM', 'evidence': {}}

    def _validate_model_theft(self, static: Dict, runtime: Dict) -> Dict:
        """T13: Validate model theft via API."""
        return {'status': 'UNVALIDATED', 'confidence': 'MEDIUM', 'evidence': {}}

    def _validate_model_transfer(self, static: Dict, runtime: Dict) -> Dict:
        """T14: Validate unencrypted model transfer."""
        unencrypted = runtime.get('unencrypted_flows', [])
        mlflow_flows = [f for f in unencrypted if 'mlflow' in str(f.get('source', '')).lower()]

        if mlflow_flows:
            return {
                'status': 'CONFIRMED',
                'confidence': 'HIGH',
                'evidence': {
                    'unencrypted_ml_flows': len(mlflow_flows),
                    'details': 'MLflow traffic observed on unencrypted HTTP'
                }
            }
        return {'status': 'POTENTIAL', 'confidence': 'MEDIUM', 'evidence': {}}

    def _validate_ml_deployment(self, static: Dict, runtime: Dict) -> Dict:
        """T15: Validate ML deployment RBAC issues."""
        return {'status': 'UNVALIDATED', 'confidence': 'MEDIUM', 'evidence': {}}

    def _validate_model_provenance(self, static: Dict, runtime: Dict) -> Dict:
        """T16: Validate model provenance tracking."""
        return {'status': 'UNVALIDATED', 'confidence': 'MEDIUM', 'evidence': {}}

    def _validate_model_metadata(self, static: Dict, runtime: Dict) -> Dict:
        """T17: Validate exposed model metadata."""
        return {'status': 'UNVALIDATED', 'confidence': 'MEDIUM', 'evidence': {}}

    # =========================================================================
    # Threat Construction
    # =========================================================================

    def _build_correlated_threat(
        self, threat_id: str, static_evidence: Dict, runtime_evidence: Dict
    ) -> Dict:
        """Build final correlated threat object."""
        # Map validation status to overall severity
        severity_map = {
            'CONFIRMED': 'CRITICAL',
            'POTENTIAL': 'HIGH',
            'UNVALIDATED': 'MEDIUM'
        }

        confidence = runtime_evidence.get('confidence', 'MEDIUM')
        status = runtime_evidence.get('status', 'UNVALIDATED')

        return {
            'threat_id': threat_id,
            'validation_status': status,
            'confidence': confidence,
            'severity': severity_map.get(status, 'MEDIUM'),
            'static_detection': static_evidence,
            'runtime_validation': runtime_evidence,
            'detection_type': 'MULTI_MODAL' if status == 'CONFIRMED' else 'STATIC_ONLY'
        }

    def _extract_runtime_only_threats(
        self, lateral_threats: List[Dict], egress_threats: List[Dict], detected_static: List[str]
    ) -> List[Dict]:
        """Extract threats detected only in runtime (not by static tools)."""
        runtime_only = []

        # Add lateral movement threats not covered by static
        for threat in lateral_threats:
            runtime_only.append({
                'threat_id': 'RUNTIME-LATERAL',
                'validation_status': 'RUNTIME_ONLY',
                'confidence': 'HIGH',
                'severity': threat.get('severity', 'HIGH'),
                'static_detection': {'detected_by': []},
                'runtime_validation': {
                    'status': 'CONFIRMED',
                    'evidence': threat
                },
                'detection_type': 'RUNTIME_ONLY'
            })

        # Add egress threats
        for threat in egress_threats:
            runtime_only.append({
                'threat_id': 'RUNTIME-EGRESS',
                'validation_status': 'RUNTIME_ONLY',
                'confidence': 'HIGH',
                'severity': threat.get('severity', 'MEDIUM'),
                'static_detection': {'detected_by': []},
                'runtime_validation': {
                    'status': 'CONFIRMED',
                    'evidence': threat
                },
                'detection_type': 'RUNTIME_ONLY'
            })

        return runtime_only


# =========================================================================
# Main Entry Point
# =========================================================================

def correlate_threats(
    tool_results: Dict,
    hubble_flows: List[Dict],
    falco_events: List[Dict],
    pods: List[Dict],
    lateral_threats: List[Dict],
    egress_threats: List[Dict],
    services: Dict
) -> List[Dict]:
    """
    Main function to correlate static and runtime threats.

    Args:
        tool_results: Trivy/Kubescape findings from tool_integrator
        hubble_flows: Network flow data
        falco_events: Runtime behavior events
        pods: Pod metadata
        lateral_threats: Detected lateral movement
        egress_threats: External connection threats
        services: Service configurations

    Returns:
        List of correlated threats with validation and confidence
    """
    correlator = ThreatCorrelator()
    return correlator.correlate_threats(
        tool_results, hubble_flows, falco_events, pods,
        lateral_threats, egress_threats, services
    )
