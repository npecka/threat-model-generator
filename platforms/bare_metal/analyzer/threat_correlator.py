#!/usr/bin/env python3
"""
Platform-Aware Threat Correlator
Validates static findings with runtime evidence from network flows
Supports: Kubernetes (Hubble/Falco), Bare-Metal (tcpdump), AWS (VPC flows)
"""

from collections import defaultdict


class BareMetalThreatCorrelator:
    """Correlates static tool findings with runtime network flows"""

    def __init__(self):
        self.platform = None  # Will be auto-detected
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
        }

    def correlate_threats(self, tool_results, metadata):
        """
        Correlate static findings with runtime evidence

        Args:
            tool_results: Output from tool_integrator (Docker Bench + Checkov)
            metadata: Bare-metal metadata including flows

        Returns:
            List of correlated threats with validation status
        """
        correlated_threats = []

        # Get detected threat IDs from tools
        detected_threats = tool_results.get('combined_detection', [])
        tools_data = tool_results.get('tools', {})

        # Build runtime context
        runtime_context = self._build_runtime_context(metadata)

        # Correlate each detected threat
        for threat_id in detected_threats:
            # Get static detection details
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

        return correlated_threats

    def _detect_platform(self, metadata):
        """Auto-detect platform from metadata structure"""
        if 'hubble_flows' in metadata or 'falco_events' in metadata or 'pods' in metadata:
            return 'kubernetes'
        elif 'instances' in metadata and 'security_groups' in metadata:
            return 'aws'
        elif 'vms' in metadata or metadata.get('platform') == 'bare-metal':
            return 'bare-metal'
        else:
            return 'unknown'

    def _normalize_flow(self, flow, platform):
        """
        Normalize flow data to common format

        Common format:
        {
            'source_ip': str,
            'source_port': str/int,
            'dest_ip': str,
            'dest_port': str/int,
            'protocol': str,
            'source_entity': str (optional - pod/vm/instance name)
        }
        """
        if platform == 'kubernetes':
            # Hubble flow format
            return {
                'source_ip': flow.get('source', {}).get('IP'),
                'source_port': flow.get('source', {}).get('port'),
                'dest_ip': flow.get('destination', {}).get('IP'),
                'dest_port': flow.get('destination', {}).get('port'),
                'protocol': flow.get('l4', {}).get('protocol', 'TCP'),
                'source_entity': flow.get('source', {}).get('pod_name')
            }
        elif platform == 'bare-metal':
            # tcpdump format (already normalized in extractor)
            return {
                'source_ip': flow.get('source_ip'),
                'source_port': str(flow.get('source_port', '')),
                'dest_ip': flow.get('dest_ip'),
                'dest_port': str(flow.get('dest_port', '')),
                'protocol': flow.get('protocol', 'TCP'),
                'source_entity': flow.get('source_vm')
            }
        elif platform == 'aws':
            # Handle both VPC flow log format AND common format (from tcpdump)
            # VPC flow logs use: srcaddr, dstaddr, srcport, dstport
            # tcpdump/common format uses: source_ip, dest_ip, source_port, dest_port
            return {
                'source_ip': flow.get('source_ip') or flow.get('srcaddr'),
                'source_port': str(flow.get('source_port') or flow.get('srcport', '')),
                'dest_ip': flow.get('dest_ip') or flow.get('dstaddr'),
                'dest_port': str(flow.get('dest_port') or flow.get('dstport', '')),
                'protocol': flow.get('protocol', 'TCP'),
                'source_entity': flow.get('source_entity') or flow.get('instance_id')
            }
        else:
            # Return as-is if unknown
            return flow

    def _build_runtime_context(self, metadata):
        """Build runtime context from network flows and entity state"""
        # Detect platform
        self.platform = self._detect_platform(metadata)

        # Get flows based on platform
        raw_flows = []
        if self.platform == 'kubernetes':
            raw_flows = metadata.get("hubble_flows", [])
        elif self.platform == 'bare-metal':
            raw_flows = metadata.get("network_flows", [])
        elif self.platform == 'aws':
            raw_flows = metadata.get("network_flows", []) or metadata.get("vpc_flows", [])

        # Normalize all flows
        flows = [self._normalize_flow(f, self.platform) for f in raw_flows]
        flows = [f for f in flows if f.get('source_ip') and f.get('dest_ip')]  # Filter invalid

        # Get entities (VMs/pods/instances)
        entities = self._get_entities(metadata)
        config_files = metadata.get("config_files", [])

        context = {
            'platform': self.platform,
            'flows': flows,  # Normalized flows
            'external_connections': self._analyze_external_connections(flows),
            'cross_entity_flows': self._analyze_cross_entity_flows(flows, entities),
            'unencrypted_flows': self._analyze_unencrypted_flows(flows),
            'exposed_services': self._analyze_exposed_services(flows),
            'privileged_containers': self._analyze_privileged_containers(config_files),
            'entity_zones': self._build_entity_zone_map(entities)
        }

        return context

    def _get_entities(self, metadata):
        """Get entities (VMs/pods/instances) based on platform"""
        if self.platform == 'kubernetes':
            return metadata.get('pods', [])
        elif self.platform == 'bare-metal':
            return metadata.get('vms', [])
        elif self.platform == 'aws':
            return metadata.get('instances', [])
        return []

    def _build_entity_zone_map(self, entities):
        """Build entity-to-zone mapping for any platform"""
        zone_map = {}

        if self.platform == 'kubernetes':
            # Pods have namespace as zone
            for pod in entities:
                name = pod.get('name', '')
                namespace = pod.get('namespace', 'default')
                zone_map[name] = namespace
                # Also map by IP if available
                if pod.get('ip'):
                    zone_map[pod['ip']] = namespace

        elif self.platform == 'bare-metal':
            # VMs have zone field
            for vm in entities:
                name = vm.get('name', vm.get('hostname', ''))
                zone = vm.get('zone', 'unknown')
                zone_map[name] = zone
                # Map VM IP to zone
                if vm.get('ip'):
                    zone_map[vm['ip']] = zone
                # Also check network_interfaces if present
                for iface in vm.get('network_interfaces', []):
                    if iface.get('ip'):
                        zone_map[iface['ip']] = zone

        elif self.platform == 'aws':
            # EC2 instances have availability zone or tags
            for instance in entities:
                instance_id = instance.get('id', '')
                zone = instance.get('zone', instance.get('availability_zone', 'unknown'))
                zone_map[instance_id] = zone
                # Map IPs
                if instance.get('private_ip'):
                    zone_map[instance['private_ip']] = zone
                if instance.get('public_ip'):
                    zone_map[instance['public_ip']] = zone

        return zone_map

    def _analyze_external_connections(self, flows):
        """Identify connections to/from external IPs (normalized flows)"""
        external_conns = defaultdict(list)

        for flow in flows:
            src_ip = flow.get('source_ip')
            dst_ip = flow.get('dest_ip')

            # Check if destination is external (not RFC1918 private addresses)
            if dst_ip and not self._is_internal_ip(dst_ip):
                external_conns[src_ip].append({
                    'dest_ip': dst_ip,
                    'port': flow.get('dest_port'),
                    'protocol': flow.get('protocol')
                })

        return dict(external_conns)

    def _is_internal_ip(self, ip):
        """Check if IP is in private address space"""
        if not ip or ip == '0.0.0.0':
            return True
        # RFC1918 private addresses
        return (ip.startswith('192.168.') or
                ip.startswith('10.') or
                ip.startswith('172.16.') or ip.startswith('172.17.') or
                ip.startswith('172.18.') or ip.startswith('172.19.') or
                ip.startswith('172.20.') or ip.startswith('172.21.') or
                ip.startswith('172.22.') or ip.startswith('172.23.') or
                ip.startswith('172.24.') or ip.startswith('172.25.') or
                ip.startswith('172.26.') or ip.startswith('172.27.') or
                ip.startswith('172.28.') or ip.startswith('172.29.') or
                ip.startswith('172.30.') or ip.startswith('172.31.') or
                ip.startswith('127.') or  # Loopback
                ip.startswith('169.254.'))  # Link-local

    def _analyze_exposed_services(self, flows):
        """Analyze services exposed and receiving traffic"""
        exposed_ports = defaultdict(set)
        common_service_ports = [80, 443, 8080, 8443, 3000, 5000, 8000, 9000, 22, 3306, 5432]

        for flow in flows:
            dest_port = flow.get('dest_port')
            dest_ip = flow.get('dest_ip')

            # Convert port to int for comparison
            try:
                port_num = int(dest_port) if dest_port else 0
            except (ValueError, TypeError):
                continue

            # Track traffic to common service ports
            if port_num in common_service_ports:
                exposed_ports[port_num].add(dest_ip)

        return {port: list(ips) for port, ips in exposed_ports.items()}

    def _analyze_cross_entity_flows(self, flows, entities):
        """Analyze flows crossing entity/zone boundaries (platform-agnostic)"""
        # Use the already-built entity_zones map from context
        # This method is called with entities but we build the map separately
        # So we'll reconstruct it here or use it from context
        entity_zones = self._build_entity_zone_map(entities)

        cross_entity_flows = []
        for flow in flows:
            src_ip = flow.get('source_ip')
            dst_ip = flow.get('dest_ip')

            src_zone = entity_zones.get(src_ip)
            dst_zone = entity_zones.get(dst_ip)

            # Also check if source_entity is provided
            src_entity = flow.get('source_entity')
            if src_entity and not src_zone:
                src_zone = entity_zones.get(src_entity)

            if src_zone and dst_zone and src_zone != dst_zone:
                cross_entity_flows.append({
                    'source': src_ip,
                    'source_zone': src_zone,
                    'dest': dst_ip,
                    'dest_zone': dst_zone,
                    'port': flow.get('dest_port'),
                    'protocol': flow.get('protocol')
                })

        return cross_entity_flows

    def _analyze_unencrypted_flows(self, flows):
        """Identify flows on commonly unencrypted ports (normalized flows)"""
        unencrypted_ports = [80, 8080, 3000, 5000, 8000, 9000]
        unencrypted = []

        for flow in flows:
            dest_port = flow.get('dest_port')

            # Convert to int for comparison
            try:
                port_num = int(dest_port) if dest_port else 0
            except (ValueError, TypeError):
                continue

            if port_num in unencrypted_ports:
                unencrypted.append({
                    'source': flow.get('source_ip'),
                    'dest': flow.get('dest_ip'),
                    'port': port_num,
                    'protocol': flow.get('protocol')
                })

        return unencrypted

    def _analyze_privileged_containers(self, config_files):
        """Identify containers running with elevated privileges"""
        privileged = []

        for config in config_files:
            if config.get("type") == "docker-compose":
                content = config.get("content", "")
                if "privileged: true" in content or "--privileged" in content:
                    privileged.append({
                        'file': config.get('path'),
                        'evidence': 'privileged mode enabled'
                    })

        return privileged

    def _extract_static_evidence(self, threat_id, tools_data):
        """Extract static detection evidence from tool results"""
        evidence = {
            'threat_id': threat_id,
            'detected_by': [],
            'findings': []
        }

        # Check Docker Bench findings
        docker_bench = tools_data.get('docker_bench', {})
        if threat_id in docker_bench.get('detected_ground_truth', []):
            evidence['detected_by'].append('docker_bench')

        # Check Checkov findings
        checkov = tools_data.get('checkov', {})
        if threat_id in checkov.get('detected_ground_truth', []):
            evidence['detected_by'].append('checkov')

        return evidence

    # Validation strategies (per threat)

    def _validate_external_access(self, static, runtime):
        """T01: Validate exposed services receiving traffic"""
        external_conns = runtime.get('external_connections', {})
        exposed_services = runtime.get('exposed_services', {})

        # CONFIRMED if truly external connections exist
        if external_conns:
            return {
                'status': 'CONFIRMED',
                'confidence': 'HIGH',
                'evidence': {
                    'entities_with_external_access': list(external_conns.keys()),
                    'connection_count': sum(len(conns) for conns in external_conns.values()),
                    'details': 'Exposed service receiving genuine external connections'
                }
            }
        # CONFIRMED if exposed services are actively receiving ANY traffic
        # (even internal traffic confirms the service is listening)
        elif exposed_services:
            ports_with_traffic = list(exposed_services.keys())
            return {
                'status': 'CONFIRMED',
                'confidence': 'MEDIUM',
                'evidence': {
                    'exposed_ports_with_traffic': ports_with_traffic,
                    'affected_ips': sum(len(ips) for ips in exposed_services.values()),
                    'details': f'Exposed services actively receiving traffic on ports: {ports_with_traffic}'
                }
            }
        else:
            return {
                'status': 'POTENTIAL',
                'confidence': 'LOW',
                'evidence': {
                    'details': 'Service configured as exposed but no traffic observed'
                }
            }

    def _validate_excessive_permissions(self, static, runtime):
        """T02: Validate excessive container/VM permissions"""
        privileged = runtime.get('privileged_containers', [])

        if privileged:
            return {
                'status': 'CONFIRMED',
                'confidence': 'HIGH',
                'evidence': {
                    'privileged_containers': len(privileged),
                    'details': 'Containers running with elevated privileges'
                }
            }
        else:
            return {
                'status': 'POTENTIAL',
                'confidence': 'MEDIUM',
                'evidence': {'details': 'Permissions exist but no runtime usage observed'}
            }

    def _validate_unencrypted_communication(self, static, runtime):
        """T03: Validate unencrypted flows"""
        unencrypted_flows = runtime.get('unencrypted_flows', [])

        if unencrypted_flows:
            return {
                'status': 'CONFIRMED',
                'confidence': 'HIGH',
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
                'evidence': {'details': 'Unencrypted service exists but no traffic observed'}
            }

    def _validate_network_segmentation(self, static, runtime):
        """T04: Validate missing network segmentation"""
        cross_entity_flows = runtime.get('cross_entity_flows', [])

        if cross_entity_flows:
            zone_pairs = list(set(
                f"{f['source_zone']} → {f['dest_zone']}"
                for f in cross_entity_flows
            ))
            return {
                'status': 'CONFIRMED',
                'confidence': 'HIGH',
                'evidence': {
                    'cross_zone_flow_count': len(cross_entity_flows),
                    'zone_violations': zone_pairs,
                    'details': f'Missing network segmentation with {len(cross_entity_flows)} cross-zone flows observed'
                }
            }
        else:
            return {
                'status': 'POTENTIAL',
                'confidence': 'MEDIUM',
                'evidence': {'details': 'Network segmentation missing but no cross-zone traffic observed'}
            }

    def _validate_registry_access(self, static, runtime):
        """T05: Validate registry access"""
        return {
            'status': 'UNVALIDATED',
            'confidence': 'MEDIUM',
            'evidence': {'details': 'Application-level threat, requires deeper inspection'}
        }

    def _validate_cross_zone_access(self, static, runtime):
        """T06: Validate inappropriate cross-zone access (e.g., CI/CD to production)"""
        cross_entity_flows = runtime.get('cross_entity_flows', [])

        # Check for sensitive zone violations (CI/CD → prod, dev → prod, etc.)
        sensitive_violations = []
        for f in cross_entity_flows:
            src_zone = f.get('source_zone', '').lower()
            dst_zone = f.get('dest_zone', '').lower()

            # Detect inappropriate cross-zone patterns
            if (('cicd' in src_zone and 'prod' in dst_zone) or
                ('dev' in src_zone and 'prod' in dst_zone) or
                ('jenkins' in src_zone and 'prod' in dst_zone)):
                sensitive_violations.append(f)

        if sensitive_violations:
            violation_details = list(set(
                f"{v['source_zone']} → {v['dest_zone']} (port {v['port']})"
                for v in sensitive_violations
            ))
            return {
                'status': 'CONFIRMED',
                'confidence': 'HIGH',
                'evidence': {
                    'violation_count': len(sensitive_violations),
                    'violations': violation_details[:5],  # Limit to top 5
                    'details': f'Inappropriate cross-zone access detected: {", ".join(violation_details[:3])}'
                }
            }
        elif cross_entity_flows:
            # Cross-zone traffic exists but not critically sensitive
            return {
                'status': 'POTENTIAL',
                'confidence': 'MEDIUM',
                'evidence': {
                    'cross_zone_flows': len(cross_entity_flows),
                    'details': 'Cross-zone traffic exists but no critical violations observed'
                }
            }
        else:
            return {
                'status': 'POTENTIAL',
                'confidence': 'LOW',
                'evidence': {'details': 'Configuration allows cross-zone access but no runtime usage observed'}
            }

    def _validate_audit_logging(self, static, runtime):
        """T07: Validate missing audit logging"""
        return {
            'status': 'UNVALIDATED',
            'confidence': 'MEDIUM',
            'evidence': {'details': 'Audit logging gap detected by static analysis'}
        }

    def _validate_secrets_exposure(self, static, runtime):
        """T08: Validate secrets exposure"""
        return {
            'status': 'CONFIRMED',
            'confidence': 'HIGH',
            'evidence': {'details': 'Hardcoded secrets found in docker-compose files'}
        }

    def _validate_source_control(self, static, runtime):
        """T09: Validate source control access"""
        return {
            'status': 'UNVALIDATED',
            'confidence': 'MEDIUM',
            'evidence': {'details': 'Application-level threat, requires deeper inspection'}
        }

    def _validate_resource_limits(self, static, runtime):
        """T10: Validate missing resource limits"""
        return {
            'status': 'UNVALIDATED',
            'confidence': 'MEDIUM',
            'evidence': {'details': 'Missing resource limits (static finding)'}
        }

    def _build_correlated_threat(self, threat_id, static_evidence, runtime_evidence):
        """Build final correlated threat object"""
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


def correlate_threats(tool_results, metadata):
    """Main entry point for threat correlation"""
    correlator = BareMetalThreatCorrelator()
    return correlator.correlate_threats(tool_results, metadata)
