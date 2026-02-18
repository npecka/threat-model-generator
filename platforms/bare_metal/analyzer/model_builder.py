from collections import defaultdict
import sys
import os

# Add project root to path for utils import
sys.path.append(os.path.join(os.path.dirname(__file__), '../../..'))
from utils import sanitize_name


def build_pytm_model(vms, containers, flows, correlated_threats=None):
    """
    Build PyTM threat model for bare-metal deployment.

    Args:
        vms: VM details with zones
        containers: Docker containers on VMs
        flows: Network flows from tcpdump
        correlated_threats: Multi-modal correlated threats (static + runtime validation)

    Returns:
        Tuple of (model_lines, dfd_entities, dfd_flows)
    """
    # Initialize threat lists if not provided
    correlated_threats = correlated_threats or []

    model_lines = [
        "from pytm import TM, Boundary, Actor, Process, Datastore, Dataflow, Data, Threat",
        "",
        "tm = TM('Bare-Metal Supply Chain Threat Model')",
        "tm.description = 'Threat model generated from bare-metal runtime + config analysis'",
        "tm.isOrdered = True",
        "tm.mergeResponses = True",
        ""
    ]

    dfd_entities = []
    dfd_flows = []

    boundaries = {}
    entities = {}

    # Create external boundary for Internet
    external_boundary_var = "externalBoundary"
    model_lines.append(f"{external_boundary_var} = Boundary('External Services')\n")

    internet_var = "Internet"
    model_lines.append(f"{internet_var} = Process(name='Internet', boundary={external_boundary_var})\n")
    model_lines.append(f"{internet_var}.description = 'External world (public internet)'")
    model_lines.append(f"{internet_var}.inBoundary = {external_boundary_var}")
    model_lines.append("")

    # Create trust boundaries from VM zones
    # Extract unique zones from VMs
    zones = set(vm.get('zone', 'unknown') for vm in vms)
    for zone in zones:
        if zone and zone != 'unknown':
            b_var = sanitize_name(zone)
            boundaries[zone] = b_var
            model_lines.append(f"{b_var} = Boundary('{zone}')")

    model_lines.append("")

    # Create entities from containers
    # Build container name -> VM zone mapping
    container_to_zone = {}
    for vm in vms:
        vm_zone = vm.get('zone', 'unknown')
        vm_name = vm.get('name', vm.get('hostname', ''))

        # Map containers to this VM's zone
        for container in containers:
            container_host = container.get('host', '')
            if container_host == vm_name or container_host == vm.get('ip'):
                container_to_zone[container['name']] = vm_zone

    # Add container entities
    for container in containers:
        container_name = container["name"]
        container_var = sanitize_name(container_name)
        zone = container_to_zone.get(container_name, 'unknown')

        if zone == 'unknown' or zone not in boundaries:
            continue

        b_var = boundaries[zone]
        container_desc = f"{container_name} in {zone}"

        # Classify as Datastore or Process based on keywords
        if any(kw in container_name.lower() for kw in ["db", "mysql", "postgres", "redis", "etcd", "storage", "registry"]):
            model_lines.append(f"{container_var} = Datastore(name='{container_name}', boundary={b_var})")
            model_lines.append(f"{container_var}.description = '{container_desc}'")
            model_lines.append(f"{container_var}.inBoundary = {b_var}")
            dfd_entities.append({"type": "Datastore", "name": container_name, "boundary": zone})
        else:
            model_lines.append(f"{container_var} = Process(name='{container_name}', boundary={b_var})")
            model_lines.append(f"{container_var}.description = '{container_desc}'")
            model_lines.append(f"{container_var}.inBoundary = {b_var}")
            dfd_entities.append({"type": "Process", "name": container_name, "boundary": zone})

        entities[container_name] = container_var

    model_lines.append("")

    # Build IP to container mapping for flow correlation
    ip_to_container = {}
    for vm in vms:
        vm_ip = vm.get('ip', vm.get('private_ip'))
        for iface in vm.get('network_interfaces', []):
            iface_ip = iface.get('ip')
            if iface_ip:
                # Check which containers are on this VM
                for container in containers:
                    if container.get('host') == vm.get('hostname'):
                        # Multiple containers on same IP - will need port differentiation
                        if iface_ip not in ip_to_container:
                            ip_to_container[iface_ip] = []
                        if container['name'] not in ip_to_container[iface_ip]:
                            ip_to_container[iface_ip].append(container['name'])

    # Add dataflows from network flows
    seen_flows = set()
    external_entities = {}

    for flow in flows:
        src_ip = flow.get('source_ip') or flow.get('src_ip')
        dst_ip = flow.get('dest_ip') or flow.get('dst_ip')
        dst_port = flow.get('dest_port') or flow.get('dst_port')
        protocol = flow.get('protocol', 'TCP')

        # Skip flows with missing IP information
        if not src_ip or not dst_ip:
            continue

        # Try to map IPs to containers
        src_containers = ip_to_container.get(src_ip, [])
        dst_containers = ip_to_container.get(dst_ip, [])

        # Determine source entity
        if src_containers:
            # Use first container (could be enhanced with port-based routing)
            src_name = src_containers[0]
            if src_name not in entities:
                continue
            src_var = entities[src_name]
        else:
            # External source
            if not _is_internal_ip(src_ip):
                src_var = internet_var
                src_name = "Internet"
            else:
                # Unknown internal source - skip
                continue

        # Determine destination entity
        if dst_containers:
            # Try to match by port if multiple containers
            dst_name = _match_container_by_port(dst_containers, dst_port, containers)
            if dst_name not in entities:
                continue
            dst_var = entities[dst_name]
        else:
            # External destination
            if not _is_internal_ip(dst_ip):
                dst_label = f"External_{dst_ip.replace('.', '_')}"
                dst_var = sanitize_name(dst_label)

                if dst_label not in external_entities:
                    model_lines.append(
                        f"{dst_var} = Process(name='{dst_ip}', boundary={external_boundary_var})"
                    )
                    model_lines.append(f"{dst_var}.description = 'External connection target'")
                    model_lines.append(f"{dst_var}.inBoundary = {external_boundary_var}")
                    external_entities[dst_label] = dst_var
                    dfd_entities.append({"type": "Process", "name": dst_ip, "boundary": "External Services"})

                dst_var = external_entities[dst_label]
                dst_name = dst_ip
            else:
                # Unknown internal destination - skip
                continue

        # Avoid self-loops and duplicates
        if src_var == dst_var:
            continue

        try:
            port = int(dst_port) if dst_port else -1
        except (TypeError, ValueError):
            port = -1

        flow_sig = (src_var, dst_var, port)
        if flow_sig in seen_flows:
            continue
        seen_flows.add(flow_sig)

        desc = f"Observed runtime flow (port={port})"
        flow_name_raw = f"{src_var}_to_{dst_var}_{port}"
        flow_name = sanitize_name(flow_name_raw)

        model_lines.append(f"{flow_name}_data = Data('{desc}')")
        model_lines.append(
            f"{flow_name} = Dataflow(name='{flow_name}', source={src_var}, sink={dst_var}, protocol='{protocol}', data={flow_name}_data, dstPort={port})"
        )

        dfd_flows.append({"source": src_name if src_var != internet_var else "Internet",
                          "destination": dst_name,
                          "protocol": protocol,
                          "port": port})

    model_lines.append("")

    # =========================================================================
    # REGISTER CUSTOM THREATS (Correlated Threats)
    # =========================================================================
    model_lines.append("# =========================================================================")
    model_lines.append("# CUSTOM THREATS - Multi-Modal Correlated Threats")
    model_lines.append("# =========================================================================")
    model_lines.append("")

    # Define custom threat objects from correlation
    if correlated_threats:
        model_lines.append("# Define correlated threat definitions")
        threat_definitions = _generate_threat_definitions(correlated_threats)
        model_lines.extend(threat_definitions)
        model_lines.append("")

        # Annotate elements with detected threats
        model_lines.append("# Annotate elements with detected threats")
        threat_annotations = _annotate_elements_with_threats(entities, correlated_threats)
        model_lines.extend(threat_annotations)
        model_lines.append("")

        # Document threats as comments
        model_lines.append("# --- CORRELATED: Multi-Modal Validated Threats ---")
        for threat in correlated_threats[:15]:  # Limit for brevity
            status = threat.get('validation_status', 'UNKNOWN')
            confidence = threat.get('confidence', 'UNKNOWN')
            threat_id = threat.get('threat_id', 'UNKNOWN')
            model_lines.append(f"# {threat_id} ({status}, {confidence} confidence)")
        model_lines.append("")

    model_lines.append("# Process the threat model (generates STRIDE + custom threats)")
    model_lines.append("tm.process()")

    return model_lines, dfd_entities, dfd_flows


def _is_internal_ip(ip):
    """Check if IP is internal (192.168.x.x or 10.x.x.x)"""
    if not ip:
        return False
    return ip.startswith('192.168.') or ip.startswith('10.')


def _match_container_by_port(container_names, port, all_containers):
    """
    Match container by exposed port.
    Returns first container exposing this port, or first container if no match.
    """
    if not port:
        return container_names[0]

    for container_name in container_names:
        container = next((c for c in all_containers if c['name'] == container_name), None)
        if container:
            exposed_ports = container.get('ports', [])
            if any(str(port) in str(p) for p in exposed_ports):
                return container_name

    return container_names[0]


def _generate_threat_definitions(correlated_threats):
    """
    Generate PyTM Threat object definitions from correlated threats.
    Maps T01-T17 taxonomy to PyTM format with validation confidence.
    """
    lines = []
    defined_threats = set()

    for threat in correlated_threats[:15]:  # Limit for PyTM diagram clarity
        threat_id = threat.get('threat_id', 'UNKNOWN')

        if threat_id not in defined_threats:
            defined_threats.add(threat_id)

            status = threat.get('validation_status', 'UNVALIDATED')
            confidence = threat.get('confidence', 'MEDIUM')
            severity = threat.get('severity', 'MEDIUM')

            # Extract evidence
            static_ev = threat.get('static_detection', {})
            runtime_ev = threat.get('runtime_validation', {})

            desc = f"{threat_id}: Validation={status}, Confidence={confidence}"
            details = f"Static: {', '.join(static_ev.get('detected_by', []))} | Runtime: {runtime_ev.get('status', 'none')}"

            lines.append(f"# {threat_id}: Multi-Modal Correlated Threat")
            lines.append(f"Threat(")
            lines.append(f"    SID='{threat_id}',")
            lines.append(f"    target=('Process', 'Datastore', 'Dataflow'),")
            lines.append(f"    description='{_escape_quotes(desc)}',")
            lines.append(f"    details='{_escape_quotes(details[:150])}',")
            lines.append(f"    severity='{severity}',")
            lines.append(f"    condition='True'  # Confidence: {confidence}")
            lines.append(f")")
            lines.append("")

    return lines


def _annotate_elements_with_threats(entities, correlated_threats):
    """
    Add threat annotations to PyTM elements for visual indicators.
    """
    lines = []
    element_threats = defaultdict(list)

    # Map threats to elements (basic heuristic based on threat evidence)
    for threat in correlated_threats:
        threat_id = threat.get('threat_id', '')
        # Could enhance this by parsing static/runtime evidence to identify affected containers
        # For now, add to all entities (conservative approach)

    # For simplicity, add summary annotation to first entity
    if correlated_threats and entities:
        first_entity_var = list(entities.values())[0]
        threat_count = len(correlated_threats)

        lines.append(f"# Total threats detected: {threat_count}")
        lines.append(f"{first_entity_var}.totalThreatsDetected = {threat_count}")

        # Calculate severity distribution
        severities = [t.get('severity', 'MEDIUM') for t in correlated_threats]
        critical_count = severities.count('CRITICAL')
        high_count = severities.count('HIGH')

        if critical_count > 0:
            lines.append(f"{first_entity_var}.riskLevel = 'Critical'")
        elif high_count > 0:
            lines.append(f"{first_entity_var}.riskLevel = 'High'")
        else:
            lines.append(f"{first_entity_var}.riskLevel = 'Medium'")

        lines.append("")

    return lines


def _escape_quotes(text):
    """Escape single quotes in text for Python string literals"""
    return text.replace("'", "\\'").replace('\n', ' ')
