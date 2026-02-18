from collections import defaultdict
from utils import sanitize_name

def build_pytm_model(pods, flows, scan_results, falco_threats=None, correlated_threats=None, ml_threats=None, lateral_threats=None, egress_threats=None):
    """
    Build PyTM threat model integrating correlated and empirical threats.

    Args:
        pods: Pod details from K8s
        flows: Hubble network flows
        scan_results: Port scan detections
        falco_threats: Runtime threats from Falco (empirical)
        correlated_threats: Multi-modal correlated threats (static + runtime validation)
        ml_threats: ML-specific domain threats (T11-T17)
        lateral_threats: Cross-namespace threats (empirical)
        egress_threats: External connection threats (empirical)

    Returns:
        Tuple of (model_lines, dfd_entities, dfd_flows)
    """
    # Initialize threat lists if not provided
    falco_threats = falco_threats or []
    correlated_threats = correlated_threats or []
    ml_threats = ml_threats or []
    lateral_threats = lateral_threats or []
    egress_threats = egress_threats or []

    # Filter to only supply chain namespaces
    supply_chain_namespaces = ['dev-zone', 'cicd-zone', 'prod-zone']
    pods = [p for p in pods if p.get('namespace') in supply_chain_namespaces]

    model_lines = [
        "from pytm import TM, Boundary, Actor, Process, Datastore, Dataflow, Data, Threat",
        "",
        "tm = TM('K8s Cluster Threat Model')",
        "tm.description = 'Threat model generated from Kubernetes runtime + config analysis'",
        "tm.isOrdered = True",
        "tm.mergeResponses = True",
        ""
    ]

    dfd_entities = []
    dfd_flows = []

    boundaries = {}
    entities = {}
    external_boundary_var = "externalBoundary"
    model_lines.append(f"{external_boundary_var} = Boundary('External Services')\n")

    internet_var = "Internet"
    model_lines.append(f"{internet_var} = Process(name='Internet', boundary={external_boundary_var})\n")
    model_lines.append(f"{internet_var}.description = 'External world (reserved:world)'")
    model_lines.append(f"{internet_var}.inBoundary = {external_boundary_var}")
    external_entities = {}

    namespaces = set(p["namespace"] for p in pods)
    for ns in namespaces:
        b_var = sanitize_name(ns)
        boundaries[ns] = b_var
        model_lines.append(f"{b_var} = Boundary('{ns}')")

    model_lines.append("")

    # Add pods/entities
    for pod in pods:
        pod_name = pod["name"]
        pod_var = sanitize_name(pod_name)
        namespace = pod["namespace"]
        b_var = boundaries[namespace]
        pod_desc = f"{pod_name} in {namespace}"

        if any(kw in pod_name.lower() for kw in ["db", "mysql", "postgres", "redis", "etcd", "minio", "storage"]):
            model_lines.append(f"{pod_var} = Datastore(name='{pod_name}', boundary={b_var})")
            model_lines.append(f"{pod_var}.description = '{pod_desc}'")
            model_lines.append(f"{pod_var}.inBoundary = {b_var}")
            dfd_entities.append({"type": "Datastore", "name": pod_name, "boundary": namespace})
        else:
            model_lines.append(f"{pod_var} = Process(name='{pod_name}', boundary={b_var})")
            model_lines.append(f"{pod_var}.description = '{pod_desc}'")
            model_lines.append(f"{pod_var}.inBoundary = {b_var}")
            dfd_entities.append({"type": "Process", "name": pod_name, "boundary": namespace})

        entities[pod_name] = pod_var

    model_lines.append("")

    # Add flows
    seen_flows = set()
    for flow_wrap in flows:
        # Skip non-dict entries (errors, parse failures, strings)
        if not isinstance(flow_wrap, dict):
            continue
        if "flow" not in flow_wrap:
            continue
        flow = flow_wrap["flow"]
        src = flow.get("source", {}).get("pod_name")
        dst = flow.get("destination", {}).get("pod_name")
        dst_labels = flow.get("destination", {}).get("labels", [])
        dst_ip = flow.get("destination", {}).get("ip")
        verdict = flow.get("verdict", "UNKNOWN")
        port = flow.get("l4", {}).get("TCP", {}).get("destinationPort")

        if not src or src == dst:
            continue
        if src not in entities:
            continue

        src_var = entities[src]

        if dst in entities:
            dst_var = entities[dst]
            dst_name = dst
        elif "reserved:world" in dst_labels:
            dst_var = internet_var
            dst_name = "Internet"
        else:
            dst_label = dst or dst_ip or "unknown_external"
            dst_key = dst_label
            dst_var = sanitize_name(dst_key)

            if dst_key not in external_entities:
                model_lines.append(
                    f"{dst_var} = Process(name='{dst_label}', boundary={external_boundary_var})"
                )
                model_lines.append(f"{dst_var}.description = 'External connection target'")
                model_lines.append(f"{dst_var}.inBoundary = {external_boundary_var}")
                external_entities[dst_key] = dst_var
                dfd_entities.append({"type": "Process", "name": dst_label, "boundary": "External Services"})
            dst_var = external_entities[dst_key]
            dst_name = dst_label

        try:
            port = int(port)
        except (TypeError, ValueError):
            port = -1
        if port == -1 and verdict == "TRACED":
            continue

        flow_sig = (src_var, dst_var, port)
        if flow_sig in seen_flows:
            continue
        seen_flows.add(flow_sig)

        desc = f"Observed runtime flow (verdict={verdict}, port={port})"
        flow_name_raw = f"{src_var}_to_{dst_var}_{port}"
        flow_name = sanitize_name(flow_name_raw)

        model_lines.append(f"{flow_name}_data = Data('{desc}')")
        model_lines.append(
            f"{flow_name} = Dataflow(name='{flow_name}', source={src_var}, sink={dst_var}, protocol='TCP', data={flow_name}_data, dstPort={port})"
        )

        dfd_flows.append({"source": src, "destination": dst_name, "protocol": "TCP", "port": port})

    model_lines.append("")

    # =========================================================================
    # REGISTER CUSTOM THREATS (Correlated + ML + Runtime Threats)
    # =========================================================================
    # PyTM can accept custom Threat objects that will appear in diagrams/reports
    # These are our detected threats from multi-modal correlation + ML detection

    model_lines.append("# =========================================================================")
    model_lines.append("# CUSTOM THREATS - Multi-Modal Correlated Threats")
    model_lines.append("# =========================================================================")
    model_lines.append("")

    # Define custom threat objects from correlation
    model_lines.append("# Define correlated threat definitions")
    threat_definitions = _generate_threat_definitions(
        correlated_threats, ml_threats, falco_threats, lateral_threats, egress_threats, scan_results
    )
    model_lines.extend(threat_definitions)
    model_lines.append("")

    # Annotate elements with detected threats
    model_lines.append("# Annotate elements with detected threats (for visual indicators)")
    threat_annotations = _annotate_elements_with_threats(
        entities, boundaries, correlated_threats, ml_threats, falco_threats, lateral_threats, egress_threats
    )
    model_lines.extend(threat_annotations)
    model_lines.append("")

    # Document threats as comments
    if correlated_threats:
        model_lines.append("# --- CORRELATED: Multi-Modal Validated Threats ---")
        for threat in correlated_threats[:10]:  # Limit to 10 for brevity
            status = threat.get('validation_status', 'UNKNOWN')
            confidence = threat.get('confidence', 'UNKNOWN')
            threat_id = threat.get('threat_id', 'UNKNOWN')
            model_lines.append(f"# {threat_id} ({status}, {confidence} confidence)")
        model_lines.append("")

    if ml_threats:
        model_lines.append("# --- ML-SPECIFIC: Domain Threats (T11-T17) ---")
        for threat in ml_threats:
            model_lines.append(f"# {threat['threat_id']}: {threat.get('pod', threat.get('service', 'unknown'))} - {threat['description']}")
        model_lines.append("")

    if scan_results:
        model_lines.append("# --- EMPIRICAL: Port Scanning (Hubble) ---")
        for scan in scan_results:
            model_lines.append(f"# {scan['source_pod']}: {scan['reason']}")
        model_lines.append("")

    if falco_threats:
        model_lines.append("# --- EMPIRICAL: Runtime Behavior (Falco) ---")
        for threat in falco_threats:
            model_lines.append(f"# {threat['threat_id']}: {threat['pod']} - {threat['description']}")
        model_lines.append("")

    if lateral_threats:
        model_lines.append("# --- EMPIRICAL: Lateral Movement (Hubble) ---")
        for threat in lateral_threats:
            model_lines.append(f"# {threat['threat_id']}: {threat['source_pod']} -> {threat['dest_pod']} - {threat['description']}")
        model_lines.append("")

    if egress_threats:
        model_lines.append("# --- EMPIRICAL: External Connections (Hubble) ---")
        for threat in egress_threats:
            model_lines.append(f"# {threat['threat_id']}: {threat['pod']} -> {threat.get('dest_ip', 'external')} - {threat['description']}")
        model_lines.append("")

    model_lines.append("# Process the threat model (generates STRIDE + custom threats)")
    model_lines.append("tm.process()")

    return model_lines, dfd_entities, dfd_flows


def _generate_threat_definitions(correlated_threats, ml_threats, falco_threats, lateral_threats, egress_threats, scan_results):
    """
    Generate PyTM Threat object definitions from correlated and ML threats.
    Maps T01-T17 taxonomy to PyTM format with validation confidence.
    """
    lines = []
    defined_threats = set()

    # Process correlated threats (T01-T17 validated with runtime)
    if correlated_threats:
        for threat in correlated_threats[:15]:  # Limit for PyTM diagram clarity
            threat_id = threat.get('threat_id', 'UNKNOWN')

            # Skip runtime-only threats (handle separately)
            if 'RUNTIME-' in threat_id:
                continue

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

    # Process ML-specific threats (T11-T17)
    if ml_threats:
        for threat in ml_threats:
            threat_id = threat.get('threat_id', 'UNKNOWN')

            if threat_id not in defined_threats:
                defined_threats.add(threat_id)

                desc = threat.get('description', 'ML-specific threat')
                severity = threat.get('severity', 'Medium')
                ml_type = threat.get('ml_threat', 'ML Security Issue')

                lines.append(f"# {threat_id}: {ml_type}")
                lines.append(f"Threat(")
                lines.append(f"    SID='{threat_id}',")
                lines.append(f"    target=('Process', 'Datastore'),")
                lines.append(f"    description='{_escape_quotes(desc[:100])}',")
                lines.append(f"    details='ML-specific domain threat',")
                lines.append(f"    severity='{severity}',")
                lines.append(f"    condition='True'")
                lines.append(f")")
                lines.append("")

    # Add runtime threats (Falco, lateral movement, etc.)
    if falco_threats:
        for i, threat in enumerate(falco_threats[:5]):  # Limit to 5 for brevity
            sid = f"RT-FALCO-{i+1:02d}"
            if sid not in defined_threats:
                defined_threats.add(sid)
                lines.append(f"# Runtime Threat: {threat.get('threat_id')}")
                lines.append(f"Threat(")
                lines.append(f"    SID='{sid}',")
                lines.append(f"    target=('Process',),")
                lines.append(f"    description='{_escape_quotes(threat.get('description', 'Runtime threat')[:100])}',")
                lines.append(f"    details='Detected via Falco runtime monitoring',")
                lines.append(f"    severity='{threat.get('severity', 'High')}',")
                lines.append(f"    condition='True'")
                lines.append(f")")
                lines.append("")

    return lines


def _annotate_elements_with_threats(entities, boundaries, correlated_threats, ml_threats, falco_threats, lateral_threats, egress_threats):
    """
    Add threat annotations to PyTM elements for visual indicators.
    This adds custom properties that can be used for coloring/marking in diagrams.
    """
    lines = []

    # Map threats to elements
    element_threats = defaultdict(list)

    # Map correlated threats to elements (extract from static evidence)
    if correlated_threats:
        for threat in correlated_threats:
            # Try to extract affected element from threat
            threat_id = threat.get('threat_id', '')
            # Correlated threats don't always have direct element mapping
            # Could enhance this based on threat_id patterns

    # Map ML threats to elements
    if ml_threats:
        for threat in ml_threats:
            # Determine which element this threat affects
            if 'pod' in threat:
                element_name = threat['pod']
                if element_name in entities:
                    element_threats[element_name].append(threat)
            elif 'service' in threat:
                service_name = threat['service']
                element_threats[f"svc_{service_name}"] = element_threats.get(f"svc_{service_name}", [])
                element_threats[f"svc_{service_name}"].append(threat)
            elif 'namespace' in threat:
                ns_name = threat['namespace']
                if ns_name in boundaries.values() or ns_name in boundaries:
                    element_threats[f"ns_{ns_name}"].append(threat)

    # Add threat annotations to elements
    for element_name, threats in element_threats.items():
        if element_name in entities:
            var_name = entities[element_name]
            threat_count = len(threats)
            threat_ids = ', '.join(t.get('threat_id', 'UNKNOWN') for t in threats[:3])

            lines.append(f"# Threats detected on {element_name}: {threat_count}")
            lines.append(f"{var_name}.threatsDetected = {threat_count}")
            lines.append(f"{var_name}.threatIds = '{threat_ids}'")

            # Add severity indicator
            severities = [t.get('severity', 'Low') for t in threats]
            if 'Critical' in severities:
                lines.append(f"{var_name}.riskLevel = 'Critical'")
            elif 'High' in severities:
                lines.append(f"{var_name}.riskLevel = 'High'")
            else:
                lines.append(f"{var_name}.riskLevel = 'Medium'")

            lines.append("")

    return lines


def _escape_quotes(text):
    """Escape single quotes in text for Python string literals"""
    return text.replace("'", "\\'").replace('\n', ' ')
