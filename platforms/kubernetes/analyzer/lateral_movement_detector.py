# lateral_movement_detector.py
"""
Empirical Threat Detection for Lateral Movement

This module analyzes Hubble network flows to detect cross-namespace
communications and lateral movement attempts. This combines empirical
data (flows) with contextual reasoning about trust boundaries.
"""

def detect_lateral_movement(flows, pods):
    """
    Detect lateral movement through cross-namespace network flows.

    Args:
        flows: List of Hubble flow dictionaries
        pods: List of pod dictionaries with namespace info

    Returns:
        List of lateral movement threat dictionaries
    """
    threats = []

    # Build namespace mapping
    pod_to_namespace = {p["name"]: p["namespace"] for p in pods}

    # Track cross-namespace flows
    cross_ns_flows = {}

    for flow_wrap in flows:
        # Skip non-dict entries (errors, parse failures, strings)
        if not isinstance(flow_wrap, dict):
            continue
        if "flow" not in flow_wrap:
            continue

        flow = flow_wrap["flow"]
        src_pod = flow.get("source", {}).get("pod_name")
        dst_pod = flow.get("destination", {}).get("pod_name")
        dst_labels = flow.get("destination", {}).get("labels", [])

        # Skip if source pod not in our pod list
        if not src_pod or src_pod not in pod_to_namespace:
            continue

        # Skip if destination is external (we handle this separately)
        if "reserved:world" in dst_labels:
            continue

        # Skip if destination pod not found (might be external service)
        if not dst_pod or dst_pod not in pod_to_namespace:
            continue

        # Skip same pod communication
        if src_pod == dst_pod:
            continue

        src_ns = pod_to_namespace[src_pod]
        dst_ns = pod_to_namespace[dst_pod]

        # Detect cross-namespace communication
        if src_ns != dst_ns:
            port = flow.get("l4", {}).get("TCP", {}).get("destinationPort") or \
                   flow.get("l4", {}).get("UDP", {}).get("destinationPort") or "unknown"

            flow_key = (src_pod, dst_pod, src_ns, dst_ns, port)

            if flow_key not in cross_ns_flows:
                cross_ns_flows[flow_key] = {
                    "source_pod": src_pod,
                    "dest_pod": dst_pod,
                    "source_namespace": src_ns,
                    "dest_namespace": dst_ns,
                    "port": port,
                    "count": 0
                }

            cross_ns_flows[flow_key]["count"] += 1

    # Analyze cross-namespace flows for threats
    for flow_info in cross_ns_flows.values():
        src_pod = flow_info["source_pod"]
        dst_pod = flow_info["dest_pod"]
        src_ns = flow_info["source_namespace"]
        dst_ns = flow_info["dest_namespace"]
        port = flow_info["port"]
        count = flow_info["count"]

        # Assess severity based on namespace trust boundaries
        severity, threat_id, description, mitigation = _assess_lateral_movement_severity(
            src_ns, dst_ns, src_pod, dst_pod, port
        )

        if severity:  # Only add if it's a threat
            threats.append({
                "source_pod": src_pod,
                "dest_pod": dst_pod,
                "source_namespace": src_ns,
                "dest_namespace": dst_ns,
                "port": port,
                "flow_count": count,
                "threat_id": threat_id,
                "category": "Empirical (Network Flow Analysis)",
                "description": description,
                "severity": severity,
                "evidence": f"Hubble detected {count} flows from {src_ns}/{src_pod} to {dst_ns}/{dst_pod}:{port}",
                "mitigation": mitigation,
                "detection_method": "Runtime Analysis (Hubble)",
                "cwe": "CWE-668",
                "k8s_threat_matrix": "Cluster Trust Boundary Violation"
            })

    return threats


def _assess_lateral_movement_severity(src_ns, dst_ns, src_pod, dst_pod, port):
    """
    Assess the severity of cross-namespace communication based on trust boundaries.

    Returns: (severity, threat_id, description, mitigation) or (None, None, None, None)
    """

    # HIGH SEVERITY: Development accessing Production
    if "dev" in src_ns.lower() and "prod" in dst_ns.lower():
        return (
            "Critical",
            "LATERAL-001",
            f"Development pod {src_pod} accessing production pod {dst_pod}:{port}",
            "Implement NetworkPolicies to isolate dev from prod; investigate unauthorized access"
        )

    # HIGH SEVERITY: Test accessing Production
    if any(env in src_ns.lower() for env in ["test", "staging", "qa"]) and "prod" in dst_ns.lower():
        return (
            "High",
            "LATERAL-002",
            f"Non-production pod {src_pod} accessing production pod {dst_pod}:{port}",
            "Implement strict namespace isolation; use NetworkPolicies"
        )

    # MEDIUM SEVERITY: User namespace accessing system namespace
    if src_ns not in ["kube-system", "kube-public", "kube-node-lease"] and \
       dst_ns in ["kube-system", "kube-public"]:
        return (
            "Medium",
            "LATERAL-003",
            f"User pod {src_pod} communicating with system namespace {dst_ns}",
            "Review necessity; most user workloads should not access kube-system"
        )

    # MEDIUM SEVERITY: Cross-namespace database access
    if port in [3306, 5432, 27017, 6379, 9042]:  # MySQL, PostgreSQL, MongoDB, Redis, Cassandra
        db_type = {3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis", 9042: "Cassandra"}.get(port, "database")
        return (
            "High",
            "LATERAL-004",
            f"Cross-namespace {db_type} access: {src_pod} ({src_ns}) → {dst_pod} ({dst_ns})",
            f"Databases should not be accessible cross-namespace; implement NetworkPolicies"
        )

    # MEDIUM SEVERITY: General cross-namespace communication
    # This indicates lack of network segmentation
    return (
        "Medium",
        "LATERAL-005",
        f"Cross-namespace communication: {src_pod} ({src_ns}) → {dst_pod} ({dst_ns}):{port}",
        "Implement NetworkPolicies for namespace isolation; verify communication is authorized"
    )


def detect_unusual_external_connections(flows, pods):
    """
    Detect pods making connections to external/Internet destinations.

    This is empirical because we can only see actual connections at runtime.
    """
    threats = []
    pod_names = {p["name"] for p in pods}

    # Track external connections
    external_conns = {}

    for flow_wrap in flows:
        # Skip non-dict entries (errors, parse failures, strings)
        if not isinstance(flow_wrap, dict):
            continue
        if "flow" not in flow_wrap:
            continue

        flow = flow_wrap["flow"]
        src_pod = flow.get("source", {}).get("pod_name")
        dst_labels = flow.get("destination", {}).get("labels", [])
        dst_ip = flow.get("destination", {}).get("ip")

        # Only interested in flows from our pods
        if not src_pod or src_pod not in pod_names:
            continue

        # Check if destination is external (world)
        if "reserved:world" in dst_labels:
            port = flow.get("l4", {}).get("TCP", {}).get("destinationPort") or \
                   flow.get("l4", {}).get("UDP", {}).get("destinationPort") or "unknown"

            conn_key = (src_pod, dst_ip, port)

            if conn_key not in external_conns:
                external_conns[conn_key] = {
                    "pod": src_pod,
                    "dest_ip": dst_ip,
                    "port": port,
                    "count": 0
                }

            external_conns[conn_key]["count"] += 1

    # Analyze external connections
    for conn_info in external_conns.values():
        pod = conn_info["pod"]
        dest_ip = conn_info["dest_ip"]
        port = conn_info["port"]
        count = conn_info["count"]

        # Assess threat based on port and frequency
        severity, threat_id, description = _assess_external_connection(pod, dest_ip, port, count)

        if severity:
            threats.append({
                "pod": pod,
                "dest_ip": dest_ip,
                "port": port,
                "flow_count": count,
                "threat_id": threat_id,
                "category": "Empirical (Egress Traffic)",
                "description": description,
                "severity": severity,
                "evidence": f"Hubble detected {count} external connections from {pod} to {dest_ip}:{port}",
                "mitigation": "Implement egress NetworkPolicies; investigate data exfiltration",
                "detection_method": "Runtime Analysis (Hubble)",
                "ground_truth_match": "GT-7",
                "cwe": "CWE-200",
                "k8s_threat_matrix": "Data Exfiltration"
            })

    return threats


def _assess_external_connection(pod, dest_ip, port, count):
    """Assess severity of external connection"""

    # Suspicious ports
    suspicious_ports = {
        22: ("SSH", "High"),
        3389: ("RDP", "High"),
        4444: ("Metasploit", "Critical"),
        6667: ("IRC", "High"),
        1337: ("Elite Hacker Port", "High")
    }

    if port in suspicious_ports:
        service, severity = suspicious_ports[port]
        return (
            severity,
            "EGRESS-001",
            f"Suspicious external connection from {pod} to {dest_ip}:{port} ({service})"
        )

    # Database ports going external (likely exfiltration)
    if port in [3306, 5432, 27017, 6379]:
        return (
            "Critical",
            "EGRESS-002",
            f"Database port {port} connection from {pod} to external IP {dest_ip}"
        )

    # High frequency connections (possible C2 or exfiltration)
    if count > 100:
        return (
            "High",
            "EGRESS-003",
            f"High-frequency external connection from {pod} to {dest_ip}:{port} ({count} flows)"
        )

    # Standard external connection (may be legitimate)
    if port in [80, 443, 53]:
        # HTTP/HTTPS/DNS might be legitimate
        return (None, None, None)

    # Other external connection
    return (
        "Medium",
        "EGRESS-004",
        f"External connection from {pod} to {dest_ip}:{port}"
    )


def get_lateral_movement_summary(threats):
    """Generate summary statistics for lateral movement threats"""
    if not threats:
        return {
            "total": 0,
            "by_severity": {},
            "unique_sources": [],
            "unique_destinations": []
        }

    from collections import Counter

    severities = Counter(t["severity"] for t in threats)
    unique_sources = list(set(t.get("source_pod", t.get("pod", "")) for t in threats))
    unique_destinations = list(set(t.get("dest_pod", t.get("dest_ip", "")) for t in threats))

    return {
        "total": len(threats),
        "by_severity": dict(severities),
        "unique_sources": unique_sources,
        "unique_destinations": unique_destinations,
        "critical_count": severities.get("Critical", 0),
        "high_count": severities.get("High", 0),
        "medium_count": severities.get("Medium", 0),
        "low_count": severities.get("Low", 0)
    }
