# falco_threat_detector.py
"""
Empirical Threat Detection from Falco Runtime Events

This module analyzes Falco runtime events to detect threats that CANNOT be
found through static YAML analysis. This proves the necessity of runtime
monitoring in the threat modeling framework.
"""

def detect_falco_runtime_threats(falco_events, pods):
    """
    Analyze Falco runtime events and convert them to threat findings.

    Args:
        falco_events: List of Falco event dictionaries from API
        pods: List of pod dictionaries with metadata

    Returns:
        List of threat dictionaries with detection metadata
    """
    threats = []

    # Build pod lookup for validation
    pod_names = {p["name"] for p in pods}
    pod_namespaces = {p["name"]: p["namespace"] for p in pods}

    # Track unique threats to avoid duplicates
    seen_threats = set()

    for event in falco_events:
        # Falco event structure varies by API version
        # Handle multiple possible formats
        rule = event.get("rule") or event.get("Rule") or ""
        priority = event.get("priority") or event.get("Priority") or "Notice"
        output = event.get("output") or event.get("Output") or ""

        # Extract pod info from output_fields or parse from output
        output_fields = event.get("output_fields") or event.get("OutputFields") or {}
        pod_name = (
            output_fields.get("k8s.pod.name") or
            output_fields.get("k8s_pod_name") or
            _extract_pod_from_output(output)
        )

        if not pod_name or pod_name not in pod_names:
            continue

        namespace = pod_namespaces.get(pod_name, "unknown")

        # Create unique key to avoid duplicate threats
        threat_key = (pod_name, rule)
        if threat_key in seen_threats:
            continue
        seen_threats.add(threat_key)

        # Map Falco rules to threat categories
        threat = _map_falco_rule_to_threat(
            rule, pod_name, namespace, priority, output, output_fields
        )

        if threat:
            threats.append(threat)

    return threats


def _extract_pod_from_output(output):
    """Extract pod name from Falco output string if output_fields missing"""
    # Example: "A shell was spawned in container my-pod (user=root)"
    import re
    match = re.search(r'pod[= ]([a-zA-Z0-9\-]+)', output)
    if match:
        return match.group(1)

    # Try container name pattern
    match = re.search(r'container[= ]([a-zA-Z0-9\-]+)', output)
    if match:
        return match.group(1)

    return None


def _map_falco_rule_to_threat(rule, pod_name, namespace, priority, output, output_fields):
    """
    Map Falco rule to threat classification.

    Returns threat dict or None if rule doesn't match known patterns.
    """

    # EMPIRICAL THREAT 1: Shell Execution in Container
    if any(keyword in rule.lower() for keyword in ["terminal", "shell", "bash", "sh spawned"]):
        return {
            "pod": pod_name,
            "namespace": namespace,
            "threat_id": "EMPIRICAL-RT001",
            "category": "Empirical (Runtime Execution)",
            "description": f"Shell spawned in {pod_name} at runtime",
            "details": output,
            "severity": _priority_to_severity(priority),
            "evidence": f"Falco rule: {rule}",
            "mitigation": "Investigate potential container compromise; containers should not spawn interactive shells",
            "detection_method": "Runtime Analysis (Falco)",
            "ground_truth_match": "GT-10",
            "cwe": "CWE-78",
            "k8s_threat_matrix": "Exec into Container"
        }

    # EMPIRICAL THREAT 2: Sensitive File Read
    if any(keyword in rule.lower() for keyword in ["sensitive file", "read sensitive", "etc/shadow", "etc/passwd"]):
        file_path = output_fields.get("fd.name") or output_fields.get("file") or "unknown file"
        return {
            "pod": pod_name,
            "namespace": namespace,
            "threat_id": "EMPIRICAL-RT002",
            "category": "Empirical (Runtime Information Disclosure)",
            "description": f"Sensitive file accessed: {file_path} in {pod_name}",
            "details": output,
            "severity": "Critical",
            "evidence": f"Falco rule: {rule}",
            "mitigation": "Implement file integrity monitoring; investigate unauthorized access",
            "detection_method": "Runtime Analysis (Falco)",
            "ground_truth_match": "GT-9",
            "cwe": "CWE-200",
            "k8s_threat_matrix": "Access Kubernetes Secrets"
        }

    # EMPIRICAL THREAT 3: File System Modification
    if any(keyword in rule.lower() for keyword in ["write below /etc", "write below etc", "modify binary", "file opened for writing"]):
        file_path = output_fields.get("fd.name") or output_fields.get("file") or "system file"
        return {
            "pod": pod_name,
            "namespace": namespace,
            "threat_id": "EMPIRICAL-RT003",
            "category": "Empirical (Runtime Tampering)",
            "description": f"System file modified: {file_path} in {pod_name}",
            "details": output,
            "severity": "Critical",
            "evidence": f"Falco rule: {rule}",
            "mitigation": "Use read-only root filesystem; enable immutable containers",
            "detection_method": "Runtime Analysis (Falco)",
            "ground_truth_match": "GT-9",
            "cwe": "CWE-732",
            "k8s_threat_matrix": "Writable hostPath Mount"
        }

    # EMPIRICAL THREAT 4: Unauthorized Network Connection
    if any(keyword in rule.lower() for keyword in ["outbound", "connection", "network", "unexpected connection"]):
        dest_ip = output_fields.get("fd.rip") or output_fields.get("fd.sip") or "external host"
        dest_port = output_fields.get("fd.rport") or output_fields.get("fd.sport") or "unknown"
        return {
            "pod": pod_name,
            "namespace": namespace,
            "threat_id": "EMPIRICAL-RT004",
            "category": "Empirical (Runtime Exfiltration)",
            "description": f"Unexpected network connection from {pod_name} to {dest_ip}:{dest_port}",
            "details": output,
            "severity": "High",
            "evidence": f"Falco rule: {rule}",
            "mitigation": "Implement NetworkPolicy egress rules; investigate data exfiltration",
            "detection_method": "Runtime Analysis (Falco)",
            "ground_truth_match": "GT-7",
            "cwe": "CWE-200",
            "k8s_threat_matrix": "Data Exfiltration"
        }

    # EMPIRICAL THREAT 5: Container Escape Attempt
    if any(keyword in rule.lower() for keyword in ["namespace", "nsenter", "unshare", "mount", "privileged operation"]):
        return {
            "pod": pod_name,
            "namespace": namespace,
            "threat_id": "EMPIRICAL-RT005",
            "category": "Empirical (Runtime Container Escape)",
            "description": f"Container escape attempt detected in {pod_name}",
            "details": output,
            "severity": "Critical",
            "evidence": f"Falco rule: {rule}",
            "mitigation": "Remove CAP_SYS_ADMIN capability; implement seccomp profiles",
            "detection_method": "Runtime Analysis (Falco)",
            "ground_truth_match": "GT-19",
            "cwe": "CWE-250",
            "k8s_threat_matrix": "Privileged Container"
        }

    # EMPIRICAL THREAT 6: Process Injection
    if any(keyword in rule.lower() for keyword in ["ptrace", "code injection", "process injection"]):
        target_proc = output_fields.get("proc.name") or "process"
        return {
            "pod": pod_name,
            "namespace": namespace,
            "threat_id": "EMPIRICAL-RT006",
            "category": "Empirical (Runtime Code Injection)",
            "description": f"Process injection detected in {pod_name} targeting {target_proc}",
            "details": output,
            "severity": "Critical",
            "evidence": f"Falco rule: {rule}",
            "mitigation": "Disable ptrace capability; use AppArmor/SELinux",
            "detection_method": "Runtime Analysis (Falco)",
            "ground_truth_match": "GT-19",
            "cwe": "CWE-94",
            "k8s_threat_matrix": "Process Injection"
        }

    # EMPIRICAL THREAT 7: Crypto Mining Activity
    if any(keyword in rule.lower() for keyword in ["crypto", "mining", "miner", "cpu"]):
        return {
            "pod": pod_name,
            "namespace": namespace,
            "threat_id": "EMPIRICAL-RT007",
            "category": "Empirical (Runtime Resource Abuse)",
            "description": f"Crypto-mining activity detected in {pod_name}",
            "details": output,
            "severity": "High",
            "evidence": f"Falco rule: {rule}",
            "mitigation": "Terminate pod; investigate compromise; set resource limits",
            "detection_method": "Runtime Analysis (Falco)",
            "ground_truth_match": "GT-6",
            "cwe": "CWE-400",
            "k8s_threat_matrix": "Resource Hijacking"
        }

    # EMPIRICAL THREAT 8: DNS Tunneling
    if any(keyword in rule.lower() for keyword in ["dns", "tunnel", "exfil"]):
        domain = output_fields.get("domain") or "suspicious domain"
        return {
            "pod": pod_name,
            "namespace": namespace,
            "threat_id": "EMPIRICAL-RT008",
            "category": "Empirical (Runtime DNS Exfiltration)",
            "description": f"DNS tunneling detected from {pod_name} to {domain}",
            "details": output,
            "severity": "Critical",
            "evidence": f"Falco rule: {rule}",
            "mitigation": "Implement DNS monitoring; block external DNS; investigate exfiltration",
            "detection_method": "Runtime Analysis (Falco)",
            "ground_truth_match": "GT-8",
            "cwe": "CWE-200",
            "k8s_threat_matrix": "Data Exfiltration"
        }

    # EMPIRICAL THREAT 9: Package Management Execution
    if any(keyword in rule.lower() for keyword in ["package", "apt", "yum", "apk", "download"]):
        return {
            "pod": pod_name,
            "namespace": namespace,
            "threat_id": "EMPIRICAL-RT009",
            "category": "Empirical (Runtime Persistence)",
            "description": f"Package manager executed in {pod_name}",
            "details": output,
            "severity": "Medium",
            "evidence": f"Falco rule: {rule}",
            "mitigation": "Containers should be immutable; investigate unauthorized software installation",
            "detection_method": "Runtime Analysis (Falco)",
            "ground_truth_match": "N/A",
            "cwe": "CWE-494",
            "k8s_threat_matrix": "Software Deployment Tools"
        }

    # If no pattern matched, return None
    return None


def _priority_to_severity(priority):
    """Convert Falco priority to threat severity"""
    priority_map = {
        "Emergency": "Critical",
        "Alert": "Critical",
        "Critical": "Critical",
        "Error": "High",
        "Warning": "High",
        "Notice": "Medium",
        "Informational": "Low",
        "Debug": "Low"
    }
    return priority_map.get(priority, "Medium")


def get_falco_threat_summary(threats):
    """Generate summary statistics for Falco threats"""
    if not threats:
        return {
            "total": 0,
            "by_severity": {},
            "by_category": {},
            "unique_pods": []
        }

    from collections import Counter

    severities = Counter(t["severity"] for t in threats)
    categories = Counter(t["category"] for t in threats)
    unique_pods = list(set(t["pod"] for t in threats))

    return {
        "total": len(threats),
        "by_severity": dict(severities),
        "by_category": dict(categories),
        "unique_pods": unique_pods,
        "critical_count": severities.get("Critical", 0),
        "high_count": severities.get("High", 0),
        "medium_count": severities.get("Medium", 0),
        "low_count": severities.get("Low", 0)
    }
