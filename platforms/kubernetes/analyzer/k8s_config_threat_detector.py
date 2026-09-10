# k8s_config_threat_detector.py
"""
Formal Threat Detection from Kubernetes Static Configuration

This module analyzes K8s pod specs and RBAC policies to detect threats that
CAN be found through static YAML analysis (formal methods). This provides
a baseline comparison to show what runtime analysis adds.
"""

def detect_k8s_config_threats(pods, rbac_data, services=None, configmaps=None, network_policies=None, namespaces=None):
    """
    Analyze Kubernetes static configuration for security threats.

    Args:
        pods: List of pod dictionaries with metadata and security context
        rbac_data: List of RBAC binding dictionaries
        services: Dict of service configurations (optional)
        configmaps: List of ConfigMap dictionaries (optional)
        network_policies: List of NetworkPolicy dictionaries (optional)
        namespaces: List of namespace metadata dictionaries (optional)

    Returns:
        List of threat dictionaries with detection metadata
    """
    threats = []

    # Analyze pod security configurations
    for pod in pods:
        pod_threats = _analyze_pod_security(pod)
        threats.extend(pod_threats)

    # Analyze RBAC configurations
    rbac_threats = _analyze_rbac_security(rbac_data)
    threats.extend(rbac_threats)

    # T1: Analyze services for external exposure
    if services:
        service_threats = _analyze_services(services)
        threats.extend(service_threats)

    # T3: Analyze services for unencrypted communication
    if services:
        http_threats = _analyze_unencrypted_services(services)
        threats.extend(http_threats)

    # T8: Analyze ConfigMaps for exposed secrets
    if configmaps:
        secret_threats = _detect_secrets_in_configmaps(configmaps)
        threats.extend(secret_threats)

    # T4: Analyze for missing NetworkPolicies
    if network_policies is not None and namespaces:
        netpol_threats = _detect_missing_network_policies(namespaces, network_policies)
        threats.extend(netpol_threats)

    # T7: Analyze namespace annotations for audit logging
    if namespaces:
        audit_threats = _detect_missing_audit_logging(namespaces)
        threats.extend(audit_threats)

    # T5: Analyze registry configuration
    if configmaps:
        registry_threats = _detect_registry_misconfig(pods, configmaps)
        threats.extend(registry_threats)

    # T9: Analyze Gitea configuration
    if configmaps:
        gitea_threats = _detect_gitea_misconfig(configmaps)
        threats.extend(gitea_threats)

    return threats


def _analyze_pod_security(pod):
    """Analyze individual pod for security misconfigurations"""
    threats = []
    pod_name = pod["name"]
    namespace = pod["namespace"]

    # Extract security-relevant fields (handle None values)
    host_pid = pod.get("hostPID", False) or False
    host_network = pod.get("hostNetwork", False) or False
    host_ipc = pod.get("hostIPC", False) or False
    service_account = pod.get("serviceAccount", "default") or "default"
    annotations = pod.get("annotations") or {}
    container_security = pod.get("containerSecurity") or []

    # Parse last-applied-configuration annotation for additional context
    last_config = annotations.get("kubectl.kubernetes.io/last-applied-configuration", "") if annotations else ""

    # FORMAL THREAT 1: hostPID Access
    if host_pid:
        threats.append({
            "pod": pod_name,
            "namespace": namespace,
            "threat_id": "T10",
            "category": "Formal (K8s Config)",
            "description": f"Pod {pod_name} has hostPID=true (host process namespace access)",
            "severity": "Critical",
            "evidence": "Static YAML analysis: spec.hostPID=true",
            "mitigation": "Remove hostPID; use isolated PID namespaces",
            "detection_method": "Static Analysis (K8s Config)",
            "ground_truth_match": "GT-1, GT-19",
            "cwe": "CWE-250",
            "k8s_threat_matrix": "Access Host Namespace"
        })

    # FORMAL THREAT 2: hostNetwork Access
    if host_network:
        threats.append({
            "pod": pod_name,
            "namespace": namespace,
            "threat_id": "T10",
            "category": "Formal (K8s Config)",
            "description": f"Pod {pod_name} has hostNetwork=true (host network namespace access)",
            "severity": "High",
            "evidence": "Static YAML analysis: spec.hostNetwork=true",
            "mitigation": "Remove hostNetwork; use CNI networking with NetworkPolicies",
            "detection_method": "Static Analysis (K8s Config)",
            "ground_truth_match": "GT-1",
            "cwe": "CWE-668",
            "k8s_threat_matrix": "Access Host Network"
        })

    # FORMAL THREAT 3: hostIPC Access
    if host_ipc:
        threats.append({
            "pod": pod_name,
            "namespace": namespace,
            "threat_id": "T10",
            "category": "Formal (K8s Config)",
            "description": f"Pod {pod_name} has hostIPC=true (host IPC namespace access)",
            "severity": "High",
            "evidence": "Static YAML analysis: spec.hostIPC=true",
            "mitigation": "Remove hostIPC; isolate IPC namespace",
            "detection_method": "Static Analysis (K8s Config)",
            "ground_truth_match": "GT-1",
            "cwe": "CWE-668",
            "k8s_threat_matrix": "Access Host Namespace"
        })

    # FORMAL THREAT 4: Privileged Container
    if '"privileged":true' in last_config or '"privileged": true' in last_config:
        threats.append({
            "pod": pod_name,
            "namespace": namespace,
            "threat_id": "T10",
            "category": "Formal (K8s Config)",
            "description": f"Pod {pod_name} runs with privileged=true",
            "severity": "Critical",
            "evidence": "Static YAML analysis: securityContext.privileged=true",
            "mitigation": "Remove privileged flag; use specific capabilities instead (e.g., CAP_NET_ADMIN)",
            "detection_method": "Static Analysis (K8s Config)",
            "ground_truth_match": "GT-1",
            "cwe": "CWE-250",
            "k8s_threat_matrix": "Privileged Container"
        })

    # Check container-level security contexts
    for container_sec in container_security:
        container_name = container_sec.get("name", "unknown")

        # FORMAL THREAT 5: Container Privileged Mode
        if container_sec.get("privileged"):
            threats.append({
                "pod": pod_name,
                "namespace": namespace,
                "threat_id": "T10",
                "category": "Formal (K8s Config)",
                "description": f"Container {container_name} in {pod_name} runs privileged",
                "severity": "Critical",
                "evidence": f"Static YAML analysis: container.securityContext.privileged=true",
                "mitigation": "Remove privileged flag from container",
                "detection_method": "Static Analysis (K8s Config)",
                "ground_truth_match": "GT-1",
                "cwe": "CWE-250",
                "k8s_threat_matrix": "Privileged Container"
            })

        # FORMAL THREAT 6: Dangerous Capabilities
        capabilities_add = container_sec.get("capabilities", {}).get("add", [])
        dangerous_caps = ["SYS_ADMIN", "NET_ADMIN", "SYS_MODULE", "SYS_PTRACE", "DAC_READ_SEARCH"]

        for cap in capabilities_add:
            if cap in dangerous_caps:
                threats.append({
                    "pod": pod_name,
                    "namespace": namespace,
                    "threat_id": "T10",
                    "category": "Formal (K8s Config)",
                    "description": f"Container {container_name} has dangerous capability {cap}",
                    "severity": "High",
                    "evidence": f"Static YAML analysis: capabilities.add=[{cap}]",
                    "mitigation": f"Remove {cap} capability if not strictly required",
                    "detection_method": "Static Analysis (K8s Config)",
                    "ground_truth_match": "GT-19",
                    "cwe": "CWE-250",
                    "k8s_threat_matrix": "Privileged Container"
                })

        # FORMAL THREAT 7: Writable Root Filesystem
        if container_sec.get("readOnlyRootFilesystem") == False:
            threats.append({
                "pod": pod_name,
                "namespace": namespace,
                "threat_id": "T10",
                "category": "Formal (K8s Config)",
                "description": f"Container {container_name} has writable root filesystem",
                "severity": "Medium",
                "evidence": "Static YAML analysis: readOnlyRootFilesystem=false",
                "mitigation": "Set readOnlyRootFilesystem=true for immutable containers",
                "detection_method": "Static Analysis (K8s Config)",
                "ground_truth_match": "N/A",
                "cwe": "CWE-732",
                "k8s_threat_matrix": "Writable hostPath Mount"
            })

    # FORMAL THREAT 8: Hardcoded Secrets in Environment
    for container in pod.get("containers", []):
        # Check if container image is from annotations
        pass  # TODO: Extract env vars if available in enhanced pod data

    # Check for secret environment variables in last-applied-config
    if any(keyword in last_config.lower() for keyword in ['"password":', '"secret":', '"api_key":', '"token":']):
        # Try to extract the actual value
        import re
        secret_matches = re.findall(r'"([A-Z_]*(?:PASSWORD|SECRET|KEY|TOKEN)[A-Z_]*)"\s*:\s*"([^"]+)"', last_config, re.IGNORECASE)

        if secret_matches:
            for env_name, env_value in secret_matches:
                # Skip if it's a reference to a secret (valueFrom)
                if "valuefrom" in last_config.lower() or "secretkeyref" in last_config.lower():
                    continue

                threats.append({
                    "pod": pod_name,
                    "namespace": namespace,
                    "threat_id": "T10",
                    "category": "Formal (K8s Config)",
                    "description": f"Hardcoded secret in environment variable {env_name}",
                    "severity": "Critical",
                    "evidence": f"Static YAML analysis: env.{env_name} contains hardcoded value",
                    "mitigation": "Use Kubernetes Secrets with secretKeyRef instead of hardcoded values",
                    "detection_method": "Static Analysis (K8s Config)",
                    "ground_truth_match": "GT-3",
                    "cwe": "CWE-798",
                    "k8s_threat_matrix": "Access Kubernetes Secrets"
                })

    return threats


def _analyze_rbac_security(rbac_data):
    """Analyze RBAC bindings for security issues"""
    threats = []

    for binding in rbac_data:
        binding_name = binding.get("binding", "unknown")
        namespace = binding.get("namespace", "cluster")
        role = binding.get("role", "")
        role_kind = binding.get("role_kind", "")
        subjects = binding.get("subjects", [])
        permissions = binding.get("permissions", [])

        # FORMAL THREAT 9: cluster-admin in Non-System Namespace
        if role == "cluster-admin" and namespace not in ["kube-system", "cluster", "kube-public", "kube-node-lease"]:
            for subject in subjects:
                threats.append({
                    "binding": binding_name,
                    "namespace": namespace,
                    "subject": f"{subject.get('kind', 'Unknown')}/{subject.get('name', 'unknown')}",
                    "threat_id": "T02",
                    "category": "Formal (RBAC)",
                    "description": f"cluster-admin role bound in namespace {namespace} to {subject.get('name')}",
                    "severity": "Critical",
                    "evidence": "RBAC analysis: ClusterRole cluster-admin bound to user namespace",
                    "mitigation": "Use least-privilege custom roles; avoid cluster-admin in user namespaces",
                    "detection_method": "Static Analysis (RBAC)",
                    "ground_truth_match": "GT-2",
                    "cwe": "CWE-269",
                    "k8s_threat_matrix": "Excessive Permissions"
                })

        # FORMAL THREAT 10: Overly Permissive Secret Access
        for perm in permissions:
            resources = perm.get("resources", [])
            verbs = perm.get("verbs", [])

            # Check for broad secret access
            if "secrets" in resources or "*" in resources:
                if any(verb in verbs for verb in ["get", "list", "*"]):
                    # Check if binding is to a regular ServiceAccount (not system)
                    for subject in subjects:
                        if subject.get("kind") == "ServiceAccount":
                            sa_name = subject.get("name", "")
                            if not sa_name.startswith("system:"):
                                threats.append({
                                    "binding": binding_name,
                                    "namespace": namespace,
                                    "subject": f"ServiceAccount/{sa_name}",
                                    "threat_id": "T06",
                                    "category": "Formal (RBAC)",
                                    "description": f"ServiceAccount {sa_name} has broad secret access",
                                    "severity": "High",
                                    "evidence": f"RBAC analysis: {role_kind}/{role} grants {verbs} on secrets",
                                    "mitigation": "Limit secret access to specific secret names using resourceNames",
                                    "detection_method": "Static Analysis (RBAC)",
                                    "ground_truth_match": "GT-2",
                                    "cwe": "CWE-269",
                                    "k8s_threat_matrix": "Access Kubernetes Secrets"
                                })

            # FORMAL THREAT 11: Pod Exec Permission
            if "pods/exec" in resources or ("pods" in resources and "create" in verbs):
                for subject in subjects:
                    sa_name = subject.get("name", "")
                    if subject.get("kind") == "ServiceAccount" and not sa_name.startswith("system:"):
                        threats.append({
                            "binding": binding_name,
                            "namespace": namespace,
                            "subject": f"ServiceAccount/{sa_name}",
                            "threat_id": "T06",
                            "category": "Formal (RBAC)",
                            "description": f"ServiceAccount {sa_name} can exec into pods",
                            "severity": "High",
                            "evidence": f"RBAC analysis: {role_kind}/{role} grants pods/exec permission",
                            "mitigation": "Remove pods/exec unless absolutely required; monitor usage",
                            "detection_method": "Static Analysis (RBAC)",
                            "ground_truth_match": "GT-17",
                            "cwe": "CWE-269",
                            "k8s_threat_matrix": "Exec into Container"
                        })

            # FORMAL THREAT 12: Wildcard Permissions
            if "*" in resources and "*" in verbs:
                for subject in subjects:
                    threats.append({
                        "binding": binding_name,
                        "namespace": namespace,
                        "subject": f"{subject.get('kind')}/{subject.get('name')}",
                        "threat_id": "T02",
                        "category": "Formal (RBAC)",
                        "description": f"Wildcard permissions (*/*) granted to {subject.get('name')}",
                        "severity": "Critical",
                        "evidence": f"RBAC analysis: {role_kind}/{role} grants all verbs on all resources",
                        "mitigation": "Replace wildcard with specific resource and verb permissions",
                        "detection_method": "Static Analysis (RBAC)",
                        "ground_truth_match": "GT-2",
                        "cwe": "CWE-269",
                        "k8s_threat_matrix": "Excessive Permissions"
                    })

        # T12: Training Data Poisoning - CI/CD access to training data
        # Detect Jenkins (cicd-zone) having access to dev-zone (where training data is)
        for subject in subjects:
            subject_ns = subject.get("namespace", "")
            subject_name = subject.get("name", "")

            if "jenkins" in subject_name.lower() and subject_ns == "cicd-zone":
                # Check if this grants access to dev-zone
                if namespace == "dev-zone" and role in ["edit", "admin", "cluster-admin"]:
                    threats.append({
                        "binding": binding_name,
                        "namespace": namespace,
                        "subject": f"{subject.get('kind')}/{subject_name}",
                        "subject_namespace": subject_ns,
                        "threat_id": "T12",
                        "category": "ML Supply Chain",
                        "description": f"CI/CD service (Jenkins) from {subject_ns} has {role} access to training data in {namespace}",
                        "severity": "High",
                        "evidence": f"Cross-zone RBAC: Jenkins can modify resources in dev-zone including training data",
                        "mitigation": "Restrict CI/CD write access to training data; use read-only service accounts",
                        "detection_method": "Static Analysis (RBAC)",
                        "cwe": "CWE-732",
                        "ml_threat": "Training Data Poisoning"
                    })

        # T15: Cross-Zone ML Deployment RBAC
        # Detect Jenkins (cicd-zone) having deployment access to prod-zone
        for subject in subjects:
            subject_ns = subject.get("namespace", "")
            subject_name = subject.get("name", "")

            if "jenkins" in subject_name.lower() and subject_ns == "cicd-zone":
                # Check if this grants deployment access to prod-zone
                if namespace == "prod-zone" and role in ["edit", "admin", "cluster-admin"]:
                    # Check if permissions include deployment/create (ML deployment capability)
                    can_deploy = False
                    for perm in permissions:
                        resources = perm.get("resources", [])
                        verbs = perm.get("verbs", [])
                        if any(r in resources for r in ["deployments", "pods", "*"]) and \
                           any(v in verbs for v in ["create", "update", "patch", "*"]):
                            can_deploy = True
                            break

                    if can_deploy or role in ["edit", "admin", "cluster-admin"]:  # These roles include deployment rights
                        threats.append({
                            "binding": binding_name,
                            "namespace": namespace,
                            "subject": f"{subject.get('kind')}/{subject_name}",
                            "subject_namespace": subject_ns,
                            "threat_id": "T15",
                            "category": "ML Supply Chain",
                            "description": f"CI/CD service (Jenkins) from {subject_ns} can deploy ML models to production ({namespace})",
                            "severity": "High",
                            "evidence": f"Cross-zone RBAC: {role_kind}/{role} in {namespace} bound to ServiceAccount from {subject_ns}",
                            "mitigation": "Use GitOps with approval gates; restrict direct CI/CD deployment to production",
                            "detection_method": "Static Analysis (RBAC)",
                            "cwe": "CWE-732",
                            "ml_threat": "Cross-Zone ML Deployment Without Approval"
                        })

    return threats


def get_k8s_threat_summary(threats):
    """Generate summary statistics for K8s config threats"""
    if not threats:
        return {
            "total": 0,
            "by_severity": {},
            "by_category": {},
            "unique_pods": [],
            "unique_bindings": []
        }

    from collections import Counter

    severities = Counter(t["severity"] for t in threats)
    categories = Counter(t["category"] for t in threats)
    unique_pods = list(set(t.get("pod", "") for t in threats if "pod" in t))
    unique_bindings = list(set(t.get("binding", "") for t in threats if "binding" in t))

    return {
        "total": len(threats),
        "by_severity": dict(severities),
        "by_category": dict(categories),
        "unique_pods": unique_pods,
        "unique_bindings": unique_bindings,
        "critical_count": severities.get("Critical", 0),
        "high_count": severities.get("High", 0),
        "medium_count": severities.get("Medium", 0),
        "low_count": severities.get("Low", 0)
    }


# ============================================================================
# NEW THREAT DETECTORS FOR T1-T10 TAXONOMY
# ============================================================================

def _analyze_services(services):
    """
    T1: Detect services exposed via LoadBalancer or NodePort

    Args:
        services: Dict of service configurations

    Returns:
        List of threat dictionaries
    """
    threats = []

    for svc_name, svc_data in services.items():
        svc_type = svc_data.get('type', 'ClusterIP')
        namespace = svc_data.get('namespace', 'unknown')

        # T1: LoadBalancer exposes service externally
        if svc_type == 'LoadBalancer':
            threats.append({
                "service": svc_name,
                "namespace": namespace,
                "threat_id": "T01",
                "category": "Formal (Service Config)",
                "description": f"Service {svc_name} exposed via LoadBalancer without authentication",
                "severity": "High",
                "evidence": f"Service type: LoadBalancer (externally accessible)",
                "mitigation": "Change to ClusterIP and use Ingress with authentication",
                "detection_method": "Static Analysis (Service Config)",
                "ground_truth_match": "T1",
                "cwe": "CWE-284",
                "k8s_threat_matrix": "External Service Exposure"
            })

        # Also flag NodePort as potentially risky
        elif svc_type == 'NodePort':
            threats.append({
                "service": svc_name,
                "namespace": namespace,
                "threat_id": "T01",
                "category": "Formal (Service Config)",
                "description": f"Service {svc_name} exposed via NodePort",
                "severity": "Medium",
                "evidence": f"Service type: NodePort (accessible on all nodes)",
                "mitigation": "Change to ClusterIP and use Ingress with authentication",
                "detection_method": "Static Analysis (Service Config)",
                "ground_truth_match": "T1",
                "cwe": "CWE-284",
                "k8s_threat_matrix": "External Service Exposure"
            })

    return threats


def _analyze_unencrypted_services(services):
    """
    T3: Detect services using unencrypted HTTP communication

    Args:
        services: Dict of service configurations

    Returns:
        List of threat dictionaries
    """
    threats = []
    http_ports = [80, 8080, 3000, 5000, 8081, 8888, 9090]  # Common HTTP ports

    for svc_name, svc_data in services.items():
        namespace = svc_data.get('namespace', 'unknown')
        ports = svc_data.get('ports', [])

        for port_info in ports:
            port_num = port_info.get('port')
            port_name = port_info.get('name', '').lower()

            # Check if it's an HTTP port (not HTTPS)
            is_http = (port_num in http_ports or
                      'http' in port_name and 'https' not in port_name)

            if is_http:
                threats.append({
                    "service": svc_name,
                    "namespace": namespace,
                    "threat_id": "T03",
                    "category": "Formal (Service Config)",
                    "description": f"Service {svc_name} uses unencrypted HTTP on port {port_num}",
                    "severity": "Medium",
                    "evidence": f"Port {port_num} (HTTP) without TLS encryption",
                    "mitigation": "Enable TLS/HTTPS, use service mesh with mTLS",
                    "detection_method": "Static Analysis (Service Config)",
                    "ground_truth_match": "T3",
                    "cwe": "CWE-319",
                    "k8s_threat_matrix": "Unencrypted Communication"
                })

    return threats


def _detect_secrets_in_configmaps(configmaps):
    """
    T8: Detect secrets stored in ConfigMaps instead of Secret resources

    Args:
        configmaps: List of ConfigMap dictionaries

    Returns:
        List of threat dictionaries
    """
    threats = []
    secret_keywords = ['password', 'secret', 'token', 'key', 'credential', 'api-key', 'jwt', 'auth']

    for cm in configmaps:
        cm_name = cm.get('name', 'unknown')
        namespace = cm.get('namespace', 'unknown')
        data = cm.get('data', {})

        for key, value in data.items():
            key_lower = key.lower()

            # Check if key name suggests it contains a secret
            if any(keyword in key_lower for keyword in secret_keywords):
                threats.append({
                    "configmap": cm_name,
                    "namespace": namespace,
                    "threat_id": "T08",
                    "category": "Formal (ConfigMap)",
                    "description": f"ConfigMap {cm_name} contains secret '{key}' in plaintext",
                    "severity": "Critical",
                    "evidence": f"Key '{key}' in ConfigMap (should use Secret resource)",
                    "mitigation": "Move to Secret resource, use external secret management (Vault, Sealed Secrets)",
                    "detection_method": "Static Analysis (ConfigMap)",
                    "ground_truth_match": "T8",
                    "cwe": "CWE-798",
                    "k8s_threat_matrix": "Hardcoded Secrets"
                })

    return threats


def _detect_missing_network_policies(namespaces, network_policies):
    """
    T4: Detect namespaces without NetworkPolicies (missing network segmentation)

    Args:
        namespaces: List of namespace metadata dictionaries
        network_policies: List of NetworkPolicy dictionaries

    Returns:
        List of threat dictionaries
    """
    threats = []

    # Build a set of namespaces that have NetworkPolicies
    namespaces_with_policies = set(np.get('namespace') for np in network_policies)

    for ns in namespaces:
        ns_name = ns.get('name')

        # Skip system namespaces
        if ns_name.startswith('kube-') or ns_name in ['default', 'falco', 'metallb-system']:
            continue

        # Check if namespace has NetworkPolicies
        if ns_name not in namespaces_with_policies:
            threats.append({
                "namespace": ns_name,
                "threat_id": "T04",
                "category": "Formal (Network Policy)",
                "description": f"Namespace {ns_name} has no NetworkPolicies (unrestricted network access)",
                "severity": "High",
                "evidence": "No NetworkPolicy resources found in namespace",
                "mitigation": "Implement NetworkPolicies to restrict pod-to-pod and cross-namespace traffic",
                "detection_method": "Static Analysis (Network Policy)",
                "ground_truth_match": "T4",
                "cwe": "CWE-284",
                "k8s_threat_matrix": "Missing Network Segmentation"
            })

    return threats


def _detect_missing_audit_logging(namespaces):
    """
    T7: Detect namespaces with audit logging disabled

    Args:
        namespaces: List of namespace metadata dictionaries

    Returns:
        List of threat dictionaries
    """
    threats = []

    for ns in namespaces:
        ns_name = ns.get('name')
        annotations = ns.get('annotations', {})

        # Check if audit logging is explicitly disabled
        if annotations.get('audit.k8s.io/enabled') == 'false':
            threats.append({
                "namespace": ns_name,
                "threat_id": "T07",
                "category": "Formal (Audit Policy)",
                "description": f"Namespace {ns_name} has audit logging disabled",
                "severity": "Medium",
                "evidence": "audit.k8s.io/enabled: false in namespace annotations",
                "mitigation": "Enable Kubernetes audit policy, deploy audit log aggregation (Falco, etc.)",
                "detection_method": "Static Analysis (Namespace Annotations)",
                "ground_truth_match": "T7",
                "cwe": "CWE-778",
                "k8s_threat_matrix": "Insufficient Logging"
            })

    return threats


def _detect_registry_misconfig(pods, configmaps):
    """
    T5: Detect Docker Registry with no authentication configured

    Args:
        pods: List of pod dictionaries
        configmaps: List of ConfigMap dictionaries

    Returns:
        List of threat dictionaries
    """
    threats = []

    # Find registry pods
    registry_pods = [p for p in pods if 'registry' in p.get('name', '').lower()]

    for pod in registry_pods:
        pod_name = pod.get('name')
        namespace = pod.get('namespace')

        # Check associated ConfigMaps for registry config
        registry_cms = [cm for cm in configmaps
                       if cm.get('namespace') == namespace and 'registry' in cm.get('name', '').lower()]

        for cm in registry_cms:
            config_data = cm.get('data', {})
            config_yml = config_data.get('config.yml', '')

            # Check if auth section is commented out or missing
            if 'auth:' in config_yml:
                # Check if auth section is commented out (more # before auth: than actual auth config)
                lines = config_yml.split('\n')
                auth_commented = any(line.strip().startswith('#') and 'auth:' in line for line in lines)

                if auth_commented or ('# auth:' in config_yml and 'auth:' not in config_yml.replace('# auth:', '')):
                    threats.append({
                        "pod": pod_name,
                        "namespace": namespace,
                        "configmap": cm.get('name'),
                        "threat_id": "T05",
                        "category": "Formal (ConfigMap)",
                        "description": f"Registry {pod_name} has no authentication configured",
                        "severity": "Critical",
                        "evidence": "Registry auth section commented out in ConfigMap",
                        "mitigation": "Enable htpasswd authentication or use external auth provider",
                        "detection_method": "Static Analysis (ConfigMap)",
                        "ground_truth_match": "T5",
                        "cwe": "CWE-306",
                        "k8s_threat_matrix": "Anonymous Access"
                    })
            elif config_yml and 'auth' not in config_yml.lower():
                # No auth configuration at all
                threats.append({
                    "pod": pod_name,
                    "namespace": namespace,
                    "configmap": cm.get('name'),
                    "threat_id": "T05",
                    "category": "Formal (ConfigMap)",
                    "description": f"Registry {pod_name} has no authentication configured",
                    "severity": "Critical",
                    "evidence": "No auth configuration found in registry ConfigMap",
                    "mitigation": "Enable htpasswd authentication or use external auth provider",
                    "detection_method": "Static Analysis (ConfigMap)",
                    "ground_truth_match": "T5",
                    "cwe": "CWE-306",
                    "k8s_threat_matrix": "Anonymous Access"
                })

    return threats


def _detect_gitea_misconfig(configmaps):
    """
    T9: Detect Gitea with anonymous repository access enabled

    Args:
        configmaps: List of ConfigMap dictionaries

    Returns:
        List of threat dictionaries
    """
    threats = []

    for cm in configmaps:
        cm_name = cm.get('name', '')
        namespace = cm.get('namespace')

        # Look for Gitea ConfigMaps
        if 'gitea' in cm_name.lower():
            data = cm.get('data', {})
            app_ini = data.get('app.ini', '')

            # Check if anonymous access is enabled
            if 'REQUIRE_SIGNIN_VIEW = false' in app_ini or 'REQUIRE_SIGNIN_VIEW=false' in app_ini:
                threats.append({
                    "configmap": cm_name,
                    "namespace": namespace,
                    "threat_id": "T09",
                    "category": "Formal (ConfigMap)",
                    "description": f"Gitea allows anonymous repository access (REQUIRE_SIGNIN_VIEW=false)",
                    "severity": "Medium",
                    "evidence": "REQUIRE_SIGNIN_VIEW = false in Gitea configuration",
                    "mitigation": "Set REQUIRE_SIGNIN_VIEW = true to require authentication",
                    "detection_method": "Static Analysis (ConfigMap)",
                    "ground_truth_match": "T9",
                    "cwe": "CWE-306",
                    "k8s_threat_matrix": "Public Repository Access"
                })

    return threats
