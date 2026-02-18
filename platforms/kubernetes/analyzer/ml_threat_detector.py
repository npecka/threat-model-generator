#!/usr/bin/env python3
"""
ML-Specific Threat Detector

Detects ML supply chain threats (T11-T17) that general-purpose tools
like Trivy/Kubescape cannot identify. These are application-level,
domain-specific threats.

Infrastructure threats (T01-T10) are handled by Trivy/Kubescape.
"""


def detect_ml_threats(pods, services=None, configmaps=None):
    """
    Detect ML-specific threats in the supply chain.

    Args:
        pods: List of pod dictionaries
        services: Dict of service configurations (optional)
        configmaps: List of ConfigMap dictionaries (optional)

    Returns:
        List of ML threat dictionaries
    """
    threats = []

    services = services or {}
    configmaps = configmaps or []

    # Convert services list to dict if needed (for compatibility)
    if isinstance(services, list):
        services = {svc.get('name', f'service-{i}'): svc for i, svc in enumerate(services)}

    # T11: Unauthorized Model Access (MLflow)
    threats.extend(_detect_mlflow_no_auth(pods, configmaps))

    # T12: Training Data Poisoning
    threats.extend(_detect_training_data_access(pods, configmaps))

    # T13: Model Theft via API
    threats.extend(_detect_model_theft_risk(pods, services))

    # T14: Unencrypted Model Transfer
    threats.extend(_detect_unencrypted_ml_transfer(services))

    # T15: Cross-Zone ML Deployment RBAC
    # (Handled by Trivy/Kubescape RBAC analysis + correlation)

    # T16: Missing Model Provenance
    threats.extend(_detect_missing_provenance(configmaps))

    # T17: Exposed Model Metadata
    threats.extend(_detect_exposed_metadata(pods, configmaps))

    return threats


# =========================================================================
# T11: Unauthorized Model Access
# =========================================================================

def _detect_mlflow_no_auth(pods, configmaps):
    """
    T11: Detect MLflow server running without authentication.

    MLflow by default has no authentication, allowing anyone with network
    access to upload/download models.
    """
    threats = []

    # Check for MLflow pods
    mlflow_pods = [p for p in pods if 'mlflow' in p['name'].lower()]

    if not mlflow_pods:
        return threats

    # Check if authentication is configured in ConfigMaps
    mlflow_configs = [
        cm for cm in configmaps
        if 'mlflow' in cm.get('metadata', {}).get('name', '').lower()
    ]

    has_auth = False
    for config in mlflow_configs:
        data = config.get('data', {})
        # Check for auth-related config
        if any(key for key in data.keys() if 'auth' in key.lower()):
            has_auth = True
            break

    if not has_auth:
        for pod in mlflow_pods:
            threats.append({
                "pod": pod['name'],
                "namespace": pod['namespace'],
                "threat_id": "ML-AUTH001",
                "category": "ML Supply Chain",
                "description": f"MLflow server {pod['name']} has no authentication configured",
                "severity": "High",
                "evidence": "No authentication configuration found in ConfigMaps",
                "mitigation": "Enable MLflow authentication (basic auth or SSO)",
                "detection_method": "Static Analysis (ML Config)",
                "ground_truth_match": "T11",
                "cwe": "CWE-306",
                "ml_threat": "Unauthorized Model Access"
            })

    return threats


# =========================================================================
# T12: Training Data Poisoning
# =========================================================================

def _detect_training_data_access(pods, configmaps):
    """
    T12: Detect overly permissive access to training data.

    If CI/CD systems (Jenkins) have write access to training data,
    attackers could poison the dataset.
    """
    threats = []

    # Check for training data pods/jobs
    training_pods = [
        p for p in pods
        if any(keyword in p['name'].lower() for keyword in ['training', 'data-init', 'dataset'])
    ]

    # Check for Jenkins/CI pods in same namespace
    jenkins_pods = [p for p in pods if 'jenkins' in p['name'].lower()]

    for training_pod in training_pods:
        training_ns = training_pod['namespace']

        # Check if Jenkins is in a different zone but could access training data
        for jenkins_pod in jenkins_pods:
            jenkins_ns = jenkins_pod['namespace']

            # If Jenkins is in cicd-zone and training data is in dev-zone,
            # this is a potential poisoning vector
            if jenkins_ns != training_ns:
                threats.append({
                    "pod": training_pod['name'],
                    "namespace": training_ns,
                    "threat_id": "ML-POISON001",
                    "category": "ML Supply Chain",
                    "description": f"Training data {training_pod['name']} accessible from CI/CD zone",
                    "severity": "High",
                    "evidence": f"Jenkins in {jenkins_ns} may have access to training data in {training_ns}",
                    "mitigation": "Restrict training data write access to authorized data science team only",
                    "detection_method": "Static Analysis (ML Architecture)",
                    "ground_truth_match": "T12",
                    "cwe": "CWE-732",
                    "ml_threat": "Training Data Poisoning"
                })

    return threats


# =========================================================================
# T13: Model Theft via API
# =========================================================================

def _detect_model_theft_risk(pods, services):
    """
    T13: Detect ML inference APIs without rate limiting.

    Attackers can steal models by making many inference requests
    and reconstructing the model.
    """
    threats = []

    # Find ML inference services
    inference_services = {
        name: svc for name, svc in services.items()
        if 'inference' in name.lower() or 'predict' in name.lower()
    }

    if not inference_services:
        return threats

    # Check for rate limiting configuration
    # (This is a heuristic - would need Ingress/Gateway configs for full check)
    for svc_name, svc_data in inference_services.items():
        namespace = svc_data.get('namespace', 'unknown')

        # If service is exposed (LoadBalancer/NodePort) without rate limiting
        svc_type = svc_data.get('type', 'ClusterIP')

        if svc_type in ['LoadBalancer', 'NodePort']:
            threats.append({
                "service": svc_name,
                "namespace": namespace,
                "threat_id": "ML-THEFT001",
                "category": "ML Supply Chain",
                "description": f"ML inference API {svc_name} exposed without apparent rate limiting",
                "severity": "Medium",
                "evidence": f"Service type {svc_type} (externally accessible)",
                "mitigation": "Implement rate limiting, authentication, and request throttling",
                "detection_method": "Static Analysis (ML Service)",
                "ground_truth_match": "T13",
                "cwe": "CWE-770",
                "ml_threat": "Model Theft via API"
            })

    return threats


# =========================================================================
# T14: Unencrypted Model Transfer
# =========================================================================

def _detect_unencrypted_ml_transfer(services):
    """
    T14: Detect ML services using unencrypted HTTP.

    Models transferred over HTTP can be intercepted.
    """
    threats = []
    http_ports = [80, 8080, 5000, 8000]

    # Find ML-related services
    ml_services = {
        name: svc for name, svc in services.items()
        if any(keyword in name.lower() for keyword in ['mlflow', 'inference', 'model', 'ml-'])
    }

    for svc_name, svc_data in ml_services.items():
        namespace = svc_data.get('namespace', 'unknown')
        ports = svc_data.get('ports', [])

        for port_info in ports:
            port_num = port_info.get('port')

            if port_num in http_ports:
                threats.append({
                    "service": svc_name,
                    "namespace": namespace,
                    "threat_id": "ML-CRYPTO001",
                    "category": "ML Supply Chain",
                    "description": f"ML service {svc_name} transfers models over unencrypted HTTP",
                    "severity": "High",
                    "evidence": f"Port {port_num} (HTTP) used for model transfer",
                    "mitigation": "Enable TLS/HTTPS for all ML service communications",
                    "detection_method": "Static Analysis (ML Service)",
                    "ground_truth_match": "T14",
                    "cwe": "CWE-319",
                    "ml_threat": "Unencrypted Model Transfer"
                })

    return threats


# =========================================================================
# T16: Missing Model Provenance
# =========================================================================

def _detect_missing_provenance(configmaps):
    """
    T16: Detect ML systems without provenance tracking.

    Models should have metadata about training data, hyperparameters,
    who trained them, when, etc.
    """
    threats = []

    # Look for MLflow or model registry configs
    ml_configs = [
        cm for cm in configmaps
        if any(keyword in cm.get('metadata', {}).get('name', '').lower()
               for keyword in ['mlflow', 'model', 'registry'])
    ]

    for config in ml_configs:
        namespace = config.get('metadata', {}).get('namespace', 'unknown')
        name = config.get('metadata', {}).get('name', 'unknown')
        data = config.get('data', {})

        # Check for provenance-related configuration
        has_provenance = any(
            key for key in data.keys()
            if any(keyword in key.lower() for keyword in ['provenance', 'lineage', 'tracking', 'metadata'])
        )

        if not has_provenance:
            threats.append({
                "configmap": name,
                "namespace": namespace,
                "threat_id": "ML-PROV001",
                "category": "ML Supply Chain",
                "description": f"ML system {name} has no model provenance tracking configured",
                "severity": "Medium",
                "evidence": "No provenance/lineage configuration found",
                "mitigation": "Enable MLflow tracking, DVC, or ML metadata store",
                "detection_method": "Static Analysis (ML Config)",
                "ground_truth_match": "T16",
                "cwe": "CWE-345",
                "ml_threat": "Missing Model Provenance"
            })

    return threats


# =========================================================================
# T17: Exposed Model Metadata
# =========================================================================

def _detect_exposed_metadata(pods, configmaps):
    """
    T17: Detect ML systems exposing debug/metadata endpoints.

    Debug modes can leak model architecture, training details, etc.
    """
    threats = []

    # Check for debug mode in ML pods
    ml_pods = [
        p for p in pods
        if any(keyword in p['name'].lower() for keyword in ['mlflow', 'inference', 'model'])
    ]

    for pod in ml_pods:
        # Check environment variables for debug mode
        # Note: Using containerSecurity since 'containers' is just a list of image names
        containers = pod.get('containerSecurity', [])

        for container in containers:
            # Skip if container is not a dict (e.g., if it's just a string image name)
            if not isinstance(container, dict):
                continue

            env_vars = container.get('env', [])

            for env in env_vars:
                if isinstance(env, dict):
                    name = env.get('name', '').upper()
                    value = str(env.get('value', '')).lower()

                    # Check for debug flags
                    if ('DEBUG' in name or 'DEV' in name) and value in ['true', '1', 'yes']:
                        threats.append({
                            "pod": pod['name'],
                            "namespace": pod['namespace'],
                            "threat_id": "ML-META001",
                            "category": "ML Supply Chain",
                            "description": f"ML service {pod['name']} running in debug mode",
                            "severity": "Medium",
                            "evidence": f"Environment variable {name}={value}",
                            "mitigation": "Disable debug mode in production",
                            "detection_method": "Static Analysis (ML Config)",
                            "ground_truth_match": "T17",
                            "cwe": "CWE-489",
                            "ml_threat": "Exposed Model Metadata"
                        })

    return threats


def get_ml_threat_summary(ml_threats):
    """
    Generate summary of ML-specific threats.

    Args:
        ml_threats: List of ML threat dictionaries

    Returns:
        Dict with threat summary statistics
    """
    total = len(ml_threats)

    severity_counts = {
        'critical_count': sum(1 for t in ml_threats if t.get('severity') == 'Critical'),
        'high_count': sum(1 for t in ml_threats if t.get('severity') == 'High'),
        'medium_count': sum(1 for t in ml_threats if t.get('severity') == 'Medium'),
        'low_count': sum(1 for t in ml_threats if t.get('severity') == 'Low'),
    }

    # Count by ML threat type
    threat_types = {}
    for threat in ml_threats:
        ml_type = threat.get('ml_threat', 'Unknown')
        threat_types[ml_type] = threat_types.get(ml_type, 0) + 1

    return {
        'total': total,
        **severity_counts,
        'by_type': threat_types
    }
