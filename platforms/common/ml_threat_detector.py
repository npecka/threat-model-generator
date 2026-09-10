#!/usr/bin/env python3
"""
Platform-Agnostic ML Threat Detector

Detects ML supply chain threats (T11-T17) across deployment platforms:
- Bare-metal: Docker Compose configurations
- Kubernetes: Pod specs and ConfigMaps
- AWS: EC2 user-data and docker-compose files

The detection logic is SEMANTIC, not product-specific. It identifies:
- Missing authentication (any ML service)
- Missing integrity checks (any model storage)
- Missing rate limiting (any inference API)
- Unencrypted transfer (any ML protocol)
- Cross-zone RBAC (any deployment boundary)
- Missing provenance (any model registry)
- Debug endpoints (any ML service)
"""


def detect_ml_threats(platform, data):
    """
    Detect ML-specific threats (T11-T17) in a platform-agnostic way.

    Args:
        platform: 'kubernetes', 'bare-metal', or 'aws'
        data: Platform-specific data structure containing:
            - services/containers/pods
            - configs (ConfigMaps, docker-compose, user-data)
            - network information

    Returns:
        List of ML threat dictionaries
    """
    threats = []

    # Normalize data to common format
    normalized = _normalize_platform_data(platform, data)

    # T11: Unauthorized Model Access
    threats.extend(_detect_unauthorized_model_access(normalized))

    # T12: Training Data Poisoning / Model Integrity
    threats.extend(_detect_model_integrity_issues(normalized))

    # T13: Model Theft via API
    threats.extend(_detect_model_theft_risk(normalized))

    # T14: Unencrypted Model Transfer
    threats.extend(_detect_unencrypted_ml_transfer(normalized))

    # T15: Cross-Zone ML Deployment RBAC (handled by platform-specific RBAC detector)

    # T16: Missing Model Provenance
    threats.extend(_detect_missing_provenance(normalized))

    # T17: Exposed Model Metadata
    threats.extend(_detect_exposed_metadata(normalized))

    return threats


def _normalize_platform_data(platform, data):
    """
    Normalize platform-specific data to common format for threat detection.

    Returns dict with:
        - ml_services: List of ML service instances
        - configs: List of configuration data
        - platform: Platform name
    """
    if platform == 'kubernetes':
        return {
            'platform': 'kubernetes',
            'ml_services': _extract_k8s_ml_services(data.get('pods', [])),
            'configs': data.get('configmaps', []),
            'services': data.get('services', {}),
        }
    elif platform == 'bare-metal':
        return {
            'platform': 'bare-metal',
            'ml_services': _extract_docker_ml_services(data.get('vms', [])),
            'configs': data.get('config_files', []),
            'services': _extract_docker_services(data.get('vms', [])),
        }
    elif platform == 'aws':
        return {
            'platform': 'aws',
            'ml_services': _extract_ec2_ml_services(data.get('instances', [])),
            'configs': _extract_ec2_configs(data.get('instances', [])),
            'services': _extract_ec2_services(data.get('instances', [])),
        }
    else:
        raise ValueError(f"Unknown platform: {platform}")


def _extract_k8s_ml_services(pods):
    """Extract ML services from Kubernetes pods"""
    ml_keywords = ['mlflow', 'ml-inference', 'ml-', 'ai-assistant', 'llm', 'ollama', 'model', 'inference']
    ml_services = []

    for pod in pods:
        if any(kw in pod.get('name', '').lower() for kw in ml_keywords):
            ml_services.append({
                'name': pod['name'],
                'namespace': pod.get('namespace', 'default'),
                'type': 'pod',
                'volumes': pod.get('volumes', []),
                'platform_data': pod
            })

    return ml_services


def _extract_docker_ml_services(vms):
    """Extract ML services from Docker containers on VMs"""
    ml_keywords = ['mlflow', 'ml-inference', 'ml-', 'ai-assistant', 'llm', 'ollama', 'model', 'inference']
    ml_services = []

    for vm in vms:
        for container in vm.get('docker_containers', []):
            if any(kw in container.get('name', '').lower() for kw in ml_keywords):
                ml_services.append({
                    'name': container['name'],
                    'namespace': vm.get('zone', 'unknown'),
                    'type': 'container',
                    'volumes': container.get('volumes', []),
                    'platform_data': container
                })

    return ml_services


def _extract_ec2_ml_services(instances):
    """Extract ML services from EC2 instances"""
    ml_keywords = ['mlflow', 'ml-inference', 'ml-', 'ai-assistant', 'llm', 'ollama', 'model', 'inference']
    ml_services = []

    for instance in instances:
        user_data = instance.get('user_data', '')
        # Parse docker-compose from user-data
        if 'mlflow' in user_data.lower() or 'ml-' in user_data.lower():
            # Extract service names from docker-compose
            for keyword in ml_keywords:
                if keyword in user_data.lower():
                    ml_services.append({
                        'name': f"{instance.get('name', 'unknown')}-{keyword}",
                        'namespace': instance.get('zone', 'unknown'),
                        'type': 'ec2-container',
                        'platform_data': instance
                    })
                    break

    return ml_services


def _extract_docker_services(vms):
    """Extract service information from Docker containers"""
    services = {}
    for vm in vms:
        for container in vm.get('docker_containers', []):
            services[container.get('name', 'unknown')] = {
                'name': container['name'],
                'ports': container.get('ports', []),
                'namespace': vm.get('zone', 'unknown')
            }
    return services


def _extract_ec2_services(instances):
    """Extract service information from EC2 instances"""
    services = {}
    for instance in instances:
        services[instance.get('name', 'unknown')] = {
            'name': instance['name'],
            'ports': instance.get('exposed_ports', []),
            'namespace': instance.get('zone', 'unknown')
        }
    return services


def _extract_ec2_configs(instances):
    """Extract configuration data from EC2 user-data scripts"""
    configs = []
    for instance in instances:
        user_data = instance.get('user_data', '')
        if user_data:
            configs.append({
                'name': f"{instance.get('name', 'unknown')}-user-data",
                'namespace': instance.get('zone', 'unknown'),
                'data': {'user_data': user_data}
            })
    return configs


# =========================================================================
# T11: Unauthorized Model Access
# =========================================================================

def _detect_unauthorized_model_access(normalized):
    """
    T11: Detect ML services running without authentication.

    SEMANTIC DETECTION (platform-agnostic):
    - Look for ML services (MLflow, model registry, LLM API)
    - Check if authentication is configured
    - Check if auth values are actually secure (not "none", "insecure-*")
    """
    threats = []
    ml_services = normalized['ml_services']
    configs = normalized['configs']

    if not ml_services:
        return threats

    # Check each ML service for authentication
    for service in ml_services:
        has_auth = False

        # Check associated configs for auth settings
        service_ns = service['namespace']
        for config in configs:
            if config.get('namespace') == service_ns:
                config_data = config.get('data', {})

                # Check for authentication configuration
                for key, value in config_data.items():
                    if not isinstance(value, str):
                        continue

                    # Pattern 1: Explicit auth keys
                    if 'auth' in key.lower():
                        # Check if value is actually secure
                        value_lower = value.lower()
                        if value_lower and value_lower not in ['none', 'false', '0', 'off', 'disabled']:
                            # Check it's not an insecure placeholder
                            if not any(word in value_lower for word in ['insecure', 'test', 'demo', 'example', '12345']):
                                has_auth = True
                                break

                    # Pattern 2: API keys in config
                    if 'api' in key.lower() and 'key' in key.lower():
                        if value and not any(word in value.lower() for word in ['insecure', 'test', 'demo', 'example', '12345']):
                            has_auth = True
                            break

        if not has_auth:
            threats.append({
                'threat_id': 'T11',
                'category': 'ML Supply Chain',
                'description': f"ML service {service['name']} has no authentication configured",
                'severity': 'High',
                'component': service['name'],
                'namespace': service_ns,
                'evidence': 'No authentication configuration found in associated configs',
                'mitigation': 'Enable authentication (basic auth, API keys, or SSO)',
                'detection_method': 'Static Analysis (ML Config)',
                'platform': normalized['platform']
            })

    return threats


# =========================================================================
# T12: Training Data Poisoning / Model Integrity
# =========================================================================

def _detect_model_integrity_issues(normalized):
    """
    T12: Detect model/data integrity issues.

    SEMANTIC DETECTION:
    - Check for non-persistent model storage (emptyDir, tmpfs, no volumes)
    - Check for training data accessible from CI/CD
    """
    threats = []
    ml_services = normalized['ml_services']

    for service in ml_services:
        # Check for ephemeral storage (no persistence = no integrity tracking)
        volumes = service.get('volumes', [])

        # Pattern: Model storage without persistence
        has_model_volume = any(
            'model' in str(vol).lower() for vol in volumes
        )

        if has_model_volume:
            # Check if it's persistent or ephemeral
            # On K8s: emptyDir is ephemeral
            # On Docker: tmpfs or no named volume is ephemeral
            platform_data = service.get('platform_data', {})

            # For K8s, check annotations for emptyDir
            if normalized['platform'] == 'kubernetes':
                annotations = platform_data.get('annotations', {})
                last_config = annotations.get('kubectl.kubernetes.io/last-applied-configuration', '')
                if 'emptyDir' in last_config:
                    threats.append({
                        'threat_id': 'T12',
                        'category': 'ML Supply Chain',
                        'description': f"ML service {service['name']} uses non-persistent storage for models",
                        'severity': 'Medium',
                        'component': service['name'],
                        'namespace': service['namespace'],
                        'evidence': 'emptyDir volume provides no persistence or integrity verification',
                        'mitigation': 'Use PersistentVolume with model versioning and integrity checksums',
                        'detection_method': 'Static Analysis (Pod Spec)',
                        'platform': normalized['platform']
                    })

            # For Docker/AWS, check for named volumes
            elif normalized['platform'] in ['bare-metal', 'aws']:
                # Check if volumes are named (persistent) or anonymous (ephemeral)
                volume_names = [str(v) for v in volumes if isinstance(v, str)]
                if any('tmpfs' in v or v.startswith('/tmp') for v in volume_names):
                    threats.append({
                        'threat_id': 'T12',
                        'category': 'ML Supply Chain',
                        'description': f"ML service {service['name']} uses non-persistent storage for models",
                        'severity': 'Medium',
                        'component': service['name'],
                        'namespace': service['namespace'],
                        'evidence': 'Temporary/ephemeral volume provides no persistence',
                        'mitigation': 'Use named Docker volumes with model versioning',
                        'detection_method': 'Static Analysis (Container Config)',
                        'platform': normalized['platform']
                    })

    return threats


# =========================================================================
# T13: Model Theft via API
# =========================================================================

def _detect_model_theft_risk(normalized):
    """
    T13: Detect ML inference APIs without rate limiting.

    SEMANTIC DETECTION:
    - Find ML inference services
    - Check if rate limiting is configured in code/config
    """
    threats = []
    services = normalized.get('services', {})
    configs = normalized['configs']

    ml_inference_keywords = ['inference', 'predict', 'ml-api', 'ai-assistant', 'llm']

    for svc_name, svc_data in services.items():
        if any(kw in svc_name.lower() for kw in ml_inference_keywords):
            namespace = svc_data.get('namespace', 'unknown')

            # Check configs for rate limiting
            has_rate_limiting = False
            for config in configs:
                if config.get('namespace') == namespace:
                    config_data = config.get('data', {})
                    for value in config_data.values():
                        if isinstance(value, str):
                            if any(pattern in value.lower() for pattern in ['rate_limit', 'ratelimit', 'throttl', 'limiter']):
                                has_rate_limiting = True
                                break

            if not has_rate_limiting:
                threats.append({
                    'threat_id': 'T13',
                    'category': 'ML Supply Chain',
                    'description': f"ML inference API {svc_name} lacks rate limiting protection",
                    'severity': 'Medium',
                    'component': svc_name,
                    'namespace': namespace,
                    'evidence': 'No rate limiting configuration found in application code',
                    'mitigation': 'Implement rate limiting, authentication, and request throttling',
                    'detection_method': 'Static Analysis (ML Service)',
                    'platform': normalized['platform']
                })

    return threats


# =========================================================================
# T14: Unencrypted Model Transfer
# =========================================================================

def _detect_unencrypted_ml_transfer(normalized):
    """
    T14: Detect ML services using unencrypted HTTP.

    SEMANTIC DETECTION:
    - Find ML services
    - Check if they use HTTP ports (not HTTPS)
    """
    threats = []
    services = normalized.get('services', {})
    http_ports = [80, 8080, 5000, 8000, 11434]  # Common HTTP ports + Ollama

    ml_keywords = ['mlflow', 'inference', 'model', 'ml-', 'ai-assistant', 'llm', 'ollama']

    for svc_name, svc_data in services.items():
        if any(kw in svc_name.lower() for kw in ml_keywords):
            namespace = svc_data.get('namespace', 'unknown')
            ports = svc_data.get('ports', [])

            for port in ports:
                port_num = port if isinstance(port, int) else port.get('port', 0)
                if port_num in http_ports:
                    threats.append({
                        'threat_id': 'T14',
                        'category': 'ML Supply Chain',
                        'description': f"ML service {svc_name} transfers models over unencrypted HTTP",
                        'severity': 'High',
                        'component': svc_name,
                        'namespace': namespace,
                        'evidence': f"Port {port_num} (HTTP) used for model transfer",
                        'mitigation': 'Enable TLS/HTTPS for all ML service communications',
                        'detection_method': 'Static Analysis (ML Service)',
                        'platform': normalized['platform']
                    })

    return threats


# =========================================================================
# T16: Missing Model Provenance
# =========================================================================

def _detect_missing_provenance(normalized):
    """
    T16: Detect ML systems without provenance tracking.

    SEMANTIC DETECTION:
    - Find model registry configs
    - Check for filesystem backends (no versioning enforcement)
    - Check for insecure model downloads
    """
    threats = []
    configs = normalized['configs']

    for config in configs:
        config_name = config.get('name', '')
        namespace = config.get('namespace', 'unknown')
        config_data = config.get('data', {})

        # Pattern 1: Filesystem backend (MLflow, model registry)
        backend_uri = config_data.get('BACKEND_STORE_URI', '')
        if 'file://' in backend_uri or backend_uri.startswith('/'):
            threats.append({
                'threat_id': 'T16',
                'category': 'ML Supply Chain',
                'description': f"Model registry {config_name} uses filesystem backend without versioning enforcement",
                'severity': 'Medium',
                'component': config_name,
                'namespace': namespace,
                'evidence': f"BACKEND_STORE_URI={backend_uri} (filesystem, not database)",
                'mitigation': 'Use PostgreSQL/MySQL backend with proper versioning',
                'detection_method': 'Static Analysis (ML Config)',
                'platform': normalized['platform']
            })

        # Pattern 2: Insecure model downloads (HTTP, no signature verification)
        for key, value in config_data.items():
            if isinstance(value, str) and 'model' in key.lower() and 'url' in key.lower():
                if value.startswith('http://'):
                    threats.append({
                        'threat_id': 'T16',
                        'category': 'ML Supply Chain',
                        'description': f"ML service {config_name} downloads models over HTTP without integrity verification",
                        'severity': 'Medium',
                        'component': config_name,
                        'namespace': namespace,
                        'evidence': f"{key}={value} (HTTP, no signature verification)",
                        'mitigation': 'Use HTTPS for model downloads and verify signatures',
                        'detection_method': 'Static Analysis (ML Config)',
                        'platform': normalized['platform']
                    })

    return threats


# =========================================================================
# T17: Exposed Model Metadata
# =========================================================================

def _detect_exposed_metadata(normalized):
    """
    T17: Detect ML systems exposing debug/metadata endpoints.

    SEMANTIC DETECTION:
    - Find ML service configs
    - Check for debug mode enabled
    - Check for prompt/request logging
    """
    threats = []
    configs = normalized['configs']

    for config in configs:
        config_name = config.get('name', '')
        namespace = config.get('namespace', 'unknown')
        config_data = config.get('data', {})

        # Check for debug-related settings
        for key, value in config_data.items():
            if not isinstance(value, str):
                continue

            # Pattern 1: Debug mode enabled
            debug_keys = ['DEBUG_MODE', 'DEBUG', 'ENABLE_DEBUG', 'LOG_PROMPTS', 'LOG_REQUESTS', 'ENABLE_MODEL_INFO']
            if key in debug_keys and value.lower() in ['true', '1', 'yes', 'enabled']:
                threats.append({
                    'threat_id': 'T17',
                    'category': 'ML Supply Chain',
                    'description': f"ML service {config_name} exposes debug/metadata endpoints",
                    'severity': 'Medium',
                    'component': config_name,
                    'namespace': namespace,
                    'evidence': f"{key}={value} enables debug/logging in production",
                    'mitigation': 'Disable debug endpoints and prompt logging in production',
                    'detection_method': 'Static Analysis (ML Config)',
                    'platform': normalized['platform']
                })
                break

            # Pattern 2: Debug endpoints in code
            debug_patterns = ['/debug', 'debug_info', 'model-info', '@app.route("/debug']
            if any(pattern in value for pattern in debug_patterns):
                threats.append({
                    'threat_id': 'T17',
                    'category': 'ML Supply Chain',
                    'description': f"ML service {config_name} exposes debug/metadata endpoints",
                    'severity': 'Medium',
                    'component': config_name,
                    'namespace': namespace,
                    'evidence': 'Debug endpoints found in application code',
                    'mitigation': 'Remove debug endpoints from production deployments',
                    'detection_method': 'Static Analysis (ML Config)',
                    'platform': normalized['platform']
                })
                break

    return threats
