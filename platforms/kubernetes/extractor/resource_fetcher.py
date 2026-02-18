# resource_fetcher.py
"""
Fetches additional Kubernetes resources needed for threat detection:
- ConfigMaps (for T5, T8, T9 detection)
- NetworkPolicies (for T4 detection)
- Namespace metadata with annotations (for T7 detection)
"""

from config_loader import v1, networking_v1

def get_configmaps(user_namespaces):
    """
    Fetch all ConfigMaps from user namespaces.

    Args:
        user_namespaces: List of namespace names to query

    Returns:
        List of ConfigMap dictionaries with name, namespace, and data
    """
    configmaps = []

    for namespace in user_namespaces:
        try:
            cm_list = v1.list_namespaced_config_map(namespace)
            for cm in cm_list.items:
                configmaps.append({
                    "name": cm.metadata.name,
                    "namespace": cm.metadata.namespace,
                    "data": cm.data or {},
                    "labels": cm.metadata.labels or {}
                })
        except Exception as e:
            print(f"Warning: Could not fetch ConfigMaps from {namespace}: {e}")

    return configmaps


def get_network_policies(user_namespaces):
    """
    Fetch all NetworkPolicies from user namespaces.

    Args:
        user_namespaces: List of namespace names to query

    Returns:
        List of NetworkPolicy dictionaries
    """
    network_policies = []

    for namespace in user_namespaces:
        try:
            netpol_list = networking_v1.list_namespaced_network_policy(namespace)
            for netpol in netpol_list.items:
                network_policies.append({
                    "name": netpol.metadata.name,
                    "namespace": netpol.metadata.namespace,
                    "pod_selector": netpol.spec.pod_selector.match_labels if netpol.spec.pod_selector else {},
                    "policy_types": netpol.spec.policy_types or [],
                    "ingress": len(netpol.spec.ingress or []),
                    "egress": len(netpol.spec.egress or [])
                })
        except Exception as e:
            print(f"Warning: Could not fetch NetworkPolicies from {namespace}: {e}")

    return network_policies


def get_namespace_metadata(user_namespaces):
    """
    Fetch namespace objects with full metadata including annotations.

    Args:
        user_namespaces: List of namespace names to query

    Returns:
        List of namespace dictionaries with annotations
    """
    namespaces = []

    for ns_name in user_namespaces:
        try:
            ns = v1.read_namespace(ns_name)
            namespaces.append({
                "name": ns.metadata.name,
                "labels": ns.metadata.labels or {},
                "annotations": ns.metadata.annotations or {},
                "creation_timestamp": str(ns.metadata.creation_timestamp) if ns.metadata.creation_timestamp else None
            })
        except Exception as e:
            print(f"Warning: Could not fetch metadata for namespace {ns_name}: {e}")

    return namespaces
