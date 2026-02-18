# rbac_fetcher.py

from config_loader import rback_v1

def get_rbac_summary():
    """
    Fetch RBAC bindings with actual permissions for threat analysis.

    Enhanced to capture role rules (verbs, resources) needed for
    formal threat detection of over-privileged service accounts.
    """
    summary = []

    # Build role lookup map with actual permissions
    roles_map = {}

    # Fetch all ClusterRoles with their rules
    print("Fetching ClusterRoles...")
    try:
        for role in rback_v1.list_cluster_role().items:
            role_key = ("ClusterRole", role.metadata.name)
            roles_map[role_key] = {
                "rules": [
                    {
                        "apiGroups": list(rule.api_groups) if rule.api_groups else [""],
                        "resources": list(rule.resources) if rule.resources else [],
                        "verbs": list(rule.verbs) if rule.verbs else [],
                        "resourceNames": list(rule.resource_names) if rule.resource_names else []
                    }
                    for rule in (role.rules or [])
                ]
            }
    except Exception as e:
        print(f"Error fetching ClusterRoles: {e}")

    # Fetch all Roles (namespaced) with their rules
    print("Fetching Roles...")
    try:
        for role in rback_v1.list_role_for_all_namespaces().items:
            role_key = ("Role", role.metadata.name, role.metadata.namespace)
            roles_map[role_key] = {
                "rules": [
                    {
                        "apiGroups": list(rule.api_groups) if rule.api_groups else [""],
                        "resources": list(rule.resources) if rule.resources else [],
                        "verbs": list(rule.verbs) if rule.verbs else [],
                        "resourceNames": list(rule.resource_names) if rule.resource_names else []
                    }
                    for rule in (role.rules or [])
                ]
            }
    except Exception as e:
        print(f"Error fetching Roles: {e}")

    # Fetch bindings and enrich with permission details
    bindings = rback_v1.list_cluster_role_binding().items + rback_v1.list_role_binding_for_all_namespaces().items

    for binding in bindings:
        role_ref = binding.role_ref
        subjects = binding.subjects or []
        namespace = getattr(binding.metadata, 'namespace', 'cluster')

        # Lookup the actual role permissions
        if role_ref.kind == "ClusterRole":
            role_key = ("ClusterRole", role_ref.name)
        else:  # Role
            role_key = ("Role", role_ref.name, namespace)

        permissions = roles_map.get(role_key, {"rules": []})["rules"]

        summary.append({
            "binding": binding.metadata.name,
            "namespace": namespace,
            "role": role_ref.name,
            "role_kind": role_ref.kind,
            "subjects": [{"kind": s.kind, "name": s.name, "namespace": getattr(s, 'namespace', None)} for s in subjects],
            "permissions": permissions  # ENHANCED: Include actual permissions
        })

    return summary
