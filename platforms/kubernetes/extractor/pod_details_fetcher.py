# pod_details_fetcher.py

from config_loader import v1

def get_pod_details(user_namespaces, service_to_pod_map):
    """
    Fetch pod details including security context for threat analysis.

    Enhanced to capture security-relevant configurations needed for
    formal threat detection (hostPID, privileged, capabilities, etc.)
    """
    pod_details = []
    all_pods = v1.list_pod_for_all_namespaces().items

    for pod in all_pods:
        if pod.metadata.namespace not in user_namespaces:
            continue

        # Extract pod-level security context
        security_context = {}
        if pod.spec.security_context:
            security_context = {
                "runAsUser": pod.spec.security_context.run_as_user,
                "runAsGroup": pod.spec.security_context.run_as_group,
                "runAsNonRoot": pod.spec.security_context.run_as_non_root,
                "fsGroup": pod.spec.security_context.fs_group,
                "supplementalGroups": pod.spec.security_context.supplemental_groups,
                "seccompProfile": _extract_seccomp_profile(pod.spec.security_context)
            }

        # Extract container-level security contexts
        container_security = []
        for container in pod.spec.containers:
            container_sec = {
                "name": container.name,
                "image": container.image,
                "privileged": False,
                "readOnlyRootFilesystem": False,
                "allowPrivilegeEscalation": True,  # Default if not specified
                "capabilities": {"add": [], "drop": []}
            }

            if container.security_context:
                sc = container.security_context
                container_sec.update({
                    "privileged": sc.privileged if sc.privileged is not None else False,
                    "readOnlyRootFilesystem": sc.read_only_root_filesystem if sc.read_only_root_filesystem is not None else False,
                    "allowPrivilegeEscalation": sc.allow_privilege_escalation if sc.allow_privilege_escalation is not None else True,
                    "runAsUser": sc.run_as_user,
                    "runAsGroup": sc.run_as_group,
                    "runAsNonRoot": sc.run_as_non_root
                })

                # Extract capabilities
                if sc.capabilities:
                    container_sec["capabilities"] = {
                        "add": list(sc.capabilities.add) if sc.capabilities.add else [],
                        "drop": list(sc.capabilities.drop) if sc.capabilities.drop else []
                    }

            container_security.append(container_sec)

        # Build comprehensive pod info
        pod_info = {
            "name": pod.metadata.name,
            "namespace": pod.metadata.namespace,
            "node": pod.spec.node_name,
            "ip": pod.status.pod_ip,
            "labels": pod.metadata.labels,
            "annotations": pod.metadata.annotations,
            "volumes": [v.name for v in pod.spec.volumes or []],
            "containers": [c.image for c in pod.spec.containers],
            # ENHANCED: Security-relevant fields
            "serviceAccount": pod.spec.service_account_name or "default",
            "hostPID": pod.spec.host_pid if pod.spec.host_pid is not None else False,
            "hostNetwork": pod.spec.host_network if pod.spec.host_network is not None else False,
            "hostIPC": pod.spec.host_ipc if pod.spec.host_ipc is not None else False,
            "securityContext": security_context,
            "containerSecurity": container_security,
            "associated_services": []
        }

        for svc, details in service_to_pod_map.items():
            if pod.metadata.name in details["pods"]:
                pod_info["associated_services"].append({
                    "service": svc,
                    "ip": details["ip"],
                    "ports": details["ports"],
                    "namespace": details["namespace"]
                })

        pod_details.append(pod_info)
    return pod_details


def _extract_seccomp_profile(security_context):
    """Extract seccomp profile information if available"""
    if hasattr(security_context, 'seccomp_profile') and security_context.seccomp_profile:
        return {
            "type": security_context.seccomp_profile.type,
            "localhostProfile": security_context.seccomp_profile.localhost_profile
        }
    return None
