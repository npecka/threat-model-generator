# service_pod_mapper.py

from config_loader import v1

def get_service_to_pod_map(user_namespaces):
    services = [svc for svc in v1.list_service_for_all_namespaces().items if svc.metadata.namespace in user_namespaces]
    service_to_pod_map = {}

    for svc in services:
        selector = svc.spec.selector or {}
        if not selector:
            continue
        pods = v1.list_namespaced_pod(svc.metadata.namespace).items
        matched = [
            pod.metadata.name 
            for pod in pods 
            if all(
                item in (pod.metadata.labels or {}).items() 
                for item in selector.items()
            )
        ]
        service_to_pod_map[svc.metadata.name] = {
            "ip": svc.spec.cluster_ip,
            "type": svc.spec.type,
            "ports": [{"port": p.port, "protocol": p.protocol, "targetPort": p.target_port} for p in svc.spec.ports],
            "pods": matched,
            "namespace": svc.metadata.namespace
        }
    return service_to_pod_map
