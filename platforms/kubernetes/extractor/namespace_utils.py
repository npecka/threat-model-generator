# namespace_utils.py

from config_loader import v1

SYSTEM_NAMESPACES = {
    "kube-public", "kube-node-lease", "kube-system",
    "cattle-fleet-local-system", "cattle-fleet-system", "cattle-provisioning-capi-system",
    "cattle-system", "cattle-provisioning-capi-system", "cattle-ui-plugin-system", "fleet-default", "longhorn-system",
    "default", "cert-manager", 
    "dashy-system", "falco", "logging-system", "metallb-system", "cilium-secrets", 
    "gitea-system", "harbor-system", "jenkins-system", "traefik-system",
    "mealie", "elastic-stack", "elastic-system"
}

def get_user_only_namespaces():
    all_namespaces = v1.list_namespace().items
    return [ns.metadata.name for ns in all_namespaces if ns.metadata.name not in SYSTEM_NAMESPACES]
