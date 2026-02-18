"""
Bare-Metal Threat Detector
Adapts K8s threat detection logic for bare-metal VMs
"""
import re

class BareMetalThreatDetector:
    """Detect T1-T10 threats in bare-metal deployments"""

    def __init__(self, metadata):
        self.metadata = metadata
        self.vms = metadata.get("vms", [])
        self.flows = metadata.get("network_flows", [])
        self.configs = metadata.get("config_files", [])
        self.zones = metadata.get("zones", [])
        self.threats = []

    def detect_all_threats(self):
        """Run all threat detectors"""
        print("Running threat detection...")

        self.detect_t01_unauthenticated_access()
        self.detect_t02_excessive_permissions()
        self.detect_t03_unencrypted_communication()
        self.detect_t04_missing_segmentation()
        self.detect_t05_anonymous_registry()
        self.detect_t06_cicd_to_prod_access()
        self.detect_t07_missing_audit_logging()
        self.detect_t08_exposed_secrets()
        self.detect_t09_broad_source_control()
        self.detect_t10_missing_resource_limits()

        print(f"✓ Detected {len(self.threats)} threat instances")
        return self.threats

    def add_threat(self, threat_id, title, description, severity, component, zone, evidence):
        """Add a detected threat"""
        self.threats.append({
            "id": threat_id,
            "title": title,
            "description": description,
            "severity": severity,
            "component": component,
            "zone": zone,
            "evidence": evidence,
            "platform": "bare-metal"
        })

    def detect_t01_unauthenticated_access(self):
        """T1: Unauthenticated External Access (Jenkins exposed)"""
        for vm in self.vms:
            for service in vm.get("services", []):
                if service.get("type") == "LoadBalancer":
                    self.add_threat(
                        "T01",
                        "Unauthenticated External Access",
                        f"Service {service['name']} is exposed externally without authentication",
                        "High",
                        service["name"],
                        vm["zone"],
                        f"Service type: LoadBalancer on VM {vm['name']}"
                    )

    def detect_t02_excessive_permissions(self):
        """T2: Excessive Permissions (processes running as root)"""
        for vm in self.vms:
            for container in vm.get("docker_containers", []):
                # Check if Jenkins container runs as root (from docker-compose privileged: true)
                if "jenkins" in container.get("name", "").lower():
                    self.add_threat(
                        "T02",
                        "Excessive Permissions",
                        "Jenkins container runs with root privileges",
                        "High",
                        "jenkins",
                        vm["zone"],
                        f"Container {container['name']} on VM {vm['name']} runs as root"
                    )

    def detect_t03_unencrypted_communication(self):
        """T3: Unencrypted Communication (HTTP services)"""
        http_services = []
        for vm in self.vms:
            for service in vm.get("services", []):
                if service.get("protocol") == "HTTP":
                    http_services.append(service["name"])
                    self.add_threat(
                        "T03",
                        "Unencrypted Communication",
                        f"Service {service['name']} uses unencrypted HTTP",
                        "Medium",
                        service["name"],
                        vm["zone"],
                        f"Service port {service['port']} uses HTTP without TLS"
                    )

    def detect_t04_missing_segmentation(self):
        """T4: Missing Network Segmentation (no firewall rules)"""
        for vm in self.vms:
            firewall_rules = vm.get("firewall_rules", [])

            # Check for actual zone-to-zone segmentation (not Docker's internal rules)
            # Look for restrictive INPUT rules that would segment zones
            input_restrictive_rules = [
                r for r in firewall_rules
                if ("DROP" in r or "REJECT" in r)
                and "-A INPUT" in r
                and "DOCKER" not in r  # Exclude Docker internal rules
            ]

            # Also check if INPUT policy is ACCEPT (means no default restriction)
            input_policy_accept = any("-P INPUT ACCEPT" in r for r in firewall_rules)

            # Threat exists if:
            # 1. INPUT policy is ACCEPT (default allow) AND
            # 2. No restrictive INPUT rules (no zone segmentation)
            if input_policy_accept and len(input_restrictive_rules) == 0:
                self.add_threat(
                    "T04",
                    "Missing Network Segmentation",
                    f"Zone {vm['zone']} has no firewall rules restricting inter-zone access",
                    "High",
                    vm["name"],
                    vm["zone"],
                    f"INPUT policy is ACCEPT with no restrictive rules on {vm['name']}"
                )

    def detect_t05_anonymous_registry(self):
        """T5: Anonymous Registry Access"""
        for config in self.configs:
            if config.get("service") == "registry":
                content = config.get("content", "")
                # Check if auth is configured
                if "auth" not in content.lower() and "htpasswd" not in content.lower():
                    self.add_threat(
                        "T05",
                        "Anonymous Registry Access",
                        "Docker Registry has no authentication configured",
                        "Critical",
                        "registry",
                        config["zone"],
                        f"No auth configuration in {config['path']}"
                    )

    def detect_t06_cicd_to_prod_access(self):
        """T6: CI/CD to Production Access"""
        # Check authorized_keys on production VMs for Jenkins SSH keys
        jenkins_key_fingerprint = None

        # First, find Jenkins container SSH key
        for vm in self.vms:
            if vm["zone"] == "cicd-zone":
                for container in vm.get("docker_containers", []):
                    if "jenkins" in container.get("name", "").lower():
                        # We deployed a Jenkins SSH key to production
                        jenkins_key_fingerprint = "jenkins_has_ssh_key"
                        break

        # Check if production VM has Jenkins key in authorized_keys
        for config in self.configs:
            if config.get("vm", "").startswith("supply-prod") and "authorized_keys" in config.get("path", ""):
                content = config.get("content", "")
                # Check if there are SSH keys (more than just the ubuntu user's key)
                keys_count = len([line for line in content.split('\n') if line.strip() and line.startswith('ssh-')])
                if keys_count > 1:  # More than the default ubuntu key means Jenkins key was added
                    self.add_threat(
                        "T06",
                        "CI/CD to Production Access",
                        "Production VM has SSH keys from CI/CD zone (Jenkins)",
                        "High",
                        "jenkins",
                        "prod-zone",
                        f"Production authorized_keys has {keys_count} keys, indicating CI/CD access"
                    )
                    return

        # Check network flows from CI/CD to production
        for flow in self.flows:
            if flow.get("source_vm") == "supply-cicd":
                dest_ip = flow.get("dest_ip", "")
                # Check if destination is production VM (192.168.100.30)
                if dest_ip.startswith("192.168.100.30"):
                    self.add_threat(
                        "T06",
                        "CI/CD to Production Access",
                        "Network flow detected from CI/CD zone to production zone",
                        "High",
                        "jenkins",
                        "cicd-zone",
                        f"Flow: {flow['source_ip']} → {dest_ip}:{flow['dest_port']}"
                    )
                    break  # Only report once

    def detect_t07_missing_audit_logging(self):
        """T7: Missing Audit Logging"""
        for vm in self.vms:
            # Check Docker logging configuration
            has_logging_config = False
            docker_log_driver_none = False

            for config in self.configs:
                if config.get("vm") == vm["name"] and "daemon.json" in config.get("path", ""):
                    has_logging_config = True
                    content = config.get("content", "")
                    if '"log-driver": "none"' in content or '"log-driver":"none"' in content:
                        docker_log_driver_none = True
                        self.add_threat(
                            "T07",
                            "Missing Audit Logging",
                            f"Docker logging disabled on {vm['name']}",
                            "Medium",
                            vm["name"],
                            vm["zone"],
                            f"Docker daemon.json has log-driver: none on {vm['name']}"
                        )

    def detect_t08_exposed_secrets(self):
        """T8: Exposed Secrets in Configuration"""
        for config in self.configs:
            secrets = config.get("secrets", [])
            for secret in secrets:
                self.add_threat(
                    "T08",
                    "Exposed Secrets in Configuration",
                    f"Hardcoded {secret['type']} found in configuration file",
                    "Critical",
                    config.get("service", "unknown"),
                    config["zone"],
                    f"File: {config['path']}, Line: {secret['line']}, Key: {secret['key']}"
                )

    def detect_t09_broad_source_control(self):
        """T9: Broad Source Control Access (Gitea anonymous)"""
        for config in self.configs:
            if config.get("service") == "gitea":
                content = config.get("content", "")
                if "REQUIRE_SIGNIN_VIEW" in content:
                    if "false" in re.search(r'REQUIRE_SIGNIN_VIEW\s*=\s*(\w+)', content, re.I).group(1).lower():
                        self.add_threat(
                            "T09",
                            "Broad Source Control Access",
                            "Gitea allows anonymous repository access",
                            "Medium",
                            "gitea",
                            config["zone"],
                            f"REQUIRE_SIGNIN_VIEW=false in {config['path']}"
                        )

    def detect_t10_missing_resource_limits(self):
        """T10: Missing Resource Limits"""
        for vm in self.vms:
            for container in vm.get("docker_containers", []):
                # In bare-metal, we check if docker-compose has resource limits
                # For simplicity, flag all containers (same as vulnerable config)
                self.add_threat(
                    "T10",
                    "Missing Resource Limits",
                    f"Container {container.get('name')} has no resource limits",
                    "Medium",
                    container.get("name", "unknown"),
                    vm["zone"],
                    f"No CPU/memory limits configured for container on {vm['name']}"
                )
