#!/usr/bin/env python3
"""
Ground Truth Architecture Generator

Parses deployment files (K8s YAML, docker-compose, Terraform) to automatically
generate ground truth architecture for validation.

This is the "source of truth" for what SHOULD be deployed, used to measure
architecture inference accuracy.
"""

import yaml
import json
import sys
from pathlib import Path
from typing import Dict, List, Any
import re

class GroundTruthGenerator:
    """Generate ground truth architecture from deployment files"""

    def __init__(self, platform: str, deployment_dir: str):
        self.platform = platform
        self.deployment_dir = Path(deployment_dir)
        self.components = []
        self.trust_boundaries = {}
        self.component_zones = {}
        self.flows = []
        self.expected_threats = []
        self.ml_components = {}

    def parse_kubernetes_yamls(self):
        """Parse Kubernetes YAML manifests"""
        print(f"📁 Parsing Kubernetes YAMLs from {self.deployment_dir}")

        # Parse all YAML files
        yaml_files = sorted(self.deployment_dir.glob("*.yaml"))

        for yaml_file in yaml_files:
            print(f"   Reading {yaml_file.name}...")
            with open(yaml_file) as f:
                # Load all documents in the file (multi-doc YAML)
                docs = list(yaml.safe_load_all(f))

                for doc in docs:
                    if not doc:
                        continue

                    kind = doc.get("kind")
                    metadata = doc.get("metadata", {})
                    name = metadata.get("name")
                    namespace = metadata.get("namespace", "default")

                    # Extract namespaces (trust boundaries)
                    if kind == "Namespace":
                        labels = metadata.get("labels", {})
                        zone_type = labels.get("environment", "unknown")
                        self.trust_boundaries[name] = zone_type
                        print(f"      Found namespace: {name} ({zone_type})")

                    # Extract deployments (components)
                    elif kind == "Deployment":
                        spec = doc.get("spec", {})
                        template = spec.get("template", {})
                        template_metadata = template.get("metadata", {})
                        labels = template_metadata.get("labels", {})

                        app_name = labels.get("app", name)
                        component_type = labels.get("component", "service")

                        self.components.append(app_name)
                        self.component_zones[app_name] = namespace

                        # Identify ML components
                        if "ml" in app_name.lower() or "mlflow" in app_name.lower():
                            self.ml_components[app_name] = {
                                "type": self._infer_ml_type(app_name),
                                "purpose": self._infer_ml_purpose(app_name),
                                "expected_threats": self._extract_ml_threats(yaml_file)
                            }

                        print(f"      Found component: {app_name} in {namespace}")

                    # Extract services (communication interfaces)
                    elif kind == "Service":
                        # Services define how components communicate
                        spec = doc.get("spec", {})
                        service_type = spec.get("type", "ClusterIP")
                        ports = spec.get("ports", [])

                        # External access = flow from external to this component
                        if service_type == "LoadBalancer":
                            self.flows.append({
                                "source": "external",
                                "destination": name,
                                "type": "external_access",
                                "protocol": self._infer_protocol(ports)
                            })
                            print(f"      Found external access: external → {name}")

        # Infer cross-component flows from deployment patterns
        self._infer_kubernetes_flows()

        # Extract threats from comments
        self._extract_threats_from_comments(yaml_files)

    def _infer_ml_type(self, component_name: str) -> str:
        """Infer ML component type from name"""
        if "mlflow" in component_name.lower():
            return "model_registry"
        elif "inference" in component_name.lower():
            return "inference_service"
        elif "training-data" in component_name.lower():
            return "data_store"
        return "ml_component"

    def _infer_ml_purpose(self, component_name: str) -> str:
        """Infer ML component purpose"""
        purposes = {
            "mlflow": "Model versioning and storage",
            "ml-inference": "Real-time predictions",
            "training-data": "Training datasets"
        }
        for key, purpose in purposes.items():
            if key in component_name.lower():
                return purpose
        return "ML component"

    def _extract_ml_threats(self, yaml_file: Path) -> List[str]:
        """Extract ML-specific threats from file comments"""
        ml_threats = []
        with open(yaml_file) as f:
            content = f.read()
            # Find T11-T17 in comments
            for i in range(11, 18):
                pattern = f"T{i:02d}"
                if pattern in content or f"T{i}" in content:
                    ml_threats.append(pattern)
        return ml_threats

    def _infer_protocol(self, ports: List[Dict]) -> str:
        """Infer protocol from port configuration"""
        if not ports:
            return "TCP"

        first_port = ports[0]
        port_num = first_port.get("port", 0)
        port_name = first_port.get("name", "").lower()

        if "https" in port_name or port_num == 443:
            return "HTTPS"
        elif "http" in port_name or port_num in [80, 3000, 8080]:
            return "HTTP"
        elif "postgres" in port_name or port_num == 5432:
            return "PostgreSQL"
        else:
            return "TCP"

    def _infer_kubernetes_flows(self):
        """Infer expected communication flows based on component roles"""
        print("\n   Inferring expected communication flows...")

        # Define expected flows based on supply chain architecture
        flow_patterns = [
            # Jenkins (CI/CD) pulls from Gitea (source control)
            {"source": "jenkins", "destination": "gitea", "type": "pull", "protocol": "HTTP"},

            # Jenkins pushes to Docker Registry
            {"source": "jenkins", "destination": "docker-registry", "type": "push", "protocol": "HTTP"},

            # Jenkins uploads models to MLflow
            {"source": "jenkins", "destination": "mlflow", "type": "model_upload", "protocol": "HTTP"},

            # Jenkins reads training data
            {"source": "jenkins", "destination": "training-data", "type": "read", "protocol": "HTTP"},

            # Application connects to database
            {"source": "application", "destination": "postgres", "type": "database", "protocol": "PostgreSQL"},

            # Application calls ML inference service
            {"source": "application", "destination": "ml-inference", "type": "prediction", "protocol": "HTTP"},

            # ML inference downloads models from MLflow
            {"source": "ml-inference", "destination": "mlflow", "type": "model_download", "protocol": "HTTP"},

            # External users access Gitea
            {"source": "external", "destination": "gitea", "type": "git_push", "protocol": "HTTP"},

            # External users access Application
            {"source": "external", "destination": "application", "type": "user_traffic", "protocol": "HTTP"},
        ]

        for flow in flow_patterns:
            # Only add flow if both components exist
            src = flow["source"]
            dst = flow["destination"]

            if src == "external" or src in self.components:
                if dst in self.components:
                    self.flows.append(flow)
                    print(f"      {src} → {dst} ({flow['type']})")

    def _extract_threats_from_comments(self, yaml_files: List[Path]):
        """Extract threat IDs from YAML comments"""
        print("\n   Extracting expected threats from comments...")

        threat_pattern = re.compile(r'T(\d+):')
        threats_found = set()

        for yaml_file in yaml_files:
            with open(yaml_file) as f:
                content = f.read()
                matches = threat_pattern.findall(content)
                for match in matches:
                    threat_id = f"T{int(match):02d}"
                    threats_found.add(threat_id)

        self.expected_threats = sorted(list(threats_found))
        print(f"      Found threats: {', '.join(self.expected_threats)}")

    def parse_docker_compose(self):
        """Parse docker-compose files for bare-metal"""
        print(f"📁 Parsing docker-compose files from {self.deployment_dir}")

        # Define zones based on README documentation
        self.trust_boundaries = {
            "dev-zone": "development",
            "cicd-zone": "ci/cd",
            "prod-zone": "production"
        }

        # Component to zone mapping (based on README)
        zone_mapping = {
            "gitea": "dev-zone",
            "training-data": "dev-zone",
            "jenkins": "cicd-zone",
            "docker-registry": "cicd-zone",
            "mlflow": "cicd-zone",
            "application": "prod-zone",
            "postgres": "prod-zone",
            "ml-inference": "prod-zone"
        }

        # Parse each docker-compose file
        compose_files = sorted(self.deployment_dir.glob("*.yml"))

        for compose_file in compose_files:
            print(f"   Reading {compose_file.name}...")
            with open(compose_file) as f:
                doc = yaml.safe_load(f)
                services = doc.get("services", {})

                for service_name, config in services.items():
                    self.components.append(service_name)
                    self.component_zones[service_name] = zone_mapping.get(service_name, "unknown")
                    print(f"      Found component: {service_name}")

                    # Identify ML components
                    if "ml" in service_name.lower() or service_name == "mlflow":
                        self.ml_components[service_name] = {
                            "type": self._infer_ml_type(service_name),
                            "purpose": self._infer_ml_purpose(service_name),
                            "expected_threats": []
                        }

        # Same flow patterns as Kubernetes
        self._infer_kubernetes_flows()

        # Standard threats for bare-metal deployment
        self.expected_threats = [f"T{i:02d}" for i in range(1, 18)]

    def parse_terraform(self):
        """Parse Terraform files for AWS"""
        print(f"📁 Parsing Terraform files from {self.deployment_dir}")

        # Define zones based on subnet structure
        self.trust_boundaries = {
            "dev-zone": "development",
            "cicd-zone": "ci/cd",
            "prod-zone": "production"
        }

        # AWS uses EC2 instances for components
        # Based on deployment pattern from README
        self.components = [
            "gitea",
            "training-data",
            "jenkins",
            "docker-registry",
            "mlflow",
            "application",
            "postgres",
            "ml-inference"
        ]

        self.component_zones = {
            "gitea": "dev-zone",
            "training-data": "dev-zone",
            "jenkins": "cicd-zone",
            "docker-registry": "cicd-zone",
            "mlflow": "cicd-zone",
            "application": "prod-zone",
            "postgres": "prod-zone",
            "ml-inference": "prod-zone"
        }

        # ML components
        self.ml_components = {
            "mlflow": {
                "type": "model_registry",
                "purpose": "Model versioning and storage",
                "expected_threats": ["T11", "T16"]
            },
            "ml-inference": {
                "type": "inference_service",
                "purpose": "Real-time predictions",
                "expected_threats": ["T13", "T17"]
            },
            "training-data": {
                "type": "data_store",
                "purpose": "Training datasets",
                "expected_threats": ["T12"]
            }
        }

        # Same flow patterns
        self._infer_kubernetes_flows()

        # Standard threats
        self.expected_threats = [f"T{i:02d}" for i in range(1, 18)]

    def generate(self) -> Dict[str, Any]:
        """Generate ground truth architecture JSON"""
        print(f"\n🏗️  Generating ground truth for {self.platform}...")

        # Parse based on platform
        if self.platform == "kubernetes":
            self.parse_kubernetes_yamls()
        elif self.platform == "bare_metal":
            self.parse_docker_compose()
        elif self.platform == "aws":
            self.parse_terraform()
        else:
            raise ValueError(f"Unknown platform: {self.platform}")

        # Build ground truth structure
        ground_truth = {
            "platform": self.platform,
            "description": "ML-enhanced software supply chain ground truth architecture",
            "generated_from": str(self.deployment_dir),
            "components": sorted(self.components),
            "trust_boundaries": self.trust_boundaries,
            "component_zones": self.component_zones,
            "flows": self.flows,
            "expected_threats": self.expected_threats,
            "ml_components": self.ml_components
        }

        print("\n✅ Ground truth generated:")
        print(f"   Components: {len(ground_truth['components'])}")
        print(f"   Trust Boundaries: {len(ground_truth['trust_boundaries'])}")
        print(f"   Flows: {len(ground_truth['flows'])}")
        print(f"   ML Components: {len(ground_truth['ml_components'])}")
        print(f"   Expected Threats: {len(ground_truth['expected_threats'])}")

        return ground_truth


def main():
    """Generate ground truth for all platforms"""

    repo_root = Path(__file__).parent.parent
    output_dir = repo_root / "dynamic_threat_modeling" / "ground_truth"
    output_dir.mkdir(parents=True, exist_ok=True)

    platforms = [
        {
            "name": "kubernetes",
            "deployment_dir": repo_root / "dynamic_threat_modeling" / "kubernetes" / "supply_chain",
            "output_file": output_dir / "kubernetes_supply_chain_architecture.json"
        },
        {
            "name": "bare_metal",
            "deployment_dir": repo_root / "dynamic_threat_modeling" / "bare_metal" / "supply_chain" / "docker-compose",
            "output_file": output_dir / "bare_metal_supply_chain_architecture.json"
        },
        {
            "name": "aws",
            "deployment_dir": repo_root / "dynamic_threat_modeling" / "cloud_aws" / "supply_chain" / "terraform",
            "output_file": output_dir / "aws_supply_chain_architecture.json"
        }
    ]

    print("="*80)
    print("GROUND TRUTH ARCHITECTURE GENERATOR")
    print("="*80)
    print()

    for platform_config in platforms:
        print(f"\n{'='*80}")
        print(f"Platform: {platform_config['name'].upper()}")
        print(f"{'='*80}\n")

        generator = GroundTruthGenerator(
            platform=platform_config['name'],
            deployment_dir=str(platform_config['deployment_dir'])
        )

        ground_truth = generator.generate()

        # Save to JSON
        with open(platform_config['output_file'], 'w') as f:
            json.dump(ground_truth, f, indent=2)

        print(f"\n💾 Saved to: {platform_config['output_file']}")

    print("\n" + "="*80)
    print("✅ ALL GROUND TRUTH FILES GENERATED")
    print("="*80)
    print(f"\nOutput directory: {output_dir}")
    print("\nNext steps:")
    print("  1. Review generated files for accuracy")
    print("  2. Use MetricsCollector.measure_architecture_accuracy() to validate")
    print("  3. Compare inferred architecture vs ground truth")
    print()


if __name__ == "__main__":
    main()
