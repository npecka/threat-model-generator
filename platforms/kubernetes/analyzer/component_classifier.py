"""
Component Classifier - Distinguishes supply chain components from infrastructure/noise

This module improves precision by filtering out non-supply-chain components
during architecture extraction.
"""

class ComponentClassifier:
    """Classifies Kubernetes components as supply-chain, infrastructure, or noise."""

    # Known infrastructure/monitoring patterns
    INFRASTRUCTURE_PATTERNS = [
        # Monitoring
        "prometheus", "grafana", "alertmanager", "pushgateway",
        "kube-state-metrics", "node-exporter", "blackbox-exporter",
        "metrics-server", "metricbeat",

        # Logging
        "elasticsearch", "kibana", "fluentd", "filebeat", "logstash",
        "apm-server",

        # Ingress/Networking
        "nginx-ingress", "ingress-controller", "cert-manager",
        "external-dns", "oauth2-proxy", "traefik",

        # Databases (if not part of supply chain)
        "mongodb", "mysql", "redis", "cassandra", "influxdb",
        "neo4j", "timescaledb", "kafka", "activemq",

        # Generic service patterns
        "-service$", "-svc$", "-exporter$", "-controller$"
    ]

    def __init__(self, ground_truth_components=None):
        """
        Initialize classifier.

        Args:
            ground_truth_components: List of known supply chain component names
                                    (from ground truth architecture)
        """
        self.ground_truth = set(ground_truth_components or [])

    def classify(self, pod):
        """
        Classify a pod as supply-chain, infrastructure, or noise.

        Args:
            pod: Dict with pod metadata (name, labels, namespace, etc.)

        Returns:
            str: "supply-chain", "infrastructure", "noise", or "unknown"
        """
        labels = pod.get("labels", {})
        name = pod.get("name", "").lower()
        namespace = pod.get("namespace", "")

        # 1. Check explicit noise marker
        if labels.get("type") == "noise-injection":
            return "noise"

        # 2. Check if in ground truth (most authoritative)
        if self.ground_truth:
            from ..analyzer.main import normalize_name  # Import from where it's defined
            normalized = normalize_name(pod.get("name", ""))
            if normalized in self.ground_truth:
                return "supply-chain"

        # 3. Check infrastructure patterns
        for pattern in self.INFRASTRUCTURE_PATTERNS:
            if pattern.endswith('$'):
                # Regex pattern
                import re
                if re.search(pattern, name):
                    return "infrastructure"
            else:
                # Simple substring match
                if pattern in name:
                    return "infrastructure"

        # 4. Check supply chain label (if explicitly marked)
        if labels.get("threat-model/supply-chain") == "true":
            return "supply-chain"

        # 5. Default: treat as unknown (could be supply chain)
        # In production, you might want to flag these for manual review
        return "unknown"

    def is_supply_chain(self, pod):
        """
        Check if a pod is part of the supply chain.

        Args:
            pod: Dict with pod metadata

        Returns:
            bool: True if supply-chain or unknown, False if infrastructure/noise
        """
        classification = self.classify(pod)
        # Conservative: include unknowns (better false positive than false negative)
        return classification in ["supply-chain", "unknown"]

    def filter_supply_chain_only(self, pods):
        """
        Filter list of pods to only supply chain components.

        Args:
            pods: List of pod dicts

        Returns:
            List of pods classified as supply-chain or unknown
        """
        return [pod for pod in pods if self.is_supply_chain(pod)]

    def get_statistics(self, pods):
        """
        Get classification statistics for a list of pods.

        Args:
            pods: List of pod dicts

        Returns:
            Dict with counts by classification
        """
        stats = {
            "supply-chain": 0,
            "infrastructure": 0,
            "noise": 0,
            "unknown": 0,
            "total": len(pods)
        }

        for pod in pods:
            classification = self.classify(pod)
            stats[classification] += 1

        return stats


# Helper function for backward compatibility
def create_classifier(ground_truth_path=None):
    """
    Create a ComponentClassifier from ground truth file.

    Args:
        ground_truth_path: Path to ground truth JSON file

    Returns:
        ComponentClassifier instance
    """
    if ground_truth_path:
        import json
        from pathlib import Path

        gt_file = Path(ground_truth_path)
        if gt_file.exists():
            with open(gt_file, 'r') as f:
                gt_data = json.load(f)
                components = gt_data.get("components", [])
                return ComponentClassifier(ground_truth_components=components)

    return ComponentClassifier()
