#!/usr/bin/env python3
"""
Tool Integrator - Runs pre-existing security tools and maps findings to ground truth

This module integrates established security scanning tools (Trivy, Kubescape)
rather than implementing custom detection logic.
"""

import subprocess
import json
import time
from pathlib import Path
from typing import Dict, List, Set, Tuple


class SecurityToolIntegrator:
    """Integrates pre-existing security tools for threat detection."""

    def __init__(self, supply_chain_namespaces=None):
        """
        Initialize tool integrator.

        Args:
            supply_chain_namespaces: List of namespaces to scope analysis
        """
        self.supply_chain_namespaces = supply_chain_namespaces or [
            "dev-zone", "cicd-zone", "prod-zone"
        ]

        # Ground truth threat mapping
        self.ground_truth_patterns = self._init_ground_truth_patterns()

    def _init_ground_truth_patterns(self) -> Dict[str, Dict]:
        """Initialize patterns to map tool findings to T01-T17."""
        return {
            "T01": {
                "keywords": ["loadbalancer", "nodeport", "external access", "unauthenticated"],
                "controls": ["C-0030", "KSV110"],  # Kubescape, Trivy control IDs
                "description": "Unauthenticated External Access"
            },
            "T02": {
                "keywords": ["cluster-admin", "excessive permission", "ClusterRoleBinding"],
                "controls": ["C-0035", "KSV041"],
                "description": "Excessive Permissions (cluster-admin)"
            },
            "T03": {
                "keywords": ["http", "unencrypted", "no tls", "port 80"],
                "controls": [],  # Application-level, need custom check
                "description": "Unencrypted Communication"
            },
            "T04": {
                "keywords": ["network policy", "networkpolicy", "network segmentation"],
                "controls": ["C-0030", "KSV036"],
                "description": "Missing Network Segmentation"
            },
            "T05": {
                "keywords": ["registry", "anonymous", "authentication"],
                "controls": [],  # Application-specific
                "description": "Anonymous Registry Access"
            },
            "T06": {
                "keywords": ["rolebinding", "production", "cross-zone", "cicd"],
                "controls": ["C-0035"],
                "description": "CI/CD to Production Access"
            },
            "T07": {
                "keywords": ["audit", "logging", "auditpolicy"],
                "controls": ["C-0067"],
                "description": "Missing Audit Logging"
            },
            "T08": {
                "keywords": ["secret", "configmap", "credential", "password", "hardcoded"],
                "controls": ["C-0012", "KSV013", "KSV014"],
                "description": "Exposed Secrets in ConfigMaps"
            },
            "T09": {
                "keywords": ["anonymous", "git", "clone", "signin"],
                "controls": [],  # Application-specific
                "description": "Overly Broad Source Control Access"
            },
            "T10": {
                "keywords": ["resource", "limit", "request", "resourcequota"],
                "controls": ["C-0009", "KSV011", "KSV015"],
                "description": "Missing Resource Limits"
            },
            "T11": {
                "keywords": ["mlflow", "model", "authentication"],
                "controls": [],  # ML-specific, custom check
                "description": "Unauthorized Model Access"
            },
            "T12": {
                "keywords": ["training data", "jenkins", "write access"],
                "controls": [],  # ML-specific, custom check
                "description": "Training Data Poisoning"
            },
            "T13": {
                "keywords": ["inference", "model theft", "rate limit"],
                "controls": [],  # ML-specific, custom check
                "description": "Model Theft via API"
            },
            "T14": {
                "keywords": ["model transfer", "mlflow", "http"],
                "controls": [],  # Covered by T03
                "description": "Unencrypted Model Transfer"
            },
            "T15": {
                "keywords": ["ml", "deployment", "rbac", "jenkins"],
                "controls": ["C-0035"],
                "description": "Cross-Zone ML Deployment RBAC"
            },
            "T16": {
                "keywords": ["provenance", "versioning", "model"],
                "controls": [],  # Requires ML governance tools
                "description": "Missing Model Provenance"
            },
            "T17": {
                "keywords": ["metadata", "debug", "inference"],
                "controls": [],  # Application-specific
                "description": "Exposed Model Metadata"
            }
        }

    # =========================================================================
    # Trivy Integration
    # =========================================================================

    def run_trivy(self) -> Tuple[Dict, Dict]:
        """
        Run Trivy K8s cluster scan.

        Returns:
            Tuple of (findings_dict, metrics_dict)
        """
        start_time = time.time()

        # Build command
        cmd = [
            'trivy', 'k8s',
            '--format', 'json',
            '--report', 'all',
            '--include-namespaces', ','.join(self.supply_chain_namespaces)
        ]

        print(f"   [Trivy] Running: {' '.join(cmd)}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.returncode != 0:
                print(f"   ⚠️  Trivy failed: {result.stderr}")
                return {}, {}

            findings = json.loads(result.stdout) if result.stdout else {}
            execution_time = time.time() - start_time

            # Parse findings
            parsed = self._parse_trivy_findings(findings)
            parsed['execution_time'] = execution_time

            return findings, parsed

        except subprocess.TimeoutExpired:
            print("   ⚠️  Trivy timed out after 120s")
            return {}, {}
        except Exception as e:
            print(f"   ⚠️  Trivy error: {e}")
            return {}, {}

    def _parse_trivy_findings(self, findings: Dict) -> Dict:
        """Parse Trivy JSON output."""
        total_findings = 0
        by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        detected_threats = set()

        # Trivy structure: Resources[] -> Results[] -> Misconfigurations[]
        for resource in findings.get('Resources', []):
            namespace = resource.get('Namespace', '')
            for result in resource.get('Results', []):
                for misconfig in result.get('Misconfigurations', []):
                    total_findings += 1
                    severity = misconfig.get('Severity', 'UNKNOWN')
                    if severity in by_severity:
                        by_severity[severity] += 1

                    # Map to ground truth
                    threat_id = self._map_finding_to_ground_truth(
                        avd_id=misconfig.get('AVDID', ''),
                        title=misconfig.get('Title', ''),
                        description=misconfig.get('Description', ''),
                        resource=namespace
                    )
                    if threat_id:
                        detected_threats.add(threat_id)

        return {
            'tool': 'trivy',
            'total_findings': total_findings,
            'by_severity': by_severity,
            'detected_ground_truth': sorted(detected_threats),
            'detection_rate': len(detected_threats) / 17
        }

    # =========================================================================
    # Kubescape Integration
    # =========================================================================

    def run_kubescape(self) -> Tuple[Dict, Dict]:
        """
        Run Kubescape cluster scan.

        Returns:
            Tuple of (findings_dict, metrics_dict)
        """
        start_time = time.time()

        # Build command - use full path if kubescape not in PATH
        import shutil
        kubescape_path = shutil.which('kubescape') or str(Path.home() / '.kubescape' / 'bin' / 'kubescape')

        cmd = [
            kubescape_path, 'scan',
            '--format', 'json',
            '--include-namespaces', ','.join(self.supply_chain_namespaces),
            '--compliance-threshold', '0'  # Report all findings
        ]

        print(f"   [Kubescape] Running: {' '.join(cmd)}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

            if result.returncode not in [0, 10]:  # 10 = findings exist
                print(f"   ⚠️  Kubescape failed: {result.stderr}")
                return {}, {}

            # Kubescape outputs JSON log lines, then the scan results
            # Find the line with actual scan results (has 'results' key)
            findings = {}
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    try:
                        data = json.loads(line)
                        if 'results' in data:
                            findings = data
                            break
                    except json.JSONDecodeError:
                        continue

            execution_time = time.time() - start_time

            # Parse findings
            parsed = self._parse_kubescape_findings(findings)
            parsed['execution_time'] = execution_time

            return findings, parsed

        except subprocess.TimeoutExpired:
            print("   ⚠️  Kubescape timed out after 180s")
            return {}, {}
        except FileNotFoundError:
            print("   ⚠️  Kubescape not installed. Install: curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash")
            return {}, {}
        except Exception as e:
            print(f"   ⚠️  Kubescape error: {e}")
            return {}, {}

    def _parse_kubescape_findings(self, findings: Dict) -> Dict:
        """Parse Kubescape JSON output."""
        total_findings = 0
        by_severity = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        detected_threats = set()

        # Kubescape structure: results[] (resources) -> controls[] -> status
        for resource in findings.get('results', []):
            resource_id = resource.get('resourceID', '')
            for control in resource.get('controls', []):
                status = control.get('status', {}).get('status', '')
                if status == 'failed':
                    total_findings += 1
                    severity = control.get('severity', 'Unknown')
                    if severity in by_severity:
                        by_severity[severity] += 1

                    # Map to ground truth
                    threat_id = self._map_finding_to_ground_truth(
                        avd_id=control.get('controlID', ''),
                        title=control.get('name', ''),
                        description='',
                        resource=resource_id
                    )
                    if threat_id:
                        detected_threats.add(threat_id)

        return {
            'tool': 'kubescape',
            'total_findings': total_findings,
            'by_severity': by_severity,
            'detected_ground_truth': sorted(detected_threats),
            'detection_rate': len(detected_threats) / 17
        }

    # =========================================================================
    # Ground Truth Mapping
    # =========================================================================

    def _map_finding_to_ground_truth(
        self,
        avd_id: str,
        title: str,
        description: str,
        resource: str
    ) -> str:
        """
        Map a tool finding to ground truth threat T01-T17.

        Args:
            avd_id: Tool-specific finding ID (e.g., KSV036, C-0030)
            title: Finding title
            description: Finding description
            resource: Resource name/namespace

        Returns:
            Ground truth threat ID (T01-T17) or empty string
        """
        search_text = f"{avd_id} {title} {description} {resource}".lower()

        for threat_id, pattern in self.ground_truth_patterns.items():
            # Check control IDs first (most specific)
            if avd_id in pattern['controls']:
                return threat_id

            # Check keyword matches
            if any(keyword in search_text for keyword in pattern['keywords']):
                return threat_id

        return ""

    # =========================================================================
    # Combined Analysis
    # =========================================================================

    def run_all_tools(self) -> Dict:
        """
        Run all integrated security tools and combine results.

        Returns:
            Dict with combined findings and metrics
        """
        print("🔍 TOOL-BASED THREAT DETECTION")
        print("="*80)
        print()

        results = {
            'tools': {},
            'combined_detection': set(),
            'tool_comparison': []
        }

        # Run Trivy
        print("   Running Trivy K8s scanner...")
        trivy_raw, trivy_parsed = self.run_trivy()
        if trivy_parsed:
            results['tools']['trivy'] = trivy_parsed
            results['combined_detection'].update(trivy_parsed['detected_ground_truth'])
            print(f"   ✅ Trivy: {trivy_parsed['total_findings']} findings, detected {len(trivy_parsed['detected_ground_truth'])}/17 ground truth threats")
        print()

        # Run Kubescape
        print("   Running Kubescape scanner...")
        ks_raw, ks_parsed = self.run_kubescape()
        if ks_parsed:
            results['tools']['kubescape'] = ks_parsed
            results['combined_detection'].update(ks_parsed['detected_ground_truth'])
            print(f"   ✅ Kubescape: {ks_parsed['total_findings']} findings, detected {len(ks_parsed['detected_ground_truth'])}/17 ground truth threats")
        print()

        # Combined results
        results['combined_detection'] = sorted(results['combined_detection'])
        results['combined_detection_rate'] = len(results['combined_detection']) / 17

        print(f"   📊 COMBINED: Detected {len(results['combined_detection'])}/17 ground truth threats ({results['combined_detection_rate']*100:.1f}%)")
        print(f"      Threats found: {', '.join(results['combined_detection'])}")
        print()

        return results


def integrate_security_tools(supply_chain_namespaces=None):
    """
    Main entry point for tool integration.

    Args:
        supply_chain_namespaces: List of namespaces to scan

    Returns:
        Dict with tool findings and ground truth mapping
    """
    integrator = SecurityToolIntegrator(supply_chain_namespaces)
    return integrator.run_all_tools()


if __name__ == '__main__':
    # Test integration
    results = integrate_security_tools()
    print(json.dumps(results, indent=2, default=str))
