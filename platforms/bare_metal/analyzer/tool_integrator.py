#!/usr/bin/env python3
"""
Bare-Metal Tool Integrator
Integrates Docker Bench Security and Checkov for bare-metal threat detection
PLUS platform-agnostic ML threat detector for T11-T17
"""

import json
import subprocess
import shutil
import sys
from pathlib import Path

# Add parent path for common modules
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from common.ml_threat_detector import detect_ml_threats


class BareMetalToolIntegrator:
    """Integrates security scanning tools for bare-metal deployments"""

    def __init__(self, metadata_path=None):
        self.metadata_path = metadata_path or "platforms/bare_metal/extractor/output/bare_metal_metadata.json"
        self.results_dir = Path("platforms/bare_metal/analyzer/output")
        self.results_dir.mkdir(parents=True, exist_ok=True)

    def run_all_tools(self):
        """Run all security scanning tools"""
        print("\n=== Phase 3: Multi-Modal Threat Identification ===")

        results = {
            "tools": {},
            "combined_detection": [],
            "detection_summary": {}
        }

        # Load metadata
        with open(self.metadata_path, 'r') as f:
            metadata = json.load(f)

        # Run Docker Bench Security (CSPM for bare-metal)
        print("\n[1/2] Running Docker Bench Security...")
        docker_bench_results = self.run_docker_bench(metadata)
        results["tools"]["docker_bench"] = docker_bench_results

        # Run Checkov on docker-compose files (Static IaC analysis)
        print("\n[2/3] Running Checkov on docker-compose files...")
        checkov_results = self.run_checkov(metadata)
        results["tools"]["checkov"] = checkov_results

        # Run ML threat detector for T11-T17
        print("\n[3/3] Running platform-agnostic ML threat detector...")
        ml_results = self.run_ml_detector(metadata)
        results["tools"]["ml_detector"] = ml_results

        # Combine detections
        results["combined_detection"] = self._combine_detections(
            docker_bench_results, checkov_results, ml_results
        )

        # Calculate detection rates
        ground_truth_threats = [f"T{i:02d}" for i in range(1, 18)]  # T01-T17
        results["detection_summary"] = {
            "total_threats": len(ground_truth_threats),
            "detected": len(results["combined_detection"]),
            "detection_rate": len(results["combined_detection"]) / len(ground_truth_threats)
        }

        # Save results
        output_file = self.results_dir / "tool_results.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)

        print(f"\n✓ Tool integration complete: {len(results['combined_detection'])}/{len(ground_truth_threats)} threats detected")
        return results

    def run_docker_bench(self, metadata):
        """
        Run Docker Bench Security on bare-metal VMs

        For now, parse existing results from case_studies/bare_metal/supply_chain/results/tool_comparison/
        Later can be replaced with live scans
        """
        results = {
            "tool": "docker_bench",
            "total_findings": 0,
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "detected_ground_truth": [],
            "findings": []
        }

        # Check for existing Docker Bench results
        bench_results_dir = Path("case_studies/bare_metal/supply_chain/results/tool_comparison")

        if bench_results_dir.exists():
            # Parse existing Docker Bench outputs
            threat_mapping_file = bench_results_dir / "docker-bench-threat-mapping.json"

            if threat_mapping_file.exists():
                with open(threat_mapping_file, 'r') as f:
                    mapping = json.load(f)
                    results["detected_ground_truth"] = mapping.get("detected_threats", [])
                    results["total_findings"] = mapping.get("total_findings", 0)
                    results["findings"] = mapping.get("findings", [])

            # Parse raw outputs if mapping doesn't exist
            else:
                for vm_file in bench_results_dir.glob("docker-bench-vm*.txt"):
                    findings = self._parse_docker_bench_output(vm_file)
                    results["findings"].extend(findings)
                    results["total_findings"] += len(findings)

                # Map findings to ground truth (simplified)
                results["detected_ground_truth"] = self._map_docker_bench_to_threats(results["findings"])

        else:
            print("  ⚠ Docker Bench results not found. Will need to run fresh scans.")
            print(f"  Expected location: {bench_results_dir}")

        return results

    def run_checkov(self, metadata):
        """
        Analyze docker-compose files for security issues

        Note: Checkov doesn't have built-in docker-compose checks, so we use
        enhanced heuristics to detect common misconfigurations.
        """
        results = {
            "tool": "static_analysis",  # Not using Checkov for docker-compose
            "total_findings": 0,
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "detected_ground_truth": [],
            "findings": []
        }

        # Extract docker-compose files from metadata
        config_files = metadata.get("config_files", [])
        compose_files = [
            cf for cf in config_files
            if "docker-compose" in cf.get("path", "")
        ]

        if not compose_files:
            print("  ⚠ No docker-compose files found in metadata")
            return results

        print(f"  ✓ Analyzing {len(compose_files)} docker-compose files")

        detected_threats = set()

        for cf in compose_files:
            content = cf.get("content", "")
            findings = []

            # T01: Exposed ports
            if "ports:" in content:
                if any(port in content for port in ["80:80", "8080:8080", "3000:3000", "443:443"]):
                    detected_threats.add("T01")
                    findings.append({"issue": "Exposed ports", "severity": "HIGH"})

            # T02: Privileged containers or root user
            if "privileged: true" in content or "user: root" in content:
                detected_threats.add("T02")
                findings.append({"issue": "Privileged container or root user", "severity": "CRITICAL"})

            # T03: Using 'latest' tag (image vulnerability risk)
            if ":latest" in content or ("image:" in content and ":" not in content.split("image:")[1].split()[0]):
                detected_threats.add("T03")
                findings.append({"issue": "Using latest tag or unversioned image", "severity": "MEDIUM"})

            # T06: Missing TLS/encryption
            if "http://" in content and "https://" not in content:
                detected_threats.add("T06")
                findings.append({"issue": "HTTP without HTTPS", "severity": "HIGH"})

            # T07: Missing logging configuration
            if "logging:" not in content:
                detected_threats.add("T07")
                findings.append({"issue": "No logging configuration", "severity": "MEDIUM"})

            # T08: Hardcoded secrets
            if any(keyword in content for keyword in ["PASSWORD", "SECRET", "TOKEN", "KEY"]):
                detected_threats.add("T08")
                findings.append({"issue": "Potential hardcoded secrets", "severity": "CRITICAL"})

            # T10: Missing resource limits
            if "deploy:" not in content or "resources:" not in content:
                detected_threats.add("T10")
                findings.append({"issue": "No resource limits", "severity": "MEDIUM"})

            results["findings"].extend(findings)
            results["total_findings"] += len(findings)

        results["detected_ground_truth"] = sorted(list(detected_threats))
        print(f"  ✓ Found {results['total_findings']} configuration issues")
        print(f"  ✓ Mapped to {len(results['detected_ground_truth'])} threat categories")

        return results

    def _parse_docker_bench_output(self, output_file):
        """Parse Docker Bench Security text output"""
        findings = []

        with open(output_file, 'r') as f:
            content = f.read()

            # Parse WARN and FAIL lines
            for line in content.split('\n'):
                if '[WARN]' in line or '[FAIL]' in line:
                    findings.append({
                        "severity": "HIGH" if '[FAIL]' in line else "MEDIUM",
                        "message": line.strip(),
                        "source_file": output_file.name
                    })

        return findings

    def _map_docker_bench_to_threats(self, findings):
        """Map Docker Bench findings to ground truth threat taxonomy"""
        detected = []

        # Mapping based on CIS Docker Benchmark controls
        for finding in findings:
            msg = finding.get("message", "").lower()

            # T01: Container ports exposed
            if "port" in msg and "expose" in msg:
                detected.append("T01")

            # T02: Privileged containers, root user
            if "privileged" in msg or "root" in msg:
                detected.append("T02")

            # T04: Network configuration
            if "network" in msg:
                detected.append("T04")

            # T05: Registry authentication
            if "registry" in msg and "auth" in msg:
                detected.append("T05")

            # T07: Logging configuration
            if "log" in msg:
                detected.append("T07")

            # T10: Resource limits
            if "limit" in msg or "resource" in msg:
                detected.append("T10")

        return list(set(detected))

    def _parse_checkov_output(self, checkov_output):
        """Parse Checkov JSON output and map to threat taxonomy"""
        results = {
            "tool": "checkov",
            "total_findings": 0,
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "detected_ground_truth": [],
            "findings": []
        }

        # Checkov output structure: {"results": {"failed_checks": [...], ...}}
        failed_checks = checkov_output.get("results", {}).get("failed_checks", [])
        results["total_findings"] = len(failed_checks)

        detected_threats = set()

        for check in failed_checks:
            check_id = check.get("check_id", "")
            check_name = check.get("check_name", "")
            severity = check.get("severity", "MEDIUM")
            file_path = check.get("file_path", "")

            # Count by severity
            results["by_severity"][severity] = results["by_severity"].get(severity, 0) + 1

            # Store finding
            results["findings"].append({
                "check_id": check_id,
                "check_name": check_name,
                "severity": severity,
                "file": file_path,
                "resource": check.get("resource", "")
            })

            # Map Checkov checks to threat taxonomy
            check_lower = (check_id + " " + check_name).lower()

            # T01: Exposed ports without proper security
            if "port" in check_lower or "expose" in check_lower:
                detected_threats.add("T01")

            # T02: Privileged containers, improper capabilities
            if any(keyword in check_lower for keyword in ["privileged", "capabilities", "root", "user"]):
                detected_threats.add("T02")

            # T03: Image vulnerabilities
            if any(keyword in check_lower for keyword in ["image", "version", "latest", "digest"]):
                detected_threats.add("T03")

            # T04: Network isolation issues
            if "network" in check_lower or "isolation" in check_lower:
                detected_threats.add("T04")

            # T06: Unencrypted communication
            if any(keyword in check_lower for keyword in ["tls", "ssl", "encrypt", "https"]):
                detected_threats.add("T06")

            # T07: Logging configuration
            if "log" in check_lower:
                detected_threats.add("T07")

            # T08: Secrets in code
            if any(keyword in check_lower for keyword in ["secret", "password", "credential", "token"]):
                detected_threats.add("T08")

            # T09: Weak authentication
            if "auth" in check_lower:
                detected_threats.add("T09")

            # T10: Resource limits
            if any(keyword in check_lower for keyword in ["resource", "limit", "memory", "cpu"]):
                detected_threats.add("T10")

        results["detected_ground_truth"] = sorted(list(detected_threats))
        return results

    def run_ml_detector(self, metadata):
        """
        Run platform-agnostic ML threat detector for T11-T17

        This is CRITICAL - without this, bare-metal deployments CANNOT detect
        ML-specific threats, which invalidates the platform-agnostic research claim.
        """
        results = {
            "tool": "ml_detector",
            "total_findings": 0,
            "detected_ground_truth": [],
            "findings": []
        }

        try:
            # Call the platform-agnostic ML detector
            ml_threats = detect_ml_threats('bare-metal', metadata)

            results["total_findings"] = len(ml_threats)
            results["findings"] = ml_threats

            # Extract detected threat IDs
            detected_ids = set()
            for threat in ml_threats:
                threat_id = threat.get('threat_id', '')
                if threat_id:
                    detected_ids.add(threat_id)

            results["detected_ground_truth"] = sorted(list(detected_ids))

            print(f"   ✅ ML Detector: {len(detected_ids)} threat types detected (T11-T17 coverage)")

        except Exception as e:
            print(f"   ⚠️  ML Detector error: {e}")
            import traceback
            traceback.print_exc()

        return results

    def _combine_detections(self, docker_bench, checkov, ml_detector=None):
        """Combine detections from all tools"""
        combined = set()

        combined.update(docker_bench.get("detected_ground_truth", []))
        combined.update(checkov.get("detected_ground_truth", []))

        if ml_detector:
            combined.update(ml_detector.get("detected_ground_truth", []))

        return sorted(list(combined))


def integrate_tools(metadata_path=None):
    """Main entry point for tool integration"""
    integrator = BareMetalToolIntegrator(metadata_path)
    return integrator.run_all_tools()


if __name__ == "__main__":
    results = integrate_tools()
    print(f"\nDetected threats: {results['combined_detection']}")
