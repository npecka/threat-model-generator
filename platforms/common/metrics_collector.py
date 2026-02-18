"""
Metrics Collector for Threat Modeling Evaluation

Measures:
1. Architecture Accuracy: Precision, Recall, F1 for components, flows, boundaries
2. Threat Detection Quality: Detection rate, false positives, false negatives
3. Performance: Execution time, memory usage, CPU usage

Usage:
    from metrics_collector import MetricsCollector

    collector = MetricsCollector()
    collector.start_phase("data_collection")
    # ... do work ...
    collector.end_phase("data_collection")

    # Measure architecture accuracy
    accuracy = collector.measure_architecture_accuracy(
        ground_truth_path="ground_truth.json",
        inferred_components=["app", "db", "jenkins"],
        inferred_flows=[("jenkins", "app")],
        inferred_boundaries={"dev-zone": ["jenkins"], "prod-zone": ["app", "db"]}
    )

    # Generate report
    report = collector.generate_report()
"""

import json
import time
import psutil
import os
from typing import Dict, List, Set, Tuple, Any
from pathlib import Path


class MetricsCollector:
    """Collects metrics for threat modeling evaluation."""

    def __init__(self):
        self.phase_times = {}
        self.phase_memory = {}
        self.phase_cpu = {}
        self._current_phase = None
        self._phase_start_time = None
        self._phase_start_memory = None
        self._phase_start_cpu_times = None
        self._process = psutil.Process(os.getpid())
        # Storage for additional metrics
        self.architecture_metrics = None
        self.threat_metrics = None
        self.drift_metrics = None

    # =========================================================================
    # Performance Metrics
    # =========================================================================

    def start_phase(self, phase_name: str):
        """Start timing a phase (e.g., 'data_collection', 'inference', 'detection')."""
        self._current_phase = phase_name
        self._phase_start_time = time.time()
        self._phase_start_memory = self._process.memory_info().rss / 1024 / 1024  # MB
        # Record CPU times at start for accurate measurement
        self._phase_start_cpu_times = self._process.cpu_times()

    def end_phase(self, phase_name: str):
        """End timing a phase and record metrics."""
        if self._current_phase != phase_name:
            print(f"Warning: end_phase({phase_name}) called but current phase is {self._current_phase}")
            return

        duration = time.time() - self._phase_start_time
        memory = self._process.memory_info().rss / 1024 / 1024  # MB

        # Calculate CPU usage more accurately using cpu_times
        end_cpu_times = self._process.cpu_times()
        cpu_time_used = (end_cpu_times.user - self._phase_start_cpu_times.user) + \
                       (end_cpu_times.system - self._phase_start_cpu_times.system)
        # Convert to percentage: (cpu_time / wall_time) * 100
        cpu_percent = (cpu_time_used / duration * 100) if duration > 0 else 0

        self.phase_times[phase_name] = duration
        self.phase_memory[phase_name] = memory
        self.phase_cpu[phase_name] = cpu_percent

        print(f"   ⏱️  {phase_name}: {duration:.2f}s | Memory: {memory:.1f}MB | CPU: {cpu_percent:.1f}%")

        self._current_phase = None

    # =========================================================================
    # Architecture Accuracy Metrics
    # =========================================================================

    def measure_architecture_accuracy(
        self,
        ground_truth_path: str,
        inferred_components: List[str],
        inferred_flows: List[Tuple[str, str]],
        inferred_boundaries: Dict[str, List[str]]
    ) -> Dict[str, Any]:
        """
        Measure architecture inference accuracy against ground truth.

        Args:
            ground_truth_path: Path to ground truth JSON file
            inferred_components: List of component names detected
            inferred_flows: List of (source, dest) tuples detected
            inferred_boundaries: Dict of {zone_name: [component_names]}

        Returns:
            Dict with precision, recall, F1 for components, flows, and boundaries
        """
        # Load ground truth
        with open(ground_truth_path, 'r') as f:
            gt = json.load(f)

        # Extract ground truth sets
        gt_components = set(gt.get("components", []))
        gt_flows = set(
            (flow["source"], flow["destination"])
            for flow in gt.get("flows", [])
            if flow["source"] != "external"  # Skip external flows for now
        )
        gt_component_zones = gt.get("component_zones", {})

        # Convert inferred to sets
        inf_components = set(inferred_components)
        inf_flows = set(inferred_flows)

        # Flatten inferred boundaries to component->zone mapping
        inf_component_zones = {}
        for zone, components in inferred_boundaries.items():
            for comp in components:
                inf_component_zones[comp] = zone

        # Calculate metrics for components
        comp_metrics = self._calculate_metrics(
            ground_truth=gt_components,
            inferred=inf_components,
            label="components"
        )

        # Calculate metrics for flows
        flow_metrics = self._calculate_metrics(
            ground_truth=gt_flows,
            inferred=inf_flows,
            label="flows"
        )

        # Calculate metrics for boundary assignments
        # Only for components that exist in both
        common_components = gt_components & inf_components
        gt_zone_assignments = set(
            (comp, gt_component_zones.get(comp))
            for comp in common_components
            if comp in gt_component_zones
        )
        inf_zone_assignments = set(
            (comp, inf_component_zones.get(comp))
            for comp in common_components
            if comp in inf_component_zones
        )

        boundary_metrics = self._calculate_metrics(
            ground_truth=gt_zone_assignments,
            inferred=inf_zone_assignments,
            label="boundary_assignments"
        )

        accuracy_metrics = {
            "components": comp_metrics,
            "flows": flow_metrics,
            "boundaries": boundary_metrics,
            "overall_f1": (
                comp_metrics["f1"] + flow_metrics["f1"] + boundary_metrics["f1"]
            ) / 3
        }

        # Store for report generation
        self.architecture_metrics = accuracy_metrics

        return accuracy_metrics

    def _calculate_metrics(
        self,
        ground_truth: Set,
        inferred: Set,
        label: str
    ) -> Dict[str, float]:
        """Calculate precision, recall, F1."""
        true_positives = len(ground_truth & inferred)
        false_positives = len(inferred - ground_truth)
        false_negatives = len(ground_truth - inferred)

        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        print(f"\n   📊 {label.upper()} Accuracy:")
        print(f"      Precision: {precision:.2%} ({true_positives}/{true_positives + false_positives})")
        print(f"      Recall:    {recall:.2%} ({true_positives}/{true_positives + false_negatives})")
        print(f"      F1 Score:  {f1:.2%}")

        if false_positives > 0:
            print(f"      ⚠️  False Positives: {false_positives}")
            print(f"         {inferred - ground_truth}")
        if false_negatives > 0:
            print(f"      ⚠️  False Negatives: {false_negatives}")
            print(f"         {ground_truth - inferred}")

        return {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_negatives": false_negatives
        }

    # =========================================================================
    # Threat Detection Quality Metrics
    # =========================================================================

    def measure_threat_detection(
        self,
        ground_truth_threats: List[str],
        detected_threats: List[str]
    ) -> Dict[str, Any]:
        """
        Measure threat detection quality.

        Args:
            ground_truth_threats: List of expected threat IDs (e.g., ["T01", "T02", "T03"])
            detected_threats: List of detected threat IDs

        Returns:
            Dict with detection rate, precision, recall, F1
        """
        gt_set = set(ground_truth_threats)
        det_set = set(detected_threats)

        metrics = self._calculate_metrics(
            ground_truth=gt_set,
            inferred=det_set,
            label="threat_detection"
        )

        metrics["detection_rate"] = metrics["recall"]  # Same as recall
        metrics["total_expected"] = len(gt_set)
        metrics["total_detected"] = len(det_set)

        # Store for report generation
        self.threat_metrics = metrics

        return metrics

    # =========================================================================
    # Drift Detection
    # =========================================================================

    def measure_drift(
        self,
        baseline_path: str,
        current_components: List[str],
        current_flows: List[Tuple[str, str]],
        current_threats: List[str]
    ) -> Dict[str, Any]:
        """
        Measure drift from a baseline architecture.

        Args:
            baseline_path: Path to baseline metrics JSON file
            current_components: Current detected components
            current_flows: Current detected flows
            current_threats: Current detected threat IDs

        Returns:
            Dict with drift metrics
        """
        try:
            with open(baseline_path, 'r') as f:
                baseline = json.load(f)
        except FileNotFoundError:
            print(f"   ⚠️  Baseline not found: {baseline_path}")
            print(f"      Saving current run as baseline...")
            # Save current as baseline
            baseline_data = {
                "components": current_components,
                "flows": [list(f) for f in current_flows],
                "threats": current_threats,
                "timestamp": time.time()
            }
            with open(baseline_path, 'w') as f:
                json.dump(baseline_data, f, indent=2)
            return {
                "drift_detected": False,
                "message": "Baseline created - no drift to measure"
            }

        # Load baseline data
        baseline_components = set(baseline.get("components", []))
        baseline_flows = set(tuple(f) for f in baseline.get("flows", []))
        baseline_threats = set(baseline.get("threats", []))

        # Current data
        current_components_set = set(current_components)
        current_flows_set = set(current_flows)
        current_threats_set = set(current_threats)

        # Calculate drift
        components_added = current_components_set - baseline_components
        components_removed = baseline_components - current_components_set
        flows_added = current_flows_set - baseline_flows
        flows_removed = baseline_flows - current_flows_set
        threats_added = current_threats_set - baseline_threats
        threats_removed = baseline_threats - current_threats_set

        # Overall drift percentage
        total_baseline = len(baseline_components) + len(baseline_flows) + len(baseline_threats)
        total_changes = len(components_added) + len(components_removed) + \
                       len(flows_added) + len(flows_removed) + \
                       len(threats_added) + len(threats_removed)
        drift_percentage = (total_changes / (2 * total_baseline) * 100) if total_baseline > 0 else 0

        drift_metrics = {
            "drift_detected": total_changes > 0,
            "drift_percentage": drift_percentage,
            "components": {
                "added": list(components_added),
                "removed": list(components_removed),
                "unchanged": len(baseline_components & current_components_set)
            },
            "flows": {
                "added": [list(f) for f in flows_added],
                "removed": [list(f) for f in flows_removed],
                "unchanged": len(baseline_flows & current_flows_set)
            },
            "threats": {
                "added": list(threats_added),
                "removed": list(threats_removed),
                "unchanged": len(baseline_threats & current_threats_set)
            },
            "baseline_timestamp": baseline.get("timestamp", "unknown")
        }

        # Print drift summary
        print(f"\n   📊 DRIFT DETECTION:")
        if not drift_metrics["drift_detected"]:
            print(f"      ✅ No drift detected - architecture is stable")
        else:
            print(f"      ⚠️  Drift detected: {drift_percentage:.1f}%")
            if components_added:
                print(f"         Components added: {list(components_added)}")
            if components_removed:
                print(f"         Components removed: {list(components_removed)}")
            if flows_added:
                print(f"         Flows added: {len(flows_added)}")
            if flows_removed:
                print(f"         Flows removed: {len(flows_removed)}")
            if threats_added:
                print(f"         Threats added: {list(threats_added)}")
            if threats_removed:
                print(f"         Threats removed: {list(threats_removed)}")

        # Store for report generation
        self.drift_metrics = drift_metrics

        return drift_metrics

    # =========================================================================
    # Report Generation
    # =========================================================================

    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive metrics report."""
        total_time = sum(self.phase_times.values())
        max_memory = max(self.phase_memory.values()) if self.phase_memory else 0
        avg_cpu = sum(self.phase_cpu.values()) / len(self.phase_cpu) if self.phase_cpu else 0

        report = {
            "performance": {
                "total_time_seconds": total_time,
                "phase_breakdown": self.phase_times,
                "max_memory_mb": max_memory,
                "memory_by_phase": self.phase_memory,
                "avg_cpu_percent": avg_cpu,
                "cpu_by_phase": self.phase_cpu
            }
        }

        # Add architecture accuracy if measured
        if self.architecture_metrics:
            report["architecture_accuracy"] = self.architecture_metrics

        # Add threat detection quality if measured
        if self.threat_metrics:
            report["threat_detection_quality"] = self.threat_metrics

        # Add drift detection if measured
        if self.drift_metrics:
            report["drift_detection"] = self.drift_metrics

        return report

    def print_summary(self):
        """Print formatted summary of all metrics."""
        print("\n" + "="*80)
        print("METRICS SUMMARY")
        print("="*80)

        print("\n📈 PERFORMANCE METRICS:")
        total_time = sum(self.phase_times.values())
        print(f"   Total Execution Time: {total_time:.2f}s")

        if self.phase_times:
            print(f"\n   Phase Breakdown:")
            for phase, duration in self.phase_times.items():
                percentage = (duration / total_time * 100) if total_time > 0 else 0
                memory = self.phase_memory.get(phase, 0)
                cpu = self.phase_cpu.get(phase, 0)
                print(f"      {phase:20s}: {duration:6.2f}s ({percentage:5.1f}%) | {memory:6.1f}MB | CPU {cpu:5.1f}%")

        if self.phase_memory:
            max_memory = max(self.phase_memory.values())
            print(f"\n   Peak Memory Usage: {max_memory:.1f}MB")

        print("\n" + "="*80)

    def save_report(self, output_path: str):
        """Save metrics report to JSON file."""
        report = self.generate_report()

        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n💾 Metrics saved to: {output_path}")


# ============================================================================
# Helper Functions
# ============================================================================

def load_ground_truth(platform: str, base_path: str = None) -> Dict:
    """
    Load ground truth architecture for a platform.

    Args:
        platform: "kubernetes", "bare_metal", or "aws"
        base_path: Optional base path to ground truth directory

    Returns:
        Ground truth dict
    """
    if base_path is None:
        # Default to dynamic_threat_modeling/ground_truth/
        base_path = Path(__file__).parent.parent.parent / "dynamic_threat_modeling" / "ground_truth"
    else:
        base_path = Path(base_path)

    gt_file = base_path / f"{platform}_supply_chain_architecture.json"

    if not gt_file.exists():
        raise FileNotFoundError(f"Ground truth not found: {gt_file}")

    with open(gt_file, 'r') as f:
        return json.load(f)


def extract_threat_ids(threats_list: List[Dict]) -> List[str]:
    """
    Extract threat IDs from threat detection output.

    Args:
        threats_list: List of threat dicts with "id" or "threat_id" field

    Returns:
        List of threat IDs (e.g., ["T01", "T02"])
    """
    ids = []
    for threat in threats_list:
        if "id" in threat:
            ids.append(threat["id"])
        elif "threat_id" in threat:
            ids.append(threat["threat_id"])
        elif "type" in threat:
            # Try to extract from type string (e.g., "T01: Unauthenticated Access")
            type_str = threat["type"]
            if type_str.startswith("T"):
                ids.append(type_str.split(":")[0])

    return list(set(ids))  # Deduplicate


# ============================================================================
# Example Usage
# ============================================================================

if __name__ == "__main__":
    print("MetricsCollector - Example Usage\n")

    # Create collector
    collector = MetricsCollector()

    # Simulate data collection phase
    collector.start_phase("data_collection")
    time.sleep(0.5)  # Simulate work
    collector.end_phase("data_collection")

    # Simulate architecture inference
    collector.start_phase("architecture_inference")
    time.sleep(0.3)
    collector.end_phase("architecture_inference")

    # Simulate threat detection
    collector.start_phase("threat_detection")
    time.sleep(0.2)
    collector.end_phase("threat_detection")

    # Measure architecture accuracy (example)
    print("\n" + "="*80)
    print("ARCHITECTURE ACCURACY MEASUREMENT")
    print("="*80)

    try:
        # Load ground truth
        gt = load_ground_truth("kubernetes")

        # Simulate inferred architecture (in practice, this comes from your detector)
        inferred_components = ["jenkins", "gitea", "registry", "postgres", "application", "mlflow", "ml-inference"]
        inferred_flows = [
            ("jenkins", "gitea"),
            ("jenkins", "registry"),
            ("application", "postgres"),
            ("ml-inference", "mlflow")
        ]
        inferred_boundaries = {
            "dev-zone": ["gitea"],
            "cicd-zone": ["jenkins", "registry", "mlflow"],
            "prod-zone": ["application", "postgres", "ml-inference"]
        }

        accuracy = collector.measure_architecture_accuracy(
            ground_truth_path=Path(__file__).parent.parent.parent / "dynamic_threat_modeling" / "ground_truth" / "kubernetes_supply_chain_architecture.json",
            inferred_components=inferred_components,
            inferred_flows=inferred_flows,
            inferred_boundaries=inferred_boundaries
        )

        print(f"\n   🎯 Overall F1 Score: {accuracy['overall_f1']:.2%}")

    except FileNotFoundError as e:
        print(f"   ⚠️  Ground truth not found: {e}")
        print("   Run this from your threat detector to compare against actual ground truth")

    # Measure threat detection (example)
    print("\n" + "="*80)
    print("THREAT DETECTION QUALITY")
    print("="*80)

    ground_truth_threats = ["T01", "T02", "T03", "T04", "T05", "T06", "T07", "T08", "T09", "T10"]
    detected_threats = ["T01", "T02", "T03", "T05", "T06", "T07", "T08", "T09", "T10"]  # Missing T04

    threat_metrics = collector.measure_threat_detection(
        ground_truth_threats=ground_truth_threats,
        detected_threats=detected_threats
    )

    print(f"\n   Detection Rate: {threat_metrics['detection_rate']:.2%}")

    # Print summary
    collector.print_summary()

    # Save report
    collector.save_report("metrics_report.json")
