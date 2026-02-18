# main.py
"""
Main orchestrator for K8s threat modeling with multi-modal threat correlation.

NEW ARCHITECTURE:
- STATIC ANALYSIS: Industry tools (Trivy/Kubescape) for infrastructure threats (T01-T10)
- ML-SPECIFIC DETECTION: Custom detector for domain threats (T11-T17)
- RUNTIME ANALYSIS: Hubble flows + Falco events for behavioral threats
- CORRELATION: Multi-modal validation of static findings with runtime evidence
- OUTPUT: PyTM model with validated, confidence-scored threats
"""

from data_loader import load_data
from port_scanner import detect_port_scanning
from falco_threat_detector import detect_falco_runtime_threats, get_falco_threat_summary
from ml_threat_detector import detect_ml_threats, get_ml_threat_summary  # NEW: ML-specific only
from lateral_movement_detector import detect_lateral_movement, detect_unusual_external_connections, get_lateral_movement_summary
from model_builder import build_pytm_model
from dfd_generator import generate_dfd_text
from tool_integrator import integrate_security_tools
from threat_correlator import correlate_threats  # NEW: Correlation layer
import json
import sys
from pathlib import Path

# Add common path for MetricsCollector
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "common"))
try:
    from metrics_collector import MetricsCollector, extract_threat_ids
    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False
    print("⚠️  MetricsCollector not available")

def main():
    print("="*80)
    print("K8S THREAT MODEL GENERATION - Formal + Empirical Analysis")
    print("="*80)
    print()

    # Create metrics collector
    metrics = MetricsCollector() if METRICS_AVAILABLE else None

    # Load runtime data collected by extractor
    if metrics:
        metrics.start_phase("data_collection")

    print("📁 Loading runtime data from extractor...")
    data = load_data()
    pods = data.get("pods", [])
    flows = data.get("hubble_flows", [])
    falco_events = data.get("falco_events", [])
    rbac = data.get("rbac", [])
    services = data.get("services", {})
    configmaps = data.get("configmaps", [])
    network_policies = data.get("network_policies", [])
    namespaces = data.get("namespaces", [])

    print(f"   Loaded: {len(pods)} pods, {len(flows)} flows, {len(falco_events)} Falco events, {len(rbac)} RBAC bindings")
    print()

    if metrics:
        metrics.end_phase("data_collection")
        metrics.start_phase("threat_detection")

    # =========================================================================
    # EMPIRICAL THREAT DETECTION (Runtime Analysis)
    # =========================================================================
    print("🔍 EMPIRICAL ANALYSIS: Detecting runtime threats...")
    print()

    # Falco runtime threats
    print("   [Falco] Analyzing runtime behavior events...")
    falco_threats = detect_falco_runtime_threats(falco_events, pods)
    falco_summary = get_falco_threat_summary(falco_threats)
    print(f"   ✅ Found {len(falco_threats)} runtime threats from Falco")
    if falco_summary["total"] > 0:
        print(f"      Critical: {falco_summary['critical_count']}, High: {falco_summary['high_count']}, Medium: {falco_summary['medium_count']}")
    print()

    # Port scanning detection
    print("   [Hubble] Detecting port scanning activity...")
    scan_results = detect_port_scanning(flows)
    print(f"   ✅ Found {len(scan_results)} port scan events")
    print()

    # Lateral movement detection
    print("   [Hubble] Detecting cross-namespace lateral movement...")
    lateral_threats = detect_lateral_movement(flows, pods)
    lateral_summary = get_lateral_movement_summary(lateral_threats)
    print(f"   ✅ Found {len(lateral_threats)} lateral movement threats")
    if lateral_summary["total"] > 0:
        print(f"      Critical: {lateral_summary['critical_count']}, High: {lateral_summary['high_count']}, Medium: {lateral_summary['medium_count']}")
    print()

    # External egress detection
    print("   [Hubble] Detecting unusual external connections...")
    egress_threats = detect_unusual_external_connections(flows, pods)
    print(f"   ✅ Found {len(egress_threats)} external connection threats")
    print()

    # =========================================================================
    # ML-SPECIFIC THREAT DETECTION (Domain Threats T11-T17)
    # =========================================================================
    print("🔍 ML-SPECIFIC ANALYSIS: Detecting ML supply chain threats...")
    print()

    print("   [ML Config] Analyzing MLflow, model access, and provenance...")
    ml_threats = detect_ml_threats(pods, services, configmaps)
    ml_summary = get_ml_threat_summary(ml_threats)
    print(f"   ✅ Found {len(ml_threats)} ML-specific threats")
    if ml_summary["total"] > 0:
        print(f"      High: {ml_summary['high_count']}, Medium: {ml_summary['medium_count']}")
    print()

    # =========================================================================
    # TOOL-BASED THREAT DETECTION (Trivy + Kubescape)
    # =========================================================================
    print()
    print("="*80)

    # Get supply chain namespaces from data
    supply_chain_namespaces = ["dev-zone", "cicd-zone", "prod-zone"]

    # Run security tools
    tool_results = integrate_security_tools(supply_chain_namespaces)

    print()
    print("="*80)
    print()

    # =========================================================================
    # THREAT CORRELATION (Multi-Modal Validation)
    # =========================================================================
    print("🔗 CORRELATION: Validating static findings with runtime evidence...")
    print()

    # Correlate static (tool + ML) findings with runtime evidence
    correlated_threats = correlate_threats(
        tool_results=tool_results,
        hubble_flows=flows,
        falco_events=falco_events,
        pods=pods,
        lateral_threats=lateral_threats,
        egress_threats=egress_threats,
        services=services
    )

    # Summarize correlation results
    confirmed_count = sum(1 for t in correlated_threats if t.get('validation_status') == 'CONFIRMED')
    potential_count = sum(1 for t in correlated_threats if t.get('validation_status') == 'POTENTIAL')
    runtime_only_count = sum(1 for t in correlated_threats if t.get('validation_status') == 'RUNTIME_ONLY')

    print(f"   ✅ Correlated {len(correlated_threats)} threats:")
    print(f"      CONFIRMED (static + runtime): {confirmed_count}")
    print(f"      POTENTIAL (static only): {potential_count}")
    print(f"      RUNTIME ONLY: {runtime_only_count}")
    print()

    # =========================================================================
    # GENERATE PYTM MODEL WITH ALL THREATS
    # =========================================================================
    print("📝 Building PyTM threat model...")
    model_lines, dfd_entities, dfd_flows = build_pytm_model(
        pods,
        flows,
        scan_results,
        falco_threats=falco_threats,
        correlated_threats=correlated_threats,  # NEW: Use correlated threats
        ml_threats=ml_threats,  # ML-specific threats
        lateral_threats=lateral_threats,
        egress_threats=egress_threats
    )

    # Save PyTM model
    with open("output/model.py", "w") as f:
        f.write("\n".join(model_lines))
    print("   ✅ output/model.py generated")

    # Save DFD text output
    dfd_text = generate_dfd_text(dfd_entities, dfd_flows)
    with open("output/dfd_text.txt", "w") as f:
        f.write(dfd_text)
    print("   ✅ output/dfd_text.txt generated")

    # =========================================================================
    # GENERATE THREAT SUMMARY REPORT
    # =========================================================================
    print()
    print("📊 Generating threat summary report...")

    total_empirical = len(falco_threats) + len(scan_results) + len(lateral_threats) + len(egress_threats)
    total_static = len(ml_threats)  # ML-specific static threats
    total_correlated = len(correlated_threats)
    total_threats = total_empirical + total_static + total_correlated

    threat_summary = {
        "total_threats": total_threats,
        "correlated_threats": {
            "total": total_correlated,
            "confirmed": confirmed_count,
            "potential": potential_count,
            "runtime_only": runtime_only_count,
            "threats": correlated_threats
        },
        "ml_specific_threats": {
            "total": len(ml_threats),
            "threats": ml_threats
        },
        "empirical_threats": {
            "total": total_empirical,
            "falco": len(falco_threats),
            "port_scans": len(scan_results),
            "lateral_movement": len(lateral_threats),
            "egress": len(egress_threats),
            "threats": {
                "falco": falco_threats,
                "port_scans": scan_results,
                "lateral_movement": lateral_threats,
                "egress": egress_threats
            }
        },
        "tool_based_detection": {
            "combined_detection": tool_results.get('combined_detection', []),
            "combined_detection_rate": tool_results.get('combined_detection_rate', 0),
            "trivy": tool_results.get('tools', {}).get('trivy', {}),
            "kubescape": tool_results.get('tools', {}).get('kubescape', {}),
            "ground_truth_coverage": f"{len(tool_results.get('combined_detection', []))}/17 threats detected"
        },
        "summary": {
            "total_pods_analyzed": len(pods),
            "total_flows_analyzed": len(flows),
            "total_falco_events": len(falco_events),
            "static_detection_rate": f"{(total_static / total_threats * 100):.1f}%" if total_threats > 0 else "0%",
            "empirical_detection_rate": f"{(total_empirical / total_threats * 100):.1f}%" if total_threats > 0 else "0%",
            "correlation_confirmation_rate": f"{(confirmed_count / total_correlated * 100):.1f}%" if total_correlated > 0 else "0%",
            "llm_threats_available": llm_analysis is not None,
            "ground_truth_detection_rate": f"{tool_results.get('combined_detection_rate', 0)*100:.1f}%"
        }
    }

    with open("output/threat_summary.json", "w") as f:
        json.dump(threat_summary, f, indent=2)
    print("   ✅ output/threat_summary.json generated")

    if metrics:
        metrics.end_phase("threat_detection")

    # =========================================================================
    # METRICS MEASUREMENT
    # =========================================================================
    if metrics:
        print()
        print("="*80)
        print("MEASURING ACCURACY METRICS")
        print("="*80)
        print()

        # Extract inferred architecture
        def normalize_name(name):
            """Normalize pod names to component names.

            Kubernetes pod naming:
            - Deployment: <name>-<replicaset-hash>-<pod-hash>
            - Pod: <name>

            Examples:
            - ml-inference-7b68c45fbc-tdlf2 → ml-inference
            - training-data-init → training-data-init
            - jenkins-6c4b664d4-hm4bq → jenkins
            """
            if '-' not in name:
                return name

            parts = name.split('-')

            # Kubernetes uses hexadecimal hashes (replicaset and pod hashes)
            # These are 5-10 characters containing only [0-9a-f]
            def is_k8s_hash(part):
                return len(part) >= 5 and len(part) <= 10 and all(c in '0123456789abcdef' for c in part)

            # Remove hash suffixes from the end
            result_parts = []
            for part in parts:
                if is_k8s_hash(part):
                    break
                result_parts.append(part)

            return '-'.join(result_parts) if result_parts else parts[0]

        # Filter to supply chain namespaces only
        supply_chain_pods = [pod for pod in pods if pod.get("namespace") in supply_chain_namespaces]
        inferred_components = list(set([normalize_name(pod["name"]) for pod in supply_chain_pods]))

        # Extract flows - handle different Hubble flow formats
        inferred_flows = []
        for flow in flows:
            if isinstance(flow, dict):
                src = flow.get("source", {})
                dst = flow.get("destination", {})

                # Handle nested structure (Hubble format)
                if isinstance(src, dict) and isinstance(dst, dict):
                    # Try multiple possible field names
                    src_pod = src.get("pod_name") or src.get("pod") or src.get("name", "")
                    dst_pod = dst.get("pod_name") or dst.get("pod") or dst.get("name", "")

                    # Extract from labels if present
                    if not src_pod and "labels" in src:
                        src_pod = src.get("labels", {}).get("k8s:io.kubernetes.pod.name", "")
                    if not dst_pod and "labels" in dst:
                        dst_pod = dst.get("labels", {}).get("k8s:io.kubernetes.pod.name", "")

                    # Only add if both pods are valid and in supply chain namespaces
                    src_ns = src.get("namespace", "")
                    dst_ns = dst.get("namespace", "")

                    if src_pod and dst_pod and \
                       src_ns in supply_chain_namespaces and \
                       dst_ns in supply_chain_namespaces:
                        inferred_flows.append((normalize_name(src_pod), normalize_name(dst_pod)))

        inferred_flows = list(set(inferred_flows))  # Deduplicate

        # Debug: Print inferred flows if empty
        if not inferred_flows:
            print("   ⚠️  No flows detected between supply chain components")
            print(f"      (This is expected with limited Hubble flow data: {len(flows)} flows)")

        # Group components by namespace (trust boundaries) - supply chain only
        inferred_boundaries = {}
        for pod in supply_chain_pods:
            ns = pod.get("namespace", "unknown")
            comp_name = normalize_name(pod["name"])
            if ns not in inferred_boundaries:
                inferred_boundaries[ns] = []
            if comp_name not in inferred_boundaries[ns]:
                inferred_boundaries[ns].append(comp_name)

        # Measure architecture accuracy
        gt_path = Path(__file__).parent.parent.parent.parent / "dynamic_threat_modeling" / "ground_truth" / "kubernetes_supply_chain_architecture.json"

        if gt_path.exists():
            accuracy = metrics.measure_architecture_accuracy(
                ground_truth_path=str(gt_path),
                inferred_components=inferred_components,
                inferred_flows=inferred_flows,
                inferred_boundaries=inferred_boundaries
            )
            print(f"\n🎯 Overall Architecture F1 Score: {accuracy['overall_f1']:.2%}")
        else:
            print("⚠️  Ground truth not found - skipping architecture accuracy measurement")

        # Measure threat detection quality
        all_threats = []
        all_threats.extend(falco_threats)
        all_threats.extend(correlated_threats)
        all_threats.extend(ml_threats)
        all_threats.extend(lateral_threats)
        all_threats.extend(egress_threats)

        # Expected threats for supply chain
        expected_threats = ["T01", "T02", "T03", "T04", "T05", "T06", "T07", "T08", "T09", "T10",
                           "T11", "T12", "T13", "T14", "T15", "T16", "T17"]

        # Extract detected threat IDs from various threat formats
        detected_threat_ids = []
        for threat in all_threats:
            if "threat_id" in threat:
                # Correlated threats have threat_id field
                detected_threat_ids.append(threat["threat_id"])
            elif "id" in threat:
                detected_threat_ids.append(threat["id"])
            elif "type" in threat:
                # Try to extract from type string (e.g., "T01: Threat Name")
                type_str = threat["type"]
                if type_str.startswith("T"):
                    tid = type_str.split(":")[0] if ":" in type_str else type_str.split()[0]
                    detected_threat_ids.append(tid)

        detected_threat_ids = list(set(detected_threat_ids))  # Deduplicate

        # Debug: Print detected threat IDs
        if detected_threat_ids:
            print(f"\n   📋 Extracted {len(detected_threat_ids)} unique threat IDs: {sorted(detected_threat_ids)}")
        else:
            print(f"\n   ⚠️  No threat IDs extracted from {len(all_threats)} threats")

        if detected_threat_ids:
            threat_quality = metrics.measure_threat_detection(
                ground_truth_threats=expected_threats,
                detected_threats=detected_threat_ids
            )
            print(f"\n   Detection Rate: {threat_quality['detection_rate']:.2%}")
            print(f"   Detected: {threat_quality['total_detected']}/{threat_quality['total_expected']}")

        # Measure drift from baseline
        baseline_path = Path("output") / "architecture_baseline.json"
        drift_metrics = metrics.measure_drift(
            baseline_path=str(baseline_path),
            current_components=inferred_components,
            current_flows=inferred_flows,
            current_threats=detected_threat_ids
        )

        # Load extractor metrics if available
        extractor_metrics_path = Path(__file__).parent.parent / "extractor" / "output" / "extractor_metrics.json"
        extractor_metrics = None
        if extractor_metrics_path.exists():
            try:
                with open(extractor_metrics_path, 'r') as f:
                    extractor_metrics = json.load(f)
                print()
                print("="*80)
                print("COMBINED END-TO-END METRICS")
                print("="*80)
                print()

                # Calculate combined metrics
                extractor_perf = extractor_metrics.get("performance", {})
                analyzer_perf = metrics.generate_report().get("performance", {})

                total_time = extractor_perf.get("total_time_seconds", 0) + analyzer_perf.get("total_time_seconds", 0)
                max_memory = max(
                    extractor_perf.get("max_memory_mb", 0),
                    analyzer_perf.get("max_memory_mb", 0)
                )

                # Weighted average CPU (by time spent in each phase)
                extractor_time = extractor_perf.get("total_time_seconds", 0)
                analyzer_time = analyzer_perf.get("total_time_seconds", 0)
                extractor_cpu = extractor_perf.get("avg_cpu_percent", 0)
                analyzer_cpu = analyzer_perf.get("avg_cpu_percent", 0)
                weighted_cpu = (extractor_cpu * extractor_time + analyzer_cpu * analyzer_time) / total_time if total_time > 0 else 0

                print(f"📊 END-TO-END PIPELINE OVERHEAD:")
                print(f"   Total Execution Time: {total_time:.2f}s")
                print(f"     ├─ Data Extraction:  {extractor_time:.2f}s ({extractor_time/total_time*100:.1f}%)")
                print(f"     └─ Threat Analysis:  {analyzer_time:.2f}s ({analyzer_time/total_time*100:.1f}%)")
                print(f"   Peak Memory Usage: {max_memory:.1f}MB")
                print(f"   Average CPU Usage: {weighted_cpu:.1f}%")
                print()

                print(f"📊 EXTRACTION PHASE BREAKDOWN:")
                extractor_phases = extractor_perf.get("phase_breakdown", {})
                for phase, duration in sorted(extractor_phases.items(), key=lambda x: x[1], reverse=True):
                    memory = extractor_perf.get("memory_by_phase", {}).get(phase, 0)
                    cpu = extractor_perf.get("cpu_by_phase", {}).get(phase, 0)
                    pct = (duration / extractor_time * 100) if extractor_time > 0 else 0
                    print(f"   {phase:30s}: {duration:6.2f}s ({pct:5.1f}%) | {memory:6.1f}MB | CPU {cpu:5.1f}%")
                print()

                print(f"📊 ANALYSIS PHASE BREAKDOWN:")
                analyzer_phases = analyzer_perf.get("phase_breakdown", {})
                for phase, duration in sorted(analyzer_phases.items(), key=lambda x: x[1], reverse=True):
                    memory = analyzer_perf.get("memory_by_phase", {}).get(phase, 0)
                    cpu = analyzer_perf.get("cpu_by_phase", {}).get(phase, 0)
                    pct = (duration / analyzer_time * 100) if analyzer_time > 0 else 0
                    print(f"   {phase:30s}: {duration:6.2f}s ({pct:5.1f}%) | {memory:6.1f}MB | CPU {cpu:5.1f}%")
                print()

            except Exception as e:
                print(f"   ⚠️  Could not load extractor metrics: {e}")

        # Print analyzer metrics summary
        metrics.print_summary()

        # Save combined metrics report
        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)

        # Generate combined report
        combined_report = metrics.generate_report()
        if extractor_metrics:
            combined_report["extractor_performance"] = extractor_metrics.get("performance", {})
            combined_report["end_to_end_overhead"] = {
                "total_time_seconds": total_time,
                "extraction_time_seconds": extractor_time,
                "analysis_time_seconds": analyzer_time,
                "extraction_percentage": (extractor_time / total_time * 100) if total_time > 0 else 0,
                "analysis_percentage": (analyzer_time / total_time * 100) if total_time > 0 else 0,
                "peak_memory_mb": max_memory,
                "weighted_avg_cpu_percent": weighted_cpu
            }

        # Save to file
        with open(str(output_dir / "metrics_report.json"), 'w') as f:
            json.dump(combined_report, f, indent=2)
        print(f"\n💾 Combined metrics saved to: {output_dir / 'metrics_report.json'}")

    # =========================================================================
    # PRINT SUMMARY
    # =========================================================================
    print()
    print("="*80)
    print("MULTI-MODAL THREAT DETECTION SUMMARY")
    print("="*80)
    print(f"Total Threats Detected: {total_threats}")
    print()

    # Calculate percentages safely
    static_pct = (total_static / total_threats * 100) if total_threats > 0 else 0
    empirical_pct = (total_empirical / total_threats * 100) if total_threats > 0 else 0
    correlated_pct = (total_correlated / total_threats * 100) if total_threats > 0 else 0

    print(f"CORRELATED (Multi-Modal):       {total_correlated:3d}  ({correlated_pct:.1f}%)")
    print(f"  ├─ CONFIRMED (static+runtime): {confirmed_count:3d}")
    print(f"  ├─ POTENTIAL (static only):    {potential_count:3d}")
    print(f"  └─ RUNTIME ONLY:               {runtime_only_count:3d}")
    print()

    print(f"ML-SPECIFIC (Domain Threats):   {total_static:3d}  ({static_pct:.1f}%)")
    print(f"  └─ T11-T17 Application Layer:  {len(ml_threats):3d}")
    print()

    print(f"EMPIRICAL (Runtime Analysis):   {total_empirical:3d}  ({empirical_pct:.1f}%)")
    print(f"  ├─ Falco Runtime Detections:  {len(falco_threats):3d}")
    print(f"  ├─ Port Scan Activity:        {len(scan_results):3d}")
    print(f"  ├─ Lateral Movement:          {len(lateral_threats):3d}")
    print(f"  └─ External Connections:      {len(egress_threats):3d}")
    print()

    # Tool-based detection summary
    detected_count = len(tool_results.get('combined_detection', []))
    detection_rate = tool_results.get('combined_detection_rate', 0) * 100
    print(f"TOOL-BASED (Trivy + Kubescape):  {detected_count}/17  ({detection_rate:.1f}%)")
    trivy_data = tool_results.get('tools', {}).get('trivy', {})
    kubescape_data = tool_results.get('tools', {}).get('kubescape', {})
    if trivy_data:
        print(f"  ├─ Trivy:                     {len(trivy_data.get('detected_ground_truth', []))}/17 threats")
    if kubescape_data:
        print(f"  ├─ Kubescape:                 {len(kubescape_data.get('detected_ground_truth', []))}/17 threats")
    print(f"  └─ Detected: {', '.join(tool_results.get('combined_detection', []))}")
    print()
    print("="*80)
    print()
    print("✅ Threat model generation complete!")
    print("   Next steps:")
    print("   1. Review output/threat_summary.json for detailed findings")
    print("   2. Run: ./run_analysis.sh to generate complete analysis with diagrams")
    print()

if __name__ == "__main__":
    main()
