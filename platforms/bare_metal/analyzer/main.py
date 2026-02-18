#!/usr/bin/env python3
"""
Bare-Metal Threat Analyzer
Orchestrates 4-phase dynamic threat modeling methodology for bare-metal deployments.

METHODOLOGY:
- Phase 1: Data Extraction (completed by extractor)
- Phase 2: Threat Model Construction (PyTM model from runtime observations)
- Phase 3: Multi-Modal Threat Detection (Docker Bench + Checkov)
- Phase 4: Runtime Validation & Prioritization (correlate static findings with flows)
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Add parent directories to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from common.metrics_collector import MetricsCollector

# Import platform-specific modules
from tool_integrator import integrate_tools
from threat_correlator import correlate_threats
from model_builder import build_pytm_model

OUTPUT_DIR = Path("platforms/bare_metal/analyzer/output")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def load_metadata(filename="bare_metal_metadata.json"):
    """Load collected metadata from extractor (Phase 1 output)"""
    input_path = Path("platforms/bare_metal/extractor/output") / filename

    if not os.path.exists(input_path):
        print(f"ERROR: Metadata file not found: {input_path}")
        print("Please run the extractor first:")
        print("  cd platforms/bare_metal/extractor && python3 main.py")
        sys.exit(1)

    with open(input_path, 'r') as f:
        return json.load(f)


def main():
    print("=" * 80)
    print("BARE-METAL DYNAMIC THREAT MODELING")
    print("=" * 80)
    print()

    # Initialize metrics collector
    metrics = MetricsCollector()

    # =========================================================================
    # PHASE 1: DATA EXTRACTION (already done by extractor)
    # =========================================================================
    print("📁 Phase 1: Loading extracted runtime data...")
    metrics.start_phase("data_collection")
    metadata = load_metadata()

    vms = metadata.get('vms', [])
    containers = []
    for vm in vms:
        # Add VM name to each container for mapping
        for container in vm.get('docker_containers', []):
            container['host'] = vm.get('name', vm.get('ip', ''))
            containers.append(container)

    flows = metadata.get('network_flows', [])
    config_files = metadata.get('config_files', [])
    metrics.end_phase("data_collection")

    print(f"   ✅ Loaded: {len(vms)} VMs, {len(containers)} containers")
    print(f"      Network flows: {len(flows)}")
    print(f"      Config files: {len(config_files)}")
    print()

    # =========================================================================
    # PHASE 3: MULTI-MODAL THREAT DETECTION
    # =========================================================================
    print("=" * 80)
    print("🔍 Phase 3: Multi-Modal Threat Detection")
    print("=" * 80)
    print()

    print("   Running security scanning tools...")
    print("   - Docker Bench Security (CSPM for bare-metal)")
    print("   - Checkov (Static IaC analysis)")
    print()

    # Run tool integration (Docker Bench + Checkov)
    metrics.start_phase("threat_detection")
    tool_results = integrate_tools()
    metrics.end_phase("threat_detection")

    detected_threats = tool_results.get('combined_detection', [])
    detection_summary = tool_results.get('detection_summary', {})

    print(f"   ✅ Detected {detection_summary.get('detected', 0)}/{detection_summary.get('total_threats', 17)} threats")
    print(f"      Detection rate: {detection_summary.get('detection_rate', 0):.1%}")
    print()

    # =========================================================================
    # PHASE 4: RUNTIME VALIDATION & PRIORITIZATION
    # =========================================================================
    print("=" * 80)
    print("🔗 Phase 4: Runtime Validation & Prioritization")
    print("=" * 80)
    print()

    print("   Correlating static findings with runtime network flows...")
    metrics.start_phase("threat_correlation")
    correlated_threats = correlate_threats(tool_results, metadata)
    metrics.end_phase("threat_correlation")

    # Summarize correlation results
    confirmed_count = sum(1 for t in correlated_threats if t.get('validation_status') == 'CONFIRMED')
    potential_count = sum(1 for t in correlated_threats if t.get('validation_status') == 'POTENTIAL')
    unvalidated_count = sum(1 for t in correlated_threats if t.get('validation_status') == 'UNVALIDATED')

    print(f"   ✅ Correlated {len(correlated_threats)} threats:")
    print(f"      CONFIRMED (static + runtime): {confirmed_count}")
    print(f"      POTENTIAL (static only): {potential_count}")
    print(f"      UNVALIDATED (cannot verify): {unvalidated_count}")
    print()

    # =========================================================================
    # PHASE 2: THREAT MODEL CONSTRUCTION
    # =========================================================================
    print("=" * 80)
    print("📝 Phase 2: Threat Model Construction (PyTM)")
    print("=" * 80)
    print()

    print("   Building PyTM threat model from runtime observations...")

    # Build PyTM model with correlated threats
    metrics.start_phase("model_building")
    model_lines, dfd_entities, dfd_flows = build_pytm_model(
        vms=vms,
        containers=containers,
        flows=flows,
        correlated_threats=correlated_threats
    )

    # Save PyTM model
    model_output = OUTPUT_DIR / "model.py"
    with open(model_output, "w") as f:
        f.write("\n".join(model_lines))
    print(f"   ✅ {model_output} generated")

    # Save DFD text summary
    dfd_output = OUTPUT_DIR / "dfd_summary.txt"
    with open(dfd_output, "w") as f:
        f.write("# Data Flow Diagram Summary\n\n")
        f.write(f"Entities: {len(dfd_entities)}\n")
        f.write(f"Flows: {len(dfd_flows)}\n\n")
        f.write("## Trust Boundaries\n")
        zones = set(e['boundary'] for e in dfd_entities)
        for zone in zones:
            f.write(f"- {zone}\n")
        f.write("\n## Components\n")
        for entity in dfd_entities:
            f.write(f"- [{entity['type']}] {entity['name']} ({entity['boundary']})\n")
    print(f"   ✅ {dfd_output} generated")
    metrics.end_phase("model_building")
    print()

    # =========================================================================
    # GENERATE THREAT SUMMARY REPORT
    # =========================================================================
    print("=" * 80)
    print("📊 Generating Comprehensive Threat Report")
    print("=" * 80)
    print()

    metrics.start_phase("report_generation")
    threat_summary = {
        "platform": "bare-metal",
        "analysis_time": datetime.now().isoformat(),
        "methodology": "4-phase dynamic threat modeling",
        "phases": {
            "phase_1_data_extraction": {
                "vms": len(vms),
                "containers": len(containers),
                "network_flows": len(flows),
                "config_files": len(config_files)
            },
            "phase_2_threat_model": {
                "entities": len(dfd_entities),
                "dataflows": len(dfd_flows),
                "trust_boundaries": len(set(e['boundary'] for e in dfd_entities))
            },
            "phase_3_threat_detection": {
                "tools_used": ["docker_bench", "checkov"],
                "total_detected": len(detected_threats),
                "detected_threats": detected_threats,
                "detection_rate": detection_summary.get('detection_rate', 0)
            },
            "phase_4_correlation": {
                "total_correlated": len(correlated_threats),
                "confirmed": confirmed_count,
                "potential": potential_count,
                "unvalidated": unvalidated_count,
                "correlated_threats": correlated_threats
            }
        },
        "summary": {
            "total_threats": len(correlated_threats),
            "critical_severity": sum(1 for t in correlated_threats if t.get('severity') == 'CRITICAL'),
            "high_severity": sum(1 for t in correlated_threats if t.get('severity') == 'HIGH'),
            "medium_severity": sum(1 for t in correlated_threats if t.get('severity') == 'MEDIUM'),
            "high_confidence": sum(1 for t in correlated_threats if t.get('confidence') == 'HIGH'),
            "medium_confidence": sum(1 for t in correlated_threats if t.get('confidence') == 'MEDIUM')
        }
    }

    # Save comprehensive threat summary
    summary_output = OUTPUT_DIR / "threat_summary.json"
    with open(summary_output, 'w') as f:
        json.dump(threat_summary, f, indent=2)
    print(f"   ✅ {summary_output} generated")

    # Save tool results
    tool_output = OUTPUT_DIR / "tool_results.json"
    with open(tool_output, 'w') as f:
        json.dump(tool_results, f, indent=2)
    print(f"   ✅ {tool_output} generated")
    metrics.end_phase("report_generation")
    print()

    # =========================================================================
    # GENERATE METRICS REPORT
    # =========================================================================
    print("=" * 80)
    print("📈 Performance Metrics Report")
    print("=" * 80)
    print()

    # Load extractor metrics if available
    extractor_metrics_path = Path("platforms/bare_metal/extractor/output/extractor_metrics.json")
    extractor_metrics = {}
    if extractor_metrics_path.exists():
        with open(extractor_metrics_path, 'r') as f:
            extractor_metrics = json.load(f)

    # Generate analyzer metrics
    analyzer_metrics = metrics.generate_report()

    # Combine metrics
    combined_metrics = {
        "end_to_end_overhead": {},
        "extractor_performance": extractor_metrics.get('performance', {}),
        "analyzer_performance": analyzer_metrics.get('performance', {}),
    }

    # Calculate end-to-end overhead
    extractor_time = extractor_metrics.get('performance', {}).get('total_time_seconds', 0)
    analyzer_time = analyzer_metrics.get('performance', {}).get('total_time_seconds', 0)
    total_time = extractor_time + analyzer_time

    if total_time > 0:
        combined_metrics["end_to_end_overhead"] = {
            "total_time_seconds": total_time,
            "extraction_time_seconds": extractor_time,
            "analysis_time_seconds": analyzer_time,
            "extraction_percentage": (extractor_time / total_time) * 100,
            "analysis_percentage": (analyzer_time / total_time) * 100,
            "peak_memory_mb": max(
                extractor_metrics.get('performance', {}).get('max_memory_mb', 0),
                analyzer_metrics.get('performance', {}).get('max_memory_mb', 0)
            ),
            "weighted_avg_cpu_percent": (
                (extractor_metrics.get('performance', {}).get('avg_cpu_percent', 0) * extractor_time +
                 analyzer_metrics.get('performance', {}).get('avg_cpu_percent', 0) * analyzer_time) / total_time
            ) if total_time > 0 else 0
        }

    # Save combined metrics
    metrics_output = OUTPUT_DIR / "metrics_report.json"
    with open(metrics_output, 'w') as f:
        json.dump(combined_metrics, f, indent=2)
    print(f"   ✅ {metrics_output} generated")
    print()

    # Print metrics summary
    print("END-TO-END OVERHEAD:")
    print(f"  Total time:        {total_time:.2f}s")
    print(f"    Extraction:      {extractor_time:.2f}s ({combined_metrics['end_to_end_overhead'].get('extraction_percentage', 0):.1f}%)")
    print(f"    Analysis:        {analyzer_time:.2f}s ({combined_metrics['end_to_end_overhead'].get('analysis_percentage', 0):.1f}%)")
    print(f"  Peak memory:       {combined_metrics['end_to_end_overhead'].get('peak_memory_mb', 0):.1f} MB")
    print(f"  Avg CPU:           {combined_metrics['end_to_end_overhead'].get('weighted_avg_cpu_percent', 0):.1f}%")
    print()

    print("ANALYZER PHASE BREAKDOWN:")
    for phase, time_s in analyzer_metrics.get('performance', {}).get('phase_breakdown', {}).items():
        pct = (time_s / analyzer_time) * 100 if analyzer_time > 0 else 0
        print(f"  {phase:30s} {time_s:6.2f}s ({pct:5.1f}%)")
    print()

    # Print summary
    print_threat_summary(threat_summary)

    print("=" * 80)
    print("✓ Analysis Complete")
    print("=" * 80)
    print()


def print_threat_summary(report):
    """Print human-readable threat summary"""
    print("THREAT DETECTION SUMMARY")
    print("-" * 80)

    phase_4 = report['phases']['phase_4_correlation']
    print(f"Total Correlated Threats: {phase_4['total_correlated']}")
    print()
    print("By Validation Status:")
    print(f"  CONFIRMED (static + runtime):  {phase_4['confirmed']}")
    print(f"  POTENTIAL (static only):       {phase_4['potential']}")
    print(f"  UNVALIDATED (cannot verify):   {phase_4['unvalidated']}")
    print()

    summary = report['summary']
    print("By Severity:")
    print(f"  CRITICAL: {summary['critical_severity']}")
    print(f"  HIGH:     {summary['high_severity']}")
    print(f"  MEDIUM:   {summary['medium_severity']}")
    print()

    print("By Confidence:")
    print(f"  HIGH:     {summary['high_confidence']}")
    print(f"  MEDIUM:   {summary['medium_confidence']}")
    print()

    # Show top threats
    print("Top Validated Threats:")
    print("-" * 80)
    correlated = sorted(
        phase_4['correlated_threats'],
        key=lambda t: (t.get('severity') == 'CRITICAL', t.get('confidence') == 'HIGH'),
        reverse=True
    )
    for threat in correlated[:5]:
        threat_id = threat.get('threat_id', 'UNKNOWN')
        status = threat.get('validation_status', 'UNKNOWN')
        confidence = threat.get('confidence', 'UNKNOWN')
        severity = threat.get('severity', 'UNKNOWN')
        print(f"  [{threat_id}] {status} | Severity: {severity} | Confidence: {confidence}")

    print()


if __name__ == "__main__":
    main()
