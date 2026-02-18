# main.py

import sys
from pathlib import Path

from namespace_utils import get_user_only_namespaces
from service_pod_mapper import get_service_to_pod_map
from pod_details_fetcher import get_pod_details
from rbac_fetcher import get_rbac_summary
from hubble_fetcher import fetch_hubble_flows
from falco_fetcher import fetch_falco_events_from_ui
from resource_fetcher import get_configmaps, get_network_policies, get_namespace_metadata
from output_writer import write_output

# Add common path for MetricsCollector
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "common"))
try:
    from metrics_collector import MetricsCollector
    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False
    print("⚠️  MetricsCollector not available")

def main():
    print("="*80)
    print("K8S DATA EXTRACTOR - Performance Measurement")
    print("="*80)
    print()

    # Create metrics collector
    metrics = MetricsCollector() if METRICS_AVAILABLE else None

    # Phase 1: Namespace Discovery
    if metrics:
        metrics.start_phase("namespace_discovery")
    print("📋 Discovering user namespaces...")
    user_ns = get_user_only_namespaces()
    print(f"   Found {len(user_ns)} namespaces")
    if metrics:
        metrics.end_phase("namespace_discovery")

    # Phase 2: Service Mapping
    if metrics:
        metrics.start_phase("service_mapping")
    print("🔗 Mapping services to pods...")
    svc_map = get_service_to_pod_map(user_ns)
    print(f"   Mapped {len(svc_map)} services")
    if metrics:
        metrics.end_phase("service_mapping")

    # Phase 3: Pod Details (Kubernetes API calls)
    if metrics:
        metrics.start_phase("kubernetes_api_pods")
    print("📦 Fetching pod details from Kubernetes API...")
    pods = get_pod_details(user_ns, svc_map)
    print(f"   Retrieved {len(pods)} pods")
    if metrics:
        metrics.end_phase("kubernetes_api_pods")

    # Phase 4: RBAC
    if metrics:
        metrics.start_phase("kubernetes_api_rbac")
    print("🔐 Fetching RBAC configuration...")
    rbac = get_rbac_summary()
    print(f"   Retrieved {len(rbac)} RBAC bindings")
    if metrics:
        metrics.end_phase("kubernetes_api_rbac")

    # Phase 5: Hubble Flow Collection
    if metrics:
        metrics.start_phase("hubble_collection")
    print("🌊 Collecting Hubble network flows...")
    hubble_flows = fetch_hubble_flows()  # Auto-detect: use collected file if available, else live query
    print(f"   Collected {len(hubble_flows)} flows")
    if metrics:
        metrics.end_phase("hubble_collection")

    # Phase 6: Falco Events
    if metrics:
        metrics.start_phase("falco_collection")
    print("🛡️  Collecting Falco runtime events...")
    falco_events = fetch_falco_events_from_ui()
    print(f"   Collected {len(falco_events)} events")
    if metrics:
        metrics.end_phase("falco_collection")

    # Phase 7: Additional Resources
    if metrics:
        metrics.start_phase("kubernetes_api_resources")
    print("📄 Fetching additional Kubernetes resources...")
    configmaps = get_configmaps(user_ns)
    network_policies = get_network_policies(user_ns)
    namespaces = get_namespace_metadata(user_ns)
    print(f"   Retrieved {len(configmaps)} configmaps, {len(network_policies)} network policies")
    if metrics:
        metrics.end_phase("kubernetes_api_resources")

    # Phase 8: Write Output
    if metrics:
        metrics.start_phase("output_serialization")
    print("💾 Writing output...")
    output = {
        "pods": pods,
        "services": svc_map,
        "rbac": rbac,
        "hubble_flows": hubble_flows,
        "falco_events": falco_events,
        "configmaps": configmaps,
        "network_policies": network_policies,
        "namespaces": namespaces
    }
    write_output(output)
    print("   ✅ Data written to output/k8s_enhanced_metadata.json")
    if metrics:
        metrics.end_phase("output_serialization")

    # Save metrics
    if metrics:
        print()
        print("="*80)
        print("EXTRACTOR PERFORMANCE METRICS")
        print("="*80)
        metrics.print_summary()

        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)
        metrics.save_report(str(output_dir / "extractor_metrics.json"))
        print()

    print("="*80)
    print("✅ Data extraction complete!")
    print("="*80)

if __name__ == "__main__":
    main()
