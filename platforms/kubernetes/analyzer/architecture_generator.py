#!/usr/bin/env python3
"""
Ground Truth Architecture Generator

Generates architecture diagrams from K8s runtime data for research validation.
Produces:
1. Visual diagram (PNG via Graphviz)
2. Text representation (for LLM input)
3. Mermaid diagram (for documentation)
"""

import json
from collections import defaultdict


def load_k8s_data(file_path="output/k8s_enhanced_metadata.json"):
    """Load K8s runtime data"""
    with open(file_path) as f:
        return json.load(f)


def build_architecture_model(data):
    """
    Build ground truth architecture from K8s runtime data.

    Returns:
        dict with architecture components, relationships, and metadata
    """
    pods = data.get("pods", [])
    flows = data.get("hubble_flows", [])
    rbac = data.get("rbac", [])

    # Build architecture model
    architecture = {
        "namespaces": {},
        "pods": {},
        "services": {},
        "external_entities": set(),
        "communications": [],
        "trust_boundaries": {},
        "security_contexts": {}
    }

    # Organize pods by namespace (trust boundary)
    namespace_pods = defaultdict(list)
    for pod in pods:
        namespace = pod["namespace"]
        pod_name = pod["name"]

        namespace_pods[namespace].append(pod_name)
        architecture["pods"][pod_name] = {
            "namespace": namespace,
            "ip": pod.get("ip"),
            "labels": pod.get("labels", {}),
            "containers": pod.get("containers", []),
            "serviceAccount": pod.get("serviceAccount", "default"),
            "hostPID": pod.get("hostPID", False),
            "hostNetwork": pod.get("hostNetwork", False),
            "security_issues": []
        }

        # Track security issues
        if pod.get("hostPID"):
            architecture["pods"][pod_name]["security_issues"].append("hostPID=true")
        if pod.get("hostNetwork"):
            architecture["pods"][pod_name]["security_issues"].append("hostNetwork=true")

        # Track service associations
        for svc in pod.get("associated_services", []):
            svc_name = f"{svc['namespace']}/{svc['service']}"
            if svc_name not in architecture["services"]:
                architecture["services"][svc_name] = {
                    "namespace": svc["namespace"],
                    "ip": svc["ip"],
                    "ports": svc["ports"],
                    "pods": []
                }
            architecture["services"][svc_name]["pods"].append(pod_name)

    # Set namespaces
    architecture["namespaces"] = dict(namespace_pods)

    # Classify namespaces as trust boundaries
    for ns in architecture["namespaces"].keys():
        if "prod" in ns.lower():
            architecture["trust_boundaries"][ns] = "production"
        elif "dev" in ns.lower() or "test" in ns.lower():
            architecture["trust_boundaries"][ns] = "development"
        elif "kube-system" in ns or "kube-public" in ns:
            architecture["trust_boundaries"][ns] = "system"
        else:
            architecture["trust_boundaries"][ns] = "application"

    # Extract communication flows from Hubble
    pod_names = set(architecture["pods"].keys())
    seen_flows = set()

    for flow_wrap in flows:
        # Skip non-dict entries (errors, parse failures, strings)
        if not isinstance(flow_wrap, dict):
            continue
        if "flow" not in flow_wrap:
            continue

        flow = flow_wrap["flow"]
        src = flow.get("source", {}).get("pod_name")
        dst = flow.get("destination", {}).get("pod_name")
        dst_labels = flow.get("destination", {}).get("labels", [])
        dst_ip = flow.get("destination", {}).get("ip")

        if not src or src not in pod_names:
            continue

        # External communication
        if "reserved:world" in dst_labels:
            architecture["external_entities"].add("Internet")
            flow_key = (src, "Internet")
            if flow_key not in seen_flows:
                architecture["communications"].append({
                    "source": src,
                    "destination": "Internet",
                    "type": "external_egress",
                    "protocol": "TCP"
                })
                seen_flows.add(flow_key)

        # Internal communication
        elif dst and dst in pod_names:
            flow_key = (src, dst)
            if flow_key not in seen_flows:
                src_ns = architecture["pods"][src]["namespace"]
                dst_ns = architecture["pods"][dst]["namespace"]

                comm_type = "cross_namespace" if src_ns != dst_ns else "intra_namespace"

                architecture["communications"].append({
                    "source": src,
                    "destination": dst,
                    "type": comm_type,
                    "protocol": "TCP",
                    "source_namespace": src_ns,
                    "dest_namespace": dst_ns
                })
                seen_flows.add(flow_key)

    architecture["external_entities"] = list(architecture["external_entities"])

    return architecture


def generate_text_representation(architecture):
    """
    Generate human-readable text representation for LLM input.
    """
    text = []
    text.append("# GROUND TRUTH KUBERNETES ARCHITECTURE")
    text.append("=" * 80)
    text.append("")

    # Summary
    text.append("## Summary")
    text.append(f"- Total Namespaces: {len(architecture['namespaces'])}")
    text.append(f"- Total Pods: {len(architecture['pods'])}")
    text.append(f"- Total Services: {len(architecture['services'])}")
    text.append(f"- External Entities: {len(architecture['external_entities'])}")
    text.append(f"- Communication Flows: {len(architecture['communications'])}")
    text.append("")

    # Trust Boundaries (Namespaces)
    text.append("## Trust Boundaries (Namespaces)")
    text.append("")
    for ns, trust_type in sorted(architecture["trust_boundaries"].items()):
        pod_count = len(architecture["namespaces"][ns])
        text.append(f"### {ns} [{trust_type.upper()}]")
        text.append(f"  Pods: {pod_count}")
        text.append("")

        for pod_name in sorted(architecture["namespaces"][ns]):
            pod = architecture["pods"][pod_name]
            text.append(f"  - {pod_name}")
            text.append(f"    ServiceAccount: {pod['serviceAccount']}")
            if pod["security_issues"]:
                text.append(f"    Security Issues: {', '.join(pod['security_issues'])}")
            text.append(f"    Containers: {', '.join(pod['containers'])}")
        text.append("")

    # External Entities
    if architecture["external_entities"]:
        text.append("## External Entities")
        text.append("")
        for entity in architecture["external_entities"]:
            text.append(f"- {entity}")
        text.append("")

    # Communication Flows
    text.append("## Communication Flows")
    text.append("")

    # Group by type
    intra_ns = [c for c in architecture["communications"] if c["type"] == "intra_namespace"]
    cross_ns = [c for c in architecture["communications"] if c["type"] == "cross_namespace"]
    external = [c for c in architecture["communications"] if c["type"] == "external_egress"]

    if intra_ns:
        text.append("### Intra-Namespace Communications")
        for comm in intra_ns:
            text.append(f"  {comm['source']} -> {comm['destination']} ({comm['protocol']})")
        text.append("")

    if cross_ns:
        text.append("### Cross-Namespace Communications (Trust Boundary Violations)")
        for comm in cross_ns:
            text.append(f"  {comm['source']} ({comm['source_namespace']}) -> {comm['destination']} ({comm['dest_namespace']}) [{comm['protocol']}]")
        text.append("")

    if external:
        text.append("### External Communications")
        for comm in external:
            text.append(f"  {comm['source']} -> {comm['destination']} ({comm['protocol']})")
        text.append("")

    # Services
    if architecture["services"]:
        text.append("## Services")
        text.append("")
        for svc_name, svc_info in sorted(architecture["services"].items()):
            text.append(f"### {svc_name}")
            text.append(f"  IP: {svc_info['ip']}")
            text.append(f"  Ports: {', '.join(str(p['port']) for p in svc_info['ports'])}")
            text.append(f"  Backend Pods: {', '.join(svc_info['pods'])}")
            text.append("")

    return "\n".join(text)


def generate_mermaid_diagram(architecture):
    """
    Generate Mermaid diagram syntax for documentation.
    """
    lines = []
    lines.append("```mermaid")
    lines.append("graph TB")
    lines.append("")

    # External entities
    for entity in architecture["external_entities"]:
        lines.append(f"    {entity}[({entity})]")
        lines.append(f"    style {entity} fill:#ff9999")
    lines.append("")

    # Namespaces as subgraphs
    for ns, trust_type in sorted(architecture["trust_boundaries"].items()):
        # Sanitize namespace name for Mermaid
        ns_id = ns.replace("-", "_").replace(".", "_")

        color = {
            "production": "#ffcccc",
            "development": "#ccffcc",
            "system": "#ccccff",
            "application": "#ffffcc"
        }.get(trust_type, "#eeeeee")

        lines.append(f"    subgraph {ns_id}[{ns} - {trust_type}]")

        for pod_name in architecture["namespaces"][ns]:
            pod_id = pod_name.replace("-", "_").replace(".", "_")
            pod = architecture["pods"][pod_name]

            # Different shapes based on pod type
            if any("db" in c.lower() or "mysql" in c.lower() for c in pod["containers"]):
                shape_start, shape_end = "[(", ")]"  # Cylinder for databases
            else:
                shape_start, shape_end = "[", "]"  # Rectangle for processes

            label = pod_name
            if pod["security_issues"]:
                label += " ⚠️"

            lines.append(f"        {pod_id}{shape_start}{label}{shape_end}")

        lines.append("    end")
        lines.append(f"    style {ns_id} fill:{color}")
        lines.append("")

    # Communications
    for comm in architecture["communications"]:
        src_id = comm["source"].replace("-", "_").replace(".", "_")

        if comm["type"] == "external_egress":
            dst_id = comm["destination"]
        else:
            dst_id = comm["destination"].replace("-", "_").replace(".", "_")

        # Different arrow styles
        if comm["type"] == "cross_namespace":
            arrow = "-.->|cross-ns|"  # Dotted for cross-namespace
        elif comm["type"] == "external_egress":
            arrow = "==>|egress|"  # Thick for external
        else:
            arrow = "-->"  # Normal for intra-namespace

        lines.append(f"    {src_id} {arrow} {dst_id}")

    lines.append("```")
    return "\n".join(lines)


def generate_graphviz_dot(architecture):
    """
    Generate Graphviz DOT format for high-quality diagram rendering.
    """
    lines = []
    lines.append("digraph K8sArchitecture {")
    lines.append("    rankdir=LR;")
    lines.append("    node [shape=box, style=filled];")
    lines.append("    graph [splines=ortho, nodesep=1, ranksep=1.5];")
    lines.append("")

    # External entities
    for entity in architecture["external_entities"]:
        lines.append(f'    "{entity}" [shape=cloud, fillcolor="#ff9999", label="{entity}\\n(External)"];')
    lines.append("")

    # Namespaces as clusters
    for ns, trust_type in sorted(architecture["trust_boundaries"].items()):
        color = {
            "production": "#ffcccc",
            "development": "#ccffcc",
            "system": "#ccccff",
            "application": "#ffffcc"
        }.get(trust_type, "#eeeeee")

        lines.append(f'    subgraph cluster_{ns.replace("-", "_")} {{')
        lines.append(f'        label="{ns}\\n[{trust_type.upper()}]";')
        lines.append(f'        style=filled;')
        lines.append(f'        fillcolor="{color}";')
        lines.append(f'        fontsize=14;')
        lines.append(f'        fontname="Arial Bold";')
        lines.append("")

        for pod_name in architecture["namespaces"][ns]:
            pod = architecture["pods"][pod_name]

            # Choose shape and color based on pod characteristics
            if any("db" in c.lower() or "mysql" in c.lower() for c in pod["containers"]):
                shape = "cylinder"
                color = "#add8e6"
            else:
                shape = "box"
                color = "#90ee90"

            # Mark insecure pods
            if pod["security_issues"]:
                color = "#ffa500"  # Orange for security issues
                label = f"{pod_name}\\n⚠️ {', '.join(pod['security_issues'])}"
            else:
                label = pod_name

            lines.append(f'        "{pod_name}" [shape={shape}, fillcolor="{color}", label="{label}"];')

        lines.append("    }")
        lines.append("")

    # Communications
    for comm in architecture["communications"]:
        src = comm["source"]
        dst = comm["destination"]

        # Different edge styles
        if comm["type"] == "cross_namespace":
            style = 'style=dashed, color=red, penwidth=2, label="CROSS-NS"'
        elif comm["type"] == "external_egress":
            style = 'style=bold, color=orange, penwidth=3, label="EGRESS"'
        else:
            style = 'color=green, penwidth=1.5'

        lines.append(f'    "{src}" -> "{dst}" [{style}];')

    lines.append("}")
    return "\n".join(lines)


def main():
    print("=" * 80)
    print("GROUND TRUTH ARCHITECTURE GENERATOR")
    print("=" * 80)
    print()

    # Load K8s data
    print("📁 Loading K8s runtime data...")
    data = load_k8s_data()
    print(f"   Loaded: {len(data.get('pods', []))} pods, {len(data.get('hubble_flows', []))} flows")
    print()

    # Build architecture model
    print("🏗️  Building architecture model...")
    architecture = build_architecture_model(data)
    print(f"   Namespaces: {len(architecture['namespaces'])}")
    print(f"   Pods: {len(architecture['pods'])}")
    print(f"   Communications: {len(architecture['communications'])}")
    print()

    # Generate text representation
    print("📝 Generating text representation...")
    text_repr = generate_text_representation(architecture)
    with open("output/ground_truth_architecture.txt", "w", encoding="utf-8") as f:
        f.write(text_repr)
    print("   ✅ Saved to output/ground_truth_architecture.txt")

    # Generate Mermaid diagram
    print("📊 Generating Mermaid diagram...")
    mermaid = generate_mermaid_diagram(architecture)
    with open("output/ground_truth_architecture_mermaid.md", "w", encoding="utf-8") as f:
        f.write("# Ground Truth Architecture\n\n")
        f.write(mermaid)
    print("   ✅ Saved to output/ground_truth_architecture_mermaid.md")

    # Generate Graphviz DOT
    print("🎨 Generating Graphviz diagram...")
    dot = generate_graphviz_dot(architecture)
    with open("output/ground_truth_architecture.dot", "w", encoding="utf-8") as f:
        f.write(dot)
    print("   ✅ Saved to output/ground_truth_architecture.dot")

    # Render diagram if Graphviz is available
    try:
        import subprocess
        print("   🖼️  Rendering PNG diagram...")
        result = subprocess.run(
            ["dot", "-Tpng", "output/ground_truth_architecture.dot", "-o", "output/ground_truth_architecture.png"],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            print("   ✅ Saved to output/ground_truth_architecture.png")
        else:
            print(f"   ⚠️  Graphviz failed: {result.stderr}")
            print("   💡 Install Graphviz: apt-get install graphviz (Linux) or brew install graphviz (Mac)")
    except FileNotFoundError:
        print("   ⚠️  Graphviz not found - skipping PNG generation")
        print("   💡 Install Graphviz to generate PNG: apt-get install graphviz")
    except Exception as e:
        print(f"   ⚠️  Could not render PNG: {e}")

    # Save architecture JSON for programmatic access
    print("💾 Saving architecture model (JSON)...")
    # Convert sets to lists for JSON serialization
    arch_json = {
        "namespaces": architecture["namespaces"],
        "pods": architecture["pods"],
        "services": architecture["services"],
        "external_entities": architecture["external_entities"],
        "communications": architecture["communications"],
        "trust_boundaries": architecture["trust_boundaries"]
    }
    with open("output/ground_truth_architecture.json", "w", encoding="utf-8") as f:
        json.dump(arch_json, f, indent=2)
    print("   ✅ Saved to output/ground_truth_architecture.json")

    print()
    print("=" * 80)
    print("✅ ARCHITECTURE GENERATION COMPLETE")
    print("=" * 80)
    print()
    print("Generated files:")
    print("  📄 output/ground_truth_architecture.txt - Text representation (for LLM)")
    print("  📊 output/ground_truth_architecture_mermaid.md - Mermaid diagram")
    print("  🎨 output/ground_truth_architecture.dot - Graphviz source")
    print("  🖼️  output/ground_truth_architecture.png - Visual diagram (if Graphviz available)")
    print("  💾 output/ground_truth_architecture.json - Structured data")
    print()
    print("Usage for LLM:")
    print("  Copy output/ground_truth_architecture.txt and paste into your LLM prompt")
    print()
    print("Usage for paper:")
    print("  Include output/ground_truth_architecture.png in your figures")
    print()


if __name__ == "__main__":
    main()
