#!/usr/bin/env python3
"""
Generate a focused threat diagram showing only the vulnerable supply chain
with T1-T10 threats clearly annotated.
"""

import json
import sys

def load_data():
    """Load metadata and extract supply chain info"""
    with open('output/k8s_enhanced_metadata.json', 'r') as f:
        metadata = json.load(f)

    with open('output/model.py', 'r') as f:
        model_content = f.read()

    return metadata, model_content

def extract_threats_from_model(model_content):
    """Extract T01-T10 threats from model.py"""
    threats = {}
    lines = model_content.split('\n')

    current_threat = None
    for i, line in enumerate(lines):
        if "SID='T" in line:
            # Extract SID
            sid = line.split("'")[1]
            current_threat = {'sid': sid, 'description': '', 'severity': '', 'details': ''}
            threats[sid] = current_threat
        elif current_threat and 'description=' in line:
            # Extract description
            desc = line.split("'")[1] if "'" in line else ''
            current_threat['description'] = desc
        elif current_threat and 'severity=' in line:
            # Extract severity
            sev = line.split("'")[1] if "'" in line else ''
            current_threat['severity'] = sev
        elif current_threat and 'details=' in line:
            # Extract details
            det = line.split("'")[1] if "'" in line else ''
            current_threat['details'] = det

    return threats

def map_threats_to_components(metadata, model_content):
    """Map detected threats to specific supply chain components"""
    supply_chain_ns = {'dev-zone', 'cicd-zone', 'prod-zone'}
    pods = [p for p in metadata['pods'] if p['namespace'] in supply_chain_ns]
    # Services is a dict with service names as keys
    services = [(name, data) for name, data in metadata['services'].items() if data['namespace'] in supply_chain_ns]

    # Component to threats mapping
    component_threats = {
        'gitea': [],
        'jenkins': [],
        'registry': [],
        'application': [],
        'postgres': []
    }

    # Parse threats from model
    lines = model_content.split('\n')
    current_sid = None
    current_desc = None

    for line in lines:
        if "SID='T" in line:
            current_sid = line.split("'")[1]
        elif "description=" in line and current_sid:
            current_desc = line.split("'")[1] if "'" in line else ''

            # Map to components
            if 'jenkins' in current_desc.lower():
                component_threats['jenkins'].append((current_sid, current_desc))
            elif 'registry' in current_desc.lower():
                component_threats['registry'].append((current_sid, current_desc))
            elif 'gitea' in current_desc.lower():
                component_threats['gitea'].append((current_sid, current_desc))
            elif 'application' in current_desc.lower():
                component_threats['application'].append((current_sid, current_desc))
            elif 'postgres' in current_desc.lower():
                component_threats['postgres'].append((current_sid, current_desc))
            elif 'cicd-zone' in current_desc.lower():
                # Namespace-level threats apply to all components in that zone
                component_threats['jenkins'].append((current_sid, current_desc))
                component_threats['registry'].append((current_sid, current_desc))
            elif 'dev-zone' in current_desc.lower():
                component_threats['gitea'].append((current_sid, current_desc))
            elif 'prod-zone' in current_desc.lower():
                component_threats['application'].append((current_sid, current_desc))
                component_threats['postgres'].append((current_sid, current_desc))

    return pods, services, component_threats

def generate_dot_diagram(pods, services, component_threats):
    """Generate Graphviz DOT file with threat annotations"""

    # Severity colors
    colors = {
        'Critical': '#FF0000',  # Red
        'High': '#FF6600',      # Orange
        'Medium': '#FFCC00',    # Yellow
        'Low': '#00CC00'        # Green
    }

    dot = []
    dot.append('digraph SupplyChainThreats {')
    dot.append('    rankdir=LR;')
    dot.append('    node [shape=box, style="rounded,filled", fontname="Arial"];')
    dot.append('    edge [fontname="Arial", fontsize=10];')
    dot.append('')
    dot.append('    // Legend')
    dot.append('    subgraph cluster_legend {')
    dot.append('        label="Threat Severity";')
    dot.append('        style=dashed;')
    dot.append('        legend_critical [label="Critical", fillcolor="#FF0000", fontcolor=white];')
    dot.append('        legend_high [label="High", fillcolor="#FF6600", fontcolor=white];')
    dot.append('        legend_medium [label="Medium", fillcolor="#FFCC00"];')
    dot.append('        legend_critical -> legend_high -> legend_medium [style=invis];')
    dot.append('    }')
    dot.append('')

    # Create namespace clusters
    namespaces = {
        'dev-zone': ('Development', '#E6F3FF'),
        'cicd-zone': ('CI/CD Pipeline', '#FFF3E6'),
        'prod-zone': ('Production', '#FFE6E6')
    }

    for ns, (label, bg_color) in namespaces.items():
        dot.append(f'    subgraph cluster_{ns.replace("-", "_")} {{')
        dot.append(f'        label="{label}\\n[{ns}]";')
        dot.append(f'        style=filled;')
        dot.append(f'        fillcolor="{bg_color}";')
        dot.append(f'        fontsize=14;')
        dot.append(f'        fontname="Arial Bold";')
        dot.append('')

        # Add pods in this namespace
        ns_pods = [p for p in pods if p['namespace'] == ns]
        for pod in ns_pods:
            base_name = pod['name'].rsplit('-', 2)[0]  # Get component name

            # Determine component type
            comp = None
            for c in component_threats.keys():
                if c in base_name:
                    comp = c
                    break

            if not comp:
                continue

            threats = component_threats.get(comp, [])
            threat_count = len(set([t[0] for t in threats]))  # Unique threat IDs

            # Determine color based on highest severity
            color = '#90EE90'  # Light green (no threats)
            if threats:
                # Find highest severity among threats
                if any('LoadBalancer' in t[1] or 'Registry' in t[1] or 'secret' in t[1].lower() for t in threats):
                    color = colors['Critical']
                elif any('NetworkPolicies' in t[1] or 'Permissions' in t[1] for t in threats):
                    color = colors['High']
                else:
                    color = colors['Medium']

            # Create label with threat info
            threat_ids = ', '.join(sorted(set([t[0] for t in threats])))
            label = f"{base_name}\\n({threat_count} threats)\\n{threat_ids}"

            fontcolor = 'white' if color in [colors['Critical'], colors['High']] else 'black'

            dot.append(f'        {base_name} [label="{label}", fillcolor="{color}", fontcolor="{fontcolor}"];')

        dot.append('    }')
        dot.append('')

    # Add external actor
    dot.append('    Internet [shape=ellipse, fillcolor="#CCCCCC", label="External\\nUser"];')
    dot.append('')

    # Add flows
    dot.append('    // Supply Chain Flow')
    dot.append('    Internet -> gitea [label="Push Code\\n(T09: Anon Access)"];')
    dot.append('    gitea -> jenkins [label="Trigger Build\\n(T03: HTTP)"];')
    dot.append('    jenkins -> registry [label="Push Image\\n(T05: No Auth)"];')
    dot.append('    registry -> application [label="Pull Image\\n(T03: HTTP)"];')
    dot.append('    application -> postgres [label="Store Data"];')
    dot.append('    Internet -> jenkins [label="External Access\\n(T01: LoadBalancer)", color=red, penwidth=2];')
    dot.append('')

    dot.append('}')

    return '\n'.join(dot)

def generate_threat_table(component_threats):
    """Generate markdown table of all detected threats"""

    table = []
    table.append('# Detected Threats in Supply Chain\\n')
    table.append('| Component | Threat ID | Description |')
    table.append('|-----------|-----------|-------------|')

    for comp, threats in sorted(component_threats.items()):
        if threats:
            unique_threats = {}
            for sid, desc in threats:
                if sid not in unique_threats:
                    unique_threats[sid] = desc

            for sid, desc in sorted(unique_threats.items()):
                # Truncate description
                short_desc = desc[:80] + '...' if len(desc) > 80 else desc
                table.append(f'| {comp} | {sid} | {short_desc} |')

    return '\n'.join(table)

def main():
    print("📊 Generating Supply Chain Threat Diagram...")

    # Load data
    metadata, model_content = load_data()

    # Extract threats and map to components
    pods, services, component_threats = map_threats_to_components(metadata, model_content)

    print(f"  Found {len(pods)} supply chain pods")
    print(f"  Found {len(services)} supply chain services")

    # Count unique threats
    all_threats = set()
    for threats in component_threats.values():
        for sid, _ in threats:
            all_threats.add(sid)
    print(f"  Detected {len(all_threats)} unique threats: {', '.join(sorted(all_threats))}")

    # Generate diagram
    dot_content = generate_dot_diagram(pods, services, component_threats)

    with open('output/supply_chain_threats.dot', 'w') as f:
        f.write(dot_content)
    print("  ✅ Generated output/supply_chain_threats.dot")

    # Generate threat table
    table_content = generate_threat_table(component_threats)

    with open('output/supply_chain_threat_table.md', 'w') as f:
        f.write(table_content)
    print("  ✅ Generated output/supply_chain_threat_table.md")

    print("\n✅ Complete! Next: Convert to PNG:")
    print('  "/mnt/c/Program Files/Graphviz/bin/dot.exe" -Tpng output/supply_chain_threats.dot -o output/supply_chain_threats.png')

if __name__ == '__main__':
    main()
