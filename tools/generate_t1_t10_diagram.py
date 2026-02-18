#!/usr/bin/env python3
"""
Generate supply chain diagram showing ONLY T1-T10 threats.
Uses the focused threat analysis results.
"""

import json

def load_threats():
    """Load T1-T10 threat analysis results"""
    with open('output/supply_chain_t1_t10_threats.json', 'r') as f:
        data = json.load(f)
    return data['supply_chain_threats']

def map_threats_to_components(threats):
    """Group threats by component"""
    from collections import defaultdict

    component_threats = defaultdict(list)

    for threat in threats:
        comp = threat['component']
        component_threats[comp].append(threat)

    return dict(component_threats)

def get_severity_color(threats):
    """Determine color based on highest severity"""
    if not threats:
        return '#90EE90', 'black'  # Light green

    severities = [t['severity'] for t in threats]

    if 'Critical' in severities:
        return '#FF0000', 'white'  # Red
    elif 'High' in severities:
        return '#FF6600', 'white'  # Orange
    elif 'Medium' in severities:
        return '#FFCC00', 'black'  # Yellow
    else:
        return '#90EE90', 'black'  # Light green

def generate_diagram(component_threats):
    """Generate DOT diagram with T1-T10 annotations"""

    dot = []
    dot.append('digraph SupplyChainT1T10 {')
    dot.append('    rankdir=LR;')
    dot.append('    node [shape=box, style="rounded,filled", fontname="Arial", fontsize=12, margin="0.6,0.4", height=1.5];')
    dot.append('    edge [fontname="Arial", fontsize=11, labeldistance=3.5, labelangle=0, labelfloat=false, margin=20];')
    dot.append('    graph [fontname="Arial", pad=2.0, ranksep=2.5, nodesep=1.2, splines=polyline];')
    dot.append('')

    # Title with K8s context
    dot.append('    labelloc="t";')
    dot.append('    label="Kubernetes Supply Chain - T1-T10 Threat Detection\\n(Dynamic Threat Modeling Methodology)";')
    dot.append('    fontsize=18;')
    dot.append('    fontname="Arial Bold";')
    dot.append('')


    # Define components with their namespaces
    components = {
        'gitea': 'dev-zone',
        'jenkins': 'cicd-zone',
        'registry': 'cicd-zone',
        'application': 'prod-zone',
        'postgres': 'prod-zone'
    }

    # Group by namespace
    namespaces = {
        'dev-zone': {'label': 'Development Zone', 'color': '#E6F3FF'},
        'cicd-zone': {'label': 'CI/CD Pipeline', 'color': '#FFF3E6'},
        'prod-zone': {'label': 'Production', 'color': '#FFE6E6'}
    }

    for ns, ns_info in namespaces.items():
        dot.append(f'    subgraph cluster_{ns.replace("-", "_")} {{')
        dot.append(f'        label="K8s Namespace: {ns}\\n{ns_info["label"]}";')
        dot.append(f'        style=filled;')
        dot.append(f'        fillcolor="{ns_info["color"]}";')
        dot.append(f'        fontsize=13;')
        dot.append(f'        fontname="Arial Bold";')
        dot.append(f'        labelloc=t;')
        dot.append(f'        margin=35;')
        dot.append(f'        penwidth=2;')
        dot.append(f'        pad=0.5;')
        dot.append('')

        # Add components in this namespace
        for comp, comp_ns in components.items():
            if comp_ns == ns:
                threats = component_threats.get(comp, [])

                # Include namespace-level threats
                ns_threats = component_threats.get(ns, [])
                all_threats = threats + ns_threats

                threat_ids = sorted(set([t['id'] for t in all_threats]))
                threat_count = len(all_threats)

                color, fontcolor = get_severity_color(all_threats)

                if threat_count > 0:
                    label = f"Pod: {comp}\\n{threat_count} threat(s)\\n{', '.join(threat_ids)}"
                else:
                    label = f"Pod: {comp}\\n(no threats)"

                dot.append(f'        {comp} [label="{label}", fillcolor="{color}", fontcolor="{fontcolor}"];')

        dot.append('    }')
        dot.append('')


    # External actor
    dot.append('    Internet [shape=ellipse, fillcolor="#CCCCCC", label="External\\nAttacker"];')
    dot.append('')

    # Data flows with threat annotations
    dot.append('    // Supply Chain Flow with Threats')

    # Check which threats apply to each flow
    def get_flow_threats(source, dest):
        """Get threats relevant to this flow"""
        flow_threats = []

        # Get threats from both source and dest
        for comp in [source, dest]:
            if comp in component_threats:
                flow_threats.extend([t['id'] for t in component_threats[comp]])

        return list(set(flow_threats))

    # Internet -> Jenkins
    jenkins_threats = get_flow_threats('Internet', 'jenkins')
    if 'T01' in jenkins_threats:
        dot.append('    Internet -> jenkins [label="  External Access  \\n  [T01: LoadBalancer]  ", color=red, penwidth=2, fontsize=10];')
    else:
        dot.append('    Internet -> jenkins [label="  Trigger Build  ", fontsize=10];')

    # Gitea -> Jenkins
    gitea_jenkins_threats = get_flow_threats('gitea', 'jenkins')
    threats_label = ', '.join([t for t in gitea_jenkins_threats if t.startswith('T0')])
    if threats_label:
        dot.append(f'    gitea -> jenkins [label="  Code Push  \\n  [{threats_label}]  ", color=orange, fontsize=10];')
    else:
        dot.append('    gitea -> jenkins [label="  Code Push  ", fontsize=10];')

    # Jenkins -> Registry
    jenkins_registry_threats = get_flow_threats('jenkins', 'registry')
    threats_label = ', '.join([t for t in jenkins_registry_threats if t.startswith('T0')])
    if threats_label:
        dot.append(f'    jenkins -> registry [label="  Push Image  \\n  [{threats_label}]  ", color=orange, fontsize=10];')
    else:
        dot.append('    jenkins -> registry [label="  Push Image  ", fontsize=10];')

    # Registry -> Application
    registry_app_threats = get_flow_threats('registry', 'application')
    threats_label = ', '.join([t for t in registry_app_threats if t.startswith('T0')])
    if threats_label:
        dot.append(f'    registry -> application [label="  Pull Image  \\n  [{threats_label}]  ", color=orange, fontsize=10];')
    else:
        dot.append('    registry -> application [label="  Pull Image  ", fontsize=10];')

    # Application -> Postgres
    app_db_threats = get_flow_threats('application', 'postgres')
    threats_label = ', '.join([t for t in app_db_threats if t.startswith('T0')])
    if threats_label:
        dot.append(f'    application -> postgres [label="  Store Data  \\n  [{threats_label}]  ", fontsize=10];')
    else:
        dot.append('    application -> postgres [label="  Store Data  ", fontsize=10];')

    # Jenkins -> Production (T06)
    if 'jenkins' in component_threats and any(t['id'] == 'T06' for t in component_threats['jenkins']):
        dot.append('    jenkins -> application [label="  CI/CD Access  \\n  [T06: Prod Access]  ", color=red, style=dashed, penwidth=2, fontsize=10];')

    dot.append('')

    # Combined info box in top-right (side-by-side layout using HTML table)
    dot.append('    info_box [shape=none, margin=0, label=<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="10" CELLPADDING="8" STYLE="DASHED">')
    dot.append('        <TR>')
    dot.append('            <TD BORDER="1" STYLE="DASHED">')
    dot.append('                <TABLE BORDER="0" CELLBORDER="0" CELLSPACING="2">')
    dot.append('                    <TR><TD COLSPAN="2"><B>Kubernetes Environment</B></TD></TR>')
    dot.append('                    <TR><TD ALIGN="LEFT">Platform: Kubernetes</TD></TR>')
    dot.append('                    <TR><TD ALIGN="LEFT">Namespaces: 3</TD></TR>')
    dot.append('                    <TR><TD ALIGN="LEFT">Pods: 5</TD></TR>')
    dot.append('                    <TR><TD ALIGN="LEFT">Services: 5</TD></TR>')
    dot.append('                </TABLE>')
    dot.append('            </TD>')
    dot.append('            <TD BORDER="1" STYLE="DASHED">')
    dot.append('                <TABLE BORDER="0" CELLBORDER="0" CELLSPACING="2">')
    dot.append('                    <TR><TD COLSPAN="2"><B>Threat Severity</B></TD></TR>')
    dot.append('                    <TR><TD ALIGN="LEFT" BGCOLOR="#FF0000"><FONT COLOR="white"><B>Critical</B></FONT></TD></TR>')
    dot.append('                    <TR><TD ALIGN="LEFT" BGCOLOR="#FF6600"><FONT COLOR="white"><B>High</B></FONT></TD></TR>')
    dot.append('                    <TR><TD ALIGN="LEFT" BGCOLOR="#FFCC00"><B>Medium</B></TD></TR>')
    dot.append('                    <TR><TD ALIGN="LEFT" BGCOLOR="#90EE90"><B>Safe</B></TD></TR>')
    dot.append('                </TABLE>')
    dot.append('            </TD>')
    dot.append('        </TR>')
    dot.append('    </TABLE>>];')
    dot.append('')

    dot.append('}')

    return '\n'.join(dot)

def generate_threat_report(component_threats):
    """Generate detailed threat report"""

    lines = []
    lines.append('# Supply Chain Threat Analysis: T1-T10')
    lines.append('')
    lines.append('## Summary')
    lines.append('')

    total_threats = sum(len(threats) for threats in component_threats.values())
    lines.append(f'**Total Threats**: {total_threats}')
    lines.append('')

    # Count by ID
    from collections import defaultdict
    by_id = defaultdict(int)
    for threats in component_threats.values():
        for t in threats:
            by_id[t['id']] += 1

    lines.append('**Threats by Type**:')
    for tid in sorted(by_id.keys()):
        lines.append(f'- {tid}: {by_id[tid]} instance(s)')
    lines.append('')

    lines.append('## Detailed Findings')
    lines.append('')

    for comp in sorted(component_threats.keys()):
        threats = component_threats[comp]
        if not threats:
            continue

        lines.append(f'### {comp.upper()}')
        lines.append('')
        lines.append(f'**Threats Detected**: {len(threats)}')
        lines.append('')

        for t in sorted(threats, key=lambda x: x['id']):
            lines.append(f'#### {t["id"]} - {t["severity"]}')
            lines.append(f'- **Description**: {t["description"]}')
            lines.append(f'- **Evidence**: {t["evidence"]}')
            lines.append('')

    return '\n'.join(lines)

def main():
    print("=" * 80)
    print("GENERATING T1-T10 THREAT DIAGRAM")
    print("=" * 80)

    # Load threats
    threats = load_threats()
    print(f"\n📊 Loaded {len(threats)} threats")

    # Group by component
    component_threats = map_threats_to_components(threats)
    print(f"  Affecting {len(component_threats)} components")

    # Check coverage
    detected_ids = set()
    for threats in component_threats.values():
        for t in threats:
            detected_ids.add(t['id'])

    print(f"  Threat types detected: {', '.join(sorted(detected_ids))}")

    # Generate diagram
    dot_content = generate_diagram(component_threats)
    with open('output/t1_t10_threats.dot', 'w') as f:
        f.write(dot_content)
    print(f"\n✅ Generated: output/t1_t10_threats.dot")

    # Generate report
    report_content = generate_threat_report(component_threats)
    with open('output/t1_t10_threat_report.md', 'w') as f:
        f.write(report_content)
    print(f"✅ Generated: output/t1_t10_threat_report.md")

    print(f"\n🖼️  Next: Generate PNG diagram:")
    print('  "/mnt/c/Program Files/Graphviz/bin/dot.exe" -Tpng output/t1_t10_threats.dot -o output/t1_t10_threats.png')

    return component_threats

if __name__ == '__main__':
    main()
