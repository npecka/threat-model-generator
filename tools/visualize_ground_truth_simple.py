#!/usr/bin/env python3
"""
Ground Truth Architecture Visualizer (No Dependencies Version)

Creates diagram files that can be rendered separately:
1. DOT files (Graphviz format)
2. Mermaid diagrams (for markdown/paper)
3. PlantUML diagrams (alternative)
"""

import json
from pathlib import Path


class GroundTruthVisualizer:
    """Generate architecture diagrams without external dependencies"""

    def __init__(self, ground_truth_path: str):
        self.gt_path = Path(ground_truth_path)
        with open(self.gt_path) as f:
            self.gt = json.load(f)

        self.platform = self.gt["platform"]

    def generate_dot(self, output_path: Path):
        """Generate Graphviz DOT file"""

        print(f"   Creating DOT file...")

        dot_content = [
            f'digraph "{self.platform}_architecture" {{',
            '  // Graph attributes',
            '  rankdir=TB;',
            '  splines=ortho;',
            '  nodesep=0.8;',
            '  ranksep=1.2;',
            '  fontname="Arial";',
            '  fontsize=12;',
            '  bgcolor=white;',
            '',
            '  // Node defaults',
            '  node [fontname="Arial", fontsize=11, style=filled];',
            '  edge [fontname="Arial", fontsize=9];',
            ''
        ]

        # Trust zones as subgraphs
        component_zones = self.gt.get("component_zones", {})
        trust_boundaries = self.gt.get("trust_boundaries", {})
        ml_components = self.gt.get("ml_components", {})

        # Group components by zone
        zones_components = {}
        for component, zone in component_zones.items():
            if zone not in zones_components:
                zones_components[zone] = []
            zones_components[zone].append(component)

        # Color definitions
        zone_colors = {
            "dev-zone": "#E8F4F8",
            "cicd-zone": "#FFF4E6",
            "prod-zone": "#F0F8E8",
        }

        # Create subgraphs for each zone
        for zone in ["dev-zone", "cicd-zone", "prod-zone"]:
            if zone not in zones_components:
                continue

            zone_type = trust_boundaries.get(zone, "unknown")
            color = zone_colors.get(zone, "#FFFFFF")

            dot_content.append(f'  subgraph cluster_{zone} {{')
            dot_content.append(f'    label="{zone}\\n({zone_type})";')
            dot_content.append(f'    style="filled,rounded";')
            dot_content.append(f'    color=black;')
            dot_content.append(f'    fillcolor="{color}";')
            dot_content.append(f'    fontname="Arial Bold";')
            dot_content.append(f'    fontsize=14;')
            dot_content.append('')

            # Add components
            for component in zones_components[zone]:
                is_ml = component in ml_components

                # Determine shape
                if is_ml:
                    ml_type = ml_components[component].get("type", "")
                    if "registry" in ml_type:
                        shape = "cylinder"
                        label = f"{component}\\n[Model Registry]"
                    elif "inference" in ml_type:
                        shape = "component"
                        label = f"{component}\\n[Inference API]"
                    elif "data" in ml_type:
                        shape = "folder"
                        label = f"{component}\\n[Training Data]"
                    else:
                        shape = "box"
                        label = f"{component}\\n[ML]"
                    fillcolor = "#FFE6F0"
                elif "postgres" in component or "db" in component:
                    shape = "cylinder"
                    label = component
                    fillcolor = "white"
                elif "registry" in component:
                    shape = "folder"
                    label = component
                    fillcolor = "white"
                else:
                    shape = "box"
                    label = component
                    fillcolor = "white"

                dot_content.append(f'    {component} [label="{label}", shape={shape}, fillcolor="{fillcolor}"];')

            dot_content.append('  }')
            dot_content.append('')

        # External entity
        dot_content.append('  external [label="External\\nUsers/Internet", shape=cloud, fillcolor="#F5F5F5"];')
        dot_content.append('')

        # Flows
        flows = self.gt.get("flows", [])
        for flow in flows:
            src = flow.get("source")
            dst = flow.get("destination")
            flow_type = flow.get("type", "")
            protocol = flow.get("protocol", "TCP")

            # Determine if cross-zone
            src_zone = component_zones.get(src, "external")
            dst_zone = component_zones.get(dst, "unknown")
            is_cross_zone = (src != "external") and (src_zone != dst_zone)

            # Styling
            if src in ml_components or dst in ml_components:
                color = "#9C27B0"
                style = "bold"
                penwidth = "2.5"
            elif is_cross_zone:
                color = "#D32F2F"
                style = "dashed"
                penwidth = "2.0"
            else:
                color = "#666666"
                style = "solid"
                penwidth = "1.5"

            label = f"{flow_type}\\n{protocol}" if flow_type else protocol

            dot_content.append(f'  {src} -> {dst} [label=" {label} ", color="{color}", style={style}, penwidth={penwidth}];')

        dot_content.append('}')

        # Write file
        with open(output_path, 'w') as f:
            f.write('\n'.join(dot_content))

        print(f"   ✅ Created: {output_path}")

    def generate_mermaid(self, output_path: Path):
        """Generate Mermaid diagram (great for papers/markdown)"""

        print(f"   Creating Mermaid diagram...")

        mermaid_content = [
            '```mermaid',
            'graph TB',
            '  %% Style definitions',
            '  classDef devZone fill:#E8F4F8,stroke:#333,stroke-width:2px',
            '  classDef cicdZone fill:#FFF4E6,stroke:#333,stroke-width:2px',
            '  classDef prodZone fill:#F0F8E8,stroke:#333,stroke-width:2px',
            '  classDef mlComp fill:#FFE6F0,stroke:#9C27B0,stroke-width:2px',
            '  classDef external fill:#F5F5F5,stroke:#333,stroke-width:2px',
            ''
        ]

        # Define zones as subgraphs
        component_zones = self.gt.get("component_zones", {})
        ml_components = self.gt.get("ml_components", {})

        zones_components = {}
        for component, zone in component_zones.items():
            if zone not in zones_components:
                zones_components[zone] = []
            zones_components[zone].append(component)

        # Create subgraphs
        for zone in ["dev-zone", "cicd-zone", "prod-zone"]:
            if zone not in zones_components:
                continue

            zone_name = zone.replace("-", "_")
            mermaid_content.append(f'  subgraph {zone_name}["{zone}"]')

            for component in zones_components[zone]:
                comp_id = component.replace("-", "_")
                is_ml = component in ml_components

                if is_ml:
                    ml_type = ml_components[component].get("type", "")
                    if "registry" in ml_type:
                        mermaid_content.append(f'    {comp_id}[("{component}<br/>[Model Registry]")]:::mlComp')
                    elif "inference" in ml_type:
                        mermaid_content.append(f'    {comp_id}["{component}<br/>[Inference API]"]:::mlComp')
                    elif "data" in ml_type:
                        mermaid_content.append(f'    {comp_id}[("{component}<br/>[Training Data]")]:::mlComp')
                    else:
                        mermaid_content.append(f'    {comp_id}["{component}<br/>[ML]"]:::mlComp')
                elif "postgres" in component:
                    mermaid_content.append(f'    {comp_id}[("{component}")]')
                elif "registry" in component:
                    mermaid_content.append(f'    {comp_id}[("{component}")]')
                else:
                    mermaid_content.append(f'    {comp_id}["{component}"]')

            mermaid_content.append('  end')
            mermaid_content.append('')

        # External
        mermaid_content.append('  external((External<br/>Users)):::external')
        mermaid_content.append('')

        # Flows
        flows = self.gt.get("flows", [])
        for flow in flows:
            src = flow.get("source").replace("-", "_")
            dst = flow.get("destination").replace("-", "_")
            flow_type = flow.get("type", "")
            protocol = flow.get("protocol", "TCP")

            label = f"{flow_type}<br/>{protocol}" if flow_type else protocol

            # Check if cross-zone or ML
            src_orig = flow.get("source")
            dst_orig = flow.get("destination")

            src_zone = component_zones.get(src_orig, "external")
            dst_zone = component_zones.get(dst_orig, "unknown")
            is_cross_zone = (src_orig != "external") and (src_zone != dst_zone)
            is_ml = src_orig in ml_components or dst_orig in ml_components

            if is_ml:
                mermaid_content.append(f'  {src} -."{label}".-> {dst}')
            elif is_cross_zone:
                mermaid_content.append(f'  {src} =="{label}"==> {dst}')
            else:
                mermaid_content.append(f'  {src} --"{label}"--> {dst}')

        # Apply styles
        for zone in ["dev-zone", "cicd-zone", "prod-zone"]:
            if zone not in zones_components:
                continue
            for component in zones_components[zone]:
                comp_id = component.replace("-", "_")
                if component not in ml_components:
                    zone_class = zone.replace("-", "").replace("_", "") + "Zone"
                    mermaid_content.append(f'  class {comp_id} {zone_class}')

        mermaid_content.append('```')

        # Write file
        with open(output_path, 'w') as f:
            f.write('\n'.join(mermaid_content))

        print(f"   ✅ Created: {output_path}")

    def generate_plantuml(self, output_path: Path):
        """Generate PlantUML diagram"""

        print(f"   Creating PlantUML diagram...")

        puml_content = [
            '@startuml',
            f'title {self.platform.upper()} Supply Chain Architecture',
            '',
            '!define DEVZONE #E8F4F8',
            '!define CICDZONE #FFF4E6',
            '!define PRODZONE #F0F8E8',
            '!define MLCOMP #FFE6F0',
            '',
            'skinparam componentStyle rectangle',
            'skinparam shadowing false',
            ''
        ]

        component_zones = self.gt.get("component_zones", {})
        ml_components = self.gt.get("ml_components", {})

        zones_components = {}
        for component, zone in component_zones.items():
            if zone not in zones_components:
                zones_components[zone] = []
            zones_components[zone].append(component)

        # Create packages for each zone
        zone_mapping = {
            "dev-zone": ("Development Zone", "DEVZONE"),
            "cicd-zone": ("CI/CD Zone", "CICDZONE"),
            "prod-zone": ("Production Zone", "PRODZONE")
        }

        for zone, (zone_label, color) in zone_mapping.items():
            if zone not in zones_components:
                continue

            puml_content.append(f'package "{zone_label}" <<Rectangle>> {color} {{')

            for component in zones_components[zone]:
                is_ml = component in ml_components

                if is_ml:
                    puml_content.append(f'  component "{component}\\n[ML]" as {component} MLCOMP')
                elif "postgres" in component:
                    puml_content.append(f'  database "{component}" as {component}')
                elif "registry" in component:
                    puml_content.append(f'  storage "{component}" as {component}')
                else:
                    puml_content.append(f'  component "{component}" as {component}')

            puml_content.append('}')
            puml_content.append('')

        # External
        puml_content.append('cloud "External Users" as external')
        puml_content.append('')

        # Flows
        flows = self.gt.get("flows", [])
        for flow in flows:
            src = flow.get("source")
            dst = flow.get("destination")
            flow_type = flow.get("type", "")
            protocol = flow.get("protocol", "TCP")

            label = f"{flow_type}\\n{protocol}" if flow_type else protocol

            puml_content.append(f'{src} --> {dst} : {label}')

        puml_content.append('')
        puml_content.append('@enduml')

        # Write file
        with open(output_path, 'w') as f:
            f.write('\n'.join(puml_content))

        print(f"   ✅ Created: {output_path}")


def main():
    """Generate all diagram formats"""

    repo_root = Path(__file__).parent.parent
    gt_dir = repo_root / "dynamic_threat_modeling" / "ground_truth"
    output_dir = repo_root / "dynamic_threat_modeling" / "ground_truth" / "diagrams"
    output_dir.mkdir(parents=True, exist_ok=True)

    print("="*80)
    print("GROUND TRUTH ARCHITECTURE VISUALIZER")
    print("="*80)
    print()

    gt_files = [
        ("kubernetes", gt_dir / "kubernetes_supply_chain_architecture.json"),
        ("bare_metal", gt_dir / "bare_metal_supply_chain_architecture.json"),
        ("aws", gt_dir / "aws_supply_chain_architecture.json")
    ]

    for platform, gt_file in gt_files:
        if not gt_file.exists():
            print(f"⚠️  Skipping {platform}: {gt_file} not found")
            continue

        print(f"\n{'='*80}")
        print(f"Platform: {platform.upper()}")
        print(f"{'='*80}\n")

        visualizer = GroundTruthVisualizer(str(gt_file))

        # Generate DOT file
        dot_path = output_dir / f"{platform}_ground_truth.dot"
        visualizer.generate_dot(dot_path)

        # Generate Mermaid
        mermaid_path = output_dir / f"{platform}_ground_truth.mmd"
        visualizer.generate_mermaid(mermaid_path)

        # Generate PlantUML
        puml_path = output_dir / f"{platform}_ground_truth.puml"
        visualizer.generate_plantuml(puml_path)

        print()

    print("="*80)
    print("✅ ALL DIAGRAM FILES GENERATED")
    print("="*80)
    print(f"\nOutput directory: {output_dir}")
    print("\n📋 How to render diagrams:\n")
    print("1. DOT files (Graphviz):")
    print("   Install: https://graphviz.org/download/")
    print("   Render: dot -Tpng kubernetes_ground_truth.dot -o kubernetes_ground_truth.png")
    print("   Or use: https://dreampuf.github.io/GraphvizOnline/")
    print("\n2. Mermaid files:")
    print("   Online: https://mermaid.live/")
    print("   Or paste directly in GitHub markdown")
    print("\n3. PlantUML files:")
    print("   Online: https://www.plantuml.com/plantuml/")
    print("   Or use PlantUML plugin in your IDE")
    print()


if __name__ == "__main__":
    main()
