#!/usr/bin/env python3
"""
Ground Truth Architecture Visualizer

Creates publication-quality diagrams from ground truth architecture files.
Generates multiple formats suitable for academic papers (PNG, PDF, SVG).
"""

import json
from pathlib import Path
import subprocess
import sys

try:
    import graphviz
except ImportError:
    print("Error: graphviz module not found")
    print("Install with: pip install graphviz")
    print("Also ensure Graphviz system package is installed:")
    print("  Ubuntu/Debian: sudo apt install graphviz")
    print("  macOS: brew install graphviz")
    print("  Windows: Download from https://graphviz.org/download/")
    sys.exit(1)


class GroundTruthVisualizer:
    """Generate architecture diagrams from ground truth JSON"""

    def __init__(self, ground_truth_path: str):
        self.gt_path = Path(ground_truth_path)
        with open(self.gt_path) as f:
            self.gt = json.load(f)

        self.platform = self.gt["platform"]

        # Color scheme for publication
        self.colors = {
            "dev-zone": "#E8F4F8",      # Light blue
            "cicd-zone": "#FFF4E6",     # Light orange
            "prod-zone": "#F0F8E8",     # Light green
            "ml_component": "#FFE6F0",  # Light pink
            "external": "#F5F5F5",      # Light gray
            "flow_normal": "#666666",   # Dark gray
            "flow_cross_zone": "#D32F2F",  # Red (security concern)
            "flow_ml": "#9C27B0",       # Purple (ML-specific)
        }

    def create_diagram(self, output_dir: Path, formats: list = ['png', 'pdf', 'svg']):
        """Create architecture diagram in multiple formats"""

        print(f"📊 Creating diagram for {self.platform}...")

        # Create Graphviz diagram
        dot = graphviz.Digraph(
            name=f'{self.platform}_architecture',
            comment=f'{self.platform.upper()} Supply Chain Architecture',
            format='png'
        )

        # Graph attributes for publication quality
        dot.attr(
            rankdir='TB',  # Top to bottom
            splines='ortho',  # Orthogonal edges
            nodesep='0.8',
            ranksep='1.2',
            fontname='Arial',
            fontsize='12',
            bgcolor='white'
        )

        # Create trust boundary subgraphs
        trust_zones = self.gt.get("trust_boundaries", {})
        component_zones = self.gt.get("component_zones", {})

        # Group components by zone
        zones_components = {}
        for component, zone in component_zones.items():
            if zone not in zones_components:
                zones_components[zone] = []
            zones_components[zone].append(component)

        # Create subgraph for each trust zone
        for zone_name in ["dev-zone", "cicd-zone", "prod-zone"]:
            if zone_name not in zones_components:
                continue

            zone_type = trust_zones.get(zone_name, "unknown")

            with dot.subgraph(name=f'cluster_{zone_name}') as cluster:
                cluster.attr(
                    label=f'{zone_name}\n({zone_type})',
                    style='filled,rounded',
                    color='black',
                    fillcolor=self.colors.get(zone_name, '#FFFFFF'),
                    fontname='Arial Bold',
                    fontsize='14',
                    labeljust='l'
                )

                # Add components in this zone
                for component in zones_components[zone_name]:
                    self._add_component_node(cluster, component)

        # Add external entity
        dot.node(
            'external',
            label='External\nUsers/Internet',
            shape='cloud',
            style='filled',
            fillcolor=self.colors['external'],
            fontname='Arial',
            fontsize='11'
        )

        # Add flows (edges)
        flows = self.gt.get("flows", [])
        self._add_flows(dot, flows, component_zones)

        # Add legend
        self._add_legend(dot)

        # Save in multiple formats
        output_dir.mkdir(parents=True, exist_ok=True)

        for fmt in formats:
            output_file = output_dir / f"{self.platform}_ground_truth_architecture"

            # Render with specific format
            dot.format = fmt
            output_path = dot.render(
                filename=str(output_file),
                cleanup=True,
                format=fmt
            )

            print(f"   ✅ Created {fmt.upper()}: {output_path}")

        # Also save the DOT source for reference
        dot_source_path = output_dir / f"{self.platform}_ground_truth_architecture.dot"
        with open(dot_source_path, 'w') as f:
            f.write(dot.source)
        print(f"   ✅ Saved DOT source: {dot_source_path}")

        return dot

    def _add_component_node(self, graph, component_name: str):
        """Add a component node with appropriate styling"""

        ml_components = self.gt.get("ml_components", {})
        is_ml = component_name in ml_components

        # Component display name
        display_name = component_name.replace('-', '-\n')  # Line break for readability

        # Determine shape and styling
        if is_ml:
            # ML components get special styling
            ml_info = ml_components[component_name]
            ml_type = ml_info.get("type", "ml_component")

            if ml_type == "model_registry":
                shape = 'cylinder'
                label = f"{display_name}\n[Model Registry]"
            elif ml_type == "inference_service":
                shape = 'component'
                label = f"{display_name}\n[Inference API]"
            elif ml_type == "data_store":
                shape = 'folder'
                label = f"{display_name}\n[Training Data]"
            else:
                shape = 'box'
                label = f"{display_name}\n[ML]"

            fillcolor = self.colors['ml_component']
            style = 'filled,rounded'

        elif 'postgres' in component_name or 'db' in component_name:
            # Database
            shape = 'cylinder'
            label = display_name
            fillcolor = 'white'
            style = 'filled'

        elif 'registry' in component_name:
            # Container registry
            shape = 'folder'
            label = display_name
            fillcolor = 'white'
            style = 'filled'

        else:
            # Regular service
            shape = 'box'
            label = display_name
            fillcolor = 'white'
            style = 'filled,rounded'

        graph.node(
            component_name,
            label=label,
            shape=shape,
            style=style,
            fillcolor=fillcolor,
            fontname='Arial',
            fontsize='11',
            width='1.5',
            height='0.8'
        )

    def _add_flows(self, graph, flows, component_zones):
        """Add flow edges to the graph"""

        for flow in flows:
            src = flow.get("source")
            dst = flow.get("destination")
            flow_type = flow.get("type", "communication")
            protocol = flow.get("protocol", "TCP")

            # Determine if cross-zone
            src_zone = component_zones.get(src, "external")
            dst_zone = component_zones.get(dst, "unknown")
            is_cross_zone = (src != "external") and (src_zone != dst_zone)

            # Determine if ML-related
            ml_components = self.gt.get("ml_components", {})
            is_ml_flow = src in ml_components or dst in ml_components

            # Edge styling based on flow type
            if is_ml_flow:
                color = self.colors['flow_ml']
                style = 'bold'
                penwidth = '2.5'
            elif is_cross_zone:
                color = self.colors['flow_cross_zone']
                style = 'dashed'
                penwidth = '2.0'
            else:
                color = self.colors['flow_normal']
                style = 'solid'
                penwidth = '1.5'

            # Edge label
            if flow_type == "external_access":
                label = f"  {protocol}  "
            else:
                label = f"  {flow_type}\n  {protocol}  "

            graph.edge(
                src,
                dst,
                label=label,
                color=color,
                style=style,
                penwidth=penwidth,
                fontname='Arial',
                fontsize='9',
                fontcolor='#333333'
            )

    def _add_legend(self, graph):
        """Add a legend explaining the diagram elements"""

        with graph.subgraph(name='cluster_legend') as legend:
            legend.attr(
                label='Legend',
                style='filled,rounded',
                color='black',
                fillcolor='#FAFAFA',
                fontname='Arial Bold',
                fontsize='11'
            )

            # Legend nodes (invisible, just for alignment)
            legend.node('leg_title', label='', shape='none', width='0', height='0')

            # Flow type examples
            legend.node('leg_normal', label='Normal Flow', shape='none', fontsize='9')
            legend.node('leg_cross', label='Cross-Zone Flow\n(Security Boundary)', shape='none', fontsize='9')
            legend.node('leg_ml', label='ML-Specific Flow', shape='none', fontsize='9')

            legend.node('leg_ml_comp', label='ML Component', shape='box', style='filled,rounded',
                       fillcolor=self.colors['ml_component'], fontsize='9', width='1.2', height='0.4')

    def create_simplified_diagram(self, output_dir: Path, formats: list = ['png', 'pdf']):
        """Create a simplified diagram focusing on trust boundaries and threats"""

        print(f"📊 Creating simplified threat-focused diagram for {self.platform}...")

        dot = graphviz.Digraph(
            name=f'{self.platform}_threats',
            comment=f'{self.platform.upper()} Threat Landscape',
            format='png'
        )

        dot.attr(
            rankdir='LR',  # Left to right
            splines='ortho',
            nodesep='1.0',
            ranksep='2.0',
            fontname='Arial',
            fontsize='12',
            bgcolor='white'
        )

        # Create trust zones as distinct clusters
        trust_zones = self.gt.get("trust_boundaries", {})
        component_zones = self.gt.get("component_zones", {})

        # Count components and threats per zone
        zone_stats = {}
        for zone in ["dev-zone", "cicd-zone", "prod-zone"]:
            components = [c for c, z in component_zones.items() if z == zone]
            zone_stats[zone] = {
                "components": len(components),
                "example": components[0] if components else "none"
            }

        # Create simplified zone representations
        for zone in ["dev-zone", "cicd-zone", "prod-zone"]:
            zone_type = trust_zones.get(zone, "unknown")
            stats = zone_stats.get(zone, {"components": 0, "example": "none"})

            label = f"{zone}\n({zone_type})\n\n{stats['components']} components\nExample: {stats['example']}"

            dot.node(
                zone,
                label=label,
                shape='box3d',
                style='filled',
                fillcolor=self.colors.get(zone, '#FFFFFF'),
                fontname='Arial',
                fontsize='12',
                width='2.5',
                height='1.5'
            )

        # Add external
        dot.node(
            'external',
            label='External\nThreat\nActors',
            shape='octagon',
            style='filled',
            fillcolor='#FFCCCC',
            fontname='Arial Bold',
            fontsize='12',
            width='2.0',
            height='1.5'
        )

        # Add high-level threat flows
        dot.edge('external', 'dev-zone', label='  T01: Unauthenticated\n  Access  ',
                color='red', style='bold', penwidth='3.0', fontcolor='red')
        dot.edge('external', 'cicd-zone', label='  T01: Exposed\n  CI/CD  ',
                color='red', style='bold', penwidth='3.0', fontcolor='red')
        dot.edge('dev-zone', 'cicd-zone', label='  T06: Pull\n  Source  ',
                color='orange', style='dashed', penwidth='2.0')
        dot.edge('cicd-zone', 'prod-zone', label='  T06: CI/CD→Prod\n  T15: ML Pipeline  ',
                color='red', style='bold', penwidth='3.0', fontcolor='red')

        # Save in multiple formats
        output_dir.mkdir(parents=True, exist_ok=True)

        for fmt in formats:
            output_file = output_dir / f"{self.platform}_threat_landscape"
            dot.format = fmt
            output_path = dot.render(
                filename=str(output_file),
                cleanup=True,
                format=fmt
            )
            print(f"   ✅ Created {fmt.upper()}: {output_path}")

        return dot


def main():
    """Generate visualizations for all ground truth architectures"""

    repo_root = Path(__file__).parent.parent
    gt_dir = repo_root / "dynamic_threat_modeling" / "ground_truth"
    output_dir = repo_root / "dynamic_threat_modeling" / "ground_truth" / "diagrams"

    print("="*80)
    print("GROUND TRUTH ARCHITECTURE VISUALIZER")
    print("="*80)
    print()

    # Check if ground truth files exist
    gt_files = [
        gt_dir / "kubernetes_supply_chain_architecture.json",
        gt_dir / "bare_metal_supply_chain_architecture.json",
        gt_dir / "aws_supply_chain_architecture.json"
    ]

    missing_files = [f for f in gt_files if not f.exists()]
    if missing_files:
        print("❌ Error: Ground truth files not found:")
        for f in missing_files:
            print(f"   {f}")
        print("\nRun generate_ground_truth.py first!")
        sys.exit(1)

    # Generate visualizations for each platform
    for gt_file in gt_files:
        print(f"\n{'='*80}")
        print(f"Platform: {gt_file.stem.split('_')[0].upper()}")
        print(f"{'='*80}\n")

        visualizer = GroundTruthVisualizer(str(gt_file))

        # Create detailed architecture diagram
        visualizer.create_diagram(
            output_dir=output_dir,
            formats=['png', 'pdf', 'svg']
        )

        print()

        # Create simplified threat landscape diagram
        visualizer.create_simplified_diagram(
            output_dir=output_dir,
            formats=['png', 'pdf']
        )

        print()

    print("="*80)
    print("✅ ALL DIAGRAMS GENERATED")
    print("="*80)
    print(f"\nOutput directory: {output_dir}")
    print("\nGenerated files:")
    print("  Detailed Architecture Diagrams:")
    print("    - kubernetes_ground_truth_architecture.png/pdf/svg")
    print("    - bare_metal_ground_truth_architecture.png/pdf/svg")
    print("    - aws_ground_truth_architecture.png/pdf/svg")
    print("\n  Simplified Threat Landscapes:")
    print("    - kubernetes_threat_landscape.png/pdf")
    print("    - bare_metal_threat_landscape.png/pdf")
    print("    - aws_threat_landscape.png/pdf")
    print("\nUse PDF or SVG formats for publication-quality figures in your paper.")
    print()


if __name__ == "__main__":
    main()
