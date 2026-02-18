#!/usr/bin/env python3
"""
Generate threat diagram using matplotlib for full control over layout and text.
No more text clipping issues!
"""

import matplotlib.pyplot as plt
import matplotlib.patches as patches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Circle
import json

# Load threat data
with open('output/supply_chain_t1_t10_threats.json', 'r') as f:
    data = json.load(f)
    threats = data['supply_chain_threats']

# Group threats by component
from collections import defaultdict
component_threats = defaultdict(list)
for threat in threats:
    comp = threat['component']
    component_threats[comp].append(threat)

# Create figure
fig, ax = plt.subplots(figsize=(20, 12))
ax.set_xlim(0, 20)
ax.set_ylim(0, 12)
ax.axis('off')

# Title
ax.text(10, 11.5, 'Kubernetes Supply Chain - T1-T10 Threat Detection',
        ha='center', va='top', fontsize=18, fontweight='bold')
ax.text(10, 11.0, '(Dynamic Threat Modeling Methodology)',
        ha='center', va='top', fontsize=14, style='italic')

# Color mapping
severity_colors = {
    'Critical': '#FF0000',
    'High': '#FF6600',
    'Medium': '#FFCC00',
    'Low': '#90EE90'
}

def get_component_color(comp):
    """Get color based on highest severity threat"""
    comp_threats = component_threats.get(comp, [])
    # Add namespace-level threats
    for ns in ['dev-zone', 'cicd-zone', 'prod-zone']:
        if ns in component_threats:
            comp_threats.extend(component_threats[ns])

    if not comp_threats:
        return '#90EE90', 'black'

    severities = [t['severity'] for t in comp_threats]
    if 'Critical' in severities:
        return severity_colors['Critical'], 'white'
    elif 'High' in severities:
        return severity_colors['High'], 'white'
    elif 'Medium' in severities:
        return severity_colors['Medium'], 'black'
    else:
        return severity_colors['Low'], 'black'

def get_threat_ids(comp):
    """Get unique threat IDs for component"""
    comp_threats = component_threats.get(comp, [])
    # Add namespace-level threats
    for ns in ['dev-zone', 'cicd-zone', 'prod-zone']:
        if comp in ['gitea'] and ns == 'dev-zone':
            comp_threats.extend(component_threats.get(ns, []))
        elif comp in ['jenkins', 'registry'] and ns == 'cicd-zone':
            comp_threats.extend(component_threats.get(ns, []))
        elif comp in ['application', 'postgres'] and ns == 'prod-zone':
            comp_threats.extend(component_threats.get(ns, []))

    threat_ids = sorted(set([t['id'] for t in comp_threats]))
    return threat_ids

def draw_component(ax, x, y, width, height, name, namespace):
    """Draw a component box with threat info"""
    threat_ids = get_threat_ids(name)
    threat_count = len(component_threats.get(name, [])) + len(component_threats.get(namespace, []))
    color, text_color = get_component_color(name)

    # Draw rounded rectangle
    box = FancyBboxPatch((x, y), width, height,
                          boxstyle="round,pad=0.1",
                          facecolor=color,
                          edgecolor='black',
                          linewidth=2)
    ax.add_patch(box)

    # Add text
    ax.text(x + width/2, y + height - 0.3, f'Pod: {name}',
            ha='center', va='top', fontsize=11, fontweight='bold', color=text_color)
    ax.text(x + width/2, y + height/2, f'{threat_count} threat(s)',
            ha='center', va='center', fontsize=10, color=text_color)
    ax.text(x + width/2, y + 0.25, ', '.join(threat_ids),
            ha='center', va='bottom', fontsize=9, color=text_color, wrap=True)

def draw_namespace(ax, x, y, width, height, ns_name, label, color):
    """Draw namespace boundary"""
    box = FancyBboxPatch((x, y), width, height,
                          boxstyle="round,pad=0.05",
                          facecolor=color,
                          edgecolor='black',
                          linewidth=2,
                          alpha=0.3)
    ax.add_patch(box)

    ax.text(x + width/2, y + height - 0.2, f'K8s Namespace: {ns_name}',
            ha='center', va='top', fontsize=12, fontweight='bold')
    ax.text(x + width/2, y + height - 0.5, label,
            ha='center', va='top', fontsize=11)

def draw_arrow(ax, x1, y1, x2, y2, label, color='black', style='solid', width=2):
    """Draw arrow with label"""
    arrow = FancyArrowPatch((x1, y1), (x2, y2),
                           arrowstyle='->,head_width=0.4,head_length=0.4',
                           color=color,
                           linewidth=width,
                           linestyle=style if style != 'solid' else '-')
    ax.add_patch(arrow)

    # Add label in middle
    mid_x, mid_y = (x1 + x2) / 2, (y1 + y2) / 2
    ax.text(mid_x, mid_y + 0.15, label, ha='center', va='bottom',
            fontsize=9, bbox=dict(boxstyle='round,pad=0.3', facecolor='white', edgecolor='none'))

# Draw namespaces
draw_namespace(ax, 0.5, 2, 3, 7, 'dev-zone', 'Development Zone', '#E6F3FF')
draw_namespace(ax, 4.5, 2, 6.5, 7, 'cicd-zone', 'CI/CD Pipeline', '#FFF3E6')
draw_namespace(ax, 12, 2, 7, 7, 'prod-zone', 'Production', '#FFE6E6')

# Draw components
# Dev zone - gitea
draw_component(ax, 1, 4.5, 2.5, 2.5, 'gitea', 'dev-zone')

# CI/CD zone - jenkins and registry
draw_component(ax, 5, 5.5, 2.5, 2.5, 'jenkins', 'cicd-zone')
draw_component(ax, 8, 5.5, 2.5, 2.5, 'registry', 'cicd-zone')

# Prod zone - application and postgres
draw_component(ax, 12.5, 5.5, 2.5, 2.5, 'application', 'prod-zone')
draw_component(ax, 16, 5.5, 2.5, 2.5, 'postgres', 'prod-zone')

# Draw External Attacker
circle = Circle((1, 1), 0.6, facecolor='#CCCCCC', edgecolor='black', linewidth=2)
ax.add_patch(circle)
ax.text(1, 1, 'External\nAttacker', ha='center', va='center', fontsize=9)

# Draw flows
# External -> Jenkins
draw_arrow(ax, 1.6, 1.2, 5.8, 5.5, 'External Access\n[T01: LoadBalancer]', color='red', width=3)

# Gitea -> Jenkins
draw_arrow(ax, 3.5, 5.7, 5, 6.7, 'Code Push\n[T09]', color='orange', width=2)

# Jenkins -> Registry
draw_arrow(ax, 7.5, 6.7, 8, 6.7, 'Push Image\n[T01, T02, T06, T03]', color='orange', width=2)

# Registry -> Application
draw_arrow(ax, 10.5, 6.7, 12.5, 6.7, 'Pull Image\n[T04, T05]', color='orange', width=2)

# Application -> Postgres
draw_arrow(ax, 15, 6.7, 16, 6.7, 'Store Data\n[T03]', color='black', width=2)

# Jenkins -> Application (T06 - CI/CD to Prod)
draw_arrow(ax, 6.25, 5.4, 13.75, 5.4, 'CI/CD Access\n[T06: Prod Access]',
          color='red', style='dashed', width=3)

# Info boxes in top right
# Kubernetes Environment box
box1 = FancyBboxPatch((14.5, 9.2), 2.3, 1.5,
                      boxstyle="round,pad=0.1",
                      facecolor='#E8F4F8',
                      edgecolor='black',
                      linewidth=1.5,
                      linestyle='--')
ax.add_patch(box1)
ax.text(15.65, 10.5, 'Kubernetes Environment', ha='center', va='top',
        fontsize=10, fontweight='bold')
ax.text(14.6, 10.1, 'Platform: Kubernetes', ha='left', va='top', fontsize=8)
ax.text(14.6, 9.8, 'Namespaces: 3', ha='left', va='top', fontsize=8)
ax.text(14.6, 9.5, 'Pods: 6', ha='left', va='top', fontsize=8)
ax.text(14.6, 9.3, 'Services: 5', ha='left', va='top', fontsize=8)

# Threat Severity box
box2 = FancyBboxPatch((17.2, 9.2), 2.3, 1.5,
                      boxstyle="round,pad=0.1",
                      facecolor='white',
                      edgecolor='black',
                      linewidth=1.5,
                      linestyle='--')
ax.add_patch(box2)
ax.text(18.35, 10.5, 'Threat Severity', ha='center', va='top',
        fontsize=10, fontweight='bold')

# Severity items
y_pos = 10.0
for severity, color in [('Critical', '#FF0000'), ('High', '#FF6600'),
                        ('Medium', '#FFCC00'), ('Safe', '#90EE90')]:
    text_color = 'white' if severity in ['Critical', 'High'] else 'black'
    severity_box = FancyBboxPatch((17.3, y_pos - 0.2), 1.8, 0.25,
                                  boxstyle="round,pad=0.02",
                                  facecolor=color,
                                  edgecolor='none')
    ax.add_patch(severity_box)
    ax.text(18.2, y_pos - 0.075, severity, ha='center', va='center',
            fontsize=8, fontweight='bold', color=text_color)
    y_pos -= 0.3

plt.tight_layout()
plt.savefig('output/t1_t10_threats.png', dpi=300, bbox_inches='tight', facecolor='white')
print("✅ Generated: output/t1_t10_threats.png (matplotlib - no text clipping!)")
