# Dynamic Threat Modeling Framework - Project Context

This document provides comprehensive context about the threat-model-generator repository for Claude Code to effectively assist with this research project.

## Project Overview

**Purpose:** Automated, platform-agnostic threat detection framework that extracts runtime architecture from deployed infrastructure and identifies security threats through multi-modal analysis.

**Research Context:** This is a research project for an IEEE journal paper titled "Semi-Automated Threat Modeling: Extracting Software Architecture from Configuration Settings to Identify Threats" by Nicholas Pecka, Lotfi Ben Othmane, and Renee Bryce at the University of North Texas.

**Key Innovation:** Unlike traditional threat modeling that requires manual architecture documentation and expert knowledge, this framework automates threat detection by extracting runtime architecture from deployed systems and applying platform-agnostic threat patterns.

## Deployment Paradigms

The framework validates threat detection across three deployment paradigms:

1. **Bare-metal:** VM-based deployments with Docker Compose
2. **Kubernetes (K8s):** Container orchestration platforms (tested with RKE2 cluster)
3. **AWS Cloud:** EC2-based cloud deployments using Terraform

## Case Studies

### Case Study 1: ML Supply Chain (Original)

**System:** A vulnerable machine learning supply chain system deployed across all three paradigms.

**Components:**
- Gitea (source control)
- Jenkins (CI/CD)
- Container Registry
- Application (web app)
- MLflow (ML experiment tracking)
- ML Inference Service
- Training Data Service

**Deployment Locations:**
- Bare-metal: 3 VMs (dev, cicd, prod zones)
- Kubernetes: RKE2 cluster with namespace-based segmentation
- AWS: EC2 instances across multiple zones

**Threats:** T01-T17 (17 threats total)

**Directory Structure:**
```
dynamic_threat_modeling/
├── bare_metal/supply_chain/docker-compose/
├── kubernetes/supply_chain/
└── cloud_aws/supply_chain/terraform/
```

### Case Study 2: Project Quay High Availability (New)

**System:** Red Hat Project Quay (open-source container registry) deployed in high availability configuration.

**Rationale:** Reviewer feedback requested a larger, more complex system to demonstrate scalability of the approach. Project Quay has ~20 components and represents a production-grade distributed system.

**Components (20 total):**
1. Quay Application (container registry web app)
2. PostgreSQL Database (metadata storage)
3. Redis (caching and session storage)
4. Clair (vulnerability scanner)
5. Minio Object Storage (image blob storage)
6. NGINX Ingress Controller
7. Horizontal Pod Autoscaler
8. Network Policies
9. Service Monitors
10. ConfigMaps and Secrets
11. Persistent Volume Claims
12. TLS certificates
13. RBAC policies
14. LLM Component (professor requirement - smallest model for threat testing)
15-20. Additional HA components (load balancers, health checks, etc.)

**Deployment Strategy:**
- **Bare-metal:** Minimal deployment (1 replica each) - hardware constraints
- **Kubernetes:** Minimal deployment (1 replica each) - current cluster: 1 physical server (32GB RAM, 2TB SSD) with 2 RKE2 nodes via Proxmox VMs
- **AWS:** Full HA deployment (3+ replicas for critical components) - sufficient cloud resources

**Threats:** T01-T21 (21 threats total)
- T01-T17: Carry over from Case Study 1 (apply to all deployments)
- T18-T21: HA-specific threats (AWS deployment only)

**Directory Structure:**
```
dynamic_threat_modeling/
├── bare_metal/quay_ha/docker-compose/
├── kubernetes/quay_ha/
└── cloud_aws/quay_ha/terraform/
```

## Threat Taxonomy

### Traditional Infrastructure Threats (T01-T10)

- **T01: Unauthenticated External Access** - Services exposed without authentication
- **T02: Excessive Permissions** - Overly broad RBAC/IAM permissions
- **T03: Unencrypted Cross-Boundary Communication** - Missing TLS between zones
- **T04: Missing Network Segmentation** - Lack of network isolation
- **T05: Anonymous Registry Access** - Container registry without authentication
- **T06: CI/CD to Production Access** - Build systems with prod access
- **T07: Missing Audit Logging** - Insufficient logging/monitoring
- **T08: Exposed Secrets in Configuration** - Hardcoded credentials
- **T09: Overly Broad Source Control Access** - Excessive git permissions
- **T10: Missing Resource Limits** - No CPU/memory limits

### ML/AI-Specific Threats (T11-T17)

- **T11: Unauthorized Model Access** - ML models accessible without auth
- **T12: Training Data Poisoning** - Unvalidated training data sources
- **T13: Model Theft via API** - Model exfiltration through inference API
- **T14: Unencrypted Model Transfer** - Models transferred without encryption
- **T15: ML Pipeline to Production Access** - Training pipeline accessing prod
- **T16: Missing Model Provenance** - No model lineage tracking
- **T17: Exposed Model Metadata** - Model details leaked in responses

### High Availability Threats (T18-T21) - Case Study 2 Only

- **T18: Split-Brain Scenario** - Cluster partitioning without quorum
- **T19: Cascading Failure** - Service failures propagating through system
- **T20: Inconsistent State Across Replicas** - Data consistency violations
- **T21: Failed Replica Detection Delay** - Slow failure detection in HA setup

## Repository Structure

```
threat-model-generator/
│
├── CLAUDE.md                          # This file - project context
├── README.md                          # Public-facing documentation
├── CHANGELOG.md                       # Version history
├── CONTRIBUTING.md                    # Contribution guidelines
│
├── dynamic_threat_modeling/           # Deployment configurations
│   ├── README.md                      # Threat taxonomy details
│   ├── bare_metal/
│   │   ├── supply_chain/              # Case Study 1: ML Supply Chain
│   │   │   └── docker-compose/
│   │   └── quay_ha/                   # Case Study 2: HA Quay
│   │       └── docker-compose/
│   ├── kubernetes/
│   │   ├── supply_chain/              # Case Study 1: ML Supply Chain
│   │   │   ├── 00-namespaces.yaml
│   │   │   ├── 01-gitea.yaml
│   │   │   ├── 02-jenkins.yaml
│   │   │   ├── 03-registry.yaml
│   │   │   ├── 04-application.yaml
│   │   │   ├── 05-mlflow.yaml
│   │   │   ├── 06-ml-inference.yaml
│   │   │   ├── 07-training-data.yaml
│   │   │   └── ml_components/
│   │   └── quay_ha/                   # Case Study 2: HA Quay
│   │       ├── 00-namespace.yaml
│   │       ├── 01-postgres.yaml
│   │       ├── 02-redis.yaml
│   │       ├── 03-minio.yaml
│   │       ├── 04-quay-config.yaml
│   │       ├── 05-quay-app.yaml
│   │       ├── 06-clair.yaml
│   │       ├── 07-ingress.yaml
│   │       └── 08-llm-service.yaml
│   ├── cloud_aws/
│   │   ├── supply_chain/              # Case Study 1: ML Supply Chain
│   │   │   └── terraform/
│   │   └── quay_ha/                   # Case Study 2: HA Quay
│   │       └── terraform/
│   └── ground_truth/                  # Reference architectures
│
├── platforms/                         # Analysis tooling
│   ├── bare_metal/
│   │   ├── extractor/                 # Data collection from VMs
│   │   └── analyzer/                  # Threat detection engine
│   ├── kubernetes/
│   │   ├── extractor/                 # K8s data collection (Hubble, Falco)
│   │   └── analyzer/                  # K8s threat detection
│   ├── cloud_aws/
│   │   ├── extractor/                 # AWS data collection
│   │   └── analyzer/                  # AWS threat detection
│   └── common/                        # Shared utilities
│
├── tools/                             # Utilities and integrations
│   ├── comparison/                    # Security tool comparison
│   ├── analyze_supply_chain_only.py
│   ├── generate_ground_truth.py
│   └── visualize_ground_truth.py
│
├── results/                           # Experimental results
│   ├── tool_comparison/               # Tool comparison results
│   ├── kubernetes/                    # K8s experiment results
│   └── BARE_METAL_ML_VALIDATION.md
│
└── docs/                              # Additional documentation
    ├── ARCHITECTURE.md
    ├── IMPLEMENTATION.md
    ├── HUBBLE_SETUP.md
    └── HUBBLE_COLLECTION.md
```

## Framework Architecture

The framework operates in two phases:

### Phase 1: Extraction (Extractor)

Collects data from deployed infrastructure:
- **Static Configuration:** K8s manifests, Terraform configs, Docker Compose files
- **Runtime Metadata:** Pod details, EC2 instances, VM configurations, RBAC policies
- **Network Flows:** Hubble (K8s), VPC Flow Logs (AWS), tcpdump (bare-metal)
- **Security Events:** Falco runtime events, security tool outputs

**Location:** `platforms/{platform}/extractor/`

### Phase 2: Analysis (Analyzer)

Multi-modal threat detection:
1. **Architecture Reconstruction:** Build graph model from extracted metadata
2. **Static Threat Detection:** Analyze configurations for misconfigurations
3. **Runtime Correlation:** Confirm threats using observed network flows
4. **Tool Integration:** Incorporate findings from security scanning tools
5. **ML Threat Detection:** Identify ML/AI-specific architectural threats
6. **Threat Correlation:** Cross-reference multiple detection signals

**Location:** `platforms/{platform}/analyzer/`

## Security Tool Integration

The framework integrates with six security scanning tools for comparative evaluation:

### Kubernetes Tools
- **Trivy:** Container and K8s configuration scanning
- **Kubescape:** K8s security posture management
- **Kubelinter:** K8s YAML static analysis

### AWS Tools
- **Prowler:** AWS security best practices assessment
- **Checkov:** IaC security scanning (Terraform)

### Bare-metal Tools
- **Docker Bench:** Docker security configuration checks

### Key Finding
**No existing tool detects ML/AI-specific architectural threats (T11-T17)**
- Static IaC scanners: 6-18% detection rate
- CSPM tools: 18-47% detection rate
- Our framework: 100% detection rate across all platforms

## Hardware Constraints

### Current Kubernetes Cluster
- **Physical Setup:** 1 server running Proxmox hypervisor
- **Specs:** 32GB RAM, 2TB SSD (max upgrade: 64GB RAM)
- **Cluster:** RKE2 with 3 VMs (2 nodes shown in conversation)
- **Limitation:** Cannot run full HA Quay (20 components with multiple replicas)

### Deployment Strategy for Case Study 2
- **Bare-metal/K8s:** Minimal deployment (1 replica per component)
- **AWS:** Full HA deployment (3+ replicas for critical components)
- **Rationale:** Demonstrates framework works with minimal AND HA setups

### Future Hardware Option (Discussed but not implemented)
- 3 physical servers (8-16 core, 32GB RAM, 512GB SSD each)
- True HA bare-metal cluster setup

## Testing and Validation

### Threat Injection Process
1. Deploy the system with intentionally vulnerable configurations
2. Inject specific threat scenarios into manifests/configs
3. Run extractor to collect runtime data
4. Run analyzer to detect threats
5. Validate detection against ground truth

### Validation Tools
The following tools are used to validate threat detection results:

**Kubernetes:**
- Trivy
- Kubescape
- Kubelinter

**AWS:**
- Prowler
- Checkov

**Bare-metal:**
- Docker Bench

### Expected Results
- **Case Study 1:** 100% detection of T01-T17 across all platforms
- **Case Study 2:** 100% detection of T01-T17 across all platforms, plus T18-T21 for AWS HA deployment

## Development Workflow

### Adding New Case Studies
1. Create directory structure under `dynamic_threat_modeling/{platform}/{case_study_name}/`
2. Create deployment manifests (docker-compose, K8s YAML, or Terraform)
3. Inject threats into configurations
4. Update extractor if new data sources needed
5. Update analyzer to detect case-study-specific threats
6. Run experiments and document results

### Updating CLAUDE.md
- Keep this file up-to-date with project changes
- Document design decisions and their rationale
- Include hardware constraints and deployment strategies
- Note any "work in progress" items temporarily, but remove before committing

### Commit Guidelines
- No "work in progress" placeholders in committed code
- Follow existing directory structure and naming conventions
- Update CHANGELOG.md with significant changes
- Ensure README.md stays in sync with major updates

## Research Paper Context

### Current Status
The paper has been submitted to an IEEE journal and received reviewer feedback requesting:
1. A larger, more complex case study system
2. Demonstration of scalability beyond the initial supply chain example

### Response Strategy
Adding Case Study 2 (Project Quay HA) addresses reviewer concerns by:
- Increasing system complexity: 7 components → 20 components
- Demonstrating HA configurations and associated threats
- Showing framework scales to production-grade distributed systems
- Adding threats T18-T21 for HA-specific scenarios

### Validation Requirements
- Expert validation from Red Hat (since they own Quay) - mentioned in conversation
- Re-running Case Study 1 with new threats T18-T21 added to AWS deployment? (discussed but not decided)

## Working Practices

### Multi-Machine Development
- Repository hosted on GitHub: https://github.com/npecka/threat-model-generator
- Also synced to internal Gitea: gitea.lab.internal (accessible only on local network)
- Work may be done across multiple machines
- Always ensure changes are committed and pushed before switching machines

### File Organization
- Keep deployment manifests organized by paradigm and case study
- Mirror directory structure across bare_metal, kubernetes, and cloud_aws
- Use consistent naming: `00-namespace.yaml`, `01-component.yaml`, etc. for K8s
- Use descriptive filenames for docker-compose: `component.docker-compose.yml`

### Claude Code Integration
- Point to this CLAUDE.md file at the start of new sessions
- Use skills like `/k8s-deploy-app` for K8s manifest creation guidance
- Leverage `/gitea-sync` skill to sync with Gitea when on local network

## Key Decisions and Rationale

### Why Project Quay?
- Open-source (not Red Hat Quay which requires licenses)
- ~20 components provides complexity reviewers requested
- Can be deployed across all three paradigms
- Represents real production-grade distributed system
- Red Hat maintains it, enabling expert validation

### Why Not OpenShift?
- Initially considered RHOAI (Red Hat OpenShift AI) or OpenShift operators
- OpenShift is enormous - would need to scope down anyway
- Scoping OpenShift defeats purpose of showing larger system
- Quay is more tractable while still being complex

### Why Minimal Deployments for Bare-metal/K8s?
- Hardware constraints: single server with limited resources
- Full HA setup requires 3+ physical servers
- Budget constraints prevent immediate hardware expansion
- Demonstrates framework works with both minimal AND HA configurations
- AWS deployment shows full HA capabilities

### Why Add LLM Component?
- Professor requirement for the research
- Use smallest available model (just for testing, not production use)
- System is ephemeral (spin up, test threats, spin down)
- Could be integrated as model scanning service for Quay

## Future Work

### Potential Enhancements
- Add more case studies (databases, messaging systems, etc.)
- Expand threat taxonomy beyond T21
- Develop automated threat injection tooling
- Create web-based visualization dashboard
- Integrate with more security scanning tools

### Hardware Upgrade Path
- 3 physical servers for true HA bare-metal cluster
- Each: 8-16 cores, 32GB RAM, 512GB SSD
- Would enable full HA testing across all paradigms

## Quick Reference

### Deploy Case Study 1 (K8s)
```bash
cd dynamic_threat_modeling/kubernetes/supply_chain
kubectl apply -f 00-namespaces.yaml
kubectl apply -f 01-gitea.yaml
kubectl apply -f 02-jenkins.yaml
kubectl apply -f 03-registry.yaml
kubectl apply -f 04-application.yaml
kubectl apply -f 05-mlflow.yaml
kubectl apply -f 06-ml-inference.yaml
kubectl apply -f 07-training-data.yaml
cd ../../../platforms/kubernetes/analyzer
python main.py
```

### Deploy Case Study 2 (K8s) - Minimal
```bash
cd dynamic_threat_modeling/kubernetes/quay_ha
kubectl apply -f 00-namespace.yaml
kubectl apply -f 01-postgres.yaml
kubectl apply -f 02-redis.yaml
kubectl apply -f 03-minio.yaml
kubectl apply -f 04-quay-config.yaml
kubectl apply -f 05-quay-app.yaml
kubectl apply -f 06-clair.yaml
kubectl apply -f 07-ingress.yaml
kubectl apply -f 08-llm-service.yaml
cd ../../../platforms/kubernetes/analyzer
python main.py
```

### Check Current K8s Cluster Status
```bash
kubectl get nodes
kubectl top nodes
kubectl get pods --all-namespaces
```

## Contact Information

**Principal Investigator:**
- Nicholas Pecka
- University of North Texas / Red Hat
- nicholaspecka@unt.edu

**Advisors:**
- Lotfi Ben Othmane
- Renee Bryce

## Version History

See CHANGELOG.md for detailed version history.

---

**Last Updated:** 2026-06-22

**Status:** Case Study 1 complete. Case Study 2 (HA Quay) in development.
