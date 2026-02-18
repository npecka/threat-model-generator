# Dynamic Threat Modeling Framework

Automated, platform-agnostic threat detection framework for cloud-native and distributed systems. Extracts runtime architecture from deployed infrastructure and identifies security threats through multi-modal analysis combining static configuration, runtime observations, and security tool integration.

## Overview

This framework detects architectural security threats across three deployment paradigms:
- **Bare-metal** - VM-based deployments with Docker
- **Kubernetes** - Container orchestration platforms
- **AWS Cloud** - EC2-based cloud deployments

**Key Features:**
- 100% detection of 17 threat types (T01-T17) including ML/AI-specific threats
- Platform-agnostic threat taxonomy
- Runtime-aware analysis combining static and dynamic data
- Integration with 6 security scanning tools (Trivy, Checkov, Kubelinter, Kubescape, Prowler, Docker Bench)
- Zero false positives through runtime flow confirmation

## Repository Structure

```
threat-model-generator/
│
├── dynamic_threat_modeling/          # Deployment configurations
│   ├── bare_metal/                   # VM + Docker deployments
│   ├── cloud_aws/                    # AWS EC2 + Terraform
│   ├── kubernetes/                   # K8s manifests
│   └── ground_truth/                 # Reference architectures
│
├── platforms/                        # Analysis tooling
│   ├── bare_metal/
│   │   ├── analyzer/                 # Threat detection engine
│   │   └── extractor/                # Data collection
│   ├── cloud_aws/
│   │   ├── analyzer/
│   │   └── extractor/
│   ├── kubernetes/
│   │   ├── analyzer/
│   │   └── extractor/
│   └── common/                       # Shared utilities
│
├── tools/                            # Security tool integration
│   └── comparison/                   # Tool comparison framework
│
├── results/                          # Tool output and analysis
│   └── tool_comparison/              # Comparative evaluation results
│
└── docs/                             # Documentation
```

## Quick Start

### Kubernetes Deployment

Deploy ML-enhanced supply chain and detect all 17 threat types:

```bash
# Deploy the vulnerable supply chain
cd dynamic_threat_modeling/kubernetes/supply_chain
kubectl apply -f 00-namespaces.yaml
kubectl apply -f 01-gitea.yaml
kubectl apply -f 02-jenkins.yaml
kubectl apply -f 03-registry.yaml
kubectl apply -f 04-application.yaml
kubectl apply -f 05-mlflow.yaml
kubectl apply -f 06-ml-inference.yaml
kubectl apply -f 07-training-data.yaml

# Wait for pods to be ready
kubectl wait --for=condition=ready pod --all -n dev-zone --timeout=300s
kubectl wait --for=condition=ready pod --all -n cicd-zone --timeout=300s
kubectl wait --for=condition=ready pod --all -n prod-zone --timeout=300s

# Run threat analysis
cd ../../../platforms/kubernetes/analyzer
python main.py
```

**Expected Output:** Detection of 17/17 threats with runtime flow confirmation

### Bare-Metal Deployment

Deploy on three VMs (example IPs: 192.168.100.10, 192.168.100.20, 192.168.100.30):

```bash
cd dynamic_threat_modeling/bare_metal/supply_chain/docker-compose

# On dev VM (192.168.100.10)
docker-compose -f gitea.docker-compose.yml up -d
docker-compose -f training-data.docker-compose.yml up -d

# On CI/CD VM (192.168.100.20)
docker-compose -f jenkins.docker-compose.yml up -d
docker-compose -f registry.docker-compose.yml up -d
docker-compose -f mlflow.docker-compose.yml up -d

# On prod VM (192.168.100.30)
docker-compose -f application.docker-compose.yml up -d
docker-compose -f ml-inference.docker-compose.yml up -d

# Run analysis
cd ../../../../platforms/bare_metal/analyzer
python main.py
```

### AWS Cloud Deployment

```bash
cd dynamic_threat_modeling/cloud_aws/supply_chain/terraform

# Configure AWS credentials
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1

# Deploy infrastructure
terraform init
terraform apply

# Run analysis
cd ../../../../platforms/cloud_aws/analyzer
python main.py
```

## Threat Taxonomy

The framework detects 17 architectural threat types:

**Traditional Infrastructure Threats (T01-T10):**
- T01: Unauthenticated External Access
- T02: Excessive Permissions
- T03: Unencrypted Cross-Boundary Communication
- T04: Missing Network Segmentation
- T05: Anonymous Registry Access
- T06: CI/CD to Production Access
- T07: Missing Audit Logging
- T08: Exposed Secrets in Configuration
- T09: Overly Broad Source Control Access
- T10: Missing Resource Limits

**ML/AI-Specific Threats (T11-T17):**
- T11: Unauthorized Model Access
- T12: Training Data Poisoning
- T13: Model Theft via API
- T14: Unencrypted Model Transfer
- T15: ML Pipeline to Production Access
- T16: Missing Model Provenance
- T17: Exposed Model Metadata

## Key Results

### Detection Accuracy by Platform

| Platform | Threats Detected | False Positives | Runtime Confirmation |
|----------|------------------|-----------------|----------------------|
| Bare-metal | 17/17 (100%) | 0 | ✓ |
| Kubernetes | 17/17 (100%) | 0 | ✓ |
| AWS Cloud | 17/17 (100%) | 0 | ✓ |

### Comparative Evaluation

Comparison against six popular security scanning tools:

| Tool | Threat Detection | Platform Support | ML/AI Threats |
|------|-----------------|------------------|---------------|
| Trivy | 6-11% (1-2/17) | K8s, Containers | 0/7 |
| Checkov | 12-18% (2-3/17) | IaC, K8s | 0/7 |
| Kubelinter | 12% (2/17) | K8s only | 0/7 |
| Kubescape | 41% (7/17) | K8s only | 0/7 |
| Prowler | 47% (8/17) | AWS only | 0/7 |
| Docker Bench | 18% (3/17) | Docker only | 0/7 |
| **Our Framework** | **100% (17/17)** | **All platforms** | **7/7** |

**Key Findings:**
- Static IaC scanners (Trivy, Checkov, Kubelinter): 6-18% detection
- CSPM tools (Kubescape, Prowler, Docker Bench): 18-47% detection
- **No existing tool detects ML/AI-specific architectural threats**
- Our methodology: 100% detection including all 7 ML-specific threats

## Architecture

The framework operates in two phases:

### Phase 1: Extraction
Collects data from deployed infrastructure:
- **Static Configuration:** K8s manifests, Terraform configs, Docker Compose files
- **Runtime Metadata:** Pod details, EC2 instances, VM configurations, RBAC policies
- **Network Flows:** Hubble (K8s), VPC Flow Logs (AWS), tcpdump (bare-metal)
- **Security Events:** Falco runtime events, security tool outputs

### Phase 2: Analysis
Multi-modal threat detection:
1. **Architecture Reconstruction:** Build graph model from extracted metadata
2. **Static Threat Detection:** Analyze configurations for misconfigurations
3. **Runtime Correlation:** Confirm threats using observed network flows
4. **Tool Integration:** Incorporate findings from Trivy, Kubescape, etc.
5. **ML Threat Detection:** Identify ML/AI-specific architectural threats
6. **Threat Correlation:** Cross-reference multiple detection signals

## Requirements

### Core Dependencies
- **Python 3.8+**
- **Kubernetes cluster** (for K8s experiments)
- **kubectl** configured
- **Python packages:**
  ```bash
  pip install kubernetes networkx matplotlib pandas requests boto3
  ```

### Platform-Specific Requirements

**Kubernetes:**
- Cilium/Hubble for network flow observation
- Falco for runtime security events
- Trivy, Kubescape, Kubelinter for tool comparison

**Bare-metal:**
- Docker and Docker Compose
- tcpdump or network flow monitoring
- Docker Bench for security scanning

**AWS:**
- AWS CLI configured
- Terraform 1.0+
- VPC Flow Logs enabled
- Prowler for AWS security assessment

## Tool Integration

The framework integrates with six security scanning tools:

### Kubernetes Tools
- **Trivy:** Container and K8s configuration scanning
- **Kubescape:** K8s security posture management
- **Kubelinter:** K8s YAML static analysis

### AWS Tools
- **Prowler:** AWS security best practices assessment
- **Checkov:** IaC security scanning

### Bare-metal Tools
- **Docker Bench:** Docker security configuration checks

### Running Tool Comparison

```bash
cd tools/comparison

# Run all tools against deployed infrastructure
./run_all_tools.sh

# Parse and map results to threat taxonomy
python parse_tool_results.py

# View comparison table
cat ../../results/tool_comparison/comparison_table.md
```

## Use Cases

### 1. Security Assessment
Identify architectural threats in existing deployments without requiring source code or design documents.

### 2. Continuous Monitoring
Integrate into CI/CD pipelines to detect configuration drift and new threats.

### 3. Multi-Platform Comparison
Compare security posture across different deployment platforms (bare-metal vs K8s vs cloud).

### 4. ML/AI Security
Detect threats specific to machine learning infrastructure (model theft, training data poisoning, etc.).

### 5. Tool Gap Analysis
Understand limitations of existing security scanning tools and their coverage gaps.

## Documentation

- **[Architecture Overview](docs/ARCHITECTURE.md)** - System design and components
- **[Implementation Guide](docs/IMPLEMENTATION.md)** - Detailed setup instructions
- **[Quick Start](docs/QUICK_START.md)** - Getting started guide
- **[Hubble Setup](docs/HUBBLE_SETUP.md)** - Network flow monitoring configuration
- **[Tool Comparison](tools/comparison/README.md)** - Security tool integration guide
- **[Threat Taxonomy](dynamic_threat_modeling/README.md)** - Complete threat descriptions

## Research Paper

This work is described in the paper:

**Title:** Semi-Automated Threat Modeling: Extracting Software Architecture from Configuration Settings to Identify Threats

**Authors:** Nicholas Pecka, Lotfi Ben Othmane, Renee Bryce

**Abstract:** Traditional threat modeling requires manual architecture documentation and expert security knowledge. This framework automates threat detection by extracting runtime architecture from deployed systems and applying platform-agnostic threat patterns. We validate the approach across three platforms (bare-metal, Kubernetes, AWS) with a vulnerable ML supply chain, achieving 100% detection of 17 threat types including 7 ML-specific threats missed by all existing tools.

## Citation

If you use this framework in your research, please cite:

```bibtex
@article{pecka2025dynamic,
  title={Semi-Automated Threat Modeling: Extracting Software Architecture from Configuration Settings to Identify Threats},
  author={Pecka, Nicholas and Ben Othmane, Lotfi and Bryce, Renee},
  year={2025}
}
```

## License

[Specify your license here]

## Contact

- **Nicholas Pecka** - University of North Texas / Red Hat
- Email: nicholaspecka@unt.edu

## Acknowledgments

Research conducted at the University of North Texas in collaboration with Red Hat.
