# Dynamic Threat Modeling Framework

Automated, platform-agnostic threat detection framework for cloud-native and distributed systems. Extracts runtime architecture from deployed infrastructure and identifies security threats through multi-modal analysis combining static configuration, runtime observations, and security tool integration.

## Overview

This framework detects architectural security threats across three deployment paradigms:
- **Bare-metal** - VM-based deployments with Docker
- **Kubernetes** - Container orchestration platforms
- **AWS Cloud** - EC2-based cloud deployments

**Key Features:**
- 100% detection of 17 threat types (T01-T17) including ML/AI-specific threat types
- Platform-agnostic threat taxonomy
- Runtime-aware analysis combining static and dynamic data
- Integration with 6 security scanning tools (Trivy, Checkov, Kubelinter, Kubescape, Prowler, Docker Bench)
- Zero false positives through runtime flow confirmation
- Validated across two case studies at different scales

## Repository Structure

```
threat-model-generator/
│
├── case_studies/                        # Experimental results
│   ├── cs1_supply_chain/                # Case Study 1: 8-component supply chain
│   │   ├── bare_metal/results/          # Bare-metal detection results
│   │   ├── kubernetes/results/          # Kubernetes detection results
│   │   └── aws/results/                 # AWS detection results
│   └── cs2_quay_registry/              # Case Study 2: 20-component container registry
│       └── aws/results/                 # AWS detection results
│
├── dynamic_threat_modeling/             # Deployment configurations
│   ├── bare_metal/                      # VM + Docker deployments
│   ├── cloud_aws/                       # AWS EC2 + Terraform
│   │   ├── supply_chain/                # CS1 AWS deployment
│   │   └── quay_minimal_single_az/      # CS2 AWS deployment
│   ├── kubernetes/                      # K8s manifests
│   └── ground_truth/                    # Reference architectures
│
├── platforms/                           # Analysis tooling
│   ├── bare_metal/
│   │   ├── analyzer/                    # Threat detection engine
│   │   └── extractor/                   # Data collection
│   ├── cloud_aws/
│   │   ├── analyzer/
│   │   └── extractor/
│   ├── kubernetes/
│   │   ├── analyzer/
│   │   └── extractor/
│   └── common/                          # Shared utilities
│
├── tools/                               # Security tool integration
│   └── comparison/                      # Tool comparison framework
│
├── results/                             # Analysis and comparison data
│   ├── tool_comparison/                 # Comparative evaluation results
│   ├── auspex_comparison/               # Auspex replication comparison
│   └── repeatability/                   # n=5 repeatability validation
│
└── docs/                                # Documentation
```

## Case Studies

### Case Study 1: ML-Enhanced Supply Chain

8-component software supply chain with ML components deployed across bare-metal, Kubernetes, and AWS.

**Components:** Gitea, Jenkins, Docker Registry, Application, PostgreSQL, MLflow, ML Inference Service, Training Data Storage.

| Platform | EC2/VMs | Traditional | ML | Total Instances |
|----------|---------|------------|-----|-----------------|
| Bare-metal | 3 VMs | 42 | 7 | 49 |
| Kubernetes | 3 namespaces | 40 | 7 | 47 |
| AWS | 3 EC2 | 63 | 8 | 71 |

### Case Study 2: Quay Container Registry

20-component enterprise container registry on AWS (2.5x component increase over CS1).

**Components:** Quay Application (x2 HA), PostgreSQL, Redis, Minio, Clair, NGINX, Jenkins, LLM image analysis service, plus supporting infrastructure.

| Platform | EC2 | Traditional | ML | Total Instances |
|----------|-----|------------|-----|-----------------|
| AWS | 7 | 36 | 11 | 47 |

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

**Expected Output:** Detection of 17/17 threat types with runtime flow confirmation

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

### Detection Accuracy

| Platform | CS1 Threat Types | CS1 Instances | CS2 Threat Types | CS2 Instances |
|----------|-------------|---------------|-------------|---------------|
| Bare-metal | 17/17 (100%) | 49 | - | - |
| Kubernetes | 17/17 (100%) | 47 | - | - |
| AWS | 17/17 (100%) | 71 | 17/17 (100%) | 47 |

### Comparative Evaluation

Comparison against security scanning tools and Auspex architectural threat modeling:

| Tool | CS1 Detection | CS2 Detection | ML/AI Threat Types | Approach |
|------|--------------|---------------|---------------|----------|
| **Our Framework** | **17/17 (100%)** | **17/17 (100%)** | **7/7** | Runtime-verified |
| Auspex | 14/17 (82%) | - | 5/7 | Hypothetical (unverified) |
| Prowler | 8/17 (47%) | 10/17 (59%) | 0/7 | AWS only |
| Checkov | 3/17 (18%) | 7/17 (41%) | 0/7 | IaC scanning |
| Kubescape | 7/17 (41%) | - | 0/7 | K8s only |
| Docker Bench | 3/17 (18%) | - | 0/7 | Docker only |
| Trivy | 1/17 (6%) | 5/17 (29%) | 0/7 | Container scanning |
| Kubelinter | 2/17 (12%) | - | 0/7 | K8s YAML analysis |

### Repeatability

n=5 independent runs on AWS demonstrate 100% detection reproducibility (mean=17.0, std=0.0 threat types) for both case studies. See `results/repeatability/` for data.

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

## Documentation

- **[Architecture Overview](docs/ARCHITECTURE.md)** - System design and components
- **[Implementation Guide](docs/IMPLEMENTATION.md)** - Detailed setup instructions
- **[Hubble Setup](docs/HUBBLE_SETUP.md)** - Network flow monitoring configuration
- **[Tool Comparison](tools/comparison/README.md)** - Security tool integration guide
- **[Threat Taxonomy](dynamic_threat_modeling/README.md)** - Complete threat descriptions

## Research Paper

This work is described in the paper:

**Title:** Semi-Automated Threat Modeling of Cloud-Based Systems Through Extracting Software Architecture from Configuration and Network Flow

**Authors:** Nicholas Pecka, Lotfi Ben Othmane, Sai Deepak Bhargava, Renee Bryce

**Venue:** IEEE Transactions on Services Computing (TSC), 2026

## Citation

If you use this framework in your research, please cite:

```bibtex
@article{pecka2026dynamic,
  title={Semi-Automated Threat Modeling of Cloud-Based Systems Through Extracting Software Architecture from Configuration and Network Flow},
  author={Pecka, Nicholas and Ben Othmane, Lotfi and Bhargava, Sai Deepak and Bryce, Renee},
  journal={IEEE Transactions on Services Computing},
  year={2026}
}
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

- **Nicholas Pecka** - University of North Texas / Red Hat
- Email: nicholaspecka@unt.edu

## Acknowledgments

Research conducted at the University of North Texas in collaboration with Red Hat.
