# Dynamic Threat Modeling Case Studies

This directory contains deployment configurations for the dynamic threat modeling paper:
**"Semi-Automated Threat Modeling: Extracting Software Architecture from Configuration Settings to Identify Threats"**

## Paper Location
`paper-automated-threat-modeling/paper.tex`

## Overview

This case study validates platform-agnostic threat detection across three deployment paradigms:
- **Bare-metal** (VMs with Docker)
- **Kubernetes** (container orchestration)
- **AWS Cloud** (EC2 instances)

Each platform deploys an identical 8-component ML-enhanced software supply chain:
1. Gitea (source control)
2. Jenkins (CI/CD)
3. Docker Registry (artifacts)
4. Application (web service)
5. PostgreSQL (database)
6. MLflow (model registry)
7. ML Inference Service
8. Training Data Storage

## Threat Taxonomy

The deployments intentionally contain 17 threat types:
- **T01-T10:** Traditional infrastructure threats
- **T11-T17:** ML/AI-specific architectural threats

See `paper-automated-threat-modeling/paper.tex` Table 2 for complete threat taxonomy.

## Deployment Instructions

### Bare-Metal

Deploy on three VMs (example IPs: 192.168.100.10, 192.168.100.20, 192.168.100.30):

```bash
cd bare_metal/supply_chain/docker-compose

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
```

### Kubernetes

```bash
cd kubernetes/supply_chain

# Deploy base supply chain
kubectl apply -f 00-namespaces.yaml
kubectl apply -f 01-gitea.yaml
kubectl apply -f 02-jenkins.yaml
kubectl apply -f 03-registry.yaml
kubectl apply -f 04-application.yaml

# Deploy ML components
kubectl apply -f 05-mlflow.yaml
kubectl apply -f 06-ml-inference.yaml
kubectl apply -f 07-training-data.yaml

# Verify deployment
kubectl get pods -n dev-zone
kubectl get pods -n cicd-zone
kubectl get pods -n prod-zone
```

### AWS Cloud

```bash
cd cloud_aws/supply_chain/terraform

# Initialize Terraform
terraform init

# Review plan
terraform plan

# Deploy infrastructure
terraform apply

# Get instance IPs
terraform output
```

## Analysis

Run threat detection using platform-specific analyzers:

### Kubernetes
```bash
cd ../../../platforms/kubernetes/analyzer
python main.py
```

### Bare-metal
```bash
cd ../../../platforms/bare_metal/analyzer
python main.py
```

### AWS
```bash
cd ../../../platforms/cloud_aws/analyzer
python main.py
```

## Expected Results

All platforms should achieve:
- **100% threat detection** (17/17 threat types)
- **Zero false positives**
- **Runtime flow confirmation**

### Detection Coverage by Platform

| Threat ID | Threat Type | Bare-Metal | Kubernetes | AWS |
|-----------|-------------|------------|------------|-----|
| T01 | Unauthenticated Access | ✓ | ✓ | ✓ |
| T02 | Excessive Permissions | ✓ | ✓ | ✓ |
| T03 | Unencrypted Communication | ✓ | ✓ | ✓ |
| T04 | Network Segmentation | ✓ | ✓ | ✓ |
| T05 | Anonymous Registry | ✓ | ✓ | ✓ |
| T06 | CI/CD to Prod Access | ✓ | ✓ | ✓ |
| T07 | Missing Logging | ✓ | ✓ | ✓ |
| T08 | Exposed Secrets | ✓ | ✓ | ✓ |
| T09 | Broad Source Access | ✓ | ✓ | ✓ |
| T10 | Resource Limits | ✓ | ✓ | ✓ |
| T11 | Unauthorized Model Access | ✓ | ✓ | ✓ |
| T12 | Training Data Poisoning | ✓ | ✓ | ✓ |
| T13 | Model Theft via API | ✓ | ✓ | ✓ |
| T14 | Unencrypted Model Transfer | ✓ | ✓ | ✓ |
| T15 | ML Pipeline to Prod Access | ✓ | ✓ | ✓ |
| T16 | Missing Model Provenance | ✓ | ✓ | ✓ |
| T17 | Exposed Model Metadata | ✓ | ✓ | ✓ |

See paper Section 3.5 for detailed results and comparative evaluation against six security scanning tools.

## Platform-Specific Threat Implementations

Each threat manifests through platform-specific mechanisms while maintaining conceptual equivalence:

**Example: T01 (Unauthenticated External Access)**
- **Bare-metal:** Jenkins VM exposed on public network interface with no firewall restrictions
- **Kubernetes:** Jenkins Service type LoadBalancer with no NetworkPolicy or authentication
- **AWS:** Jenkins EC2 Security Group allowing 0.0.0.0/0 ingress on port 8080

This design validates that our methodology's abstract constructs correctly identify threats independent of platform-specific implementation details.

## Directory Structure

```
dynamic_threat_modeling/
├── bare_metal/
│   └── supply_chain/
│       └── docker-compose/
│           ├── gitea.docker-compose.yml
│           ├── jenkins.docker-compose.yml
│           ├── registry.docker-compose.yml
│           ├── application.docker-compose.yml
│           ├── mlflow.docker-compose.yml
│           ├── ml-inference.docker-compose.yml
│           ├── training-data.docker-compose.yml
│           ├── ml-inference-app/
│           └── training-data/
│
├── cloud_aws/
│   └── supply_chain/
│       └── terraform/
│           ├── main.tf
│           ├── ec2.tf
│           ├── variables.tf
│           └── user-data/
│
└── kubernetes/
    └── supply_chain/
        ├── 00-namespaces.yaml
        ├── 01-gitea.yaml
        ├── 02-jenkins.yaml
        ├── 03-registry.yaml
        ├── 04-application.yaml
        ├── 05-mlflow.yaml
        ├── 06-ml-inference.yaml
        └── 07-training-data.yaml
```

## Related Work

For attack path construction experiments (AP1-AP5), see:
- `../attack_path_experiments/` directory
- Paper: `paper/paper.tex`
