# Case Study 1: ML-Enhanced Supply Chain

8-component software supply chain deployed across bare-metal, Kubernetes, and AWS.

## Components

Gitea (source control), Jenkins (CI/CD), Docker Registry, Application (production), PostgreSQL (database), MLflow (model registry), ML Inference Service, Training Data Storage.

## Trust Zones

- **Development Zone**: Gitea, Training Data Storage
- **CI/CD Zone**: Jenkins, Docker Registry, MLflow Model Registry
- **Production Zone**: Application, PostgreSQL, ML Inference Service

## Platform Deployments

### Bare-Metal
- 3 Proxmox VMs (Ubuntu 22.04, Docker)
- SSH/tcpdump for config/flow extraction
- **49 instances** (42 traditional + 7 ML)

### Kubernetes
- 3 namespaces on RKE2 cluster
- API/Hubble for config/flow extraction
- **47 instances** (40 traditional + 7 ML)

### AWS Cloud
- 3 EC2 t3.micro instances, separate VPC subnets
- Boto3/tcpdump for config/flow extraction
- **71 instances** (63 traditional + 8 ML)

## Results Summary

All platforms detected 17/17 threat types (100%) with zero false positives.

| Platform | Traditional | ML | Total Instances |
|----------|------------|-----|-----------------|
| Bare-metal | 42 | 7 | 49 |
| Kubernetes | 40 | 7 | 47 |
| AWS | 63 | 8 | 71 |
