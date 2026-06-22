# Case Study 2: Project Quay High Availability

## Overview

This case study deploys **Project Quay** (open-source container registry) with intentionally vulnerable configurations to validate the dynamic threat modeling framework against a larger, more complex distributed system.

## System Components

1. **Quay Application** - Container registry web application
2. **PostgreSQL** - Metadata and configuration storage
3. **Redis** - Caching and session management
4. **Clair** - Container vulnerability scanner
5. **Minio** - S3-compatible object storage for image blobs
6. **NGINX Ingress** - External access to services
7. **LLM Analyzer** - Small language model for image security analysis
8. **RBAC Policies** - Role-based access control
9. **Network Policies** - (Intentionally missing/commented out)

## Deployment Configuration

This is a **minimal deployment** (1 replica per component) designed for resource-constrained environments.

**Current cluster specs:**
- 1 physical server (32GB RAM, 2TB SSD)
- Proxmox hypervisor with RKE2 cluster
- 2-3 Kubernetes nodes

For **full HA deployment** see `dynamic_threat_modeling/cloud_aws/quay_ha/`.

## Injected Threats

This deployment intentionally includes all 17 original threats:

### Traditional Infrastructure Threats (T01-T10)
- **T01**: Unauthenticated External Access - Services exposed without authentication
- **T02**: Excessive Permissions - Overly broad RBAC roles
- **T03**: Unencrypted Cross-Boundary Communication - HTTP instead of HTTPS
- **T04**: Missing Network Segmentation - No network policies enabled
- **T05**: Anonymous Registry Access - Quay allows anonymous pulls
- **T06**: CI/CD to Production Access - CI role has production permissions
- **T07**: Missing Audit Logging - Audit logging disabled in Quay config
- **T08**: Exposed Secrets in Configuration - Hardcoded credentials
- **T09**: Overly Broad Source Control Access - Excessive git-related permissions
- **T10**: Missing Resource Limits - No CPU/memory limits on pods

### ML/AI-Specific Threats (T11-T17)
- **T11**: Unauthorized Model Access - LLM API accessible without auth
- **T12**: Training Data Poisoning - Simulated via threat injection job
- **T13**: Model Theft via API - LLM inference API allows model extraction
- **T14**: Unencrypted Model Transfer - Model downloaded over HTTP
- **T15**: ML Pipeline to Production Access - LLM service can access prod
- **T16**: Missing Model Provenance - No model lineage tracking
- **T17**: Exposed Model Metadata - Model parameters in ConfigMap

## Prerequisites

- Kubernetes cluster (RKE2, K3s, or similar)
- kubectl configured
- NGINX Ingress Controller installed
- At least 16GB available RAM
- 100GB available storage

## Deployment Steps

### 1. Deploy Infrastructure Components

```bash
# Create namespace
kubectl apply -f 00-namespace.yaml

# Deploy database
kubectl apply -f 01-postgres.yaml

# Deploy cache
kubectl apply -f 02-redis.yaml

# Deploy object storage
kubectl apply -f 03-minio.yaml

# Wait for infrastructure to be ready
kubectl wait --for=condition=ready pod -l app=postgres -n quay-system --timeout=300s
kubectl wait --for=condition=ready pod -l app=redis -n quay-system --timeout=300s
kubectl wait --for=condition=ready pod -l app=minio -n quay-system --timeout=300s
```

### 2. Deploy Quay Application

```bash
# Deploy Quay configuration
kubectl apply -f 04-quay-config.yaml

# Deploy Quay application
kubectl apply -f 05-quay-app.yaml

# Deploy Clair vulnerability scanner
kubectl apply -f 06-clair.yaml

# Wait for Quay to be ready
kubectl wait --for=condition=ready pod -l app=quay -n quay-system --timeout=300s
kubectl wait --for=condition=ready pod -l app=clair -n quay-system --timeout=300s
```

### 3. Deploy Supporting Services

```bash
# Deploy ingress rules
kubectl apply -f 07-ingress.yaml

# Deploy LLM service (takes longer due to model download)
kubectl apply -f 08-llm-service.yaml

# Deploy RBAC policies
kubectl apply -f 09-rbac.yaml

# Deploy network policies (commented out - demonstrating T04)
kubectl apply -f 10-network-policy.yaml

# Wait for LLM service (may take 5-10 minutes for model download)
kubectl wait --for=condition=ready pod -l app=llm-analyzer -n quay-system --timeout=600s
```

### 4. Verify Deployment

```bash
# Check all pods are running
kubectl get pods -n quay-system

# Check services
kubectl get svc -n quay-system

# Check ingress
kubectl get ingress -n quay-system

# Check for injected threats
kubectl logs -n quay-system job/llm-threat-injection
```

### 5. Access Quay

Add to `/etc/hosts`:
```
<cluster-ip> quay-registry.local
<cluster-ip> minio-console.local
<cluster-ip> clair.local
<cluster-ip> llm-analyzer.local
```

Access Quay at: `http://quay-registry.local`

## Running Threat Analysis

```bash
cd ../../../platforms/kubernetes/analyzer
python main.py --namespace quay-system
```

**Expected Output:**
- Detection of all 17 threats (T01-T17)
- Runtime flow confirmation via Hubble
- Zero false positives

## Threat Locations by Manifest

| Threat | Manifest File | Line/Component |
|--------|---------------|----------------|
| T01 | 01-postgres.yaml, 05-quay-app.yaml, 07-ingress.yaml | Service exposure |
| T02 | 09-rbac.yaml | ClusterRole permissions |
| T03 | 04-quay-config.yaml, 07-ingress.yaml | HTTP without TLS |
| T04 | 10-network-policy.yaml | Policies commented out |
| T05 | 04-quay-config.yaml | FEATURE_ANONYMOUS_ACCESS |
| T06 | 09-rbac.yaml | CI role permissions |
| T07 | 04-quay-config.yaml | FEATURE_AUDIT_LOG: false |
| T08 | 01-postgres.yaml, 04-quay-config.yaml | Hardcoded credentials |
| T09 | 09-rbac.yaml | Overly broad ClusterRole |
| T10 | All deployment files | Resources section commented |
| T11 | 08-llm-service.yaml | DISABLE_AUTH: true |
| T12 | 08-llm-service.yaml | Threat injection job |
| T13 | 08-llm-service.yaml | Open inference API |
| T14 | 08-llm-service.yaml | HTTP model download |
| T15 | 09-rbac.yaml | LLM service permissions |
| T16 | 08-llm-service.yaml | No provenance tracking |
| T17 | 08-llm-service.yaml | Model metadata in ConfigMap |

## Resource Requirements

**Minimal deployment (current):**
- CPU: ~5-6 cores
- Memory: ~12-16 GB
- Storage: ~100 GB

**Per-component breakdown:**
- PostgreSQL: 1 CPU, 1-2 GB RAM
- Redis: 0.5 CPU, 512 MB RAM
- Minio: 1 CPU, 1 GB RAM
- Quay: 2 CPU, 4 GB RAM
- Clair: 1 CPU, 2 GB RAM
- LLM Service: 2 CPU, 4 GB RAM (during inference)
- NGINX Ingress: 0.5 CPU, 512 MB RAM

## Cleanup

```bash
kubectl delete namespace quay-system
```

## Comparison with Case Study 1

| Aspect | Case Study 1 (Supply Chain) | Case Study 2 (Quay HA) |
|--------|------------------------------|------------------------|
| Components | 7 | 10+ |
| Complexity | Medium | High |
| Threats | T01-T17 | T01-T17 (+ T18-T21 in AWS) |
| Use Case | ML pipeline | Container registry |
| HA Support | No | Yes (in AWS deployment) |

## Known Issues

1. **LLM Model Download**: First deployment takes 5-10 minutes to download the model
2. **Resource Constraints**: Full deployment may not fit on single-node clusters
3. **Ingress DNS**: Requires manual /etc/hosts configuration
4. **Persistent Storage**: Requires PV provisioner (local-path, NFS, etc.)

## Next Steps

1. Run threat analysis with framework
2. Compare against security scanning tools (Trivy, Kubescape, Kubelinter)
3. Validate detection accuracy
4. Document results in research paper

## References

- [Project Quay](https://github.com/quay/quay)
- [Clair](https://github.com/quay/clair)
- [Llama CPP Python](https://github.com/abetlen/llama-cpp-python)
