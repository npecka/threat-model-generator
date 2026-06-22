# AWS HA Quay Deployment - Terraform

## Overview

This Terraform configuration deploys **Project Quay** in a **full High Availability (HA)** configuration on AWS. This deployment demonstrates all threats (T01-T21) including HA-specific threats (T18-T21).

## Architecture

### Network Architecture
- **VPC**: 10.0.0.0/16
- **3 Availability Zones** for high availability
- **6 Subnets**: 3 public, 3 private
- **NAT Gateways**: 1 per AZ for redundancy
- **Application Load Balancer**: Public-facing for Quay access
- **Network Load Balancer**: Internal for Redis access

### Compute Resources
- **Quay Application**: Auto Scaling Group (3-6 instances, t3.medium)
- **LLM Service**: Auto Scaling Group (2-4 instances, t3.large)
- **Clair Scanner**: Auto Scaling Group (2-4 instances, t3.medium)

### Database & Caching
- **Aurora PostgreSQL**: 3-node cluster across 3 AZs
- **ElastiCache Redis**: Replication group with 3 nodes (1 primary + 2 replicas)

### Storage
- **S3**: Image blob storage with public access (T05)
- **S3**: LLM model storage (T11)
- **EFS**: Shared configuration across instances

## Injected Threats

This deployment includes all 21 threats:

### Traditional Infrastructure (T01-T10)
- **T01**: Security groups allow access from 0.0.0.0/0
- **T02**: IAM roles with excessive permissions (S3:*, secretsmanager:*)
- **T03**: HTTP instead of HTTPS, no encryption in transit
- **T04**: Network ACLs not configured, overly broad security groups
- **T05**: S3 buckets allow public read access
- **T06**: IAM roles grant CI/CD access to production
- **T07**: CloudWatch logging disabled, no VPC Flow Logs, short backup retention
- **T08**: Secrets in Terraform variables, user data, and logs
- **T09**: Broad ClusterRole equivalent via IAM
- **T10**: No detailed monitoring, no resource quotas

### ML/AI-Specific (T11-T17)
- **T11**: LLM model bucket publicly accessible, API without auth
- **T12**: No training data validation (simulated)
- **T13**: LLM API allows model extraction
- **T14**: Models downloaded over HTTP
- **T15**: LLM service has production IAM access
- **T16**: No model provenance tracking
- **T17**: Model metadata exposed in config files

### High Availability-Specific (T18-T21)
- **T18**: Split-brain scenarios possible during network partitions
  - Auto Scaling Groups lack proper quorum configuration
  - No cluster coordination for distributed state
  - Database failover without application-level coordination
  
- **T19**: Cascading failure vulnerabilities
  - No circuit breakers configured
  - Zero deregistration delay causes immediate traffic shift
  - No gradual rollout for ASG updates
  - Single point of failure in ALB despite HA instances
  
- **T20**: State inconsistency across replicas
  - No session stickiness on ALB (disabled)
  - Redis replication lag not monitored
  - No consistency checks between Quay instances
  - Model version mismatches across LLM replicas
  
- **T21**: Delayed failure detection
  - Health check intervals too long (30-60s)
  - Long grace periods mask failures
  - No proactive health monitoring
  - Slow response to AZ failures

## Prerequisites

- **AWS CLI** configured with credentials
- **Terraform** >= 1.0
- **AWS Account** with sufficient permissions
- **S3 Backend** (optional, for state management)

## Deployment Steps

### 1. Configure Variables

Create `terraform.tfvars`:

```hcl
aws_region     = "us-east-1"
environment    = "threat-modeling"
db_password    = "change_me_insecure_password"
redis_password = ""  # Empty for T01 demonstration

# HA Configuration
min_app_instances     = 3
max_app_instances     = 6
desired_app_instances = 3

# Threat injection flags
enable_monitoring  = false  # T07
enable_logging     = false  # T07
enable_encryption  = false  # T03
```

### 2. Initialize Terraform

```bash
terraform init
```

### 3. Review Plan

```bash
terraform plan
```

**Expected resources**: ~60-70 resources including:
- VPC, subnets, route tables, gateways
- Security groups
- RDS Aurora cluster (3 instances)
- ElastiCache Redis (3 nodes)
- S3 buckets (2)
- EFS file system
- Application Load Balancer
- Auto Scaling Groups (3)
- Launch templates (3)
- Target groups (4)
- IAM roles and policies

### 4. Deploy Infrastructure

```bash
terraform apply
```

**Deployment time**: 15-20 minutes

### 5. Verify Deployment

```bash
# Get ALB DNS name
terraform output alb_dns_name

# Check ASG status
aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names quay-app-asg

# Check RDS cluster
aws rds describe-db-clusters --db-cluster-identifier quay-postgres-cluster

# Check ElastiCache
aws elasticache describe-replication-groups --replication-group-id quay-redis-cluster
```

### 6. Access Quay

```bash
ALB_DNS=$(terraform output -raw alb_dns_name)
echo "Quay URL: http://$ALB_DNS"
```

## Running Threat Analysis

```bash
cd ../../../../platforms/cloud_aws/analyzer
python main.py
```

**Expected detection**: All 21 threats (T01-T21)

## Cost Estimation

**Approximate monthly costs** (us-east-1):
- **EC2 Instances**: ~$250-400 (7-14 instances)
- **RDS Aurora**: ~$200-300 (3 db.t3.medium instances)
- **ElastiCache**: ~$150-200 (3 cache.t3.medium nodes)
- **NAT Gateways**: ~$100 (3 gateways)
- **ALB**: ~$20
- **S3 & Data Transfer**: ~$50-100
- **EFS**: ~$10

**Total**: ~$780-1,200/month

**Cost optimization for testing**:
- Reduce instance counts to minimum (1-2 per ASG)
- Use smaller instance types
- Deploy to single AZ (loses HA but reduces costs by ~40%)
- Destroy resources after testing

## Threat Locations by File

| Threat | File | Resource/Line |
|--------|------|---------------|
| T01 | main.tf | Security group ingress rules |
| T02 | compute.tf | IAM role policies |
| T03 | loadbalancer.tf, database.tf | HTTP listeners, unencrypted connections |
| T04 | main.tf | Missing network ACLs |
| T05 | storage.tf | S3 bucket policies |
| T06 | compute.tf | IAM role with prod access |
| T07 | database.tf, main.tf | Disabled logging |
| T08 | variables.tf, user-data/*.sh | Secrets in code |
| T09 | compute.tf | Excessive IAM permissions |
| T10 | compute.tf | Monitoring disabled |
| T11 | storage.tf | Public model bucket |
| T12 | user-data/llm-service.sh | No data validation |
| T13 | user-data/llm-service.sh | Open inference API |
| T14 | user-data/llm-service.sh | HTTP model download |
| T15 | compute.tf | LLM service IAM role |
| T16 | user-data/llm-service.sh | No provenance tracking |
| T17 | user-data/llm-service.sh | Model metadata exposed |
| T18 | compute.tf, database.tf | No quorum/coordination |
| T19 | loadbalancer.tf, compute.tf | Zero drain delay, no circuit breaker |
| T20 | loadbalancer.tf, database.tf | No stickiness, replication lag |
| T21 | loadbalancer.tf | Long health check intervals |

## HA-Specific Threat Details

### T18: Split-Brain Scenario
**Location**: compute.tf, database.tf
**Manifestation**: 
- Auto Scaling Groups can scale independently without coordination
- RDS failover doesn't coordinate with application layer
- No distributed consensus mechanism
**Detection**: Monitor for duplicate writes, conflicting states during network partitions

### T19: Cascading Failure
**Location**: loadbalancer.tf, compute.tf
**Manifestation**:
- `deregistration_delay = 0` causes immediate traffic cutover
- No circuit breaker when backend failures occur
- ASG updates apply immediately without gradual rollout
**Detection**: Monitor for spike in 5xx errors during instance failures

### T20: State Inconsistency
**Location**: loadbalancer.tf, database.tf
**Manifestation**:
- `stickiness.enabled = false` routes same session to different instances
- Redis replication lag monitoring not enabled
- LLM model versions may differ across instances
**Detection**: Session state loss, inconsistent query results

### T21: Delayed Failure Detection
**Location**: loadbalancer.tf
**Manifestation**:
- Health check intervals: 30-60 seconds
- Grace periods: 300-600 seconds
- Failed instances serve traffic for extended periods
**Detection**: Monitor time-to-detect metrics for failed instances

## Cleanup

```bash
# Destroy all resources
terraform destroy

# Verify S3 buckets are deleted
aws s3 ls | grep quay
```

**Note**: Some resources may have deletion protection. Disable before destroying.

## Comparison: K8s vs AWS

| Aspect | K8s (Minimal) | AWS (HA) |
|--------|---------------|----------|
| Deployment | Single-node | Multi-AZ (3 AZs) |
| Quay Replicas | 1 | 3-6 (ASG) |
| Database | 1 pod | 3-node Aurora cluster |
| Redis | 1 pod | 3-node replication group |
| LLM Service | 1 pod | 2-4 instances (ASG) |
| Threats | T01-T17 | T01-T21 (+ HA threats) |
| Cost | Free (local) | ~$800-1,200/month |
| Complexity | Medium | High |

## Security Tool Validation

Run Prowler against this deployment:

```bash
# Install Prowler
pip install prowler

# Run security assessment
prowler aws --output-directory ./prowler-results

# Compare Prowler findings vs framework detection
# Expected: Framework detects all 21 threats
#           Prowler detects ~8-10 threats (47% coverage)
```

## References

- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/)
- [Project Quay](https://github.com/quay/quay)
- [Terraform AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
